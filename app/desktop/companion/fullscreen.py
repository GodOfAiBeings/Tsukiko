"""Tsukiko Safe Fullscreen Detection Policy (Phase 2).

Determines whether the current foreground window is occupying the monitor
in fullscreen mode using minimal, read-only operating system window metadata.

Safety and Anti-Cheat Invariants:
1. NEVER inspects game process memory, scans memory pages, or reads structures.
2. NEVER enumerates game processes or checks running executable names.
3. NEVER injects DLLs, installs API hooks, or registers global hooks (SetWindowsHookEx).
4. NEVER captures screen buffers, window frames, or user input.
5. Fails closed / safely: if OS metadata is unavailable, unsupported, or raises an
   exception, reports that always-on-top must be disabled.
6. Does not claim universal anti-cheat compatibility or guarantee that every game
   permits third-party desktop overlays or companions.
"""

from __future__ import annotations

import logging
import os
import platform
from dataclasses import dataclass
from typing import Any, Optional, Set

logger = logging.getLogger(__name__)

# Windows Constants
MONITOR_DEFAULTTONEAREST = 2

# Ctypes structures & pointer-sized handle types
try:
    import ctypes
    import ctypes.wintypes

    class MONITORINFO(ctypes.Structure):
        _fields_ = [
            ("cbSize", ctypes.wintypes.DWORD),
            ("rcMonitor", ctypes.wintypes.RECT),
            ("rcWork", ctypes.wintypes.RECT),
            ("dwFlags", ctypes.wintypes.DWORD),
        ]

    # Explicit pointer-sized handle types
    HMONITOR = getattr(ctypes.wintypes, "HMONITOR", ctypes.c_void_p)
    HWND = ctypes.wintypes.HWND
    BOOL = ctypes.wintypes.BOOL
    DWORD = ctypes.wintypes.DWORD
    RECT = ctypes.wintypes.RECT
    LPWSTR = ctypes.wintypes.LPWSTR
    LPRECT = ctypes.POINTER(RECT)
    LPMONITORINFO = ctypes.POINTER(MONITORINFO)
    LPDWORD = ctypes.POINTER(DWORD)
    HAS_WINTYPES = True
except (ImportError, AttributeError):
    HAS_WINTYPES = False
    MONITORINFO = None  # type: ignore[assignment,misc]
    HMONITOR = None  # type: ignore[assignment,misc]
    HWND = None  # type: ignore[assignment,misc]
    BOOL = None  # type: ignore[assignment,misc]
    DWORD = None  # type: ignore[assignment,misc]
    RECT = None  # type: ignore[assignment,misc]
    LPWSTR = None  # type: ignore[assignment,misc]
    LPRECT = None  # type: ignore[assignment,misc]
    LPMONITORINFO = None  # type: ignore[assignment,misc]
    LPDWORD = None  # type: ignore[assignment,misc]


def setup_user32_signatures(user32: Any) -> None:
    """Explicitly declares correct argtypes and pointer-sized restype for all User32 APIs used."""
    if not HAS_WINTYPES or user32 is None:
        return

    # 1. GetForegroundWindow: HWND GetForegroundWindow(void)
    user32.GetForegroundWindow.restype = HWND
    user32.GetForegroundWindow.argtypes = []

    # 2. GetDesktopWindow: HWND GetDesktopWindow(void)
    user32.GetDesktopWindow.restype = HWND
    user32.GetDesktopWindow.argtypes = []

    # 3. GetShellWindow: HWND GetShellWindow(void)
    user32.GetShellWindow.restype = HWND
    user32.GetShellWindow.argtypes = []

    # 4. GetClassNameW: int GetClassNameW(HWND hWnd, LPWSTR lpClassName, int nMaxCount)
    user32.GetClassNameW.restype = ctypes.c_int
    user32.GetClassNameW.argtypes = [HWND, LPWSTR, ctypes.c_int]

    # 5. GetWindowThreadProcessId: DWORD GetWindowThreadProcessId(HWND hWnd, LPDWORD lpdwProcessId)
    user32.GetWindowThreadProcessId.restype = DWORD
    user32.GetWindowThreadProcessId.argtypes = [HWND, LPDWORD]

    # 6. IsIconic: BOOL IsIconic(HWND hWnd)
    user32.IsIconic.restype = BOOL
    user32.IsIconic.argtypes = [HWND]

    # 7. IsWindowVisible: BOOL IsWindowVisible(HWND hWnd)
    user32.IsWindowVisible.restype = BOOL
    user32.IsWindowVisible.argtypes = [HWND]

    # 8. GetWindowRect: BOOL GetWindowRect(HWND hWnd, LPRECT lpRect)
    user32.GetWindowRect.restype = BOOL
    user32.GetWindowRect.argtypes = [HWND, LPRECT]

    # 9. MonitorFromWindow: HMONITOR MonitorFromWindow(HWND hwnd, DWORD dwFlags)
    user32.MonitorFromWindow.restype = HMONITOR
    user32.MonitorFromWindow.argtypes = [HWND, DWORD]

    # 10. GetMonitorInfoW: BOOL GetMonitorInfoW(HMONITOR hMonitor, LPMONITORINFO lpmi)
    user32.GetMonitorInfoW.restype = BOOL
    user32.GetMonitorInfoW.argtypes = [HMONITOR, LPMONITORINFO]


@dataclass(frozen=True)
class FullscreenEvaluation:
    """Result of read-only foreground window fullscreen evaluation."""

    detection_available: bool
    is_fullscreen: bool
    safe_always_on_top: bool
    reason: str


class FullscreenDetector:
    """Inspects operating system foreground window geometry in a read-only manner."""

    def __init__(self) -> None:
        self._is_windows = platform.system() == "Windows"
        self._user32 = None

        if self._is_windows and HAS_WINTYPES:
            try:
                import ctypes
                self._user32 = ctypes.windll.user32
                setup_user32_signatures(self._user32)
            except Exception as e:
                logger.warning(f"Unable to bind Windows user32 for fullscreen detection: {e}")
                self._user32 = None

    def is_available(self) -> bool:
        """Returns True if operating system window metadata can be safely inspected."""
        return self._is_windows and (self._user32 is not None) and HAS_WINTYPES

    def evaluate_fullscreen(
        self,
        own_pids: Optional[Set[int]] = None,
    ) -> FullscreenEvaluation:
        """Evaluates whether the foreground window occupies the display in fullscreen mode.
        
        Fails safely if detection is unavailable or encounters an error.
        """
        if not self.is_available():
            return FullscreenEvaluation(
                detection_available=False,
                is_fullscreen=False,
                safe_always_on_top=False,
                reason="Fullscreen detection unavailable on this platform/environment; failing safe.",
            )

        try:
            user32 = self._user32
            assert user32 is not None

            # 1. Get foreground window handle (minimal read-only handle)
            hwnd = user32.GetForegroundWindow()
            if not hwnd:
                # No foreground window active; safe to maintain normal state
                return FullscreenEvaluation(
                    detection_available=True,
                    is_fullscreen=False,
                    safe_always_on_top=True,
                    reason="No foreground window active.",
                )

            # 2. Exclude desktop and shell windows
            desktop_hwnd = user32.GetDesktopWindow()
            shell_hwnd = user32.GetShellWindow()
            if hwnd == desktop_hwnd or (shell_hwnd and hwnd == shell_hwnd):
                return FullscreenEvaluation(
                    detection_available=True,
                    is_fullscreen=False,
                    safe_always_on_top=True,
                    reason="Foreground window is desktop or shell window.",
                )

            # 3. Check window class name for Windows desktop background
            buf = ctypes.create_unicode_buffer(256)
            user32.GetClassNameW(hwnd, buf, 256)
            class_name = buf.value
            if class_name in ("Progman", "WorkerW", "Shell_TrayWnd", "Shell_SecondaryTrayWnd"):
                return FullscreenEvaluation(
                    detection_available=True,
                    is_fullscreen=False,
                    safe_always_on_top=True,
                    reason=f"Foreground window is shell element ({class_name}).",
                )

            # 4. Check whether foreground window belongs to Tsukiko itself
            if own_pids is None:
                own_pids = {os.getpid()}
            else:
                own_pids = set(own_pids) | {os.getpid()}

            fg_pid = DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(fg_pid))
            if fg_pid.value in own_pids:
                return FullscreenEvaluation(
                    detection_available=True,
                    is_fullscreen=False,
                    safe_always_on_top=True,
                    reason="Foreground window belongs to Tsukiko.",
                )

            # 5. Check if window is minimized (iconic) or not visible
            if user32.IsIconic(hwnd) or not user32.IsWindowVisible(hwnd):
                return FullscreenEvaluation(
                    detection_available=True,
                    is_fullscreen=False,
                    safe_always_on_top=True,
                    reason="Foreground window is minimized or invisible.",
                )

            # 6. Retrieve window rectangle
            rect = RECT()
            if not user32.GetWindowRect(hwnd, ctypes.byref(rect)):
                # WindowRect query failed; fail safe
                return FullscreenEvaluation(
                    detection_available=True,
                    is_fullscreen=True,
                    safe_always_on_top=False,
                    reason="GetWindowRect failed on foreground window; failing safe.",
                )

            # 7. Retrieve monitor bounds containing the foreground window
            hmon = user32.MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST)
            if not hmon:
                return FullscreenEvaluation(
                    detection_available=True,
                    is_fullscreen=True,
                    safe_always_on_top=False,
                    reason="MonitorFromWindow failed; failing safe.",
                )

            mi = MONITORINFO()
            mi.cbSize = ctypes.sizeof(MONITORINFO)
            if not user32.GetMonitorInfoW(hmon, ctypes.byref(mi)):
                return FullscreenEvaluation(
                    detection_available=True,
                    is_fullscreen=True,
                    safe_always_on_top=False,
                    reason="GetMonitorInfoW failed; failing safe.",
                )

            # 8. Check if window occupies or exceeds the monitor rect
            # Fullscreen games cover from top-left (<= 0) to bottom-right (>= monitor dimensions)
            is_fullscreen = (
                rect.left <= mi.rcMonitor.left
                and rect.top <= mi.rcMonitor.top
                and rect.right >= mi.rcMonitor.right
                and rect.bottom >= mi.rcMonitor.bottom
            )

            if is_fullscreen:
                return FullscreenEvaluation(
                    detection_available=True,
                    is_fullscreen=True,
                    safe_always_on_top=False,
                    reason=f"Foreground window occupies entire monitor ({rect.left},{rect.top},{rect.right},{rect.bottom}).",
                )

            return FullscreenEvaluation(
                detection_available=True,
                is_fullscreen=False,
                safe_always_on_top=True,
                reason="Foreground window does not occupy entire monitor.",
            )

        except Exception as e:
            logger.debug(f"Error during fullscreen detection: {e}; failing safe.")
            return FullscreenEvaluation(
                detection_available=False,
                is_fullscreen=False,
                safe_always_on_top=False,
                reason=f"Exception during fullscreen inspection: {e}; failing safe.",
            )
