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
from typing import Optional, Set

logger = logging.getLogger(__name__)

# Windows Constants
MONITOR_DEFAULTTONEAREST = 2


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

        if self._is_windows:
            try:
                import ctypes
                self._user32 = ctypes.windll.user32
            except Exception as e:
                logger.warning(f"Unable to bind Windows user32 for fullscreen detection: {e}")
                self._user32 = None

    def is_available(self) -> bool:
        """Returns True if operating system window metadata can be safely inspected."""
        return self._is_windows and (self._user32 is not None)

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
            import ctypes
            import ctypes.wintypes

            class MONITORINFO(ctypes.Structure):
                _fields_ = [
                    ("cbSize", ctypes.wintypes.DWORD),
                    ("rcMonitor", ctypes.wintypes.RECT),
                    ("rcWork", ctypes.wintypes.RECT),
                    ("dwFlags", ctypes.wintypes.DWORD),
                ]

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

            fg_pid = ctypes.wintypes.DWORD()
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
            rect = ctypes.wintypes.RECT()
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
