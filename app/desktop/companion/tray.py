"""Tsukiko Desktop Companion — System Tray Manager (Phase 2).

Provides the lightweight desktop system tray icon (QSystemTrayIcon)
and menu to restore the companion widget or main application window.

Actions:
- Show Widget: unhides the floating companion widget.
- Open Tsukiko: brings up the full Tsukiko main application window.
- Resume from Game Mode: visible/enabled when Game Mode is active.
- Exit: cleanly terminates Tsukiko.

Safety and Anti-Cheat Invariants:
- Read-only Qt desktop hooks only.
- Never hooks games, inputs, or system processes.
- Gracefully degrades with clear fallback if the operating system or environment
  does not support system tray icons (QSystemTrayIcon.isSystemTrayAvailable() == False).
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from app.desktop.companion.avatar import TsukikoAvatarWidget

logger = logging.getLogger(__name__)

try:
    from PySide6.QtCore import QObject, Signal
    from PySide6.QtGui import QAction, QIcon
    from PySide6.QtWidgets import QApplication, QMenu, QSystemTrayIcon
    HAS_PYSIDE6 = True
except ImportError:
    HAS_PYSIDE6 = False
    QObject = object  # type: ignore[misc,assignment]


class TsukikoTrayManager(QObject if HAS_PYSIDE6 else object):  # type: ignore[misc]
    """Manages system tray integration and restore actions for Tsukiko."""

    if HAS_PYSIDE6:
        show_widget_requested = Signal()
        open_main_requested = Signal()
        resume_game_mode_requested = Signal()
        exit_requested = Signal()

    def __init__(
        self,
        widget: Optional[Any] = None,
        main_window: Optional[Any] = None,
        parent: Optional[QObject] = None,
    ) -> None:
        if not HAS_PYSIDE6:
            raise RuntimeError("PySide6 is required to instantiate TsukikoTrayManager")
        super().__init__(parent)

        self._widget = widget
        self._main_window = main_window
        self._tray_icon: Optional[QSystemTrayIcon] = None
        self._menu: Optional[QMenu] = None
        self._is_tray_available = QSystemTrayIcon.isSystemTrayAvailable()

        if self._is_tray_available:
            self._setup_tray()
        else:
            logger.warning(
                "System tray is unavailable in this environment (headless, unsupported display server, etc.). "
                "Enabling main-window fallback controls so user is never stranded."
            )
            if self._main_window and hasattr(self._main_window, "enable_tray_fallback"):
                self._main_window.enable_tray_fallback(self._widget)

    @property
    def is_available(self) -> bool:
        """Returns True if the OS environment provides an active system tray."""
        return self._is_tray_available

    @property
    def tray_icon(self) -> Optional[QSystemTrayIcon]:
        return self._tray_icon

    def _setup_tray(self) -> None:
        """Creates the QSystemTrayIcon with required actions and vector icon."""
        self._tray_icon = QSystemTrayIcon(self)
        self._tray_icon.setToolTip("Tsukiko — Desktop Companion")

        # Procedural vector emblem icon
        icon = TsukikoAvatarWidget.render_to_icon(32)
        self._tray_icon.setIcon(icon)

        # Context menu with required Phase 2 actions:
        # 1. Show Widget
        # 2. Open Tsukiko
        # 3. Resume from Game Mode (enabled/visible when Game Mode active)
        # 4. Exit
        self._menu = QMenu()
        self._menu.setObjectName("TsukikoTrayMenu")

        self.action_show_widget = QAction("Show Widget", self)
        self.action_show_widget.triggered.connect(self._handle_show_widget)
        self._menu.addAction(self.action_show_widget)

        self.action_open = QAction("Open Tsukiko", self)
        self.action_open.triggered.connect(self._handle_open_main)
        self._menu.addAction(self.action_open)

        self.action_resume_game = QAction("Resume from Game Mode", self)
        self.action_resume_game.setEnabled(False)
        self.action_resume_game.setVisible(False)
        self.action_resume_game.triggered.connect(self._handle_resume_game)
        self._menu.addAction(self.action_resume_game)

        self._menu.addSeparator()

        self.action_exit = QAction("Exit", self)
        self.action_exit.triggered.connect(self._handle_exit)
        self._menu.addAction(self.action_exit)

        self._tray_icon.setContextMenu(self._menu)
        self._tray_icon.activated.connect(self._on_tray_activated)

        # Wire widget signals to update menu state dynamically if provided
        if self._widget:
            if hasattr(self._widget, "game_mode_activated"):
                self._widget.game_mode_activated.connect(self._on_widget_game_mode_activated)
            if hasattr(self._widget, "game_mode_deactivated"):
                self._widget.game_mode_deactivated.connect(self._on_widget_game_mode_deactivated)

        self._tray_icon.show()
        logger.info("Tsukiko system tray icon registered successfully.")

    def update_state(self, is_game_mode: bool = False, is_widget_hidden: bool = False) -> None:
        """Dynamically updates tray menu item visibility and enabled states."""
        if not self._is_tray_available or not self.action_resume_game:
            return

        if is_game_mode:
            self.action_resume_game.setVisible(True)
            self.action_resume_game.setEnabled(True)
        else:
            self.action_resume_game.setVisible(False)
            self.action_resume_game.setEnabled(False)

    def _on_widget_game_mode_activated(self) -> None:
        self.update_state(is_game_mode=True)

    def _on_widget_game_mode_deactivated(self) -> None:
        self.update_state(is_game_mode=False)

    def _handle_show_widget(self) -> None:
        """Restores the companion widget from hidden or game mode."""
        logger.info("Show Widget requested from system tray.")
        if self._widget:
            if hasattr(self._widget, "disable_game_mode") and getattr(self._widget, "is_game_mode", False):
                self._widget.disable_game_mode()
            if hasattr(self._widget, "show_widget"):
                self._widget.show_widget()
            else:
                self._widget.show()
        self.show_widget_requested.emit()

    def _handle_open_main(self) -> None:
        """Opens and focuses the complete Tsukiko main window."""
        logger.info("Open Tsukiko requested from system tray.")
        if self._main_window:
            self._main_window.show()
            self._main_window.raise_()
            self._main_window.activateWindow()
        self.open_main_requested.emit()

    def _handle_resume_game(self) -> None:
        """Resumes Tsukiko from Game Mode."""
        logger.info("Resume from Game Mode requested from system tray.")
        if self._widget and hasattr(self._widget, "disable_game_mode"):
            self._widget.disable_game_mode()
        self.update_state(is_game_mode=False)
        self.resume_game_mode_requested.emit()

    def _handle_exit(self) -> None:
        """Clean shutdown requested from system tray."""
        logger.info("Exit requested from system tray.")
        self.exit_requested.emit()
        app = QApplication.instance()
        if app:
            app.quit()

    def _on_tray_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        """Handles user clicking or double-clicking tray icon."""
        if reason in (QSystemTrayIcon.Trigger, QSystemTrayIcon.DoubleClick):
            # If main window is visible, raise it; otherwise show widget or main window
            if self._main_window and self._main_window.isVisible():
                self._main_window.raise_()
                self._main_window.activateWindow()
            elif self._widget:
                if getattr(self._widget, "is_game_mode", False):
                    self._widget.disable_game_mode()
                elif getattr(self._widget, "is_hidden", False):
                    self._widget.show_widget()
                elif not self._widget.isVisible():
                    self._widget.show()
                else:
                    self._handle_open_main()
            elif self._main_window:
                self._handle_open_main()

    def hide(self) -> None:
        """Cleanly hides the tray icon."""
        if self._tray_icon:
            self._tray_icon.hide()
