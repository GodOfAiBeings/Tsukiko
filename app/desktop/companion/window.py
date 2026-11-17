"""Tsukiko Desktop Companion — Main Application Window (Phase 2).

Displays the complete Tsukiko companion interface:
- Sidebar navigation: Chat, System Status, Privacy, Memory, Settings.
- Stacked view presentation with Moonlight theme.
- Visually separate from floating companion widget; functions independently.
- Closing this window hides it without terminating the background companion.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from app.core.config.settings import TsukikoConfig, get_config
from app.desktop.companion.theme import MoonlightTheme
from app.desktop.companion.views.chat import ChatView
from app.desktop.companion.views.memory_view import MemoryView
from app.desktop.companion.views.privacy_view import PrivacyView
from app.desktop.companion.views.settings_view import SettingsView
from app.desktop.companion.views.system_status import SystemStatusView

logger = logging.getLogger(__name__)

try:
    from PySide6.QtCore import QPoint, Qt
    from PySide6.QtGui import QCloseEvent, QFont, QIcon, QMouseEvent
    from PySide6.QtWidgets import (
        QApplication,
        QFrame,
        QHBoxLayout,
        QLabel,
        QMainWindow,
        QPushButton,
        QStackedWidget,
        QVBoxLayout,
        QWidget,
    )
    HAS_PYSIDE6 = True
except ImportError:
    HAS_PYSIDE6 = False
    QMainWindow = object  # type: ignore[misc,assignment]
    QWidget = object  # type: ignore[misc,assignment]


class NavButton(QPushButton if HAS_PYSIDE6 else object):  # type: ignore[misc]
    """Sidebar navigation tab button."""

    def __init__(
        self,
        icon_str: str,
        text: str,
        parent: Optional[QWidget] = None,
    ) -> None:
        if not HAS_PYSIDE6:
            raise RuntimeError("PySide6 is required to instantiate NavButton")
        super().__init__(parent)
        self.setCheckable(True)
        self.setFixedHeight(42)
        self.setCursor(Qt.PointingHandCursor)
        self._setup_ui(icon_str, text)

    def _setup_ui(self, icon_str: str, text: str) -> None:
        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 4, 14, 4)
        layout.setSpacing(10)

        icon_lbl = QLabel(icon_str)
        icon_lbl.setStyleSheet("font-size: 15px; background: transparent;")
        layout.addWidget(icon_lbl)

        text_lbl = QLabel(text)
        text_lbl.setStyleSheet("font-size: 13px; font-weight: 500; background: transparent; color: inherit;")
        layout.addWidget(text_lbl, stretch=1)

        self.setStyleSheet(
            "QPushButton {"
            "  background-color: transparent;"
            "  border: 1px solid transparent;"
            "  border-radius: 8px;"
            "  color: #94A3B8;"
            "  text-align: left;"
            "}"
            "QPushButton:hover {"
            "  background-color: rgba(127, 179, 213, 0.12);"
            "  color: #D4E6F1;"
            "}"
            "QPushButton:checked {"
            "  background-color: rgba(127, 179, 213, 0.22);"
            "  border: 1px solid rgba(127, 179, 213, 0.4);"
            "  color: #FFFFFF;"
            "  font-weight: bold;"
            "}"
        )


class CompanionMainWindow(QMainWindow):
    """Complete Tsukiko Main Application Window.
    
    Houses the full suite of Phase 2 views:
    - Chat (Phase 3 disclaimer)
    - System Status (genuine hardware telemetry)
    - Privacy (locked sensors and zero-trust verification)
    - Memory (Phase 4 placeholder)
    - Settings (UI customization)
    """

    def __init__(
        self,
        config: Optional[TsukikoConfig] = None,
        orchestrator: Optional[Any] = None,
        parent: Optional[QWidget] = None,
    ) -> None:
        if not HAS_PYSIDE6:
            raise RuntimeError("PySide6 is required to instantiate CompanionMainWindow")
        super().__init__(parent)
        self.setObjectName("CompanionMainWindow")
        self.setWindowTitle("Tsukiko — Desktop Companion")
        self.resize(920, 640)
        self.setMinimumSize(780, 520)

        self._config = config or get_config()
        self._orchestrator = orchestrator
        self._widget: Optional[Any] = None
        self._tray_fallback_enabled: bool = False
        self._nav_buttons: Dict[str, NavButton] = {}

        self._init_theme()
        self._init_ui()
        self.setWindowOpacity(self._config.ui.background_opacity)
        self.settings_view.settings_applied.connect(self.apply_ui_config)

    def _init_theme(self) -> None:
        """Apply shared silver-blue moonlight theme stylesheet."""
        self.setStyleSheet(MoonlightTheme.get_full_stylesheet())

    def _init_ui(self) -> None:
        # Central widget with horizontal split (Sidebar | Content)
        central = QWidget(self)
        central.setObjectName("central_widget")
        central.setStyleSheet("background-color: #0F172A;")
        self.setCentralWidget(central)

        main_layout = QHBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # 1. Left Sidebar
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(220)
        sidebar.setStyleSheet(
            "QFrame#sidebar {"
            "  background-color: #111B2E;"
            "  border-right: 1px solid rgba(127, 179, 213, 0.18);"
            "}"
        )
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(12, 16, 12, 16)
        sidebar_layout.setSpacing(6)

        # Brand / Title header in sidebar
        brand_box = QHBoxLayout()
        brand_box.setSpacing(8)
        brand_icon = QLabel("🌙")
        brand_icon.setStyleSheet("font-size: 22px;")
        brand_box.addWidget(brand_icon)

        brand_text = QVBoxLayout()
        brand_title = QLabel("Tsukiko")
        brand_title.setStyleSheet("font-size: 16px; font-weight: bold; color: #D4E6F1;")
        brand_sub = QLabel("Desktop Companion")
        brand_sub.setStyleSheet("font-size: 11px; color: #7FB3D5;")
        brand_text.addWidget(brand_title)
        brand_text.addWidget(brand_sub)
        brand_box.addLayout(brand_text, stretch=1)
        sidebar_layout.addLayout(brand_box)

        # Separator
        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setStyleSheet("background-color: rgba(127, 179, 213, 0.2); max-height: 1px; margin: 12px 0;")
        sidebar_layout.addWidget(sep)

        # Navigation buttons
        self._add_nav_button(sidebar_layout, "chat", "💬", "Chat")
        self._add_nav_button(sidebar_layout, "status", "📊", "System Status")
        self._add_nav_button(sidebar_layout, "privacy", "🛡️", "Privacy & Security")
        self._add_nav_button(sidebar_layout, "memory", "🧠", "Memory")
        self._add_nav_button(sidebar_layout, "settings", "⚙️", "Settings")

        sidebar_layout.addStretch(1)

        # Fallback companion controls (shown if system tray is unavailable)
        self.fallback_frame = QFrame()
        self.fallback_frame.setObjectName("fallback_frame")
        self.fallback_frame.setStyleSheet(
            "QFrame#fallback_frame {"
            "  background-color: rgba(30, 41, 59, 0.7);"
            "  border: 1px solid rgba(127, 179, 213, 0.3);"
            "  border-radius: 6px;"
            "  padding: 6px;"
            "}"
        )
        fb_layout = QVBoxLayout(self.fallback_frame)
        fb_layout.setContentsMargins(6, 6, 6, 6)
        fb_layout.setSpacing(4)

        fb_title = QLabel("Companion Controls")
        fb_title.setStyleSheet("font-size: 11px; font-weight: bold; color: #7FB3D5;")
        fb_layout.addWidget(fb_title)

        self.btn_fallback_restore = QPushButton("Show Widget")
        self.btn_fallback_restore.setStyleSheet(
            "QPushButton {"
            "  background: rgba(127, 179, 213, 0.15);"
            "  border: 1px solid #7FB3D5;"
            "  color: #F8FAFC;"
            "  font-size: 11px;"
            "  border-radius: 4px;"
            "  padding: 4px;"
            "}"
            "QPushButton:hover { background: rgba(127, 179, 213, 0.3); }"
        )
        self.btn_fallback_restore.clicked.connect(self._on_fallback_restore_clicked)
        fb_layout.addWidget(self.btn_fallback_restore)

        self.btn_fallback_game_mode = QPushButton("Resume from Game Mode")
        self.btn_fallback_game_mode.setStyleSheet(
            "QPushButton {"
            "  background: rgba(82, 190, 128, 0.15);"
            "  border: 1px solid #52BE80;"
            "  color: #A8D5BA;"
            "  font-size: 11px;"
            "  border-radius: 4px;"
            "  padding: 4px;"
            "}"
            "QPushButton:hover { background: rgba(82, 190, 128, 0.3); }"
        )
        self.btn_fallback_game_mode.clicked.connect(self._on_fallback_game_mode_clicked)
        self.btn_fallback_game_mode.setVisible(False)
        fb_layout.addWidget(self.btn_fallback_game_mode)

        self.btn_fallback_exit = QPushButton("Exit Tsukiko")
        self.btn_fallback_exit.setStyleSheet(
            "QPushButton {"
            "  background: rgba(236, 112, 99, 0.15);"
            "  border: 1px solid #EC7063;"
            "  color: #FADBD8;"
            "  font-size: 11px;"
            "  border-radius: 4px;"
            "  padding: 4px;"
            "}"
            "QPushButton:hover { background: rgba(236, 112, 99, 0.3); }"
        )
        self.btn_fallback_exit.clicked.connect(self._on_fallback_exit_clicked)
        fb_layout.addWidget(self.btn_fallback_exit)

        self.fallback_frame.setVisible(False)
        sidebar_layout.addWidget(self.fallback_frame)

        # Offline privacy invariant badge at bottom of sidebar
        badge_frame = QFrame()
        badge_frame.setStyleSheet(
            "QFrame {"
            "  background-color: rgba(15, 23, 42, 0.8);"
            "  border: 1px solid rgba(168, 213, 186, 0.3);"
            "  border-radius: 6px;"
            "  padding: 8px;"
            "}"
        )
        badge_layout = QVBoxLayout(badge_frame)
        badge_layout.setContentsMargins(8, 6, 8, 6)
        badge_layout.setSpacing(2)

        badge_status = QLabel("● Offline Enforced")
        badge_status.setStyleSheet("color: #A8D5BA; font-weight: bold; font-size: 11px;")
        badge_desc = QLabel("Zero external telemetry")
        badge_desc.setStyleSheet("color: #64748B; font-size: 10px;")
        badge_layout.addWidget(badge_status)
        badge_layout.addWidget(badge_desc)
        sidebar_layout.addWidget(badge_frame)

        main_layout.addWidget(sidebar)

        # 2. Right Content Area (Stacked Views)
        content_area = QWidget()
        content_layout = QVBoxLayout(content_area)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(0)

        self.stack = QStackedWidget()
        self.stack.setObjectName("content_stack")

        # Instantiate views
        self.chat_view = ChatView()
        self.status_view = SystemStatusView(orchestrator=self._orchestrator)
        self.privacy_view = PrivacyView()
        self.memory_view = MemoryView()
        self.settings_view = SettingsView(config=self._config)

        self.stack.addWidget(self.chat_view)     # index 0: chat
        self.stack.addWidget(self.status_view)   # index 1: status
        self.stack.addWidget(self.privacy_view)  # index 2: privacy
        self.stack.addWidget(self.memory_view)   # index 3: memory
        self.stack.addWidget(self.settings_view) # index 4: settings

        content_layout.addWidget(self.stack)
        main_layout.addWidget(content_area, stretch=1)

        # Default to chat view
        self.show_chat()

    def _add_nav_button(
        self,
        layout: QVBoxLayout,
        key: str,
        icon: str,
        label: str,
    ) -> None:
        btn = NavButton(icon, label)
        btn.clicked.connect(lambda: self.show_view(key))
        self._nav_buttons[key] = btn
        layout.addWidget(btn)

    def show_view(self, key: str) -> None:
        """Switch to view by key name."""
        indices = {
            "chat": 0,
            "status": 1,
            "privacy": 2,
            "memory": 3,
            "settings": 4,
        }
        idx = indices.get(key, 0)
        self.stack.setCurrentIndex(idx)

        # Update button check states
        for k, btn in self._nav_buttons.items():
            btn.setChecked(k == key)

        # Refresh status if navigating to status view
        if key == "status":
            self.status_view.refresh_metrics()

    def show_chat(self) -> None:
        self.show_view("chat")

    def show_settings(self) -> None:
        self.show_view("settings")

    def show_status(self) -> None:
        self.show_view("status")

    def closeEvent(self, event: QCloseEvent) -> None:
        """Closing the main window hides it in tray mode, or minimizes it in fallback mode."""
        if self._tray_fallback_enabled:
            logger.info("System tray unavailable: minimizing main window instead of hiding so recovery controls remain accessible.")
            self.showMinimized()
            event.ignore()
            return

        logger.info("Main companion window closed; hiding to background companion widget.")
        self.hide()
        event.ignore()

    def enable_tray_fallback(self, widget: Optional[Any] = None) -> None:
        """Enables in-window companion controls when system tray is unavailable."""
        self._tray_fallback_enabled = True
        if widget:
            self.set_widget_controller(widget)
        self.fallback_frame.setVisible(True)

    def set_widget_controller(self, widget: Any) -> None:
        """Wires floating widget state to fallback controls."""
        self._widget = widget
        if hasattr(widget, "game_mode_activated"):
            widget.game_mode_activated.connect(self._on_widget_game_mode_entered)
        if hasattr(widget, "game_mode_deactivated"):
            widget.game_mode_deactivated.connect(self._on_widget_game_mode_exited)
        if hasattr(widget, "widget_visibility_changed"):
            widget.widget_visibility_changed.connect(self._on_widget_visibility_changed)

    def _on_widget_game_mode_entered(self) -> None:
        self.btn_fallback_game_mode.setVisible(True)
        self.btn_fallback_game_mode.setEnabled(True)
        if self._tray_fallback_enabled:
            if self.isMinimized():
                self.showNormal()
            self.show()
            self.raise_()

    def _on_widget_game_mode_exited(self) -> None:
        self.btn_fallback_game_mode.setVisible(False)
        self.btn_fallback_game_mode.setEnabled(False)

    def _on_widget_visibility_changed(self, is_visible: bool) -> None:
        if not is_visible and self._tray_fallback_enabled:
            if self.isMinimized():
                self.showNormal()
            self.show()
            self.raise_()

    def _on_fallback_restore_clicked(self) -> None:
        if self._widget:
            if hasattr(self._widget, "disable_game_mode") and getattr(self._widget, "is_game_mode", False):
                self._widget.disable_game_mode()
            if hasattr(self._widget, "show_widget"):
                self._widget.show_widget()
            else:
                self._widget.show()
            if hasattr(self._widget, "raise_"):
                self._widget.raise_()

    def _on_fallback_game_mode_clicked(self) -> None:
        if self._widget and hasattr(self._widget, "disable_game_mode"):
            self._widget.disable_game_mode()
        self.btn_fallback_game_mode.setVisible(False)

    def _on_fallback_exit_clicked(self) -> None:
        logger.info("Exit requested from main window fallback controls.")
        app = QApplication.instance()
        if app:
            app.quit()

    def apply_ui_config(self, new_config: Any) -> None:
        """Applies dynamic UI settings to the main window."""
        self._config.ui = new_config
        self.setWindowOpacity(new_config.background_opacity)
        self.setStyleSheet(
            MoonlightTheme.get_stylesheet(
                accent=new_config.accent_color,
                glow=new_config.glow_color,
                opacity=new_config.background_opacity,
            )
        )
