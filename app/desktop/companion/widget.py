"""Tsukiko Desktop Companion — Final Floating Widget & Compact Menu (Phase 2).

Primary Phase 2 desktop interaction:
1. Small, transparent, frameless floating Qt window displaying Tsukiko logo/avatar.
2. Lightweight procedural QPainter rendering; no VRM, Live2D, 3D character, or GPU engine.
3. Clicking logo opens a compact vertical menu immediately to its LEFT.
4. Menu options in exact order:
   - Open: opens complete Tsukiko main application window.
   - Microphone: voice input control (locked / Phase 6).
   - Speaker: voice output control (locked / Phase 6).
   - Screen Sharing: screen capture control (locked / Phase 5).
   - Settings: opens settings section of main UI.
   - Game Mode: hides widget and suspends visual animations without game hooking/inspection.
   - Hide Widget: hides floating widget without exiting Tsukiko.
   - Exit: shuts down application cleanly.
5. Never forces itself over exclusive fullscreen games or windows.
   - Read-only OS window metadata check.
   - Relinquishes always-on-top when fullscreen foreground window is active.
   - Restores configured preference when fullscreen mode ends.
   - Fails safely by disabling always-on-top if inspection is unavailable or fails.
6. Preserves Phase 1 privacy and security invariants.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Optional

from app.core.config.settings import UIConfig, get_config
from app.desktop.companion.avatar import TsukikoAvatarWidget
from app.desktop.companion.fullscreen import FullscreenDetector, FullscreenEvaluation

logger = logging.getLogger(__name__)

try:
    from PySide6.QtCore import QPoint, QRect, QSize, QTimer, Qt, Signal
    from PySide6.QtGui import QCursor, QGuiApplication, QMouseEvent, QPainter, QPaintEvent
    from PySide6.QtWidgets import (
        QApplication,
        QFrame,
        QHBoxLayout,
        QLabel,
        QPushButton,
        QVBoxLayout,
        QWidget,
    )
    HAS_PYSIDE6 = True
except ImportError:
    HAS_PYSIDE6 = False
    QWidget = object  # type: ignore[misc,assignment]


class CompanionMenuButton(QPushButton if HAS_PYSIDE6 else object):  # type: ignore[misc]
    """Individual action button for the compact companion menu."""

    def __init__(
        self,
        icon_str: str,
        text: str,
        subtitle: Optional[str] = None,
        is_locked: bool = False,
        parent: Optional[QWidget] = None,
    ) -> None:
        if not HAS_PYSIDE6:
            raise RuntimeError("PySide6 is required to instantiate CompanionMenuButton")
        super().__init__(parent)
        self._button_text = text
        self._is_locked = is_locked
        self.setCursor(Qt.PointingHandCursor if not is_locked else Qt.ForbiddenCursor)
        self.setFixedHeight(36)
        self._setup_ui(icon_str, text, subtitle, is_locked)

    def text(self) -> str:
        return self._button_text

    def _setup_ui(
        self,
        icon_str: str,
        text: str,
        subtitle: Optional[str],
        is_locked: bool,
    ) -> None:
        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 4, 10, 4)
        layout.setSpacing(10)

        # Icon
        icon_lbl = QLabel(icon_str)
        icon_lbl.setStyleSheet("font-size: 14px; background: transparent;")
        layout.addWidget(icon_lbl)

        # Label
        text_lbl = QLabel(text)
        text_lbl.setStyleSheet(
            "font-size: 12px; font-weight: 500; background: transparent; "
            + ("color: #F8FAFC;" if not is_locked else "color: #64748B;")
        )
        layout.addWidget(text_lbl, stretch=1)

        # Optional locked badge or subtitle
        if subtitle:
            sub_lbl = QLabel(subtitle)
            sub_lbl.setStyleSheet(
                "font-size: 10px; font-weight: 600; background: transparent; "
                + ("color: #7FB3D5;" if not is_locked else "color: #64748B;")
            )
            layout.addWidget(sub_lbl)

        # Button Styling
        if is_locked:
            self.setEnabled(False)
            self.setStyleSheet(
                "QPushButton {"
                "  background-color: transparent;"
                "  border: none;"
                "  border-radius: 6px;"
                "}"
            )
        else:
            self.setStyleSheet(
                "QPushButton {"
                "  background-color: transparent;"
                "  border: 1px solid transparent;"
                "  border-radius: 6px;"
                "  text-align: left;"
                "}"
                "QPushButton:hover {"
                "  background-color: rgba(127, 179, 213, 0.18);"
                "  border: 1px solid rgba(127, 179, 213, 0.35);"
                "}"
                "QPushButton:pressed {"
                "  background-color: rgba(127, 179, 213, 0.28);"
                "}"
            )


class CompactCompanionMenu(QWidget):
    """Compact vertical menu positioned immediately to the left of the floating companion.
    
    Opens on logo click; closes smoothly when clicking outside or selecting an action.
    """

    if HAS_PYSIDE6:
        open_main_window_requested = Signal()
        open_settings_requested = Signal()
        game_mode_requested = Signal()
        hide_widget_requested = Signal()
        exit_requested = Signal()

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        if not HAS_PYSIDE6:
            raise RuntimeError("PySide6 is required to instantiate CompactCompanionMenu")
        super().__init__(
            parent,
            Qt.Popup | Qt.FramelessWindowHint | Qt.NoDropShadowWindowHint,
        )
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setObjectName("CompactCompanionMenu")
        self.setFixedWidth(200)
        self._init_ui()

    def _init_ui(self) -> None:
        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.setSpacing(0)

        # Translucent styled container frame
        frame = QFrame(self)
        frame.setObjectName("menu_frame")
        frame.setStyleSheet(
            "QFrame#menu_frame {"
            "  background-color: rgba(15, 23, 42, 0.95);"
            "  border: 1px solid rgba(127, 179, 213, 0.45);"
            "  border-radius: 10px;"
            "}"
        )
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(6, 8, 6, 8)
        layout.setSpacing(2)

        # 1. Open — opens complete Tsukiko main application window
        self.btn_open = CompanionMenuButton("🌕", "Open", "Main UI")
        self.btn_open.clicked.connect(self._on_open)
        layout.addWidget(self.btn_open)

        # 2. Microphone — voice input control (Locked - Phase 6)
        self.btn_mic = CompanionMenuButton("🎤", "Microphone", "Phase 6", is_locked=True)
        self.btn_mic.setToolTip("Voice input is locked until Phase 6 implementation.")
        layout.addWidget(self.btn_mic)

        # 3. Speaker — Tsukiko voice output control (Locked - Phase 6)
        self.btn_speaker = CompanionMenuButton("🔊", "Speaker", "Phase 6", is_locked=True)
        self.btn_speaker.setToolTip("Voice output is locked until Phase 6 implementation.")
        layout.addWidget(self.btn_speaker)

        # 4. Screen Sharing — explicit screen-sharing control (Locked - Phase 5)
        self.btn_screen = CompanionMenuButton("🖥️", "Screen Sharing", "Phase 5", is_locked=True)
        self.btn_screen.setToolTip("Screen perception is locked until Phase 5 implementation.")
        layout.addWidget(self.btn_screen)

        # Separator line
        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setStyleSheet("background-color: rgba(127, 179, 213, 0.2); max-height: 1px; margin: 4px 6px;")
        layout.addWidget(sep)

        # 5. Settings — opens settings interface
        self.btn_settings = CompanionMenuButton("⚙️", "Settings")
        self.btn_settings.clicked.connect(self._on_settings)
        layout.addWidget(self.btn_settings)

        # 6. Game Mode — hides widget and suspends visual activity
        self.btn_game_mode = CompanionMenuButton("🎮", "Game Mode")
        self.btn_game_mode.clicked.connect(self._on_game_mode)
        layout.addWidget(self.btn_game_mode)

        # 7. Hide Widget — hides floating widget without exiting Tsukiko
        self.btn_hide = CompanionMenuButton("👁️", "Hide Widget")
        self.btn_hide.clicked.connect(self._on_hide_widget)
        layout.addWidget(self.btn_hide)

        # Separator line
        sep2 = QFrame()
        sep2.setFrameShape(QFrame.HLine)
        sep2.setStyleSheet("background-color: rgba(127, 179, 213, 0.2); max-height: 1px; margin: 4px 6px;")
        layout.addWidget(sep2)

        # 8. Exit — shuts down entire application cleanly
        self.btn_exit = CompanionMenuButton("🚪", "Exit", "Quit")
        self.btn_exit.clicked.connect(self._on_exit)
        layout.addWidget(self.btn_exit)

        outer_layout.addWidget(frame)

    def _on_open(self) -> None:
        self.close()
        self.open_main_window_requested.emit()

    def _on_settings(self) -> None:
        self.close()
        self.open_settings_requested.emit()

    def _on_game_mode(self) -> None:
        self.close()
        self.game_mode_requested.emit()

    def _on_hide_widget(self) -> None:
        self.close()
        self.hide_widget_requested.emit()

    def _on_exit(self) -> None:
        self.close()
        self.exit_requested.emit()


class FloatingCompanionWidget(QWidget):
    """Small Tsukiko logo/avatar floating transparent Qt window.
    
    Primary Phase 2 desktop interaction:
    - Independent transparent frameless window.
    - Clicking logo opens CompactCompanionMenu immediately to its LEFT.
    - Draggable across desktop; clamped to available screen boundaries.
    - Never forces itself over fullscreen exclusive games or windows.
    - Fullscreen detector automatically removes always-on-top when fullscreen app is foreground.
    - Restores user's configured preference when fullscreen mode exits.
    - Safe fail-closed behavior: disables always-on-top if detection fails.
    """

    if HAS_PYSIDE6:
        open_main_requested = Signal()
        open_settings_requested = Signal()
        game_mode_activated = Signal()
        game_mode_deactivated = Signal()
        widget_visibility_changed = Signal(bool)
        exit_requested = Signal()

    def __init__(
        self,
        config: Optional[UIConfig] = None,
        parent: Optional[QWidget] = None,
    ) -> None:
        if not HAS_PYSIDE6:
            raise RuntimeError("PySide6 is required to instantiate FloatingCompanionWidget")

        self.ui_config: UIConfig = config or get_config().ui
        self._size = self.ui_config.companion_size

        # Determine initial window flags based on configuration
        initial_flags = Qt.FramelessWindowHint | Qt.Tool | Qt.SubWindow
        if self.ui_config.always_on_top:
            initial_flags |= Qt.WindowStaysOnTopHint

        super().__init__(parent, initial_flags)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setObjectName("FloatingCompanionWidget")
        self.resize(self._size, self._size)

        # State tracking
        self._is_game_mode: bool = False
        self._is_hidden: bool = False
        self._effective_always_on_top: bool = self.ui_config.always_on_top

        # Drag state tracking
        self._drag_start_pos: Optional[QPoint] = None
        self._mouse_press_pos: Optional[QPoint] = None
        self._is_dragging: bool = False

        # Fullscreen detection engine (safe read-only OS metadata)
        self._fullscreen_detector = FullscreenDetector()
        self._fullscreen_timer = QTimer(self)
        self._fullscreen_timer.timeout.connect(self._check_fullscreen_policy)

        # Compact menu positioned to the left
        self.menu = CompactCompanionMenu()
        self.menu.open_main_window_requested.connect(self._handle_open_main)
        self.menu.open_settings_requested.connect(self._handle_open_settings)
        self.menu.game_mode_requested.connect(self.enable_game_mode)
        self.menu.hide_widget_requested.connect(self.hide_widget)
        self.menu.exit_requested.connect(self._handle_exit)

        self._setup_ui()
        self._position_to_initial_corner()

        # Start periodic fullscreen evaluation
        self._fullscreen_timer.start(1000)
        self._check_fullscreen_policy()

    @property
    def is_game_mode(self) -> bool:
        return self._is_game_mode

    @property
    def is_hidden(self) -> bool:
        return self._is_hidden

    @property
    def effective_always_on_top(self) -> bool:
        return self._effective_always_on_top

    @property
    def fullscreen_detector(self) -> FullscreenDetector:
        return self._fullscreen_detector

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Procedural vector avatar logo (respects fps & idle_animation config)
        self.avatar = TsukikoAvatarWidget(
            size=self._size,
            accent_color=self.ui_config.accent_color,
            glow_color=self.ui_config.glow_color,
            active=False,
            fps=self.ui_config.fps,
            idle_animation=self.ui_config.idle_animation,
            parent=self,
        )
        layout.addWidget(self.avatar)
        self.setCursor(Qt.PointingHandCursor)

    def closeEvent(self, event: Any) -> None:
        self._fullscreen_timer.stop()
        self.avatar.stop_animation()
        if hasattr(self, "menu") and self.menu:
            self.menu.close()
        super().closeEvent(event)

    def _check_fullscreen_policy(self) -> FullscreenEvaluation:
        """Inspects foreground window geometry in read-only manner and adjusts always-on-top.
        
        Invariant:
        - If foreground window is fullscreen: remove always-on-top and lower widget.
        - If foreground window is NOT fullscreen: restore user's configured always_on_top preference.
        - If detection fails or is unavailable: fail safely by removing always-on-top.
        """
        eval_result = self._fullscreen_detector.evaluate_fullscreen(own_pids={os.getpid()})

        # Calculate target always-on-top state
        target_always_on_top = eval_result.safe_always_on_top and self.ui_config.always_on_top

        # Apply state transition if changed
        if target_always_on_top != self._effective_always_on_top:
            self._set_effective_always_on_top(target_always_on_top)

        # If a fullscreen application is active, ensure we do not sit over it
        if eval_result.is_fullscreen and self.isVisible():
            self.lower()

        return eval_result

    def _set_effective_always_on_top(self, enabled: bool) -> None:
        """Applies WindowStaysOnTopHint flag change cleanly without unintended hiding."""
        if self._effective_always_on_top == enabled:
            return

        self._effective_always_on_top = enabled
        was_visible = self.isVisible() and not self._is_hidden and not self._is_game_mode

        self.setWindowFlag(Qt.WindowStaysOnTopHint, enabled)
        if was_visible:
            self.show()

    def set_always_on_top(self, enabled: bool) -> None:
        """Updates user's always_on_top preference and applies fullscreen safety check."""
        self.ui_config.always_on_top = enabled
        self._check_fullscreen_policy()

    def apply_ui_config(self, new_config: UIConfig) -> None:
        """Dynamically applies updated UIConfig settings in memory."""
        self.ui_config = new_config

        # Update avatar palette
        self.avatar.set_palette(new_config.accent_color, new_config.glow_color)
        self.avatar._fps = max(10, min(60, new_config.fps))
        self.avatar._idle_animation = new_config.idle_animation
        self.avatar._sync_animation_state()

        # Reposition widget based on corner and margins
        self._position_to_corner(
            new_config.default_corner,
            new_config.margin_x,
            new_config.margin_y,
        )

        # Re-evaluate always on top policy with new user preference
        self._check_fullscreen_policy()

    def _position_to_corner(self, corner: str, mx: int, my: int) -> None:
        """Position widget in specified desktop corner with custom margins."""
        screen = QGuiApplication.primaryScreen()
        if not screen:
            return

        geo = screen.availableGeometry()

        if corner == "bottom-right":
            x = geo.right() - self._size - mx
            y = geo.bottom() - self._size - my
        elif corner == "bottom-left":
            x = geo.left() + mx
            y = geo.bottom() - self._size - my
        elif corner == "top-left":
            x = geo.left() + mx
            y = geo.top() + my
        elif corner == "top-right":
            x = geo.right() - self._size - mx
            y = geo.top() + my
        else:
            x = geo.right() - self._size - mx
            y = geo.bottom() - self._size - my

        self.move(self._clamp_point_to_screen(QPoint(x, y)))

    def _position_to_initial_corner(self) -> None:
        """Position widget in the configured desktop corner with margins."""
        self._position_to_corner(
            self.ui_config.default_corner,
            self.ui_config.margin_x,
            self.ui_config.margin_y,
        )

    def _clamp_point_to_screen(self, pos: QPoint) -> QPoint:
        """Clamp position so widget stays completely within available screen boundaries."""
        screen = QGuiApplication.primaryScreen()
        if not screen:
            return pos

        geo = screen.availableGeometry()
        max_x = geo.right() - self.width()
        max_y = geo.bottom() - self.height()

        clamped_x = max(geo.left(), min(pos.x(), max_x))
        clamped_y = max(geo.top(), min(pos.y(), max_y))
        return QPoint(clamped_x, clamped_y)

    def mousePressEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.LeftButton:
            self._drag_start_pos = event.globalPosition().toPoint() - self.frameGeometry().topLeft()
            self._mouse_press_pos = event.globalPosition().toPoint()
            self._is_dragging = False
            event.accept()
        elif event.button() == Qt.RightButton:
            self.toggle_menu()
            event.accept()
        else:
            super().mousePressEvent(event)

    def mouseMoveEvent(self, event: QMouseEvent) -> None:
        if event.buttons() & Qt.LeftButton and self._drag_start_pos:
            current_pos = event.globalPosition().toPoint()
            if self._mouse_press_pos and (current_pos - self._mouse_press_pos).manhattanLength() > 5:
                self._is_dragging = True
                new_pos = current_pos - self._drag_start_pos
                self.move(self._clamp_point_to_screen(new_pos))
            event.accept()
        else:
            super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.LeftButton:
            if not self._is_dragging:
                self.toggle_menu()
            self._drag_start_pos = None
            self._mouse_press_pos = None
            self._is_dragging = False
            event.accept()
        else:
            super().mouseReleaseEvent(event)

    def toggle_menu(self) -> None:
        """Toggle compact menu positioned immediately to the LEFT of this widget."""
        if self.menu.isVisible():
            self.menu.close()
        else:
            self.show_menu()

    def show_menu(self) -> None:
        """Show compact menu positioned immediately to the LEFT of the widget."""
        screen = QGuiApplication.primaryScreen()
        screen_geo = screen.availableGeometry() if screen else QRect(0, 0, 1920, 1080)

        menu_w = self.menu.width()
        menu_h = self.menu.sizeHint().height()

        # Calculate position to the LEFT of the widget
        target_x = self.x() - menu_w - 8
        target_y = self.y() + (self.height() // 2) - (menu_h // 2)

        # Boundary checks: if left edge is clipped, place immediately to the RIGHT
        if target_x < screen_geo.left():
            target_x = self.x() + self.width() + 8

        # Clamp vertical position to stay within screen
        if target_y + menu_h > screen_geo.bottom():
            target_y = screen_geo.bottom() - menu_h
        if target_y < screen_geo.top():
            target_y = screen_geo.top()

        self.menu.move(target_x, target_y)
        self.menu.show()
        self.menu.raise_()
        self.menu.activateWindow()

    def enable_game_mode(self) -> None:
        """Activates Game Mode: hides the widget and suspends visual animations.
        
        Does not interact with games, inspect processes, inject code, or install hooks.
        """
        logger.info("Game Mode activated: suspending animations and hiding widget.")
        self._is_game_mode = True
        self.avatar.stop_animation()
        self._fullscreen_timer.stop()
        self.hide()
        self.menu.close()
        self.game_mode_activated.emit()

    def disable_game_mode(self) -> None:
        """Exits Game Mode: restores widget visibility and resumes animations."""
        logger.info("Exiting Game Mode: restoring widget and animations.")
        self._is_game_mode = False
        self.avatar.set_animated(True)
        self._fullscreen_timer.start(1000)
        if not self._is_hidden:
            self.show()
            self._check_fullscreen_policy()
        self.game_mode_deactivated.emit()

    def hide_widget(self) -> None:
        """Hides the floating widget without exiting Tsukiko."""
        logger.info("Hiding Tsukiko companion widget.")
        self._is_hidden = True
        self.menu.close()
        self.hide()
        self.widget_visibility_changed.emit(False)

    def show_widget(self) -> None:
        """Restores visibility of the companion widget."""
        logger.info("Showing Tsukiko companion widget.")
        self._is_hidden = False
        if self._is_game_mode:
            self.disable_game_mode()
        else:
            self.show()
            self.avatar._sync_animation_state()
            self._check_fullscreen_policy()
        self.widget_visibility_changed.emit(True)

    def _handle_open_main(self) -> None:
        self.open_main_requested.emit()

    def _handle_open_settings(self) -> None:
        self.open_settings_requested.emit()

    def _handle_exit(self) -> None:
        logger.info("Exit requested from companion menu.")
        self.exit_requested.emit()
        app = QApplication.instance()
        if app:
            app.quit()
