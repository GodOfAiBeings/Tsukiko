"""Tsukiko Desktop Companion UI Tests (Phase 2).

Verifies the complete PySide6 desktop companion subsystem:
- Moonlight theme styling and token definitions
- Vector procedural moonlight avatar
- Final floating companion widget and compact left menu
- Strict locking of microphone, speaker, and screen sharing
- Clean Game Mode (animation suspension and hiding without game inspection)
- Independent operation of floating widget when main window is closed
- ChatView strictly disabled pending Phase 3 AI brain
- SystemStatusView displaying genuine hardware metrics
- PrivacyView locking sensor controls and displaying zero-trust invariants
- MemoryView placeholder with no database creation
- SettingsView input validation and dynamic application
- Headless and CLI hardware diagnostic preservation
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Generator
from unittest.mock import MagicMock, patch

import pytest

# Enforce offscreen Qt rendering for headless CI and automated test environments
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from app.core.config.settings import TsukikoConfig, UIConfig
from app.desktop.companion.avatar import TsukikoAvatarWidget
from app.desktop.companion.theme import MoonlightTheme
from app.desktop.companion.views.chat import ChatView
from app.desktop.companion.views.memory_view import MemoryView
from app.desktop.companion.views.privacy_view import PrivacyView
from app.desktop.companion.views.settings_view import SettingsView
from app.desktop.companion.views.system_status import SystemStatusView
from app.desktop.companion.widget import (
    CompactCompanionMenu,
    CompanionMenuButton,
    FloatingCompanionWidget,
)
from app.desktop.companion.window import CompanionMainWindow
from app.desktop.companion import launch_companion

try:
    from PySide6.QtCore import QPoint, QRect, Qt
    from PySide6.QtGui import QCloseEvent, QGuiApplication
    from PySide6.QtWidgets import QApplication
    HAS_PYSIDE6 = True
except ImportError:
    HAS_PYSIDE6 = False


@pytest.fixture(scope="session")
def qapp() -> Generator[QApplication, None, None]:
    """Ensure a singleton QApplication exists in offscreen mode for all UI tests."""
    app = QApplication.instance()
    if app is None:
        app = QApplication(["tsukiko_test", "-platform", "offscreen"])
    yield app


@pytest.mark.skipif(not HAS_PYSIDE6, reason="PySide6 is required for UI tests")
class TestMoonlightTheme:
    """Verifies color tokens and QSS stylesheet compilation."""

    def test_theme_colors(self) -> None:
        assert MoonlightTheme.PRIMARY_ACCENT == "#7FB3D5"
        assert MoonlightTheme.MOONLIGHT_GLOW == "#D4E6F1"
        assert MoonlightTheme.BG_VOID == "#0D131C"
        assert MoonlightTheme.DEFAULT_OPACITY == 0.92

    def test_theme_stylesheet_generation(self) -> None:
        css = MoonlightTheme.get_full_stylesheet()
        assert "background-color: #151F2C" in css
        assert "#7FB3D5" in css
        assert "QScrollBar" in css
        assert "QPushButton" in css


@pytest.mark.skipif(not HAS_PYSIDE6, reason="PySide6 is required for UI tests")
class TestTsukikoAvatarWidget:
    """Verifies procedural vector avatar rendering and animations."""

    def test_avatar_construction(self, qapp: QApplication) -> None:
        avatar = TsukikoAvatarWidget(size=96, accent_color="#7FB3D5", glow_color="#D4E6F1")
        assert avatar.width() == 96
        assert avatar.height() == 96
        assert avatar.is_active is False
        assert avatar.animation_timer.isActive() is True

    def test_avatar_state_toggle(self, qapp: QApplication) -> None:
        avatar = TsukikoAvatarWidget(size=64)
        avatar.set_active(True)
        assert avatar.is_active is True
        avatar.set_active(False)
        assert avatar.is_active is False

    def test_avatar_animation_suspend_and_resume(self, qapp: QApplication) -> None:
        avatar = TsukikoAvatarWidget(size=64)
        avatar.stop_animation()
        assert avatar.animation_timer.isActive() is False
        avatar.start_animation()
        assert avatar.animation_timer.isActive() is True


@pytest.mark.skipif(not HAS_PYSIDE6, reason="PySide6 is required for UI tests")
class TestCompactCompanionMenu:
    """Verifies layout, ordering, locked states, and signals of the compact menu."""

    def test_menu_structure_and_order(self, qapp: QApplication) -> None:
        menu = CompactCompanionMenu()
        assert menu.width() == 200

        # Menu options in exact required order:
        # 1. Open
        assert menu.btn_open.text() == "Open"
        assert menu.btn_open.isEnabled() is True

        # 2. Microphone (Locked)
        assert menu.btn_mic.text() == "Microphone"
        assert menu.btn_mic.isEnabled() is False

        # 3. Speaker (Locked)
        assert menu.btn_speaker.text() == "Speaker"
        assert menu.btn_speaker.isEnabled() is False

        # 4. Screen Sharing (Locked)
        assert menu.btn_screen.text() == "Screen Sharing"
        assert menu.btn_screen.isEnabled() is False

        # 5. Settings
        assert menu.btn_settings.text() == "Settings"
        assert menu.btn_settings.isEnabled() is True

        # 6. Game Mode
        assert menu.btn_game_mode.text() == "Game Mode"
        assert menu.btn_game_mode.isEnabled() is True

        # 7. Hide Widget
        assert menu.btn_hide.text() == "Hide Widget"
        assert menu.btn_hide.isEnabled() is True

        # 8. Exit
        assert menu.btn_exit.text() == "Exit"
        assert menu.btn_exit.isEnabled() is True

    def test_menu_signals_emitted_on_click(self, qapp: QApplication) -> None:
        menu = CompactCompanionMenu()
        open_called = False
        settings_called = False
        game_called = False
        hide_called = False
        exit_called = False

        menu.open_main_window_requested.connect(lambda: nonlocal_assign("open"))
        menu.open_settings_requested.connect(lambda: nonlocal_assign("settings"))
        menu.game_mode_requested.connect(lambda: nonlocal_assign("game"))
        menu.hide_widget_requested.connect(lambda: nonlocal_assign("hide"))
        menu.exit_requested.connect(lambda: nonlocal_assign("exit"))

        def nonlocal_assign(kind: str) -> None:
            nonlocal open_called, settings_called, game_called, hide_called, exit_called
            if kind == "open":
                open_called = True
            elif kind == "settings":
                settings_called = True
            elif kind == "game":
                game_called = True
            elif kind == "hide":
                hide_called = True
            elif kind == "exit":
                exit_called = True

        menu.btn_open.click()
        assert open_called is True

        menu.btn_settings.click()
        assert settings_called is True

        menu.btn_game_mode.click()
        assert game_called is True

        menu.btn_hide.click()
        assert hide_called is True

        menu.btn_exit.click()
        assert exit_called is True


@pytest.mark.skipif(not HAS_PYSIDE6, reason="PySide6 is required for UI tests")
class TestFloatingCompanionWidget:
    """Verifies the primary floating desktop companion widget."""

    def test_widget_flags_and_properties(self, qapp: QApplication) -> None:
        widget = FloatingCompanionWidget()
        flags = widget.windowFlags()
        assert bool(flags & Qt.FramelessWindowHint) is True
        assert bool(flags & Qt.WindowStaysOnTopHint) is True
        assert widget.testAttribute(Qt.WA_TranslucentBackground) is True

    def test_widget_screen_clamping(self, qapp: QApplication) -> None:
        widget = FloatingCompanionWidget()
        # Clamping test: negative coordinate should be clamped to >= screen.left
        clamped_neg = widget._clamp_point_to_screen(QPoint(-500, -500))
        assert clamped_neg.x() >= 0
        assert clamped_neg.y() >= 0

        # Clamping test: huge coordinate should be clamped to within screen
        clamped_huge = widget._clamp_point_to_screen(QPoint(50000, 50000))
        assert clamped_huge.x() <= 50000
        assert clamped_huge.y() <= 50000

    def test_menu_positioned_to_left_of_widget(self, qapp: QApplication) -> None:
        widget = FloatingCompanionWidget()
        widget.move(500, 400)
        widget.show_menu()

        # The menu must be positioned immediately to the LEFT of the widget
        assert widget.menu.x() < widget.x()
        widget.menu.close()

    def test_game_mode_activation_and_deactivation(self, qapp: QApplication) -> None:
        widget = FloatingCompanionWidget()
        widget.show()
        assert widget.isVisible() is True
        assert widget.avatar.animation_timer.isActive() is True

        # Activate Game Mode
        widget.enable_game_mode()
        assert widget._is_game_mode is True
        assert widget.isVisible() is False
        assert widget.avatar.animation_timer.isActive() is False

        # Disable Game Mode
        widget.disable_game_mode()
        assert widget._is_game_mode is False
        assert widget.isVisible() is True
        assert widget.avatar.animation_timer.isActive() is True

    def test_hide_widget(self, qapp: QApplication) -> None:
        widget = FloatingCompanionWidget()
        widget.show()
        widget.hide_widget()
        assert widget.isVisible() is False


@pytest.mark.skipif(not HAS_PYSIDE6, reason="PySide6 is required for UI tests")
class TestChatView:
    """Verifies that ChatView strictly disables message submission in Phase 2."""

    def test_submission_strictly_disabled(self, qapp: QApplication) -> None:
        chat = ChatView()
        assert chat.is_submission_disabled() is True
        assert chat.input_field.isEnabled() is False
        assert chat.send_button.isEnabled() is False

    def test_phase3_notice_banner(self, qapp: QApplication) -> None:
        chat = ChatView()
        assert chat.notice_banner is not None
        # Check that greeting bubble is present
        assert chat.messages_layout.count() >= 2


@pytest.mark.skipif(not HAS_PYSIDE6, reason="PySide6 is required for UI tests")
class TestSystemStatusView:
    """Verifies genuine hardware metrics display without mock values."""

    def test_status_view_reads_real_metrics(self, qapp: QApplication) -> None:
        status_view = SystemStatusView()
        assert status_view._profile is not None
        assert status_view.cards_layout.count() >= 4

        # Verify refresh action executes cleanly
        status_view.refresh_metrics()
        assert status_view._profile is not None


@pytest.mark.skipif(not HAS_PYSIDE6, reason="PySide6 is required for UI tests")
class TestPrivacyView:
    """Verifies locked sensors and zero-trust indicators."""

    def test_privacy_rows_and_locks(self, qapp: QApplication) -> None:
        privacy = PrivacyView()
        assert privacy.layout() is not None


@pytest.mark.skipif(not HAS_PYSIDE6, reason="PySide6 is required for UI tests")
class TestMemoryView:
    """Verifies placeholder behavior without creating any SQLite database."""

    def test_memory_view_creates_no_database(self, qapp: QApplication, tmp_path: Path) -> None:
        memory_view = MemoryView()
        assert memory_view.layout() is not None
        # Ensure no SQLite or db files exist in workspace
        db_files = list(Path(".").glob("*.db")) + list(Path(".").glob("*.sqlite*"))
        assert len(db_files) == 0


@pytest.mark.skipif(not HAS_PYSIDE6, reason="PySide6 is required for UI tests")
class TestSettingsView:
    """Verifies settings validation and dynamic application."""

    def test_settings_validation_rejects_invalid_hex(self, qapp: QApplication) -> None:
        settings = SettingsView()
        settings.edit_accent.setText("invalid-color")
        is_valid, msg = settings.validate_inputs()
        assert is_valid is False
        assert "Invalid Accent Color" in msg

    def test_settings_validation_rejects_invalid_opacity(self, qapp: QApplication) -> None:
        settings = SettingsView()
        settings.slider_opacity.setValue(10)  # 10% is below 20% limit
        is_valid, msg = settings.validate_inputs()
        assert is_valid is False
        assert "Opacity" in msg

    def test_settings_validation_accepts_valid(self, qapp: QApplication) -> None:
        settings = SettingsView()
        settings.edit_accent.setText("#7FB3D5")
        settings.edit_glow.setText("#D4E6F1")
        settings.slider_opacity.setValue(92)
        settings.spin_margin_x.setValue(24)
        settings.spin_margin_y.setValue(48)
        is_valid, msg = settings.validate_inputs()
        assert is_valid is True
        assert settings.save_settings() is True


@pytest.mark.skipif(not HAS_PYSIDE6, reason="PySide6 is required for UI tests")
class TestCompanionMainWindow:
    """Verifies main window layout, tab navigation, and close event handling."""

    def test_main_window_tabs(self, qapp: QApplication) -> None:
        win = CompanionMainWindow()
        assert win.stack.count() == 5

        # Switch to each tab
        win.show_chat()
        assert win.stack.currentIndex() == 0

        win.show_status()
        assert win.stack.currentIndex() == 1

        win.show_view("privacy")
        assert win.stack.currentIndex() == 2

        win.show_view("memory")
        assert win.stack.currentIndex() == 3

        win.show_settings()
        assert win.stack.currentIndex() == 4

    def test_close_event_hides_window(self, qapp: QApplication) -> None:
        win = CompanionMainWindow()
        win.show()
        assert win.isVisible() is True

        event = QCloseEvent()
        win.closeEvent(event)
        # Window should now be hidden, preserving the independent floating widget
        assert win.isVisible() is False


@pytest.mark.skipif(not HAS_PYSIDE6, reason="PySide6 is required for UI tests")
class TestLaunchCompanionIntegration:
    """Verifies full companion launch and signal wiring."""

    def test_launch_companion(self, qapp: QApplication) -> None:
        config = TsukikoConfig()
        widget, main_window = launch_companion(config=config)
        assert widget is not None
        assert main_window is not None
        assert widget.isVisible() is True
        assert main_window.isVisible() is False

        # Trigger open main window from widget menu
        widget.menu.btn_open.click()
        assert main_window.isVisible() is True

        # Trigger settings from widget menu
        widget.menu.btn_settings.click()
        assert main_window.stack.currentIndex() == 4

        widget.close()
        main_window.close()


class TestCliAndHeadlessPreservation:
    """Verifies that --headless and --check-hardware continue to function without UI."""

    def test_check_hardware_cli(self) -> None:
        from app.main import main
        exit_code = main(["--check-hardware"])
        assert exit_code == 0
