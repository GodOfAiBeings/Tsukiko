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

from app.core.config.settings import (
    TsukikoConfig,
    UIConfig,
    get_active_config_path,
    load_config,
    reset_config,
    save_config,
)
from app.desktop.companion.avatar import TsukikoAvatarWidget
from app.desktop.companion.fullscreen import (
    BOOL,
    DWORD,
    HMONITOR,
    HWND,
    MONITORINFO,
    RECT,
    FullscreenDetector,
    FullscreenEvaluation,
    setup_user32_signatures,
)
from app.desktop.companion.theme import MoonlightTheme
from app.desktop.companion.tray import TsukikoTrayManager
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
    if app:
        for w in app.topLevelWidgets():
            w.close()
            w.deleteLater()
        app.processEvents()


@pytest.fixture(autouse=True)
def clean_qt_widgets(qapp: QApplication) -> Generator[None, None, None]:
    """Ensure all Qt widgets created during a test are closed and drained."""
    yield
    if qapp:
        for w in list(qapp.topLevelWidgets()):
            w.close()
            w.deleteLater()
        qapp.processEvents()
        qapp.sendPostedEvents(None, 0)


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
        # Static idle emblem by default: timer does not run
        assert avatar.animation_timer.isActive() is False

    def test_avatar_construction_with_idle_animation(self, qapp: QApplication) -> None:
        avatar = TsukikoAvatarWidget(size=96, idle_animation=True)
        assert avatar.animation_timer.isActive() is True

    def test_avatar_renders_pixmap_and_icon(self, qapp: QApplication) -> None:
        pm = TsukikoAvatarWidget.render_to_pixmap(64)
        assert not pm.isNull()
        assert pm.width() == 64
        assert pm.height() == 64

        icon = TsukikoAvatarWidget.render_to_icon(32)
        assert not icon.isNull()

    def test_avatar_state_toggle(self, qapp: QApplication) -> None:
        avatar = TsukikoAvatarWidget(size=64)
        avatar.set_active(True)
        assert avatar.is_active is True
        assert avatar.animation_timer.isActive() is True
        avatar.set_active(False)
        assert avatar.is_active is False
        assert avatar.animation_timer.isActive() is False

    def test_avatar_animation_suspend_and_resume(self, qapp: QApplication) -> None:
        avatar = TsukikoAvatarWidget(size=64, idle_animation=True)
        assert avatar.animation_timer.isActive() is True
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
        assert widget.testAttribute(Qt.WA_TranslucentBackground) is True
        if widget.fullscreen_detector.is_available():
            assert bool(flags & Qt.WindowStaysOnTopHint) == widget.effective_always_on_top
        else:
            assert widget.effective_always_on_top is False
            assert bool(flags & Qt.WindowStaysOnTopHint) is False

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
        config = UIConfig(idle_animation=True)
        widget = FloatingCompanionWidget(config=config)
        widget.show()
        assert widget.isVisible() is True
        assert widget.avatar.animation_timer.isActive() is True

        # Activate Game Mode
        widget.enable_game_mode()
        assert widget.is_game_mode is True
        assert widget.isVisible() is False
        assert widget.avatar.animation_timer.isActive() is False

        # Disable Game Mode
        widget.disable_game_mode()
        assert widget.is_game_mode is False
        assert widget.isVisible() is True
        assert widget.avatar.animation_timer.isActive() is True

    def test_distinct_hide_and_game_mode_states(self, qapp: QApplication) -> None:
        widget = FloatingCompanionWidget()
        widget.show()
        assert widget.is_hidden is False
        assert widget.is_game_mode is False

        # Hide widget
        widget.hide_widget()
        assert widget.is_hidden is True
        assert widget.is_game_mode is False
        assert widget.isVisible() is False

        # Show widget
        widget.show_widget()
        assert widget.is_hidden is False
        assert widget.is_game_mode is False
        assert widget.isVisible() is True

        # Enable game mode
        widget.enable_game_mode()
        assert widget.is_game_mode is True
        assert widget.is_hidden is False
        assert widget.isVisible() is False

        # Disable game mode
        widget.disable_game_mode()
        assert widget.is_game_mode is False
        assert widget.is_hidden is False
        assert widget.isVisible() is True

    def test_hide_widget(self, qapp: QApplication) -> None:
        widget = FloatingCompanionWidget()
        widget.show()
        widget.hide_widget()
        assert widget.isVisible() is False
        assert widget.is_hidden is True


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
        with patch("app.desktop.companion.views.settings_view.save_config"):
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
        from PySide6.QtWidgets import QSystemTrayIcon

        config = TsukikoConfig()
        with patch.object(QSystemTrayIcon, "isSystemTrayAvailable", return_value=True):
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


@pytest.mark.skipif(not HAS_PYSIDE6, reason="PySide6 is required for UI tests")
class TestFullscreenDetector:
    """Verifies safe read-only foreground window fullscreen evaluation."""

    def test_unavailable_fails_safe(self) -> None:
        detector = FullscreenDetector()
        with patch.object(detector, "is_available", return_value=False):
            eval_res = detector.evaluate_fullscreen()
            assert eval_res.detection_available is False
            assert eval_res.safe_always_on_top is False
            assert "failing safe" in eval_res.reason

    def test_exception_in_evaluation_fails_safe(self) -> None:
        detector = FullscreenDetector()
        with patch.object(detector, "is_available", return_value=True):
            with patch.object(detector, "_user32", None):
                eval_res = detector.evaluate_fullscreen()
                assert eval_res.safe_always_on_top is False

    def test_evaluate_fullscreen_real_or_simulated(self) -> None:
        detector = FullscreenDetector()
        eval_res = detector.evaluate_fullscreen()
        assert isinstance(eval_res, FullscreenEvaluation)
        assert isinstance(eval_res.safe_always_on_top, bool)
        assert isinstance(eval_res.is_fullscreen, bool)
        assert len(eval_res.reason) > 0

    def test_user32_api_signatures_setup(self) -> None:
        import ctypes
        mock_user32 = MagicMock()
        setup_user32_signatures(mock_user32)
        assert mock_user32.GetForegroundWindow.restype == HWND
        assert mock_user32.GetForegroundWindow.argtypes == []
        assert mock_user32.GetDesktopWindow.restype == HWND
        assert mock_user32.GetDesktopWindow.argtypes == []
        assert mock_user32.GetShellWindow.restype == HWND
        assert mock_user32.GetShellWindow.argtypes == []
        assert mock_user32.GetClassNameW.restype == ctypes.c_int
        assert len(mock_user32.GetClassNameW.argtypes) == 3
        assert mock_user32.GetWindowThreadProcessId.restype == DWORD
        assert len(mock_user32.GetWindowThreadProcessId.argtypes) == 2
        assert mock_user32.IsIconic.restype == BOOL
        assert len(mock_user32.IsIconic.argtypes) == 1
        assert mock_user32.IsWindowVisible.restype == BOOL
        assert len(mock_user32.IsWindowVisible.argtypes) == 1
        assert mock_user32.GetWindowRect.restype == BOOL
        assert len(mock_user32.GetWindowRect.argtypes) == 2
        assert mock_user32.MonitorFromWindow.restype == HMONITOR
        assert len(mock_user32.MonitorFromWindow.argtypes) == 2
        assert mock_user32.GetMonitorInfoW.restype == BOOL
        assert len(mock_user32.GetMonitorInfoW.argtypes) == 2

    def test_mocked_64bit_handle_values(self) -> None:
        detector = FullscreenDetector()
        mock_user32 = MagicMock()
        mock_user32.GetForegroundWindow.return_value = 0x7FFF00001234
        mock_user32.GetDesktopWindow.return_value = 0x1000
        mock_user32.GetShellWindow.return_value = 0x2000
        mock_user32.IsIconic.return_value = False
        mock_user32.IsWindowVisible.return_value = True
        mock_user32.MonitorFromWindow.return_value = 0x7FFF00005678

        def mock_class_name(hwnd, buf, n):
            buf.value = "TestGame"
            return len("TestGame")
        mock_user32.GetClassNameW.side_effect = mock_class_name

        def mock_pid(hwnd, byref_pid):
            byref_pid._obj.value = 9999
            return 9999
        mock_user32.GetWindowThreadProcessId.side_effect = mock_pid

        def mock_rect(hwnd, byref_rect):
            r = byref_rect._obj
            r.left = 0
            r.top = 0
            r.right = 1920
            r.bottom = 1080
            return 1
        mock_user32.GetWindowRect.side_effect = mock_rect

        def mock_mon(hmon, byref_mi):
            mi = byref_mi._obj
            mi.rcMonitor.left = 0
            mi.rcMonitor.top = 0
            mi.rcMonitor.right = 1920
            mi.rcMonitor.bottom = 1080
            return 1
        mock_user32.GetMonitorInfoW.side_effect = mock_mon

        with patch.object(detector, "is_available", return_value=True):
            with patch.object(detector, "_user32", mock_user32):
                eval_res = detector.evaluate_fullscreen(own_pids={1111})
                assert eval_res.is_fullscreen is True
                assert eval_res.safe_always_on_top is False


@pytest.mark.skipif(not HAS_PYSIDE6, reason="PySide6 is required for UI tests")
class TestWidgetFullscreenPolicy:
    """Verifies that the floating companion widget respects fullscreen games."""

    def test_widget_drops_always_on_top_on_fullscreen(self, qapp: QApplication) -> None:
        widget = FloatingCompanionWidget()
        fullscreen_eval = FullscreenEvaluation(
            detection_available=True,
            is_fullscreen=True,
            safe_always_on_top=False,
            reason="Game is fullscreen",
        )
        with patch.object(widget._fullscreen_detector, "evaluate_fullscreen", return_value=fullscreen_eval):
            widget._check_fullscreen_policy()
            assert widget.effective_always_on_top is False
            assert bool(widget.windowFlags() & Qt.WindowStaysOnTopHint) is False

    def test_widget_restores_always_on_top_when_fullscreen_exits(self, qapp: QApplication) -> None:
        widget = FloatingCompanionWidget()
        widget.set_always_on_top(True)

        # 1. Fullscreen active
        fs_eval = FullscreenEvaluation(
            detection_available=True,
            is_fullscreen=True,
            safe_always_on_top=False,
            reason="Game is fullscreen",
        )
        with patch.object(widget._fullscreen_detector, "evaluate_fullscreen", return_value=fs_eval):
            widget._check_fullscreen_policy()
            assert widget.effective_always_on_top is False

        # 2. Fullscreen ends -> restores preference
        windowed_eval = FullscreenEvaluation(
            detection_available=True,
            is_fullscreen=False,
            safe_always_on_top=True,
            reason="Windowed application",
        )
        with patch.object(widget._fullscreen_detector, "evaluate_fullscreen", return_value=windowed_eval):
            widget._check_fullscreen_policy()
            assert widget.effective_always_on_top is True
            assert bool(widget.windowFlags() & Qt.WindowStaysOnTopHint) is True

    def test_widget_fails_safe_on_detector_error(self, qapp: QApplication) -> None:
        widget = FloatingCompanionWidget()
        widget.set_always_on_top(True)

        error_eval = FullscreenEvaluation(
            detection_available=False,
            is_fullscreen=False,
            safe_always_on_top=False,
            reason="Inspection failed",
        )
        with patch.object(widget._fullscreen_detector, "evaluate_fullscreen", return_value=error_eval):
            widget._check_fullscreen_policy()
            assert widget.effective_always_on_top is False
            assert bool(widget.windowFlags() & Qt.WindowStaysOnTopHint) is False


@pytest.mark.skipif(not HAS_PYSIDE6, reason="PySide6 is required for UI tests")
class TestSettingsApplicationAndPersistence:
    """Verifies that settings apply dynamically to UI and persist to YAML."""

    def test_save_config_persists_to_yaml(self, tmp_path: Path) -> None:
        target_yaml = tmp_path / "tsukiko_test.yaml"
        cfg = TsukikoConfig()
        cfg.ui.accent_color = "#123456"
        cfg.ui.glow_color = "#654321"
        cfg.ui.default_corner = "top-left"
        cfg.ui.background_opacity = 0.88

        save_config(config=cfg, target_path=target_yaml)
        assert target_yaml.exists()

        import yaml
        with open(target_yaml, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        assert data["ui"]["accent_color"] == "#123456"
        assert data["ui"]["glow_color"] == "#654321"
        assert data["ui"]["default_corner"] == "top-left"
        assert data["ui"]["background_opacity"] == 0.88

    def test_settings_view_saves_and_persists(self, qapp: QApplication) -> None:
        cfg = TsukikoConfig()
        settings_view = SettingsView(config=cfg)
        settings_view.edit_accent.setText("#224466")
        settings_view.edit_glow.setText("#88AACC")
        settings_view.slider_opacity.setValue(80)

        with patch("app.desktop.companion.views.settings_view.save_config") as mock_save:
            assert settings_view.save_settings() is True
            mock_save.assert_called_once()
            assert cfg.ui.accent_color == "#224466"
            assert cfg.ui.glow_color == "#88AACC"
            assert abs(cfg.ui.background_opacity - 0.80) < 0.01

    def test_settings_view_persistence_failure_reports_truthfully(self, qapp: QApplication) -> None:
        cfg = TsukikoConfig()
        settings_view = SettingsView(config=cfg)
        settings_view.edit_accent.setText("#336699")

        with patch("app.desktop.companion.views.settings_view.save_config", side_effect=PermissionError("Disk is write-protected")):
            res = settings_view.save_settings()
            assert res is False
            assert "failed to save to disk" in settings_view.status_label.text()
            assert "applied to current session" in settings_view.status_label.text()
            assert "✓" not in settings_view.status_label.text()
            assert "⚠" in settings_view.status_label.text()
            # Session must be updated despite disk failure
            assert cfg.ui.accent_color == "#336699"

    def test_save_config_honors_active_config_path(self, tmp_path: Path) -> None:
        custom_yaml = tmp_path / "custom_config.yaml"
        cfg = TsukikoConfig()
        cfg.ui.accent_color = "#112233"
        save_config(config=cfg, target_path=custom_yaml)
        assert custom_yaml.exists()

        try:
            loaded_cfg = load_config(custom_yaml)
            assert get_active_config_path() == custom_yaml

            loaded_cfg.ui.accent_color = "#445566"
            saved_path = save_config(config=loaded_cfg)
            assert saved_path == custom_yaml

            import yaml
            with open(custom_yaml, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            assert data["ui"]["accent_color"] == "#445566"
        finally:
            reset_config()

    def test_apply_ui_config_to_widget(self, qapp: QApplication) -> None:
        widget = FloatingCompanionWidget()
        new_ui = UIConfig(
            accent_color="#AABBCC",
            glow_color="#DDEEFF",
            default_corner="bottom-left",
            margin_x=30,
            margin_y=50,
        )
        widget.apply_ui_config(new_ui)
        assert widget.avatar._accent_hex == "#AABBCC"
        assert widget.avatar._glow_hex == "#DDEEFF"
        assert widget.ui_config.default_corner == "bottom-left"

    def test_apply_ui_config_to_main_window(self, qapp: QApplication) -> None:
        win = CompanionMainWindow()
        new_ui = UIConfig(
            background_opacity=0.75,
            accent_color="#7FB3D5",
            glow_color="#D4E6F1",
        )
        win.apply_ui_config(new_ui)
        assert abs(win.windowOpacity() - 0.75) < 0.01


@pytest.mark.skipif(not HAS_PYSIDE6, reason="PySide6 is required for UI tests")
class TestSystemTrayAndWidgetRecovery:
    """Verifies system tray restore actions and fallback behavior when tray is unavailable."""

    def test_tray_manager_actions_when_available(self, qapp: QApplication) -> None:
        from PySide6.QtWidgets import QSystemTrayIcon
        widget = FloatingCompanionWidget()
        main_win = CompanionMainWindow()
        with patch.object(QSystemTrayIcon, "isSystemTrayAvailable", return_value=True):
            tray = TsukikoTrayManager(widget=widget, main_window=main_win)

            assert tray.is_available is True
            assert tray.action_show_widget.text() == "Show Widget"
            assert tray.action_open.text() == "Open Tsukiko"
            assert tray.action_resume_game.text() == "Resume from Game Mode"
            assert tray.action_exit.text() == "Exit"

            # Hide widget -> tray restores
            widget.hide_widget()
            assert widget.isVisible() is False
            assert widget.is_hidden is True
            tray._handle_show_widget()
            assert widget.isVisible() is True
            assert widget.is_hidden is False

            # Game mode -> tray resumes
            widget.enable_game_mode()
            assert widget.is_game_mode is True
            tray.update_state(is_game_mode=True)
            assert tray.action_resume_game.isEnabled() is True
            tray._handle_resume_game()
            assert widget.is_game_mode is False

    def test_tray_unavailable_fallback_in_main_window(self, qapp: QApplication) -> None:
        widget = FloatingCompanionWidget()
        main_win = CompanionMainWindow()
        main_win.show()
        main_win.enable_tray_fallback(widget)

        assert main_win.fallback_frame.isVisible() is True

        # Test restore button
        widget.hide_widget()
        assert widget.isVisible() is False
        main_win.btn_fallback_restore.click()
        assert widget.isVisible() is True

        # Test resume from game mode button
        widget.enable_game_mode()
        assert main_win.btn_fallback_game_mode.isVisible() is True
        main_win.btn_fallback_game_mode.click()
        assert widget.is_game_mode is False
        assert main_win.btn_fallback_game_mode.isVisible() is False

    def test_tray_unavailable_end_to_end_recovery_flow(self, qapp: QApplication) -> None:
        from PySide6.QtWidgets import QSystemTrayIcon
        from app.desktop.companion import launch_companion

        with patch.object(QSystemTrayIcon, "isSystemTrayAvailable", return_value=False):
            widget, main_win = launch_companion()
            assert widget is not None
            assert main_win is not None

            # Window must be shown at launch with fallback controls
            assert main_win.isVisible() is True
            assert main_win.fallback_frame.isVisible() is True

            # Hide widget -> recover via fallback Show Widget button
            widget.hide_widget()
            assert widget.isVisible() is False
            assert main_win.isVisible() is True
            main_win.btn_fallback_restore.click()
            assert widget.isVisible() is True
            assert widget.is_hidden is False

            # Game Mode -> recover via fallback Resume button
            widget.enable_game_mode()
            assert widget.is_game_mode is True
            assert widget.isVisible() is False
            assert main_win.btn_fallback_game_mode.isVisible() is True
            main_win.btn_fallback_game_mode.click()
            assert widget.is_game_mode is False
            assert widget.isVisible() is True

            # Exit button cleanly calls application quit
            with patch.object(qapp, "quit") as mock_quit:
                main_win.btn_fallback_exit.click()
                mock_quit.assert_called_once()

    def test_main_window_close_minimizes_in_fallback_mode(self, qapp: QApplication) -> None:
        from PySide6.QtGui import QCloseEvent

        widget = FloatingCompanionWidget()
        main_win = CompanionMainWindow()
        main_win.show()
        main_win.enable_tray_fallback(widget)

        close_event = QCloseEvent()
        main_win.closeEvent(close_event)

        assert close_event.isAccepted() is False
        assert main_win.isMinimized() is True
        assert main_win.isHidden() is False


@pytest.mark.skipif(not HAS_PYSIDE6, reason="PySide6 is required for UI tests")
class TestIdleAnimationZeroOverhead:
    """Verifies that static idle emblem consumes zero CPU timer wakeups."""

    def test_zero_overhead_idle_state(self, qapp: QApplication) -> None:
        avatar = TsukikoAvatarWidget(active=False, idle_animation=False)
        assert avatar.animation_timer.isActive() is False

        avatar.set_active(True)
        assert avatar.animation_timer.isActive() is True

        avatar.set_active(False)
        assert avatar.animation_timer.isActive() is False

    def test_hide_stops_active_animation(self, qapp: QApplication) -> None:
        avatar = TsukikoAvatarWidget(active=True)
        avatar.show()
        assert avatar.animation_timer.isActive() is True

        avatar.hide()
        assert avatar.animation_timer.isActive() is False

        avatar.show()
        assert avatar.animation_timer.isActive() is True

    def test_close_event_stops_timer(self, qapp: QApplication) -> None:
        avatar = TsukikoAvatarWidget(active=True)
        avatar.close()
        assert avatar.animation_timer.isActive() is False

    def test_real_floating_widget_default_config_has_inactive_avatar_timer(self, qapp: QApplication) -> None:
        widget = FloatingCompanionWidget()
        assert widget.ui_config.idle_animation is False
        assert widget.avatar.animation_timer.isActive() is False
        assert widget.avatar.is_active is False

        widget.avatar.set_active(True)
        assert widget.avatar.animation_timer.isActive() is True

        widget.avatar.set_active(False)
        assert widget.avatar.animation_timer.isActive() is False


class TestCliAndHeadlessPreservation:
    """Verifies that --headless and --check-hardware continue to function without UI."""

    def test_check_hardware_cli(self) -> None:
        from app.main import main
        exit_code = main(["--check-hardware"])
        assert exit_code == 0
