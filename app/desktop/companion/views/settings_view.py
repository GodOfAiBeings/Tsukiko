"""Tsukiko Desktop Companion — Settings View (Phase 2).

Provides user interface customization for the companion widget and window.
Settings validation enforces valid ranges (e.g. opacity 0.2-1.0, non-negative margins).
Privacy policies cannot be altered or bypassed from this view.
"""

from __future__ import annotations

import logging
import re
from typing import Callable, Optional

from app.core.config.settings import TsukikoConfig, UIConfig, get_config, save_config

logger = logging.getLogger(__name__)

try:
    from PySide6.QtCore import Qt, Signal
    from PySide6.QtWidgets import (
        QCheckBox,
        QComboBox,
        QFrame,
        QGridLayout,
        QHBoxLayout,
        QLabel,
        QLineEdit,
        QPushButton,
        QScrollArea,
        QSlider,
        QSpinBox,
        QVBoxLayout,
        QWidget,
    )
    HAS_PYSIDE6 = True
except ImportError:
    HAS_PYSIDE6 = False
    QWidget = object  # type: ignore[misc,assignment]


HEX_COLOR_REGEX = re.compile(r"^#[0-9a-fA-F]{6}$")


class SettingsView(QWidget):
    """Settings view for configuring Desktop Companion visual appearance."""

    # Signal emitted when UI settings are modified and saved
    if HAS_PYSIDE6:
        settings_applied = Signal(object)  # emits UIConfig

    def __init__(
        self,
        config: Optional[TsukikoConfig] = None,
        parent: Optional[QWidget] = None,
    ) -> None:
        if not HAS_PYSIDE6:
            raise RuntimeError("PySide6 is required to instantiate SettingsView")
        super().__init__(parent)
        self.setObjectName("SettingsView")
        self._config = config or get_config()
        self._ui_config: UIConfig = self._config.ui
        self._init_ui()
        self._load_values()

    def _init_ui(self) -> None:
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(14)

        # Title
        title = QLabel("Companion UI Settings")
        title.setStyleSheet("font-size: 16px; font-weight: bold; color: #D4E6F1;")
        main_layout.addWidget(title)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setStyleSheet("background: transparent;")

        container = QWidget()
        container.setStyleSheet("background: transparent;")
        c_layout = QVBoxLayout(container)
        c_layout.setContentsMargins(0, 0, 0, 0)
        c_layout.setSpacing(16)

        # Section 1: Appearance Card
        app_card = QFrame()
        app_card.setStyleSheet(
            "QFrame {"
            "  background-color: rgba(30, 41, 59, 0.7);"
            "  border: 1px solid rgba(127, 179, 213, 0.25);"
            "  border-radius: 10px;"
            "  padding: 12px;"
            "}"
        )
        app_grid = QGridLayout(app_card)
        app_grid.setHorizontalSpacing(16)
        app_grid.setVerticalSpacing(10)

        # Theme
        lbl_theme = QLabel("Theme")
        lbl_theme.setStyleSheet("color: #94A3B8; font-size: 12px;")
        self.combo_theme = QComboBox()
        self.combo_theme.addItems(["silver-blue-moonlight"])
        app_grid.addWidget(lbl_theme, 0, 0)
        app_grid.addWidget(self.combo_theme, 0, 1)

        # Accent Color
        lbl_accent = QLabel("Accent Color (Hex)")
        lbl_accent.setStyleSheet("color: #94A3B8; font-size: 12px;")
        self.edit_accent = QLineEdit()
        self.edit_accent.setPlaceholderText("#7FB3D5")
        app_grid.addWidget(lbl_accent, 1, 0)
        app_grid.addWidget(self.edit_accent, 1, 1)

        # Glow Color
        lbl_glow = QLabel("Glow Color (Hex)")
        lbl_glow.setStyleSheet("color: #94A3B8; font-size: 12px;")
        self.edit_glow = QLineEdit()
        self.edit_glow.setPlaceholderText("#D4E6F1")
        app_grid.addWidget(lbl_glow, 2, 0)
        app_grid.addWidget(self.edit_glow, 2, 1)

        # Background Opacity
        lbl_opacity = QLabel("Background Opacity")
        lbl_opacity.setStyleSheet("color: #94A3B8; font-size: 12px;")
        self.slider_opacity = QSlider(Qt.Horizontal)
        self.slider_opacity.setRange(0, 100)  # 0% to 100% (validated in validate_inputs to [20, 100])
        self.lbl_opacity_val = QLabel("92%")
        self.lbl_opacity_val.setStyleSheet("color: #D4E6F1; font-size: 12px; width: 40px;")
        self.slider_opacity.valueChanged.connect(
            lambda v: self.lbl_opacity_val.setText(f"{v}%")
        )
        op_layout = QHBoxLayout()
        op_layout.addWidget(self.slider_opacity, stretch=1)
        op_layout.addWidget(self.lbl_opacity_val)
        app_grid.addWidget(lbl_opacity, 3, 0)
        app_grid.addLayout(op_layout, 3, 1)

        c_layout.addWidget(app_card)

        # Section 2: Window Positioning Card
        pos_card = QFrame()
        pos_card.setStyleSheet(
            "QFrame {"
            "  background-color: rgba(30, 41, 59, 0.7);"
            "  border: 1px solid rgba(127, 179, 213, 0.25);"
            "  border-radius: 10px;"
            "  padding: 12px;"
            "}"
        )
        pos_grid = QGridLayout(pos_card)
        pos_grid.setHorizontalSpacing(16)
        pos_grid.setVerticalSpacing(10)

        # Always on top
        self.chk_always_on_top = QCheckBox("Keep Floating Widget Always on Top")
        self.chk_always_on_top.setStyleSheet("color: #F8FAFC; font-size: 12px;")
        pos_grid.addWidget(self.chk_always_on_top, 0, 0, 1, 2)

        # Default corner
        lbl_corner = QLabel("Default Desktop Corner")
        lbl_corner.setStyleSheet("color: #94A3B8; font-size: 12px;")
        self.combo_corner = QComboBox()
        self.combo_corner.addItems(["bottom-right", "bottom-left", "top-right", "top-left"])
        pos_grid.addWidget(lbl_corner, 1, 0)
        pos_grid.addWidget(self.combo_corner, 1, 1)

        # Margin X
        lbl_margin_x = QLabel("Horizontal Margin (px)")
        lbl_margin_x.setStyleSheet("color: #94A3B8; font-size: 12px;")
        self.spin_margin_x = QSpinBox()
        self.spin_margin_x.setRange(0, 500)
        pos_grid.addWidget(lbl_margin_x, 2, 0)
        pos_grid.addWidget(self.spin_margin_x, 2, 1)

        # Margin Y
        lbl_margin_y = QLabel("Vertical Margin (px)")
        lbl_margin_y.setStyleSheet("color: #94A3B8; font-size: 12px;")
        self.spin_margin_y = QSpinBox()
        self.spin_margin_y.setRange(0, 500)
        pos_grid.addWidget(lbl_margin_y, 3, 0)
        pos_grid.addWidget(self.spin_margin_y, 3, 1)

        c_layout.addWidget(pos_card)

        # Feedback label for validation errors or success
        self.status_label = QLabel("")
        self.status_label.setStyleSheet("font-size: 12px;")
        self.status_label.setAlignment(Qt.AlignCenter)
        c_layout.addWidget(self.status_label)

        # Buttons
        btn_bar = QHBoxLayout()
        btn_bar.addStretch(1)

        self.btn_reset = QPushButton("Reset Defaults")
        self.btn_reset.setStyleSheet(
            "QPushButton {"
            "  background-color: transparent;"
            "  color: #94A3B8;"
            "  border: 1px solid rgba(148, 163, 184, 0.3);"
            "  border-radius: 6px;"
            "  padding: 6px 16px;"
            "}"
            "QPushButton:hover {"
            "  border-color: #94A3B8;"
            "  color: #F8FAFC;"
            "}"
        )
        self.btn_reset.clicked.connect(self._reset_defaults)
        btn_bar.addWidget(self.btn_reset)

        self.btn_save = QPushButton("Apply Settings")
        self.btn_save.setObjectName("save_settings_button")
        self.btn_save.setStyleSheet(
            "QPushButton {"
            "  background-color: #2B4C7E;"
            "  color: #FFFFFF;"
            "  border: 1px solid #7FB3D5;"
            "  border-radius: 6px;"
            "  padding: 6px 20px;"
            "  font-weight: bold;"
            "}"
            "QPushButton:hover {"
            "  background-color: #365D9D;"
            "}"
        )
        self.btn_save.clicked.connect(self.save_settings)
        btn_bar.addWidget(self.btn_save)

        c_layout.addLayout(btn_bar)
        c_layout.addStretch(1)

        scroll.setWidget(container)
        main_layout.addWidget(scroll, stretch=1)

    def _load_values(self) -> None:
        """Load UI configuration into input controls."""
        self.edit_accent.setText(self._ui_config.accent_color)
        self.edit_glow.setText(self._ui_config.glow_color)
        op_val = int(self._ui_config.background_opacity * 100)
        self.slider_opacity.setValue(op_val)
        self.lbl_opacity_val.setText(f"{op_val}%")

        self.chk_always_on_top.setChecked(self._ui_config.always_on_top)
        idx = self.combo_corner.findText(self._ui_config.default_corner)
        if idx >= 0:
            self.combo_corner.setCurrentIndex(idx)
        self.spin_margin_x.setValue(self._ui_config.margin_x)
        self.spin_margin_y.setValue(self._ui_config.margin_y)

    def _reset_defaults(self) -> None:
        """Reset inputs to default configuration."""
        self._ui_config = UIConfig()
        self._load_values()
        self.status_label.setText("Reset to defaults. Click Apply to confirm.")
        self.status_label.setStyleSheet("color: #7FB3D5; font-size: 12px;")

    def validate_inputs(self) -> tuple[bool, str]:
        """Validate input settings."""
        accent = self.edit_accent.text().strip()
        if not HEX_COLOR_REGEX.match(accent):
            return False, f"Invalid Accent Color: '{accent}'. Must be format #RRGGBB."

        glow = self.edit_glow.text().strip()
        if not HEX_COLOR_REGEX.match(glow):
            return False, f"Invalid Glow Color: '{glow}'. Must be format #RRGGBB."

        op = self.slider_opacity.value() / 100.0
        if op < 0.2 or op > 1.0:
            return False, f"Opacity {op:.2f} out of allowed range [0.20, 1.00]."

        if self.spin_margin_x.value() < 0:
            return False, "Horizontal margin cannot be negative."

        if self.spin_margin_y.value() < 0:
            return False, "Vertical margin cannot be negative."

        return True, ""

    def save_settings(self) -> bool:
        """Validate and apply UI settings."""
        is_valid, msg = self.validate_inputs()
        if not is_valid:
            self.status_label.setText(f"❌ {msg}")
            self.status_label.setStyleSheet("color: #E06C75; font-size: 12px;")
            return False

        self._ui_config.theme = self.combo_theme.currentText()
        self._ui_config.accent_color = self.edit_accent.text().strip()
        self._ui_config.glow_color = self.edit_glow.text().strip()
        self._ui_config.background_opacity = self.slider_opacity.value() / 100.0
        self._ui_config.always_on_top = self.chk_always_on_top.isChecked()
        self._ui_config.default_corner = self.combo_corner.currentText()
        self._ui_config.margin_x = self.spin_margin_x.value()
        self._ui_config.margin_y = self.spin_margin_y.value()

        # Update root config and apply to current session
        self._config.ui = self._ui_config
        if HAS_PYSIDE6:
            self.settings_applied.emit(self._ui_config)

        # Persist to disk using active config path
        try:
            saved_path = save_config(self._config)
            self.status_label.setText(f"✓ Settings applied to current session and saved to {saved_path.name}.")
            self.status_label.setStyleSheet("color: #A8D5BA; font-size: 12px;")
            return True
        except Exception as e:
            logger.error(f"Failed to persist settings to disk: {e}")
            self.status_label.setText(f"⚠ Settings applied to current session, but failed to save to disk: {e}")
            self.status_label.setStyleSheet("color: #F5B041; font-size: 12px;")
            return False
