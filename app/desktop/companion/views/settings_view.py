"""Tsukiko Desktop Companion — Settings View (Phase 2).

Provides user interface customization for the companion widget and window.
Settings validation enforces valid ranges (e.g. opacity 0.2-1.0, non-negative margins).
Privacy policies cannot be altered or bypassed from this view.
"""

from __future__ import annotations

import logging
from pathlib import Path
import re
from typing import Any, Callable, Optional

from app.core.config.settings import AIConfig, TsukikoConfig, UIConfig, get_config, save_config
from app.core.model_manager.gguf_parser import GGUFValidationError, inspect_gguf_file

logger = logging.getLogger(__name__)

try:
    from PySide6.QtCore import QThread, Qt, Signal
    from PySide6.QtWidgets import (
        QCheckBox,
        QComboBox,
        QFileDialog,
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
    QFileDialog = object  # type: ignore[misc,assignment]
    QThread = object  # type: ignore[misc,assignment]


HEX_COLOR_REGEX = re.compile(r"^#[0-9a-fA-F]{6}$")


if HAS_PYSIDE6:

    class ModelLifecycleWorker(QThread):
        """Worker thread for asynchronous model loading and unloading.

        Guarantees the desktop GUI never freezes while weights are loaded or unloaded.
        """

        finished_signal = Signal(bool, str)  # (success, status_message)

        def __init__(
            self,
            action: str,
            brain: Any,
            model_path: Optional[str] = None,
            parent: Optional[QWidget] = None,
        ) -> None:
            super().__init__(parent)
            self.action = action
            self.brain = brain
            self.model_path = model_path

        def run(self) -> None:
            try:
                if self.action == "load":
                    if self.model_path is not None:
                        self.brain.model_manager._ai_config.model_path = self.model_path
                        self.brain.model_manager.inspect_configured_model()
                    ok = self.brain.load_model(force=True)
                    if ok:
                        info = self.brain.model_manager.info
                        msg = (
                            f"✓ Model loaded: {info.model_name} "
                            f"({info.backend.upper()}, {info.gpu_layers_offloaded} GPU layers)"
                        )
                        self.finished_signal.emit(True, msg)
                    else:
                        err = self.brain.model_manager.info.error_message or "Unknown error"
                        self.finished_signal.emit(False, f"❌ Load failed: {err}")
                elif self.action == "unload":
                    ok = self.brain.unload_model()
                    if ok:
                        self.finished_signal.emit(True, "Model unloaded from memory/VRAM.")
                    else:
                        self.finished_signal.emit(
                            False, "Cannot unload model right now (generation may be active)."
                        )
            except Exception as e:
                self.finished_signal.emit(False, f"❌ Operation error: {e}")
else:
    ModelLifecycleWorker = object  # type: ignore[misc,assignment]


class SettingsView(QWidget):
    """Settings view for configuring Desktop Companion visual appearance."""

    # Signal emitted when UI settings are modified and saved
    if HAS_PYSIDE6:
        settings_applied = Signal(object)  # emits UIConfig

    def __init__(
        self,
        config: Optional[TsukikoConfig] = None,
        orchestrator: Optional[Any] = None,
        parent: Optional[QWidget] = None,
        target_config_path: Optional[Path] = None,
    ) -> None:
        if not HAS_PYSIDE6:
            raise RuntimeError("PySide6 is required to instantiate SettingsView")
        super().__init__(parent)
        self.setObjectName("SettingsView")
        self._config = config or get_config()
        self._ui_config: UIConfig = self._config.ui
        self._ai_config: AIConfig = self._config.ai
        self._orchestrator = orchestrator
        self._brain = getattr(orchestrator, "brain", None) if orchestrator else None
        self._target_config_path = target_config_path
        self._lifecycle_worker: Optional[ModelLifecycleWorker] = None
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

        # Section 3: Local AI Brain Configuration (Phase 3)
        ai_card = QFrame()
        ai_card.setObjectName("ai_settings_card")
        ai_card.setStyleSheet(
            "QFrame {"
            "  background-color: rgba(30, 41, 59, 0.7);"
            "  border: 1px solid rgba(127, 179, 213, 0.25);"
            "  border-radius: 10px;"
            "  padding: 12px;"
            "}"
        )
        ai_grid = QGridLayout(ai_card)
        ai_grid.setHorizontalSpacing(16)
        ai_grid.setVerticalSpacing(10)

        ai_title = QLabel("Local AI Brain & Inference (Phase 3)")
        ai_title.setStyleSheet("font-size: 13px; font-weight: bold; color: #7FB3D5;")
        ai_grid.addWidget(ai_title, 0, 0, 1, 2)

        # Model File Path + File Picker
        lbl_model_path = QLabel("Model File (GGUF)")
        lbl_model_path.setStyleSheet("color: #94A3B8; font-size: 12px;")
        path_box = QHBoxLayout()
        self.edit_model_path = QLineEdit()
        self.edit_model_path.setPlaceholderText("Path to local .gguf model file...")
        self.btn_browse_model = QPushButton("Browse...")
        self.btn_browse_model.setStyleSheet("padding: 4px 10px; font-size: 11px;")
        self.btn_browse_model.clicked.connect(self._browse_model_file)
        path_box.addWidget(self.edit_model_path, stretch=1)
        path_box.addWidget(self.btn_browse_model)
        ai_grid.addWidget(lbl_model_path, 1, 0)
        ai_grid.addLayout(path_box, 1, 1)

        # Action Buttons: Validate, Load, Unload
        lbl_actions = QLabel("Model Actions")
        lbl_actions.setStyleSheet("color: #94A3B8; font-size: 12px;")
        actions_box = QHBoxLayout()
        self.btn_validate_model = QPushButton("Validate GGUF")
        self.btn_validate_model.setStyleSheet("padding: 4px 10px; font-size: 11px;")
        self.btn_validate_model.clicked.connect(self._validate_model)
        actions_box.addWidget(self.btn_validate_model)

        self.btn_load_model = QPushButton("Load Model")
        self.btn_load_model.setStyleSheet("padding: 4px 10px; font-size: 11px;")
        self.btn_load_model.clicked.connect(self._load_model)
        actions_box.addWidget(self.btn_load_model)

        self.btn_unload_model = QPushButton("Unload Model")
        self.btn_unload_model.setStyleSheet("padding: 4px 10px; font-size: 11px;")
        self.btn_unload_model.clicked.connect(self._unload_model)
        actions_box.addWidget(self.btn_unload_model)
        ai_grid.addWidget(lbl_actions, 2, 0)
        ai_grid.addLayout(actions_box, 2, 1)

        # Context Window
        lbl_ctx = QLabel("Context Window (Tokens)")
        lbl_ctx.setStyleSheet("color: #94A3B8; font-size: 12px;")
        self.spin_context_window = QSpinBox()
        self.spin_context_window.setRange(512, 32768)
        self.spin_context_window.setSingleStep(512)
        ai_grid.addWidget(lbl_ctx, 3, 0)
        ai_grid.addWidget(self.spin_context_window, 3, 1)

        # CPU Thread Count
        lbl_threads = QLabel("CPU Thread Count")
        lbl_threads.setStyleSheet("color: #94A3B8; font-size: 12px;")
        self.spin_threads = QSpinBox()
        self.spin_threads.setRange(1, 64)
        ai_grid.addWidget(lbl_threads, 4, 0)
        ai_grid.addWidget(self.spin_threads, 4, 1)

        # Max Safe VRAM
        lbl_vram = QLabel("Max Safe VRAM (MB)")
        lbl_vram.setStyleSheet("color: #94A3B8; font-size: 12px;")
        self.spin_max_vram = QSpinBox()
        self.spin_max_vram.setRange(0, 24000)
        self.spin_max_vram.setSingleStep(100)
        ai_grid.addWidget(lbl_vram, 5, 0)
        ai_grid.addWidget(self.spin_max_vram, 5, 1)

        # Max Safe RAM
        lbl_ram = QLabel("Max Safe RAM (MB)")
        lbl_ram.setStyleSheet("color: #94A3B8; font-size: 12px;")
        self.spin_max_ram = QSpinBox()
        self.spin_max_ram.setRange(1024, 64000)
        self.spin_max_ram.setSingleStep(256)
        ai_grid.addWidget(lbl_ram, 6, 0)
        ai_grid.addWidget(self.spin_max_ram, 6, 1)

        # Selected Inference Backend
        lbl_backend = QLabel("Inference Backend")
        lbl_backend.setStyleSheet("color: #94A3B8; font-size: 12px;")
        self.combo_backend = QComboBox()
        self.combo_backend.addItems(["auto", "cuda", "cpu"])
        ai_grid.addWidget(lbl_backend, 7, 0)
        ai_grid.addWidget(self.combo_backend, 7, 1)

        # Live Model Status
        self.lbl_model_status = QLabel("")
        self.lbl_model_status.setStyleSheet("color: #7FB3D5; font-size: 11px;")
        self.lbl_model_status.setWordWrap(True)
        ai_grid.addWidget(self.lbl_model_status, 8, 0, 1, 2)

        c_layout.addWidget(ai_card)

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

        # AI Brain settings
        self.edit_model_path.setText(str(self._ai_config.model_path or ""))
        self.spin_context_window.setValue(self._ai_config.context_window)
        self.spin_threads.setValue(self._ai_config.threads)
        self.spin_max_vram.setValue(self._ai_config.max_vram_mb)
        self.spin_max_ram.setValue(self._ai_config.max_ram_mb)
        b_idx = self.combo_backend.findText(self._ai_config.backend)
        if b_idx >= 0:
            self.combo_backend.setCurrentIndex(b_idx)
        self._update_model_status_label()

    def _reset_defaults(self) -> None:
        """Reset inputs to default configuration."""
        self._ui_config = UIConfig()
        self._ai_config = AIConfig()
        self._load_values()
        self.status_label.setText("Reset to defaults. Click Apply to confirm.")
        self.status_label.setStyleSheet("color: #7FB3D5; font-size: 12px;")

    def _browse_model_file(self) -> None:
        if not HAS_PYSIDE6:
            return
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select GGUF Model File",
            "",
            "GGUF Models (*.gguf);;All Files (*)",
        )
        if file_path:
            self.edit_model_path.setText(file_path)
            self._validate_model()

    def _validate_model(self) -> None:
        path_str = self.edit_model_path.text().strip()
        if not path_str:
            self.lbl_model_status.setText("Please specify a model path.")
            self.lbl_model_status.setStyleSheet("color: #F5B041;")
            return
        try:
            metadata = inspect_gguf_file(path_str)
            self.lbl_model_status.setText(
                f"✓ Valid GGUF: {metadata.model_name} | Arch: {metadata.architecture} | "
                f"Quant: {metadata.quantization} | Layers: {metadata.block_count} | Size: {metadata.file_size_mb} MB"
            )
            self.lbl_model_status.setStyleSheet("color: #A8D5BA;")
        except Exception as e:
            self.lbl_model_status.setText(f"❌ Validation failed: {e}")
            self.lbl_model_status.setStyleSheet("color: #E06C75;")

    def _load_model(self) -> None:
        if not self._brain:
            self.lbl_model_status.setText("Local AI Brain is not available.")
            self.lbl_model_status.setStyleSheet("color: #E06C75;")
            return

        if self._lifecycle_worker is not None and self._lifecycle_worker.isRunning():
            return

        self.btn_load_model.setEnabled(False)
        self.btn_unload_model.setEnabled(False)
        self.lbl_model_status.setText("⏳ Loading model into memory/VRAM...")
        self.lbl_model_status.setStyleSheet("color: #7FB3D5;")

        path_text = self.edit_model_path.text().strip() or None
        self._lifecycle_worker = ModelLifecycleWorker("load", self._brain, path_text, self)
        self._lifecycle_worker.finished_signal.connect(self._on_lifecycle_finished)
        self._lifecycle_worker.start()

    def _unload_model(self) -> None:
        if not self._brain:
            return

        if self._lifecycle_worker is not None and self._lifecycle_worker.isRunning():
            return

        self.btn_load_model.setEnabled(False)
        self.btn_unload_model.setEnabled(False)
        self.lbl_model_status.setText("⏳ Unloading model from memory/VRAM...")
        self.lbl_model_status.setStyleSheet("color: #7FB3D5;")

        self._lifecycle_worker = ModelLifecycleWorker("unload", self._brain, None, self)
        self._lifecycle_worker.finished_signal.connect(self._on_lifecycle_finished)
        self._lifecycle_worker.start()

    def _on_lifecycle_finished(self, ok: bool, msg: str) -> None:
        self.btn_load_model.setEnabled(True)
        self.btn_unload_model.setEnabled(True)
        self.lbl_model_status.setText(msg)
        if ok:
            if "unloaded" in msg.lower():
                self.lbl_model_status.setStyleSheet("color: #D4E6F1;")
            else:
                self.lbl_model_status.setStyleSheet("color: #A8D5BA;")
        else:
            self.lbl_model_status.setStyleSheet("color: #E06C75;")

    def _update_model_status_label(self) -> None:
        if self._brain:
            info = self._brain.model_manager.info
            state = info.state.value
            loaded_desc = " (Loaded)" if info.is_loaded else ""
            self.lbl_model_status.setText(f"Current State: {state}{loaded_desc}")
            self.lbl_model_status.setStyleSheet("color: #7FB3D5;")

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

        if self.spin_context_window.value() < 512:
            return False, "Context window must be at least 512 tokens."

        if self.spin_threads.value() < 1:
            return False, "CPU thread count must be at least 1."

        if self.spin_max_ram.value() < 1024:
            return False, "Maximum safe RAM must be at least 1024 MB."

        return True, ""

    def save_settings(self) -> bool:
        """Validate and apply UI and AI settings."""
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

        # Update AI settings
        self._ai_config.model_path = self.edit_model_path.text().strip() or None
        self._ai_config.context_window = self.spin_context_window.value()
        self._ai_config.threads = self.spin_threads.value()
        self._ai_config.max_vram_mb = self.spin_max_vram.value()
        self._ai_config.max_ram_mb = self.spin_max_ram.value()
        self._ai_config.backend = self.combo_backend.currentText()

        # Update root config and apply to current session
        self._config.ui = self._ui_config
        self._config.ai = self._ai_config

        if self._brain:
            self._brain.model_manager._ai_config = self._ai_config
            self._brain.model_manager.inspect_configured_model()
            self._update_model_status_label()

        if HAS_PYSIDE6:
            self.settings_applied.emit(self._ui_config)

        # Persist to disk using active or specified config path
        try:
            saved_path = save_config(self._config, target_path=self._target_config_path)
            self.status_label.setText(f"✓ Settings applied to current session and saved to {saved_path.name}.")
            self.status_label.setStyleSheet("color: #A8D5BA; font-size: 12px;")
            return True
        except Exception as e:
            logger.error(f"Failed to persist settings to disk: {e}")
            self.status_label.setText(f"⚠ Settings applied to current session, but failed to save to disk: {e}")
            self.status_label.setStyleSheet("color: #F5B041; font-size: 12px;")
            return False
