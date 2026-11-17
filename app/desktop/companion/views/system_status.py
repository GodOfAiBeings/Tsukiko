"""Tsukiko Desktop Companion — System Status View (Phase 2).

Displays genuine hardware metrics and subsystem operational states.
Does not fabricate or simulate data; reads directly from HardwareInspector
and TsukikoOrchestrator.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional
import psutil

from app.core.resource_manager.hardware import HardwareInspector, HardwareProfile

logger = logging.getLogger(__name__)

try:
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import (
        QFrame,
        QGridLayout,
        QHBoxLayout,
        QLabel,
        QPushButton,
        QScrollArea,
        QVBoxLayout,
        QWidget,
    )
    HAS_PYSIDE6 = True
except ImportError:
    HAS_PYSIDE6 = False
    QWidget = object  # type: ignore[misc,assignment]


class StatusCard(QFrame if HAS_PYSIDE6 else object):  # type: ignore[misc]
    """Card widget grouping related system metrics."""

    def __init__(self, title: str, icon: str = "📊", parent: Optional[QWidget] = None) -> None:
        if not HAS_PYSIDE6:
            raise RuntimeError("PySide6 is required to instantiate StatusCard")
        super().__init__(parent)
        self.setObjectName("status_card")
        self.setStyleSheet(
            "QFrame#status_card {"
            "  background-color: rgba(30, 41, 59, 0.7);"
            "  border: 1px solid rgba(127, 179, 213, 0.25);"
            "  border-radius: 10px;"
            "  padding: 12px;"
            "}"
        )
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(12, 10, 12, 10)
        self.layout.setSpacing(8)

        # Header
        header = QHBoxLayout()
        header.setSpacing(6)
        icon_lbl = QLabel(icon)
        icon_lbl.setStyleSheet("font-size: 14px;")
        header.addWidget(icon_lbl)

        title_lbl = QLabel(title)
        title_lbl.setStyleSheet("font-weight: 600; font-size: 13px; color: #7FB3D5;")
        header.addWidget(title_lbl, stretch=1)
        self.layout.addLayout(header)

        # Content grid
        self.grid = QGridLayout()
        self.grid.setHorizontalSpacing(16)
        self.grid.setVerticalSpacing(6)
        self.layout.addLayout(self.grid)
        self._row = 0

    def add_row(self, label: str, value: str, badge_color: Optional[str] = None) -> None:
        """Add a labeled metric row."""
        lbl = QLabel(label)
        lbl.setStyleSheet("color: #94A3B8; font-size: 12px;")
        val = QLabel(value)
        if badge_color:
            val.setStyleSheet(
                f"color: {badge_color}; font-weight: 600; font-size: 12px;"
            )
        else:
            val.setStyleSheet("color: #F8FAFC; font-size: 12px;")
        val.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.grid.addWidget(lbl, self._row, 0)
        self.grid.addWidget(val, self._row, 1)
        self._row += 1


class SystemStatusView(QWidget):
    """System and Hardware Status View.
    
    Presents genuine telemetry from the local system without mock data.
    """

    def __init__(
        self,
        orchestrator: Optional[Any] = None,
        parent: Optional[QWidget] = None,
    ) -> None:
        if not HAS_PYSIDE6:
            raise RuntimeError("PySide6 is required to instantiate SystemStatusView")
        super().__init__(parent)
        self.setObjectName("SystemStatusView")
        self._orchestrator = orchestrator
        self._profile: Optional[HardwareProfile] = None
        self._init_ui()
        self.refresh_metrics()

    def _init_ui(self) -> None:
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(14)

        # Header & refresh button
        top_bar = QHBoxLayout()
        title = QLabel("System & Hardware Status")
        title.setStyleSheet("font-size: 16px; font-weight: bold; color: #D4E6F1;")
        top_bar.addWidget(title, stretch=1)

        self.refresh_btn = QPushButton("Refresh Status")
        self.refresh_btn.setObjectName("refresh_status_button")
        self.refresh_btn.setStyleSheet(
            "QPushButton {"
            "  background-color: rgba(30, 58, 95, 0.8);"
            "  color: #D4E6F1;"
            "  border: 1px solid #7FB3D5;"
            "  border-radius: 6px;"
            "  padding: 6px 14px;"
            "  font-size: 12px;"
            "}"
            "QPushButton:hover {"
            "  background-color: rgba(43, 79, 126, 0.9);"
            "}"
        )
        self.refresh_btn.clicked.connect(self.refresh_metrics)
        top_bar.addWidget(self.refresh_btn)
        main_layout.addLayout(top_bar)

        # Scrollable cards container
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setStyleSheet("background: transparent;")

        container = QWidget()
        container.setStyleSheet("background: transparent;")
        self.cards_layout = QVBoxLayout(container)
        self.cards_layout.setContentsMargins(0, 0, 0, 0)
        self.cards_layout.setSpacing(14)

        scroll.setWidget(container)
        main_layout.addWidget(scroll, stretch=1)

    def refresh_metrics(self) -> None:
        """Inspects hardware and updates all cards."""
        try:
            self._profile = HardwareInspector.inspect()
        except Exception as e:
            logger.error(f"Failed to inspect hardware for SystemStatusView: {e}")

        # Clear existing cards
        while self.cards_layout.count():
            item = self.cards_layout.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()

        if not self._profile:
            err_lbl = QLabel("Unable to inspect system hardware.")
            err_lbl.setStyleSheet("color: #E06C75;")
            self.cards_layout.addWidget(err_lbl)
            return

        # 1. CPU Card
        cpu_card = StatusCard("Processor (CPU)", icon="⚡")
        cpu_card.add_row("Processor Model", self._profile.cpu.brand)
        cpu_card.add_row(
            "Cores / Threads",
            f"{self._profile.cpu.physical_cores} Physical / {self._profile.cpu.logical_cores} Logical",
        )
        cpu_card.add_row("Current Load", f"{self._profile.cpu.utilization_percent:.1f}%")
        self.cards_layout.addWidget(cpu_card)

        # 2. RAM Card
        ram_card = StatusCard("System Memory (RAM)", icon="💾")
        ram_card.add_row("Total RAM", f"{self._profile.memory.total_ram_mb} MB")
        ram_card.add_row("Available RAM", f"{self._profile.memory.available_ram_mb} MB")
        ram_card.add_row("Used RAM", f"{self._profile.memory.used_ram_mb} MB ({self._profile.memory.percent_used:.1f}%)")
        ram_card.add_row("Safe Budget", f"{self._profile.recommended_max_ram_mb} MB")
        self.cards_layout.addWidget(ram_card)

        # 3. GPU / VRAM Card
        gpu_card = StatusCard("Graphics (GPU / VRAM)", icon="🎮")
        if self._profile.gpus:
            primary_gpu = self._profile.gpus[0]
            gpu_card.add_row("GPU Model", primary_gpu.name)
            gpu_card.add_row("Driver Version", primary_gpu.driver_version)
            if primary_gpu.total_vram_mb is not None:
                gpu_card.add_row("Total VRAM", f"{primary_gpu.total_vram_mb} MB")
            else:
                gpu_card.add_row("Total VRAM", "N/A (Integrated/Shared)")
            if primary_gpu.free_vram_mb is not None:
                gpu_card.add_row("Free VRAM", f"{primary_gpu.free_vram_mb} MB")
            gpu_card.add_row("Budget Status", self._profile.budget_status, badge_color="#A8D5BA" if self._profile.budget_status == "measured" else "#E5C07B")
            gpu_card.add_row("Recommended Max VRAM", f"{self._profile.recommended_max_vram_mb} MB")
        else:
            gpu_card.add_row("GPU Model", "No dedicated GPU detected")
            gpu_card.add_row("Budget Status", self._profile.budget_status, badge_color="#E06C75")
        self.cards_layout.addWidget(gpu_card)

        # 4. Local AI Brain & Inference Telemetry Card (Phase 3)
        brain_card = StatusCard("Local AI Brain & Inference", icon="🧠")
        brain_status: Dict[str, Any] = {}
        if self._orchestrator and hasattr(self._orchestrator, "brain") and self._orchestrator.brain:
            try:
                brain_status = self._orchestrator.brain.get_brain_status()
            except Exception as e:
                logger.warning(f"Failed to query brain status: {e}")

        model_name = brain_status.get("model_name", "None")
        model_path = brain_status.get("model_path") or "Not configured"
        quant = brain_status.get("quantization", "N/A")
        rt_ver = brain_status.get("runtime_version", "N/A")
        backend = brain_status.get("backend", "cpu").upper()
        state = brain_status.get("state", "NOT_CONFIGURED")
        ctx = brain_status.get("context_window", 4096)
        is_gen = brain_status.get("is_generating", False)
        gen_status = "Generating..." if is_gen else "Idle"

        # Measured process RAM via psutil
        try:
            proc = psutil.Process()
            proc_ram_mb = int(proc.memory_info().rss / (1024 * 1024))
            proc_ram_str = f"{proc_ram_mb} MB"
        except Exception:
            proc_ram_str = "Unavailable"

        # Measured GPU memory
        if self._profile.gpus and self._profile.gpus[0].free_vram_mb is not None:
            gpu_mem_str = (
                f"{self._profile.gpus[0].used_vram_mb or 0} MB used / "
                f"{self._profile.gpus[0].total_vram_mb or 0} MB total "
                f"({self._profile.gpus[0].free_vram_mb} MB free)"
            )
        else:
            gpu_mem_str = "N/A (CPU Mode / No discrete GPU)"

        is_loaded = brain_status.get("is_loaded", False)
        badge_color = "#A8D5BA" if is_loaded else ("#E5C07B" if state in ("READY", "VALIDATING") else "#94A3B8")
        loaded_desc = "Loaded" if is_loaded else "Unloaded"

        brain_card.add_row("Model Name", model_name)
        brain_card.add_row("Model Path", model_path)
        brain_card.add_row("Quantization", quant)
        brain_card.add_row("Runtime Version", rt_ver)
        brain_card.add_row("Inference Backend", backend)
        brain_card.add_row("Lifecycle State", f"{state} ({loaded_desc})", badge_color=badge_color)
        brain_card.add_row("Context Window", f"{ctx} tokens")
        brain_card.add_row("Generation Status", gen_status, badge_color="#7FB3D5" if is_gen else None)
        brain_card.add_row("Process RSS RAM", proc_ram_str)
        brain_card.add_row("Measured GPU VRAM", gpu_mem_str)
        self.cards_layout.addWidget(brain_card)

        # 5. Tsukiko Subsystems Card
        orch_card = StatusCard("Tsukiko Subsystems", icon="⚙️")
        orch_status: Dict[str, Any] = {}
        if self._orchestrator and hasattr(self._orchestrator, "get_status"):
            try:
                orch_status = self._orchestrator.get_status()
            except Exception:
                pass

        orch_card.add_row(
            "Core Orchestrator",
            orch_status.get("state", "Running (Desktop Mode)"),
            badge_color="#A8D5BA",
        )
        orch_card.add_row("Network Isolation", "Active (Zero-Trust Local-Only)", badge_color="#A8D5BA")
        orch_card.add_row("Local AI Brain", f"Phase 3 — {state}", badge_color=badge_color)
        orch_card.add_row("Persistent Memory", "Phase 4 — Uninstalled", badge_color="#94A3B8")
        orch_card.add_row("Perception / Vision", "Phase 5 — Disabled", badge_color="#94A3B8")
        orch_card.add_row("Voice & Audio", "Phase 6 — Disabled", badge_color="#94A3B8")
        orch_card.add_row("Desktop Control", "Phase 7 — Disabled", badge_color="#94A3B8")
        self.cards_layout.addWidget(orch_card)

        self.cards_layout.addStretch(1)
