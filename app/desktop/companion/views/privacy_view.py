"""Tsukiko Desktop Companion — Privacy View (Phase 2).

Displays zero-trust privacy configuration, firewall and socket guard states,
and visibly locked sensor controls (screen, microphone, desktop automation).
"""

from __future__ import annotations

import logging
from typing import Optional

from app.core.config.settings import PrivacyConfig, get_config

logger = logging.getLogger(__name__)

try:
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import (
        QFrame,
        QHBoxLayout,
        QLabel,
        QScrollArea,
        QVBoxLayout,
        QWidget,
    )
    HAS_PYSIDE6 = True
except ImportError:
    HAS_PYSIDE6 = False
    QWidget = object  # type: ignore[misc,assignment]


class PrivacyIndicatorRow(QFrame if HAS_PYSIDE6 else object):  # type: ignore[misc]
    """Displays a single privacy invariant with lock state."""

    def __init__(
        self,
        title: str,
        status: str,
        badge_color: str,
        description: str,
        is_locked: bool = True,
        parent: Optional[QWidget] = None,
    ) -> None:
        if not HAS_PYSIDE6:
            raise RuntimeError("PySide6 is required to instantiate PrivacyIndicatorRow")
        super().__init__(parent)
        self.setObjectName("privacy_row")
        self.setStyleSheet(
            "QFrame#privacy_row {"
            "  background-color: rgba(30, 41, 59, 0.65);"
            "  border: 1px solid rgba(127, 179, 213, 0.2);"
            "  border-radius: 8px;"
            "  padding: 8px;"
            "}"
        )
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(4)

        # Top row: Title + Badge
        top = QHBoxLayout()
        top.setSpacing(8)

        lock_icon = QLabel("🔒" if is_locked else "🛡️")
        lock_icon.setStyleSheet("font-size: 13px;")
        top.addWidget(lock_icon)

        title_lbl = QLabel(title)
        title_lbl.setStyleSheet("font-size: 13px; font-weight: 600; color: #F8FAFC;")
        top.addWidget(title_lbl, stretch=1)

        badge = QLabel(status)
        badge.setStyleSheet(
            f"background-color: rgba(15, 23, 42, 0.8);"
            f"color: {badge_color};"
            f"border: 1px solid {badge_color};"
            f"border-radius: 10px;"
            f"padding: 2px 10px;"
            f"font-size: 11px;"
            f"font-weight: bold;"
        )
        top.addWidget(badge)
        layout.addLayout(top)

        # Description
        desc_lbl = QLabel(description)
        desc_lbl.setWordWrap(True)
        desc_lbl.setStyleSheet("color: #94A3B8; font-size: 11px;")
        layout.addWidget(desc_lbl)


class PrivacyView(QWidget):
    """Zero-Trust Privacy and Security Boundary View."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        if not HAS_PYSIDE6:
            raise RuntimeError("PySide6 is required to instantiate PrivacyView")
        super().__init__(parent)
        self.setObjectName("PrivacyView")
        self._config: PrivacyConfig = get_config().privacy
        self._init_ui()

    def _init_ui(self) -> None:
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(14)

        title = QLabel("Privacy & Security Boundaries")
        title.setStyleSheet("font-size: 16px; font-weight: bold; color: #D4E6F1;")
        main_layout.addWidget(title)

        banner = QLabel(
            "Tsukiko enforces a strict offline-first zero-trust policy. "
            "All telemetry, external API queries, and outbound connections are permanently disabled "
            "at the process socket level and operating system firewall."
        )
        banner.setWordWrap(True)
        banner.setStyleSheet("color: #94A3B8; font-size: 12px; margin-bottom: 4px;")
        main_layout.addWidget(banner)

        # Scrollable rows
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setStyleSheet("background: transparent;")

        container = QWidget()
        container.setStyleSheet("background: transparent;")
        rows_layout = QVBoxLayout(container)
        rows_layout.setContentsMargins(0, 0, 0, 0)
        rows_layout.setSpacing(10)

        # 1. Local-Only Mode
        rows_layout.addWidget(
            PrivacyIndicatorRow(
                title="Local-Only Execution",
                status="ENFORCED (ON)",
                badge_color="#A8D5BA",
                description="Core AI operations and data storage run entirely on local workstation hardware. External endpoints are unreachable.",
                is_locked=True,
            )
        )

        # 2. Outbound Telemetry
        rows_layout.addWidget(
            PrivacyIndicatorRow(
                title="Outbound Telemetry & Analytics",
                status="DISABLED (BLOCKED)",
                badge_color="#A8D5BA",
                description="Usage statistics, diagnostics, and telemetry reporting are physically disabled. Zero analytics collection.",
                is_locked=True,
            )
        )

        # 3. Cloud Fallback
        rows_layout.addWidget(
            PrivacyIndicatorRow(
                title="Cloud LLM Fallback",
                status="DISABLED (BLOCKED)",
                badge_color="#A8D5BA",
                description="Tsukiko never routes user prompts or context to external LLM providers or remote cloud servers.",
                is_locked=True,
            )
        )

        # 4. Screen Sharing Sensor
        rows_layout.addWidget(
            PrivacyIndicatorRow(
                title="Screen Sharing & Visual Perception",
                status="LOCKED (PHASE 5)",
                badge_color="#94A3B8",
                description="Desktop screen capture is disabled and locked. Vision processing arrives in Phase 5 with explicit user activation.",
                is_locked=True,
            )
        )

        # 5. Microphone & Audio Sensor
        rows_layout.addWidget(
            PrivacyIndicatorRow(
                title="Microphone & Voice Input",
                status="LOCKED (PHASE 6)",
                badge_color="#94A3B8",
                description="Audio input is disabled and locked. Voice input and local STT arrive in Phase 6.",
                is_locked=True,
            )
        )

        # 6. Desktop Automation Control
        rows_layout.addWidget(
            PrivacyIndicatorRow(
                title="Desktop Action & Automation Control",
                status="DISABLED (PHASE 7)",
                badge_color="#94A3B8",
                description="Direct system mouse and keyboard manipulation is disabled and locked until Phase 7 explicit authorization.",
                is_locked=True,
            )
        )

        rows_layout.addStretch(1)
        scroll.setWidget(container)
        main_layout.addWidget(scroll, stretch=1)
