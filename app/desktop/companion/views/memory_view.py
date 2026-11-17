"""Tsukiko Desktop Companion — Memory View (Phase 2 Placeholder).

In Phase 2, the persistent memory subsystem is uninstalled and offline.
This view provides an honest structural placeholder explaining that SQLite
and memory management arrive in Phase 4.
No database or storage files are created or accessed in this phase.
"""

from __future__ import annotations

import logging
from typing import Optional

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


class MemoryView(QWidget):
    """Memory view placeholder for Phase 2."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        if not HAS_PYSIDE6:
            raise RuntimeError("PySide6 is required to instantiate MemoryView")
        super().__init__(parent)
        self.setObjectName("MemoryView")
        self._init_ui()

    def _init_ui(self) -> None:
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(16)

        # Title
        title = QLabel("Persistent Memory & Knowledge Base")
        title.setStyleSheet("font-size: 16px; font-weight: bold; color: #D4E6F1;")
        main_layout.addWidget(title)

        # Status Banner
        banner = QFrame()
        banner.setStyleSheet(
            "QFrame {"
            "  background-color: rgba(30, 41, 59, 0.65);"
            "  border: 1px solid rgba(127, 179, 213, 0.3);"
            "  border-radius: 8px;"
            "  padding: 12px;"
            "}"
        )
        b_layout = QHBoxLayout(banner)
        b_layout.setSpacing(12)

        icon = QLabel("🧠")
        icon.setStyleSheet("font-size: 24px;")
        b_layout.addWidget(icon)

        text_layout = QVBoxLayout()
        t1 = QLabel("<b>Phase 4 Feature — Subsystem Currently Uninstalled</b>")
        t1.setStyleSheet("color: #E5C07B; font-size: 13px;")
        t2 = QLabel(
            "Tsukiko's persistent memory architecture arrives in Phase 4. "
            "No SQLite database has been created, and no user profile data is currently stored. "
            "All session state is ephemeral."
        )
        t2.setWordWrap(True)
        t2.setStyleSheet("color: #94A3B8; font-size: 11px;")
        text_layout.addWidget(t1)
        text_layout.addWidget(t2)
        b_layout.addLayout(text_layout, stretch=1)

        main_layout.addWidget(banner)

        # Overview of planned Phase 4 memory guarantees
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setStyleSheet("background: transparent;")

        cards_widget = QWidget()
        cards_widget.setStyleSheet("background: transparent;")
        cards_layout = QVBoxLayout(cards_widget)
        cards_layout.setContentsMargins(0, 0, 0, 0)
        cards_layout.setSpacing(12)

        def make_feature_card(heading: str, details: str) -> QFrame:
            card = QFrame()
            card.setStyleSheet(
                "QFrame {"
                "  background-color: rgba(15, 23, 42, 0.7);"
                "  border: 1px solid rgba(148, 163, 184, 0.2);"
                "  border-radius: 8px;"
                "  padding: 10px;"
                "}"
            )
            c_layout = QVBoxLayout(card)
            c_layout.setContentsMargins(10, 8, 10, 8)
            c_layout.setSpacing(4)
            h_lbl = QLabel(heading)
            h_lbl.setStyleSheet("font-size: 12px; font-weight: 600; color: #7FB3D5;")
            d_lbl = QLabel(details)
            d_lbl.setWordWrap(True)
            d_lbl.setStyleSheet("font-size: 11px; color: #94A3B8;")
            c_layout.addWidget(h_lbl)
            c_layout.addWidget(d_lbl)
            return card

        cards_layout.addWidget(
            make_feature_card(
                "1. Fully Transparent Fact Ledger",
                "Users will be able to inspect, edit, and delete every discrete fact or preference remembered by Tsukiko.",
            )
        )
        cards_layout.addWidget(
            make_feature_card(
                "2. Zero External Cloud Sync",
                "All vector embeddings and relational entities remain encrypted on local disk with zero telemetry.",
            )
        )
        cards_layout.addWidget(
            make_feature_card(
                "3. Episodic vs Semantic Separation",
                "Conversational memories will be distinct from long-term factual knowledge to ensure tight token budget management.",
            )
        )

        cards_layout.addStretch(1)
        scroll.setWidget(cards_widget)
        main_layout.addWidget(scroll, stretch=1)
