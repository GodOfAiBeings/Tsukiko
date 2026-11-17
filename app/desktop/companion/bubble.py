"""Tsukiko Desktop Companion — Proactive Speech Bubble (Phase 3).

Frameless, translucent Moonlight-themed popover window anchored near the
floating avatar widget to display proactive conversational remarks directly
on the user's desktop without requiring the main chat window to be open.
"""

from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger(__name__)

try:
    from PySide6.QtCore import QPoint, QRect, QTimer, Qt, Signal
    from PySide6.QtGui import QCursor, QGuiApplication, QMouseEvent
    from PySide6.QtWidgets import (
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
    Signal = lambda *args: None  # type: ignore[assignment]


class CompanionSpeechBubble(QWidget if HAS_PYSIDE6 else object):  # type: ignore[misc]
    """Visual speech bubble anchored near the floating companion avatar."""

    if HAS_PYSIDE6:
        clicked = Signal()
        dismissed = Signal()

    def __init__(
        self,
        parent: Optional[QWidget] = None,
        auto_dismiss_ms: int = 15000,
    ) -> None:
        if not HAS_PYSIDE6:
            raise RuntimeError("PySide6 is required to instantiate CompanionSpeechBubble")

        flags = Qt.FramelessWindowHint | Qt.Tool | Qt.WindowStaysOnTopHint
        super().__init__(parent, flags)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setObjectName("CompanionSpeechBubble")
        self.setCursor(Qt.PointingHandCursor)

        self._auto_dismiss_ms = auto_dismiss_ms
        self._dismiss_timer = QTimer(self)
        self._dismiss_timer.setSingleShot(True)
        self._dismiss_timer.timeout.connect(self.dismiss)

        self._setup_ui()

    def _setup_ui(self) -> None:
        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(6, 6, 6, 6)
        outer_layout.setSpacing(0)

        # Bubble frame container
        self.frame = QFrame(self)
        self.frame.setObjectName("bubble_frame")
        self.frame.setStyleSheet(
            "QFrame#bubble_frame {"
            "  background-color: rgba(17, 27, 46, 0.95);"
            "  border: 1px solid rgba(127, 179, 213, 0.5);"
            "  border-radius: 10px;"
            "}"
        )

        frame_layout = QVBoxLayout(self.frame)
        frame_layout.setContentsMargins(12, 10, 12, 10)
        frame_layout.setSpacing(6)

        # Header with Moon icon, title, and close button
        header_layout = QHBoxLayout()
        header_layout.setContentsMargins(0, 0, 0, 0)
        header_layout.setSpacing(6)

        moon_lbl = QLabel("🌙")
        moon_lbl.setStyleSheet("font-size: 13px; background: transparent;")
        header_layout.addWidget(moon_lbl)

        title_lbl = QLabel("Tsukiko")
        title_lbl.setStyleSheet("font-size: 11px; font-weight: 600; color: #7FB3D5; background: transparent;")
        header_layout.addWidget(title_lbl, stretch=1)

        self.btn_close = QPushButton("✕")
        self.btn_close.setFixedSize(18, 18)
        self.btn_close.setCursor(Qt.PointingHandCursor)
        self.btn_close.setStyleSheet(
            "QPushButton {"
            "  background: transparent;"
            "  color: #94A3B8;"
            "  border: none;"
            "  font-size: 11px;"
            "  font-weight: bold;"
            "}"
            "QPushButton:hover { color: #EC7063; }"
        )
        self.btn_close.clicked.connect(self.dismiss)
        header_layout.addWidget(self.btn_close)
        frame_layout.addLayout(header_layout)

        # Body text label
        self.lbl_text = QLabel("")
        self.lbl_text.setObjectName("bubble_text")
        self.lbl_text.setWordWrap(True)
        self.lbl_text.setStyleSheet(
            "font-size: 12px;"
            "line-height: 1.4;"
            "color: #F8FAFC;"
            "background: transparent;"
        )
        self.lbl_text.setMaximumWidth(280)
        frame_layout.addWidget(self.lbl_text)

        # Subtle hint at bottom
        hint_lbl = QLabel("Click to open chat")
        hint_lbl.setStyleSheet("font-size: 9px; color: #64748B; background: transparent;")
        frame_layout.addWidget(hint_lbl)

        outer_layout.addWidget(self.frame)

    def show_message(self, text: str, anchor_pos: QPoint, parent_size: int = 96) -> None:
        """Positions and shows the speech bubble near the anchor position."""
        self.lbl_text.setText(text)
        self.adjustSize()

        screen = QGuiApplication.primaryScreen()
        screen_geo = screen.availableGeometry() if screen else QRect(0, 0, 1920, 1080)

        bw = self.width()
        bh = self.height()

        # Position above the avatar by default
        target_x = anchor_pos.x() + (parent_size // 2) - (bw // 2)
        target_y = anchor_pos.y() - bh - 8

        # If too close to top edge, place to the LEFT or below
        if target_y < screen_geo.top():
            target_y = anchor_pos.y() + parent_size + 8

        # Clamp horizontal boundaries
        if target_x + bw > screen_geo.right():
            target_x = screen_geo.right() - bw - 10
        if target_x < screen_geo.left():
            target_x = screen_geo.left() + 10

        self.move(target_x, target_y)
        self.show()
        self.raise_()

        # Start auto-dismiss timer
        if self._auto_dismiss_ms > 0:
            self._dismiss_timer.start(self._auto_dismiss_ms)

    def dismiss(self) -> None:
        """Hides and dismisses the speech bubble."""
        self._dismiss_timer.stop()
        self.hide()
        self.dismissed.emit()

    def mousePressEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.LeftButton:
            self.clicked.emit()
            self.dismiss()
            event.accept()
        else:
            super().mousePressEvent(event)
