"""Tsukiko Desktop Companion — Chat View (Phase 2).

Displays companion dialogue interface and history presentation.
In accordance with Phase 2 scope boundaries, message submission is
strictly disabled until the local AI brain is integrated in Phase 3.
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
        QLineEdit,
        QPushButton,
        QScrollArea,
        QSizePolicy,
        QVBoxLayout,
        QWidget,
    )
    HAS_PYSIDE6 = True
except ImportError:
    HAS_PYSIDE6 = False
    QWidget = object  # type: ignore[misc,assignment]


class MessageBubble(QFrame if HAS_PYSIDE6 else object):  # type: ignore[misc]
    """Visual message bubble for chat history."""

    def __init__(
        self,
        text: str,
        sender: str = "tsukiko",
        timestamp: Optional[str] = None,
        parent: Optional[QWidget] = None,
    ) -> None:
        if not HAS_PYSIDE6:
            raise RuntimeError("PySide6 is required to instantiate MessageBubble")
        super().__init__(parent)
        self._sender = sender
        self._setup_ui(text, sender, timestamp)

    def _setup_ui(self, text: str, sender: str, timestamp: Optional[str]) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(4)

        # Sender label
        sender_label = QLabel("Tsukiko" if sender == "tsukiko" else "You")
        sender_label.setObjectName("bubble_sender")
        sender_label.setStyleSheet(
            "font-size: 11px; font-weight: 600; "
            + ("color: #7FB3D5;" if sender == "tsukiko" else "color: #94A3B8;")
        )
        layout.addWidget(sender_label)

        # Message body
        body_label = QLabel(text)
        body_label.setObjectName("bubble_body")
        body_label.setWordWrap(True)
        body_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        body_label.setStyleSheet("font-size: 13px; line-height: 1.4; color: #FFFFFF;")
        layout.addWidget(body_label)

        # Bubble frame styling
        if sender == "tsukiko":
            self.setStyleSheet(
                "QFrame {"
                "  background-color: rgba(30, 41, 59, 0.85);"
                "  border: 1px solid rgba(127, 179, 213, 0.35);"
                "  border-radius: 12px;"
                "}"
            )
        else:
            self.setStyleSheet(
                "QFrame {"
                "  background-color: rgba(15, 23, 42, 0.85);"
                "  border: 1px solid rgba(148, 163, 184, 0.25);"
                "  border-radius: 12px;"
                "}"
            )


class ChatView(QWidget):
    """Chat view for companion interaction.
    
    Message submission is strictly disabled in Phase 2 because the
    local neural inference engine arrives in Phase 3.
    """

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        if not HAS_PYSIDE6:
            raise RuntimeError("PySide6 is required to instantiate ChatView")
        super().__init__(parent)
        self.setObjectName("ChatView")
        self._init_ui()

    def _init_ui(self) -> None:
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(16)

        # Phase 3 Notice Banner (Prominent and unambiguous)
        self.notice_banner = QFrame()
        self.notice_banner.setObjectName("notice_banner")
        self.notice_banner.setStyleSheet(
            "QFrame#notice_banner {"
            "  background-color: rgba(30, 58, 95, 0.65);"
            "  border: 1px solid rgba(127, 179, 213, 0.5);"
            "  border-radius: 8px;"
            "  padding: 8px;"
            "}"
        )
        banner_layout = QHBoxLayout(self.notice_banner)
        banner_layout.setContentsMargins(12, 10, 12, 10)
        banner_layout.setSpacing(10)

        banner_icon = QLabel("🌙")
        banner_icon.setStyleSheet("font-size: 20px;")
        banner_layout.addWidget(banner_icon)

        banner_text = QLabel(
            "<b>Phase 2 Desktop UI Active</b> — Local AI Brain arrives in Phase 3.<br>"
            "<span style='color: #94A3B8; font-size: 11px;'>"
            "Message submission is strictly disabled until the local inference engine is integrated. "
            "Zero network traffic is permitted.</span>"
        )
        banner_text.setWordWrap(True)
        banner_text.setStyleSheet("color: #D4E6F1; font-size: 12px;")
        banner_layout.addWidget(banner_text, stretch=1)

        main_layout.addWidget(self.notice_banner)

        # Scrollable message history area
        self.scroll_area = QScrollArea()
        self.scroll_area.setObjectName("chat_scroll_area")
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setFrameShape(QFrame.NoFrame)
        self.scroll_area.setStyleSheet("background: transparent;")

        self.messages_container = QWidget()
        self.messages_container.setObjectName("messages_container")
        self.messages_container.setStyleSheet("background: transparent;")
        self.messages_layout = QVBoxLayout(self.messages_container)
        self.messages_layout.setContentsMargins(0, 0, 0, 0)
        self.messages_layout.setSpacing(12)
        self.messages_layout.addStretch(1)

        self.scroll_area.setWidget(self.messages_container)
        main_layout.addWidget(self.scroll_area, stretch=1)

        # Add initial companion greeting message
        self._add_initial_message()

        # Composer bar at the bottom
        composer_container = QFrame()
        composer_container.setObjectName("composer_container")
        composer_container.setStyleSheet(
            "QFrame#composer_container {"
            "  background-color: rgba(15, 23, 42, 0.7);"
            "  border: 1px solid rgba(127, 179, 213, 0.2);"
            "  border-radius: 10px;"
            "  padding: 4px;"
            "}"
        )
        composer_layout = QHBoxLayout(composer_container)
        composer_layout.setContentsMargins(8, 6, 8, 6)
        composer_layout.setSpacing(8)

        self.input_field = QLineEdit()
        self.input_field.setObjectName("chat_input")
        self.input_field.setPlaceholderText(
            "Message Tsukiko (disabled — Local AI Brain uninstalled until Phase 3)..."
        )
        self.input_field.setEnabled(False)  # Strictly disabled in Phase 2
        self.input_field.setToolTip(
            "Message submission is disabled in Phase 2. Local AI inference arrives in Phase 3."
        )
        composer_layout.addWidget(self.input_field, stretch=1)

        self.send_button = QPushButton("Send")
        self.send_button.setObjectName("chat_send_button")
        self.send_button.setEnabled(False)  # Strictly disabled in Phase 2
        self.send_button.setToolTip(
            "Message submission is disabled in Phase 2. Local AI inference arrives in Phase 3."
        )
        composer_layout.addWidget(self.send_button)

        main_layout.addWidget(composer_container)

    def _add_initial_message(self) -> None:
        """Add the default Tsukiko greeting explaining Phase 2 state."""
        greeting = (
            "Greetings! I am Tsukiko (月子), your offline desktop companion.\n\n"
            "My Phase 2 desktop user interface is active. My local neural AI brain "
            "will be installed in Phase 3. Outbound network communication remains "
            "strictly blocked by the zero-trust privacy boundary."
        )
        bubble = MessageBubble(greeting, sender="tsukiko")
        # Insert before stretch
        count = self.messages_layout.count()
        self.messages_layout.insertWidget(count - 1, bubble)

    def is_submission_disabled(self) -> bool:
        """Check if message submission is disabled."""
        return not self.input_field.isEnabled() and not self.send_button.isEnabled()
