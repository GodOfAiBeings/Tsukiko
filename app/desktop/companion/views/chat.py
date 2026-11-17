"""Tsukiko Desktop Companion — Chat View (Phase 3).

Displays companion dialogue interface, user/assistant message bubbles,
progressive streaming text generation via background QThread, loading indicator,
cancellation controls, error handling with retry, and clear conversation action.
"""

from __future__ import annotations

import logging
from typing import Any, List, Optional

from app.core.model_manager.lifecycle import ModelLifecycleState

logger = logging.getLogger(__name__)

try:
    from PySide6.QtCore import QObject, QThread, Qt, Signal
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
    QThread = object  # type: ignore[misc,assignment]
    Signal = lambda *args: None  # type: ignore[assignment]


class ChatWorker(QThread if HAS_PYSIDE6 else object):  # type: ignore[misc]
    """Background worker thread for non-blocking streaming inference."""

    if HAS_PYSIDE6:
        chunk_received = Signal(str)
        finished = Signal(str)
        error_occurred = Signal(str)
        cancelled = Signal()

    def __init__(self, brain: Any, user_text: str, parent: Optional[QObject] = None) -> None:
        if not HAS_PYSIDE6:
            raise RuntimeError("PySide6 is required for ChatWorker")
        super().__init__(parent)
        self._brain = brain
        self._user_text = user_text
        self._is_cancelled = False

    def cancel(self) -> None:
        self._is_cancelled = True
        if self._brain:
            self._brain.cancel_generation()

    def run(self) -> None:
        if not self._brain:
            self.error_occurred.emit("Local AI Brain is not available.")
            return

        accumulated: List[str] = []
        try:
            for chunk in self._brain.stream_response(self._user_text):
                if self._is_cancelled:
                    self.cancelled.emit()
                    return
                accumulated.append(chunk)
                self.chunk_received.emit(chunk)

            self.finished.emit("".join(accumulated))
        except Exception as e:
            logger.error(f"Error during streaming chat inference: {e}", exc_info=True)
            self.error_occurred.emit(str(e))


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
        self._full_text = text
        self._setup_ui(text, sender, timestamp)

    def _setup_ui(self, text: str, sender: str, timestamp: Optional[str]) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(4)

        # Sender label
        sender_display = "Tsukiko" if sender == "tsukiko" else ("You" if sender == "user" else "System")
        self.sender_label = QLabel(sender_display)
        self.sender_label.setObjectName("bubble_sender")
        if sender == "tsukiko":
            color = "color: #7FB3D5;"
        elif sender == "user":
            color = "color: #94A3B8;"
        else:
            color = "color: #E06C75;"
        self.sender_label.setStyleSheet(f"font-size: 11px; font-weight: 600; {color}")
        layout.addWidget(self.sender_label)

        # Message body
        self.body_label = QLabel(text)
        self.body_label.setObjectName("bubble_body")
        self.body_label.setWordWrap(True)
        self.body_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.body_label.setStyleSheet("font-size: 13px; line-height: 1.4; color: #FFFFFF;")
        layout.addWidget(self.body_label)

        # Bubble frame styling
        if sender == "tsukiko":
            self.setStyleSheet(
                "QFrame {"
                "  background-color: rgba(30, 41, 59, 0.85);"
                "  border: 1px solid rgba(127, 179, 213, 0.35);"
                "  border-radius: 12px;"
                "}"
            )
        elif sender == "user":
            self.setStyleSheet(
                "QFrame {"
                "  background-color: rgba(15, 23, 42, 0.85);"
                "  border: 1px solid rgba(148, 163, 184, 0.25);"
                "  border-radius: 12px;"
                "}"
            )
        else:
            self.setStyleSheet(
                "QFrame {"
                "  background-color: rgba(60, 20, 25, 0.75);"
                "  border: 1px solid rgba(224, 108, 117, 0.4);"
                "  border-radius: 12px;"
                "}"
            )

    def set_text(self, text: str) -> None:
        self._full_text = text
        self.body_label.setText(text)

    def append_chunk(self, chunk: str) -> None:
        self._full_text += chunk
        self.body_label.setText(self._full_text)


class ChatView(QWidget):
    """Activated Chat View for companion interaction (Phase 3).
    
    Provides real message submission, background streaming generation,
    cancellation, clear conversation, and accurate model lifecycle status.
    """

    def __init__(
        self,
        brain: Optional[Any] = None,
        orchestrator: Optional[Any] = None,
        parent: Optional[QWidget] = None,
    ) -> None:
        if not HAS_PYSIDE6:
            raise RuntimeError("PySide6 is required to instantiate ChatView")
        super().__init__(parent)
        self.setObjectName("ChatView")
        self._orchestrator = orchestrator
        self._brain = brain or (getattr(orchestrator, "brain", None) if orchestrator else None)
        self._active_worker: Optional[ChatWorker] = None
        self._current_assistant_bubble: Optional[MessageBubble] = None
        self._last_user_message: str = ""

        self._init_ui()
        self.update_model_status()

    def set_brain(self, brain: Any) -> None:
        """Sets or updates the conversational intelligence brain instance."""
        self._brain = brain
        self.update_model_status()

    def _init_ui(self) -> None:
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(12)

        # Header bar (Status Banner & Actions)
        top_bar = QHBoxLayout()
        top_bar.setSpacing(10)

        # Status Banner
        self.notice_banner = QFrame()
        self.notice_banner.setObjectName("notice_banner")
        self.notice_banner.setStyleSheet(
            "QFrame#notice_banner {"
            "  background-color: rgba(30, 58, 95, 0.65);"
            "  border: 1px solid rgba(127, 179, 213, 0.5);"
            "  border-radius: 8px;"
            "  padding: 6px 10px;"
            "}"
        )
        banner_layout = QHBoxLayout(self.notice_banner)
        banner_layout.setContentsMargins(8, 6, 8, 6)
        banner_layout.setSpacing(8)

        self.banner_icon = QLabel("🌙")
        self.banner_icon.setStyleSheet("font-size: 16px;")
        banner_layout.addWidget(self.banner_icon)

        self.banner_text = QLabel("Local AI Brain Status: Initializing...")
        self.banner_text.setWordWrap(True)
        self.banner_text.setStyleSheet("color: #D4E6F1; font-size: 12px;")
        banner_layout.addWidget(self.banner_text, stretch=1)

        top_bar.addWidget(self.notice_banner, stretch=1)

        # Clear Conversation Button
        self.btn_clear = QPushButton("Clear Chat")
        self.btn_clear.setObjectName("clear_chat_button")
        self.btn_clear.setStyleSheet(
            "QPushButton {"
            "  background-color: rgba(15, 23, 42, 0.7);"
            "  color: #94A3B8;"
            "  border: 1px solid rgba(127, 179, 213, 0.3);"
            "  border-radius: 6px;"
            "  padding: 6px 12px;"
            "  font-size: 11px;"
            "}"
            "QPushButton:hover { color: #FFFFFF; border-color: #7FB3D5; background: rgba(30, 41, 59, 0.8); }"
        )
        self.btn_clear.clicked.connect(self.clear_conversation)
        top_bar.addWidget(self.btn_clear)

        main_layout.addLayout(top_bar)

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

        # Loading / Status Indicator (hidden by default)
        self.loading_indicator = QLabel("🌙 Tsukiko is thinking...")
        self.loading_indicator.setObjectName("loading_indicator")
        self.loading_indicator.setStyleSheet(
            "color: #7FB3D5; font-size: 11px; font-style: italic; margin-left: 8px;"
        )
        self.loading_indicator.setVisible(False)
        main_layout.addWidget(self.loading_indicator)

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
        self.input_field.setPlaceholderText("Message Tsukiko...")
        self.input_field.returnPressed.connect(self._handle_send)
        composer_layout.addWidget(self.input_field, stretch=1)

        self.send_button = QPushButton("Send")
        self.send_button.setObjectName("chat_send_button")
        self.send_button.setStyleSheet(
            "QPushButton {"
            "  background-color: #2B4C7E;"
            "  color: #FFFFFF;"
            "  border: 1px solid #7FB3D5;"
            "  border-radius: 6px;"
            "  padding: 6px 16px;"
            "  font-weight: bold;"
            "}"
            "QPushButton:hover { background-color: #365D9D; }"
            "QPushButton:disabled { background-color: rgba(43, 76, 126, 0.4); color: #64748B; border-color: #475569; }"
        )
        self.send_button.clicked.connect(self._handle_send)
        composer_layout.addWidget(self.send_button)

        self.stop_button = QPushButton("Stop")
        self.stop_button.setObjectName("chat_stop_button")
        self.stop_button.setStyleSheet(
            "QPushButton {"
            "  background-color: rgba(236, 112, 99, 0.2);"
            "  color: #FADBD8;"
            "  border: 1px solid #EC7063;"
            "  border-radius: 6px;"
            "  padding: 6px 14px;"
            "  font-weight: bold;"
            "}"
            "QPushButton:hover { background-color: rgba(236, 112, 99, 0.4); }"
        )
        self.stop_button.setVisible(False)
        self.stop_button.clicked.connect(self._handle_stop)
        composer_layout.addWidget(self.stop_button)

        main_layout.addWidget(composer_container)

    def _add_initial_message(self) -> None:
        """Add the default Tsukiko greeting."""
        greeting = (
            "Greetings! I am Tsukiko (月子), your offline personal companion.\n\n"
            "I operate completely local and offline on your computer. All conversations "
            "remain strictly in-memory during this session and zero telemetry is transmitted."
        )
        bubble = MessageBubble(greeting, sender="tsukiko")
        count = self.messages_layout.count()
        self.messages_layout.insertWidget(count - 1, bubble)

    def update_model_status(self) -> None:
        """Updates the status banner and enables/disables composer based on model state."""
        if not self._brain:
            self.banner_text.setText(
                "<b>Local AI Brain Not Configured</b> — Open Settings to specify a local GGUF model file."
            )
            self.input_field.setEnabled(False)
            self.send_button.setEnabled(False)
            self.input_field.setPlaceholderText("Message Tsukiko (disabled — configure GGUF in Settings)...")
            return

        status = self._brain.get_brain_status()
        state = status.get("state")
        model_name = status.get("model_name", "None")
        quant = status.get("quantization", "Unknown")
        backend = status.get("backend", "cpu").upper()

        if state == ModelLifecycleState.NOT_CONFIGURED.value:
            self.banner_text.setText(
                "<b>Model Not Configured</b> — Open Settings to select a local GGUF model file. "
                "Inference will execute 100% offline."
            )
            self.input_field.setEnabled(False)
            self.send_button.setEnabled(False)
            self.input_field.setPlaceholderText("Configure a local GGUF model in Settings to begin chat...")
        elif state == ModelLifecycleState.NOT_INSTALLED.value:
            self.banner_text.setText(
                f"<b>Model File Missing</b> — Configured file for <code>{model_name}</code> was not found on disk. "
                "Check the model path in Settings."
            )
            self.input_field.setEnabled(False)
            self.send_button.setEnabled(False)
            self.input_field.setPlaceholderText("Model file not found on disk. Check Settings...")
        elif state == ModelLifecycleState.ERROR.value:
            err = status.get("error_message", "Unknown error")
            self.banner_text.setText(f"<b>Model Error</b> — {err}")
            self.input_field.setEnabled(False)
            self.send_button.setEnabled(False)
            self.input_field.setPlaceholderText(f"Model error: {err}")
        else:
            # READY, LOADING, LOADED, GENERATING
            loaded_desc = "Loaded" if status.get("is_loaded") else "Ready (Lazy Load)"
            self.banner_text.setText(
                f"<b>Tsukiko Brain Active</b> — Model: <b>{model_name}</b> ({quant}) | "
                f"Backend: <b>{backend}</b> | State: <b>{loaded_desc}</b>"
            )
            if not self._active_worker:
                self.input_field.setEnabled(True)
                self.send_button.setEnabled(True)
                self.input_field.setPlaceholderText("Message Tsukiko (Enter to send)...")

    def is_submission_disabled(self) -> bool:
        """Check if message submission is currently disabled."""
        return not self.input_field.isEnabled() and not self.send_button.isEnabled()

    def _handle_send(self) -> None:
        """Submits the current input field message for processing."""
        text = self.input_field.text().strip()
        if not text or self._active_worker is not None:
            return

        self._last_user_message = text
        self.input_field.clear()

        # Add user message bubble
        user_bubble = MessageBubble(text, sender="user")
        count = self.messages_layout.count()
        self.messages_layout.insertWidget(count - 1, user_bubble)

        # Create empty assistant bubble for progressive streaming
        self._current_assistant_bubble = MessageBubble("", sender="tsukiko")
        count = self.messages_layout.count()
        self.messages_layout.insertWidget(count - 1, self._current_assistant_bubble)

        # UI state transitions
        self.input_field.setEnabled(False)
        self.send_button.setVisible(False)
        self.stop_button.setVisible(True)
        self.loading_indicator.setText("🌙 Tsukiko is thinking...")
        self.loading_indicator.setVisible(True)
        self._scroll_to_bottom()

        # Start streaming worker
        self._active_worker = ChatWorker(self._brain, text, parent=self)
        self._active_worker.chunk_received.connect(self._on_chunk_received)
        self._active_worker.finished.connect(self._on_generation_finished)
        self._active_worker.error_occurred.connect(self._on_generation_error)
        self._active_worker.cancelled.connect(self._on_generation_cancelled)
        self._active_worker.start()

    def _handle_stop(self) -> None:
        """Cancels the active streaming inference."""
        if self._active_worker is not None:
            self.loading_indicator.setText("Cancelling generation...")
            self._active_worker.cancel()

    def _on_chunk_received(self, chunk: str) -> None:
        self.loading_indicator.setVisible(False)
        if self._current_assistant_bubble is not None:
            self._current_assistant_bubble.append_chunk(chunk)
            self._scroll_to_bottom()

    def _on_generation_finished(self, full_text: str) -> None:
        self._cleanup_worker()
        self._scroll_to_bottom()

    def _on_generation_cancelled(self) -> None:
        if self._current_assistant_bubble is not None:
            self._current_assistant_bubble.append_chunk(" [Cancelled]")
        self._cleanup_worker()
        self._scroll_to_bottom()

    def _on_generation_error(self, err_msg: str) -> None:
        if self._current_assistant_bubble is not None:
            self._current_assistant_bubble.set_text(f"❌ Error during generation: {err_msg}")
        self._cleanup_worker()
        self._add_retry_button()
        self._scroll_to_bottom()

    def _add_retry_button(self) -> None:
        """Adds a retry button after a generation error."""
        retry_frame = QFrame()
        retry_layout = QHBoxLayout(retry_frame)
        retry_layout.setContentsMargins(0, 0, 0, 0)
        btn_retry = QPushButton("↺ Retry Last Message")
        btn_retry.setStyleSheet(
            "QPushButton {"
            "  background-color: rgba(224, 108, 117, 0.2);"
            "  color: #E06C75;"
            "  border: 1px solid #E06C75;"
            "  border-radius: 4px;"
            "  padding: 4px 10px;"
            "  font-size: 11px;"
            "}"
            "QPushButton:hover { background-color: rgba(224, 108, 117, 0.4); }"
        )
        btn_retry.clicked.connect(lambda: (retry_frame.deleteLater(), self._retry_message()))
        retry_layout.addWidget(btn_retry)
        retry_layout.addStretch(1)
        count = self.messages_layout.count()
        self.messages_layout.insertWidget(count - 1, retry_frame)

    def _retry_message(self) -> None:
        if self._last_user_message:
            self.input_field.setText(self._last_user_message)
            self._handle_send()

    def _cleanup_worker(self) -> None:
        self._active_worker = None
        self._current_assistant_bubble = None
        self.loading_indicator.setVisible(False)
        self.stop_button.setVisible(False)
        self.send_button.setVisible(True)
        self.update_model_status()

    def clear_conversation(self) -> None:
        """Clears both UI message bubbles and temporary in-memory session history."""
        if self._brain:
            self._brain.clear_conversation()

        # Remove all message widgets except stretch
        while self.messages_layout.count() > 1:
            item = self.messages_layout.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()

        self._add_initial_message()
        self._scroll_to_bottom()

    def _scroll_to_bottom(self) -> None:
        bar = self.scroll_area.verticalScrollBar()
        if bar:
            bar.setValue(bar.maximum())
