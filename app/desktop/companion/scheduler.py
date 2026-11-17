"""Tsukiko Desktop Companion — Proactive Conversational Scheduler (Phase 3).

Connects the ConversationalInitiativeEngine to the live PySide6 application lifecycle.
Runs periodic idle evaluation, enforces strict suppression rules (Game Mode, hidden
widget, minimized window, disabled chat, unanswered backoff, cooldown), and offloads
proactive inference strictly to a background QThread to keep the UI 100% responsive.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Optional

from app.core.model_manager.lifecycle import ModelLifecycleState

logger = logging.getLogger(__name__)

try:
    from PySide6.QtCore import QObject, QThread, QTimer, Signal
    HAS_PYSIDE6 = True
except ImportError:
    HAS_PYSIDE6 = False
    QObject = object  # type: ignore[misc,assignment]
    QThread = object  # type: ignore[misc,assignment]
    Signal = lambda *args: None  # type: ignore[assignment]


class ProactiveInitiativeWorker(QThread if HAS_PYSIDE6 else object):  # type: ignore[misc]
    """Background worker thread for generating proactive conversational initiatives.
    
    CRITICAL RESPONSIVENESS INVARIANT:
    Model generation runs strictly on this background thread, never on the Qt main GUI thread.
    """

    if HAS_PYSIDE6:
        initiative_ready = Signal(str)
        initiative_silent = Signal()
        error_occurred = Signal(str)

    def __init__(self, brain: Any, parent: Optional[QObject] = None) -> None:
        if not HAS_PYSIDE6:
            raise RuntimeError("PySide6 is required to instantiate ProactiveInitiativeWorker")
        super().__init__(parent)
        self._brain = brain

    def run(self) -> None:
        if not self._brain:
            self.initiative_silent.emit()
            return

        try:
            # Check model loaded state inside worker
            if not self._brain.model_manager.info.is_loaded:
                self.initiative_silent.emit()
                return

            remark = self._brain.check_conversational_initiative()
            if remark:
                self.initiative_ready.emit(remark)
            else:
                self.initiative_silent.emit()
        except Exception as e:
            logger.debug(f"Exception during background proactive initiative: {e}")
            self.error_occurred.emit(str(e))


class CompanionInitiativeScheduler(QObject if HAS_PYSIDE6 else object):  # type: ignore[misc]
    """Automatic idle-check scheduler connected to the live desktop companion application."""

    if HAS_PYSIDE6:
        initiative_triggered = Signal(str)

    def __init__(
        self,
        widget: Optional[Any] = None,
        main_window: Optional[Any] = None,
        brain: Optional[Any] = None,
        check_interval_ms: int = 5000,
        parent: Optional[QObject] = None,
    ) -> None:
        if not HAS_PYSIDE6:
            raise RuntimeError("PySide6 is required to instantiate CompanionInitiativeScheduler")
        super().__init__(parent)

        self._widget = widget
        self._main_window = main_window
        self._brain = brain
        self._active_worker: Optional[ProactiveInitiativeWorker] = None

        self._timer = QTimer(self)
        self._timer.setInterval(check_interval_ms)
        self._timer.timeout.connect(self.check_initiative)

    @property
    def is_running(self) -> bool:
        return self._timer.isActive()

    @property
    def check_interval_ms(self) -> int:
        return self._timer.interval()

    def set_check_interval_ms(self, ms: int) -> None:
        self._timer.setInterval(ms)

    def start(self) -> None:
        """Starts periodic idle checking."""
        if not self._timer.isActive():
            self._timer.start()
            logger.debug("Companion conversational initiative scheduler started.")

    def stop(self) -> None:
        """Stops periodic idle checking and aborts any active worker."""
        if self._timer.isActive():
            self._timer.stop()
        if self._active_worker and self._active_worker.isRunning():
            self._active_worker.wait(1000)
            self._active_worker = None
        logger.debug("Companion conversational initiative scheduler stopped.")

    def check_initiative(self) -> bool:
        """Evaluates whether to initiate a conversation right now.
        
        Returns True if a background worker was launched; False otherwise.
        """
        if not self._brain:
            return False

        # 1. Do NOT automatically load an unloaded model just to generate a proactive message
        if not self._brain.model_manager.info.is_loaded:
            return False

        # 2. Concurrency Protection: never launch overlapping generation or background workers
        if self._active_worker is not None:
            return False
        if self._brain.model_manager.info.state == ModelLifecycleState.GENERATING:
            return False

        # 3. Game Mode Suppression: strictly silent during gaming
        if self._widget and self._widget.is_game_mode:
            logger.debug("Initiative scheduler: suppressed due to Game Mode.")
            return False

        # 4. Hidden Widget State Suppression
        if self._widget and self._widget.is_hidden:
            logger.debug("Initiative scheduler: suppressed due to hidden companion widget.")
            return False

        # 5. Minimized and Disabled Chat Conditions Suppression
        if self._main_window:
            if self._main_window.isMinimized():
                logger.debug("Initiative scheduler: suppressed due to minimized main window.")
                return False
            if hasattr(self._main_window, "chat_view"):
                chat_view = self._main_window.chat_view
                if hasattr(chat_view, "input_field") and not chat_view.input_field.isEnabled():
                    logger.debug("Initiative scheduler: suppressed due to disabled chat input.")
                    return False
                if getattr(chat_view, "_active_worker", None) is not None:
                    return False

        # 6. Evaluate Initiative Engine Invariants (idle >= 45s, cooldown >= 120s, unanswered backoff)
        game_mode_active = self._widget.is_game_mode if self._widget else False
        widget_hidden = self._widget.is_hidden if self._widget else False
        window_minimized = self._main_window.isMinimized() if self._main_window else False

        can_speak, reason = self._brain.personality.initiative_engine.can_initiate(
            current_time=time.time(),
            game_mode_active=game_mode_active,
            widget_hidden=widget_hidden,
            window_minimized=window_minimized,
        )
        if not can_speak:
            logger.debug(f"Initiative scheduler evaluation: {reason}")
            return False

        # 7. Offload inference strictly to background QThread
        self._active_worker = ProactiveInitiativeWorker(brain=self._brain, parent=self)
        self._active_worker.initiative_ready.connect(self._handle_initiative_ready)
        self._active_worker.initiative_silent.connect(self._handle_initiative_silent)
        self._active_worker.error_occurred.connect(self._handle_initiative_silent)
        self._active_worker.finished.connect(self._cleanup_worker)
        self._active_worker.start()
        return True

    def _handle_initiative_ready(self, remark: str) -> None:
        """Called on Qt main thread when background inference yields a proactive remark."""
        logger.info(f"Delivering proactive remark: {remark[:40]}...")

        # 1. Add to main chat conversation view
        if self._main_window and hasattr(self._main_window, "chat_view"):
            self._main_window.chat_view.add_proactive_message(remark)

        # 2. Make sure proactive messages are actually visible to the user:
        # If the main window is not visible or minimized, show the speech bubble anchored to the floating widget!
        if self._widget and hasattr(self._widget, "show_speech_bubble"):
            if not self._widget.is_hidden and not self._widget.is_game_mode:
                self._widget.show_speech_bubble(remark)

        self.initiative_triggered.emit(remark)

    def _handle_initiative_silent(self) -> None:
        logger.debug("Proactive worker concluded with silence.")

    def _cleanup_worker(self) -> None:
        self._active_worker = None
