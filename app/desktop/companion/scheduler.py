"""Tsukiko Desktop Companion — Proactive Conversational Scheduler (Phase 3).

Connects the ConversationalInitiativeEngine to the live PySide6 application lifecycle.
Runs periodic idle evaluation, enforces strict suppression rules (Game Mode, hidden
widget, minimized window, disabled chat, unanswered backoff, cooldown), and offloads
proactive inference strictly to a background QThread to keep the UI 100% responsive.
"""

from __future__ import annotations

import logging
import os
import time
import warnings
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
        self._is_aborted = False

    def abort(self) -> None:
        """Signals the worker to abort and cancels active generation in the brain."""
        self._is_aborted = True
        if self._brain:
            try:
                self._brain.cancel_generation()
            except Exception as e:
                logger.debug(f"Exception during worker abort cancelling brain: {e}")

    @property
    def is_aborted(self) -> bool:
        return self._is_aborted

    def run(self) -> None:
        if self._is_aborted or not self._brain:
            if not self._is_aborted:
                self.initiative_silent.emit()
            return

        try:
            # Check model loaded state inside worker
            if not self._brain.model_manager.info.is_loaded:
                if not self._is_aborted:
                    self.initiative_silent.emit()
                return

            remark = self._brain.check_conversational_initiative()
            if self._is_aborted:
                return

            if remark:
                self.initiative_ready.emit(remark)
            else:
                self.initiative_silent.emit()
        except Exception as e:
            if self._is_aborted:
                return
            logger.debug(f"Exception during background proactive initiative: {e}")
            self.error_occurred.emit(str(e))


# Module-level registry to prevent premature garbage collection of running threads
_LIVING_WORKERS: set[ProactiveInitiativeWorker] = set()


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
        self._retained_workers: list[ProactiveInitiativeWorker] = []
        self._is_stopped: bool = False
        self._on_deferred_shutdown_callback: Optional[Any] = None

        self._timer = QTimer(self)
        self._timer.setInterval(check_interval_ms)
        self._timer.timeout.connect(self.check_initiative)

    @property
    def has_running_workers(self) -> bool:
        """Returns True if the active worker or any retained worker is actively executing."""
        if self._active_worker and self._active_worker.isRunning():
            return True
        for w in self._retained_workers:
            if w.isRunning():
                return True
        return False

    def set_deferred_shutdown_callback(self, callback: Any) -> None:
        """Registers a callback to execute once all running workers have terminated."""
        if not self.has_running_workers:
            try:
                callback()
            except Exception as e:
                logger.debug(f"Exception invoking immediate shutdown callback: {e}")
        else:
            self._on_deferred_shutdown_callback = callback

    @property
    def is_running(self) -> bool:
        return self._timer.isActive() and not self._is_stopped

    @property
    def is_stopped(self) -> bool:
        return self._is_stopped

    @property
    def active_worker(self) -> Optional[ProactiveInitiativeWorker]:
        return self._active_worker

    @property
    def retained_workers(self) -> list[ProactiveInitiativeWorker]:
        return list(self._retained_workers)

    @property
    def check_interval_ms(self) -> int:
        return self._timer.interval()

    def set_check_interval_ms(self, ms: int) -> None:
        self._timer.setInterval(ms)

    def start(self) -> None:
        """Starts periodic idle checking."""
        self._is_stopped = False
        if not self._timer.isActive():
            self._timer.start()
            logger.debug("Companion conversational initiative scheduler started.")

    def stop(self, wait_timeout_ms: int = 2000) -> bool:
        """Stops periodic idle checking and aborts any active worker deterministically.
        
        Lifecycle & Concurrency Invariants:
        1. Idempotent: safe to invoke repeatedly from signal handlers, UI events, and orchestrator.
        2. Halts the periodic QTimer immediately so no new checks run.
        3. Never destroys or discards a running QThread wrapper prematurely.
        4. Cancels active proactive generation in the brain via worker.abort().
        5. Waits up to wait_timeout_ms for the worker thread to exit cleanly.
        6. If the worker outlives wait_timeout_ms, the reference is safely retained until
           worker.finished fires, completely preventing 'QThread: Destroyed while thread is still running'.
        
        Returns True if clean shutdown succeeded (or no worker was running); False if worker is still running.
        """
        self._is_stopped = True
        if self._timer.isActive():
            self._timer.stop()

        worker = self._active_worker
        if worker is None:
            logger.debug("Companion conversational initiative scheduler stopped (no active worker).")
            return True

        if worker.isRunning():
            # 1. Safely disconnect delivery signals so no UI callbacks fire during shutdown
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", RuntimeWarning)
                for sig, slot in (
                    (worker.initiative_ready, self._handle_initiative_ready),
                    (worker.initiative_silent, self._handle_initiative_silent),
                    (worker.error_occurred, self._handle_initiative_silent),
                    (worker.finished, self._cleanup_worker),
                ):
                    try:
                        sig.disconnect(slot)
                    except Exception:
                        pass

            # 2. Retain reference so Python never garbage-collects a running QThread
            if worker not in self._retained_workers:
                self._retained_workers.append(worker)

            # 3. Request abort and cancel brain generation
            worker.abort()

            # 4. Attach safe deferred cleanup to release reference ONLY when thread has truly exited
            def _on_retired_finished(w: ProactiveInitiativeWorker = worker) -> None:
                try:
                    if w in self._retained_workers:
                        self._retained_workers.remove(w)
                except (ValueError, RuntimeError):
                    pass
                if self._active_worker is w:
                    self._active_worker = None
                _LIVING_WORKERS.discard(w)

                # If all workers have completed, invoke deferred shutdown callback if registered
                if not self.has_running_workers and self._on_deferred_shutdown_callback is not None:
                    cb = self._on_deferred_shutdown_callback
                    self._on_deferred_shutdown_callback = None
                    try:
                        cb()
                    except Exception as e:
                        logger.debug(f"Exception in deferred shutdown callback: {e}")

            try:
                worker.finished.connect(_on_retired_finished)
            except (RuntimeError, TypeError):
                pass

            # 5. Wait bounded duration for clean exit
            finished = worker.wait(wait_timeout_ms)
            if finished:
                _on_retired_finished(worker)
                self._active_worker = None
                logger.debug("Companion conversational initiative scheduler stopped cleanly.")
                return True
            else:
                logger.warning(
                    f"Active proactive worker exceeded {wait_timeout_ms}ms wait timeout; "
                    "retaining worker reference safely until thread completion."
                )
                return False
        else:
            self._active_worker = None
            logger.debug("Companion conversational initiative scheduler stopped (worker was not running).")
            return True

    def check_initiative(self) -> bool:
        """Evaluates whether to initiate a conversation right now.
        
        Returns True if a background worker was launched; False otherwise.
        """
        if self._is_stopped or not self._brain:
            return False

        # 1. Do NOT automatically load an unloaded model just to generate a proactive message
        if not self._brain.model_manager.info.is_loaded:
            return False

        # 2. Concurrency Protection: never launch overlapping generation or background workers
        if self._active_worker is not None and self._active_worker.isRunning():
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

        # 5. Fullscreen Safety Suppression
        # Speech bubbles and proactive initiatives must never intrude over fullscreen games or apps
        if self._widget and hasattr(self._widget, "_fullscreen_detector"):
            eval_result = self._widget._fullscreen_detector.evaluate_fullscreen(own_pids={os.getpid()})
            if eval_result.is_fullscreen or not eval_result.safe_always_on_top:
                logger.debug(f"Initiative scheduler: suppressed due to fullscreen safety ({eval_result.reason}).")
                return False

        # 6. Minimized and Disabled Chat Conditions Suppression
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

        # 7. Evaluate Initiative Engine Invariants (idle >= 45s, cooldown >= 120s, unanswered backoff)
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

        # 8. Offload inference strictly to background QThread (parent=None ensures independent lifetime)
        worker = ProactiveInitiativeWorker(brain=self._brain, parent=None)
        self._active_worker = worker
        _LIVING_WORKERS.add(worker)
        worker.initiative_ready.connect(self._handle_initiative_ready)
        worker.initiative_silent.connect(self._handle_initiative_silent)
        worker.error_occurred.connect(self._handle_initiative_silent)
        worker.finished.connect(self._cleanup_worker)
        worker.start()
        return True

    def _handle_initiative_ready(self, remark: str) -> None:
        """Called on Qt main thread when background inference yields a proactive remark."""
        if self._is_stopped:
            return

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
        if self._active_worker and not self._active_worker.isRunning():
            _LIVING_WORKERS.discard(self._active_worker)
            self._active_worker = None
