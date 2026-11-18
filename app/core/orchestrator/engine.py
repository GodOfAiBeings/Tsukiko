"""
Tsukiko Core Orchestrator
Coordinates lifecycle, subsystems, resource awareness, and state transitions.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Dict, Optional

from app.core.config.settings import TsukikoConfig, get_config
from app.core.brain.brain import TsukikoBrain
from app.core.logging.logger import get_logger
from app.core.resource_manager.hardware import HardwareInspector, HardwareProfile

logger = get_logger("SYSTEM")


class TsukikoOrchestrator:
    """Master orchestrator for Tsukiko subsystems."""

    def __init__(self, config: Optional[TsukikoConfig] = None):
        self.config = config or get_config()
        self.brain = TsukikoBrain(config=self.config)
        self.initiative_scheduler: Optional[Any] = None
        self.hardware_profile: Optional[HardwareProfile] = None
        self._deferred_watcher_thread: Optional[threading.Thread] = None
        self._is_running = False
        self._lock = threading.RLock()
        self._status: Dict[str, Any] = {
            "state": "uninitialized",
            "brain": "not_loaded",
            "memory": "offline",
            "perception": "disabled",
            "voice": "disabled",
            "screen_sharing": False,
        }

    def initialize(self, force: bool = False) -> None:
        """Inspects hardware, validates configurations, and initializes subsystem state."""
        with self._lock:
            if self._status["state"] == "initialized" and not force:
                logger.debug("Core Orchestrator is already initialized.")
                return

            logger.info("Initializing Tsukiko Core Orchestrator...")
            self.hardware_profile = HardwareInspector.inspect()
            logger.info(
                f"Environment verified: {self.hardware_profile.os_name} | "
                f"CPU: {self.hardware_profile.cpu.brand} | "
                f"RAM: {self.hardware_profile.memory.available_ram_mb}MB free | "
                f"GPU: {self.hardware_profile.gpus[0].name if self.hardware_profile.gpus else 'None'}"
            )

            # Enforce strict privacy checks at boot
            if not self.config.privacy.local_only:
                logger.warning("Privacy local_only is not True! Forcing local_only=True for safety.")
                self.config.privacy.local_only = True

            # Technically enforce offline privacy by activating socket guard
            from app.core.privacy.enforcement import enable_offline_guard
            enable_offline_guard()

            # Initialize Local AI Brain
            self.brain.initialize()
            self._status["brain"] = self.brain.model_manager.state.value

            # Ensure screen sharing starts OFF
            self.config.perception.screen_sharing_enabled = False
            self._status["screen_sharing"] = False
            self._status["state"] = "initialized"
            logger.info("Core Orchestrator initialized successfully.")

    def start(self) -> None:
        """Starts background monitoring and event loops."""
        with self._lock:
            if self._is_running:
                logger.debug("Core Orchestrator is already running.")
                return

            if self._status["state"] != "initialized":
                self.initialize()
            self._is_running = True
            self._status["state"] = "running"
            logger.info("Tsukiko Core Orchestrator is running.")

    def stop(self, timeout_seconds: float = 1.0) -> bool:
        """Gracefully shuts down all active subsystems in strict order:
        1. Initiative Scheduler (aborts proactive background worker & stops timer)
        2. Local Brain & Model Manager (cancels active inference, clears session, unloads weights)
        3. Orchestrator state transition to stopped

        Safety & Responsiveness Invariants:
        1. Never marks the orchestrator 'stopped' unless brain shutdown actually succeeds.
        2. Checks and handles the return value of both brain.shutdown() and brain.complete_deferred_shutdown().
        3. Deferred completion accounts for ALL active brain inference (normal chat + proactive scheduler).
        4. Does not immediately consider deferred shutdown complete just because the proactive scheduler has no workers.
        5. Retries deferred shutdown safely and asynchronously until all inference halts.
        6. Keeps model weights alive until all inference has stopped.
        7. Preserves bounded GUI shutdown behavior and QThread lifetime safety.
        8. Idempotent on repeated calls.

        Returns True if shutdown completed immediately; False if shutdown is deferred.
        """
        with self._lock:
            if self._status["state"] == "stopped":
                return True

            if self._status["state"] == "stopping":
                # Already in deferred shutdown mode; check if ready to complete now
                return self.complete_deferred_shutdown()

            logger.info("Stopping Tsukiko Core Orchestrator...")

            # 1. Stop initiative scheduler first if attached
            scheduler_clean = True
            if self.initiative_scheduler is not None:
                try:
                    scheduler_clean = self.initiative_scheduler.stop(wait_timeout_ms=int(timeout_seconds * 1000))
                except Exception as e:
                    logger.debug(f"Exception stopping initiative scheduler during orchestrator stop: {e}")
                    scheduler_clean = False

            # Always request brain cancellation so active generation (chat or proactive) begins stopping
            if self.brain is not None and hasattr(self.brain, "cancel_generation"):
                self.brain.cancel_generation()

            # Check if workers or brain generation are still active
            has_running_workers = (
                not scheduler_clean
                or (hasattr(self.initiative_scheduler, "has_running_workers") and self.initiative_scheduler.has_running_workers)
            )
            brain_generating = getattr(self.brain, "is_generating", False)

            if has_running_workers or brain_generating:
                logger.warning(
                    "Scheduler worker or local brain inference (chat/proactive) did not halt within timeout. "
                    "Initiating deferred shutdown to prevent racing active inference."
                )
                self._status["state"] = "stopping"
                self._is_running = False

                # Hook deferred shutdown to scheduler completion if available
                if self.initiative_scheduler is not None and hasattr(self.initiative_scheduler, "set_deferred_shutdown_callback"):
                    self.initiative_scheduler.set_deferred_shutdown_callback(self.complete_deferred_shutdown)

                # Always start deferred watcher thread to poll and retry safely until all inference halts
                self._start_deferred_shutdown_watcher()
                return False

            # 2. Both scheduler and brain appear clean; attempt immediate brain shutdown
            brain_clean = self.brain.shutdown(timeout_seconds=0.0)
            if not brain_clean:
                logger.warning(
                    "Brain refused immediate shutdown; entering deferred shutdown mode."
                )
                self._status["state"] = "stopping"
                self._is_running = False
                self._start_deferred_shutdown_watcher()
                return False

            # 3. Brain shutdown succeeded; transition to stopped
            self._is_running = False
            self._status["screen_sharing"] = False
            self._status["brain"] = "stopped"
            self._status["state"] = "stopped"
            logger.info("Tsukiko Core Orchestrator stopped cleanly.")
            return True

    def _start_deferred_shutdown_watcher(self) -> None:
        """Starts a background daemon thread that monitors and retries deferred shutdown."""
        if self._deferred_watcher_thread is not None and self._deferred_watcher_thread.is_alive():
            return

        def _watcher() -> None:
            deadline = time.time() + 15.0  # Bounded maximum retry window
            while time.time() < deadline:
                time.sleep(0.02)
                with self._lock:
                    if self._status["state"] == "stopped":
                        return
                    if self.complete_deferred_shutdown():
                        return

        self._deferred_watcher_thread = threading.Thread(
            target=_watcher,
            daemon=True,
            name="deferred-shutdown-watcher",
        )
        self._deferred_watcher_thread.start()

    def complete_deferred_shutdown(self) -> bool:
        """Completes previously deferred shutdown once active workers/inference have terminated.

        Returns True if shutdown was completed and state transitioned to 'stopped';
        False if workers or inference are still active.
        """
        with self._lock:
            if self._status["state"] == "stopped":
                return True

            # 1. Proactive workers must be completely finished
            if (
                self.initiative_scheduler is not None
                and hasattr(self.initiative_scheduler, "has_running_workers")
                and self.initiative_scheduler.has_running_workers
            ):
                logger.debug("Deferred shutdown retry: proactive scheduler workers still running.")
                return False

            # 2. Brain must not be generating (accounts for normal chat inference!)
            if getattr(self.brain, "is_generating", False):
                logger.debug("Deferred shutdown retry: brain generation (chat/proactive) still active.")
                return False

            # 3. Attempt brain deferred shutdown
            brain_clean = self.brain.complete_deferred_shutdown()
            if not brain_clean:
                logger.debug("Deferred shutdown retry: brain.complete_deferred_shutdown returned False.")
                return False

            # 4. ONLY NOW transition to 'stopped'
            self._is_running = False
            self._status["screen_sharing"] = False
            self._status["brain"] = "stopped"
            self._status["state"] = "stopped"
            logger.info("Deferred Tsukiko Core Orchestrator shutdown finished cleanly.")
            return True

    @property
    def is_running(self) -> bool:
        with self._lock:
            return self._is_running

    def get_status(self) -> Dict[str, Any]:
        """Returns snapshot of current orchestrator subsystem statuses."""
        with self._lock:
            status_copy = dict(self._status)
            if self.brain:
                if hasattr(self.brain, "model_manager") and hasattr(self.brain.model_manager, "state"):
                    status_copy["brain"] = getattr(self.brain.model_manager.state, "value", str(self.brain.model_manager.state))
                if hasattr(self.brain, "get_brain_status"):
                    status_copy["brain_details"] = self.brain.get_brain_status()
            if self.hardware_profile:
                status_copy["vram_budget_mb"] = self.hardware_profile.recommended_max_vram_mb
                status_copy["ram_budget_mb"] = self.hardware_profile.recommended_max_ram_mb
            return status_copy
