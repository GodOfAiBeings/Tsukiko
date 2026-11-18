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
        1. Does not ignore a failed or timed-out scheduler shutdown.
        2. If proactive workers or brain generation outlive timeout_seconds, orchestrator
           initiates safe DEFERRED shutdown rather than prematurely destroying models
           or indefinitely blocking the Qt GUI thread.
        3. Brain and model weights are kept alive until the background worker has cleanly halted.

        Returns True if shutdown completed immediately; False if shutdown is deferred.
        """
        with self._lock:
            if self._status["state"] == "stopped":
                return True
            if self._status["state"] == "stopping":
                has_running_workers = (
                    hasattr(self.initiative_scheduler, "has_running_workers")
                    and self.initiative_scheduler.has_running_workers
                )
                if not has_running_workers and not getattr(self.brain, "is_generating", False):
                    self.complete_deferred_shutdown()
                    return True
                return False

            logger.info("Stopping Tsukiko Core Orchestrator...")

            # 1. Stop initiative scheduler first if attached
            scheduler_clean = True
            if self.initiative_scheduler is not None:
                try:
                    scheduler_clean = self.initiative_scheduler.stop(wait_timeout_ms=int(timeout_seconds * 1000))
                except Exception as e:
                    logger.debug(f"Exception stopping initiative scheduler during orchestrator stop: {e}")
                    scheduler_clean = False

            # Check if workers or brain generation are still active
            has_running_workers = (
                not scheduler_clean
                or (hasattr(self.initiative_scheduler, "has_running_workers") and self.initiative_scheduler.has_running_workers)
            )
            brain_generating = getattr(self.brain, "is_generating", False)

            if has_running_workers or brain_generating:
                logger.warning(
                    "Scheduler worker or local brain inference did not halt within bounded timeout. "
                    "Initiating deferred shutdown to prevent racing active inference."
                )
                self._status["state"] = "stopping"
                self._is_running = False

                # Hook deferred shutdown to scheduler completion or watcher thread
                if self.initiative_scheduler is not None and hasattr(self.initiative_scheduler, "set_deferred_shutdown_callback"):
                    self.initiative_scheduler.set_deferred_shutdown_callback(self.complete_deferred_shutdown)
                else:
                    def _deferred_watcher() -> None:
                        deadline = time.time() + 10.0
                        while time.time() < deadline:
                            if not self.brain.is_generating:
                                break
                            time.sleep(0.05)
                        self.complete_deferred_shutdown()

                    watcher = threading.Thread(target=_deferred_watcher, daemon=True, name="deferred-shutdown-watcher")
                    watcher.start()

                return False

            # 2. Both scheduler and brain are clean; complete immediate shutdown
            self.brain.shutdown(timeout_seconds=0.0)
            self._is_running = False
            self._status["screen_sharing"] = False
            self._status["brain"] = "stopped"
            self._status["state"] = "stopped"
            logger.info("Tsukiko Core Orchestrator stopped cleanly.")
            return True

    def complete_deferred_shutdown(self) -> None:
        """Completes previously deferred shutdown once active workers/inference have terminated."""
        with self._lock:
            if self._status["state"] == "stopped":
                return
            logger.info("Completing deferred Tsukiko Core Orchestrator shutdown...")
            self.brain.complete_deferred_shutdown()
            self._is_running = False
            self._status["screen_sharing"] = False
            self._status["brain"] = "stopped"
            self._status["state"] = "stopped"
            logger.info("Deferred Tsukiko Core Orchestrator shutdown finished cleanly.")

    @property
    def is_running(self) -> bool:
        with self._lock:
            return self._is_running

    def get_status(self) -> Dict[str, Any]:
        """Returns snapshot of current orchestrator subsystem statuses."""
        with self._lock:
            status_copy = dict(self._status)
            if self.brain:
                status_copy["brain"] = self.brain.model_manager.state.value
                status_copy["brain_details"] = self.brain.get_brain_status()
            if self.hardware_profile:
                status_copy["vram_budget_mb"] = self.hardware_profile.recommended_max_vram_mb
                status_copy["ram_budget_mb"] = self.hardware_profile.recommended_max_ram_mb
            return status_copy
