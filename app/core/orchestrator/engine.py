"""
Tsukiko Core Orchestrator
Coordinates lifecycle, subsystems, resource awareness, and state transitions.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Dict, Optional

from app.core.config.settings import TsukikoConfig, get_config
from app.core.logging.logger import get_logger
from app.core.resource_manager.hardware import HardwareInspector, HardwareProfile

logger = get_logger("SYSTEM")


class TsukikoOrchestrator:
    """Master orchestrator for Tsukiko subsystems."""

    def __init__(self, config: Optional[TsukikoConfig] = None):
        self.config = config or get_config()
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

    def stop(self) -> None:
        """Gracefully shuts down all active subsystems."""
        with self._lock:
            if not self._is_running and self._status["state"] == "stopped":
                return
            logger.info("Stopping Tsukiko Core Orchestrator...")
            self._is_running = False
            self._status["screen_sharing"] = False
            self._status["state"] = "stopped"
            # Note: The in-process offline privacy guard remains active for the process lifetime.
            logger.info("Tsukiko Core Orchestrator stopped cleanly.")

    @property
    def is_running(self) -> bool:
        with self._lock:
            return self._is_running

    def get_status(self) -> Dict[str, Any]:
        """Returns snapshot of current orchestrator subsystem statuses."""
        with self._lock:
            status_copy = dict(self._status)
            if self.hardware_profile:
                status_copy["vram_budget_mb"] = self.hardware_profile.recommended_max_vram_mb
                status_copy["ram_budget_mb"] = self.hardware_profile.recommended_max_ram_mb
            return status_copy
