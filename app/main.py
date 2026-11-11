"""
Tsukiko Main Entry Point
Offline-First AI Desktop Companion for Windows 11
"""

from __future__ import annotations

import argparse
import os
import signal
import sys
import time
from pathlib import Path
from typing import Any, Optional

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app import __version__, __app_name__
from app.core.config.settings import load_config
from app.core.logging.logger import get_logger, setup_logging
from app.core.orchestrator.engine import TsukikoOrchestrator
from app.core.resource_manager.hardware import HardwareInspector

logger = get_logger("SYSTEM")


def parse_args(args: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="tsukiko",
        description="Tsukiko - Offline-First AI Desktop Companion for Windows 11",
    )
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"{__app_name__} v{__version__}",
    )
    parser.add_argument(
        "-c", "--config",
        type=str,
        default=None,
        help="Path to YAML configuration file (default: config/default_config.yaml)",
    )
    parser.add_argument(
        "--check-hardware",
        action="store_true",
        help="Run environment and hardware compatibility audit and exit",
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        help="Run Tsukiko core orchestrator without graphical interface",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default=None,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Set console and file logging level",
    )
    return parser.parse_args(args)


def main(args: list[str] | None = None) -> int:
    parsed = parse_args(args)

    if parsed.check_hardware:
        from app.core.resource_manager.diagnostic import run_hardware_diagnostic
        return run_hardware_diagnostic()

    # Load configuration
    config = load_config(parsed.config)
    log_level = parsed.log_level or config.app.log_level

    # Initialize structured logging
    setup_logging(log_level=log_level)
    logger.info(f"Starting {__app_name__} v{__version__}...")

    # Initialize orchestrator
    orchestrator = TsukikoOrchestrator(config=config)
    orchestrator.initialize()

    # Handle termination signals
    def handle_exit(sig: int, frame: Any) -> None:
        logger.info(f"Received exit signal ({sig}). Shutting down gracefully...")
        orchestrator.stop()
        sys.exit(0)

    try:
        signal.signal(signal.SIGINT, handle_exit)
        if hasattr(signal, "SIGTERM"):
            signal.signal(signal.SIGTERM, handle_exit)
    except (ValueError, AttributeError):
        # Signals can only be registered in the main thread of the main interpreter
        pass

    if parsed.headless:
        logger.info("Running Tsukiko in HEADLESS mode (GUI disabled). Press Ctrl+C to terminate.")
        orchestrator.start()
        try:
            while orchestrator.is_running:
                time.sleep(0.5)
        except KeyboardInterrupt:
            logger.info("Interrupted by user.")
        finally:
            orchestrator.stop()
        return 0

    # Graphical Desktop Mode
    try:
        from PySide6.QtWidgets import QApplication
        from PySide6.QtCore import QTimer
        GUI_AVAILABLE = True
    except ImportError:
        GUI_AVAILABLE = False

    if not GUI_AVAILABLE:
        logger.warning(
            "PySide6 is not yet installed in the current environment. "
            "Falling back to headless orchestrator mode. "
            "Install PySide6 via 'pip install -r requirements/ui.txt' for desktop UI."
        )
        orchestrator.start()
        try:
            while orchestrator.is_running:
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass
        finally:
            orchestrator.stop()
        return 0

    # PySide6 GUI launch
    # In Phase 2, the Tsukiko Companion Window will be attached here
    qt_app = QApplication.instance() or QApplication(sys.argv)
    qt_app.aboutToQuit.connect(orchestrator.stop)
    orchestrator.start()
    logger.info("GUI subsystem initialized. Ready for Phase 2 UI attachment.")

    # Periodic timer to allow Python signal handlers to process in Qt event loop
    timer = QTimer()
    timer.timeout.connect(lambda: None)
    timer.start(500)

    exit_code = qt_app.exec() if hasattr(qt_app, "exec") else qt_app.exec_()
    orchestrator.stop()
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
