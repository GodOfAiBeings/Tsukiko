"""
Tests for Tsukiko Application Entry Point and Orchestrator Lifecycle.
"""

from app.core.config.settings import TsukikoConfig
from app.core.orchestrator.engine import TsukikoOrchestrator
from app.main import parse_args
import app.main


def test_cli_argument_parsing():
    args = parse_args(["--headless", "--log-level", "DEBUG"])
    assert args.headless is True
    assert args.log_level == "DEBUG"
    assert args.check_hardware is False


def test_orchestrator_lifecycle():
    config = TsukikoConfig()
    orchestrator = TsukikoOrchestrator(config=config)

    assert orchestrator.is_running is False
    status_init = orchestrator.get_status()
    assert status_init["state"] == "uninitialized"

    orchestrator.initialize()
    status_ready = orchestrator.get_status()
    assert status_ready["state"] == "initialized"
    assert status_ready["screen_sharing"] is False

    orchestrator.start()
    assert orchestrator.is_running is True
    status_running = orchestrator.get_status()
    assert status_running["state"] == "running"

    orchestrator.stop()
    assert orchestrator.is_running is False
    status_stopped = orchestrator.get_status()
    assert status_stopped["state"] == "stopped"


def test_orchestrator_direct_start_reentrancy():
    """Regression test for Issue 2: Calling start() directly on an uninitialized orchestrator must not deadlock."""
    config = TsukikoConfig()
    orchestrator = TsukikoOrchestrator(config=config)

    assert orchestrator.get_status()["state"] == "uninitialized"
    # This must acquire re-entrant lock, call initialize(), and complete without deadlock
    orchestrator.start()
    assert orchestrator.is_running is True
    assert orchestrator.get_status()["state"] == "running"
    orchestrator.stop()
    assert orchestrator.is_running is False


def test_main_module_exports_and_imports():
    """Regression test for Issue 1: Verify app.main imports Any and has no undefined type annotations."""
    assert hasattr(app.main, "Any")
    assert getattr(app.main, "Any") is not None
