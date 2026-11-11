"""
Tests for Tsukiko Application Entry Point and Orchestrator Lifecycle.
"""

from app.core.config.settings import TsukikoConfig
from app.core.orchestrator.engine import TsukikoOrchestrator
from app.main import parse_args


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
