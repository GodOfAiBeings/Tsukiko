"""
Tests for Tsukiko Application Entry Point, Packaging, and Orchestrator Lifecycle.
Regression coverage for deadlock prevention, re-entrancy, failure recovery, and guard lifecycle.
"""

from __future__ import annotations

import subprocess
import sys
import pytest

from app.core.config.settings import TsukikoConfig
from app.core.orchestrator.engine import TsukikoOrchestrator
from app.main import parse_args
import app.main


def _run_subprocess_snippet(code: str, timeout: float = 5.0) -> subprocess.CompletedProcess[str]:
    """Runs a Python code snippet in an isolated child process with strict bounded timeout.

    Guarantees child process termination/reaping if the bounded timeout expires.
    """
    proc = subprocess.Popen(
        [sys.executable, "-c", code],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
        completed = subprocess.CompletedProcess(
            args=proc.args,
            returncode=proc.returncode,
            stdout=stdout,
            stderr=stderr,
        )
        return completed
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate()
        pytest.fail(
            f"Child process deadlocked and exceeded timeout of {timeout}s! "
            f"Stdout: {stdout}\nStderr: {stderr}"
        )


def test_cli_argument_parsing():
    args = parse_args(["--headless", "--log-level", "DEBUG"])
    assert args.headless is True
    assert args.log_level == "DEBUG"
    assert args.check_hardware is False


def test_main_module_exports_and_imports():
    """Regression test for Issue 1: Verify app.main imports Any and has no undefined type annotations."""
    assert hasattr(app.main, "Any")
    assert getattr(app.main, "Any") is not None


def test_check_hardware_packaged_entrypoint():
    """Regression test for Finding 3: Packaging verification - main(['--check-hardware']) runs cleanly."""
    exit_code = app.main.main(["--check-hardware"])
    assert exit_code == 0


def test_orchestrator_direct_start_subprocess():
    """Regression test: Calling start() directly without prior initialize() must not deadlock (bounded 5s)."""
    code = """
import sys
from app.core.config.settings import TsukikoConfig
from app.core.orchestrator.engine import TsukikoOrchestrator

orchestrator = TsukikoOrchestrator(config=TsukikoConfig())
assert orchestrator.get_status()["state"] == "uninitialized"
orchestrator.start()
assert orchestrator.is_running is True
assert orchestrator.get_status()["state"] == "running"
orchestrator.stop()
assert orchestrator.is_running is False
assert orchestrator.get_status()["state"] == "stopped"
sys.exit(0)
"""
    result = _run_subprocess_snippet(code, timeout=5.0)
    assert result.returncode == 0, f"Subprocess failed with stderr:\n{result.stderr}"


def test_orchestrator_repeated_start_subprocess():
    """Regression test: Repeated calls to start() must be idempotent and not deadlock (bounded 5s)."""
    code = """
import sys
from app.core.config.settings import TsukikoConfig
from app.core.orchestrator.engine import TsukikoOrchestrator

orchestrator = TsukikoOrchestrator(config=TsukikoConfig())
orchestrator.start()
orchestrator.start()
orchestrator.start()
assert orchestrator.is_running is True
orchestrator.stop()
assert orchestrator.is_running is False
sys.exit(0)
"""
    result = _run_subprocess_snippet(code, timeout=5.0)
    assert result.returncode == 0, f"Subprocess failed with stderr:\n{result.stderr}"


def test_orchestrator_repeated_stop_subprocess():
    """Regression test: Repeated calls to stop() must be idempotent and not deadlock (bounded 5s)."""
    code = """
import sys
from app.core.config.settings import TsukikoConfig
from app.core.orchestrator.engine import TsukikoOrchestrator

orchestrator = TsukikoOrchestrator(config=TsukikoConfig())
orchestrator.start()
assert orchestrator.is_running is True
orchestrator.stop()
orchestrator.stop()
orchestrator.stop()
assert orchestrator.is_running is False
assert orchestrator.get_status()["state"] == "stopped"
sys.exit(0)
"""
    result = _run_subprocess_snippet(code, timeout=5.0)
    assert result.returncode == 0, f"Subprocess failed with stderr:\n{result.stderr}"


def test_orchestrator_init_failure_handling_subprocess():
    """Regression test: Initialization failure must release locks and leave orchestrator in clean state."""
    code = """
import sys
from unittest.mock import patch
from app.core.config.settings import TsukikoConfig
from app.core.orchestrator.engine import TsukikoOrchestrator
from app.core.resource_manager.hardware import HardwareInspector

orchestrator = TsukikoOrchestrator(config=TsukikoConfig())
with patch.object(HardwareInspector, "inspect", side_effect=RuntimeError("Simulated inspect failure")):
    try:
        orchestrator.initialize()
        sys.exit(1)
    except RuntimeError:
        pass

# Ensure lock was cleanly released and orchestrator status remains uninitialized
status = orchestrator.get_status()
assert status["state"] == "uninitialized"
assert orchestrator.is_running is False
sys.exit(0)
"""
    result = _run_subprocess_snippet(code, timeout=5.0)
    assert result.returncode == 0, f"Subprocess failed with stderr:\n{result.stderr}"


def test_orchestrator_guard_lifecycle_subprocess():
    """Regression test: Normal orchestrator stop must NOT disable offline guard while process lives."""
    code = """
import sys
import socket
from app.core.config.settings import TsukikoConfig
from app.core.orchestrator.engine import TsukikoOrchestrator
from app.core.privacy.enforcement import is_offline_guard_active, PrivacyViolationError

orchestrator = TsukikoOrchestrator(config=TsukikoConfig())
orchestrator.initialize()
assert is_offline_guard_active() is True

orchestrator.start()
orchestrator.stop()

# Offline guard MUST remain active for process lifetime
assert is_offline_guard_active() is True

# Verify external outbound connect is strictly blocked after stop()
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    s.connect(("8.8.8.8", 53))
    sys.exit(2)
except PrivacyViolationError:
    sys.exit(0)
finally:
    s.close()
"""
    result = _run_subprocess_snippet(code, timeout=5.0)
    assert result.returncode == 0, f"Subprocess failed with stderr:\n{result.stderr}"
