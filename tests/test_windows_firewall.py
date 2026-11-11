"""
Tests for Tsukiko Windows Firewall Policy Strategy
Verifies that OS firewall rules are never created against shared Python interpreters,
and that status reporting distinguishes in-process vs OS boundary accurately.
"""

from pathlib import Path
from unittest.mock import patch
import pytest

from app.core.privacy.windows_firewall import (
    DEFAULT_RULE_NAME,
    SecurityStatus,
    generate_firewall_rule_command,
    generate_remove_rule_command,
    get_security_status,
    is_safe_target_executable,
)


def test_is_safe_target_executable_refuses_shared_interpreters():
    """Verify that python.exe, pythonw.exe, and shared tools are strictly rejected."""
    bad_executables = [
        "python.exe",
        "pythonw.exe",
        "py.exe",
        "pytest.exe",
        "ipython.exe",
        "C:\\Python311\\python.exe",
        "C:\\Users\\User\\.venv\\Scripts\\pythonw.exe",
    ]
    for exe in bad_executables:
        is_safe, reason = is_safe_target_executable(exe)
        assert is_safe is False
        assert "shared Python interpreter" in reason


def test_is_safe_target_executable_accepts_dedicated_binary():
    """Verify that dedicated Tsukiko binaries are accepted."""
    good_executables = [
        "tsukiko.exe",
        "C:\\Program Files\\Tsukiko\\tsukiko.exe",
        "C:\\REA\\Tsukiko\\dist\\tsukiko.exe",
    ]
    for exe in good_executables:
        is_safe, reason = is_safe_target_executable(exe)
        assert is_safe is True
        assert "dedicated application binary" in reason


def test_generate_firewall_rule_command_validates_target():
    """Verify command generation works for dedicated binaries and rejects shared interpreters."""
    # Shared interpreter must raise ValueError
    with pytest.raises(ValueError) as exc_info:
        generate_firewall_rule_command("python.exe")
    assert "shared Python interpreter" in str(exc_info.value)

    # Dedicated binary must generate valid netsh syntax
    cmd = generate_firewall_rule_command("C:\\Tsukiko\\tsukiko.exe", rule_name="Test Rule")
    assert 'netsh advfirewall firewall add rule name="Test Rule"' in cmd
    assert 'dir=out action=block' in cmd
    assert 'program="C:\\Tsukiko\\tsukiko.exe"' in cmd


def test_generate_remove_rule_command():
    """Verify remove command generation."""
    cmd = generate_remove_rule_command("Test Rule")
    assert 'netsh advfirewall firewall delete rule name="Test Rule"' in cmd


def test_security_status_shared_python_environment():
    """When running under shared python interpreter (e.g. pytest / development), status is in_process_only."""
    status = get_security_status()
    assert isinstance(status, SecurityStatus)
    assert status.status == "in_process_only"
    assert status.is_dedicated_binary is False
    assert status.rule_exists is False
    assert status.defense_level == "in_process_socket_interception"
    assert "shared Python interpreter" in status.details


def test_security_status_dedicated_binary_unconfigured():
    """When running as dedicated binary but no OS firewall rule is present."""
    with patch("app.core.privacy.windows_firewall.verify_firewall_rule", return_value=False):
        status = get_security_status("C:\\Tsukiko\\tsukiko.exe")
        assert status.status == "os_policy_not_configured"
        assert status.is_dedicated_binary is True
        assert status.rule_exists is False
        assert "no Windows Firewall outbound rule was detected" in status.details


def test_security_status_dedicated_binary_active():
    """When running as dedicated binary and OS firewall rule is confirmed active."""
    with patch("app.core.privacy.windows_firewall.verify_firewall_rule", return_value=True):
        status = get_security_status("C:\\Tsukiko\\tsukiko.exe")
        assert status.status == "os_policy_active"
        assert status.is_dedicated_binary is True
        assert status.rule_exists is True
        assert status.defense_level == "os_kernel_firewall_and_socket_interception"
        assert "Windows Firewall outbound blocking rule enforced" in status.details
