"""
Tests for Tsukiko Windows Firewall Policy Strategy
Verifies strict executable identity validation, property-level rule verification,
authorization enforcement, and honest 4-state security status reporting.
"""

from pathlib import Path
import subprocess
from unittest.mock import MagicMock, patch
import pytest

from app.core.privacy.windows_firewall import (
    DEFAULT_RULE_NAME,
    SecurityStatus,
    create_firewall_rule,
    generate_firewall_rule_command,
    generate_remove_rule_command,
    get_security_status,
    is_safe_target_executable,
    remove_firewall_rule,
    verify_firewall_rule,
)


def test_is_safe_target_executable_rejects_empty_none_and_control_chars():
    """Verify rejection of empty, None, and command injection strings."""
    assert is_safe_target_executable(None)[0] is False
    assert is_safe_target_executable("")[0] is False
    assert is_safe_target_executable("   ")[0] is False
    assert is_safe_target_executable("tsukiko.exe; echo evil")[0] is False
    assert is_safe_target_executable("tsukiko.exe|calc.exe")[0] is False
    assert is_safe_target_executable("tsukiko.exe&echo hi")[0] is False
    assert is_safe_target_executable("tsukiko.exe\nevil")[0] is False


def test_is_safe_target_executable_rejects_nonexistent_and_directories(temp_dir):
    """Verify nonexistent paths and directories are rejected."""
    nonexistent = temp_dir / "does_not_exist_tsukiko.exe"
    is_safe, reason = is_safe_target_executable(nonexistent)
    assert is_safe is False
    assert "does not exist" in reason

    # Directory named tsukiko.exe must still be rejected
    dir_target = temp_dir / "tsukiko.exe"
    dir_target.mkdir()
    is_safe_dir, reason_dir = is_safe_target_executable(dir_target)
    assert is_safe_dir is False
    assert "not a regular file" in reason_dir


def test_is_safe_target_executable_rejects_shared_interpreters(temp_dir):
    """Verify shared Python interpreters and shells are strictly rejected."""
    bad_names = ["python.exe", "pythonw.exe", "py.exe", "pytest.exe", "cmd.exe", "powershell.exe"]
    for name in bad_names:
        fake_exe = temp_dir / name
        fake_exe.write_text("binary-stub")
        is_safe, reason = is_safe_target_executable(fake_exe)
        assert is_safe is False
        assert "shared Python interpreter" in reason


def test_is_safe_target_executable_rejects_arbitrary_executables(temp_dir):
    """Verify arbitrary non-Tsukiko executables are rejected even if they exist."""
    fake_notepad = temp_dir / "notepad.exe"
    fake_notepad.write_text("binary-stub")
    is_safe, reason = is_safe_target_executable(fake_notepad)
    assert is_safe is False
    assert "not the dedicated deployment binary" in reason

    fake_other = temp_dir / "custom_app.exe"
    fake_other.write_text("binary-stub")
    assert is_safe_target_executable(fake_other)[0] is False


def test_is_safe_target_executable_accepts_dedicated_tsukiko_binary(temp_dir):
    """Verify dedicated existing tsukiko.exe binary is accepted."""
    dedicated = temp_dir / "tsukiko.exe"
    dedicated.write_text("binary-stub")
    is_safe, reason = is_safe_target_executable(dedicated)
    assert is_safe is True
    assert "Verified dedicated deployment binary" in reason


def test_generate_firewall_rule_command_validates_target(temp_dir):
    """Verify command generation works for dedicated binaries and rejects invalid ones."""
    dedicated = temp_dir / "tsukiko.exe"
    dedicated.write_text("binary-stub")

    cmd = generate_firewall_rule_command(dedicated, rule_name="Test Rule")
    assert 'netsh advfirewall firewall add rule name="Test Rule"' in cmd
    assert 'dir=out action=block' in cmd
    assert f'program="{dedicated.resolve()}"' in cmd

    with pytest.raises(ValueError) as exc:
        generate_firewall_rule_command("python.exe")
    assert "shared Python interpreter" in str(exc.value) or "does not exist" in str(exc.value)


def test_generate_remove_rule_command():
    """Verify remove command generation enforces Tsukiko rule prefix."""
    cmd = generate_remove_rule_command("Tsukiko Test Rule")
    assert 'netsh advfirewall firewall delete rule name="Tsukiko Test Rule"' in cmd

    with pytest.raises(ValueError) as exc:
        generate_remove_rule_command("Arbitrary System Rule")
    assert "non-Tsukiko firewall rule" in str(exc.value)


# Rule Property Verification Tests
def test_verify_firewall_rule_matches_all_properties(temp_dir):
    """Rule verification passes when direction=out, action=block, enabled=yes, and program matches."""
    dedicated = temp_dir / "tsukiko.exe"
    dedicated.write_text("binary-stub")

    mock_netsh_output = (
        f"Rule Name:                            Tsukiko Outbound Block\n"
        f"----------------------------------------------------------------------\n"
        f"Enabled:                              Yes\n"
        f"Direction:                            Out\n"
        f"Profiles:                             Domain,Private,Public\n"
        f"Grouping:                             \n"
        f"LocalIP:                              Any\n"
        f"RemoteIP:                             Any\n"
        f"Protocol:                             Any\n"
        f"Edge traversal:                       No\n"
        f"Action:                               Block\n"
        f"Program:                              {dedicated.resolve()}\n"
    )

    mock_proc = subprocess.CompletedProcess(
        args=["netsh"], returncode=0, stdout=mock_netsh_output, stderr=""
    )
    with patch("subprocess.run", return_value=mock_proc):
        verified, reason = verify_firewall_rule(dedicated)
        assert verified is True
        assert "Firewall rule verified" in reason


def test_verify_firewall_rule_rejects_mismatched_properties(temp_dir):
    """Rule verification fails if direction, action, enabled, or program mismatch."""
    dedicated = temp_dir / "tsukiko.exe"
    dedicated.write_text("binary-stub")

    # 1. Action is Allow instead of Block
    output_allow = (
        f"Rule Name: Tsukiko Outbound Block\nEnabled: Yes\nDirection: Out\nAction: Allow\nProgram: {dedicated.resolve()}\n"
    )
    with patch("subprocess.run", return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=output_allow)):
        assert verify_firewall_rule(dedicated)[0] is False

    # 2. Direction is In instead of Out
    output_in = (
        f"Rule Name: Tsukiko Outbound Block\nEnabled: Yes\nDirection: In\nAction: Block\nProgram: {dedicated.resolve()}\n"
    )
    with patch("subprocess.run", return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=output_in)):
        assert verify_firewall_rule(dedicated)[0] is False

    # 3. Enabled is No
    output_disabled = (
        f"Rule Name: Tsukiko Outbound Block\nEnabled: No\nDirection: Out\nAction: Block\nProgram: {dedicated.resolve()}\n"
    )
    with patch("subprocess.run", return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=output_disabled)):
        assert verify_firewall_rule(dedicated)[0] is False

    # 4. Program mismatch
    output_mismatched_exe = (
        f"Rule Name: Tsukiko Outbound Block\nEnabled: Yes\nDirection: Out\nAction: Block\nProgram: C:\\other\\app.exe\n"
    )
    with patch("subprocess.run", return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=output_mismatched_exe)):
        verified, reason = verify_firewall_rule(dedicated)
        assert verified is False
        assert "Rule program mismatch" in reason


# 4-State Security Status Tests
def test_security_status_in_process_only():
    """Shared python environment reports in_process_only."""
    status = get_security_status()
    assert isinstance(status, SecurityStatus)
    assert status.status == "in_process_only"
    assert status.is_dedicated_binary is False
    assert status.rule_exists is False
    assert status.defense_level == "in_process_socket_interception"


def test_security_status_os_policy_not_configured(temp_dir):
    """Dedicated binary with no existing firewall rule reports os_policy_not_configured."""
    dedicated = temp_dir / "tsukiko.exe"
    dedicated.write_text("binary-stub")

    with patch("subprocess.run", return_value=subprocess.CompletedProcess(args=[], returncode=1, stdout="No rules match")):
        status = get_security_status(dedicated)
        assert status.status == "os_policy_not_configured"
        assert status.is_dedicated_binary is True
        assert status.rule_exists is False


def test_security_status_os_policy_unverified(temp_dir):
    """Dedicated binary with rule name present but property mismatch reports os_policy_unverified."""
    dedicated = temp_dir / "tsukiko.exe"
    dedicated.write_text("binary-stub")

    # show rule returns an Allow rule or mismatched program
    mismatched_output = f"Rule Name: Tsukiko Outbound Block\nEnabled: Yes\nDirection: Out\nAction: Allow\nProgram: {dedicated.resolve()}\n"
    with patch("subprocess.run", return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=mismatched_output)):
        status = get_security_status(dedicated)
        assert status.status == "os_policy_unverified"
        assert status.is_dedicated_binary is True
        assert status.rule_exists is True
        assert "could not establish" in status.details


def test_security_status_os_policy_active(temp_dir):
    """Dedicated binary with verified Outbound Block rule reports os_policy_active."""
    dedicated = temp_dir / "tsukiko.exe"
    dedicated.write_text("binary-stub")

    matching_output = f"Rule Name: Tsukiko Outbound Block\nEnabled: Yes\nDirection: Out\nAction: Block\nProgram: {dedicated.resolve()}\n"
    with patch("subprocess.run", return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=matching_output)):
        status = get_security_status(dedicated)
        assert status.status == "os_policy_active"
        assert status.is_dedicated_binary is True
        assert status.rule_exists is True
        assert status.defense_level == "os_kernel_firewall_and_socket_interception"


# Creation and Removal Tests
def test_create_firewall_rule_requires_user_authorization(temp_dir):
    """Creating rule without user_authorized=True is rejected."""
    dedicated = temp_dir / "tsukiko.exe"
    dedicated.write_text("binary-stub")

    ok, reason = create_firewall_rule(dedicated, user_authorized=False)
    assert ok is False
    assert "authorization is required" in reason


def test_create_firewall_rule_requires_admin(temp_dir):
    """Creating rule when not admin is rejected."""
    dedicated = temp_dir / "tsukiko.exe"
    dedicated.write_text("binary-stub")

    with patch("app.core.privacy.windows_firewall.is_admin", return_value=False):
        ok, reason = create_firewall_rule(dedicated, user_authorized=True)
        assert ok is False
        assert "elevation required" in reason


def test_remove_firewall_rule_enforces_authorization_and_prefix():
    """Removal requires user authorization and Tsukiko prefix."""
    assert remove_firewall_rule("Tsukiko Rule", user_authorized=False)[0] is False
    assert remove_firewall_rule("Foreign Rule", user_authorized=True)[0] is False
