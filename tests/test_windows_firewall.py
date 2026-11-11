"""
Tests for Tsukiko Windows Firewall Policy Strategy
Verifies strict executable identity validation (including Windows PE binary format),
property-level rule verification (direction, action, enabled, program, profiles, ownership),
authorization enforcement, and honest 4-state security status reporting.
"""

from pathlib import Path
import subprocess
from unittest.mock import MagicMock, patch
import pytest

from app.core.privacy.windows_firewall import (
    DEFAULT_RULE_NAME,
    RULE_GROUPING,
    RULE_OWNERSHIP_MARKER,
    SecurityStatus,
    create_firewall_rule,
    generate_firewall_rule_command,
    generate_remove_rule_command,
    get_security_status,
    is_safe_target_executable,
    remove_firewall_rule,
    verify_firewall_rule,
)


def _create_mock_pe_executable(path: Path) -> Path:
    """Creates a mock Windows PE executable starting with the MZ header."""
    path.write_bytes(b"MZ" + b"\x00" * 510)
    return path


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
        _create_mock_pe_executable(fake_exe)
        is_safe, reason = is_safe_target_executable(fake_exe)
        assert is_safe is False
        assert "shared Python interpreter" in reason


def test_is_safe_target_executable_rejects_arbitrary_executables(temp_dir):
    """Verify arbitrary non-Tsukiko executables are rejected even if they exist and have PE headers."""
    fake_notepad = temp_dir / "notepad.exe"
    _create_mock_pe_executable(fake_notepad)
    is_safe, reason = is_safe_target_executable(fake_notepad)
    assert is_safe is False
    assert "not the dedicated deployment binary" in reason

    fake_other = temp_dir / "custom_app.exe"
    _create_mock_pe_executable(fake_other)
    assert is_safe_target_executable(fake_other)[0] is False


def test_is_safe_target_executable_rejects_non_pe_binary_header(temp_dir):
    """Verify dedicated executable lacking the Windows PE 'MZ' magic header is rejected."""
    text_stub = temp_dir / "tsukiko.exe"
    text_stub.write_text("plain text stub not a real windows pe binary")
    is_safe, reason = is_safe_target_executable(text_stub)
    assert is_safe is False
    assert "missing 'MZ' executable header" in reason


def test_is_safe_target_executable_accepts_dedicated_tsukiko_binary(temp_dir):
    """Verify dedicated existing tsukiko.exe binary with PE header is accepted."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)
    is_safe, reason = is_safe_target_executable(dedicated)
    assert is_safe is True
    assert "Verified dedicated deployment binary" in reason


def test_generate_firewall_rule_command_validates_target(temp_dir):
    """Verify command generation works for dedicated binaries and rejects invalid ones."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    cmd = generate_firewall_rule_command(dedicated, rule_name="Test Rule")
    assert 'netsh advfirewall firewall add rule name="Test Rule"' in cmd
    assert 'dir=out action=block' in cmd
    assert f'program="{dedicated.resolve()}"' in cmd
    assert f'group="{RULE_GROUPING}"' in cmd
    assert RULE_OWNERSHIP_MARKER in cmd

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
    """Rule verification passes when direction=out, action=block, enabled=yes, program matches, and Tsukiko ownership verified."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    mock_netsh_output = (
        f"Rule Name:                            {DEFAULT_RULE_NAME}\n"
        f"----------------------------------------------------------------------\n"
        f"Enabled:                              Yes\n"
        f"Direction:                            Out\n"
        f"Profiles:                             Domain,Private,Public\n"
        f"Grouping:                             {RULE_GROUPING}\n"
        f"LocalIP:                              Any\n"
        f"RemoteIP:                             Any\n"
        f"Protocol:                             Any\n"
        f"Edge traversal:                       No\n"
        f"Action:                               Block\n"
        f"Program:                              {dedicated.resolve()}\n"
        f"Description:                          {RULE_OWNERSHIP_MARKER} Offline privacy boundary\n"
    )

    mock_proc = subprocess.CompletedProcess(
        args=["netsh"], returncode=0, stdout=mock_netsh_output, stderr=""
    )
    with patch("subprocess.run", return_value=mock_proc):
        verified, reason = verify_firewall_rule(dedicated, rule_name=DEFAULT_RULE_NAME)
        assert verified is True
        assert "Firewall rule verified" in reason


def test_verify_firewall_rule_rejects_unowned_or_foreign_rule(temp_dir):
    """Rule verification fails if the rule lacks Tsukiko grouping and description marker."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    # Rule named Tsukiko but without grouping or marker
    unowned_output = (
        f"Rule Name:                            {DEFAULT_RULE_NAME}\n"
        f"Enabled:                              Yes\n"
        f"Direction:                            Out\n"
        f"Profiles:                             Domain,Private,Public\n"
        f"Grouping:                             \n"
        f"Action:                               Block\n"
        f"Program:                              {dedicated.resolve()}\n"
        f"Description:                          Unrelated custom rule\n"
    )

    mock_proc = subprocess.CompletedProcess(args=["netsh"], returncode=0, stdout=unowned_output, stderr="")
    with patch("subprocess.run", return_value=mock_proc):
        verified, reason = verify_firewall_rule(dedicated, rule_name=DEFAULT_RULE_NAME)
        assert verified is False
        assert "lacks verified Tsukiko ownership markers" in reason


def test_verify_firewall_rule_rejects_mismatched_properties(temp_dir):
    """Rule verification fails if direction, action, enabled, or program mismatch."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    base_header = (
        f"Rule Name: {DEFAULT_RULE_NAME}\n"
        f"Grouping: {RULE_GROUPING}\n"
        f"Profiles: Domain,Private,Public\n"
    )

    # 1. Action is Allow instead of Block
    output_allow = f"{base_header}Enabled: Yes\nDirection: Out\nAction: Allow\nProgram: {dedicated.resolve()}\n"
    with patch("subprocess.run", return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=output_allow)):
        assert verify_firewall_rule(dedicated, rule_name=DEFAULT_RULE_NAME)[0] is False

    # 2. Direction is In instead of Out
    output_in = f"{base_header}Enabled: Yes\nDirection: In\nAction: Block\nProgram: {dedicated.resolve()}\n"
    with patch("subprocess.run", return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=output_in)):
        assert verify_firewall_rule(dedicated, rule_name=DEFAULT_RULE_NAME)[0] is False

    # 3. Enabled is No
    output_disabled = f"{base_header}Enabled: No\nDirection: Out\nAction: Block\nProgram: {dedicated.resolve()}\n"
    with patch("subprocess.run", return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=output_disabled)):
        assert verify_firewall_rule(dedicated, rule_name=DEFAULT_RULE_NAME)[0] is False

    # 4. Program mismatch
    output_mismatched_exe = f"{base_header}Enabled: Yes\nDirection: Out\nAction: Block\nProgram: C:\\other\\app.exe\n"
    with patch("subprocess.run", return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=output_mismatched_exe)):
        verified, reason = verify_firewall_rule(dedicated, rule_name=DEFAULT_RULE_NAME)
        assert verified is False
        assert "Rule program mismatch" in reason


def test_verify_firewall_rule_rejects_incomplete_profiles(temp_dir):
    """Rule verification fails if the rule does not cover all network profiles."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    incomplete_profiles = (
        f"Rule Name: {DEFAULT_RULE_NAME}\n"
        f"Grouping: {RULE_GROUPING}\n"
        f"Profiles: Public\n"
        f"Enabled: Yes\n"
        f"Direction: Out\n"
        f"Action: Block\n"
        f"Program: {dedicated.resolve()}\n"
    )
    with patch("subprocess.run", return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=incomplete_profiles)):
        verified, reason = verify_firewall_rule(dedicated, rule_name=DEFAULT_RULE_NAME)
        assert verified is False
        assert "profiles incomplete" in reason


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
    _create_mock_pe_executable(dedicated)

    with patch("subprocess.run", return_value=subprocess.CompletedProcess(args=[], returncode=1, stdout="No rules match")):
        status = get_security_status(dedicated)
        assert status.status == "os_policy_not_configured"
        assert status.is_dedicated_binary is True
        assert status.rule_exists is False


def test_security_status_os_policy_unverified(temp_dir):
    """Dedicated binary with rule name present but property mismatch reports os_policy_unverified."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    # show rule returns an Allow rule or mismatched program
    mismatched_output = (
        f"Rule Name: {DEFAULT_RULE_NAME}\n"
        f"Grouping: {RULE_GROUPING}\n"
        f"Enabled: Yes\nDirection: Out\nAction: Allow\nProgram: {dedicated.resolve()}\n"
    )
    with patch("subprocess.run", return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=mismatched_output)):
        status = get_security_status(dedicated)
        assert status.status == "os_policy_unverified"
        assert status.is_dedicated_binary is True
        assert status.rule_exists is True
        assert "could not establish" in status.details


def test_security_status_os_policy_active(temp_dir):
    """Dedicated binary with verified Outbound Block rule reports os_policy_active."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    matching_output = (
        f"Rule Name: {DEFAULT_RULE_NAME}\n"
        f"Grouping: {RULE_GROUPING}\n"
        f"Profiles: Domain,Private,Public\n"
        f"Enabled: Yes\nDirection: Out\nAction: Block\nProgram: {dedicated.resolve()}\n"
        f"Description: {RULE_OWNERSHIP_MARKER} Offline privacy boundary\n"
    )
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
    _create_mock_pe_executable(dedicated)

    ok, reason = create_firewall_rule(dedicated, user_authorized=False)
    assert ok is False
    assert "authorization is required" in reason


def test_create_firewall_rule_requires_admin(temp_dir):
    """Creating rule when not admin is rejected."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    with patch("app.core.privacy.windows_firewall.is_admin", return_value=False):
        ok, reason = create_firewall_rule(dedicated, user_authorized=True)
        assert ok is False
        assert "elevation required" in reason


def test_remove_firewall_rule_enforces_authorization_prefix_and_ownership():
    """Removal requires user authorization, Tsukiko prefix, and verified ownership."""
    # 1. Unauthorized
    assert remove_firewall_rule("Tsukiko Rule", user_authorized=False)[0] is False

    # 2. Foreign non-Tsukiko rule
    assert remove_firewall_rule("Foreign Rule", user_authorized=True)[0] is False

    # 3. Tsukiko rule but lacks ownership marker in Windows Firewall
    foreign_tsukiko_output = "Rule Name: Tsukiko Impostor\nGrouping: Other\nDescription: Non-Tsukiko rule\n"
    mock_chk = subprocess.CompletedProcess(args=["netsh"], returncode=0, stdout=foreign_tsukiko_output)
    with patch("app.core.privacy.windows_firewall.is_admin", return_value=True), \
         patch("subprocess.run", return_value=mock_chk):
        ok, reason = remove_firewall_rule("Tsukiko Impostor", user_authorized=True)
        assert ok is False
        assert "not verified as a Tsukiko-owned rule" in reason

    # 4. Genuine Tsukiko rule with verified ownership marker
    owned_output = f"Rule Name: {DEFAULT_RULE_NAME}\nGrouping: {RULE_GROUPING}\n"
    mock_chk_owned = subprocess.CompletedProcess(args=["netsh"], returncode=0, stdout=owned_output)
    mock_del = subprocess.CompletedProcess(args=["netsh"], returncode=0, stdout="Deleted 1 rule(s).")
    with patch("app.core.privacy.windows_firewall.is_admin", return_value=True), \
         patch("subprocess.run", side_effect=[mock_chk_owned, mock_del]):
        ok, reason = remove_firewall_rule(DEFAULT_RULE_NAME, user_authorized=True)
        assert ok is True
        assert "removed" in reason
