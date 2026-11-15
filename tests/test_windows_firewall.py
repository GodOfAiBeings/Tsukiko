"""
Tests for Tsukiko Windows Firewall Policy Strategy.
Verifies:
1. Strict Windows PE binary structural validation (MZ magic, 0x3C e_lfanew, PE\\0\\0 signature, bounds).
2. Fail-closed Windows Firewall profile validation (rejection of missing, empty, unknown, and partial profiles).
3. ActiveStore effective policy verification (profiles enabled, AllowLocalFirewallRules, effective rules).
4. Precise rule ownership validation and safe multi-rule deletion.
5. Honest 4-state security status reporting.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
from unittest.mock import MagicMock, patch
import pytest

from app.core.privacy.windows_firewall import (
    DEFAULT_DESCRIPTION,
    DEFAULT_RULE_NAME,
    LEGACY_RULE_NAME,
    RULE_GROUPING,
    RULE_OWNERSHIP_MARKER,
    STABLE_RULE_ID,
    FirewallRuleInfo,
    SecurityStatus,
    create_firewall_rule,
    generate_firewall_rule_command,
    generate_remove_rule_command,
    get_security_status,
    is_safe_target_executable,
    is_tsukiko_owned_rule,
    parse_netsh_rule_blocks,
    parse_powershell_rules_json,
    query_matching_firewall_rules,
    remove_firewall_rule,
    validate_firewall_profiles,
    validate_pe_structure,
    verify_effective_firewall_policy,
    verify_firewall_rule,
)


@pytest.fixture(autouse=True)
def mock_windows_env():
    """Ensure Windows Firewall unit tests run consistently across all platforms."""
    with patch("platform.system", return_value="Windows"), \
         patch("shutil.which", side_effect=lambda cmd: f"C:\\Windows\\System32\\{cmd}.exe"):
        yield


def _create_mock_pe_executable(path: Path) -> Path:
    """Creates a structurally valid mock Windows PE executable.

    Layout:
    - 64-byte DOS header starting with b'MZ' (0x4D, 0x5A).
    - At offset 0x3C: 4-byte little-endian integer pointing to offset 64 (0x40).
    - At offset 64 (0x40): 4-byte signature b'PE\\0\\0' (0x50, 0x45, 0x00, 0x00).
    - Trailing bytes so total file size is 128 bytes (>= 68 bytes).
    """
    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    dos_header[0x3C:0x40] = (64).to_bytes(4, byteorder="little", signed=False)
    pe_sig = b"PE\x00\x00"
    trailing = b"\x00" * 60
    path.write_bytes(bytes(dos_header) + pe_sig + trailing)
    return path


# =====================================================================
# 1. PE Structural Validation Tests
# =====================================================================

def test_validate_pe_structure_valid(temp_dir):
    """Valid synthetic PE binary passes structural validation."""
    fake_exe = temp_dir / "valid.exe"
    _create_mock_pe_executable(fake_exe)
    ok, reason = validate_pe_structure(fake_exe)
    assert ok is True
    assert "Valid Windows PE executable binary structure confirmed" in reason


def test_validate_pe_structure_file_too_small(temp_dir):
    """File smaller than 64 bytes is rejected as having truncated DOS header."""
    small_exe = temp_dir / "small.exe"
    small_exe.write_bytes(b"MZ" + b"\x00" * 20)
    ok, reason = validate_pe_structure(small_exe)
    assert ok is False
    assert "too small" in reason


def test_validate_pe_structure_missing_mz(temp_dir):
    """File >= 64 bytes lacking 'MZ' magic at byte 0 is rejected."""
    bad_mz = temp_dir / "bad_mz.exe"
    content = bytearray(128)
    content[0:2] = b"XX"
    content[0x3C:0x40] = (64).to_bytes(4, "little")
    content[64:68] = b"PE\x00\x00"
    bad_mz.write_bytes(bytes(content))
    ok, reason = validate_pe_structure(bad_mz)
    assert ok is False
    assert "Missing DOS executable signature" in reason


def test_validate_pe_structure_offset_overlaps_dos(temp_dir):
    """PE offset < 0x40 (overlapping DOS header) is rejected."""
    overlap_exe = temp_dir / "overlap.exe"
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = (0x20).to_bytes(4, "little")  # 32 < 64
    overlap_exe.write_bytes(bytes(dos) + b"\x00" * 64)
    ok, reason = validate_pe_structure(overlap_exe)
    assert ok is False
    assert "overlaps DOS header" in reason


def test_validate_pe_structure_offset_beyond_eof(temp_dir):
    """PE offset pointing beyond file length is rejected."""
    eof_exe = temp_dir / "beyond_eof.exe"
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = (500).to_bytes(4, "little")  # offset 500 in 128-byte file
    eof_exe.write_bytes(bytes(dos) + b"\x00" * 64)
    ok, reason = validate_pe_structure(eof_exe)
    assert ok is False
    assert "outside file boundaries" in reason


def test_validate_pe_structure_truncated_pe_sig(temp_dir):
    """PE offset pointing so close to EOF that 4-byte signature cannot be read is rejected."""
    trunc_exe = temp_dir / "trunc_pe.exe"
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = (64).to_bytes(4, "little")
    # File is only 66 bytes, so pe_sig at 64 only has 2 bytes
    trunc_exe.write_bytes(bytes(dos) + b"PE")
    ok, reason = validate_pe_structure(trunc_exe)
    assert ok is False
    assert "outside file boundaries" in reason


def test_validate_pe_structure_invalid_pe_sig(temp_dir):
    """Valid DOS header pointing to non-PE signature (e.g. NE or garbage) is rejected."""
    bad_sig_exe = temp_dir / "bad_sig.exe"
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = (64).to_bytes(4, "little")
    bad_sig_exe.write_bytes(bytes(dos) + b"NE\x00\x00" + b"\x00" * 60)
    ok, reason = validate_pe_structure(bad_sig_exe)
    assert ok is False
    assert "Invalid PE signature" in reason


# =====================================================================
# 2. Executable Identity & Safety Tests
# =====================================================================

def test_is_safe_target_executable_accepts_dedicated_tsukiko_binary(temp_dir):
    """Dedicated tsukiko.exe with valid PE binary structure is accepted."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)
    is_safe, reason = is_safe_target_executable(dedicated)
    assert is_safe is True
    assert "Verified dedicated deployment binary" in reason


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

    dir_target = temp_dir / "tsukiko.exe"
    dir_target.mkdir()
    is_safe_dir, reason_dir = is_safe_target_executable(dir_target)
    assert is_safe_dir is False
    assert "not a regular file" in reason_dir


def test_is_safe_target_executable_rejects_shared_interpreters(temp_dir):
    """Shared Python interpreters and shell binaries are strictly rejected."""
    bad_names = ["python.exe", "pythonw.exe", "py.exe", "pytest.exe", "cmd.exe", "powershell.exe"]
    for name in bad_names:
        fake_exe = temp_dir / name
        _create_mock_pe_executable(fake_exe)
        is_safe, reason = is_safe_target_executable(fake_exe)
        assert is_safe is False
        assert "shared Python interpreter" in reason


def test_is_safe_target_executable_rejects_arbitrary_executables(temp_dir):
    """Arbitrary executables with valid PE structures are rejected if not tsukiko.exe."""
    fake_notepad = temp_dir / "notepad.exe"
    _create_mock_pe_executable(fake_notepad)
    is_safe, reason = is_safe_target_executable(fake_notepad)
    assert is_safe is False
    assert "not the dedicated deployment binary" in reason


def test_is_safe_target_executable_rejects_non_pe_text_file(temp_dir):
    """Dedicated tsukiko.exe that is a plain text file is rejected."""
    stub = temp_dir / "tsukiko.exe"
    stub.write_text("plain text script pretending to be an executable binary" + " " * 40)
    is_safe, reason = is_safe_target_executable(stub)
    assert is_safe is False
    assert "Missing DOS executable signature" in reason or "too small" in reason


# =====================================================================
# 3. Fail-Closed Profile Validation Tests
# =====================================================================

def test_validate_firewall_profiles_missing():
    """Missing (None) profile information fails closed."""
    ok, msg = validate_firewall_profiles(None)
    assert ok is False
    assert "missing" in msg


def test_validate_firewall_profiles_empty():
    """Empty or whitespace-only profile information fails closed."""
    assert validate_firewall_profiles("")[0] is False
    assert validate_firewall_profiles("   ")[0] is False


def test_validate_firewall_profiles_domain_only():
    """Rule covering only Domain profile is rejected as incomplete."""
    ok, msg = validate_firewall_profiles("Domain")
    assert ok is False
    assert "missing required profiles" in msg


def test_validate_firewall_profiles_private_only():
    """Rule covering only Private profile is rejected as incomplete."""
    ok, msg = validate_firewall_profiles("Private")
    assert ok is False
    assert "missing required profiles" in msg


def test_validate_firewall_profiles_public_only():
    """Rule covering only Public profile is rejected as incomplete."""
    ok, msg = validate_firewall_profiles("Public")
    assert ok is False
    assert "missing required profiles" in msg


def test_validate_firewall_profiles_malformed_values():
    """Unrecognized profile tokens fail validation."""
    ok, msg = validate_firewall_profiles("Domain,BogusProfile")
    assert ok is False
    assert "unknown profile values" in msg


def test_validate_firewall_profiles_all_three():
    """Profiles covering Domain, Private, and Public in any order succeed."""
    assert validate_firewall_profiles("Domain,Private,Public")[0] is True
    assert validate_firewall_profiles("Public,Domain,Private")[0] is True
    assert validate_firewall_profiles("Private, Public, Domain")[0] is True


def test_validate_firewall_profiles_any():
    """Profiles specified as 'Any' succeeds."""
    assert validate_firewall_profiles("Any")[0] is True
    assert validate_firewall_profiles("any")[0] is True


def test_verify_firewall_rule_rejects_missing_profiles_field(temp_dir):
    """Persistent rule verification fails if output has no Profiles line."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    output = (
        f"Rule Name: {DEFAULT_RULE_NAME}\n"
        f"Grouping: {RULE_GROUPING}\n"
        f"Description: {RULE_OWNERSHIP_MARKER} Offline privacy boundary\n"
        f"Enabled: Yes\n"
        f"Direction: Out\n"
        f"Action: Block\n"
        f"Program: {dedicated.resolve()}\n"
    )
    with patch("subprocess.run", return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=output)):
        ok, reason = verify_firewall_rule(dedicated)
        assert ok is False
        assert "profile information is missing" in reason


def test_verify_firewall_rule_rejects_empty_profiles_field(temp_dir):
    """Persistent rule verification fails if Profiles field is empty."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    output = (
        f"Rule Name: {DEFAULT_RULE_NAME}\n"
        f"Grouping: {RULE_GROUPING}\n"
        f"Description: {RULE_OWNERSHIP_MARKER} Offline privacy boundary\n"
        f"Profiles: \n"
        f"Enabled: Yes\n"
        f"Direction: Out\n"
        f"Action: Block\n"
        f"Program: {dedicated.resolve()}\n"
    )
    with patch("subprocess.run", return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=output)):
        ok, reason = verify_firewall_rule(dedicated)
        assert ok is False
        assert "profile information is empty" in reason


def test_verify_firewall_rule_rejects_incomplete_profiles(temp_dir):
    """Persistent rule verification fails if Profiles field only covers Public."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    output = (
        f"Rule Name: {DEFAULT_RULE_NAME}\n"
        f"Grouping: {RULE_GROUPING}\n"
        f"Description: {RULE_OWNERSHIP_MARKER} Offline privacy boundary\n"
        f"Profiles: Public\n"
        f"Enabled: Yes\n"
        f"Direction: Out\n"
        f"Action: Block\n"
        f"Program: {dedicated.resolve()}\n"
    )
    with patch("subprocess.run", return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=output)):
        ok, reason = verify_firewall_rule(dedicated)
        assert ok is False
        assert "profiles incomplete" in reason


# =====================================================================
# 4. Effective Windows Firewall Policy (ActiveStore) Tests
# =====================================================================

def _make_powershell_activestore_json(
    profiles_status: list[dict] | None = None,
    rules: list[dict] | None = None,
) -> str:
    """Helper to generate mock PowerShell ActiveStore JSON payload."""
    if profiles_status is None:
        profiles_status = [
            {"Name": "Domain", "Enabled": 1, "AllowLocalFirewallRules": 1},
            {"Name": "Private", "Enabled": 1, "AllowLocalFirewallRules": 1},
            {"Name": "Public", "Enabled": 1, "AllowLocalFirewallRules": 1},
        ]
    return json.dumps({
        "Profiles": profiles_status,
        "Rules": rules or [],
    })


def test_verify_effective_firewall_policy_success(temp_dir):
    """Effective policy verification succeeds when all profiles are enabled and rule is active."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    mock_json = _make_powershell_activestore_json(
        rules=[{
            "Name": STABLE_RULE_ID,
            "DisplayName": DEFAULT_RULE_NAME,
            "Group": RULE_GROUPING,
            "Description": f"{RULE_OWNERSHIP_MARKER} ActiveStore rule",
            "Enabled": True,
            "Direction": "Outbound",
            "Action": "Block",
            "Profiles": "Domain,Private,Public",
            "Program": str(dedicated.resolve()),
        }]
    )

    with patch("subprocess.run", return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=mock_json)):
        ok, reason = verify_effective_firewall_policy(dedicated)
        assert ok is True
        assert "Effective Windows Firewall policy verified in ActiveStore" in reason


def test_verify_effective_firewall_policy_profile_disabled(temp_dir):
    """Fails if any network profile (e.g. Public) is disabled in ActiveStore."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    mock_json = _make_powershell_activestore_json(
        profiles_status=[
            {"Name": "Domain", "Enabled": 1, "AllowLocalFirewallRules": 1},
            {"Name": "Private", "Enabled": 1, "AllowLocalFirewallRules": 1},
            {"Name": "Public", "Enabled": 0, "AllowLocalFirewallRules": 1},
        ],
        rules=[{
            "Name": STABLE_RULE_ID,
            "DisplayName": DEFAULT_RULE_NAME,
            "Group": RULE_GROUPING,
            "Description": RULE_OWNERSHIP_MARKER,
            "Enabled": True,
            "Direction": "Outbound",
            "Action": "Block",
            "Profiles": "Any",
            "Program": str(dedicated.resolve()),
        }]
    )

    with patch("subprocess.run", return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=mock_json)):
        ok, reason = verify_effective_firewall_policy(dedicated)
        assert ok is False
        assert "profile 'Public' is disabled in ActiveStore" in reason


def test_verify_effective_firewall_policy_local_rules_restricted(temp_dir):
    """Fails if a profile restricts local firewall rules (e.g. AllowLocalFirewallRules=0)."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    mock_json = _make_powershell_activestore_json(
        profiles_status=[
            {"Name": "Domain", "Enabled": 1, "AllowLocalFirewallRules": 0},
            {"Name": "Private", "Enabled": 1, "AllowLocalFirewallRules": 1},
            {"Name": "Public", "Enabled": 1, "AllowLocalFirewallRules": 1},
        ],
        rules=[{
            "Name": STABLE_RULE_ID,
            "DisplayName": DEFAULT_RULE_NAME,
            "Group": RULE_GROUPING,
            "Description": RULE_OWNERSHIP_MARKER,
            "Enabled": True,
            "Direction": "Outbound",
            "Action": "Block",
            "Profiles": "Any",
            "Program": str(dedicated.resolve()),
        }]
    )

    with patch("subprocess.run", return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=mock_json)):
        ok, reason = verify_effective_firewall_policy(dedicated)
        assert ok is False
        assert "restricts local firewall rules" in reason


def test_verify_effective_firewall_policy_effective_rule_missing(temp_dir):
    """Fails if no rules exist in ActiveStore policy view."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    mock_json = _make_powershell_activestore_json(rules=[])
    with patch("subprocess.run", return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=mock_json)):
        ok, reason = verify_effective_firewall_policy(dedicated)
        assert ok is False
        assert "does not exist in ActiveStore effective policy" in reason


def test_verify_effective_firewall_policy_effective_rule_disabled(temp_dir):
    """Fails if the effective rule in ActiveStore is disabled."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    mock_json = _make_powershell_activestore_json(
        rules=[{
            "Name": STABLE_RULE_ID,
            "DisplayName": DEFAULT_RULE_NAME,
            "Group": RULE_GROUPING,
            "Description": RULE_OWNERSHIP_MARKER,
            "Enabled": False,
            "Direction": "Outbound",
            "Action": "Block",
            "Profiles": "Any",
            "Program": str(dedicated.resolve()),
        }]
    )

    with patch("subprocess.run", return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=mock_json)):
        ok, reason = verify_effective_firewall_policy(dedicated)
        assert ok is False
        assert "is disabled" in reason


def test_verify_effective_firewall_policy_action_allow(temp_dir):
    """Fails if effective rule action is Allow instead of Block."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    mock_json = _make_powershell_activestore_json(
        rules=[{
            "Name": STABLE_RULE_ID,
            "DisplayName": DEFAULT_RULE_NAME,
            "Group": RULE_GROUPING,
            "Description": RULE_OWNERSHIP_MARKER,
            "Enabled": True,
            "Direction": "Outbound",
            "Action": "Allow",
            "Profiles": "Any",
            "Program": str(dedicated.resolve()),
        }]
    )

    with patch("subprocess.run", return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=mock_json)):
        ok, reason = verify_effective_firewall_policy(dedicated)
        assert ok is False
        assert "action mismatch" in reason


def test_verify_effective_firewall_policy_direction_in(temp_dir):
    """Fails if effective rule direction is Inbound instead of Outbound."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    mock_json = _make_powershell_activestore_json(
        rules=[{
            "Name": STABLE_RULE_ID,
            "DisplayName": DEFAULT_RULE_NAME,
            "Group": RULE_GROUPING,
            "Description": RULE_OWNERSHIP_MARKER,
            "Enabled": True,
            "Direction": "Inbound",
            "Action": "Block",
            "Profiles": "Any",
            "Program": str(dedicated.resolve()),
        }]
    )

    with patch("subprocess.run", return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=mock_json)):
        ok, reason = verify_effective_firewall_policy(dedicated)
        assert ok is False
        assert "direction mismatch" in reason


def test_verify_effective_firewall_policy_executable_mismatch(temp_dir):
    """Fails if effective rule program does not match target executable."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    mock_json = _make_powershell_activestore_json(
        rules=[{
            "Name": STABLE_RULE_ID,
            "DisplayName": DEFAULT_RULE_NAME,
            "Group": RULE_GROUPING,
            "Description": RULE_OWNERSHIP_MARKER,
            "Enabled": True,
            "Direction": "Outbound",
            "Action": "Block",
            "Profiles": "Any",
            "Program": "C:\\other\\app.exe",
        }]
    )

    with patch("subprocess.run", return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=mock_json)):
        ok, reason = verify_effective_firewall_policy(dedicated)
        assert ok is False
        assert "matched Tsukiko ownership and target executable" in reason


def test_verify_effective_firewall_policy_profile_mismatch(temp_dir):
    """Fails if effective rule does not cover all network profiles."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    mock_json = _make_powershell_activestore_json(
        rules=[{
            "Name": STABLE_RULE_ID,
            "DisplayName": DEFAULT_RULE_NAME,
            "Group": RULE_GROUPING,
            "Description": RULE_OWNERSHIP_MARKER,
            "Enabled": True,
            "Direction": "Outbound",
            "Action": "Block",
            "Profiles": "Public",
            "Program": str(dedicated.resolve()),
        }]
    )

    with patch("subprocess.run", return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=mock_json)):
        ok, reason = verify_effective_firewall_policy(dedicated)
        assert ok is False
        assert "Effective rule profile validation failed" in reason


def test_verify_effective_firewall_policy_powershell_unavailable(temp_dir):
    """Fails cleanly if powershell is not installed or found on PATH."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    with patch("shutil.which", return_value=None):
        ok, reason = verify_effective_firewall_policy(dedicated)
        assert ok is False
        assert "not available on PATH" in reason


def test_verify_effective_firewall_policy_powershell_timeout(temp_dir):
    """Fails cleanly if PowerShell inspection command times out."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="powershell", timeout=10)):
        ok, reason = verify_effective_firewall_policy(dedicated)
        assert ok is False
        assert "timed out" in reason


def test_verify_effective_firewall_policy_malformed_json(temp_dir):
    """Fails cleanly if PowerShell returns non-JSON text."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    with patch("subprocess.run", return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout="ERROR: not json")):
        ok, reason = verify_effective_firewall_policy(dedicated)
        assert ok is False
        assert "Malformed PowerShell output" in reason


# =====================================================================
# 5. Precise Rule Ownership & Safe Deletion Tests
# =====================================================================

def test_is_tsukiko_owned_rule_valid():
    """Validates genuine Tsukiko rule matching all identifiers."""
    rule = FirewallRuleInfo(
        name=DEFAULT_RULE_NAME,
        display_name=DEFAULT_RULE_NAME,
        group=RULE_GROUPING,
        description=f"{RULE_OWNERSHIP_MARKER} Offline privacy boundary",
        program="C:\\Tsukiko\\tsukiko.exe",
    )
    ok, msg = is_tsukiko_owned_rule(rule, expected_exe="C:\\Tsukiko\\tsukiko.exe")
    assert ok is True
    assert "ownership verified" in msg


def test_is_tsukiko_owned_rule_rejects_foreign_name():
    """Rule with foreign name is rejected."""
    rule = FirewallRuleInfo(
        name="Foreign App",
        display_name="Foreign App",
        group=RULE_GROUPING,
        description=RULE_OWNERSHIP_MARKER,
    )
    ok, msg = is_tsukiko_owned_rule(rule)
    assert ok is False
    assert "does not match Tsukiko rule identity" in msg


def test_is_tsukiko_owned_rule_rejects_foreign_group():
    """Rule with incorrect grouping is rejected."""
    rule = FirewallRuleInfo(
        name=DEFAULT_RULE_NAME,
        display_name=DEFAULT_RULE_NAME,
        group="Other Group",
        description=RULE_OWNERSHIP_MARKER,
    )
    ok, msg = is_tsukiko_owned_rule(rule)
    assert ok is False
    assert "grouping mismatch" in msg


def test_is_tsukiko_owned_rule_rejects_missing_marker():
    """Rule lacking ownership marker in description is rejected."""
    rule = FirewallRuleInfo(
        name=DEFAULT_RULE_NAME,
        display_name=DEFAULT_RULE_NAME,
        group=RULE_GROUPING,
        description="Regular rule without marker",
    )
    ok, msg = is_tsukiko_owned_rule(rule)
    assert ok is False
    assert "lacks required Tsukiko ownership marker" in msg


def test_remove_firewall_rule_exact_owned_rule():
    """Successfully deletes rule when exactly one Tsukiko-owned rule matches."""
    owned_output = (
        f"Rule Name:                            {DEFAULT_RULE_NAME}\n"
        f"Grouping:                             {RULE_GROUPING}\n"
        f"Description:                          {RULE_OWNERSHIP_MARKER} Boundary\n"
    )
    mock_chk = subprocess.CompletedProcess(args=["netsh"], returncode=0, stdout=owned_output)
    mock_del = subprocess.CompletedProcess(args=["netsh"], returncode=0, stdout="Deleted 1 rule(s).")

    with patch("app.core.privacy.windows_firewall.is_admin", return_value=True), \
         patch("subprocess.run", side_effect=[mock_chk, mock_del]):
        ok, reason = remove_firewall_rule(DEFAULT_RULE_NAME, user_authorized=True)
        assert ok is True
        assert "removed" in reason


def test_remove_firewall_rule_rejects_foreign_rule_same_display_name():
    """Refuses deletion if rule has matching display name but foreign grouping and description."""
    foreign_output = (
        f"Rule Name:                            {DEFAULT_RULE_NAME}\n"
        f"Grouping:                             Unrelated Group\n"
        f"Description:                          Custom firewall rule\n"
    )
    mock_chk = subprocess.CompletedProcess(args=["netsh"], returncode=0, stdout=foreign_output)

    with patch("app.core.privacy.windows_firewall.is_admin", return_value=True), \
         patch("subprocess.run", return_value=mock_chk):
        ok, reason = remove_firewall_rule(DEFAULT_RULE_NAME, user_authorized=True)
        assert ok is False
        assert "Foreign rules will not be deleted" in reason


def test_remove_firewall_rule_rejects_tsukiko_prefix_foreign_rule():
    """Refuses deletion of rule named 'Tsukiko Impostor' that is not owned."""
    impostor_output = (
        "Rule Name:                            Tsukiko Impostor\n"
        "Grouping:                             ThirdParty\n"
        "Description:                          Impostor rule\n"
    )
    mock_chk = subprocess.CompletedProcess(args=["netsh"], returncode=0, stdout=impostor_output)

    with patch("app.core.privacy.windows_firewall.is_admin", return_value=True), \
         patch("subprocess.run", return_value=mock_chk):
        ok, reason = remove_firewall_rule("Tsukiko Impostor", user_authorized=True)
        assert ok is False
        assert "Foreign rules will not be deleted" in reason


def test_remove_firewall_rule_rejects_ambiguous_identity():
    """Refuses deletion if multiple rules claim Tsukiko ownership, requiring operator intervention."""
    ambiguous_output = (
        f"Rule Name:                            {DEFAULT_RULE_NAME}\n"
        f"Grouping:                             {RULE_GROUPING}\n"
        f"Description:                          {RULE_OWNERSHIP_MARKER} Rule 1\n"
        f"\n"
        f"Rule Name:                            {DEFAULT_RULE_NAME}\n"
        f"Grouping:                             {RULE_GROUPING}\n"
        f"Description:                          {RULE_OWNERSHIP_MARKER} Rule 2\n"
    )
    mock_chk = subprocess.CompletedProcess(args=["netsh"], returncode=0, stdout=ambiguous_output)

    with patch("app.core.privacy.windows_firewall.is_admin", return_value=True), \
         patch("subprocess.run", return_value=mock_chk):
        ok, reason = remove_firewall_rule(DEFAULT_RULE_NAME, user_authorized=True)
        assert ok is False
        assert "Ambiguous rule identity" in reason


def test_remove_firewall_rule_multiple_rules_one_owned():
    """If netsh returns 2 rules with same name but only 1 is Tsukiko-owned, delete the owned one."""
    mixed_output = (
        f"Rule Name:                            {DEFAULT_RULE_NAME}\n"
        f"Grouping:                             Foreign\n"
        f"Description:                          Not ours\n"
        f"\n"
        f"Rule Name:                            {DEFAULT_RULE_NAME}\n"
        f"Grouping:                             {RULE_GROUPING}\n"
        f"Description:                          {RULE_OWNERSHIP_MARKER} Real one\n"
    )
    mock_chk = subprocess.CompletedProcess(args=["netsh"], returncode=0, stdout=mixed_output)
    mock_del = subprocess.CompletedProcess(args=["netsh"], returncode=0, stdout="Deleted 1 rule(s).")

    with patch("app.core.privacy.windows_firewall.is_admin", return_value=True), \
         patch("subprocess.run", side_effect=[mock_chk, mock_del]):
        ok, reason = remove_firewall_rule(DEFAULT_RULE_NAME, user_authorized=True)
        assert ok is True
        assert "removed" in reason


def test_remove_firewall_rule_unauthorized():
    """Removal without explicit user authorization is rejected."""
    ok, reason = remove_firewall_rule(DEFAULT_RULE_NAME, user_authorized=False)
    assert ok is False
    assert "authorization is required" in reason


def test_remove_firewall_rule_not_admin():
    """Removal when process is not elevated is rejected."""
    with patch("app.core.privacy.windows_firewall.is_admin", return_value=False):
        ok, reason = remove_firewall_rule(DEFAULT_RULE_NAME, user_authorized=True)
        assert ok is False
        assert "elevation required" in reason


def test_create_firewall_rule_refuses_when_foreign_conflicting_rule_exists(temp_dir):
    """Creation refuses if a non-Tsukiko rule already occupies the rule name."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    foreign_existing = (
        f"Rule Name:                            {DEFAULT_RULE_NAME}\n"
        f"Grouping:                             ForeignGroup\n"
        f"Description:                          Someone else's rule\n"
    )
    mock_chk = subprocess.CompletedProcess(args=["netsh"], returncode=0, stdout=foreign_existing)

    with patch("app.core.privacy.windows_firewall.is_admin", return_value=True), \
         patch("subprocess.run", return_value=mock_chk):
        ok, reason = create_firewall_rule(dedicated, user_authorized=True)
        assert ok is False
        assert "does not belong to Tsukiko" in reason or "foreign rule" in reason


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


# =====================================================================
# 6. Persistent Rule Verification Tests
# =====================================================================

def test_verify_firewall_rule_matches_all_properties(temp_dir):
    """Rule verification passes when direction=out, action=block, enabled=yes, program matches, and ownership verified."""
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
        f"Description: {RULE_OWNERSHIP_MARKER} Boundary\n"
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


# =====================================================================
# 7. Command Generation Tests
# =====================================================================

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


# =====================================================================
# 8. 4-State Security Status Tests
# =====================================================================

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
    """Dedicated binary with rule present but effective ActiveStore policy unverified reports os_policy_unverified."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    mismatched_output = (
        f"Rule Name: {DEFAULT_RULE_NAME}\n"
        f"Grouping: {RULE_GROUPING}\n"
        f"Description: {RULE_OWNERSHIP_MARKER} Test\n"
        f"Profiles: Domain,Private,Public\n"
        f"Enabled: Yes\nDirection: Out\nAction: Block\nProgram: {dedicated.resolve()}\n"
    )
    # verify_effective_firewall_policy fails (returns False), but verify_firewall_rule or candidates succeed
    with patch("app.core.privacy.windows_firewall.verify_effective_firewall_policy", return_value=(False, "ActiveStore query failed")), \
         patch("subprocess.run", return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=mismatched_output)):
        status = get_security_status(dedicated)
        assert status.status == "os_policy_unverified"
        assert status.is_dedicated_binary is True
        assert status.rule_exists is True
        assert "ActiveStore query failed" in status.details or "could not establish" in status.details


def test_security_status_os_policy_active(temp_dir):
    """Dedicated binary with active rule confirmed in ActiveStore reports os_policy_active."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    with patch("app.core.privacy.windows_firewall.verify_effective_firewall_policy", return_value=(True, "Effective policy confirmed")):
        status = get_security_status(dedicated)
        assert status.status == "os_policy_active"
        assert status.is_dedicated_binary is True
        assert status.rule_exists is True
        assert status.defense_level == "os_kernel_firewall_and_socket_interception"


def test_security_status_on_non_windows(temp_dir):
    """On non-Windows platforms, get_security_status returns in_process_only with explanatory details."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    with patch("platform.system", return_value="Linux"):
        status = get_security_status(dedicated)
        assert status.status == "in_process_only"
        assert "only supported on Windows" in status.details
