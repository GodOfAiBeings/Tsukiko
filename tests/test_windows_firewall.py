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
    FirewallQueryResult,
    FirewallRuleInfo,
    SecurityStatus,
    create_firewall_rule,
    generate_firewall_rule_command,
    generate_powershell_firewall_rule_command,
    generate_powershell_remove_rule_command,
    generate_remove_rule_command,
    get_security_status,
    is_safe_target_executable,
    is_tsukiko_owned_rule,
    parse_netsh_rule_blocks,
    parse_powershell_rules_json,
    query_matching_firewall_rules,
    remove_firewall_rule,
    validate_firewall_filters,
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
    success: bool = True,
    inspection_complete: bool = True,
    error: str | None = None,
    raw_rules: bool = False,
) -> str:
    """Helper to generate mock PowerShell ActiveStore JSON payload with response envelope."""
    if profiles_status is None:
        profiles_status = [
            {"Name": "Domain", "Enabled": 1, "AllowLocalFirewallRules": 1},
            {"Name": "Private", "Enabled": 1, "AllowLocalFirewallRules": 1},
            {"Name": "Public", "Enabled": 1, "AllowLocalFirewallRules": 1},
        ]
    full_rules = []
    if rules:
        for r in rules:
            if raw_rules:
                full_rules.append(r)
            else:
                base = {
                    "Name": STABLE_RULE_ID,
                    "DisplayName": DEFAULT_RULE_NAME,
                    "Group": RULE_GROUPING,
                    "Description": DEFAULT_DESCRIPTION,
                    "Enabled": True,
                    "Direction": "Outbound",
                    "Action": "Block",
                    "Profiles": "Domain,Private,Public",
                    "Program": "C:\\Tsukiko\\tsukiko.exe",
                    "LocalAddress": "Any",
                    "RemoteAddress": "Any",
                    "Protocol": "Any",
                    "LocalPort": "Any",
                    "RemotePort": "Any",
                    "Service": "Any",
                    "InterfaceAlias": "Any",
                    "InterfaceType": "Any",
                    "Authentication": "NotRequired",
                    "Encryption": "NotRequired",
                    "OverrideBlockRules": False,
                    "LocalUser": "Any",
                    "RemoteUser": "Any",
                    "RemoteMachine": "Any",
                }
                merged = dict(base)
                merged.update(r)
                full_rules.append(merged)
    return json.dumps({
        "Success": success,
        "InspectionComplete": inspection_complete,
        "Profiles": profiles_status,
        "Rules": full_rules,
        "Error": error,
    })


def _make_powershell_query_json(
    rules: list[dict] | None = None,
    success: bool = True,
    inspection_complete: bool = True,
    error: str | None = None,
    raw_rules: bool = False,
) -> str:
    """Helper to generate mock PowerShell query JSON payload with response envelope."""
    full_rules = []
    if rules:
        for r in rules:
            if raw_rules:
                full_rules.append(r)
            else:
                base = {
                    "Name": STABLE_RULE_ID,
                    "DisplayName": DEFAULT_RULE_NAME,
                    "Group": RULE_GROUPING,
                    "Description": DEFAULT_DESCRIPTION,
                    "Enabled": True,
                    "Direction": "Outbound",
                    "Action": "Block",
                    "Profiles": "Domain,Private,Public",
                    "Program": "C:\\Tsukiko\\tsukiko.exe",
                    "LocalAddress": "Any",
                    "RemoteAddress": "Any",
                    "Protocol": "Any",
                    "LocalPort": "Any",
                    "RemotePort": "Any",
                    "Service": "Any",
                    "InterfaceAlias": "Any",
                    "InterfaceType": "Any",
                    "Authentication": "NotRequired",
                    "Encryption": "NotRequired",
                    "OverrideBlockRules": False,
                    "LocalUser": "Any",
                    "RemoteUser": "Any",
                    "RemoteMachine": "Any",
                }
                merged = dict(base)
                merged.update(r)
                full_rules.append(merged)
    return json.dumps({
        "Success": success,
        "InspectionComplete": inspection_complete,
        "Rules": full_rules,
        "Error": error,
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
    """Successfully deletes rule when exactly one Tsukiko-owned rule matches stable internal identifier."""
    owned_rule_json = _make_powershell_query_json(rules=[{
        "Name": STABLE_RULE_ID,
        "DisplayName": DEFAULT_RULE_NAME,
        "Group": RULE_GROUPING,
        "Description": f"{RULE_OWNERSHIP_MARKER} Boundary",
        "Enabled": True,
        "Direction": "Outbound",
        "Action": "Block",
        "Profiles": "Any",
    }])
    mock_chk = subprocess.CompletedProcess(args=["powershell"], returncode=0, stdout=owned_rule_json)
    mock_del = subprocess.CompletedProcess(args=["powershell"], returncode=0, stdout="")
    mock_post_chk = subprocess.CompletedProcess(args=["powershell"], returncode=0, stdout=_make_powershell_query_json(rules=[]))

    with patch("app.core.privacy.windows_firewall.is_admin", return_value=True), \
         patch("subprocess.run", side_effect=[mock_chk, mock_del, mock_post_chk]):
        ok, reason = remove_firewall_rule(DEFAULT_RULE_NAME, user_authorized=True)
        assert ok is True
        assert "removed" in reason


def test_remove_firewall_rule_refuses_legacy_rule_without_stable_id():
    """Refuses automatic deletion if rule lacks the verified stable internal identifier."""
    legacy_rule_json = _make_powershell_query_json(rules=[{
        "Name": DEFAULT_RULE_NAME,  # Legacy rule created where Name == DisplayName
        "DisplayName": DEFAULT_RULE_NAME,
        "Group": RULE_GROUPING,
        "Description": f"{RULE_OWNERSHIP_MARKER} Boundary",
        "Enabled": True,
        "Direction": "Outbound",
        "Action": "Block",
        "Profiles": "Any",
    }])
    mock_chk = subprocess.CompletedProcess(args=["powershell"], returncode=0, stdout=legacy_rule_json)

    with patch("app.core.privacy.windows_firewall.is_admin", return_value=True), \
         patch("subprocess.run", return_value=mock_chk):
        ok, reason = remove_firewall_rule(DEFAULT_RULE_NAME, user_authorized=True)
        assert ok is False
        assert "legacy rule without verified stable internal identifier" in reason


def test_remove_firewall_rule_fails_if_rule_persists_after_deletion():
    """Fails if post-deletion verification re-query indicates rule was not actually removed."""
    owned_rule_json = _make_powershell_query_json(rules=[{
        "Name": STABLE_RULE_ID,
        "DisplayName": DEFAULT_RULE_NAME,
        "Group": RULE_GROUPING,
        "Description": f"{RULE_OWNERSHIP_MARKER} Boundary",
        "Enabled": True,
    }])
    mock_chk = subprocess.CompletedProcess(args=["powershell"], returncode=0, stdout=owned_rule_json)
    mock_del = subprocess.CompletedProcess(args=["powershell"], returncode=0, stdout="")
    mock_post_chk = subprocess.CompletedProcess(args=["powershell"], returncode=0, stdout=owned_rule_json)

    with patch("app.core.privacy.windows_firewall.is_admin", return_value=True), \
         patch("subprocess.run", side_effect=[mock_chk, mock_del, mock_post_chk]):
        ok, reason = remove_firewall_rule(DEFAULT_RULE_NAME, user_authorized=True)
        assert ok is False
        assert "still exists" in reason


def test_remove_firewall_rule_refuses_on_query_failure():
    """Refuses deletion if inspection query fails (non-zero returncode)."""
    mock_fail = subprocess.CompletedProcess(args=["powershell"], returncode=1, stdout="", stderr="Access Denied")

    with patch("app.core.privacy.windows_firewall.is_admin", return_value=True), \
         patch("subprocess.run", return_value=mock_fail):
        ok, reason = remove_firewall_rule(DEFAULT_RULE_NAME, user_authorized=True)
        assert ok is False
        assert "inspection failure" in reason


def test_remove_firewall_rule_rejects_foreign_rule_same_display_name():
    """Refuses deletion if rule has matching display name but foreign grouping and description."""
    foreign_output = _make_powershell_query_json(rules=[{
        "Name": "Foreign_Rule_ID",
        "DisplayName": DEFAULT_RULE_NAME,
        "Group": "Unrelated Group",
        "Description": "Custom firewall rule",
    }], raw_rules=True)
    mock_chk = subprocess.CompletedProcess(args=["powershell"], returncode=0, stdout=foreign_output)

    with patch("app.core.privacy.windows_firewall.is_admin", return_value=True), \
         patch("subprocess.run", return_value=mock_chk):
        ok, reason = remove_firewall_rule(DEFAULT_RULE_NAME, user_authorized=True)
        assert ok is False
        assert "Foreign rules will not be deleted" in reason


def test_remove_firewall_rule_rejects_tsukiko_prefix_foreign_rule():
    """Refuses deletion of rule named 'Tsukiko Impostor' that is not owned."""
    impostor_output = _make_powershell_query_json(rules=[{
        "Name": "Tsukiko_Impostor",
        "DisplayName": "Tsukiko Impostor",
        "Group": "ThirdParty",
        "Description": "Impostor rule",
    }], raw_rules=True)
    mock_chk = subprocess.CompletedProcess(args=["powershell"], returncode=0, stdout=impostor_output)

    with patch("app.core.privacy.windows_firewall.is_admin", return_value=True), \
         patch("subprocess.run", return_value=mock_chk):
        ok, reason = remove_firewall_rule("Tsukiko Impostor", user_authorized=True)
        assert ok is False
        assert "Foreign rules will not be deleted" in reason


def test_remove_firewall_rule_rejects_ambiguous_identity():
    """Refuses deletion if multiple rules claim Tsukiko stable identity, requiring operator intervention."""
    ambiguous_output = _make_powershell_query_json(rules=[
        {
            "Name": STABLE_RULE_ID,
            "DisplayName": DEFAULT_RULE_NAME,
            "Group": RULE_GROUPING,
            "Description": f"{RULE_OWNERSHIP_MARKER} Rule 1",
            "Enabled": True,
        },
        {
            "Name": STABLE_RULE_ID,
            "DisplayName": DEFAULT_RULE_NAME,
            "Group": RULE_GROUPING,
            "Description": f"{RULE_OWNERSHIP_MARKER} Rule 2",
            "Enabled": True,
        },
    ])
    mock_chk = subprocess.CompletedProcess(args=["powershell"], returncode=0, stdout=ambiguous_output)

    with patch("app.core.privacy.windows_firewall.is_admin", return_value=True), \
         patch("subprocess.run", return_value=mock_chk):
        ok, reason = remove_firewall_rule(DEFAULT_RULE_NAME, user_authorized=True)
        assert ok is False
        assert "Ambiguous rule identity" in reason


def test_remove_firewall_rule_multiple_rules_one_owned():
    """If store returns 2 rules but only 1 is Tsukiko-owned with STABLE_RULE_ID, delete the owned one."""
    mixed_output = _make_powershell_query_json(rules=[
        {
            "Name": "Foreign_Rule",
            "DisplayName": DEFAULT_RULE_NAME,
            "Group": "Foreign",
            "Description": "Not ours",
            "Enabled": True,
        },
        {
            "Name": STABLE_RULE_ID,
            "DisplayName": DEFAULT_RULE_NAME,
            "Group": RULE_GROUPING,
            "Description": f"{RULE_OWNERSHIP_MARKER} Real one",
            "Enabled": True,
        },
    ], raw_rules=True)
    mock_chk = subprocess.CompletedProcess(args=["powershell"], returncode=0, stdout=mixed_output)
    mock_del = subprocess.CompletedProcess(args=["powershell"], returncode=0, stdout="")
    mock_post_chk = subprocess.CompletedProcess(args=["powershell"], returncode=0, stdout=_make_powershell_query_json(rules=[]))

    with patch("app.core.privacy.windows_firewall.is_admin", return_value=True), \
         patch("subprocess.run", side_effect=[mock_chk, mock_del, mock_post_chk]):
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


def test_create_firewall_rule_powershell_success(temp_dir):
    """Creates rule via PowerShell New-NetFirewallRule, assigns stable internal ID, and verifies."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    created_rule_json = _make_powershell_query_json(rules=[{
        "Name": STABLE_RULE_ID,
        "DisplayName": DEFAULT_RULE_NAME,
        "Group": RULE_GROUPING,
        "Description": DEFAULT_DESCRIPTION,
        "Enabled": True,
        "Direction": "Outbound",
        "Action": "Block",
        "Profiles": "Any",
        "Program": str(dedicated.resolve()),
        "LocalAddress": "Any",
        "RemoteAddress": "Any",
        "Protocol": "Any",
        "LocalPort": "Any",
        "RemotePort": "Any",
        "Service": "Any",
        "InterfaceAlias": "Any",
        "InterfaceType": "Any",
        "Authentication": "NotRequired",
        "Encryption": "NotRequired",
        "OverrideBlockRules": False,
        "LocalUser": "Any",
        "RemoteUser": "Any",
        "RemoteMachine": "Any",
    }])

    # 1. Pre-creation check (envelope with Rules=[] -> confirmed absence)
    mock_pre_chk = subprocess.CompletedProcess(args=["powershell"], returncode=0, stdout=_make_powershell_query_json(rules=[]))
    # 2. Creation command
    mock_create = subprocess.CompletedProcess(args=["powershell"], returncode=0, stdout="")
    # 3. Post-creation check (returns created rule)
    mock_post_chk = subprocess.CompletedProcess(args=["powershell"], returncode=0, stdout=created_rule_json)

    with patch("app.core.privacy.windows_firewall.is_admin", return_value=True), \
         patch("subprocess.run", side_effect=[mock_pre_chk, mock_create, mock_post_chk]):
        ok, reason = create_firewall_rule(dedicated, user_authorized=True)
        assert ok is True
        assert "created and verified" in reason


def test_create_firewall_rule_refuses_when_foreign_conflicting_rule_exists(temp_dir):
    """Creation refuses if a non-Tsukiko rule already occupies the rule name."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    foreign_existing = _make_powershell_query_json(rules=[{
        "Name": STABLE_RULE_ID,
        "DisplayName": DEFAULT_RULE_NAME,
        "Group": "ForeignGroup",
        "Description": "Someone else's rule",
    }], raw_rules=True)
    mock_chk = subprocess.CompletedProcess(args=["powershell"], returncode=0, stdout=foreign_existing)

    with patch("app.core.privacy.windows_firewall.is_admin", return_value=True), \
         patch("subprocess.run", return_value=mock_chk):
        ok, reason = create_firewall_rule(dedicated, user_authorized=True)
        assert ok is False
        assert "does not belong to Tsukiko" in reason or "conflicting foreign rule" in reason


def test_create_firewall_rule_refuses_on_query_failure(temp_dir):
    """Refuses creation if pre-creation inspection query fails."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    mock_fail = subprocess.CompletedProcess(args=["powershell"], returncode=1, stdout="", stderr="WMI query error")

    with patch("app.core.privacy.windows_firewall.is_admin", return_value=True), \
         patch("subprocess.run", return_value=mock_fail):
        ok, reason = create_firewall_rule(dedicated, user_authorized=True)
        assert ok is False
        assert "inspection failure" in reason


def test_create_firewall_rule_idempotent_when_already_exists(temp_dir):
    """When a matching verified rule already exists, returns success idempotently."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    existing_rule_json = _make_powershell_query_json(rules=[{
        "Name": STABLE_RULE_ID,
        "DisplayName": DEFAULT_RULE_NAME,
        "Group": RULE_GROUPING,
        "Description": DEFAULT_DESCRIPTION,
        "Enabled": True,
        "Direction": "Outbound",
        "Action": "Block",
        "Profiles": "Any",
        "Program": str(dedicated.resolve()),
        "LocalAddress": "Any",
        "RemoteAddress": "Any",
        "Protocol": "Any",
        "LocalPort": "Any",
        "RemotePort": "Any",
        "Service": "Any",
        "InterfaceAlias": "Any",
        "InterfaceType": "Any",
        "Authentication": "NotRequired",
        "Encryption": "NotRequired",
        "OverrideBlockRules": False,
        "LocalUser": "Any",
        "RemoteUser": "Any",
        "RemoteMachine": "Any",
    }])

    mock_pre_chk = subprocess.CompletedProcess(args=["powershell"], returncode=0, stdout=existing_rule_json)

    with patch("app.core.privacy.windows_firewall.is_admin", return_value=True), \
         patch("subprocess.run", return_value=mock_pre_chk):
        ok, reason = create_firewall_rule(dedicated, user_authorized=True)
        assert ok is True
        assert "already exists and is fully verified" in reason


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


# =====================================================================
# 9. All 7 Filter Categories Verification Tests
# =====================================================================

def test_validate_firewall_filters_rejects_empty_and_wildcard_program(temp_dir):
    """Reject empty, None, wildcard, or 'Any' program filters."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    rule = FirewallRuleInfo(program="")
    ok, msg = validate_firewall_filters(rule, dedicated)
    assert ok is False
    assert "Application filter is empty or wildcard" in msg

    rule_wildcard = FirewallRuleInfo(program="*")
    ok, msg = validate_firewall_filters(rule_wildcard, dedicated)
    assert ok is False
    assert "Application filter is empty or wildcard" in msg

    rule_any = FirewallRuleInfo(program="Any")
    ok, msg = validate_firewall_filters(rule_any, dedicated)
    assert ok is False
    assert "Application filter is empty or wildcard" in msg


def test_validate_firewall_filters_rejects_restricted_addresses(temp_dir):
    """Reject restrictive LocalAddress or RemoteAddress (must be Any)."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    # Local address restricted
    r1 = FirewallRuleInfo.create_unrestricted(program=str(dedicated), local_address="192.168.1.100")
    ok, msg = validate_firewall_filters(r1, dedicated)
    assert ok is False
    assert "Local address filter is restricted" in msg

    # Remote address restricted
    r2 = FirewallRuleInfo.create_unrestricted(program=str(dedicated), remote_address="8.8.8.8")
    ok, msg = validate_firewall_filters(r2, dedicated)
    assert ok is False
    assert "Remote address filter is restricted" in msg


def test_validate_firewall_filters_rejects_restricted_ports_and_protocols(temp_dir):
    """Reject restrictive Protocol, LocalPort, or RemotePort (must be Any)."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    # Protocol restricted to TCP
    r1 = FirewallRuleInfo.create_unrestricted(program=str(dedicated), protocol="TCP")
    ok, msg = validate_firewall_filters(r1, dedicated)
    assert ok is False
    assert "Protocol filter is restricted" in msg

    # LocalPort restricted
    r2 = FirewallRuleInfo.create_unrestricted(program=str(dedicated), local_port="8080")
    ok, msg = validate_firewall_filters(r2, dedicated)
    assert ok is False
    assert "Local port filter is restricted" in msg

    # RemotePort restricted
    r3 = FirewallRuleInfo.create_unrestricted(program=str(dedicated), remote_port="443")
    ok, msg = validate_firewall_filters(r3, dedicated)
    assert ok is False
    assert "Remote port filter is restricted" in msg


def test_validate_firewall_filters_rejects_restricted_services_and_interfaces(temp_dir):
    """Reject restrictive Service, InterfaceAlias, or InterfaceType."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    # Service restricted
    r1 = FirewallRuleInfo.create_unrestricted(program=str(dedicated), service="Spooler")
    ok, msg = validate_firewall_filters(r1, dedicated)
    assert ok is False
    assert "Service filter is restricted" in msg

    # Interface alias restricted
    r2 = FirewallRuleInfo.create_unrestricted(program=str(dedicated), interface_alias="Ethernet 1")
    ok, msg = validate_firewall_filters(r2, dedicated)
    assert ok is False
    assert "Interface filter is restricted" in msg

    # Interface type restricted
    r3 = FirewallRuleInfo.create_unrestricted(program=str(dedicated), interface_type="Wireless")
    ok, msg = validate_firewall_filters(r3, dedicated)
    assert ok is False
    assert "Interface type filter is restricted" in msg


def test_validate_firewall_filters_rejects_security_constraints(temp_dir):
    """Reject IPsec authentication, encryption, or user/machine security constraints."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    # Authentication required
    r1 = FirewallRuleInfo.create_unrestricted(program=str(dedicated), authentication="Required")
    ok, msg = validate_firewall_filters(r1, dedicated)
    assert ok is False
    assert "Security filter requires authentication" in msg

    # Encryption required
    r2 = FirewallRuleInfo.create_unrestricted(program=str(dedicated), encryption="Required")
    ok, msg = validate_firewall_filters(r2, dedicated)
    assert ok is False
    assert "Security filter requires encryption" in msg

    # LocalUser restricted
    r3 = FirewallRuleInfo.create_unrestricted(program=str(dedicated), local_user="Alice")
    ok, msg = validate_firewall_filters(r3, dedicated)
    assert ok is False
    assert "Security filter restricts local users" in msg

    # RemoteUser restricted
    r4 = FirewallRuleInfo.create_unrestricted(program=str(dedicated), remote_user="Bob")
    ok, msg = validate_firewall_filters(r4, dedicated)
    assert ok is False
    assert "Security filter restricts remote users" in msg

    # RemoteMachine restricted
    r5 = FirewallRuleInfo.create_unrestricted(program=str(dedicated), remote_machine="Server01")
    ok, msg = validate_firewall_filters(r5, dedicated)
    assert ok is False
    assert "Security filter restricts remote machines" in msg

    # OverrideBlockRules enabled
    r6 = FirewallRuleInfo.create_unrestricted(program=str(dedicated), override_block_rules=True)
    ok, msg = validate_firewall_filters(r6, dedicated)
    assert ok is False
    assert "OverrideBlockRules enabled" in msg


def test_verify_effective_firewall_policy_rejects_restrictive_filter(temp_dir):
    """Effective ActiveStore policy fails if any of the 7 filter categories is restricted."""
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
            "Profiles": "Domain,Private,Public",
            "Program": str(dedicated.resolve()),
            "RemoteAddress": "192.168.1.1",  # RESTRICTIVE!
        }]
    )

    with patch("subprocess.run", return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=mock_json)):
        ok, reason = verify_effective_firewall_policy(dedicated)
        assert ok is False
        assert "Effective rule filter validation failed" in reason
        assert "Remote address filter is restricted" in reason


# =====================================================================
# 10. FirewallQueryResult Inspection Failure vs Absence Tests
# =====================================================================

def test_query_matching_firewall_rules_confirmed_absence():
    """Successful envelope with empty Rules array indicates confirmed absence."""
    envelope = _make_powershell_query_json(rules=[])
    mock_proc = subprocess.CompletedProcess(args=["powershell"], returncode=0, stdout=envelope)
    with patch("subprocess.run", return_value=mock_proc):
        res = query_matching_firewall_rules(DEFAULT_RULE_NAME)
        assert isinstance(res, FirewallQueryResult)
        assert res.success is True
        assert res.inspection_complete is True
        assert res.rules == []
        assert res.error is None


def test_query_matching_firewall_rules_empty_stdout_fails_closed():
    """Empty standard output is rejected as missing response envelope; NEVER mistaken for confirmed absence."""
    mock_empty = subprocess.CompletedProcess(args=["powershell"], returncode=0, stdout="")
    with patch("subprocess.run", return_value=mock_empty):
        res = query_matching_firewall_rules(DEFAULT_RULE_NAME)
        assert res.success is False
        assert res.inspection_complete is False
        assert res.rules == []
        assert "missing response envelope" in res.error


def test_query_matching_firewall_rules_confirmed_presence():
    """Valid envelope with rules from PowerShell indicates confirmed presence."""
    envelope = _make_powershell_query_json(rules=[{
        "Name": STABLE_RULE_ID,
        "DisplayName": DEFAULT_RULE_NAME,
        "Group": RULE_GROUPING,
        "Description": DEFAULT_DESCRIPTION,
    }])
    mock_proc = subprocess.CompletedProcess(args=["powershell"], returncode=0, stdout=envelope)
    with patch("subprocess.run", return_value=mock_proc):
        res = query_matching_firewall_rules(DEFAULT_RULE_NAME)
        assert res.success is True
        assert res.inspection_complete is True
        assert len(res.rules) == 1
        assert res.rules[0].name == STABLE_RULE_ID


def test_query_matching_firewall_rules_missing_envelope_fails_closed():
    """Output without response envelope (raw list) fails closed."""
    raw_list_json = json.dumps([{
        "Name": STABLE_RULE_ID,
        "DisplayName": DEFAULT_RULE_NAME,
    }])
    mock_proc = subprocess.CompletedProcess(args=["powershell"], returncode=0, stdout=raw_list_json)
    with patch("subprocess.run", return_value=mock_proc):
        res = query_matching_firewall_rules(DEFAULT_RULE_NAME)
        assert res.success is False
        assert res.inspection_complete is False
        assert "missing" in res.error


def test_query_matching_firewall_rules_incomplete_envelope_fails_closed():
    """Incomplete envelope missing required fields fails closed."""
    bad_env = json.dumps({"Rules": []})  # missing Success and InspectionComplete
    mock_proc = subprocess.CompletedProcess(args=["powershell"], returncode=0, stdout=bad_env)
    with patch("subprocess.run", return_value=mock_proc):
        res = query_matching_firewall_rules(DEFAULT_RULE_NAME)
        assert res.success is False
        assert res.inspection_complete is False
        assert "Incomplete PowerShell response envelope" in res.error


def test_query_matching_firewall_rules_envelope_failure_fails_closed():
    """Envelope explicitly reporting failure fails closed."""
    fail_env = json.dumps({
        "Success": False,
        "InspectionComplete": False,
        "Rules": [],
        "Error": "NetSecurity CIM provider crashed",
    })
    mock_proc = subprocess.CompletedProcess(args=["powershell"], returncode=0, stdout=fail_env)
    with patch("subprocess.run", return_value=mock_proc):
        res = query_matching_firewall_rules(DEFAULT_RULE_NAME)
        assert res.success is False
        assert res.inspection_complete is False
        assert "NetSecurity CIM provider crashed" in res.error


def test_query_matching_firewall_rules_inspection_failure_error_code():
    """Non-zero exit code from PowerShell indicates inspection failure."""
    mock_fail = subprocess.CompletedProcess(args=["powershell"], returncode=1, stdout="", stderr="Access is denied.")
    with patch("subprocess.run", return_value=mock_fail):
        res = query_matching_firewall_rules(DEFAULT_RULE_NAME)
        assert res.success is False
        assert res.inspection_complete is False
        assert res.rules == []
        assert "Access is denied" in res.error


def test_query_matching_firewall_rules_inspection_failure_timeout():
    """Timeout from PowerShell indicates inspection failure."""
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="powershell", timeout=10)):
        res = query_matching_firewall_rules(DEFAULT_RULE_NAME)
        assert res.success is False
        assert res.inspection_complete is False
        assert "timed out" in res.error


def test_query_matching_firewall_rules_inspection_failure_malformed_json():
    """Malformed non-JSON output from PowerShell indicates inspection failure."""
    mock_bad = subprocess.CompletedProcess(args=["powershell"], returncode=0, stdout="FATAL: syntax error")
    with patch("subprocess.run", return_value=mock_bad):
        res = query_matching_firewall_rules(DEFAULT_RULE_NAME)
        assert res.success is False
        assert res.inspection_complete is False
        assert "Malformed PowerShell JSON output" in res.error


def test_security_status_reports_unverified_on_inspection_failure(temp_dir):
    """When query inspection fails, get_security_status reports os_policy_unverified, NEVER os_policy_not_configured."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    mock_fail_result = FirewallQueryResult(
        success=False,
        inspection_complete=False,
        rules=[],
        error="WMI access failed",
    )

    with patch("app.core.privacy.windows_firewall.verify_effective_firewall_policy", return_value=(False, "ActiveStore query failed")), \
         patch("app.core.privacy.windows_firewall.query_matching_firewall_rules", return_value=mock_fail_result):
        status = get_security_status(dedicated)
        assert status.status == "os_policy_unverified"
        assert "inspection failed" in status.details
        assert status.rule_exists is False


# =====================================================================
# 11. PowerShell Command Generation Tests
# =====================================================================

def test_generate_powershell_firewall_rule_command(temp_dir):
    """PowerShell rule creation command specifies stable internal Name and all required arguments."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    cmd = generate_powershell_firewall_rule_command(dedicated, rule_name="Tsukiko Boundary")
    assert f'New-NetFirewallRule -Name "{STABLE_RULE_ID}"' in cmd
    assert '-DisplayName "Tsukiko Boundary"' in cmd
    assert f'-Group "{RULE_GROUPING}"' in cmd
    assert RULE_OWNERSHIP_MARKER in cmd
    assert '-Direction Outbound -Action Block -Enabled True -Profile Any' in cmd
    assert f'-Program "{dedicated.resolve()}"' in cmd
    assert '-PolicyStore PersistentStore' in cmd


def test_generate_powershell_remove_rule_command():
    """PowerShell remove command deletes strictly by stable internal Name."""
    cmd = generate_powershell_remove_rule_command(DEFAULT_RULE_NAME)
    assert f'Remove-NetFirewallRule -Name "{STABLE_RULE_ID}" -PolicyStore PersistentStore' in cmd

    with pytest.raises(ValueError) as exc:
        generate_powershell_remove_rule_command("Unrelated System Rule")
    assert "non-Tsukiko firewall rule" in str(exc.value)


# =====================================================================
# 12. Defect A: Correct NetSecurity Security-Filter Properties Tests
# =====================================================================

def test_defect_a_override_block_rules_true_rejected(temp_dir):
    """OverrideBlockRules=True is rejected because it permits outbound bypass."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    rule = FirewallRuleInfo.create_unrestricted(program=str(dedicated), override_block_rules=True)
    ok, msg = validate_firewall_filters(rule, dedicated)
    assert ok is False
    assert "OverrideBlockRules enabled" in msg
    assert "must be False" in msg


def test_defect_a_override_block_rules_false_accepted(temp_dir):
    """OverrideBlockRules=False is accepted when all other security fields are valid."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    rule = FirewallRuleInfo.create_unrestricted(program=str(dedicated), override_block_rules=False)
    ok, msg = validate_firewall_filters(rule, dedicated)
    assert ok is True
    assert "All 7 outbound filter categories positively verified" in msg


def test_defect_a_override_block_rules_missing_rejected(temp_dir):
    """Missing OverrideBlockRules property is rejected (fails closed)."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    # When override_block_rules is not provided, it defaults to None (missing)
    rule = FirewallRuleInfo.create_unrestricted(program=str(dedicated), override_block_rules=None)
    ok, msg = validate_firewall_filters(rule, dedicated)
    assert ok is False
    assert "missing or null OverrideBlockRules" in msg


def test_defect_a_override_block_rules_null_rejected(temp_dir):
    """Null OverrideBlockRules property parsed from JSON is rejected."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    raw_json = {
        "Program": str(dedicated),
        "LocalAddress": "Any",
        "RemoteAddress": "Any",
        "Protocol": "Any",
        "LocalPort": "Any",
        "RemotePort": "Any",
        "Service": "Any",
        "InterfaceAlias": "Any",
        "InterfaceType": "Any",
        "Authentication": "NotRequired",
        "Encryption": "NotRequired",
        "OverrideBlockRules": None,  # JSON null
        "LocalUser": "Any",
        "RemoteUser": "Any",
        "RemoteMachine": "Any",
    }
    rules = parse_powershell_rules_json(raw_json)
    assert len(rules) == 1
    assert rules[0].override_block_rules is None
    ok, msg = validate_firewall_filters(rules[0], dedicated)
    assert ok is False
    assert "missing or null OverrideBlockRules" in msg


def test_defect_a_override_block_rules_malformed_rejected(temp_dir):
    """Malformed boolean values for OverrideBlockRules are rejected."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    for malformed in ["not_a_boolean", "maybe", 42]:
        raw_json = {
            "Program": str(dedicated),
            "LocalAddress": "Any",
            "RemoteAddress": "Any",
            "Protocol": "Any",
            "LocalPort": "Any",
            "RemotePort": "Any",
            "Service": "Any",
            "InterfaceAlias": "Any",
            "InterfaceType": "Any",
            "Authentication": "NotRequired",
            "Encryption": "NotRequired",
            "OverrideBlockRules": malformed,
            "LocalUser": "Any",
            "RemoteUser": "Any",
            "RemoteMachine": "Any",
        }
        rules = parse_powershell_rules_json(raw_json)
        assert len(rules) == 1
        ok, msg = validate_firewall_filters(rules[0], dedicated)
        assert ok is False
        assert "OverrideBlockRules" in msg


def test_defect_a_restricted_local_user_rejected(temp_dir):
    """Restricted LocalUser is rejected."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    rule = FirewallRuleInfo.create_unrestricted(program=str(dedicated), local_user="Domain\\Alice")
    ok, msg = validate_firewall_filters(rule, dedicated)
    assert ok is False
    assert "restricts local users" in msg


def test_defect_a_restricted_remote_user_rejected(temp_dir):
    """Restricted RemoteUser is rejected."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    rule = FirewallRuleInfo.create_unrestricted(program=str(dedicated), remote_user="Domain\\Bob")
    ok, msg = validate_firewall_filters(rule, dedicated)
    assert ok is False
    assert "restricts remote users" in msg


def test_defect_a_restricted_remote_machine_rejected(temp_dir):
    """Restricted RemoteMachine is rejected."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    rule = FirewallRuleInfo.create_unrestricted(program=str(dedicated), remote_machine="CORP-SERVER-01")
    ok, msg = validate_firewall_filters(rule, dedicated)
    assert ok is False
    assert "restricts remote machines" in msg


@pytest.mark.parametrize("sec_field", [
    "Authentication",
    "Encryption",
    "OverrideBlockRules",
    "LocalUser",
    "RemoteUser",
    "RemoteMachine",
])
def test_defect_a_missing_security_filter_properties_rejected(temp_dir, sec_field):
    """Missing any security filter property from JSON fails verification closed."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    full_dict = {
        "Program": str(dedicated),
        "LocalAddress": "Any",
        "RemoteAddress": "Any",
        "Protocol": "Any",
        "LocalPort": "Any",
        "RemotePort": "Any",
        "Service": "Any",
        "InterfaceAlias": "Any",
        "InterfaceType": "Any",
        "Authentication": "NotRequired",
        "Encryption": "NotRequired",
        "OverrideBlockRules": False,
        "LocalUser": "Any",
        "RemoteUser": "Any",
        "RemoteMachine": "Any",
    }
    del full_dict[sec_field]
    rules = parse_powershell_rules_json(full_dict)
    assert len(rules) == 1
    ok, msg = validate_firewall_filters(rules[0], dedicated)
    assert ok is False
    assert sec_field in msg or "Security filter" in msg


def test_defect_a_plural_property_names_rejected(temp_dir):
    """Old incorrect plural property names (LocalUsers, RemoteUsers, RemoteMachines) cannot pass verification."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    plural_only_dict = {
        "Program": str(dedicated),
        "LocalAddress": "Any",
        "RemoteAddress": "Any",
        "Protocol": "Any",
        "LocalPort": "Any",
        "RemotePort": "Any",
        "Service": "Any",
        "InterfaceAlias": "Any",
        "InterfaceType": "Any",
        "Authentication": "NotRequired",
        "Encryption": "NotRequired",
        "OverrideBlockRules": False,
        # Plural properties supplied, but singular CIM properties omitted:
        "LocalUsers": "Any",
        "RemoteUsers": "Any",
        "RemoteMachines": "Any",
    }
    rules = parse_powershell_rules_json(plural_only_dict)
    assert len(rules) == 1
    # Singular properties must be None:
    assert rules[0].local_user is None
    assert rules[0].remote_user is None
    assert rules[0].remote_machine is None

    ok, msg = validate_firewall_filters(rules[0], dedicated)
    assert ok is False
    assert "LocalUser" in msg or "Security filter" in msg


# =====================================================================
# 13. Defect B: Strict Missing-Value Handling Parameterized Matrix Tests
# =====================================================================

FILTER_PROPERTY_MATRIX = [
    ("Program", "C:\\test\\valid.exe", "", "*"),
    ("LocalAddress", "Any", "192.168.1.1", "10.0.0.0/8"),
    ("RemoteAddress", "Any", "8.8.8.8", "172.16.0.0/12"),
    ("Protocol", "Any", "TCP", "UDP"),
    ("LocalPort", "Any", "80", "443"),
    ("RemotePort", "Any", "8080", "53"),
    ("Service", "Any", "Spooler", "Dhcp"),
    ("InterfaceAlias", "Any", "Ethernet 1", "Wi-Fi"),
    ("InterfaceType", "Any", "Wireless", "RemoteAccess"),
    ("Authentication", "NotRequired", "Required", "RandomAuth"),
    ("Encryption", "NotRequired", "Required", "RandomEnc"),
    ("OverrideBlockRules", False, True, "malformed_string"),
    ("LocalUser", "Any", "LocalAdmin", "CORP\\User1"),
    ("RemoteUser", "Any", "RemoteAdmin", "CORP\\User2"),
    ("RemoteMachine", "Any", "DESKTOP-RESTRICTED", "SRV-DB-01"),
]


@pytest.mark.parametrize("prop_name,unrestricted_val,restrictive_val,alt_restrictive", FILTER_PROPERTY_MATRIX)
def test_defect_b_parameterized_filter_matrix_explicit_unrestricted(temp_dir, prop_name, unrestricted_val, restrictive_val, alt_restrictive):
    """Explicit unrestricted values pass filter verification."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    full_dict = {
        "Program": str(dedicated),
        "LocalAddress": "Any",
        "RemoteAddress": "Any",
        "Protocol": "Any",
        "LocalPort": "Any",
        "RemotePort": "Any",
        "Service": "Any",
        "InterfaceAlias": "Any",
        "InterfaceType": "Any",
        "Authentication": "NotRequired",
        "Encryption": "NotRequired",
        "OverrideBlockRules": False,
        "LocalUser": "Any",
        "RemoteUser": "Any",
        "RemoteMachine": "Any",
    }
    if prop_name != "Program":
        full_dict[prop_name] = unrestricted_val
    rules = parse_powershell_rules_json(full_dict)
    assert len(rules) == 1
    ok, msg = validate_firewall_filters(rules[0], dedicated)
    assert ok is True, f"Failed on unrestricted {prop_name}={unrestricted_val}: {msg}"


@pytest.mark.parametrize("prop_name,unrestricted_val,restrictive_val,alt_restrictive", FILTER_PROPERTY_MATRIX)
def test_defect_b_parameterized_filter_matrix_restrictive_rejected(temp_dir, prop_name, unrestricted_val, restrictive_val, alt_restrictive):
    """Explicit restrictive values fail filter verification."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    full_dict = {
        "Program": str(dedicated),
        "LocalAddress": "Any",
        "RemoteAddress": "Any",
        "Protocol": "Any",
        "LocalPort": "Any",
        "RemotePort": "Any",
        "Service": "Any",
        "InterfaceAlias": "Any",
        "InterfaceType": "Any",
        "Authentication": "NotRequired",
        "Encryption": "NotRequired",
        "OverrideBlockRules": False,
        "LocalUser": "Any",
        "RemoteUser": "Any",
        "RemoteMachine": "Any",
    }
    full_dict[prop_name] = restrictive_val
    rules = parse_powershell_rules_json(full_dict)
    assert len(rules) == 1
    ok, msg = validate_firewall_filters(rules[0], dedicated)
    assert ok is False, f"Expected rejection for restrictive {prop_name}={restrictive_val}, but passed!"


@pytest.mark.parametrize("prop_name,unrestricted_val,restrictive_val,alt_restrictive", FILTER_PROPERTY_MATRIX)
def test_defect_b_parameterized_filter_matrix_missing_rejected(temp_dir, prop_name, unrestricted_val, restrictive_val, alt_restrictive):
    """Missing property in JSON must never manufacture default and must fail verification closed."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    full_dict = {
        "Program": str(dedicated),
        "LocalAddress": "Any",
        "RemoteAddress": "Any",
        "Protocol": "Any",
        "LocalPort": "Any",
        "RemotePort": "Any",
        "Service": "Any",
        "InterfaceAlias": "Any",
        "InterfaceType": "Any",
        "Authentication": "NotRequired",
        "Encryption": "NotRequired",
        "OverrideBlockRules": False,
        "LocalUser": "Any",
        "RemoteUser": "Any",
        "RemoteMachine": "Any",
    }
    del full_dict[prop_name]
    rules = parse_powershell_rules_json(full_dict)
    assert len(rules) == 1
    ok, msg = validate_firewall_filters(rules[0], dedicated)
    assert ok is False, f"Expected rejection when {prop_name} is missing, but passed!"


@pytest.mark.parametrize("prop_name,unrestricted_val,restrictive_val,alt_restrictive", FILTER_PROPERTY_MATRIX)
def test_defect_b_parameterized_filter_matrix_null_rejected(temp_dir, prop_name, unrestricted_val, restrictive_val, alt_restrictive):
    """Null (None) property in JSON must never manufacture default and must fail verification closed."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    full_dict = {
        "Program": str(dedicated),
        "LocalAddress": "Any",
        "RemoteAddress": "Any",
        "Protocol": "Any",
        "LocalPort": "Any",
        "RemotePort": "Any",
        "Service": "Any",
        "InterfaceAlias": "Any",
        "InterfaceType": "Any",
        "Authentication": "NotRequired",
        "Encryption": "NotRequired",
        "OverrideBlockRules": False,
        "LocalUser": "Any",
        "RemoteUser": "Any",
        "RemoteMachine": "Any",
    }
    full_dict[prop_name] = None
    rules = parse_powershell_rules_json(full_dict)
    assert len(rules) == 1
    ok, msg = validate_firewall_filters(rules[0], dedicated)
    assert ok is False, f"Expected rejection when {prop_name} is null, but passed!"


# =====================================================================
# 14. Defect C: PowerShell Inspection Fail-Closed Tests
# =====================================================================

def test_defect_c_get_netfirewallrule_failure_propagates():
    """When Get-NetFirewallRule throws an error, PowerShell returns exit code 1 and error envelope."""
    mock_fail = subprocess.CompletedProcess(
        args=["powershell"],
        returncode=1,
        stdout=json.dumps({
            "Success": False,
            "InspectionComplete": False,
            "Rules": [],
            "Error": "The term 'Get-NetFirewallRule' is not recognized as the name of a cmdlet.",
        }),
        stderr="",
    )
    with patch("subprocess.run", return_value=mock_fail):
        res = query_matching_firewall_rules(DEFAULT_RULE_NAME)
        assert res.success is False
        assert res.inspection_complete is False
        assert res.rules == []
        assert "Get-NetFirewallRule" in res.error


def test_defect_c_filter_cmdlet_failure_propagates():
    """When a filter cmdlet (e.g. Get-NetFirewallSecurityFilter) throws, query fails closed."""
    mock_fail = subprocess.CompletedProcess(
        args=["powershell"],
        returncode=1,
        stdout=json.dumps({
            "Success": False,
            "InspectionComplete": False,
            "Rules": [],
            "Error": "Get-NetFirewallSecurityFilter : Access is denied to CIM repository.",
        }),
        stderr="",
    )
    with patch("subprocess.run", return_value=mock_fail):
        res = query_matching_firewall_rules(DEFAULT_RULE_NAME)
        assert res.success is False
        assert res.inspection_complete is False
        assert res.rules == []
        assert "Get-NetFirewallSecurityFilter" in res.error


def test_defect_c_missing_netsecurity_module_fails_closed():
    """When NetSecurity module is missing, non-zero returncode fails closed."""
    mock_fail = subprocess.CompletedProcess(
        args=["powershell"],
        returncode=1,
        stdout="",
        stderr="Import-Module : The specified module 'NetSecurity' was not found.",
    )
    with patch("subprocess.run", return_value=mock_fail):
        res = query_matching_firewall_rules(DEFAULT_RULE_NAME)
        assert res.success is False
        assert res.inspection_complete is False
        assert "NetSecurity" in res.error


def test_defect_c_activestore_envelope_failure(temp_dir):
    """When ActiveStore PowerShell script returns failure envelope, verify_effective_firewall_policy fails."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    mock_fail_env = _make_powershell_activestore_json(
        success=False,
        inspection_complete=False,
        error="WMI repository corrupted",
    )
    with patch("subprocess.run", return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=mock_fail_env)):
        ok, reason = verify_effective_firewall_policy(dedicated)
        assert ok is False
        assert "WMI repository corrupted" in reason or "inspection failed" in reason


def test_defect_c_activestore_incomplete_envelope(temp_dir):
    """ActiveStore query with incomplete envelope (missing Success/InspectionComplete) fails."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    incomplete_json = json.dumps({"Profiles": [], "Rules": []})
    with patch("subprocess.run", return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=incomplete_json)):
        ok, reason = verify_effective_firewall_policy(dedicated)
        assert ok is False
        assert "Incomplete ActiveStore response envelope" in reason


def test_defect_c_create_firewall_rule_refuses_when_pre_creation_incomplete(temp_dir):
    """create_firewall_rule refuses to proceed when pre-creation query has inspection_complete=False."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    mock_incomplete = FirewallQueryResult(
        success=False,
        inspection_complete=False,
        rules=[],
        error="RPC server unavailable",
    )
    with patch("app.core.privacy.windows_firewall.is_admin", return_value=True), \
         patch("app.core.privacy.windows_firewall.query_matching_firewall_rules", return_value=mock_incomplete):
        ok, reason = create_firewall_rule(dedicated, user_authorized=True)
        assert ok is False
        assert "inspection failure" in reason
        assert "RPC server unavailable" in reason


def test_defect_c_remove_firewall_rule_refuses_when_post_deletion_incomplete():
    """remove_firewall_rule refuses to confirm deletion when post-deletion query has inspection_complete=False."""
    pre_query_ok = FirewallQueryResult(
        success=True,
        inspection_complete=True,
        rules=[FirewallRuleInfo.create_unrestricted(
            program="C:\\Tsukiko\\tsukiko.exe",
            name=STABLE_RULE_ID,
            display_name=DEFAULT_RULE_NAME,
        )],
    )
    post_query_failed = FirewallQueryResult(
        success=False,
        inspection_complete=False,
        rules=[],
        error="PowerShell execution timeout",
    )
    mock_del_proc = subprocess.CompletedProcess(args=["powershell"], returncode=0, stdout="")

    with patch("app.core.privacy.windows_firewall.is_admin", return_value=True), \
         patch("app.core.privacy.windows_firewall.query_matching_firewall_rules", side_effect=[pre_query_ok, post_query_failed]), \
         patch("subprocess.run", return_value=mock_del_proc):
        ok, reason = remove_firewall_rule(DEFAULT_RULE_NAME, user_authorized=True)
        assert ok is False
        assert "post-deletion inspection failed" in reason
        assert "PowerShell execution timeout" in reason

