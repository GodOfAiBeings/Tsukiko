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
import shutil
import subprocess
import sys
from unittest.mock import MagicMock, patch
import pytest

from app.core.privacy.windows_firewall import (
    DEFAULT_DESCRIPTION,
    DEFAULT_RULE_NAME,
    LEGACY_RULE_NAME,
    RULE_GROUPING,
    RULE_OWNERSHIP_MARKER,
    STABLE_RULE_ID,
    PS_CIM_SERIALIZER_SNIPPET,
    CimFieldRecord,
    CimFieldState,
    FirewallParseError,
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
    validate_response_envelope,
    verify_effective_firewall_policy,
    verify_firewall_rule,
)


_REAL_SHUTIL_WHICH = shutil.which


@pytest.fixture(autouse=True)
def mock_windows_env():
    """Ensure Windows Firewall unit tests run consistently across all platforms."""
    def _custom_which(cmd: str):
        real = _REAL_SHUTIL_WHICH(cmd)
        if real:
            return real
        if "powershell" in cmd.lower():
            return "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
        return f"C:\\Windows\\System32\\{cmd}.exe"

    with patch("platform.system", return_value="Windows"), \
         patch("shutil.which", side_effect=_custom_which):
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
    """Persistent rule verification fails if output has no Profiles property."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    output = _make_powershell_query_json(rules=[{
        "Program": str(dedicated.resolve()),
        "Profiles": None,
    }])
    with patch("subprocess.run", return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=output)):
        ok, reason = verify_firewall_rule(dedicated)
        assert ok is False
        assert "profile information is missing" in reason


def test_verify_firewall_rule_rejects_empty_profiles_field(temp_dir):
    """Persistent rule verification fails if Profiles field is empty."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    output = _make_powershell_query_json(rules=[{
        "Program": str(dedicated.resolve()),
        "Profiles": "",
    }])
    with patch("subprocess.run", return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=output)):
        ok, reason = verify_firewall_rule(dedicated)
        assert ok is False
        assert "profile information is empty" in reason


def test_verify_firewall_rule_rejects_incomplete_profiles(temp_dir):
    """Persistent rule verification fails if Profiles field only covers Public."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    output = _make_powershell_query_json(rules=[{
        "Program": str(dedicated.resolve()),
        "Profiles": "Public",
    }])
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
    errors: list[str] | None = None,
    bypass_rules: list[dict] | None = None,
    raw_rules: bool = False,
    schema_version: int = 1,
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
                    "Package": None,
                    "LocalAddress": "Any",
                    "RemoteAddress": "Any",
                    "Protocol": "Any",
                    "LocalPort": "Any",
                    "RemotePort": "Any",
                    "IcmpType": "Any",
                    "DynamicTarget": "Any",
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
        "SchemaVersion": schema_version,
        "Success": success,
        "InspectionComplete": inspection_complete,
        "PolicyStore": "ActiveStore",
        "Profiles": profiles_status,
        "Rules": full_rules,
        "BypassRules": bypass_rules or [],
        "Errors": errors if errors is not None else ([error] if error else []),
        "Error": error,
    })


def _make_powershell_query_json(
    rules: list[dict] | None = None,
    success: bool = True,
    inspection_complete: bool = True,
    error: str | None = None,
    errors: list[str] | None = None,
    bypass_rules: list[dict] | None = None,
    raw_rules: bool = False,
    policy_store: str = "PersistentStore",
    schema_version: int = 1,
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
                    "Package": None,
                    "LocalAddress": "Any",
                    "RemoteAddress": "Any",
                    "Protocol": "Any",
                    "LocalPort": "Any",
                    "RemotePort": "Any",
                    "IcmpType": "Any",
                    "DynamicTarget": "Any",
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
        "SchemaVersion": schema_version,
        "Success": success,
        "InspectionComplete": inspection_complete,
        "PolicyStore": policy_store,
        "Profiles": [],
        "Rules": full_rules,
        "BypassRules": bypass_rules or [],
        "Errors": errors if errors is not None else ([error] if error else []),
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

    mock_json = _make_powershell_query_json(rules=[{
        "Name": STABLE_RULE_ID,
        "DisplayName": DEFAULT_RULE_NAME,
        "Group": RULE_GROUPING,
        "Description": f"{RULE_OWNERSHIP_MARKER} Offline privacy boundary",
        "Enabled": True,
        "Direction": "Outbound",
        "Action": "Block",
        "Profiles": "Domain,Private,Public",
        "Program": str(dedicated.resolve()),
    }])
    mock_proc = subprocess.CompletedProcess(
        args=["powershell"], returncode=0, stdout=mock_json, stderr=""
    )
    with patch("subprocess.run", return_value=mock_proc):
        verified, reason = verify_firewall_rule(dedicated, rule_name=DEFAULT_RULE_NAME)
        assert verified is True
        assert "Firewall rule verified" in reason


def test_verify_firewall_rule_rejects_unowned_or_foreign_rule(temp_dir):
    """Rule verification fails if the rule lacks Tsukiko grouping and description marker."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    unowned_json = _make_powershell_query_json(rules=[{
        "Name": DEFAULT_RULE_NAME,
        "DisplayName": DEFAULT_RULE_NAME,
        "Group": "",
        "Description": "Unrelated custom rule",
        "Enabled": True,
        "Direction": "Outbound",
        "Action": "Block",
        "Profiles": "Domain,Private,Public",
        "Program": str(dedicated.resolve()),
    }])
    mock_proc = subprocess.CompletedProcess(args=["powershell"], returncode=0, stdout=unowned_json, stderr="")
    with patch("subprocess.run", return_value=mock_proc):
        verified, reason = verify_firewall_rule(dedicated, rule_name=DEFAULT_RULE_NAME)
        assert verified is False
        assert "lacks verified Tsukiko ownership markers" in reason


def test_verify_firewall_rule_rejects_mismatched_properties(temp_dir):
    """Rule verification fails if direction, action, enabled, or program mismatch."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    # 1. Action is Allow instead of Block
    json_allow = _make_powershell_query_json(rules=[{"Action": "Allow", "Program": str(dedicated.resolve())}])
    with patch("subprocess.run", return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=json_allow)):
        assert verify_firewall_rule(dedicated, rule_name=DEFAULT_RULE_NAME)[0] is False

    # 2. Direction is In instead of Out
    json_in = _make_powershell_query_json(rules=[{"Direction": "In", "Program": str(dedicated.resolve())}])
    with patch("subprocess.run", return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=json_in)):
        assert verify_firewall_rule(dedicated, rule_name=DEFAULT_RULE_NAME)[0] is False

    # 3. Enabled is No
    json_disabled = _make_powershell_query_json(rules=[{"Enabled": False, "Program": str(dedicated.resolve())}])
    with patch("subprocess.run", return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=json_disabled)):
        assert verify_firewall_rule(dedicated, rule_name=DEFAULT_RULE_NAME)[0] is False

    # 4. Program mismatch
    json_mismatched_exe = _make_powershell_query_json(rules=[{"Program": "C:\\other\\app.exe"}])
    with patch("subprocess.run", return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=json_mismatched_exe)):
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

    empty_json = _make_powershell_query_json(rules=[])
    with patch("app.core.privacy.windows_firewall.verify_effective_firewall_policy", return_value=(False, "Rule does not exist")), \
         patch("subprocess.run", return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=empty_json)):
        status = get_security_status(dedicated)
        assert status.status == "os_policy_not_configured"
        assert status.is_dedicated_binary is True
        assert status.rule_exists is False


def test_security_status_os_policy_unverified(temp_dir):
    """Dedicated binary with rule present but effective ActiveStore policy unverified reports os_policy_unverified."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    persistent_json = _make_powershell_query_json(rules=[{
        "Name": DEFAULT_RULE_NAME,
        "DisplayName": DEFAULT_RULE_NAME,
        "Group": RULE_GROUPING,
        "Description": f"{RULE_OWNERSHIP_MARKER} Test",
        "Profiles": "Domain,Private,Public",
        "Enabled": True,
        "Direction": "Outbound",
        "Action": "Block",
        "Program": str(dedicated.resolve()),
    }])
    with patch("app.core.privacy.windows_firewall.verify_effective_firewall_policy", return_value=(False, "ActiveStore query failed")), \
         patch("subprocess.run", return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=persistent_json)):
        status = get_security_status(dedicated)
        assert status.status == "os_policy_unverified"
        assert status.is_dedicated_binary is True
        assert status.rule_exists is True
        assert "ActiveStore query failed" in status.details or "could not be established" in status.details


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
        assert "response envelope" in res.error.lower() or "missing" in res.error.lower()


def test_query_matching_firewall_rules_incomplete_envelope_fails_closed():
    """Incomplete envelope missing required fields fails closed."""
    bad_env = json.dumps({"Rules": []})  # missing required fields
    mock_proc = subprocess.CompletedProcess(args=["powershell"], returncode=0, stdout=bad_env)
    with patch("subprocess.run", return_value=mock_proc):
        res = query_matching_firewall_rules(DEFAULT_RULE_NAME)
        assert res.success is False
        assert res.inspection_complete is False
        assert "incomplete" in res.error.lower() or "missing required fields" in res.error.lower()


def test_query_matching_firewall_rules_envelope_failure_fails_closed():
    """Envelope explicitly reporting failure fails closed."""
    fail_env = json.dumps({
        "SchemaVersion": 1,
        "Success": False,
        "InspectionComplete": False,
        "PolicyStore": "PersistentStore",
        "Profiles": [],
        "Rules": [],
        "BypassRules": [],
        "Errors": ["NetSecurity CIM provider crashed"],
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
        "Package": None,
        "LocalAddress": "Any",
        "RemoteAddress": "Any",
        "Protocol": "Any",
        "LocalPort": "Any",
        "RemotePort": "Any",
        "IcmpType": "Any",
        "DynamicTarget": "Any",
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
            "Package": None,
            "LocalAddress": "Any",
            "RemoteAddress": "Any",
            "Protocol": "Any",
            "LocalPort": "Any",
            "RemotePort": "Any",
            "IcmpType": "Any",
            "DynamicTarget": "Any",
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
        "Package": None,
        "LocalAddress": "Any",
        "RemoteAddress": "Any",
        "Protocol": "Any",
        "LocalPort": "Any",
        "RemotePort": "Any",
        "IcmpType": "Any",
        "DynamicTarget": "Any",
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
        "Package": None,
        "LocalAddress": "Any",
        "RemoteAddress": "Any",
        "Protocol": "Any",
        "LocalPort": "Any",
        "RemotePort": "Any",
        "IcmpType": "Any",
        "DynamicTarget": "Any",
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
    ("Package", None, "Microsoft.WindowsStore_8wekyb3d8bbwe", "S-1-15-2-1"),
    ("LocalAddress", "Any", "192.168.1.1", "10.0.0.0/8"),
    ("RemoteAddress", "Any", "8.8.8.8", "172.16.0.0/12"),
    ("Protocol", "Any", "TCP", "UDP"),
    ("LocalPort", "Any", "80", "443"),
    ("RemotePort", "Any", "8080", "53"),
    ("IcmpType", "Any", "8", "Echo"),
    ("DynamicTarget", "Any", "WifiDirectPrinting", "ProximityBySharing"),
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
        "Package": None,
        "LocalAddress": "Any",
        "RemoteAddress": "Any",
        "Protocol": "Any",
        "LocalPort": "Any",
        "RemotePort": "Any",
        "IcmpType": "Any",
        "DynamicTarget": "Any",
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

    for val in [restrictive_val, alt_restrictive]:
        full_dict = {
            "Program": str(dedicated),
            "Package": None,
            "LocalAddress": "Any",
            "RemoteAddress": "Any",
            "Protocol": "Any",
            "LocalPort": "Any",
            "RemotePort": "Any",
            "IcmpType": "Any",
            "DynamicTarget": "Any",
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
        full_dict[prop_name] = val
        rules = parse_powershell_rules_json(full_dict)
        assert len(rules) == 1
        ok, msg = validate_firewall_filters(rules[0], dedicated)
        assert ok is False, f"Expected rejection for restrictive {prop_name}={val!r}, but passed!"


@pytest.mark.parametrize("prop_name,unrestricted_val,restrictive_val,alt_restrictive", FILTER_PROPERTY_MATRIX)
def test_defect_b_parameterized_filter_matrix_missing_rejected(temp_dir, prop_name, unrestricted_val, restrictive_val, alt_restrictive):
    """Missing property in JSON must never manufacture default and must fail verification closed."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    full_dict = {
        "Program": str(dedicated),
        "Package": None,
        "LocalAddress": "Any",
        "RemoteAddress": "Any",
        "Protocol": "Any",
        "LocalPort": "Any",
        "RemotePort": "Any",
        "IcmpType": "Any",
        "DynamicTarget": "Any",
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
    """Null (None) property in JSON: Package=None is valid unrestricted for Win32; all other 17 properties fail closed."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    full_dict = {
        "Program": str(dedicated),
        "Package": None,
        "LocalAddress": "Any",
        "RemoteAddress": "Any",
        "Protocol": "Any",
        "LocalPort": "Any",
        "RemotePort": "Any",
        "IcmpType": "Any",
        "DynamicTarget": "Any",
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
    if prop_name == "Package":
        assert ok is True, f"Expected Package=None to pass for standard Win32 binary, got error: {msg}"
    else:
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
        assert "response envelope" in reason.lower() or "missing required fields" in reason.lower()


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


# =====================================================================
# 15. Complete NetSecurity CIM Filter Schema & Bypass Evaluation Tests
# =====================================================================

def test_activestore_bypass_outbound_allow_override_block_rules_rejects(temp_dir):
    """When ActiveStore contains an Outbound Allow rule with OverrideBlockRules=True, effective policy fails closed."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    mock_json = _make_powershell_activestore_json(
        rules=[{
            "Name": STABLE_RULE_ID,
            "DisplayName": DEFAULT_RULE_NAME,
            "Program": str(dedicated.resolve()),
        }],
        bypass_rules=[{
            "Name": "Admin_Bypass_Allow",
            "DisplayName": "Admin Bypass Allow",
            "Program": str(dedicated.resolve()),
            "Scope": "ExactExecutable",
            "OverrideBlockRules": True,
        }],
    )
    with patch("subprocess.run", return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=mock_json)):
        ok, reason = verify_effective_firewall_policy(dedicated)
        assert ok is False
        assert "Conflicting outbound bypass Allow rule" in reason
        assert "Admin Bypass Allow" in reason
        assert "OverrideBlockRules=True" in reason


def test_filter_association_count_mismatch_fails_closed():
    """When any associated filter cmdlet returns != 1 object, PowerShell query fails closed."""
    mock_fail = subprocess.CompletedProcess(
        args=["powershell"],
        returncode=1,
        stdout=json.dumps({
            "SchemaVersion": 1,
            "Success": False,
            "InspectionComplete": False,
            "PolicyStore": "PersistentStore",
            "Profiles": [],
            "Rules": [],
            "BypassRules": [],
            "Errors": ["Application filter association integrity failure for rule 'TestRule': expected 1 filter object, got 2"],
        }),
        stderr="",
    )
    with patch("subprocess.run", return_value=mock_fail):
        res = query_matching_firewall_rules(DEFAULT_RULE_NAME)
        assert res.success is False
        assert res.inspection_complete is False
        assert "association integrity failure" in res.error


def test_envelope_unsupported_schema_version_fails_closed():
    """Unsupported SchemaVersion (e.g. 2 or 0) raises FirewallParseError / fails closed."""
    bad_schema_json = json.dumps({
        "SchemaVersion": 2,
        "Success": True,
        "InspectionComplete": True,
        "PolicyStore": "PersistentStore",
        "Profiles": [],
        "Rules": [],
        "BypassRules": [],
        "Errors": [],
    })
    with pytest.raises(FirewallParseError) as exc:
        parse_powershell_rules_json(json.loads(bad_schema_json))
    assert "Unsupported SchemaVersion: 2" in str(exc.value)

    mock_proc = subprocess.CompletedProcess(args=["powershell"], returncode=0, stdout=bad_schema_json)
    with patch("subprocess.run", return_value=mock_proc):
        res = query_matching_firewall_rules(DEFAULT_RULE_NAME)
        assert res.success is False
        assert res.inspection_complete is False
        assert "Unsupported SchemaVersion" in res.error


def test_envelope_missing_or_null_rules_fails_closed():
    """Null or non-list Rules property in envelope fails closed."""
    null_rules = json.dumps({
        "SchemaVersion": 1,
        "Success": True,
        "InspectionComplete": True,
        "PolicyStore": "PersistentStore",
        "Profiles": [],
        "Rules": None,
        "BypassRules": [],
        "Errors": [],
    })
    with pytest.raises(FirewallParseError) as exc:
        parse_powershell_rules_json(json.loads(null_rules))
    assert "contains null for required fields" in str(exc.value)

    invalid_type_rules = json.dumps({
        "SchemaVersion": 1,
        "Success": True,
        "InspectionComplete": True,
        "PolicyStore": "PersistentStore",
        "Profiles": [],
        "Rules": "invalid_not_a_list",
        "BypassRules": [],
        "Errors": [],
    })
    with pytest.raises(FirewallParseError) as exc:
        parse_powershell_rules_json(json.loads(invalid_type_rules))
    assert "Rules must be a list" in str(exc.value)


def test_query_matching_firewall_rules_without_powershell_fails_closed():
    """When PowerShell is not available, query_matching_firewall_rules strictly fails closed (no netsh fallback)."""
    with patch("shutil.which", return_value=None):
        res = query_matching_firewall_rules(DEFAULT_RULE_NAME)
        assert res.success is False
        assert res.inspection_complete is False
        assert "PowerShell is not available on PATH" in res.error


def test_security_status_fails_closed_to_os_policy_unverified_when_powershell_unavailable(temp_dir):
    """When PowerShell is unavailable, security status reports os_policy_unverified."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    with patch("shutil.which", return_value=None):
        status = get_security_status(dedicated)
        assert status.status == "os_policy_unverified"
        assert status.is_dedicated_binary is True
        assert status.rule_exists is False
        assert "inspection failed" in status.details


def test_validate_firewall_filters_rejects_restricted_package(temp_dir):
    """Reject AppContainer package restriction on standard Win32 binary."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    r = FirewallRuleInfo.create_unrestricted(program=str(dedicated), package="Microsoft.WindowsStore_8wekyb3d8bbwe")
    ok, msg = validate_firewall_filters(r, dedicated)
    assert ok is False
    assert "restricts package" in msg


def test_validate_firewall_filters_rejects_restricted_icmp_and_dynamic_target(temp_dir):
    """Reject restrictive IcmpType or DynamicTarget."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    r1 = FirewallRuleInfo.create_unrestricted(program=str(dedicated), icmp_type="8")
    ok, msg = validate_firewall_filters(r1, dedicated)
    assert ok is False
    assert "restricts ICMP type" in msg

    r2 = FirewallRuleInfo.create_unrestricted(program=str(dedicated), dynamic_target="WifiDirectPrinting")
    ok, msg = validate_firewall_filters(r2, dedicated)
    assert ok is False
    assert "restricts dynamic target" in msg


# =====================================================================
# 16. Comprehensive Acceptance Regression Tests (Bypass, Envelope, CIM)
# =====================================================================

def test_bypass_exact_executable_outbound_allow_rejects(temp_dir):
    """Exact executable-specific outbound Allow bypass rule in ActiveStore rejects os_policy_active."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    mock_json = _make_powershell_activestore_json(
        rules=[{
            "Name": STABLE_RULE_ID,
            "DisplayName": DEFAULT_RULE_NAME,
            "Program": str(dedicated.resolve()),
        }],
        bypass_rules=[{
            "Name": "Bypass_Exact_Tsukiko",
            "DisplayName": "Bypass Exact Tsukiko",
            "Program": str(dedicated.resolve()),
            "Scope": "ExactExecutable",
            "OverrideBlockRules": True,
        }],
    )
    with patch("subprocess.run", return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=mock_json)):
        ok, reason = verify_effective_firewall_policy(dedicated)
        assert ok is False
        assert "Bypass Exact Tsukiko" in reason
        assert "OverrideBlockRules=True" in reason


def test_bypass_all_programs_outbound_allow_rejects(temp_dir):
    """Unrestricted All-Programs outbound Allow bypass rule in ActiveStore rejects os_policy_active."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    mock_json = _make_powershell_activestore_json(
        rules=[{
            "Name": STABLE_RULE_ID,
            "DisplayName": DEFAULT_RULE_NAME,
            "Program": str(dedicated.resolve()),
        }],
        bypass_rules=[{
            "Name": "Global_Allow_Bypass",
            "DisplayName": "Global Allow Bypass",
            "Program": "Any",
            "Scope": "AllPrograms",
            "OverrideBlockRules": True,
        }],
    )
    with patch("subprocess.run", return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=mock_json)):
        ok, reason = verify_effective_firewall_policy(dedicated)
        assert ok is False
        assert "Global Allow Bypass" in reason
        assert "AllPrograms" in reason


def test_bypass_unrelated_executable_allowed_tsukiko_accepted(temp_dir):
    """Unrelated executable-specific bypass does NOT invalidate Tsukiko's outbound policy."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    # When unrelated bypass rule exists on the system (e.g. for svchost.exe),
    # the PowerShell bypass discovery identifies that it does not apply to Tsukiko,
    # so bypass_rules is empty for Tsukiko.
    mock_json = _make_powershell_activestore_json(
        rules=[{
            "Name": STABLE_RULE_ID,
            "DisplayName": DEFAULT_RULE_NAME,
            "Program": str(dedicated.resolve()),
        }],
        bypass_rules=[],
    )
    with patch("subprocess.run", return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=mock_json)):
        ok, reason = verify_effective_firewall_policy(dedicated)
        assert ok is True
        assert "Effective Windows Firewall policy verified" in reason


def test_bypass_application_filter_cmdlet_failure_fails_closed(temp_dir):
    """Application-filter cmdlet failure during bypass discovery propagates to failure envelope."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    fail_json = json.dumps({
        "SchemaVersion": 1,
        "Success": False,
        "InspectionComplete": False,
        "PolicyStore": "ActiveStore",
        "Profiles": [],
        "Rules": [],
        "BypassRules": [],
        "Errors": ["Get-NetFirewallApplicationFilter : Access is denied"],
    })
    with patch("subprocess.run", return_value=subprocess.CompletedProcess(args=[], returncode=1, stdout=fail_json)):
        ok, reason = verify_effective_firewall_policy(dedicated)
        assert ok is False
        assert "Access is denied" in reason or "ActiveStore inspection failed" in reason


def test_bypass_rule_query_failure_fails_closed(temp_dir):
    """Rule query failure during bypass discovery propagates to failure envelope."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    fail_json = json.dumps({
        "SchemaVersion": 1,
        "Success": False,
        "InspectionComplete": False,
        "PolicyStore": "ActiveStore",
        "Profiles": [],
        "Rules": [],
        "BypassRules": [],
        "Errors": ["Get-NetFirewallRule : RPC server unavailable"],
    })
    with patch("subprocess.run", return_value=subprocess.CompletedProcess(args=[], returncode=1, stdout=fail_json)):
        ok, reason = verify_effective_firewall_policy(dedicated)
        assert ok is False
        assert "RPC server unavailable" in reason or "ActiveStore inspection failed" in reason


def test_bypass_security_filter_cmdlet_failure_fails_closed(temp_dir):
    """Security-filter cmdlet failure during bypass discovery propagates to failure envelope."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    fail_json = json.dumps({
        "SchemaVersion": 1,
        "Success": False,
        "InspectionComplete": False,
        "PolicyStore": "ActiveStore",
        "Profiles": [],
        "Rules": [],
        "BypassRules": [],
        "Errors": ["Get-NetFirewallSecurityFilter : Cannot query ActiveStore"],
    })
    with patch("subprocess.run", return_value=subprocess.CompletedProcess(args=[], returncode=1, stdout=fail_json)):
        ok, reason = verify_effective_firewall_policy(dedicated)
        assert ok is False
        assert "Cannot query ActiveStore" in reason or "ActiveStore inspection failed" in reason


def test_bypass_zero_associated_security_filters_fails_closed(temp_dir):
    """Zero associated security filters for a candidate rule causes association integrity failure."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    fail_json = json.dumps({
        "SchemaVersion": 1,
        "Success": False,
        "InspectionComplete": False,
        "PolicyStore": "ActiveStore",
        "Profiles": [],
        "Rules": [],
        "BypassRules": [],
        "Errors": ["Association integrity violation: Bypass candidate rule 'RuleX' has 0 security filters (expected exactly 1)"],
    })
    with patch("subprocess.run", return_value=subprocess.CompletedProcess(args=[], returncode=1, stdout=fail_json)):
        ok, reason = verify_effective_firewall_policy(dedicated)
        assert ok is False
        assert "Association integrity violation" in reason


def test_bypass_multiple_associated_security_filters_fails_closed(temp_dir):
    """Multiple associated security filters for a candidate rule causes association integrity failure."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    fail_json = json.dumps({
        "SchemaVersion": 1,
        "Success": False,
        "InspectionComplete": False,
        "PolicyStore": "ActiveStore",
        "Profiles": [],
        "Rules": [],
        "BypassRules": [],
        "Errors": ["Association integrity violation: Bypass candidate rule 'RuleY' has 2 security filters (expected exactly 1)"],
    })
    with patch("subprocess.run", return_value=subprocess.CompletedProcess(args=[], returncode=1, stdout=fail_json)):
        ok, reason = verify_effective_firewall_policy(dedicated)
        assert ok is False
        assert "Association integrity violation" in reason


def test_bypass_malformed_response_fails_closed(temp_dir):
    """Malformed or non-list BypassRules in response envelope fails validation."""
    dedicated = temp_dir / "tsukiko.exe"
    _create_mock_pe_executable(dedicated)

    malformed_json = json.dumps({
        "SchemaVersion": 1,
        "Success": True,
        "InspectionComplete": True,
        "PolicyStore": "ActiveStore",
        "Profiles": [
            {"Name": "Domain", "Enabled": 1, "AllowLocalFirewallRules": 1},
            {"Name": "Private", "Enabled": 1, "AllowLocalFirewallRules": 1},
            {"Name": "Public", "Enabled": 1, "AllowLocalFirewallRules": 1},
        ],
        "Rules": [],
        "BypassRules": "not_a_list",
        "Errors": [],
    })
    with patch("subprocess.run", return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=malformed_json)):
        ok, reason = verify_effective_firewall_policy(dedicated)
        assert ok is False
        assert "BypassRules must be a list" in reason


# --- Response Envelope Schema Tests ---

def test_envelope_missing_schema_version_fails_closed():
    """Missing SchemaVersion key in response envelope is strictly rejected."""
    env = {
        "Success": True,
        "InspectionComplete": True,
        "PolicyStore": "PersistentStore",
        "Profiles": [],
        "Rules": [],
        "BypassRules": [],
        "Errors": [],
    }
    ok, err = validate_response_envelope(env, expected_policy_store="PersistentStore")
    assert ok is False
    assert "missing required fields" in err
    assert "SchemaVersion" in err

    with pytest.raises(FirewallParseError) as exc:
        parse_powershell_rules_json(env, expected_policy_store="PersistentStore")
    assert "missing required fields" in str(exc.value)


def test_envelope_missing_policy_store_fails_closed():
    """Missing PolicyStore key in response envelope is strictly rejected."""
    env = {
        "SchemaVersion": 1,
        "Success": True,
        "InspectionComplete": True,
        "Profiles": [],
        "Rules": [],
        "BypassRules": [],
        "Errors": [],
    }
    ok, err = validate_response_envelope(env)
    assert ok is False
    assert "missing required fields" in err
    assert "PolicyStore" in err


def test_envelope_policy_store_mismatch_fails_closed():
    """PolicyStore mismatch between envelope and expected store is strictly rejected."""
    env = {
        "SchemaVersion": 1,
        "Success": True,
        "InspectionComplete": True,
        "PolicyStore": "PersistentStore",
        "Profiles": [],
        "Rules": [],
        "BypassRules": [],
        "Errors": [],
    }
    ok, err = validate_response_envelope(env, expected_policy_store="ActiveStore")
    assert ok is False
    assert "PolicyStore mismatch" in err
    assert "PersistentStore" in err
    assert "ActiveStore" in err


def test_envelope_missing_bypass_rules_fails_closed():
    """Missing BypassRules key in response envelope is strictly rejected."""
    env = {
        "SchemaVersion": 1,
        "Success": True,
        "InspectionComplete": True,
        "PolicyStore": "ActiveStore",
        "Profiles": [],
        "Rules": [],
        "Errors": [],
    }
    ok, err = validate_response_envelope(env, expected_policy_store="ActiveStore")
    assert ok is False
    assert "missing required fields" in err
    assert "BypassRules" in err


def test_envelope_missing_profiles_fails_closed():
    """Missing Profiles key in response envelope is strictly rejected."""
    env = {
        "SchemaVersion": 1,
        "Success": True,
        "InspectionComplete": True,
        "PolicyStore": "ActiveStore",
        "Rules": [],
        "BypassRules": [],
        "Errors": [],
    }
    ok, err = validate_response_envelope(env, expected_policy_store="ActiveStore")
    assert ok is False
    assert "missing required fields" in err
    assert "Profiles" in err


def test_envelope_null_field_fails_closed():
    """Null values for any required envelope fields are strictly rejected."""
    for field in ["SchemaVersion", "Success", "InspectionComplete", "PolicyStore", "Profiles", "Rules", "BypassRules", "Errors"]:
        env = {
            "SchemaVersion": 1,
            "Success": True,
            "InspectionComplete": True,
            "PolicyStore": "ActiveStore",
            "Profiles": [],
            "Rules": [],
            "BypassRules": [],
            "Errors": [],
        }
        env[field] = None
        ok, err = validate_response_envelope(env, expected_policy_store="ActiveStore")
        assert ok is False
        assert f"contains null for required fields: ['{field}']" in err


def test_envelope_incorrect_type_fails_closed():
    """Incorrect types for envelope fields (e.g. non-bool Success, non-int SchemaVersion) are rejected."""
    bad_types = [
        ("SchemaVersion", "1", "must be an integer"),
        ("SchemaVersion", True, "must be an integer"),
        ("Success", 1, "must be a boolean"),
        ("Success", "True", "must be a boolean"),
        ("InspectionComplete", 0, "must be a boolean"),
        ("PolicyStore", 123, "must be a string"),
        ("Profiles", "not_a_list", "must be a list"),
        ("Rules", "not_a_list", "must be a list"),
        ("BypassRules", "not_a_list", "must be a list"),
        ("Errors", "not_a_list", "must be a list"),
    ]
    for field, bad_val, exp_msg in bad_types:
        env = {
            "SchemaVersion": 1,
            "Success": True,
            "InspectionComplete": True,
            "PolicyStore": "ActiveStore",
            "Profiles": [],
            "Rules": [],
            "BypassRules": [],
            "Errors": [],
        }
        env[field] = bad_val
        ok, err = validate_response_envelope(env, expected_policy_store="ActiveStore")
        assert ok is False
        assert exp_msg in err


def test_envelope_inconsistent_success_inspection_complete_fails_closed():
    """Inconsistent combinations of Success and InspectionComplete are rejected."""
    env1 = {
        "SchemaVersion": 1,
        "Success": True,
        "InspectionComplete": False,
        "PolicyStore": "ActiveStore",
        "Profiles": [],
        "Rules": [],
        "BypassRules": [],
        "Errors": [],
    }
    ok, err = validate_response_envelope(env1)
    assert ok is False
    assert "Contradictory envelope state" in err

    env2 = {
        "SchemaVersion": 1,
        "Success": False,
        "InspectionComplete": True,
        "PolicyStore": "ActiveStore",
        "Profiles": [],
        "Rules": [],
        "BypassRules": [],
        "Errors": [],
    }
    ok, err = validate_response_envelope(env2)
    assert ok is False
    assert "Contradictory envelope state" in err


def test_envelope_inconsistent_success_errors_fails_closed():
    """Success=True with a non-empty Errors list is contradictory and rejected."""
    env = {
        "SchemaVersion": 1,
        "Success": True,
        "InspectionComplete": True,
        "PolicyStore": "ActiveStore",
        "Profiles": [],
        "Rules": [],
        "BypassRules": [],
        "Errors": ["Some unexpected error occurred"],
    }
    ok, err = validate_response_envelope(env)
    assert ok is False
    assert "Success is True but Errors is non-empty" in err


# --- CIM Field-State Record Tests ---

def test_cim_record_every_valid_field_state():
    """CimFieldRecord accurately classifies and represents all valid field states."""
    rec_val = CimFieldRecord.from_raw({
        "State": "PROPERTY_PRESENT_WITH_VALID_VALUE",
        "Exists": True,
        "IsNull": False,
        "Value": "Any",
        "StringValue": "Any",
        "Type": "String",
    })
    assert rec_val.state == CimFieldState.VALID
    assert rec_val.exists is True
    assert rec_val.is_null is False
    assert rec_val.value == "Any"
    assert rec_val.type_name == "String"

    rec_null = CimFieldRecord.from_raw({
        "State": "PROPERTY_PRESENT_WITH_NULL",
        "Exists": True,
        "IsNull": True,
        "Value": None,
        "StringValue": None,
        "Type": "Null",
    })
    assert rec_null.state == CimFieldState.NULL
    assert rec_null.exists is True
    assert rec_null.is_null is True
    assert rec_null.value is None

    rec_miss = CimFieldRecord.from_raw({
        "State": "PROPERTY_MISSING",
        "Exists": False,
        "IsNull": True,
        "Value": None,
        "StringValue": None,
        "Type": "None",
    })
    assert rec_miss.state == CimFieldState.MISSING
    assert rec_miss.exists is False
    assert rec_miss.is_null is True

    rec_mal = CimFieldRecord.from_raw({
        "State": "PROPERTY_PRESENT_WITH_MALFORMED_VALUE",
        "Exists": True,
        "IsNull": False,
        "Value": "invalid",
        "StringValue": "invalid",
        "Type": "Malformed",
    })
    assert rec_mal.state == CimFieldState.MALFORMED


def test_cim_record_missing_and_null_states():
    """Null and Missing helper factory methods produce correct invariants."""
    null_rec = CimFieldRecord.null("String")
    assert null_rec.state == CimFieldState.NULL
    assert null_rec.exists is True
    assert null_rec.is_null is True
    assert null_rec.value is None
    assert null_rec.type_name == "String"

    miss_rec = CimFieldRecord.missing()
    assert miss_rec.state == CimFieldState.MISSING
    assert miss_rec.exists is False
    assert miss_rec.is_null is True
    assert miss_rec.value is None


def test_cim_record_rejects_non_boolean_exists():
    """Non-boolean Exists values (e.g. strings, integers) are rejected as malformed without coercion."""
    for bad_exists in ["True", "False", 1, 0, None, [True]]:
        raw = {
            "State": "PROPERTY_PRESENT_WITH_VALID_VALUE",
            "Exists": bad_exists,
            "IsNull": False,
            "Value": "Any",
            "StringValue": "Any",
            "Type": "String",
        }
        rec = CimFieldRecord.from_raw(raw)
        assert rec.state == CimFieldState.MALFORMED
        assert "Non-boolean Exists" in (rec.string_value or "")


def test_cim_record_rejects_non_boolean_is_null():
    """Non-boolean IsNull values are rejected as malformed without coercion."""
    for bad_null in ["True", "False", 1, 0, None, [False]]:
        raw = {
            "State": "PROPERTY_PRESENT_WITH_VALID_VALUE",
            "Exists": True,
            "IsNull": bad_null,
            "Value": "Any",
            "StringValue": "Any",
            "Type": "String",
        }
        rec = CimFieldRecord.from_raw(raw)
        assert rec.state == CimFieldState.MALFORMED
        assert "Non-boolean IsNull" in (rec.string_value or "")


def test_cim_record_rejects_contradictory_combinations():
    """Contradictory field state combinations are strictly rejected as malformed."""
    contradictory_cases = [
        # VALID but exists is False
        {"State": "PROPERTY_PRESENT_WITH_VALID_VALUE", "Exists": False, "IsNull": False, "Value": "Any"},
        # VALID but is_null is True
        {"State": "PROPERTY_PRESENT_WITH_VALID_VALUE", "Exists": True, "IsNull": True, "Value": "Any"},
        # VALID but value is None
        {"State": "PROPERTY_PRESENT_WITH_VALID_VALUE", "Exists": True, "IsNull": False, "Value": None},
        # NULL but is_null is False
        {"State": "PROPERTY_PRESENT_WITH_NULL", "Exists": True, "IsNull": False, "Value": None},
        # NULL but value is not None
        {"State": "PROPERTY_PRESENT_WITH_NULL", "Exists": True, "IsNull": True, "Value": "not_null"},
        # NULL but string_value is non-empty
        {"State": "PROPERTY_PRESENT_WITH_NULL", "Exists": True, "IsNull": True, "Value": None, "StringValue": "unexpected"},
        # MISSING but exists is True
        {"State": "PROPERTY_MISSING", "Exists": True, "IsNull": True, "Value": None},
        # MISSING but value is not None
        {"State": "PROPERTY_MISSING", "Exists": False, "IsNull": True, "Value": "not_null"},
    ]
    for case in contradictory_cases:
        rec = CimFieldRecord.from_raw(case)
        assert rec.state == CimFieldState.MALFORMED
        assert "Contradictory" in (rec.string_value or "")


def test_cim_record_exact_type_preservation():
    """Exact CIM types (Boolean, String, UInt16, UInt32, Array, etc.) are preserved in type_name."""
    types_to_test = ["Boolean", "String", "UInt16", "UInt32", "Integer", "Array", "StringArray"]
    for t in types_to_test:
        raw = {
            "State": "PROPERTY_PRESENT_WITH_VALID_VALUE",
            "Exists": True,
            "IsNull": False,
            "Value": "Any",
            "StringValue": "Any",
            "Type": t,
        }
        rec = CimFieldRecord.from_raw(raw)
        assert rec.state == CimFieldState.VALID
        assert rec.type_name == t


def test_cim_record_roundtrip_serialization_powershell():
    """When PowerShell is available, verify Get-CimFieldRecord roundtrips genuine booleans, numbers, strings, and nulls."""
    real_ps = _REAL_SHUTIL_WHICH("powershell") or _REAL_SHUTIL_WHICH("powershell.exe")
    if not real_ps or not Path(real_ps).exists():
        pytest.skip("PowerShell is not available on host system")

    test_script = PS_CIM_SERIALIZER_SNIPPET + """
$testObj = [PSCustomObject]@{
    TestBool = $true
    TestInt = 42
    TestStr = "LoopbackOnly"
    TestNull = $null
}

$results = [PSCustomObject]@{
    BoolRec = Get-CimFieldRecord $testObj "TestBool"
    IntRec = Get-CimFieldRecord $testObj "TestInt"
    StrRec = Get-CimFieldRecord $testObj "TestStr"
    NullRec = Get-CimFieldRecord $testObj "TestNull"
    MissingRec = Get-CimFieldRecord $testObj "NonExistentProp"
}

$results | ConvertTo-Json -Depth 3
"""
    res = subprocess.run(
        [real_ps, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", test_script],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert res.returncode == 0
    data = json.loads(res.stdout.strip())

    rec_bool = CimFieldRecord.from_raw(data["BoolRec"])
    assert rec_bool.state == CimFieldState.VALID
    assert rec_bool.value is True
    assert type(rec_bool.value) is bool

    rec_int = CimFieldRecord.from_raw(data["IntRec"])
    assert rec_int.state == CimFieldState.VALID
    assert rec_int.value == 42
    assert isinstance(rec_int.value, int)

    rec_str = CimFieldRecord.from_raw(data["StrRec"])
    assert rec_str.state == CimFieldState.VALID
    assert rec_str.value == "LoopbackOnly"

    rec_null = CimFieldRecord.from_raw(data["NullRec"])
    assert rec_null.state == CimFieldState.NULL
    assert rec_null.value is None

    rec_miss = CimFieldRecord.from_raw(data["MissingRec"])
    assert rec_miss.state == CimFieldState.MISSING
    assert rec_miss.exists is False



