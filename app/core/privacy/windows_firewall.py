"""
Tsukiko Windows Firewall Policy Manager
Provides safe, application-specific OS-level outbound firewall rule management and status inspection.
Enforces strict structural PE validation, fail-closed profile verification, precise rule ownership,
safe deletion, and effective policy inspection in the ActiveStore.

Note on Executable Identity:
Structural PE binary validation confirms that the file is formatted as a valid Windows PE binary.
It is NOT cryptographic proof of application identity (e.g. Authenticode certificate verification).
Real cryptographic verification requires an established code-signing certificate infrastructure.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
from typing import Any, Optional, Tuple
from pydantic import BaseModel, Field

from app.core.logging.logger import get_logger

logger = get_logger("SYSTEM")

DEFAULT_RULE_NAME = "Tsukiko Outbound Privacy Boundary"
LEGACY_RULE_NAME = "Tsukiko Outbound Block"
STABLE_RULE_ID = "Tsukiko_Privacy_Outbound_Block"
EXPECTED_EXECUTABLE_NAME = "tsukiko.exe"
RULE_GROUPING = "Tsukiko Desktop Companion"
RULE_OWNERSHIP_MARKER = "[Tsukiko-Privacy-Core:Outbound-Block]"
DEFAULT_DESCRIPTION = f"{RULE_OWNERSHIP_MARKER} Offline boundary: blocks outbound network traffic for dedicated executable"

# Interpreters, shells, and system binaries that must NEVER be targeted by firewall rules
DISALLOWED_EXECUTABLE_NAMES = frozenset({
    "python.exe",
    "pythonw.exe",
    "py.exe",
    "pytest.exe",
    "ipython.exe",
    "pip.exe",
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "bash.exe",
    "conhost.exe",
    "explorer.exe",
    "services.exe",
    "svchost.exe",
    "rundll32.exe",
    "python3.exe",
    "python310.exe",
    "python311.exe",
    "python312.exe",
    "python313.exe",
})


class SecurityStatus(BaseModel):
    status: str = Field(
        description="One of: 'in_process_only', 'os_policy_not_configured', 'os_policy_unverified', 'os_policy_active'"
    )
    is_dedicated_binary: bool
    executable_path: str
    rule_name: str
    rule_exists: bool
    defense_level: str
    details: str


class FirewallRuleInfo(BaseModel):
    name: str = ""
    display_name: str = ""
    group: str = ""
    description: str = ""
    enabled: bool = False
    direction: str = ""
    action: str = ""
    profiles: str = ""
    program: str = ""


def is_admin() -> bool:
    """Checks whether the current process possesses elevated Windows administrative privileges."""
    if platform.system() != "Windows":
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def validate_pe_structure(file_path: Path) -> Tuple[bool, str]:
    """Validates the internal binary structure of a Windows Portable Executable (PE) file.

    Enforces:
    1. File size is at least 64 bytes (minimum DOS header size).
    2. File starts with the MS-DOS magic bytes b'MZ' (0x4D, 0x5A).
    3. Reads the 4-byte little-endian PE header offset at 0x3C (e_lfanew).
    4. Validates that the PE offset is in-bounds and does not overlap the DOS header:
       0x40 <= pe_offset <= file_size - 4.
    5. Reads the 4-byte signature at pe_offset and confirms it equals b'PE\\0\\0' (0x50, 0x45, 0x00, 0x00).

    Limitation:
    Structural PE validation confirms the file is formatted as a valid Windows PE binary, but does
    NOT prove application identity or prevent executable substitution. Cryptographic Authenticode
    verification requires an established digital signing infrastructure.
    """
    try:
        if not file_path.exists():
            return False, f"File does not exist: {file_path}"
        if not file_path.is_file():
            return False, f"Target path is not a regular file: {file_path}"

        file_size = file_path.stat().st_size
        if file_size < 64:
            return False, f"File size ({file_size} bytes) is too small to contain a valid DOS header (minimum 64 bytes)."

        with open(file_path, "rb") as f:
            dos_header = f.read(64)
            if len(dos_header) < 64:
                return False, "Truncated DOS header: unable to read 64 bytes."

            if dos_header[:2] != b"MZ":
                return False, f"Missing DOS executable signature (got {dos_header[:2]!r}, expected b'MZ')."

            # Read 32-bit unsigned little-endian integer at offset 0x3C
            pe_offset = int.from_bytes(dos_header[0x3C:0x40], byteorder="little", signed=False)

            if pe_offset < 0x40:
                return False, f"Invalid PE header offset: 0x{pe_offset:X} (< 0x40 overlaps DOS header)."

            if pe_offset + 4 > file_size:
                return False, f"PE header offset 0x{pe_offset:X} is outside file boundaries ({file_size} bytes)."

            f.seek(pe_offset)
            pe_sig = f.read(4)
            if len(pe_sig) < 4:
                return False, f"Truncated PE signature at offset 0x{pe_offset:X}."

            if pe_sig != b"PE\x00\x00":
                return False, f"Invalid PE signature at offset 0x{pe_offset:X}: got {pe_sig!r}, expected b'PE\\0\\0'."

        return True, "Valid Windows PE executable binary structure confirmed."
    except Exception as e:
        return False, f"Could not inspect target file binary structure: {e}"


def is_safe_target_executable(path: Path | str) -> Tuple[bool, str]:
    """Strictly validates whether the target file is the dedicated Tsukiko deployment binary.

    Enforces:
    - Path must exist and be a regular file on disk.
    - File extension must be '.exe'.
    - Filename must match dedicated deployment binary ('tsukiko.exe').
    - Target must contain valid structural Windows PE executable headers (MZ + e_lfanew + PE\\0\\0).
    - Path must not target shared Python interpreters or shell binaries.
    - Path must not contain control characters or command-injection sequences.

    Limitation: Structural PE validation confirms valid binary format, not cryptographic code signature.
    """
    if path is None:
        return False, "Executable path cannot be None."

    path_str = str(path).strip()
    if not path_str:
        return False, "Executable path cannot be empty."

    # Prevent command/path injection characters
    if any(c in path_str for c in "\r\n\t;\"'|&><`"):
        return False, "Executable path contains invalid or dangerous control characters."

    target = Path(path_str)
    try:
        resolved = target.resolve()
    except Exception as e:
        return False, f"Could not resolve absolute path: {e}"

    if not resolved.exists():
        return False, f"Executable file does not exist: {resolved}"

    if not resolved.is_file():
        return False, f"Target path is not a regular file: {resolved}"

    file_name = resolved.name.lower()

    if resolved.suffix.lower() != ".exe":
        return False, f"Target file must have a .exe extension, got '{resolved.suffix}'."

    if file_name in DISALLOWED_EXECUTABLE_NAMES:
        return (
            False,
            f"Target executable '{file_name}' is a shared Python interpreter or development tool. "
            "Refusing to create a system-wide OS firewall rule against shared development tooling."
        )

    # Strictly require dedicated deployment binary name
    if file_name != EXPECTED_EXECUTABLE_NAME:
        return (
            False,
            f"Target executable '{file_name}' is not the dedicated deployment binary ('{EXPECTED_EXECUTABLE_NAME}'). "
            "Arbitrary executables are strictly rejected."
        )

    # Structural Windows PE format validation
    pe_valid, pe_reason = validate_pe_structure(resolved)
    if not pe_valid:
        return False, pe_reason

    return True, f"Verified dedicated deployment binary: {resolved}"


def validate_firewall_profiles(raw_profiles: Optional[str]) -> Tuple[bool, str]:
    """Validates that a rule's profile specification covers all network profiles.

    Accepts only:
    - 'Any'
    - 'Domain, Private, Public' (all three, comma-separated in any order)

    Rejects:
    - Missing or None profile string
    - Empty or whitespace profile string
    - Partial profile coverage (Domain-only, Private-only, Public-only, etc.)
    - Unknown or malformed profile names
    """
    if raw_profiles is None:
        return False, "Rule profile information is missing."

    clean = raw_profiles.strip()
    if not clean:
        return False, "Rule profile information is empty."

    tokens = {p.strip().lower() for p in clean.split(",") if p.strip()}
    if not tokens:
        return False, "Rule profile information contains no valid profile names."

    if tokens == {"any"}:
        return True, "Profiles verified: Any (applies to all network locations)."

    allowed_profiles = {"domain", "private", "public"}
    unknown = tokens - allowed_profiles
    if unknown:
        return False, f"Rule specifies unknown profile values: {sorted(unknown)}."

    missing = allowed_profiles - tokens
    if missing:
        return (
            False,
            f"Rule profiles incomplete: applies only to '{clean}', "
            f"missing required profiles: {sorted(missing)}."
        )

    return True, "Profiles verified: Domain, Private, Public (all profiles covered)."


def is_tsukiko_owned_rule(
    rule: FirewallRuleInfo,
    expected_exe: Optional[Path | str] = None,
) -> Tuple[bool, str]:
    """Validates whether a candidate firewall rule genuinely belongs to Tsukiko.

    Verifies:
    1. Display Name matches 'Tsukiko Outbound Privacy Boundary' OR internal Name matches 'Tsukiko_Privacy_Outbound_Block'.
    2. Group / DisplayGroup matches 'Tsukiko Desktop Companion'.
    3. Description contains the ownership marker '[Tsukiko-Privacy-Core:Outbound-Block]'.
    4. Program (if provided) matches the normalized expected executable path.
    """
    name_matches = (
        rule.display_name.strip().lower() == DEFAULT_RULE_NAME.lower()
        or rule.name.strip().lower() == STABLE_RULE_ID.lower()
        or rule.display_name.strip().lower() == LEGACY_RULE_NAME.lower()
    )
    if not name_matches:
        return False, f"Rule name '{rule.display_name}' does not match Tsukiko rule identity."

    if rule.group.strip().lower() != RULE_GROUPING.lower():
        return (
            False,
            f"Rule grouping mismatch: got '{rule.group}', expected '{RULE_GROUPING}'."
        )

    if RULE_OWNERSHIP_MARKER.lower() not in rule.description.lower():
        return (
            False,
            f"Rule description lacks required Tsukiko ownership marker '{RULE_OWNERSHIP_MARKER}'."
        )

    if expected_exe is not None:
        try:
            expected_norm = Path(expected_exe).resolve()
            actual_norm = Path(rule.program).resolve() if rule.program else None
            if actual_norm != expected_norm:
                return (
                    False,
                    f"Rule program mismatch: targets '{actual_norm}', expected '{expected_norm}'."
                )
        except Exception as e:
            return False, f"Could not compare executable paths: {e}"

    return True, "Rule ownership verified as Tsukiko Desktop Companion."


def parse_netsh_rule_blocks(output: str) -> list[FirewallRuleInfo]:
    """Parses netsh advfirewall show rule text output into FirewallRuleInfo objects."""
    rules: list[FirewallRuleInfo] = []
    blocks = re.split(r"(?=^\s*Rule Name:\s*)", output, flags=re.MULTILINE)
    for block in blocks:
        block = block.strip()
        if not block or "Rule Name:" not in block:
            continue
        name_m = re.search(r"^[^\S\r\n]*Rule Name:[^\S\r\n]*(.*)$", block, re.IGNORECASE | re.MULTILINE)
        enabled_m = re.search(r"^[^\S\r\n]*Enabled:[^\S\r\n]*(Yes|True|No|False)\b", block, re.IGNORECASE | re.MULTILINE)
        direction_m = re.search(r"^[^\S\r\n]*Direction:[^\S\r\n]*(\S+)", block, re.IGNORECASE | re.MULTILINE)
        profiles_m = re.search(r"^[^\S\r\n]*Profiles:[^\S\r\n]*(.*)$", block, re.IGNORECASE | re.MULTILINE)
        group_m = re.search(r"^[^\S\r\n]*Grouping:[^\S\r\n]*(.*)$", block, re.IGNORECASE | re.MULTILINE)
        action_m = re.search(r"^[^\S\r\n]*Action:[^\S\r\n]*(\S+)", block, re.IGNORECASE | re.MULTILINE)
        prog_m = re.search(r"^[^\S\r\n]*Program:[^\S\r\n]*(.*)$", block, re.IGNORECASE | re.MULTILINE)
        desc_m = re.search(r"^[^\S\r\n]*Description:[^\S\r\n]*(.*)$", block, re.IGNORECASE | re.MULTILINE)

        if name_m:
            display_name = name_m.group(1).strip()
            enabled = enabled_m.group(1).lower() in ("yes", "true") if enabled_m else False
            direction = direction_m.group(1).strip() if direction_m else ""
            profiles = profiles_m.group(1).strip() if profiles_m else ""
            group = group_m.group(1).strip() if group_m else ""
            action = action_m.group(1).strip() if action_m else ""
            program = prog_m.group(1).strip() if prog_m else ""
            description = desc_m.group(1).strip() if desc_m else ""

            rules.append(FirewallRuleInfo(
                name=display_name,
                display_name=display_name,
                group=group,
                description=description,
                enabled=enabled,
                direction=direction,
                action=action,
                profiles=profiles,
                program=program,
            ))
    return rules


def parse_powershell_rules_json(data: Any) -> list[FirewallRuleInfo]:
    """Parses JSON rule objects from PowerShell into FirewallRuleInfo list."""
    if not data:
        return []
    if isinstance(data, dict):
        raw_list = [data]
    elif isinstance(data, list):
        raw_list = data
    else:
        return []

    rules: list[FirewallRuleInfo] = []
    for r in raw_list:
        if not isinstance(r, dict):
            continue
        enabled_val = r.get("Enabled")
        enabled = bool(enabled_val) if not isinstance(enabled_val, (int, str)) else str(enabled_val).lower() in ("1", "true")
        rules.append(FirewallRuleInfo(
            name=str(r.get("Name", "")).strip(),
            display_name=str(r.get("DisplayName", "")).strip(),
            group=str(r.get("Group", "")).strip(),
            description=str(r.get("Description", "")).strip(),
            enabled=enabled,
            direction=str(r.get("Direction", "")).strip(),
            action=str(r.get("Action", "")).strip(),
            profiles=str(r.get("Profiles", "")).strip(),
            program=str(r.get("Program", "")).strip(),
        ))
    return rules


def query_matching_firewall_rules(
    rule_name: str = DEFAULT_RULE_NAME,
) -> list[FirewallRuleInfo]:
    """Queries and returns all candidate firewall rules matching rule_name or Tsukiko identity."""
    if platform.system() != "Windows":
        return []

    # 1. Try querying via netsh advfirewall (fast, standard)
    netsh_path = shutil.which("netsh")
    if netsh_path:
        try:
            res = subprocess.run(
                [netsh_path, "advfirewall", "firewall", "show", "rule", f"name={rule_name}", "verbose"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if res.returncode == 0 and "No rules match" not in res.stdout:
                rules = parse_netsh_rule_blocks(res.stdout)
                if rules:
                    return rules
        except Exception:
            pass

    # 2. Fall back to querying via PowerShell NetSecurity
    ps_path = shutil.which("powershell") or shutil.which("powershell.exe")
    if ps_path:
        ps_script = """
$targetRuleName = $env:TSUKIKO_TARGET_RULE_NAME
$targetGroup = $env:TSUKIKO_TARGET_GROUP
$ErrorActionPreference = 'Stop'
try {
    $rules = @(Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq $targetRuleName -or $_.Name -eq $targetRuleName -or $_.DisplayGroup -eq $targetGroup } | ForEach-Object {
        $app = $_ | Get-NetFirewallApplicationFilter
        [PSCustomObject]@{
            Name = $_.Name
            DisplayName = $_.DisplayName
            Group = $_.DisplayGroup
            Description = $_.Description
            Enabled = [bool]$_.Enabled
            Direction = [string]$_.Direction
            Action = [string]$_.Action
            Profiles = [string]($_.Profile -join ',')
            Program = [string]$app.Program
        }
    })
    $rules | ConvertTo-Json -Depth 3
} catch {
    Write-Error $_.Exception.Message
    exit 1
}
"""
        env = os.environ.copy()
        env["TSUKIKO_TARGET_RULE_NAME"] = rule_name
        env["TSUKIKO_TARGET_GROUP"] = RULE_GROUPING
        try:
            res = subprocess.run(
                [ps_path, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
                capture_output=True,
                text=True,
                timeout=5,
                env=env,
            )
            if res.returncode == 0 and res.stdout.strip():
                try:
                    data = json.loads(res.stdout.strip())
                    return parse_powershell_rules_json(data)
                except Exception:
                    pass
        except Exception:
            pass

    return []


def verify_effective_firewall_policy(
    executable_path: Path | str,
    rule_name: str = DEFAULT_RULE_NAME,
) -> Tuple[bool, str]:
    """Verifies that the outbound block policy is genuinely effective in the Windows Firewall ActiveStore.

    Validates:
    1. PowerShell is available and executable.
    2. ActiveStore firewall profiles (Domain, Private, Public) are all Enabled.
    3. ActiveStore profile policy permits local firewall rules (AllowLocalFirewallRules is True).
    4. An active rule matching Tsukiko ownership exists in ActiveStore:
       - DisplayName == 'Tsukiko Outbound Privacy Boundary' OR Name == 'Tsukiko_Privacy_Outbound_Block'
       - Group == 'Tsukiko Desktop Companion'
       - Description contains '[Tsukiko-Privacy-Core:Outbound-Block]'
       - Direction is Outbound
       - Action is Block
       - Enabled is True
       - Program matches normalized executable_path
       - Profiles covers all network profiles (Domain,Private,Public or Any)
    """
    if platform.system() != "Windows":
        return False, "Windows Firewall effective policy verification is only available on Windows."

    ps_path = shutil.which("powershell") or shutil.which("powershell.exe")
    if not ps_path:
        return False, "PowerShell is not available on PATH to query Windows Firewall ActiveStore."

    try:
        resolved_exe = Path(executable_path).resolve()
    except Exception as e:
        return False, f"Invalid target executable path: {e}"

    ps_script = """
$targetRuleName = $env:TSUKIKO_TARGET_RULE_NAME
$targetGroup = $env:TSUKIKO_TARGET_GROUP
$ErrorActionPreference = 'Stop'
try {
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name, Enabled, AllowLocalFirewallRules)
    $rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq $targetRuleName -or $_.Name -eq $targetRuleName -or $_.DisplayGroup -eq $targetGroup } | ForEach-Object {
        $app = $_ | Get-NetFirewallApplicationFilter
        [PSCustomObject]@{
            Name = $_.Name
            DisplayName = $_.DisplayName
            Group = $_.DisplayGroup
            Description = $_.Description
            Enabled = [bool]$_.Enabled
            Direction = [string]$_.Direction
            Action = [string]$_.Action
            Profiles = [string]($_.Profile -join ',')
            Program = [string]$app.Program
        }
    })
    [PSCustomObject]@{
        Profiles = $profiles
        Rules = $rules
    } | ConvertTo-Json -Depth 4
} catch {
    Write-Error $_.Exception.Message
    exit 1
}
"""
    env = os.environ.copy()
    env["TSUKIKO_TARGET_RULE_NAME"] = rule_name
    env["TSUKIKO_TARGET_GROUP"] = RULE_GROUPING

    try:
        res = subprocess.run(
            [ps_path, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
            capture_output=True,
            text=True,
            timeout=10,
            env=env,
        )
        if res.returncode != 0:
            err = res.stderr.strip() or res.stdout.strip()
            return False, f"PowerShell ActiveStore inspection failed (exit code {res.returncode}): {err}"

        output = res.stdout.strip()
        if not output:
            return False, "PowerShell ActiveStore query returned empty output."

        try:
            data = json.loads(output)
        except json.JSONDecodeError as e:
            return False, f"Malformed PowerShell output: unable to parse JSON: {e}"

        # 1. Verify Profiles in ActiveStore
        profiles_raw = data.get("Profiles", [])
        if isinstance(profiles_raw, dict):
            profiles_raw = [profiles_raw]
        if not profiles_raw:
            return False, "No profile information returned from ActiveStore query."

        seen_profiles = set()
        for p in profiles_raw:
            p_name = str(p.get("Name", "")).strip().lower()
            seen_profiles.add(p_name)

            p_enabled = p.get("Enabled")
            is_enabled = bool(p_enabled) if not isinstance(p_enabled, (int, str)) else str(p_enabled).lower() in ("1", "true")
            if not is_enabled:
                return False, f"Windows Firewall profile '{p.get('Name')}' is disabled in ActiveStore. Outbound blocking cannot be effective."

            p_allow_local = p.get("AllowLocalFirewallRules")
            allows_local = bool(p_allow_local) if not isinstance(p_allow_local, (int, str)) else str(p_allow_local).lower() in ("1", "true")
            if not allows_local:
                return False, f"Windows Firewall profile '{p.get('Name')}' restricts local firewall rules (AllowLocalFirewallRules is False). Local outbound blocking policy is overridden."

        req_profiles = {"domain", "private", "public"}
        missing_profiles = req_profiles - seen_profiles
        if missing_profiles:
            return False, f"ActiveStore profile information missing required profiles: {sorted(missing_profiles)}."

        # 2. Verify Rules in ActiveStore
        rules_raw = data.get("Rules", [])
        rules = parse_powershell_rules_json(rules_raw)
        if not rules:
            return False, f"Rule '{rule_name}' does not exist in ActiveStore effective policy."

        matching_rule = None
        for r in rules:
            is_owned, own_reason = is_tsukiko_owned_rule(r, expected_exe=resolved_exe)
            if not is_owned:
                continue

            if not r.enabled:
                return False, "Effective rule exists in ActiveStore but is disabled (Enabled: False)."

            if r.direction.lower() not in ("outbound", "out", "2"):
                return False, f"Effective rule direction mismatch: got '{r.direction}', expected Outbound."

            if r.action.lower() not in ("block", "2"):
                return False, f"Effective rule action mismatch: got '{r.action}', expected Block."

            prof_ok, prof_msg = validate_firewall_profiles(r.profiles)
            if not prof_ok:
                return False, f"Effective rule profile validation failed: {prof_msg}"

            matching_rule = r
            break

        if not matching_rule:
            return False, f"No rule in ActiveStore matched Tsukiko ownership and target executable '{resolved_exe}'."

        return True, "Effective Windows Firewall policy verified in ActiveStore: Outbound Block active on all profiles."
    except subprocess.TimeoutExpired:
        return False, "PowerShell query timed out while inspecting ActiveStore policy view."
    except Exception as e:
        return False, f"Effective policy verification failed due to system error: {e}"


def verify_firewall_rule(
    executable_path: Path | str,
    rule_name: str = DEFAULT_RULE_NAME,
) -> Tuple[bool, str]:
    """Verifies that an existing persistent Windows Firewall rule protects the specified executable.

    Validates:
    1. Rule exists and query succeeds.
    2. Rule ownership: Grouping matches 'Tsukiko Desktop Companion' and Description contains '[Tsukiko-Privacy-Core:Outbound-Block]'.
    3. Rule is Enabled (Yes).
    4. Direction is Outbound (Out).
    5. Action is Block.
    6. Program exactly matches normalized executable path.
    7. Profiles explicitly covers all network profiles (Domain,Private,Public or Any).
    """
    if platform.system() != "Windows":
        return False, "Windows Firewall verification is only available on Windows."

    netsh_path = shutil.which("netsh")
    if not netsh_path:
        return False, "netsh utility not found on system PATH."

    try:
        resolved_exe = Path(executable_path).resolve()
    except Exception:
        return False, "Invalid executable path provided for verification."

    try:
        res = subprocess.run(
            [netsh_path, "advfirewall", "firewall", "show", "rule", f"name={rule_name}", "verbose"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if res.returncode != 0 or "No rules match" in res.stdout:
            return False, f"Rule '{rule_name}' does not exist in Windows Firewall."

        output = res.stdout

        # 1. Rule ownership verification
        grouping_match = re.search(r"^\s*Grouping:\s*(.+)$", output, re.IGNORECASE | re.MULTILINE)
        description_match = re.search(r"^\s*Description:\s*(.+)$", output, re.IGNORECASE | re.MULTILINE)

        has_group = bool(grouping_match and RULE_GROUPING.lower() in grouping_match.group(1).lower())
        has_marker = bool(description_match and RULE_OWNERSHIP_MARKER.lower() in description_match.group(1).lower())

        if not (has_group and has_marker):
            return (
                False,
                f"Rule '{rule_name}' exists but lacks verified Tsukiko ownership markers "
                f"(Grouping '{RULE_GROUPING}' and marker '{RULE_OWNERSHIP_MARKER}'). "
                "Foreign or unrelated rules with the Tsukiko name prefix are rejected."
            )

        # 2. Enabled
        enabled_match = re.search(r"^\s*Enabled:\s*(Yes|True)\b", output, re.IGNORECASE | re.MULTILINE)
        if not enabled_match:
            return False, "Rule exists but is not Enabled."

        # 3. Direction Out
        direction_match = re.search(r"^\s*Direction:\s*(Out)\b", output, re.IGNORECASE | re.MULTILINE)
        if not direction_match:
            return False, "Rule exists but Direction is not Outbound."

        # 4. Action Block
        action_match = re.search(r"^\s*Action:\s*(Block)\b", output, re.IGNORECASE | re.MULTILINE)
        if not action_match:
            return False, "Rule exists but Action is not Block."

        # 5. Program matches exact normalized executable path
        program_match = re.search(r"^\s*Program:\s*(.+)$", output, re.IGNORECASE | re.MULTILINE)
        if not program_match:
            return False, "Rule exists but specifies no Program filter."

        rule_program = program_match.group(1).strip()
        try:
            resolved_rule_program = Path(rule_program).resolve()
        except Exception:
            resolved_rule_program = Path(rule_program)

        if resolved_rule_program != resolved_exe:
            return (
                False,
                f"Rule program mismatch: rule targets '{resolved_rule_program}', expected '{resolved_exe}'."
            )

        # 6. Fail-closed Profiles verification
        profiles_match = re.search(r"^[^\S\r\n]*Profiles:[^\S\r\n]*(.*)$", output, re.IGNORECASE | re.MULTILINE)
        raw_profiles = profiles_match.group(1).strip() if profiles_match else None
        prof_ok, prof_msg = validate_firewall_profiles(raw_profiles)
        if not prof_ok:
            return False, prof_msg

        return True, "Firewall rule verified: Active, Outbound, Block, matching target executable, Tsukiko owned."
    except subprocess.TimeoutExpired:
        return False, "Query timed out while inspecting Windows Firewall rules."
    except Exception as e:
        return False, f"Verification failed due to system query error: {e}"


def get_security_status(
    executable_path: Optional[Path | str] = None,
    rule_name: str = DEFAULT_RULE_NAME,
) -> SecurityStatus:
    """Returns an honest security status report distinguishing in-process defense from OS firewall boundaries.

    Reports:
    - 'in_process_only': Running under shared Python or unverified non-dedicated binary.
    - 'os_policy_not_configured': Dedicated binary present, but no firewall rule configured.
    - 'os_policy_unverified': Rule present, but effective policy in ActiveStore could not be verified.
    - 'os_policy_active': Dedicated binary with confirmed matching Outbound Block rule verified in ActiveStore.
    """
    target = Path(executable_path or sys.executable)

    if platform.system() != "Windows":
        return SecurityStatus(
            status="in_process_only",
            is_dedicated_binary=False,
            executable_path=str(target),
            rule_name=rule_name,
            rule_exists=False,
            defense_level="in_process_socket_interception",
            details="Windows Firewall policy inspection is only supported on Windows.",
        )

    is_safe, reason = is_safe_target_executable(target)

    if not is_safe:
        return SecurityStatus(
            status="in_process_only",
            is_dedicated_binary=False,
            executable_path=str(target),
            rule_name=rule_name,
            rule_exists=False,
            defense_level="in_process_socket_interception",
            details=(
                "Tsukiko is running in a development Python environment. Technical in-process socket and "
                "DNS interception hooks are active, providing defense-in-depth against outbound requests. "
                "OS-level firewall rules are deliberately not applied to shared python.exe to preserve system-wide tooling."
            ),
        )

    resolved_target = target.resolve()

    # 1. First, check effective policy in ActiveStore
    effective_verified, effective_reason = verify_effective_firewall_policy(resolved_target, rule_name)
    if effective_verified:
        return SecurityStatus(
            status="os_policy_active",
            is_dedicated_binary=True,
            executable_path=str(resolved_target),
            rule_name=rule_name,
            rule_exists=True,
            defense_level="os_kernel_firewall_and_socket_interception",
            details=(
                "Tsukiko is running as a dedicated application executable with an active Windows Firewall "
                "outbound blocking rule verified in the ActiveStore effective policy."
            ),
        )

    # 2. Check if persistent rule exists locally
    local_verified, local_reason = verify_firewall_rule(resolved_target, rule_name)
    candidates = query_matching_firewall_rules(rule_name)

    if candidates or local_verified:
        return SecurityStatus(
            status="os_policy_unverified",
            is_dedicated_binary=True,
            executable_path=str(resolved_target),
            rule_name=rule_name,
            rule_exists=True,
            defense_level="in_process_socket_interception",
            details=(
                f"A Windows Firewall rule named '{rule_name}' exists in the configuration, but its effective "
                f"status in ActiveStore could not be established ({effective_reason})."
            ),
        )
    else:
        return SecurityStatus(
            status="os_policy_not_configured",
            is_dedicated_binary=True,
            executable_path=str(resolved_target),
            rule_name=rule_name,
            rule_exists=False,
            defense_level="in_process_socket_interception",
            details=(
                "Tsukiko is running as a dedicated executable, but no Windows Firewall outbound rule was detected. "
                "In-process socket interception is active. To enable OS-level kernel blocking, run rule creation with user authorization."
            ),
        )


def create_firewall_rule(
    executable_path: Optional[Path | str] = None,
    rule_name: str = DEFAULT_RULE_NAME,
    user_authorized: bool = False,
) -> Tuple[bool, str]:
    """Creates a Windows Firewall outbound blocking rule for the dedicated executable.

    Requires explicit user authorization and administrator elevation.
    Never modifies firewall rules automatically without authorization.
    Refuses to overwrite or adopt foreign rules that share the display name.
    """
    if not user_authorized:
        return False, "Explicit user authorization is required before modifying Windows Firewall rules."

    target = Path(executable_path or sys.executable)

    if platform.system() != "Windows":
        return SecurityStatus(
            status="in_process_only",
            is_dedicated_binary=False,
            executable_path=str(target),
            rule_name=rule_name,
            rule_exists=False,
            defense_level="in_process_socket_interception",
            details="Windows Firewall policy inspection is only supported on Windows.",
        )

    is_safe, reason = is_safe_target_executable(target)
    if not is_safe:
        return False, reason

    if platform.system() != "Windows":
        return False, "Windows Firewall configuration is only supported on Windows."

    if not is_admin():
        return False, "Administrator elevation required. Please run from an elevated administrator prompt."

    resolved_target = target.resolve()

    # Pre-creation check: verify no conflicting foreign rule exists with the same name
    existing_candidates = query_matching_firewall_rules(rule_name)
    for c in existing_candidates:
        is_owned, _ = is_tsukiko_owned_rule(c)
        if not is_owned:
            return (
                False,
                f"Refusing to create firewall rule: a foreign rule named '{rule_name}' already exists "
                "and does not belong to Tsukiko. Will not overwrite or adopt foreign rules."
            )

    netsh_path = shutil.which("netsh")
    if not netsh_path:
        return False, "netsh utility not found on PATH."

    try:
        cmd_args = [
            netsh_path, "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=out",
            "action=block",
            f"program={resolved_target}",
            "enable=yes",
            "profile=any",
            f"group={RULE_GROUPING}",
            f"description={DEFAULT_DESCRIPTION}",
        ]
        res = subprocess.run(cmd_args, capture_output=True, text=True, timeout=10)
        if res.returncode == 0:
            verified, v_reason = verify_firewall_rule(resolved_target, rule_name)
            if verified:
                logger.info(f"Windows Firewall rule '{rule_name}' successfully created and verified for {resolved_target}.")
                return True, f"Windows Firewall rule '{rule_name}' created and verified."
            else:
                return False, f"Rule created but verification failed: {v_reason}"
        else:
            return False, f"Failed to create firewall rule: {res.stderr or res.stdout}"
    except Exception as e:
        return False, f"Execution failed: {e}"


def remove_firewall_rule(
    rule_name: str = DEFAULT_RULE_NAME,
    user_authorized: bool = False,
) -> Tuple[bool, str]:
    """Removes a previously configured Tsukiko Windows Firewall rule.

    Requires explicit user authorization and verifies that the rule is genuinely Tsukiko-owned before deleting.
    Refuses to delete arbitrary or foreign rules.
    If multiple rules match ownership ambiguously, refuses deletion to prevent unintended impact.
    """
    if not user_authorized:
        return False, "Explicit user authorization is required before modifying Windows Firewall rules."

    if not rule_name.startswith("Tsukiko"):
        return False, f"Refusing to remove non-Tsukiko firewall rule '{rule_name}'."

    if platform.system() != "Windows":
        return False, "Windows Firewall management is only supported on Windows."

    if not is_admin():
        return False, "Administrator elevation required. Please run from an elevated administrator prompt."

    # Enumerate all matching candidates
    candidates = query_matching_firewall_rules(rule_name)
    if not candidates:
        return False, f"Rule '{rule_name}' does not exist in Windows Firewall."

    # Inspect ownership of each candidate
    owned_candidates = [c for c in candidates if is_tsukiko_owned_rule(c)[0]]

    if len(owned_candidates) == 0:
        return (
            False,
            f"Refusing to delete rule '{rule_name}': rule exists but is not verified as a Tsukiko-owned rule "
            f"(lacks required grouping '{RULE_GROUPING}' and marker '{RULE_OWNERSHIP_MARKER}'). "
            "Foreign rules will not be deleted."
        )

    if len(owned_candidates) > 1:
        return (
            False,
            f"Ambiguous rule identity: found {len(owned_candidates)} matching rules that claim Tsukiko ownership. "
            "Manual operator intervention required to resolve ambiguity without deleting unintended rules."
        )

    target_rule = owned_candidates[0]

    netsh_path = shutil.which("netsh")
    if not netsh_path:
        return False, "netsh utility not found on PATH."

    try:
        res = subprocess.run(
            [netsh_path, "advfirewall", "firewall", "delete", "rule", f"name={target_rule.display_name}"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if res.returncode == 0:
            logger.info(f"Windows Firewall rule '{target_rule.display_name}' removed.")
            return True, f"Windows Firewall rule '{target_rule.display_name}' removed."
        else:
            return False, f"Failed to remove rule: {res.stderr or res.stdout}"
    except Exception as e:
        return False, f"Execution failed: {e}"


def generate_firewall_rule_command(
    executable_path: Optional[Path | str] = None,
    rule_name: str = DEFAULT_RULE_NAME,
) -> str:
    """Generates the Windows netsh command to block outbound traffic for a dedicated Tsukiko executable."""
    target = Path(executable_path or sys.executable).resolve()
    is_safe, reason = is_safe_target_executable(target)
    if not is_safe:
        raise ValueError(reason)

    return (
        f'netsh advfirewall firewall add rule name="{rule_name}" '
        f'dir=out action=block program="{target}" enable=yes profile=any '
        f'group="{RULE_GROUPING}" '
        f'description="{DEFAULT_DESCRIPTION}"'
    )


def generate_remove_rule_command(rule_name: str = DEFAULT_RULE_NAME) -> str:
    """Generates the Windows netsh command to delete a Tsukiko outbound firewall rule."""
    if not rule_name.startswith("Tsukiko"):
        raise ValueError("Refusing to generate removal command for non-Tsukiko firewall rule.")
    return f'netsh advfirewall firewall delete rule name="{rule_name}"'
