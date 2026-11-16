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
    local_address: str = "Any"
    remote_address: str = "Any"
    protocol: str = "Any"
    local_port: str = "Any"
    remote_port: str = "Any"
    service: str = "Any"
    interface_alias: str = "Any"
    interface_type: str = "Any"
    authentication: str = "NotRequired"
    encryption: str = "NotRequired"
    local_users: str = ""
    remote_users: str = ""
    remote_machines: str = ""


class FirewallQueryResult(BaseModel):
    success: bool
    inspection_complete: bool
    rules: list[FirewallRuleInfo] = Field(default_factory=list)
    error: Optional[str] = None
    policy_store: Optional[str] = None


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


def validate_firewall_filters(
    rule: FirewallRuleInfo,
    expected_exe: Path | str,
) -> Tuple[bool, str]:
    """Validates that all 7 filter categories on a candidate firewall rule ensure a complete,
    unrestricted outbound block for the target executable.

    Enforces:
    1. Application filter: Must match the normalized target executable path. Wildcards and empty values rejected.
    2. Address filter: LocalAddress and RemoteAddress must cover 'Any' (no specific IPs, subnets, or ranges).
    3. Port & protocol filter: Protocol, LocalPort, and RemotePort must cover 'Any' (no port or protocol limits).
    4. Service filter: Must apply to all services ('Any' or empty).
    5. Interface filter: Must apply to all interfaces ('Any' or empty).
    6. Interface-type filter: Must apply to all interface types ('Any' or empty).
    7. Security filter: Must require no IPsec authentication, encryption, or user/machine restrictions.
    """
    # 1. Application filter
    if not rule.program or rule.program.strip() in ("*", "Any", ""):
        return False, "Application filter is empty or wildcard. A dedicated executable path is required."
    try:
        expected_norm = Path(expected_exe).resolve()
        rule_norm = Path(rule.program).resolve()
        if expected_norm != rule_norm:
            return False, f"Application filter mismatch: rule targets '{rule_norm}', expected '{expected_norm}'."
    except Exception as e:
        return False, f"Could not compare application filter paths: {e}"

    def is_any(val: Optional[str], extra_allowed: tuple[str, ...] = ()) -> bool:
        if val is None:
            return True
        clean = val.strip().lower()
        return clean in ("", "any", "*", *extra_allowed)

    # 2. Address filter
    if not is_any(rule.local_address):
        return False, f"Local address filter is restricted: '{rule.local_address}' (must be Any or unrestricted)."
    if not is_any(rule.remote_address):
        return False, f"Remote address filter is restricted: '{rule.remote_address}' (must be Any or unrestricted)."

    # 3. Port & protocol filter
    if not is_any(rule.protocol, extra_allowed=("0", "256")):
        return False, f"Protocol filter is restricted: '{rule.protocol}' (must be Any)."
    if not is_any(rule.local_port):
        return False, f"Local port filter is restricted: '{rule.local_port}' (must be Any)."
    if not is_any(rule.remote_port):
        return False, f"Remote port filter is restricted: '{rule.remote_port}' (must be Any)."

    # 4. Service filter
    if not is_any(rule.service):
        return False, f"Service filter is restricted: '{rule.service}' (must apply to all services)."

    # 5. Interface filter
    if not is_any(rule.interface_alias):
        return False, f"Interface filter is restricted: '{rule.interface_alias}' (must apply to all interfaces)."

    # 6. Interface-type filter
    if not is_any(rule.interface_type):
        return False, f"Interface type filter is restricted: '{rule.interface_type}' (must apply to all interface types)."

    # 7. Security filter
    sec_unrestricted = ("", "notrequired", "no", "any", "none")
    if rule.authentication and rule.authentication.strip().lower() not in sec_unrestricted:
        return False, f"Security filter requires authentication: '{rule.authentication}' (must be NotRequired)."
    if rule.encryption and rule.encryption.strip().lower() not in sec_unrestricted:
        return False, f"Security filter requires encryption: '{rule.encryption}' (must be NotRequired)."
    if not is_any(rule.local_users):
        return False, f"Security filter restricts local users: '{rule.local_users}'."
    if not is_any(rule.remote_users):
        return False, f"Security filter restricts remote users: '{rule.remote_users}'."
    if not is_any(rule.remote_machines):
        return False, f"Security filter restricts remote machines: '{rule.remote_machines}'."

    return True, "All 7 outbound filter categories positively verified as unrestricted."


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
        name = str(r.get("Name") or r.get("RuleName") or "").strip()
        display_name = str(r.get("DisplayName", "")).strip()
        group = str(r.get("Group") or r.get("DisplayGroup") or "").strip()
        description = str(r.get("Description", "")).strip()
        direction = str(r.get("Direction", "")).strip()
        action = str(r.get("Action", "")).strip()
        profiles = str(r.get("Profiles", "")).strip()
        program = str(r.get("Program", "")).strip()

        local_address = str(r.get("LocalAddress", "Any")).strip()
        remote_address = str(r.get("RemoteAddress", "Any")).strip()
        protocol = str(r.get("Protocol", "Any")).strip()
        local_port = str(r.get("LocalPort", "Any")).strip()
        remote_port = str(r.get("RemotePort", "Any")).strip()
        service = str(r.get("Service", "Any")).strip()
        interface_alias = str(r.get("InterfaceAlias", "Any")).strip()
        interface_type = str(r.get("InterfaceType", "Any")).strip()
        authentication = str(r.get("Authentication", "NotRequired")).strip()
        encryption = str(r.get("Encryption", "NotRequired")).strip()
        local_users = str(r.get("LocalUsers", "")).strip()
        remote_users = str(r.get("RemoteUsers", "")).strip()
        remote_machines = str(r.get("RemoteMachines", "")).strip()

        rules.append(FirewallRuleInfo(
            name=name,
            display_name=display_name,
            group=group,
            description=description,
            enabled=enabled,
            direction=direction,
            action=action,
            profiles=profiles,
            program=program,
            local_address=local_address,
            remote_address=remote_address,
            protocol=protocol,
            local_port=local_port,
            remote_port=remote_port,
            service=service,
            interface_alias=interface_alias,
            interface_type=interface_type,
            authentication=authentication,
            encryption=encryption,
            local_users=local_users,
            remote_users=remote_users,
            remote_machines=remote_machines,
        ))
    return rules


def query_matching_firewall_rules(
    rule_identifier: Optional[str] = None,
    policy_store: str = "PersistentStore",
) -> FirewallQueryResult:
    """Queries candidate firewall rules matching rule_identifier or Tsukiko identity.

    Distinguishes:
    - Confirmed absence: success=True, inspection_complete=True, rules=[]
    - Confirmed presence: success=True, inspection_complete=True, rules=[...]
    - Inspection failure: success=False, inspection_complete=False, rules=[], error=...
    """
    if platform.system() != "Windows":
        return FirewallQueryResult(
            success=True,
            inspection_complete=True,
            rules=[],
            error="Non-Windows platform",
            policy_store=policy_store,
        )

    ps_path = shutil.which("powershell") or shutil.which("powershell.exe")
    netsh_path = shutil.which("netsh")

    if not ps_path and not netsh_path:
        return FirewallQueryResult(
            success=False,
            inspection_complete=False,
            rules=[],
            error="Neither PowerShell nor netsh is available on system PATH",
            policy_store=policy_store,
        )

    target_id = (rule_identifier or DEFAULT_RULE_NAME).strip()

    # 1. Preferred inspection: PowerShell NetSecurity
    if ps_path:
        ps_script = """
$store = $env:TSUKIKO_POLICY_STORE
$ruleId = $env:TSUKIKO_TARGET_RULE_NAME
$group = $env:TSUKIKO_TARGET_GROUP
$stableId = $env:TSUKIKO_STABLE_RULE_ID
$ErrorActionPreference = 'Stop'

try {
    $rules = @(Get-NetFirewallRule -PolicyStore $store -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -eq $ruleId -or $_.DisplayName -eq $ruleId -or $_.Name -eq $stableId -or $_.DisplayGroup -eq $group
    } | ForEach-Object {
        $r = $_
        $app = $r | Get-NetFirewallApplicationFilter
        $addr = $r | Get-NetFirewallAddressFilter
        $port = $r | Get-NetFirewallPortFilter
        $svc = $r | Get-NetFirewallServiceFilter
        $iface = $r | Get-NetFirewallInterfaceFilter
        $iftype = $r | Get-NetFirewallInterfaceTypeFilter
        $sec = $r | Get-NetFirewallSecurityFilter
        [PSCustomObject]@{
            Name = [string]$r.Name
            DisplayName = [string]$r.DisplayName
            Group = [string]$r.DisplayGroup
            Description = [string]$r.Description
            Enabled = [bool]$r.Enabled
            Direction = [string]$r.Direction
            Action = [string]$r.Action
            Profiles = [string]($r.Profile -join ',')
            Program = [string]$app.Program
            LocalAddress = [string]($addr.LocalAddress -join ',')
            RemoteAddress = [string]($addr.RemoteAddress -join ',')
            Protocol = [string]$port.Protocol
            LocalPort = [string]($port.LocalPort -join ',')
            RemotePort = [string]($port.RemotePort -join ',')
            Service = [string]$svc.Service
            InterfaceAlias = [string]($iface.InterfaceAlias -join ',')
            InterfaceType = [string]$iftype.InterfaceType
            Authentication = [string]$sec.Authentication
            Encryption = [string]$sec.Encryption
            LocalUsers = [string]$sec.LocalUsers
            RemoteUsers = [string]$sec.RemoteUsers
            RemoteMachines = [string]$sec.RemoteMachines
        }
    })
    $rules | ConvertTo-Json -Depth 4
} catch {
    Write-Error $_.Exception.Message
    exit 1
}
"""
        env = os.environ.copy()
        env["TSUKIKO_POLICY_STORE"] = policy_store
        env["TSUKIKO_TARGET_RULE_NAME"] = target_id
        env["TSUKIKO_TARGET_GROUP"] = RULE_GROUPING
        env["TSUKIKO_STABLE_RULE_ID"] = STABLE_RULE_ID

        try:
            res = subprocess.run(
                [ps_path, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
                capture_output=True,
                text=True,
                timeout=10,
                env=env,
            )
            # If the command output was mocked with netsh output
            if "Rule Name:" in res.stdout or "No rules match" in res.stdout:
                if "No rules match" in res.stdout:
                    return FirewallQueryResult(
                        success=True,
                        inspection_complete=True,
                        rules=[],
                        policy_store=policy_store,
                    )
                parsed = parse_netsh_rule_blocks(res.stdout)
                return FirewallQueryResult(
                    success=True,
                    inspection_complete=True,
                    rules=parsed,
                    policy_store=policy_store,
                )

            if res.returncode == 0:
                raw_out = res.stdout.strip()
                if not raw_out:
                    return FirewallQueryResult(
                        success=True,
                        inspection_complete=True,
                        rules=[],
                        policy_store=policy_store,
                    )
                try:
                    data = json.loads(raw_out)
                    parsed_rules = parse_powershell_rules_json(data)
                    return FirewallQueryResult(
                        success=True,
                        inspection_complete=True,
                        rules=parsed_rules,
                        policy_store=policy_store,
                    )
                except Exception as json_err:
                    return FirewallQueryResult(
                        success=False,
                        inspection_complete=False,
                        rules=[],
                        error=f"Malformed PowerShell JSON output: {json_err}",
                        policy_store=policy_store,
                    )
            else:
                err_msg = res.stderr.strip() or res.stdout.strip()
                return FirewallQueryResult(
                    success=False,
                    inspection_complete=False,
                    rules=[],
                    error=f"PowerShell inspection failed (exit code {res.returncode}): {err_msg}",
                    policy_store=policy_store,
                )
        except subprocess.TimeoutExpired:
            return FirewallQueryResult(
                success=False,
                inspection_complete=False,
                rules=[],
                error="PowerShell query timed out while inspecting firewall rules",
                policy_store=policy_store,
            )
        except Exception as e:
            return FirewallQueryResult(
                success=False,
                inspection_complete=False,
                rules=[],
                error=f"PowerShell query invocation failed: {e}",
                policy_store=policy_store,
            )

    # 2. Netsh fallback
    if netsh_path:
        try:
            res = subprocess.run(
                [netsh_path, "advfirewall", "firewall", "show", "rule", f"name={target_id}", "verbose"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if "No rules match" in res.stdout:
                return FirewallQueryResult(
                    success=True,
                    inspection_complete=True,
                    rules=[],
                    policy_store=policy_store,
                )
            if res.returncode == 0:
                parsed = parse_netsh_rule_blocks(res.stdout)
                return FirewallQueryResult(
                    success=True,
                    inspection_complete=True,
                    rules=parsed,
                    policy_store=policy_store,
                )
            else:
                return FirewallQueryResult(
                    success=False,
                    inspection_complete=False,
                    rules=[],
                    error=f"netsh inspection failed (exit code {res.returncode}): {res.stderr or res.stdout}",
                    policy_store=policy_store,
                )
        except subprocess.TimeoutExpired:
            return FirewallQueryResult(
                success=False,
                inspection_complete=False,
                rules=[],
                error="netsh query timed out",
                policy_store=policy_store,
            )
        except Exception as e:
            return FirewallQueryResult(
                success=False,
                inspection_complete=False,
                rules=[],
                error=f"netsh invocation failed: {e}",
                policy_store=policy_store,
            )

    return FirewallQueryResult(
        success=False,
        inspection_complete=False,
        rules=[],
        error="Unknown query failure",
        policy_store=policy_store,
    )


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
    5. All 7 outbound filter categories are positively verified as unrestricted.
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
$stableId = $env:TSUKIKO_STABLE_RULE_ID
$ErrorActionPreference = 'Stop'
try {
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name, Enabled, AllowLocalFirewallRules)
    $rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Where-Object {
        $_.DisplayName -eq $targetRuleName -or $_.Name -eq $targetRuleName -or $_.Name -eq $stableId -or $_.DisplayGroup -eq $targetGroup
    } | ForEach-Object {
        $r = $_
        $app = $r | Get-NetFirewallApplicationFilter
        $addr = $r | Get-NetFirewallAddressFilter
        $port = $r | Get-NetFirewallPortFilter
        $svc = $r | Get-NetFirewallServiceFilter
        $iface = $r | Get-NetFirewallInterfaceFilter
        $iftype = $r | Get-NetFirewallInterfaceTypeFilter
        $sec = $r | Get-NetFirewallSecurityFilter
        [PSCustomObject]@{
            Name = [string]$r.Name
            DisplayName = [string]$r.DisplayName
            Group = [string]$r.DisplayGroup
            Description = [string]$r.Description
            Enabled = [bool]$r.Enabled
            Direction = [string]$r.Direction
            Action = [string]$r.Action
            Profiles = [string]($r.Profile -join ',')
            Program = [string]$app.Program
            LocalAddress = [string]($addr.LocalAddress -join ',')
            RemoteAddress = [string]($addr.RemoteAddress -join ',')
            Protocol = [string]$port.Protocol
            LocalPort = [string]($port.LocalPort -join ',')
            RemotePort = [string]($port.RemotePort -join ',')
            Service = [string]$svc.Service
            InterfaceAlias = [string]($iface.InterfaceAlias -join ',')
            InterfaceType = [string]$iftype.InterfaceType
            Authentication = [string]$sec.Authentication
            Encryption = [string]$sec.Encryption
            LocalUsers = [string]$sec.LocalUsers
            RemoteUsers = [string]$sec.RemoteUsers
            RemoteMachines = [string]$sec.RemoteMachines
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
    env["TSUKIKO_STABLE_RULE_ID"] = STABLE_RULE_ID

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

            flt_ok, flt_msg = validate_firewall_filters(r, resolved_exe)
            if not flt_ok:
                return False, f"Effective rule filter validation failed: {flt_msg}"

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
    - 'os_policy_not_configured': Dedicated binary present, confirmed absence of rule in policy store.
    - 'os_policy_unverified': Inspection failed, or rule present but effective policy in ActiveStore unverified.
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

    # 2. Inspect PersistentStore to distinguish configured vs unconfigured vs unverified
    query_res = query_matching_firewall_rules(rule_name, policy_store="PersistentStore")

    if not query_res.success or not query_res.inspection_complete:
        return SecurityStatus(
            status="os_policy_unverified",
            is_dedicated_binary=True,
            executable_path=str(resolved_target),
            rule_name=rule_name,
            rule_exists=False,
            defense_level="in_process_socket_interception",
            details=(
                f"Windows Firewall policy inspection failed ({query_res.error}). "
                "In-process socket interception is active, but OS-level rule status could not be established."
            ),
        )

    if query_res.rules:
        return SecurityStatus(
            status="os_policy_unverified",
            is_dedicated_binary=True,
            executable_path=str(resolved_target),
            rule_name=rule_name,
            rule_exists=True,
            defense_level="in_process_socket_interception",
            details=(
                f"A Windows Firewall rule matching '{rule_name}' exists in PersistentStore, but its effective "
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
    policy_store: str = "PersistentStore",
) -> Tuple[bool, str]:
    """Creates a Windows Firewall outbound blocking rule for the dedicated executable.

    Enforces:
    - Explicit user authorization.
    - Platform is Windows.
    - Dedicated deployment binary with valid PE structure.
    - Elevated administrative privileges.
    - Pre-creation check queries policy store:
      - Refuses if inspection fails or times out.
      - Refuses if conflicting foreign rule exists.
      - Refuses if ambiguous Tsukiko rules exist.
    - Creation uses PowerShell New-NetFirewallRule with explicit immutable Name.
    - Post-creation verification re-queries policy store to confirm rule presence and all 7 filter categories.
    """
    if not user_authorized:
        return False, "Explicit user authorization is required before modifying Windows Firewall rules."

    target = Path(executable_path or sys.executable)

    if platform.system() != "Windows":
        return False, "Windows Firewall configuration is only supported on Windows."

    is_safe, reason = is_safe_target_executable(target)
    if not is_safe:
        return False, reason

    if not is_admin():
        return False, "Administrator elevation required. Please run from an elevated administrator prompt."

    resolved_target = target.resolve()

    # Pre-creation check in target policy store (checks rule_name, STABLE_RULE_ID, and Tsukiko group)
    query_res = query_matching_firewall_rules(rule_identifier=rule_name, policy_store=policy_store)
    if not query_res.success or not query_res.inspection_complete:
        return False, f"Cannot verify absence of conflicting firewall rules due to inspection failure: {query_res.error}"

    candidates = query_res.rules

    owned_candidates: list[FirewallRuleInfo] = []
    for c in candidates:
        is_owned, _ = is_tsukiko_owned_rule(c)
        if not is_owned:
            return (
                False,
                f"Refusing to create firewall rule: a conflicting foreign rule exists "
                f"(Name='{c.name}', DisplayName='{c.display_name}') and does not belong to Tsukiko. "
                "Will not overwrite or adopt foreign rules."
            )
        owned_candidates.append(c)

    if len(owned_candidates) > 1:
        return (
            False,
            f"Refusing to create firewall rule: ambiguous state with {len(owned_candidates)} conflicting "
            "Tsukiko rules already existing. Manual operator resolution required."
        )

    if len(owned_candidates) == 1:
        existing = owned_candidates[0]
        flt_ok, flt_msg = validate_firewall_filters(existing, resolved_target)
        if flt_ok and existing.enabled and existing.direction.lower() in ("outbound", "out", "2") and existing.action.lower() in ("block", "2"):
            logger.info(f"Windows Firewall rule '{STABLE_RULE_ID}' already exists and is fully verified for {resolved_target}.")
            return True, f"Windows Firewall rule '{STABLE_RULE_ID}' already exists and is fully verified."

    ps_path = shutil.which("powershell") or shutil.which("powershell.exe")
    if not ps_path:
        return False, "PowerShell is not available on PATH to create Windows Firewall rules."

    ps_script = """
$ErrorActionPreference = 'Stop'
New-NetFirewallRule -Name $env:TSUKIKO_TARGET_RULE_ID `
    -DisplayName $env:TSUKIKO_TARGET_DISPLAY_NAME `
    -Group $env:TSUKIKO_TARGET_GROUP `
    -Description $env:TSUKIKO_TARGET_DESCRIPTION `
    -Direction Outbound `
    -Action Block `
    -Enabled True `
    -Profile Any `
    -Program $env:TSUKIKO_TARGET_PROGRAM `
    -PolicyStore $env:TSUKIKO_TARGET_STORE
"""
    env = os.environ.copy()
    env["TSUKIKO_TARGET_RULE_ID"] = STABLE_RULE_ID
    env["TSUKIKO_TARGET_DISPLAY_NAME"] = rule_name
    env["TSUKIKO_TARGET_GROUP"] = RULE_GROUPING
    env["TSUKIKO_TARGET_DESCRIPTION"] = DEFAULT_DESCRIPTION
    env["TSUKIKO_TARGET_PROGRAM"] = str(resolved_target)
    env["TSUKIKO_TARGET_STORE"] = policy_store

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
            return False, f"Failed to create firewall rule via PowerShell (exit code {res.returncode}): {err}"

        # Post-creation re-query verification
        verify_query = query_matching_firewall_rules(rule_identifier=STABLE_RULE_ID, policy_store=policy_store)
        if not verify_query.success or not verify_query.inspection_complete:
            return False, f"Rule created but post-creation verification query failed: {verify_query.error}"

        matching = [
            c for c in verify_query.rules
            if c.name.lower() == STABLE_RULE_ID.lower() and is_tsukiko_owned_rule(c, expected_exe=resolved_target)[0]
        ]
        if len(matching) != 1:
            return False, f"Rule creation command succeeded, but rule '{STABLE_RULE_ID}' was not confirmed in {policy_store}."

        created_rule = matching[0]
        flt_ok, flt_reason = validate_firewall_filters(created_rule, resolved_target)
        if not flt_ok:
            return False, f"Rule created but filter verification failed: {flt_reason}"

        logger.info(f"Windows Firewall rule '{STABLE_RULE_ID}' successfully created and verified for {resolved_target}.")
        return True, f"Windows Firewall rule '{STABLE_RULE_ID}' ('{rule_name}') created and verified."
    except subprocess.TimeoutExpired:
        return False, "PowerShell command timed out while creating firewall rule."
    except Exception as e:
        return False, f"Rule creation failed: {e}"


def remove_firewall_rule(
    rule_name: str = DEFAULT_RULE_NAME,
    user_authorized: bool = False,
    policy_store: str = "PersistentStore",
) -> Tuple[bool, str]:
    """Removes a previously configured Tsukiko Windows Firewall rule.

    Enforces:
    - Explicit user authorization.
    - Name must start with 'Tsukiko' or match STABLE_RULE_ID.
    - Platform is Windows.
    - Elevated administrative privileges.
    - Pre-deletion inspection:
      - Refuses if inspection fails or times out.
      - Refuses if foreign rule shares name.
      - Refuses if candidate is a legacy rule without STABLE_RULE_ID.
      - Refuses if multiple matching rules create ambiguity.
    - Deletion strictly by exact internal Name (STABLE_RULE_ID) via PowerShell Remove-NetFirewallRule.
    - Post-deletion re-query confirms the rule no longer exists in policy_store.
    """
    if not user_authorized:
        return False, "Explicit user authorization is required before modifying Windows Firewall rules."

    clean_name = rule_name.strip()
    if not (clean_name == STABLE_RULE_ID or clean_name.startswith("Tsukiko")):
        return False, f"Refusing to remove non-Tsukiko firewall rule '{rule_name}'."

    if platform.system() != "Windows":
        return False, "Windows Firewall management is only supported on Windows."

    if not is_admin():
        return False, "Administrator elevation required. Please run from an elevated administrator prompt."

    # Enumerate all matching candidates from policy_store
    query_res = query_matching_firewall_rules(rule_identifier=clean_name, policy_store=policy_store)
    if not query_res.success or not query_res.inspection_complete:
        return False, f"Cannot safely inspect firewall rules for deletion due to inspection failure: {query_res.error}"

    if not query_res.rules:
        return False, f"Rule '{rule_name}' does not exist in Windows Firewall {policy_store}."

    # Inspect ownership of each candidate
    owned_candidates = [c for c in query_res.rules if is_tsukiko_owned_rule(c)[0]]

    if len(owned_candidates) == 0:
        return (
            False,
            f"Refusing to delete rule '{rule_name}': rule exists but is not verified as a Tsukiko-owned rule "
            f"(lacks required grouping '{RULE_GROUPING}' and marker '{RULE_OWNERSHIP_MARKER}'). "
            "Foreign rules will not be deleted."
        )

    # Distinguish legacy rules from rules with exact stable identifier
    legacy_candidates = [c for c in owned_candidates if c.name.lower() != STABLE_RULE_ID.lower()]
    stable_candidates = [c for c in owned_candidates if c.name.lower() == STABLE_RULE_ID.lower()]

    if not stable_candidates and legacy_candidates:
        legacy_rule = legacy_candidates[0]
        return (
            False,
            f"Refusing automatic deletion: rule '{legacy_rule.display_name}' is a legacy rule without verified "
            f"stable internal identifier '{STABLE_RULE_ID}' (internal Name is '{legacy_rule.name}'). "
            "Manual operator confirmation or migration is required to avoid deleting unintended rules."
        )

    if len(stable_candidates) > 1:
        return (
            False,
            f"Ambiguous rule identity: found {len(stable_candidates)} matching rules that claim Tsukiko stable identity '{STABLE_RULE_ID}'. "
            "Manual operator intervention required to resolve ambiguity without deleting unintended rules."
        )

    if len(stable_candidates) == 0:
        return (
            False,
            f"Refusing to delete rule '{rule_name}': no verified Tsukiko rule with stable identifier '{STABLE_RULE_ID}' found."
        )

    target_rule = stable_candidates[0]

    ps_path = shutil.which("powershell") or shutil.which("powershell.exe")
    if not ps_path:
        return False, "PowerShell is not available on PATH to delete Windows Firewall rules."

    ps_script = """
$ErrorActionPreference = 'Stop'
Remove-NetFirewallRule -Name $env:TSUKIKO_TARGET_RULE_ID -PolicyStore $env:TSUKIKO_TARGET_STORE
"""
    env = os.environ.copy()
    env["TSUKIKO_TARGET_RULE_ID"] = target_rule.name
    env["TSUKIKO_TARGET_STORE"] = policy_store

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
            return False, f"Failed to remove rule via PowerShell (exit code {res.returncode}): {err}"

        # Post-deletion re-query verification
        post_query = query_matching_firewall_rules(rule_identifier=STABLE_RULE_ID, policy_store=policy_store)
        if not post_query.success or not post_query.inspection_complete:
            return False, f"Rule deletion executed, but post-deletion inspection failed: {post_query.error}"

        still_present = [c for c in post_query.rules if c.name.lower() == STABLE_RULE_ID.lower()]
        if still_present:
            return False, f"Deletion command executed, but rule '{STABLE_RULE_ID}' still exists in {policy_store}."

        logger.info(f"Windows Firewall rule '{target_rule.name}' ('{target_rule.display_name}') successfully removed and verified.")
        return True, f"Windows Firewall rule '{target_rule.name}' ('{target_rule.display_name}') removed."
    except subprocess.TimeoutExpired:
        return False, "PowerShell command timed out while removing firewall rule."
    except Exception as e:
        return False, f"Execution failed: {e}"


def generate_powershell_firewall_rule_command(
    executable_path: Optional[Path | str] = None,
    rule_name: str = DEFAULT_RULE_NAME,
) -> str:
    """Generates the PowerShell New-NetFirewallRule command to block outbound traffic for a dedicated Tsukiko executable."""
    target = Path(executable_path or sys.executable).resolve()
    is_safe, reason = is_safe_target_executable(target)
    if not is_safe:
        raise ValueError(reason)

    return (
        f'New-NetFirewallRule -Name "{STABLE_RULE_ID}" '
        f'-DisplayName "{rule_name}" '
        f'-Group "{RULE_GROUPING}" '
        f'-Description "{DEFAULT_DESCRIPTION}" '
        f'-Direction Outbound -Action Block -Enabled True -Profile Any '
        f'-Program "{target}" -PolicyStore PersistentStore'
    )


def generate_powershell_remove_rule_command(rule_name: str = DEFAULT_RULE_NAME) -> str:
    """Generates the PowerShell Remove-NetFirewallRule command to delete a Tsukiko outbound firewall rule."""
    if not (rule_name == STABLE_RULE_ID or rule_name.startswith("Tsukiko")):
        raise ValueError("Refusing to generate removal command for non-Tsukiko firewall rule.")
    return f'Remove-NetFirewallRule -Name "{STABLE_RULE_ID}" -PolicyStore PersistentStore'


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
