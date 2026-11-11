"""
Tsukiko Windows Firewall Policy Manager
Provides safe, application-specific OS-level outbound firewall rule management and status inspection.
Enforces strict target validation, verifies actual rule properties (direction, action, program, enabled,
profiles, ownership identity), and never targets shared Python interpreters or arbitrary binaries.

Note on Executable Identity:
Checking file naming and the Windows PE 'MZ' binary header ensures the target is formatted as a valid
Windows PE executable. This deployment check is not a cryptographic signature verification (such as
Authenticode digital signing). Cryptographic verification requires an established code-signing certificate.
"""

from __future__ import annotations

import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
from typing import Optional, Tuple
from pydantic import BaseModel, Field

from app.core.logging.logger import get_logger

logger = get_logger("SYSTEM")

DEFAULT_RULE_NAME = "Tsukiko Outbound Privacy Boundary"
LEGACY_RULE_NAME = "Tsukiko Outbound Block"
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


def is_admin() -> bool:
    """Checks whether the current process possesses elevated Windows administrative privileges."""
    if platform.system() != "Windows":
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def is_safe_target_executable(path: Path | str) -> Tuple[bool, str]:
    """Strictly validates whether the target file is the dedicated Tsukiko deployment binary.

    Enforces:
    - Path must exist and be a regular file on disk.
    - File extension must be '.exe'.
    - Filename must match dedicated deployment binary ('tsukiko.exe').
    - Target must contain valid Windows PE executable magic ('MZ' header).
    - Path must not target shared Python interpreters or shell binaries.
    - Path must not contain control characters or command-injection sequences.

    Limitation: Validating PE header confirms binary format, not cryptographic code signature.
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

    # PE Header validation: binary must start with 'MZ' (0x4D, 0x5A)
    try:
        with open(resolved, "rb") as f:
            magic = f.read(2)
            if magic != b"MZ":
                return (
                    False,
                    f"Target file '{resolved}' is not a valid Windows PE binary (missing 'MZ' executable header). "
                    "Plain text stubs and arbitrary non-PE files are rejected."
                )
    except Exception as e:
        return False, f"Could not inspect target file binary header: {e}"

    return True, f"Verified dedicated deployment binary: {resolved}"


def generate_firewall_rule_command(
    executable_path: Optional[Path | str] = None,
    rule_name: str = DEFAULT_RULE_NAME,
) -> str:
    """Generates the Windows netsh command to block outbound traffic for a dedicated Tsukiko executable.

    Raises ValueError if called with an invalid, shared, or arbitrary binary.
    """
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


def verify_firewall_rule(
    executable_path: Path | str,
    rule_name: str = DEFAULT_RULE_NAME,
) -> Tuple[bool, str]:
    """Verifies that an existing Windows Firewall rule actually protects the specified executable.

    Validates:
    1. Rule exists and query succeeds.
    2. Rule ownership: Grouping matches 'Tsukiko Desktop Companion' or Description contains '[Tsukiko-Privacy-Core:Outbound-Block]'.
    3. Rule is Enabled (Yes).
    4. Direction is Outbound (Out).
    5. Action is Block.
    6. Program exactly matches normalized executable path.
    7. Profiles includes all network profiles (Domain,Private,Public or Any).
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

        # 1. Rule ownership verification (Grouping or Description ownership marker)
        grouping_match = re.search(r"^\s*Grouping:\s*(.+)$", output, re.IGNORECASE | re.MULTILINE)
        description_match = re.search(r"^\s*Description:\s*(.+)$", output, re.IGNORECASE | re.MULTILINE)

        has_ownership = False
        if grouping_match and RULE_GROUPING.lower() in grouping_match.group(1).lower():
            has_ownership = True
        if description_match and RULE_OWNERSHIP_MARKER.lower() in description_match.group(1).lower():
            has_ownership = True

        if not has_ownership:
            return (
                False,
                f"Rule '{rule_name}' exists but lacks verified Tsukiko ownership markers "
                f"(Grouping '{RULE_GROUPING}' or marker '{RULE_OWNERSHIP_MARKER}'). "
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

        # 6. Profiles verification
        profiles_match = re.search(r"^\s*Profiles:\s*(.+)$", output, re.IGNORECASE | re.MULTILINE)
        if profiles_match:
            prof = profiles_match.group(1).strip().lower()
            if "any" not in prof and not ("domain" in prof and "private" in prof and "public" in prof):
                return (
                    False,
                    f"Rule profiles incomplete: applies only to '{profiles_match.group(1).strip()}', "
                    "must apply to all network profiles (Domain,Private,Public or Any)."
                )

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
    - 'os_policy_unverified': Rule present, but properties (direction/action/path/ownership) could not be verified.
    - 'os_policy_active': Dedicated binary with confirmed matching Outbound Block firewall rule.
    """
    target = Path(executable_path or sys.executable)
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
    verified, v_reason = verify_firewall_rule(resolved_target, rule_name)

    if verified:
        return SecurityStatus(
            status="os_policy_active",
            is_dedicated_binary=True,
            executable_path=str(resolved_target),
            rule_name=rule_name,
            rule_exists=True,
            defense_level="os_kernel_firewall_and_socket_interception",
            details=(
                "Tsukiko is running as a dedicated application executable with an active Windows Firewall "
                "outbound blocking rule verified at the Windows kernel filtering layer."
            ),
        )

    # Check if a rule exists at all
    netsh_path = shutil.which("netsh")
    rule_exists = False
    if netsh_path and platform.system() == "Windows":
        try:
            chk = subprocess.run(
                [netsh_path, "advfirewall", "firewall", "show", "rule", f"name={rule_name}"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            rule_exists = chk.returncode == 0 and "No rules match" not in chk.stdout
        except Exception:
            rule_exists = False

    if rule_exists:
        return SecurityStatus(
            status="os_policy_unverified",
            is_dedicated_binary=True,
            executable_path=str(resolved_target),
            rule_name=rule_name,
            rule_exists=True,
            defense_level="in_process_socket_interception",
            details=(
                f"A Windows Firewall rule named '{rule_name}' exists, but verification could not establish "
                f"that it matches the current executable or policy requirements ({v_reason})."
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
    """
    if not user_authorized:
        return False, "Explicit user authorization is required before modifying Windows Firewall rules."

    target = Path(executable_path or sys.executable)
    is_safe, reason = is_safe_target_executable(target)
    if not is_safe:
        return False, reason

    if platform.system() != "Windows":
        return False, "Windows Firewall configuration is only supported on Windows."

    if not is_admin():
        return False, "Administrator elevation required. Please run from an elevated administrator prompt."

    resolved_target = target.resolve()
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
    """
    if not user_authorized:
        return False, "Explicit user authorization is required before modifying Windows Firewall rules."

    if not rule_name.startswith("Tsukiko"):
        return False, f"Refusing to remove non-Tsukiko firewall rule '{rule_name}'."

    if platform.system() != "Windows":
        return False, "Windows Firewall management is only supported on Windows."

    if not is_admin():
        return False, "Administrator elevation required. Please run from an elevated administrator prompt."

    netsh_path = shutil.which("netsh")
    if not netsh_path:
        return False, "netsh utility not found on PATH."

    # Inspect existing rule to verify ownership before deletion
    try:
        chk = subprocess.run(
            [netsh_path, "advfirewall", "firewall", "show", "rule", f"name={rule_name}", "verbose"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if chk.returncode != 0 or "No rules match" in chk.stdout:
            return False, f"Rule '{rule_name}' does not exist in Windows Firewall."

        output = chk.stdout
        has_ownership = (
            RULE_GROUPING.lower() in output.lower()
            or RULE_OWNERSHIP_MARKER.lower() in output.lower()
        )
        if not has_ownership:
            return (
                False,
                f"Refusing to delete rule '{rule_name}': rule exists but is not verified as a Tsukiko-owned rule."
            )
    except Exception as e:
        return False, f"Pre-deletion rule inspection failed: {e}"

    try:
        res = subprocess.run(
            [netsh_path, "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if res.returncode == 0:
            logger.info(f"Windows Firewall rule '{rule_name}' removed.")
            return True, f"Windows Firewall rule '{rule_name}' removed."
        else:
            return False, f"Failed to remove rule: {res.stderr or res.stdout}"
    except Exception as e:
        return False, f"Execution failed: {e}"
