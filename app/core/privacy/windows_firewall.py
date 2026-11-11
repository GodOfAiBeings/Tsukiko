"""
Tsukiko Windows Firewall Policy Manager
Provides safe, application-specific OS-level outbound firewall rule management and status inspection.
Enforces that firewall rules are NEVER created against shared Python interpreters (python.exe/pythonw.exe),
safeguarding system-wide Python networking while supporting dedicated Tsukiko executables.
"""

from __future__ import annotations

import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
from typing import Optional, Tuple
from pydantic import BaseModel, Field

from app.core.logging.logger import get_logger

logger = get_logger("SYSTEM")

DEFAULT_RULE_NAME = "Tsukiko Outbound Block"

SHARED_INTERPRETER_NAMES = frozenset({
    "python.exe",
    "pythonw.exe",
    "py.exe",
    "pytest.exe",
    "ipython.exe",
    "python3.exe",
    "python311.exe",
    "python312.exe",
    "python310.exe",
})


class SecurityStatus(BaseModel):
    status: str = Field(
        description="One of: 'in_process_only', 'os_policy_not_configured', 'os_policy_active'"
    )
    is_dedicated_binary: bool
    executable_path: str
    rule_name: str
    rule_exists: bool
    defense_level: str
    details: str


def is_safe_target_executable(path: Path | str) -> Tuple[bool, str]:
    """Evaluates whether the executable is safe for application-specific OS firewall rules.

    Strictly refuses shared Python interpreters (python.exe, pythonw.exe, py.exe, etc.)
    to avoid disrupting other Python workflows on the user's workstation.
    """
    exe_path = Path(path)
    file_name = exe_path.name.lower()

    if not file_name:
        return False, "Executable path cannot be empty."

    if file_name in SHARED_INTERPRETER_NAMES:
        return (
            False,
            f"Target executable '{file_name}' is a shared Python interpreter. "
            "Creating an OS-level firewall rule against it would block networking for all other "
            "Python applications on this computer. Use dedicated packaged Tsukiko executable instead."
        )

    # Dedicated packaged Tsukiko binaries (e.g. tsukiko.exe) or custom binaries
    return True, f"Target executable '{file_name}' is a dedicated application binary safe for OS firewall policy."


def generate_firewall_rule_command(
    executable_path: Optional[Path | str] = None,
    rule_name: str = DEFAULT_RULE_NAME,
) -> str:
    """Generates the Windows netsh command to block outbound traffic for a dedicated Tsukiko executable.

    Raises ValueError if called with a shared Python interpreter.
    """
    target = Path(executable_path or sys.executable).resolve()
    is_safe, reason = is_safe_target_executable(target)
    if not is_safe:
        raise ValueError(reason)

    return (
        f'netsh advfirewall firewall add rule name="{rule_name}" '
        f'dir=out action=block program="{target}" enable=yes '
        f'description="Tsukiko Offline Privacy Boundary: blocks outbound network traffic for dedicated executable"'
    )


def generate_remove_rule_command(rule_name: str = DEFAULT_RULE_NAME) -> str:
    """Generates the Windows netsh command to delete a Tsukiko outbound firewall rule."""
    return f'netsh advfirewall firewall delete rule name="{rule_name}"'


def verify_firewall_rule(rule_name: str = DEFAULT_RULE_NAME) -> bool:
    """Checks whether the specified Windows Firewall rule is currently registered and active."""
    if platform.system() != "Windows":
        return False

    netsh_path = shutil.which("netsh")
    if not netsh_path:
        return False

    try:
        res = subprocess.run(
            [netsh_path, "advfirewall", "firewall", "show", "rule", f"name={rule_name}"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if res.returncode == 0 and "No rules match" not in res.stdout:
            return True
        return False
    except Exception as e:
        logger.debug(f"Failed to query Windows Firewall status: {e}")
        return False


def get_security_status(
    executable_path: Optional[Path | str] = None,
    rule_name: str = DEFAULT_RULE_NAME,
) -> SecurityStatus:
    """Returns an honest security status report distinguishing in-process defense from OS firewall boundaries."""
    target = Path(executable_path or sys.executable).resolve()
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
                "Tsukiko is running under a shared Python interpreter. Technical in-process socket and "
                "DNS interception hooks are active, providing defense-in-depth against accidental outbound requests. "
                "OS-level firewall rules are deliberately not applied to shared python.exe to preserve system-wide tooling."
            ),
        )

    rule_active = verify_firewall_rule(rule_name)
    if rule_active:
        return SecurityStatus(
            status="os_policy_active",
            is_dedicated_binary=True,
            executable_path=str(target),
            rule_name=rule_name,
            rule_exists=True,
            defense_level="os_kernel_firewall_and_socket_interception",
            details=(
                "Tsukiko is running as a dedicated application executable with an active Windows Firewall "
                "outbound blocking rule enforced at the Windows kernel filtering layer, in addition to in-process socket hooks."
            ),
        )
    else:
        return SecurityStatus(
            status="os_policy_not_configured",
            is_dedicated_binary=True,
            executable_path=str(target),
            rule_name=rule_name,
            rule_exists=False,
            defense_level="in_process_socket_interception",
            details=(
                "Tsukiko is running as a dedicated executable, but no Windows Firewall outbound rule was detected. "
                "In-process socket interception is active. To enable OS-level kernel blocking, run the firewall setup command as Administrator."
            ),
        )


def create_firewall_rule(
    executable_path: Optional[Path | str] = None,
    rule_name: str = DEFAULT_RULE_NAME,
) -> Tuple[bool, str]:
    """Attempts to create a Windows Firewall rule for a dedicated executable (requires Admin privileges)."""
    target = Path(executable_path or sys.executable).resolve()
    is_safe, reason = is_safe_target_executable(target)
    if not is_safe:
        return False, reason

    if platform.system() != "Windows":
        return False, "Windows Firewall management is only supported on Windows."

    cmd_str = generate_firewall_rule_command(target, rule_name)
    try:
        # Run via netsh
        res = subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule",
             f"name={rule_name}", "dir=out", "action=block",
             f"program={target}", "enable=yes",
             "description=Tsukiko Offline Privacy Boundary: blocks outbound network traffic"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if res.returncode == 0:
            logger.info(f"Windows Firewall rule '{rule_name}' created successfully for {target}.")
            return True, f"Windows Firewall rule '{rule_name}' created successfully."
        else:
            return False, f"Failed to create firewall rule (administrative elevation required): {res.stderr or res.stdout}"
    except Exception as e:
        return False, f"Execution failed: {e}. Run in elevated PowerShell: {cmd_str}"


def remove_firewall_rule(rule_name: str = DEFAULT_RULE_NAME) -> Tuple[bool, str]:
    """Attempts to remove a previously configured Windows Firewall rule."""
    if platform.system() != "Windows":
        return False, "Windows Firewall management is only supported on Windows."

    try:
        res = subprocess.run(
            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
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
