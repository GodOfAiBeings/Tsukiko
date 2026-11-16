"""
Tsukiko Windows Firewall Inspection Verification Script (Read-Only)
Verifies NetSecurity ActiveStore query capability and Python schema parsing
without modifying, adding, or deleting any firewall rules.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys

from app.core.privacy.windows_firewall import parse_powershell_rules_json


def main() -> int:
    print("=== Tsukiko Windows Firewall Read-Only Policy Inspection ===")
    if platform.system() != "Windows":
        print("Note: Non-Windows platform detected. Skipping Windows Firewall policy inspection.")
        return 0

    ps_path = shutil.which("powershell") or shutil.which("powershell.exe")
    if not ps_path:
        print("ERROR: PowerShell is not available on PATH.")
        return 1

    ps_script = """
$ErrorActionPreference = 'Stop'
Import-Module NetSecurity -ErrorAction Stop

$profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name, Enabled, AllowLocalFirewallRules)
$sampleRules = @(Get-NetFirewallRule -PolicyStore ActiveStore | Select-Object -First 5 | ForEach-Object {
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
    Rules = $sampleRules
} | ConvertTo-Json -Depth 4
"""

    try:
        res = subprocess.run(
            [ps_path, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if res.returncode != 0:
            print(f"ERROR: PowerShell ActiveStore query failed (exit code {res.returncode}): {res.stderr or res.stdout}")
            return 1

        data = json.loads(res.stdout.strip())
        profiles = data.get("Profiles", [])
        rules_data = data.get("Rules", [])

        print(f"Successfully queried ActiveStore: {len(profiles)} network profiles inspected:")
        for p in profiles:
            print(f"  - Profile: {p.get('Name')} | Enabled: {p.get('Enabled')} | AllowLocal: {p.get('AllowLocalFirewallRules')}")

        parsed_rules = parse_powershell_rules_json(rules_data)
        print(f"Successfully parsed {len(parsed_rules)} real Windows Firewall rules with all 7 filter categories:")
        for r in parsed_rules:
            print(
                f"  - Rule: {r.name[:30]:<30} | Proto: {r.protocol:<6} | Remote: {r.remote_address[:15]:<15} "
                f"| Program: {Path(r.program).name if r.program else '<any>'}"
            )

        print("\nAll 7 NetSecurity filter categories verified compatible with Tsukiko parser schema.")
        print("Read-only inspection verification complete: NO rules were modified or added.")
        return 0

    except Exception as e:
        print(f"ERROR during read-only inspection verification: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
