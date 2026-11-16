"""
Tsukiko Windows Firewall Inspection Verification Script (Read-Only)
Verifies NetSecurity ActiveStore query capability, 7-filter schema integrity,
boolean serialization, and fail-closed Python parsing on the host system
without modifying, adding, or deleting any firewall rules.
"""

from __future__ import annotations

import json
from pathlib import Path
import platform
import shutil
import subprocess
import sys

from app.core.privacy.windows_firewall import (
    FirewallRuleInfo,
    parse_powershell_rules_json,
    validate_firewall_filters,
)

REQUIRED_RULE_FIELDS = frozenset({
    "Name",
    "DisplayName",
    "Group",
    "Description",
    "Enabled",
    "Direction",
    "Action",
    "Profiles",
    "Program",
    "LocalAddress",
    "RemoteAddress",
    "Protocol",
    "LocalPort",
    "RemotePort",
    "Service",
    "InterfaceAlias",
    "InterfaceType",
    "Authentication",
    "Encryption",
    "OverrideBlockRules",
    "LocalUser",
    "RemoteUser",
    "RemoteMachine",
})


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

try {
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name, Enabled, AllowLocalFirewallRules)
    $sampleRules = @(Get-NetFirewallRule -PolicyStore ActiveStore | Select-Object -First 10 | ForEach-Object {
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
            OverrideBlockRules = [bool]$sec.OverrideBlockRules
            LocalUser = [string]$sec.LocalUser
            RemoteUser = [string]$sec.RemoteUser
            RemoteMachine = [string]$sec.RemoteMachine
        }
    })

    [PSCustomObject]@{
        Success = $true
        InspectionComplete = $true
        Profiles = $profiles
        Rules = $sampleRules
        Error = $null
    } | ConvertTo-Json -Depth 5
} catch {
    [PSCustomObject]@{
        Success = $false
        InspectionComplete = $false
        Profiles = @()
        Rules = @()
        Error = $_.Exception.Message
    } | ConvertTo-Json -Depth 3
    exit 1
}
"""

    try:
        res = subprocess.run(
            [ps_path, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
            capture_output=True,
            text=True,
            timeout=20,
        )
        if res.returncode != 0:
            err = res.stderr.strip() or res.stdout.strip()
            print(f"ERROR: PowerShell ActiveStore query failed (exit code {res.returncode}): {err}")
            return 1

        output = res.stdout.strip()
        if not output:
            print("ERROR: PowerShell ActiveStore query returned empty output.")
            return 1

        data = json.loads(output)
        if not isinstance(data, dict):
            print("ERROR: Response is not a JSON object envelope.")
            return 1

        if data.get("Success") is not True or data.get("InspectionComplete") is not True:
            print(f"ERROR: ActiveStore inspection envelope reports failure: {data.get('Error')}")
            return 1

        profiles = data.get("Profiles", [])
        rules_data = data.get("Rules", [])

        # 1. Profile Verification
        print(f"\n[1/5] ActiveStore Firewall Profiles ({len(profiles)} detected):")
        seen_profiles = set()
        for p in profiles:
            p_name = str(p.get("Name", "")).strip()
            seen_profiles.add(p_name.lower())
            print(f"  - Profile: {p_name:<10} | Enabled: {p.get('Enabled')} | AllowLocal: {p.get('AllowLocalFirewallRules')}")

        required_profiles = {"domain", "private", "public"}
        missing_profiles = required_profiles - seen_profiles
        if missing_profiles:
            print(f"ERROR: Missing expected firewall profile(s): {sorted(missing_profiles)}")
            return 1
        print("  --> Profile schema and expected entries verified.")

        # 2. Non-empty Rule Sample
        print(f"\n[2/5] Real Windows Firewall Rules Sample:")
        if not rules_data or len(rules_data) == 0:
            print("ERROR: ActiveStore query returned an empty rules sample. At least 1 rule required to verify schema.")
            return 1
        print(f"  --> Retrieved {len(rules_data)} real firewall rules for schema verification.")

        # 3. Output Schema Integrity
        print(f"\n[3/5] Schema Verification across all 7 Filter Categories:")
        for idx, r in enumerate(rules_data):
            missing_fields = REQUIRED_RULE_FIELDS - set(r.keys())
            if missing_fields:
                print(f"ERROR: Sample rule #{idx} ('{r.get('Name')}') missing required schema fields: {sorted(missing_fields)}")
                return 1
        print(f"  --> All {len(rules_data)} rules contain all {len(REQUIRED_RULE_FIELDS)} required fields:")
        print(f"      (App: Program | Addr: Local/RemoteAddress | Port: Protocol/Local/RemotePort |")
        print(f"       Service: Service | Interface: InterfaceAlias/Type |")
        print(f"       Security: Authentication, Encryption, OverrideBlockRules, LocalUser, RemoteUser, RemoteMachine)")

        # 4. Boolean Serialization Verification
        print(f"\n[4/5] Boolean Serialization Verification:")
        for idx, r in enumerate(rules_data):
            obr = r.get("OverrideBlockRules")
            if not isinstance(obr, bool):
                print(f"ERROR: Rule #{idx} ('{r.get('Name')}') OverrideBlockRules is {type(obr).__name__} ({obr!r}), expected bool.")
                return 1
            enabled = r.get("Enabled")
            if not isinstance(enabled, bool):
                print(f"ERROR: Rule #{idx} ('{r.get('Name')}') Enabled is {type(enabled).__name__} ({enabled!r}), expected bool.")
                return 1
        print("  --> NetSecurity CIM boolean properties (OverrideBlockRules, Enabled) verified as genuine booleans.")

        # 5. Parser Execution & Synthetic Rejection Testing
        print(f"\n[5/5] Python Parser & Synthetic Rejection Verification:")
        parsed_rules = parse_powershell_rules_json(rules_data)
        if len(parsed_rules) != len(rules_data):
            print(f"ERROR: parse_powershell_rules_json parsed {len(parsed_rules)} rules, expected {len(rules_data)}.")
            return 1

        for r in parsed_rules:
            if r.override_block_rules is not None and not isinstance(r.override_block_rules, bool):
                print(f"ERROR: Parsed rule '{r.name}' has non-boolean override_block_rules: {r.override_block_rules!r}")
                return 1
        print(f"  --> Successfully parsed {len(parsed_rules)} real rules into FirewallRuleInfo.")

        # Verify that malformed / incomplete synthetic data is rejected
        # Use an unrestricted base so the specific condition under test is the cause of rejection
        test_exe = Path(sys.executable).resolve()
        synthetic_base = {
            "Name": "Tsukiko_Synthetic_Test_Rule",
            "DisplayName": "Tsukiko Synthetic Test Rule",
            "Group": "Tsukiko Desktop Companion",
            "Description": "[Tsukiko-Privacy-Core:Outbound-Block] Test",
            "Enabled": True,
            "Direction": "Outbound",
            "Action": "Block",
            "Profiles": "Domain,Private,Public",
            "Program": str(test_exe),
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

        # Test A: Missing OverrideBlockRules
        corrupt_a = dict(synthetic_base)
        del corrupt_a["OverrideBlockRules"]
        rule_a = parse_powershell_rules_json([corrupt_a])[0]
        if rule_a.override_block_rules is not None:
            print("ERROR: Parser failed to set override_block_rules=None when property was missing.")
            return 1
        ok_a, msg_a = validate_firewall_filters(rule_a, test_exe)
        if ok_a:
            print("ERROR: Validator accepted rule with missing OverrideBlockRules!")
            return 1
        print("  --> Confirmed: Missing OverrideBlockRules is rejected.")

        # Test B: OverrideBlockRules = True (bypass risk)
        corrupt_b = dict(synthetic_base)
        corrupt_b["OverrideBlockRules"] = True
        rule_b = parse_powershell_rules_json([corrupt_b])[0]
        ok_b, msg_b = validate_firewall_filters(rule_b, test_exe)
        if ok_b:
            print("ERROR: Validator accepted rule with OverrideBlockRules=True!")
            return 1
        if "OverrideBlockRules enabled" not in msg_b:
            print(f"ERROR: Unexpected rejection message for OverrideBlockRules=True: {msg_b}")
            return 1
        print("  --> Confirmed: OverrideBlockRules=True is rejected.")

        # Test C: Malformed boolean OverrideBlockRules
        corrupt_c = dict(synthetic_base)
        corrupt_c["OverrideBlockRules"] = "invalid_not_bool"
        rule_c = parse_powershell_rules_json([corrupt_c])[0]
        ok_c, _ = validate_firewall_filters(rule_c, test_exe)
        if ok_c:
            print("ERROR: Validator accepted rule with malformed OverrideBlockRules string!")
            return 1
        print("  --> Confirmed: Malformed boolean OverrideBlockRules is rejected.")

        # Test D: Missing Security property
        corrupt_d = dict(synthetic_base)
        del corrupt_d["Authentication"]
        rule_d = parse_powershell_rules_json([corrupt_d])[0]
        ok_d, _ = validate_firewall_filters(rule_d, test_exe)
        if ok_d:
            print("ERROR: Validator accepted rule with missing Authentication property!")
            return 1
        print("  --> Confirmed: Missing security property (Authentication) is rejected.")

        # Test E: Plural property cannot substitute for singular CIM property
        corrupt_e = dict(synthetic_base)
        del corrupt_e["LocalUser"]
        corrupt_e["LocalUsers"] = "Any"  # deprecated plural
        rule_e = parse_powershell_rules_json([corrupt_e])[0]
        ok_e, _ = validate_firewall_filters(rule_e, test_exe)
        if ok_e:
            print("ERROR: Validator accepted rule where LocalUsers was supplied but LocalUser was absent!")
            return 1
        print("  --> Confirmed: Plural property name (LocalUsers) cannot substitute for singular LocalUser.")

        print("\nAll 5 inspection checks passed successfully.")
        print("Real Windows Firewall policy inspection verified: strictly read-only, NO system mutations.")
        return 0

    except Exception as e:
        print(f"ERROR during read-only inspection verification: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
