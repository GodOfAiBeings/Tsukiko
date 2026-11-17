"""
Tsukiko Windows Firewall Inspection Verification Script (Read-Only)
Verifies NetSecurity ActiveStore query capability, complete 18-property CIM filter schema
integrity across all 7 categories, lossless field-state serialization, boolean fidelity,
and fail-closed Python parsing on the host system without modifying, adding, or deleting
any firewall rules.
"""

from __future__ import annotations

import json
from pathlib import Path
import platform
import shutil
import subprocess
import sys

from app.core.privacy.windows_firewall import (
    CimFieldRecord,
    CimFieldState,
    FirewallRuleInfo,
    parse_powershell_rules_json,
    validate_firewall_filters,
)

# 8 Rule Metadata Fields + 18 CIM Filter Properties = 26 Total Schema Fields
REQUIRED_RULE_FIELDS = frozenset({
    "Name",
    "DisplayName",
    "Group",
    "Description",
    "Enabled",
    "Direction",
    "Action",
    "Profiles",
    # Category 1: Application (2)
    "Program",
    "Package",
    # Category 2: Address (2)
    "LocalAddress",
    "RemoteAddress",
    # Category 3: Port & Protocol (5)
    "Protocol",
    "LocalPort",
    "RemotePort",
    "IcmpType",
    "DynamicTarget",
    # Category 4: Service (1)
    "Service",
    # Category 5: Interface (1)
    "InterfaceAlias",
    # Category 6: InterfaceType (1)
    "InterfaceType",
    # Category 7: Security (6)
    "Authentication",
    "Encryption",
    "OverrideBlockRules",
    "LocalUser",
    "RemoteUser",
    "RemoteMachine",
})

CIM_FILTER_PROPERTIES = frozenset({
    "Program",
    "Package",
    "LocalAddress",
    "RemoteAddress",
    "Protocol",
    "LocalPort",
    "RemotePort",
    "IcmpType",
    "DynamicTarget",
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

function Get-CimFieldRecord($Obj, $PropName) {
    if ($null -eq $Obj) {
        return [PSCustomObject]@{
            State = "PROPERTY_MISSING"
            Exists = $false
            IsNull = $true
            Value = $null
            StringValue = $null
            Type = "None"
        }
    }
    $prop = $Obj.PSObject.Properties[$PropName]
    if ($null -eq $prop) {
        return [PSCustomObject]@{
            State = "PROPERTY_MISSING"
            Exists = $false
            IsNull = $true
            Value = $null
            StringValue = $null
            Type = "None"
        }
    }
    $val = $prop.Value
    if ($null -eq $val) {
        return [PSCustomObject]@{
            State = "PROPERTY_PRESENT_WITH_NULL"
            Exists = $true
            IsNull = $true
            Value = $null
            StringValue = $null
            Type = "Null"
        }
    }
    if ($val -is [System.Array]) {
        $strVal = ($val | ForEach-Object { [string]$_ }) -join ','
        return [PSCustomObject]@{
            State = "PROPERTY_PRESENT_WITH_VALID_VALUE"
            Exists = $true
            IsNull = $false
            Value = @($val)
            StringValue = $strVal
            Type = "Array"
        }
    }
    if ($val -is [bool]) {
        return [PSCustomObject]@{
            State = "PROPERTY_PRESENT_WITH_VALID_VALUE"
            Exists = $true
            IsNull = $false
            Value = [bool]$val
            StringValue = if ($val) { "True" } else { "False" }
            Type = "Boolean"
        }
    }
    if ($val -is [int] -or $val -is [long] -or $val -is [byte]) {
        return [PSCustomObject]@{
            State = "PROPERTY_PRESENT_WITH_VALID_VALUE"
            Exists = $true
            IsNull = $false
            Value = [int]$val
            StringValue = [string]$val
            Type = "Integer"
        }
    }
    return [PSCustomObject]@{
        State = "PROPERTY_PRESENT_WITH_VALID_VALUE"
        Exists = $true
        IsNull = $false
        Value = [string]$val
        StringValue = [string]$val
        Type = "String"
    }
}

try {
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name, Enabled, AllowLocalFirewallRules)
    $sampleRules = @(Get-NetFirewallRule -PolicyStore ActiveStore | Select-Object -First 10 | ForEach-Object {
        $r = $_

        $apps = @(Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $r)
        if ($apps.Count -ne 1) { throw "Application filter association failure for rule '$($r.Name)'" }
        $app = $apps[0]

        $addrs = @(Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $r)
        if ($addrs.Count -ne 1) { throw "Address filter association failure for rule '$($r.Name)'" }
        $addr = $addrs[0]

        $ports = @(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $r)
        if ($ports.Count -ne 1) { throw "Port filter association failure for rule '$($r.Name)'" }
        $port = $ports[0]

        $svcs = @(Get-NetFirewallServiceFilter -AssociatedNetFirewallRule $r)
        if ($svcs.Count -ne 1) { throw "Service filter association failure for rule '$($r.Name)'" }
        $svc = $svcs[0]

        $ifaces = @(Get-NetFirewallInterfaceFilter -AssociatedNetFirewallRule $r)
        if ($ifaces.Count -ne 1) { throw "Interface filter association failure for rule '$($r.Name)'" }
        $iface = $ifaces[0]

        $iftypes = @(Get-NetFirewallInterfaceTypeFilter -AssociatedNetFirewallRule $r)
        if ($iftypes.Count -ne 1) { throw "InterfaceType filter association failure for rule '$($r.Name)'" }
        $iftype = $iftypes[0]

        $secs = @(Get-NetFirewallSecurityFilter -AssociatedNetFirewallRule $r)
        if ($secs.Count -ne 1) { throw "Security filter association failure for rule '$($r.Name)'" }
        $sec = $secs[0]

        $profStr = if ($r.Profile -is [System.Array]) { ($r.Profile | ForEach-Object { [string]$_ }) -join ',' } elseif ($null -ne $r.Profile) { [string]$r.Profile } else { "" }

        [PSCustomObject]@{
            Name = [string]$r.Name
            DisplayName = [string]$r.DisplayName
            Group = [string]$r.DisplayGroup
            Description = [string]$r.Description
            Enabled = [bool]$r.Enabled
            Direction = [string]$r.Direction
            Action = [string]$r.Action
            Profiles = $profStr
            Program = Get-CimFieldRecord $app "Program"
            Package = Get-CimFieldRecord $app "Package"
            LocalAddress = Get-CimFieldRecord $addr "LocalAddress"
            RemoteAddress = Get-CimFieldRecord $addr "RemoteAddress"
            Protocol = Get-CimFieldRecord $port "Protocol"
            LocalPort = Get-CimFieldRecord $port "LocalPort"
            RemotePort = Get-CimFieldRecord $port "RemotePort"
            IcmpType = Get-CimFieldRecord $port "IcmpType"
            DynamicTarget = Get-CimFieldRecord $port "DynamicTarget"
            Service = Get-CimFieldRecord $svc "Service"
            InterfaceAlias = Get-CimFieldRecord $iface "InterfaceAlias"
            InterfaceType = Get-CimFieldRecord $iftype "InterfaceType"
            Authentication = Get-CimFieldRecord $sec "Authentication"
            Encryption = Get-CimFieldRecord $sec "Encryption"
            OverrideBlockRules = Get-CimFieldRecord $sec "OverrideBlockRules"
            LocalUser = Get-CimFieldRecord $sec "LocalUser"
            RemoteUser = Get-CimFieldRecord $sec "RemoteUser"
            RemoteMachine = Get-CimFieldRecord $sec "RemoteMachine"
        }
    })

    [PSCustomObject]@{
        SchemaVersion = 1
        Success = $true
        InspectionComplete = $true
        PolicyStore = "ActiveStore"
        Profiles = $profiles
        Rules = $sampleRules
        BypassRules = @()
        Errors = @()
    } | ConvertTo-Json -Depth 6
} catch {
    [PSCustomObject]@{
        SchemaVersion = 1
        Success = $false
        InspectionComplete = $false
        PolicyStore = "ActiveStore"
        Profiles = @()
        Rules = @()
        BypassRules = @()
        Errors = @($_.Exception.Message)
    } | ConvertTo-Json -Depth 3
    exit 1
}
"""

    try:
        res = subprocess.run(
            [ps_path, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
            capture_output=True,
            text=True,
            timeout=25,
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

        if data.get("SchemaVersion") != 1:
            print(f"ERROR: Response envelope has unexpected SchemaVersion: {data.get('SchemaVersion')} (expected 1).")
            return 1

        if data.get("Success") is not True or data.get("InspectionComplete") is not True:
            errs = data.get("Errors") or [data.get("Error")]
            print(f"ERROR: ActiveStore inspection envelope reports failure: {errs}")
            return 1

        profiles = data.get("Profiles", [])
        rules_data = data.get("Rules", [])

        # -------------------------------------------------------------
        # 1. Profile Verification
        # -------------------------------------------------------------
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

        # -------------------------------------------------------------
        # 2. Non-empty Rule Sample
        # -------------------------------------------------------------
        print(f"\n[2/5] Real Windows Firewall Rules Sample:")
        if not rules_data or len(rules_data) == 0:
            print("ERROR: ActiveStore query returned an empty rules sample. At least 1 rule required to verify schema.")
            return 1
        print(f"  --> Retrieved {len(rules_data)} real firewall rules for schema verification.")

        # -------------------------------------------------------------
        # 3. Output Schema Integrity
        # -------------------------------------------------------------
        print(f"\n[3/5] Schema Verification across all 18 Filter Properties (26 total fields):")
        for idx, r in enumerate(rules_data):
            missing_fields = REQUIRED_RULE_FIELDS - set(r.keys())
            if missing_fields:
                print(f"ERROR: Sample rule #{idx} ('{r.get('Name')}') missing required schema fields: {sorted(missing_fields)}")
                return 1

            # Validate that each of the 18 filter fields is serialized as a structured CimFieldRecord
            for prop in CIM_FILTER_PROPERTIES:
                f_val = r.get(prop)
                if not isinstance(f_val, dict):
                    print(f"ERROR: Rule #{idx} property '{prop}' is not a structured record dict (got {type(f_val).__name__}).")
                    return 1
                if "State" not in f_val or "Exists" not in f_val or "IsNull" not in f_val:
                    print(f"ERROR: Rule #{idx} property '{prop}' missing State/Exists/IsNull in CimFieldRecord: {f_val}")
                    return 1

        print(f"  --> All {len(rules_data)} rules contain all {len(REQUIRED_RULE_FIELDS)} required fields:")
        print("      (Category 1 App: Program, Package | Category 2 Addr: LocalAddress, RemoteAddress |")
        print("       Category 3 Port: Protocol, LocalPort, RemotePort, IcmpType, DynamicTarget |")
        print("       Category 4 Service: Service | Category 5 Interface: InterfaceAlias |")
        print("       Category 6 InterfaceType: InterfaceType |")
        print("       Category 7 Security: Authentication, Encryption, OverrideBlockRules, LocalUser, RemoteUser, RemoteMachine)")

        # -------------------------------------------------------------
        # 4. Boolean Serialization Verification
        # -------------------------------------------------------------
        print(f"\n[4/5] Boolean Serialization Verification:")
        for idx, r in enumerate(rules_data):
            obr_rec = r.get("OverrideBlockRules")
            if not isinstance(obr_rec, dict):
                print(f"ERROR: Rule #{idx} OverrideBlockRules is not a structured record dict.")
                return 1
            obr_val = obr_rec.get("Value")
            if obr_val is not None and not isinstance(obr_val, bool):
                print(f"ERROR: Rule #{idx} ('{r.get('Name')}') OverrideBlockRules Value is {type(obr_val).__name__} ({obr_val!r}), expected bool.")
                return 1
            enabled = r.get("Enabled")
            if not isinstance(enabled, bool):
                print(f"ERROR: Rule #{idx} ('{r.get('Name')}') Enabled is {type(enabled).__name__} ({enabled!r}), expected bool.")
                return 1
        print("  --> NetSecurity CIM boolean properties (OverrideBlockRules, Enabled) verified as genuine booleans.")

        # -------------------------------------------------------------
        # 5. Parser Execution & Synthetic Rejection Testing
        # -------------------------------------------------------------
        print(f"\n[5/5] Python Parser & Synthetic Rejection Verification:")
        parsed_rules = parse_powershell_rules_json(data)
        if len(parsed_rules) != len(rules_data):
            print(f"ERROR: parse_powershell_rules_json parsed {len(parsed_rules)} rules, expected {len(rules_data)}.")
            return 1

        for r in parsed_rules:
            if r.override_block_rules is not None and not isinstance(r.override_block_rules, bool):
                print(f"ERROR: Parsed rule '{r.name}' has non-boolean override_block_rules: {r.override_block_rules!r}")
                return 1
        print(f"  --> Successfully parsed {len(parsed_rules)} real rules into FirewallRuleInfo.")

        # Synthetic Rejection Suite: test all 18-property and schema failure modes
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

        # 1. Missing OverrideBlockRules
        corrupt_1 = dict(synthetic_base)
        del corrupt_1["OverrideBlockRules"]
        rule_1 = parse_powershell_rules_json([corrupt_1])[0]
        ok_1, msg_1 = validate_firewall_filters(rule_1, test_exe)
        if ok_1 or "OverrideBlockRules" not in msg_1:
            print(f"ERROR: Expected rejection for missing OverrideBlockRules, got ok={ok_1}, msg={msg_1}")
            return 1
        print("  --> Confirmed: Missing OverrideBlockRules is rejected.")

        # 2. OverrideBlockRules = True (bypass risk)
        corrupt_2 = dict(synthetic_base)
        corrupt_2["OverrideBlockRules"] = True
        rule_2 = parse_powershell_rules_json([corrupt_2])[0]
        ok_2, msg_2 = validate_firewall_filters(rule_2, test_exe)
        if ok_2 or "OverrideBlockRules enabled" not in msg_2:
            print(f"ERROR: Expected rejection for OverrideBlockRules=True, got ok={ok_2}, msg={msg_2}")
            return 1
        print("  --> Confirmed: OverrideBlockRules=True is rejected.")

        # 3. Malformed boolean OverrideBlockRules
        corrupt_3 = dict(synthetic_base)
        corrupt_3["OverrideBlockRules"] = "invalid_not_bool"
        rule_3 = parse_powershell_rules_json([corrupt_3])[0]
        ok_3, msg_3 = validate_firewall_filters(rule_3, test_exe)
        if ok_3 or "OverrideBlockRules" not in msg_3:
            print(f"ERROR: Expected rejection for malformed OverrideBlockRules, got ok={ok_3}, msg={msg_3}")
            return 1
        print("  --> Confirmed: Malformed boolean OverrideBlockRules is rejected.")

        # 4. Missing Package
        corrupt_4 = dict(synthetic_base)
        del corrupt_4["Package"]
        rule_4 = parse_powershell_rules_json([corrupt_4])[0]
        ok_4, msg_4 = validate_firewall_filters(rule_4, test_exe)
        if ok_4 or "Package" not in msg_4:
            print(f"ERROR: Expected rejection for missing Package, got ok={ok_4}, msg={msg_4}")
            return 1
        print("  --> Confirmed: Missing Package is rejected.")

        # 5. Restrictive Package (AppContainer restriction)
        corrupt_5 = dict(synthetic_base)
        corrupt_5["Package"] = "Microsoft.WindowsStore_8wekyb3d8bbwe"
        rule_5 = parse_powershell_rules_json([corrupt_5])[0]
        ok_5, msg_5 = validate_firewall_filters(rule_5, test_exe)
        if ok_5 or "restricts package" not in msg_5:
            print(f"ERROR: Expected rejection for restrictive Package, got ok={ok_5}, msg={msg_5}")
            return 1
        print("  --> Confirmed: Restrictive Package is rejected.")

        # 6. Missing IcmpType
        corrupt_6 = dict(synthetic_base)
        del corrupt_6["IcmpType"]
        rule_6 = parse_powershell_rules_json([corrupt_6])[0]
        ok_6, msg_6 = validate_firewall_filters(rule_6, test_exe)
        if ok_6 or "IcmpType" not in msg_6:
            print(f"ERROR: Expected rejection for missing IcmpType, got ok={ok_6}, msg={msg_6}")
            return 1
        print("  --> Confirmed: Missing IcmpType is rejected.")

        # 7. Restrictive IcmpType (specific ICMP message type)
        corrupt_7 = dict(synthetic_base)
        corrupt_7["IcmpType"] = "8"
        rule_7 = parse_powershell_rules_json([corrupt_7])[0]
        ok_7, msg_7 = validate_firewall_filters(rule_7, test_exe)
        if ok_7 or "restricts ICMP type" not in msg_7:
            print(f"ERROR: Expected rejection for restrictive IcmpType, got ok={ok_7}, msg={msg_7}")
            return 1
        print("  --> Confirmed: Restrictive IcmpType is rejected.")

        # 8. Missing DynamicTarget
        corrupt_8 = dict(synthetic_base)
        del corrupt_8["DynamicTarget"]
        rule_8 = parse_powershell_rules_json([corrupt_8])[0]
        ok_8, msg_8 = validate_firewall_filters(rule_8, test_exe)
        if ok_8 or "DynamicTarget" not in msg_8:
            print(f"ERROR: Expected rejection for missing DynamicTarget, got ok={ok_8}, msg={msg_8}")
            return 1
        print("  --> Confirmed: Missing DynamicTarget is rejected.")

        # 9. Restrictive DynamicTarget
        corrupt_9 = dict(synthetic_base)
        corrupt_9["DynamicTarget"] = "WifiDirectPrinting"
        rule_9 = parse_powershell_rules_json([corrupt_9])[0]
        ok_9, msg_9 = validate_firewall_filters(rule_9, test_exe)
        if ok_9 or "restricts dynamic target" not in msg_9:
            print(f"ERROR: Expected rejection for restrictive DynamicTarget, got ok={ok_9}, msg={msg_9}")
            return 1
        print("  --> Confirmed: Restrictive DynamicTarget is rejected.")

        # 10. Missing Authentication property
        corrupt_10 = dict(synthetic_base)
        del corrupt_10["Authentication"]
        rule_10 = parse_powershell_rules_json([corrupt_10])[0]
        ok_10, msg_10 = validate_firewall_filters(rule_10, test_exe)
        if ok_10 or "Authentication" not in msg_10:
            print(f"ERROR: Expected rejection for missing Authentication, got ok={ok_10}, msg={msg_10}")
            return 1
        print("  --> Confirmed: Missing security property (Authentication) is rejected.")

        # 11. Plural property name substitution
        corrupt_11 = dict(synthetic_base)
        del corrupt_11["LocalUser"]
        corrupt_11["LocalUsers"] = "Any"  # deprecated plural
        rule_11 = parse_powershell_rules_json([corrupt_11])[0]
        ok_11, msg_11 = validate_firewall_filters(rule_11, test_exe)
        if ok_11 or "LocalUser" not in msg_11:
            print(f"ERROR: Expected rejection when LocalUsers is supplied but LocalUser is absent, got ok={ok_11}, msg={msg_11}")
            return 1
        print("  --> Confirmed: Plural property name (LocalUsers) cannot substitute for singular LocalUser.")

        print("\nAll 5 inspection checks passed successfully.")
        print("Real Windows Firewall policy inspection verified: strictly read-only, NO system mutations.")
        return 0
    except subprocess.TimeoutExpired:
        print("ERROR: PowerShell ActiveStore query timed out.")
        return 1
    except Exception as e:
        print(f"ERROR: Inspection script encountered an unexpected exception: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
