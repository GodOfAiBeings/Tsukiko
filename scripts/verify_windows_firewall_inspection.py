"""
Tsukiko Windows Firewall Inspection Verification Script (Read-Only)
Verifies NetSecurity ActiveStore query capability, complete 18-property CIM filter schema
integrity across all 7 categories, lossless field-state serialization, boolean fidelity,
unmanufactured ActiveStore bypass discovery, fail-closed command failure behavior,
and strict response envelope validation on the host system without modifying, adding, or deleting
any firewall rules.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
from typing import Any

from app.core.privacy.windows_firewall import (
    CimFieldRecord,
    CimFieldState,
    FirewallParseError,
    FirewallRuleInfo,
    PS_CIM_SERIALIZER_SNIPPET,
    build_activestore_inspection_powershell_script,
    parse_powershell_rules_json,
    validate_firewall_filters,
    validate_response_envelope,
    DEFAULT_RULE_NAME,
    RULE_GROUPING,
    STABLE_RULE_ID,
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

    target_exe = Path(sys.executable).resolve()

    # -------------------------------------------------------------
    # 1. Production ActiveStore Query & Response Envelope Validation
    # -------------------------------------------------------------
    print("\n[1/6] Production ActiveStore Inspection & Response Envelope Validation:")
    ps_script = build_activestore_inspection_powershell_script()
    env = os.environ.copy()
    env["TSUKIKO_TARGET_RULE_NAME"] = DEFAULT_RULE_NAME
    env["TSUKIKO_TARGET_GROUP"] = RULE_GROUPING
    env["TSUKIKO_STABLE_RULE_ID"] = STABLE_RULE_ID
    env["TSUKIKO_TARGET_EXE"] = str(target_exe)

    try:
        res = subprocess.run(
            [ps_path, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
            capture_output=True,
            text=True,
            timeout=25,
            env=env,
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
        ok, env_err = validate_response_envelope(data, expected_policy_store="ActiveStore")
        if not ok:
            print(f"ERROR: ActiveStore response envelope validation failed: {env_err}")
            return 1

        profiles = data["Profiles"]
        print(f"  --> Response envelope strictly valid (SchemaVersion: 1, PolicyStore: ActiveStore).")
        print(f"  --> ActiveStore Firewall Profiles ({len(profiles)} detected):")
        seen_profiles = set()
        for p in profiles:
            p_name = str(p.get("Name", "")).strip()
            seen_profiles.add(p_name.lower())
            print(f"      - Profile: {p_name:<10} | Enabled: {p.get('Enabled')} | AllowLocal: {p.get('AllowLocalFirewallRules')}")

        required_profiles = {"domain", "private", "public"}
        missing_profiles = required_profiles - seen_profiles
        if missing_profiles:
            print(f"ERROR: Missing expected firewall profile(s): {sorted(missing_profiles)}")
            return 1
        print("  --> Profile schema and expected entries verified.")

        # -------------------------------------------------------------
        # 2. Unmanufactured ActiveStore Bypass Discovery Verification
        # -------------------------------------------------------------
        print("\n[2/6] Unmanufactured ActiveStore Bypass Discovery Verification:")
        bypass_rules = data.get("BypassRules", [])
        if not isinstance(bypass_rules, list):
            print(f"ERROR: BypassRules must be a list, got {type(bypass_rules).__name__}.")
            return 1

        print(f"  --> Discovered {len(bypass_rules)} active bypass rules in ActiveStore for target: {target_exe.name}")
        for b in bypass_rules:
            if not isinstance(b, dict):
                print(f"ERROR: Bypass rule entry is not a dict: {b}")
                return 1
            print(f"      - Candidate: {b.get('Name')} | Scope: {b.get('Scope')} | Program: {b.get('Program')}")
            if b.get("OverrideBlockRules") is not True:
                print(f"ERROR: Bypass rule '{b.get('Name')}' OverrideBlockRules is not True.")
                return 1
        print("  --> ActiveStore bypass discovery query executed successfully without error suppression.")

        # -------------------------------------------------------------
        # 3. Real Associated Filter Objects & Full Schema Coverage
        # -------------------------------------------------------------
        print("\n[3/6] Real Associated Filter Objects & Full 26-Field Schema Coverage:")
        sample_script = PS_CIM_SERIALIZER_SNIPPET + """
$ErrorActionPreference = 'Stop'
try {
    $sampleRules = @(Get-NetFirewallRule -PolicyStore ActiveStore | Select-Object -First 10 | ForEach-Object {
        Get-RuleCimRecord $_
    })
    [PSCustomObject]@{
        SchemaVersion = 1
        Success = $true
        InspectionComplete = $true
        PolicyStore = "ActiveStore"
        Profiles = @()
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
        sample_res = subprocess.run(
            [ps_path, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", sample_script],
            capture_output=True,
            text=True,
            timeout=25,
        )
        if sample_res.returncode != 0:
            print(f"ERROR: Sample rules query failed (exit code {sample_res.returncode}): {sample_res.stderr.strip()}")
            return 1

        sample_data = json.loads(sample_res.stdout.strip())
        ok_sample, sample_env_err = validate_response_envelope(sample_data, expected_policy_store="ActiveStore")
        if not ok_sample:
            print(f"ERROR: Sample rules envelope validation failed: {sample_env_err}")
            return 1

        rules_sample = sample_data["Rules"]
        if not rules_sample or len(rules_sample) == 0:
            print("ERROR: ActiveStore query returned an empty rules sample. At least 1 rule required to verify schema.")
            return 1
        print(f"  --> Retrieved {len(rules_sample)} real firewall rules using production Get-RuleCimRecord serializer.")

        for idx, r in enumerate(rules_sample):
            missing_fields = REQUIRED_RULE_FIELDS - set(r.keys())
            if missing_fields:
                print(f"ERROR: Sample rule #{idx} ('{r.get('Name')}') missing required schema fields: {sorted(missing_fields)}")
                return 1

            for prop in CIM_FILTER_PROPERTIES:
                f_val = r.get(prop)
                if not isinstance(f_val, dict):
                    print(f"ERROR: Rule #{idx} property '{prop}' is not a structured record dict (got {type(f_val).__name__}).")
                    return 1
                if "State" not in f_val or "Exists" not in f_val or "IsNull" not in f_val:
                    print(f"ERROR: Rule #{idx} property '{prop}' missing State/Exists/IsNull in CimFieldRecord: {f_val}")
                    return 1

        print(f"  --> All {len(rules_sample)} rules contain all {len(REQUIRED_RULE_FIELDS)} required fields across all 7 categories:")
        print("      (Category 1 App: Program, Package | Category 2 Addr: LocalAddress, RemoteAddress |")
        print("       Category 3 Port: Protocol, LocalPort, RemotePort, IcmpType, DynamicTarget |")
        print("       Category 4 Service: Service | Category 5 Interface: InterfaceAlias |")
        print("       Category 6 InterfaceType: InterfaceType |")
        print("       Category 7 Security: Authentication, Encryption, OverrideBlockRules, LocalUser, RemoteUser, RemoteMachine)")

        # -------------------------------------------------------------
        # 4. CIM Field-State Consistency & Boolean Fidelity on Real Objects
        # -------------------------------------------------------------
        print("\n[4/6] CIM Field-State Consistency & Boolean Fidelity on Real Objects:")
        for idx, r in enumerate(rules_sample):
            # 1. State Invariant Validation for all 18 properties
            for prop in CIM_FILTER_PROPERTIES:
                f_val = r[prop]
                rec = CimFieldRecord.from_raw(f_val)
                if rec.state == CimFieldState.MALFORMED:
                    print(f"ERROR: Rule #{idx} property '{prop}' parsed as MALFORMED: {f_val}")
                    return 1
                if f_val["State"] == "PROPERTY_PRESENT_WITH_VALID_VALUE":
                    if not (f_val["Exists"] is True and f_val["IsNull"] is False):
                        print(f"ERROR: Rule #{idx} '{prop}' invalid VALID state invariant: {f_val}")
                        return 1
                elif f_val["State"] == "PROPERTY_PRESENT_WITH_NULL":
                    if not (f_val["Exists"] is True and f_val["IsNull"] is True):
                        print(f"ERROR: Rule #{idx} '{prop}' invalid NULL state invariant: {f_val}")
                        return 1
                elif f_val["State"] == "PROPERTY_MISSING":
                    if not (f_val["Exists"] is False and f_val["IsNull"] is True):
                        print(f"ERROR: Rule #{idx} '{prop}' invalid MISSING state invariant: {f_val}")
                        return 1

            # 2. Boolean Fidelity on OverrideBlockRules and Enabled
            obr_rec = r["OverrideBlockRules"]
            obr_val = obr_rec.get("Value")
            if obr_val is not None:
                if not isinstance(obr_val, bool) or isinstance(obr_val, str):
                    print(f"ERROR: Rule #{idx} ('{r.get('Name')}') OverrideBlockRules Value is {type(obr_val).__name__} ({obr_val!r}), expected bool.")
                    return 1
            enabled = r.get("Enabled")
            if not isinstance(enabled, bool):
                print(f"ERROR: Rule #{idx} ('{r.get('Name')}') Enabled is {type(enabled).__name__} ({enabled!r}), expected bool.")
                return 1

        parsed_sample = parse_powershell_rules_json(sample_data, expected_policy_store="ActiveStore")
        if len(parsed_sample) != len(rules_sample):
            print(f"ERROR: parse_powershell_rules_json parsed {len(parsed_sample)} rules, expected {len(rules_sample)}.")
            return 1
        for pr in parsed_sample:
            if pr.override_block_rules is not None and not isinstance(pr.override_block_rules, bool):
                print(f"ERROR: Parsed rule '{pr.name}' has non-boolean override_block_rules: {pr.override_block_rules!r}")
                return 1

        print("  --> All 18 CIM filter properties strictly conform to field-state invariants.")
        print("  --> NetSecurity CIM boolean properties (OverrideBlockRules, Enabled) verified as genuine booleans.")

        # -------------------------------------------------------------
        # 5. Python Parser & Synthetic Rejection Verification
        # -------------------------------------------------------------
        print("\n[5/6] Python Parser & Synthetic Rejection Verification:")
        synthetic_base = {
            "Name": "Tsukiko_Synthetic_Test_Rule",
            "DisplayName": "Tsukiko Synthetic Test Rule",
            "Group": "Tsukiko Desktop Companion",
            "Description": "[Tsukiko-Privacy-Core:Outbound-Block] Test",
            "Enabled": True,
            "Direction": "Outbound",
            "Action": "Block",
            "Profiles": "Domain,Private,Public",
            "Program": str(target_exe),
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
        ok_1, msg_1 = validate_firewall_filters(rule_1, target_exe)
        if ok_1 or "OverrideBlockRules" not in msg_1:
            print(f"ERROR: Expected rejection for missing OverrideBlockRules, got ok={ok_1}, msg={msg_1}")
            return 1
        print("  --> Confirmed: Missing OverrideBlockRules is rejected.")

        # 2. OverrideBlockRules = True (bypass risk)
        corrupt_2 = dict(synthetic_base)
        corrupt_2["OverrideBlockRules"] = True
        rule_2 = parse_powershell_rules_json([corrupt_2])[0]
        ok_2, msg_2 = validate_firewall_filters(rule_2, target_exe)
        if ok_2 or "OverrideBlockRules enabled" not in msg_2:
            print(f"ERROR: Expected rejection for OverrideBlockRules=True, got ok={ok_2}, msg={msg_2}")
            return 1
        print("  --> Confirmed: OverrideBlockRules=True is rejected.")

        # 3. Malformed boolean OverrideBlockRules
        corrupt_3 = dict(synthetic_base)
        corrupt_3["OverrideBlockRules"] = "invalid_not_bool"
        rule_3 = parse_powershell_rules_json([corrupt_3])[0]
        ok_3, msg_3 = validate_firewall_filters(rule_3, target_exe)
        if ok_3 or "OverrideBlockRules" not in msg_3:
            print(f"ERROR: Expected rejection for malformed OverrideBlockRules, got ok={ok_3}, msg={msg_3}")
            return 1
        print("  --> Confirmed: Malformed boolean OverrideBlockRules is rejected.")

        # 4. Missing Package
        corrupt_4 = dict(synthetic_base)
        del corrupt_4["Package"]
        rule_4 = parse_powershell_rules_json([corrupt_4])[0]
        ok_4, msg_4 = validate_firewall_filters(rule_4, target_exe)
        if ok_4 or "Package" not in msg_4:
            print(f"ERROR: Expected rejection for missing Package, got ok={ok_4}, msg={msg_4}")
            return 1
        print("  --> Confirmed: Missing Package is rejected.")

        # 5. Restrictive Package (AppContainer restriction)
        corrupt_5 = dict(synthetic_base)
        corrupt_5["Package"] = "Microsoft.WindowsStore_8wekyb3d8bbwe"
        rule_5 = parse_powershell_rules_json([corrupt_5])[0]
        ok_5, msg_5 = validate_firewall_filters(rule_5, target_exe)
        if ok_5 or "restricts package" not in msg_5:
            print(f"ERROR: Expected rejection for restrictive Package, got ok={ok_5}, msg={msg_5}")
            return 1
        print("  --> Confirmed: Restrictive Package is rejected.")

        # 6. Missing IcmpType
        corrupt_6 = dict(synthetic_base)
        del corrupt_6["IcmpType"]
        rule_6 = parse_powershell_rules_json([corrupt_6])[0]
        ok_6, msg_6 = validate_firewall_filters(rule_6, target_exe)
        if ok_6 or "IcmpType" not in msg_6:
            print(f"ERROR: Expected rejection for missing IcmpType, got ok={ok_6}, msg={msg_6}")
            return 1
        print("  --> Confirmed: Missing IcmpType is rejected.")

        # 7. Restrictive IcmpType (specific ICMP message type)
        corrupt_7 = dict(synthetic_base)
        corrupt_7["IcmpType"] = "8"
        rule_7 = parse_powershell_rules_json([corrupt_7])[0]
        ok_7, msg_7 = validate_firewall_filters(rule_7, target_exe)
        if ok_7 or "restricts ICMP type" not in msg_7:
            print(f"ERROR: Expected rejection for restrictive IcmpType, got ok={ok_7}, msg={msg_7}")
            return 1
        print("  --> Confirmed: Restrictive IcmpType is rejected.")

        # 8. Missing DynamicTarget
        corrupt_8 = dict(synthetic_base)
        del corrupt_8["DynamicTarget"]
        rule_8 = parse_powershell_rules_json([corrupt_8])[0]
        ok_8, msg_8 = validate_firewall_filters(rule_8, target_exe)
        if ok_8 or "DynamicTarget" not in msg_8:
            print(f"ERROR: Expected rejection for missing DynamicTarget, got ok={ok_8}, msg={msg_8}")
            return 1
        print("  --> Confirmed: Missing DynamicTarget is rejected.")

        # 9. Restrictive DynamicTarget
        corrupt_9 = dict(synthetic_base)
        corrupt_9["DynamicTarget"] = "WifiDirectPrinting"
        rule_9 = parse_powershell_rules_json([corrupt_9])[0]
        ok_9, msg_9 = validate_firewall_filters(rule_9, target_exe)
        if ok_9 or "restricts dynamic target" not in msg_9:
            print(f"ERROR: Expected rejection for restrictive DynamicTarget, got ok={ok_9}, msg={msg_9}")
            return 1
        print("  --> Confirmed: Restrictive DynamicTarget is rejected.")

        # 10. Missing Authentication property
        corrupt_10 = dict(synthetic_base)
        del corrupt_10["Authentication"]
        rule_10 = parse_powershell_rules_json([corrupt_10])[0]
        ok_10, msg_10 = validate_firewall_filters(rule_10, target_exe)
        if ok_10 or "Authentication" not in msg_10:
            print(f"ERROR: Expected rejection for missing Authentication, got ok={ok_10}, msg={msg_10}")
            return 1
        print("  --> Confirmed: Missing security property (Authentication) is rejected.")

        # 11. Plural property name substitution
        corrupt_11 = dict(synthetic_base)
        del corrupt_11["LocalUser"]
        corrupt_11["LocalUsers"] = "Any"  # deprecated plural
        rule_11 = parse_powershell_rules_json([corrupt_11])[0]
        ok_11, msg_11 = validate_firewall_filters(rule_11, target_exe)
        if ok_11 or "LocalUser" not in msg_11:
            print(f"ERROR: Expected rejection when LocalUsers is supplied but LocalUser is absent, got ok={ok_11}, msg={msg_11}")
            return 1
        print("  --> Confirmed: Plural property name (LocalUsers) cannot substitute for singular LocalUser.")

        # Envelope Rejection Tests
        env_1 = dict(data)
        del env_1["BypassRules"]
        ok_e1, msg_e1 = validate_response_envelope(env_1, "ActiveStore")
        if ok_e1 or "BypassRules" not in msg_e1:
            print(f"ERROR: Expected envelope rejection for missing BypassRules: ok={ok_e1}, msg={msg_e1}")
            return 1
        print("  --> Confirmed: Envelope missing BypassRules key is strictly rejected.")

        env_2 = dict(data)
        env_2["SchemaVersion"] = 2
        ok_e2, msg_e2 = validate_response_envelope(env_2, "ActiveStore")
        if ok_e2 or "schemaversion: 2" not in msg_e2.lower():
            print(f"ERROR: Expected envelope rejection for SchemaVersion 2: ok={ok_e2}, msg={msg_e2}")
            return 1
        print("  --> Confirmed: Envelope with unsupported SchemaVersion is strictly rejected.")

        env_3 = dict(data)
        env_3["InspectionComplete"] = False
        ok_e3, msg_e3 = validate_response_envelope(env_3, "ActiveStore")
        if ok_e3 or "contradictory envelope state" not in msg_e3.lower():
            print(f"ERROR: Expected envelope rejection for contradictory state: ok={ok_e3}, msg={msg_e3}")
            return 1
        print("  --> Confirmed: Contradictory envelope state (Success=True, InspectionComplete=False) is strictly rejected.")

        env_4 = dict(data)
        ok_e4, msg_e4 = validate_response_envelope(env_4, expected_policy_store="PersistentStore")
        if ok_e4 or "policystore mismatch" not in msg_e4.lower():
            print(f"ERROR: Expected envelope rejection for policy store mismatch: ok={ok_e4}, msg={msg_e4}")
            return 1
        print("  --> Confirmed: PolicyStore mismatch is strictly rejected.")

        # -------------------------------------------------------------
        # 6. Command & Cmdlet Failure Behavior Verification (Fail-Closed)
        # -------------------------------------------------------------
        print("\n[6/6] Command & Cmdlet Failure Behavior Verification (Fail-Closed):")
        # Build synthetic PowerShell script simulating an uncaught NetSecurity cmdlet error
        fail_script = """
$ErrorActionPreference = 'Stop'
try {
    throw "Simulated NetSecurity CIM provider communication failure"
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
        fail_res = subprocess.run(
            [ps_path, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", fail_script],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if fail_res.returncode != 1:
            print(f"ERROR: Expected failing PowerShell script to exit with code 1, got {fail_res.returncode}.")
            return 1

        fail_data = json.loads(fail_res.stdout.strip())
        ok_f, msg_f = validate_response_envelope(fail_data, expected_policy_store="ActiveStore")
        if not ok_f:
            print(f"ERROR: Expected failure envelope structure to be valid, got err={msg_f}")
            return 1
        if fail_data.get("Success") is not False or fail_data.get("InspectionComplete") is not False:
            print(f"ERROR: Expected failure envelope Success=False, InspectionComplete=False, got {fail_data}")
            return 1
        if not fail_data.get("Errors"):
            print(f"ERROR: Expected failure envelope Errors to contain error message, got {fail_data}")
            return 1

        try:
            parse_powershell_rules_json(fail_data, expected_policy_store="ActiveStore")
            print("ERROR: Expected parse_powershell_rules_json to raise FirewallParseError on failure envelope.")
            return 1
        except FirewallParseError as pe:
            print(f"  --> Confirmed: parse_powershell_rules_json raises FirewallParseError on failure envelope ({pe}).")

        print("  --> Confirmed: PowerShell exit code 1 with failure envelope propagates and fails closed.")

        print("\nAll 6 inspection checks passed successfully.")
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
