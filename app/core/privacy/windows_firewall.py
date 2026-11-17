"""
Tsukiko Windows Firewall Policy Manager
Provides safe, application-specific OS-level outbound firewall rule management and status inspection.
Enforces strict structural PE validation, fail-closed profile verification, precise rule ownership,
safe deletion, effective policy inspection in the ActiveStore, full Microsoft NetSecurity CIM filter
schema coverage across all 18 properties, lossless field-state serialization, and bypass evaluation.

Note on Executable Identity:
Structural PE binary validation confirms that the file is formatted as a valid Windows PE binary.
It is NOT cryptographic proof of application identity (e.g. Authenticode certificate verification).
Real cryptographic verification requires an established code-signing certificate infrastructure.
"""

from __future__ import annotations

from enum import Enum
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


class FirewallParseError(ValueError):
    """Raised when firewall query output violates schema, is malformed, or cannot be parsed."""
    pass


class CimFieldState(str, Enum):
    """Explicit field state classification for Microsoft NetSecurity CIM filter properties."""
    VALID = "PROPERTY_PRESENT_WITH_VALID_VALUE"
    NULL = "PROPERTY_PRESENT_WITH_NULL"
    MISSING = "PROPERTY_MISSING"
    MALFORMED = "PROPERTY_PRESENT_WITH_MALFORMED_VALUE"


class CimFieldRecord(BaseModel):
    """Structured field record representing a Microsoft NetSecurity CIM property."""
    state: CimFieldState
    exists: bool
    is_null: bool
    value: Any = None
    string_value: Optional[str] = None
    type_name: str = "None"

    @classmethod
    def valid(cls, value: Any, string_value: Optional[str] = None, type_name: str = "String") -> CimFieldRecord:
        if string_value is None and value is not None:
            if isinstance(value, bool):
                string_value = "True" if value else "False"
            elif isinstance(value, list):
                string_value = ",".join(str(x) for x in value)
            else:
                string_value = str(value)
        return cls(
            state=CimFieldState.VALID,
            exists=True,
            is_null=False,
            value=value,
            string_value=string_value,
            type_name=type_name,
        )

    @classmethod
    def null(cls, type_name: str = "Null") -> CimFieldRecord:
        return cls(
            state=CimFieldState.NULL,
            exists=True,
            is_null=True,
            value=None,
            string_value=None,
            type_name=type_name,
        )

    @classmethod
    def missing(cls) -> CimFieldRecord:
        return cls(
            state=CimFieldState.MISSING,
            exists=False,
            is_null=True,
            value=None,
            string_value=None,
            type_name="None",
        )

    @classmethod
    def malformed(cls, value: Any = None, string_value: Optional[str] = None) -> CimFieldRecord:
        return cls(
            state=CimFieldState.MALFORMED,
            exists=True,
            is_null=False,
            value=value,
            string_value=string_value or (str(value) if value is not None else None),
            type_name="Malformed",
        )

    @classmethod
    def from_raw(cls, raw: Any) -> CimFieldRecord:
        if isinstance(raw, CimFieldRecord):
            return raw
        if isinstance(raw, dict):
            state_val = raw.get("State")
            if state_val is None:
                state_val = raw.get("state")
            if state_val is None:
                return cls.malformed(raw, str(raw))
            try:
                state_enum = CimFieldState(state_val)
            except ValueError:
                return cls.malformed(raw, str(raw))

            exists_raw = raw.get("Exists") if "Exists" in raw else raw.get("exists")
            if type(exists_raw) is not bool:
                return cls.malformed(raw, f"Non-boolean Exists field: {exists_raw!r}")
            exists = exists_raw

            is_null_raw = raw.get("IsNull") if "IsNull" in raw else raw.get("is_null")
            if type(is_null_raw) is not bool:
                return cls.malformed(raw, f"Non-boolean IsNull field: {is_null_raw!r}")
            is_null = is_null_raw

            val = raw.get("Value") if "Value" in raw else raw.get("value")
            str_val = raw.get("StringValue") if "StringValue" in raw else raw.get("string_value")
            t_name = str(raw.get("Type") or raw.get("type_name") or "None")

            # Validate consistency between State, Exists, IsNull, Value, StringValue
            if state_enum == CimFieldState.VALID:
                if exists is not True or is_null is not False or val is None:
                    return cls.malformed(val, f"Contradictory VALID state: exists={exists}, is_null={is_null}, value={val!r}")
                if str_val is None or not isinstance(str_val, str):
                    return cls.malformed(val, f"Missing, null, or non-string StringValue for VALID state: {str_val!r}")
                if isinstance(val, str):
                    if val.strip().lower() != str_val.strip().lower():
                        return cls.malformed(val, f"Contradictory Value and StringValue for VALID state: Value={val!r}, StringValue={str_val!r}")
                elif isinstance(val, list):
                    joined_val = ",".join(str(x) for x in val).strip().lower()
                    if joined_val != str_val.strip().lower():
                        return cls.malformed(val, f"Contradictory Array Value and StringValue for VALID state: Value={val!r}, StringValue={str_val!r}")
                elif isinstance(val, bool):
                    expected_str = "true" if val else "false"
                    if str_val.strip().lower() != expected_str:
                        return cls.malformed(val, f"Contradictory Boolean Value and StringValue for VALID state: Value={val!r}, StringValue={str_val!r}")
                elif isinstance(val, (int, float)):
                    if str(val).strip().lower() != str_val.strip().lower():
                        return cls.malformed(val, f"Contradictory Numeric Value and StringValue for VALID state: Value={val!r}, StringValue={str_val!r}")
            elif state_enum == CimFieldState.NULL:
                if exists is not True or is_null is not True or val is not None:
                    return cls.malformed(val, f"Contradictory NULL state: exists={exists}, is_null={is_null}, value={val!r}")
                if str_val is not None and str_val != "":
                    return cls.malformed(val, f"Contradictory NULL state: non-empty string_value={str_val!r}")
            elif state_enum == CimFieldState.MISSING:
                if exists is not False or is_null is not True or val is not None:
                    return cls.malformed(val, f"Contradictory MISSING state: exists={exists}, is_null={is_null}, value={val!r}")
                if str_val is not None and str_val != "":
                    return cls.malformed(val, f"Contradictory MISSING state: non-empty string_value={str_val!r}")
            elif state_enum == CimFieldState.MALFORMED:
                pass

            return cls(
                state=state_enum,
                exists=exists,
                is_null=is_null,
                value=val,
                string_value=str_val,
                type_name=t_name,
            )
        if raw is None:
            return cls.null()
        if type(raw) is bool:
            return cls.valid(raw, "True" if raw else "False", "Boolean")
        if isinstance(raw, (int, float)):
            return cls.valid(raw, str(raw), "Integer" if isinstance(raw, int) else "Float")
        if isinstance(raw, list):
            return cls.valid(raw, ",".join(str(x) for x in raw), "Array")
        if isinstance(raw, str):
            return cls.valid(raw, raw, "String")
        return cls.valid(raw, str(raw), type(raw).__name__)


REQUIRED_ENVELOPE_KEYS = (
    "SchemaVersion",
    "Success",
    "InspectionComplete",
    "PolicyStore",
    "Profiles",
    "Rules",
    "BypassRules",
    "Errors",
)


def validate_response_envelope(
    data: Any,
    expected_policy_store: Optional[str] = None,
) -> tuple[bool, str]:
    """Strictly validates that a response envelope conforms to the versioned NetSecurity schema.

    Requirements:
    - data is a dict
    - SchemaVersion: exactly integer 1 (type(SchemaVersion) is int)
    - Success: actual Boolean (type(Success) is bool)
    - InspectionComplete: actual Boolean (type(InspectionComplete) is bool)
    - PolicyStore: string matching expected_policy_store if provided
    - Profiles: list
    - Rules: list
    - BypassRules: list
    - Errors: list
    - No required field is null
    - No contradictory states (Success != InspectionComplete, Success=True with non-empty Errors)
    """
    if not isinstance(data, dict):
        return False, f"Expected response envelope JSON object, got {type(data).__name__}."

    # 1. Missing fields check
    missing = [k for k in REQUIRED_ENVELOPE_KEYS if k not in data]
    if missing:
        return False, f"Incomplete response envelope: missing required fields {missing}."

    # 2. Null values check
    null_keys = [k for k in REQUIRED_ENVELOPE_KEYS if data[k] is None]
    if null_keys:
        return False, f"Response envelope contains null for required fields: {null_keys}."

    # 3. SchemaVersion validation
    schema_ver = data["SchemaVersion"]
    if type(schema_ver) is not int:
        return False, f"SchemaVersion must be an integer, got {type(schema_ver).__name__}."
    if schema_ver != 1:
        return False, f"Unsupported SchemaVersion: {schema_ver} (expected 1)."

    # 4. Success and InspectionComplete boolean validation
    success = data["Success"]
    if type(success) is not bool:
        return False, f"Success must be a boolean, got {type(success).__name__}."

    inspection_complete = data["InspectionComplete"]
    if type(inspection_complete) is not bool:
        return False, f"InspectionComplete must be a boolean, got {type(inspection_complete).__name__}."

    # Contradictory success states
    if success is True and inspection_complete is not True:
        return False, "Contradictory envelope state: Success is True but InspectionComplete is False."
    if success is False and inspection_complete is not False:
        return False, "Contradictory envelope state: Success is False but InspectionComplete is True."

    # 5. PolicyStore validation
    p_store = data["PolicyStore"]
    if not isinstance(p_store, str):
        return False, f"PolicyStore must be a string, got {type(p_store).__name__}."
    if expected_policy_store:
        if p_store.strip().lower() != expected_policy_store.strip().lower():
            return False, f"PolicyStore mismatch: got '{p_store}', expected '{expected_policy_store}'."

    # 6. List fields validation
    profiles = data["Profiles"]
    if not isinstance(profiles, list):
        return False, f"Profiles must be a list, got {type(profiles).__name__}."

    rules = data["Rules"]
    if not isinstance(rules, list):
        return False, f"Rules must be a list, got {type(rules).__name__}."

    bypass_rules = data["BypassRules"]
    if not isinstance(bypass_rules, list):
        return False, f"BypassRules must be a list, got {type(bypass_rules).__name__}."

    errors = data["Errors"]
    if not isinstance(errors, list):
        return False, f"Errors must be a list, got {type(errors).__name__}."

    if success is True and len(errors) > 0:
        return False, f"Contradictory envelope state: Success is True but Errors is non-empty: {errors}."

    return True, "Response envelope is valid."


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


_CIM_FILTER_MAP: dict[str, str] = {
    "program": "program_field",
    "package": "package_field",
    "local_address": "local_address_field",
    "remote_address": "remote_address_field",
    "protocol": "protocol_field",
    "local_port": "local_port_field",
    "remote_port": "remote_port_field",
    "icmp_type": "icmp_type_field",
    "dynamic_target": "dynamic_target_field",
    "service": "service_field",
    "interface_alias": "interface_alias_field",
    "interface_type": "interface_type_field",
    "authentication": "authentication_field",
    "encryption": "encryption_field",
    "override_block_rules": "override_block_rules_field",
    "local_user": "local_user_field",
    "remote_user": "remote_user_field",
    "remote_machine": "remote_machine_field",
}


class FirewallRuleInfo(BaseModel):
    """Complete representation of a Windows Firewall rule across all 18 NetSecurity filter properties."""
    name: str = ""
    display_name: str = ""
    group: str = ""
    description: str = ""
    enabled: bool = False
    direction: str = ""
    action: str = ""
    profiles: Optional[str] = None

    # Category 1: Application Filter (MSFT_NetFirewallRuleFilterByApplication)
    program_field: CimFieldRecord = Field(default_factory=CimFieldRecord.missing)
    package_field: CimFieldRecord = Field(default_factory=CimFieldRecord.missing)

    # Category 2: Address Filter (MSFT_NetFirewallRuleFilterByAddress)
    local_address_field: CimFieldRecord = Field(default_factory=CimFieldRecord.missing)
    remote_address_field: CimFieldRecord = Field(default_factory=CimFieldRecord.missing)

    # Category 3: Port Filter (MSFT_NetFirewallRuleFilterByPort)
    protocol_field: CimFieldRecord = Field(default_factory=CimFieldRecord.missing)
    local_port_field: CimFieldRecord = Field(default_factory=CimFieldRecord.missing)
    remote_port_field: CimFieldRecord = Field(default_factory=CimFieldRecord.missing)
    icmp_type_field: CimFieldRecord = Field(default_factory=CimFieldRecord.missing)
    dynamic_target_field: CimFieldRecord = Field(default_factory=CimFieldRecord.missing)

    # Category 4: Service Filter (MSFT_NetFirewallRuleFilterByService)
    service_field: CimFieldRecord = Field(default_factory=CimFieldRecord.missing)

    # Category 5: Interface Filter (MSFT_NetFirewallRuleFilterByInterface)
    interface_alias_field: CimFieldRecord = Field(default_factory=CimFieldRecord.missing)

    # Category 6: Interface Type Filter (MSFT_NetFirewallRuleFilterByInterfaceType)
    interface_type_field: CimFieldRecord = Field(default_factory=CimFieldRecord.missing)

    # Category 7: Security Filter (MSFT_NetFirewallRuleFilterBySecurity)
    authentication_field: CimFieldRecord = Field(default_factory=CimFieldRecord.missing)
    encryption_field: CimFieldRecord = Field(default_factory=CimFieldRecord.missing)
    override_block_rules_field: CimFieldRecord = Field(default_factory=CimFieldRecord.missing)
    local_user_field: CimFieldRecord = Field(default_factory=CimFieldRecord.missing)
    remote_user_field: CimFieldRecord = Field(default_factory=CimFieldRecord.missing)
    remote_machine_field: CimFieldRecord = Field(default_factory=CimFieldRecord.missing)

    raw_properties: dict[str, Any] = Field(default_factory=dict)

    def __init__(self, **data: Any):
        # Convert any scalar or field kwargs into CimFieldRecord instances
        for prop_name, field_name in _CIM_FILTER_MAP.items():
            if field_name in data:
                data[field_name] = CimFieldRecord.from_raw(data[field_name])
            elif prop_name in data:
                val = data.pop(prop_name)
                data[field_name] = CimFieldRecord.from_raw(val)
            else:
                data[field_name] = CimFieldRecord.missing()
        super().__init__(**data)

    # Property accessors for callers and existing code
    @property
    def program(self) -> Optional[str]:
        return self.program_field.string_value if self.program_field.exists and not self.program_field.is_null else None

    @property
    def package(self) -> Optional[str]:
        return self.package_field.string_value if self.package_field.exists and not self.package_field.is_null else None

    @property
    def local_address(self) -> Optional[str]:
        return self.local_address_field.string_value if self.local_address_field.exists and not self.local_address_field.is_null else None

    @property
    def remote_address(self) -> Optional[str]:
        return self.remote_address_field.string_value if self.remote_address_field.exists and not self.remote_address_field.is_null else None

    @property
    def protocol(self) -> Optional[str]:
        return self.protocol_field.string_value if self.protocol_field.exists and not self.protocol_field.is_null else None

    @property
    def local_port(self) -> Optional[str]:
        return self.local_port_field.string_value if self.local_port_field.exists and not self.local_port_field.is_null else None

    @property
    def remote_port(self) -> Optional[str]:
        return self.remote_port_field.string_value if self.remote_port_field.exists and not self.remote_port_field.is_null else None

    @property
    def icmp_type(self) -> Optional[str]:
        return self.icmp_type_field.string_value if self.icmp_type_field.exists and not self.icmp_type_field.is_null else None

    @property
    def dynamic_target(self) -> Optional[str]:
        return self.dynamic_target_field.string_value if self.dynamic_target_field.exists and not self.dynamic_target_field.is_null else None

    @property
    def service(self) -> Optional[str]:
        return self.service_field.string_value if self.service_field.exists and not self.service_field.is_null else None

    @property
    def interface_alias(self) -> Optional[str]:
        return self.interface_alias_field.string_value if self.interface_alias_field.exists and not self.interface_alias_field.is_null else None

    @property
    def interface_type(self) -> Optional[str]:
        return self.interface_type_field.string_value if self.interface_type_field.exists and not self.interface_type_field.is_null else None

    @property
    def authentication(self) -> Optional[str]:
        return self.authentication_field.string_value if self.authentication_field.exists and not self.authentication_field.is_null else None

    @property
    def encryption(self) -> Optional[str]:
        return self.encryption_field.string_value if self.encryption_field.exists and not self.encryption_field.is_null else None

    @property
    def override_block_rules(self) -> Any:
        if not self.override_block_rules_field.exists or self.override_block_rules_field.is_null:
            return None
        return self.override_block_rules_field.value

    @property
    def local_user(self) -> Optional[str]:
        return self.local_user_field.string_value if self.local_user_field.exists and not self.local_user_field.is_null else None

    @property
    def remote_user(self) -> Optional[str]:
        return self.remote_user_field.string_value if self.remote_user_field.exists and not self.remote_user_field.is_null else None

    @property
    def remote_machine(self) -> Optional[str]:
        return self.remote_machine_field.string_value if self.remote_machine_field.exists and not self.remote_machine_field.is_null else None

    # Read-only plural aliases retained strictly for backward compatibility
    @property
    def local_users(self) -> Optional[str]:
        return self.local_user

    @property
    def remote_users(self) -> Optional[str]:
        return self.remote_user

    @property
    def remote_machines(self) -> Optional[str]:
        return self.remote_machine

    @classmethod
    def create_unrestricted(
        cls,
        program: str,
        name: str = DEFAULT_RULE_NAME,
        display_name: str = DEFAULT_RULE_NAME,
        group: str = RULE_GROUPING,
        description: str = DEFAULT_DESCRIPTION,
        enabled: bool = True,
        direction: str = "Outbound",
        action: str = "Block",
        profiles: str = "Domain,Private,Public",
        **overrides: Any,
    ) -> FirewallRuleInfo:
        """Creates a FirewallRuleInfo instance with all 18 filter properties across all 7 categories positively verified as unrestricted."""
        kwargs: dict[str, Any] = {
            "name": name,
            "display_name": display_name,
            "group": group,
            "description": description,
            "enabled": enabled,
            "direction": direction,
            "action": action,
            "profiles": profiles,
            "program_field": CimFieldRecord.valid(program, program, "String"),
            "package_field": CimFieldRecord.null("Null"),
            "local_address_field": CimFieldRecord.valid("Any", "Any", "String"),
            "remote_address_field": CimFieldRecord.valid("Any", "Any", "String"),
            "protocol_field": CimFieldRecord.valid("Any", "Any", "String"),
            "local_port_field": CimFieldRecord.valid("Any", "Any", "String"),
            "remote_port_field": CimFieldRecord.valid("Any", "Any", "String"),
            "icmp_type_field": CimFieldRecord.valid("Any", "Any", "String"),
            "dynamic_target_field": CimFieldRecord.valid("Any", "Any", "String"),
            "service_field": CimFieldRecord.valid("Any", "Any", "String"),
            "interface_alias_field": CimFieldRecord.valid("Any", "Any", "String"),
            "interface_type_field": CimFieldRecord.valid("Any", "Any", "String"),
            "authentication_field": CimFieldRecord.valid("NotRequired", "NotRequired", "String"),
            "encryption_field": CimFieldRecord.valid("NotRequired", "NotRequired", "String"),
            "override_block_rules_field": CimFieldRecord.valid(False, "False", "Boolean"),
            "local_user_field": CimFieldRecord.valid("Any", "Any", "String"),
            "remote_user_field": CimFieldRecord.valid("Any", "Any", "String"),
            "remote_machine_field": CimFieldRecord.valid("Any", "Any", "String"),
        }
        for k, v in overrides.items():
            field_name = _CIM_FILTER_MAP.get(k, k)
            if field_name in kwargs or field_name.endswith("_field"):
                kwargs[field_name] = CimFieldRecord.from_raw(v) if not isinstance(v, CimFieldRecord) else v
            else:
                kwargs[k] = v
        return cls(**kwargs)


class FirewallQueryResult(BaseModel):
    """Structured result returned by Windows Firewall policy inspections."""
    schema_version: int = 1
    success: bool
    inspection_complete: bool
    rules: list[FirewallRuleInfo] = Field(default_factory=list)
    bypass_rules: list[dict[str, Any]] = Field(default_factory=list)
    error: Optional[str] = None
    errors: list[str] = Field(default_factory=list)
    policy_store: Optional[str] = None
    profiles: list[dict[str, Any]] = Field(default_factory=list)


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

    if file_name != EXPECTED_EXECUTABLE_NAME:
        return (
            False,
            f"Target executable '{file_name}' is not the dedicated deployment binary ('{EXPECTED_EXECUTABLE_NAME}'). "
            "Arbitrary executables are strictly rejected."
        )

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
            f"Rule '{rule.display_name}' exists but lacks verified Tsukiko ownership markers "
            f"(Grouping '{RULE_GROUPING}' and marker '{RULE_OWNERSHIP_MARKER}'). "
            f"Rule grouping mismatch: got '{rule.group}', expected '{RULE_GROUPING}'."
        )

    if RULE_OWNERSHIP_MARKER.lower() not in rule.description.lower():
        return (
            False,
            f"Rule '{rule.display_name}' exists but lacks verified Tsukiko ownership markers "
            f"(Grouping '{RULE_GROUPING}' and marker '{RULE_OWNERSHIP_MARKER}'). "
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
    """Validates that all 18 filter properties across all 7 NetSecurity categories ensure
    a complete, unrestricted outbound block for the target executable.

    Enforces:
    1. Application filter:
       - Program: Must match normalized target executable path. Wildcards and empty values rejected.
       - Package: Must be null, empty, or 'Any' (unrestricted Win32). Specific package SIDs fail closed.
    2. Address filter:
       - LocalAddress: Must be 'Any' or unrestricted. Specific IPs/ranges fail closed.
       - RemoteAddress: Must be 'Any' or unrestricted. Specific IPs/ranges fail closed.
    3. Port & protocol filter:
       - Protocol: Must be 'Any' (or '0' / '256'). Specific protocols (e.g. TCP, UDP) fail closed.
       - LocalPort: Must be 'Any' or unrestricted. Specific ports fail closed.
       - RemotePort: Must be 'Any' or unrestricted. Specific ports fail closed.
       - IcmpType: Must be 'Any' or unrestricted. Specific ICMP types (e.g. 8) fail closed.
       - DynamicTarget: Must be 'Any', '0', or unrestricted. Specific dynamic targets fail closed.
    4. Service filter:
       - Service: Must apply to all services ('Any' or empty).
    5. Interface filter:
       - InterfaceAlias: Must apply to all interfaces ('Any' or empty).
    6. Interface-type filter:
       - InterfaceType: Must apply to all interface types ('Any', '0', or empty).
    7. Security filter:
       - Authentication: Must be explicitly 'NotRequired' (or 'No' / '0').
       - Encryption: Must be explicitly 'NotRequired' (or 'No' / '0').
       - OverrideBlockRules: Must be explicitly verified as boolean False.
       - LocalUser: Must apply to all users ('Any' or empty).
       - RemoteUser: Must apply to all remote users ('Any' or empty).
       - RemoteMachine: Must apply to all remote machines ('Any' or empty).

    Fail-closed semantics:
    - Missing properties fail closed.
    - Null properties fail closed (except where null is the documented Windows representation
      of unrestricted Win32 binary, e.g. Package).
    - Restrictive or unrecognized values fail closed.
    - Malformed values fail closed.
    """
    # -------------------------------------------------------------
    # Category 1: Application filter
    # -------------------------------------------------------------
    if rule.program_field.state == CimFieldState.MISSING or rule.program_field.is_null:
        return False, "Application filter is missing or null. A dedicated executable path is required."
    if rule.program_field.state == CimFieldState.MALFORMED:
        return False, "Application filter has malformed Program property."
    if rule.program is None or rule.program.strip() in ("*", "Any", ""):
        return False, "Application filter is empty or wildcard. A dedicated executable path is required."
    try:
        expected_norm = Path(expected_exe).resolve()
        rule_norm = Path(rule.program).resolve()
        if expected_norm != rule_norm:
            return False, f"Application filter mismatch: rule targets '{rule_norm}', expected '{expected_norm}'."
    except Exception as e:
        return False, f"Could not compare application filter paths: {e}"

    # Package: standard Win32 binary is null, empty, or 'Any'
    if rule.package_field.state == CimFieldState.MISSING:
        return False, "Application filter missing Package property."
    if rule.package_field.state == CimFieldState.MALFORMED:
        return False, "Application filter has malformed Package property."
    if rule.package_field.state != CimFieldState.NULL:
        pkg_val = str(rule.package_field.value or "").strip().lower()
        if pkg_val not in ("", "any", "*"):
            return False, f"Application filter restricts package: '{rule.package_field.string_value}'."

    # -------------------------------------------------------------
    # Helper for generic unrestricted field checks
    # -------------------------------------------------------------
    def check_field_unrestricted(
        field: CimFieldRecord,
        prop_label: str,
        extra_allowed: tuple[str, ...] = (),
        allow_empty: bool = False,
    ) -> Tuple[bool, str]:
        if field.state == CimFieldState.MISSING or field.is_null:
            return False, f"Filter property '{prop_label}' is missing or null (cannot be verified as unrestricted)."
        if field.state == CimFieldState.MALFORMED:
            return False, f"Filter property '{prop_label}' has malformed value: {field.string_value}."
        if field.state != CimFieldState.VALID:
            return False, f"Filter property '{prop_label}' has invalid state: {field.state}."
        if field.string_value is None or not isinstance(field.string_value, str):
            return False, f"Filter property '{prop_label}' has missing, null, or non-string StringValue."

        str_clean = field.string_value.strip().lower()
        allowed = ("any", "*", *extra_allowed)
        if allow_empty:
            allowed = allowed + ("",)

        if str_clean not in allowed:
            return False, f"{prop_label} filter is restricted: '{field.string_value}' (must be Any or unrestricted)."

        # Validate Value matches StringValue and is not restricted
        if field.value is None:
            return False, f"Filter property '{prop_label}' has null Value."
        if isinstance(field.value, str):
            val_clean = field.value.strip().lower()
            if val_clean not in allowed:
                return False, f"{prop_label} filter Value is restricted: '{field.value}' (must be Any or unrestricted)."
            if val_clean != str_clean:
                return False, f"{prop_label} filter has contradictory Value ({field.value!r}) and StringValue ({field.string_value!r})."
        elif isinstance(field.value, list):
            if len(field.value) == 0 and not allow_empty:
                return False, f"{prop_label} filter Value array is empty (must be Any or unrestricted)."
            for elem in field.value:
                elem_clean = str(elem).strip().lower()
                if elem_clean not in allowed:
                    return False, f"{prop_label} filter Value contains restricted element: '{elem}' (must be Any or unrestricted)."
            joined = ",".join(str(x) for x in field.value).strip().lower()
            if joined != str_clean:
                return False, f"{prop_label} filter has contradictory Array Value ({field.value!r}) and StringValue ({field.string_value!r})."
        elif isinstance(field.value, (int, float)):
            val_str = str(field.value).strip().lower()
            if val_str not in allowed:
                return False, f"{prop_label} filter Value is restricted: '{field.value}' (must be Any or unrestricted)."
            if val_str != str_clean:
                return False, f"{prop_label} filter has contradictory Numeric Value ({field.value!r}) and StringValue ({field.string_value!r})."

        return True, ""

    # -------------------------------------------------------------
    # Category 2: Address filter
    # -------------------------------------------------------------
    ok, err = check_field_unrestricted(rule.local_address_field, "Local address", allow_empty=False)
    if not ok:
        return False, err
    ok, err = check_field_unrestricted(rule.remote_address_field, "Remote address", allow_empty=False)
    if not ok:
        return False, err

    # -------------------------------------------------------------
    # Category 3: Port & protocol filter
    # -------------------------------------------------------------
    ok, err = check_field_unrestricted(rule.protocol_field, "Protocol", extra_allowed=("0", "256"), allow_empty=False)
    if not ok:
        return False, err
    ok, err = check_field_unrestricted(rule.local_port_field, "Local port", allow_empty=False)
    if not ok:
        return False, err
    ok, err = check_field_unrestricted(rule.remote_port_field, "Remote port", allow_empty=False)
    if not ok:
        return False, err

    # IcmpType
    if rule.icmp_type_field.state == CimFieldState.MISSING:
        return False, "Port filter missing IcmpType property."
    if rule.icmp_type_field.is_null:
        return False, "Port filter missing or null IcmpType property."
    if rule.icmp_type_field.state == CimFieldState.MALFORMED:
        return False, f"Port filter has malformed IcmpType property: {rule.icmp_type_field.string_value}."
    ok, err = check_field_unrestricted(rule.icmp_type_field, "ICMP type", extra_allowed=("0",), allow_empty=False)
    if not ok:
        return False, f"Port filter restricts ICMP type: '{rule.icmp_type}'." if "restricted" in err else err

    # DynamicTarget
    if rule.dynamic_target_field.state == CimFieldState.MISSING:
        return False, "Port filter missing DynamicTarget property."
    if rule.dynamic_target_field.is_null:
        return False, "Port filter missing or null DynamicTarget property."
    if rule.dynamic_target_field.state == CimFieldState.MALFORMED:
        return False, f"Port filter has malformed DynamicTarget property: {rule.dynamic_target_field.string_value}."
    ok, err = check_field_unrestricted(rule.dynamic_target_field, "Dynamic target", extra_allowed=("0",), allow_empty=True)
    if not ok:
        return False, f"Port filter restricts dynamic target: '{rule.dynamic_target}'." if "restricted" in err else err

    # -------------------------------------------------------------
    # Category 4: Service filter
    # -------------------------------------------------------------
    ok, err = check_field_unrestricted(rule.service_field, "Service", allow_empty=True)
    if not ok:
        return False, err

    # -------------------------------------------------------------
    # Category 5: Interface filter
    # -------------------------------------------------------------
    ok, err = check_field_unrestricted(rule.interface_alias_field, "Interface", allow_empty=False)
    if not ok:
        return False, err

    # -------------------------------------------------------------
    # Category 6: Interface-type filter
    # -------------------------------------------------------------
    ok, err = check_field_unrestricted(rule.interface_type_field, "Interface type", extra_allowed=("0",), allow_empty=True)
    if not ok:
        return False, err

    # -------------------------------------------------------------
    # Category 7: Security filter
    # -------------------------------------------------------------
    # Authentication
    if rule.authentication_field.state == CimFieldState.MISSING or rule.authentication_field.is_null:
        return False, "Security filter missing or null Authentication property (must be explicitly NotRequired)."
    if rule.authentication_field.state == CimFieldState.MALFORMED:
        return False, f"Security filter has malformed Authentication property: {rule.authentication_field.string_value}."
    if rule.authentication_field.string_value is None or not isinstance(rule.authentication_field.string_value, str):
        return False, "Security filter has missing or non-string Authentication StringValue."
    auth_val = rule.authentication_field.string_value.strip().lower()
    if auth_val not in ("notrequired", "no", "0"):
        return False, f"Security filter requires authentication: '{rule.authentication}' (must be NotRequired)."
    if rule.authentication_field.value is not None:
        raw_auth = str(rule.authentication_field.value).strip().lower()
        if raw_auth not in ("notrequired", "no", "0"):
            return False, f"Security filter requires authentication: '{rule.authentication_field.value}' (must be NotRequired)."

    # Encryption
    if rule.encryption_field.state == CimFieldState.MISSING or rule.encryption_field.is_null:
        return False, "Security filter missing or null Encryption property (must be explicitly NotRequired)."
    if rule.encryption_field.state == CimFieldState.MALFORMED:
        return False, f"Security filter has malformed Encryption property: {rule.encryption_field.string_value}."
    if rule.encryption_field.string_value is None or not isinstance(rule.encryption_field.string_value, str):
        return False, "Security filter has missing or non-string Encryption StringValue."
    enc_val = rule.encryption_field.string_value.strip().lower()
    if enc_val not in ("notrequired", "no", "0"):
        return False, f"Security filter requires encryption: '{rule.encryption}' (must be NotRequired)."
    if rule.encryption_field.value is not None:
        raw_enc = str(rule.encryption_field.value).strip().lower()
        if raw_enc not in ("notrequired", "no", "0"):
            return False, f"Security filter requires encryption: '{rule.encryption_field.value}' (must be NotRequired)."

    # OverrideBlockRules: strictly boolean False
    if rule.override_block_rules_field.state == CimFieldState.MISSING or rule.override_block_rules_field.is_null:
        return False, "Security filter missing or null OverrideBlockRules property (must be explicitly False)."
    if rule.override_block_rules_field.state == CimFieldState.MALFORMED:
        return False, f"Security filter has malformed OverrideBlockRules value: {rule.override_block_rules_field.value!r} (must be boolean False)."
    if rule.override_block_rules is True:
        return False, "Security filter has OverrideBlockRules enabled (must be False). Outbound block can be bypassed."
    if rule.override_block_rules is not False:
        return False, f"Security filter has malformed OverrideBlockRules value: {rule.override_block_rules!r} (must be boolean False)."

    # LocalUser: singular CIM property
    if rule.local_user_field.state == CimFieldState.MISSING or rule.local_user_field.is_null:
        return False, "Security filter missing or null LocalUser property (must be unrestricted Any)."
    if rule.local_user_field.state == CimFieldState.MALFORMED:
        return False, "Security filter has malformed LocalUser property."
    ok, err = check_field_unrestricted(rule.local_user_field, "LocalUser", allow_empty=True)
    if not ok:
        if "is restricted" in err:
            return False, f"Security filter restricts local users: '{rule.local_user}'."
        return False, err

    # RemoteUser: singular CIM property
    if rule.remote_user_field.state == CimFieldState.MISSING or rule.remote_user_field.is_null:
        return False, "Security filter missing or null RemoteUser property (must be unrestricted Any)."
    if rule.remote_user_field.state == CimFieldState.MALFORMED:
        return False, "Security filter has malformed RemoteUser property."
    ok, err = check_field_unrestricted(rule.remote_user_field, "RemoteUser", allow_empty=True)
    if not ok:
        if "is restricted" in err:
            return False, f"Security filter restricts remote users: '{rule.remote_user}'."
        return False, err

    # RemoteMachine: singular CIM property
    if rule.remote_machine_field.state == CimFieldState.MISSING or rule.remote_machine_field.is_null:
        return False, "Security filter missing or null RemoteMachine property (must be unrestricted Any)."
    if rule.remote_machine_field.state == CimFieldState.MALFORMED:
        return False, "Security filter has malformed RemoteMachine property."
    ok, err = check_field_unrestricted(rule.remote_machine_field, "RemoteMachine", allow_empty=True)
    if not ok:
        if "is restricted" in err:
            return False, f"Security filter restricts remote machines: '{rule.remote_machine}'."
        return False, err

    return True, "All 7 outbound filter categories positively verified as unrestricted."


def parse_netsh_rule_blocks(output: str) -> list[FirewallRuleInfo]:
    """Parses netsh advfirewall show rule text output into FirewallRuleInfo objects.

    Deprecated / Degraded:
    netsh cannot inspect the complete 18-property NetSecurity CIM filter schema.
    This function is retained solely for legacy text output parsing and must NOT be used
    to declare os_policy_active.
    """
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


def parse_powershell_rules_json(
    data: Any,
    expected_policy_store: Optional[str] = None,
) -> list[FirewallRuleInfo]:
    """Parses JSON rule objects from PowerShell into FirewallRuleInfo list.

    Enforces:
    - Complete response envelope validation when an envelope dictionary is provided.
    - SchemaVersion check (must equal integer 1).
    - Requires all 8 envelope fields: SchemaVersion, Success, InspectionComplete, PolicyStore,
      Profiles, Rules, BypassRules, Errors.
    - Rejects null, non-list, or missing Rules property in envelope.
    - Rejects policy store mismatches when expected_policy_store is given.
    - Lossless deserialization of structured CimFieldRecord representations.
    - Strict singular NetSecurity property names (LocalUser, RemoteUser, RemoteMachine).
      Deprecated plural property names in incoming payloads do NOT map to singular fields and fail closed.
    - Preserves field-state distinctions: VALID, NULL, MISSING, MALFORMED.
    """
    if data is None:
        return []

    if isinstance(data, dict):
        if any(k in data for k in ("SchemaVersion", "Success", "InspectionComplete", "PolicyStore", "Profiles", "Rules", "BypassRules", "Errors")):
            ok, err = validate_response_envelope(data, expected_policy_store=expected_policy_store)
            if not ok:
                raise FirewallParseError(err)
            if data.get("Success") is not True or data.get("InspectionComplete") is not True:
                errs = data.get("Errors", [])
                raise FirewallParseError(f"PowerShell inspection reported failure envelope: {errs}")
            raw_list = data["Rules"]
        else:
            raw_list = [data]
    elif isinstance(data, list):
        raw_list = data
    else:
        raise FirewallParseError(f"Expected JSON object or list of rules, got {type(data).__name__}.")

    rules: list[FirewallRuleInfo] = []
    for r in raw_list:
        if not isinstance(r, dict):
            raise FirewallParseError(f"Rule entry must be a dictionary, got {type(r).__name__}.")

        name = str(r["Name"]).strip() if "Name" in r and r["Name"] is not None else ""
        if not name and "RuleName" in r and r["RuleName"] is not None:
            name = str(r["RuleName"]).strip()
        display_name = str(r["DisplayName"]).strip() if "DisplayName" in r and r["DisplayName"] is not None else ""
        group = str(r["Group"]).strip() if "Group" in r and r["Group"] is not None else ""
        if not group and "DisplayGroup" in r and r["DisplayGroup"] is not None:
            group = str(r["DisplayGroup"]).strip()
        description = str(r["Description"]).strip() if "Description" in r and r["Description"] is not None else ""

        enabled_val = r.get("Enabled")
        enabled = bool(enabled_val) if not isinstance(enabled_val, (int, str)) else str(enabled_val).lower() in ("1", "true")
        direction = str(r["Direction"]).strip() if "Direction" in r and r["Direction"] is not None else ""
        action = str(r["Action"]).strip() if "Action" in r and r["Action"] is not None else ""
        profiles = str(r["Profiles"]).strip() if "Profiles" in r and r["Profiles"] is not None else None

        # Extract 18 CIM filter fields with explicit presence checking
        cim_kwargs: dict[str, CimFieldRecord] = {}
        cim_names = [
            ("Program", "program_field"),
            ("Package", "package_field"),
            ("LocalAddress", "local_address_field"),
            ("RemoteAddress", "remote_address_field"),
            ("Protocol", "protocol_field"),
            ("LocalPort", "local_port_field"),
            ("RemotePort", "remote_port_field"),
            ("IcmpType", "icmp_type_field"),
            ("DynamicTarget", "dynamic_target_field"),
            ("Service", "service_field"),
            ("InterfaceAlias", "interface_alias_field"),
            ("InterfaceType", "interface_type_field"),
            ("Authentication", "authentication_field"),
            ("Encryption", "encryption_field"),
            ("OverrideBlockRules", "override_block_rules_field"),
            ("LocalUser", "local_user_field"),
            ("RemoteUser", "remote_user_field"),
            ("RemoteMachine", "remote_machine_field"),
        ]

        for json_key, attr_name in cim_names:
            if json_key in r:
                val = r[json_key]
                if val is None:
                    cim_kwargs[attr_name] = CimFieldRecord.null()
                elif isinstance(val, dict) and ("State" in val or "state" in val):
                    cim_kwargs[attr_name] = CimFieldRecord.from_raw(val)
                elif json_key == "OverrideBlockRules":
                    if isinstance(val, bool):
                        cim_kwargs[attr_name] = CimFieldRecord.valid(val, "True" if val else "False", "Boolean")
                    elif isinstance(val, str) and val.strip().lower() in ("false", "0"):
                        cim_kwargs[attr_name] = CimFieldRecord.valid(False, "False", "Boolean")
                    elif isinstance(val, str) and val.strip().lower() in ("true", "1"):
                        cim_kwargs[attr_name] = CimFieldRecord.valid(True, "True", "Boolean")
                    elif isinstance(val, (int, float)) and val == 0:
                        cim_kwargs[attr_name] = CimFieldRecord.valid(False, "False", "Boolean")
                    elif isinstance(val, (int, float)) and val == 1:
                        cim_kwargs[attr_name] = CimFieldRecord.valid(True, "True", "Boolean")
                    else:
                        cim_kwargs[attr_name] = CimFieldRecord.malformed(val, str(val))
                else:
                    cim_kwargs[attr_name] = CimFieldRecord.from_raw(val)
            else:
                # Strictly missing: do not map plural substitutes like LocalUsers
                cim_kwargs[attr_name] = CimFieldRecord.missing()

        rules.append(FirewallRuleInfo(
            name=name,
            display_name=display_name,
            group=group,
            description=description,
            enabled=enabled,
            direction=direction,
            action=action,
            profiles=profiles,
            raw_properties=dict(r),
            **cim_kwargs,
        ))
    return rules


# =====================================================================
# PowerShell Script Snippets
# =====================================================================

PS_CIM_SERIALIZER_SNIPPET = """
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

function Get-RuleCimRecord($r) {
    $apps = @(Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $r)
    if ($apps.Count -ne 1) { throw "Application filter association integrity failure for rule '$($r.Name)': expected 1 filter object, got $($apps.Count)" }
    $app = $apps[0]

    $addrs = @(Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $r)
    if ($addrs.Count -ne 1) { throw "Address filter association integrity failure for rule '$($r.Name)': expected 1 filter object, got $($addrs.Count)" }
    $addr = $addrs[0]

    $ports = @(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $r)
    if ($ports.Count -ne 1) { throw "Port filter association integrity failure for rule '$($r.Name)': expected 1 filter object, got $($ports.Count)" }
    $port = $ports[0]

    $svcs = @(Get-NetFirewallServiceFilter -AssociatedNetFirewallRule $r)
    if ($svcs.Count -ne 1) { throw "Service filter association integrity failure for rule '$($r.Name)': expected 1 filter object, got $($svcs.Count)" }
    $svc = $svcs[0]

    $ifaces = @(Get-NetFirewallInterfaceFilter -AssociatedNetFirewallRule $r)
    if ($ifaces.Count -ne 1) { throw "Interface filter association integrity failure for rule '$($r.Name)': expected 1 filter object, got $($ifaces.Count)" }
    $iface = $ifaces[0]

    $iftypes = @(Get-NetFirewallInterfaceTypeFilter -AssociatedNetFirewallRule $r)
    if ($iftypes.Count -ne 1) { throw "InterfaceType filter association integrity failure for rule '$($r.Name)': expected 1 filter object, got $($iftypes.Count)" }
    $iftype = $iftypes[0]

    $secs = @(Get-NetFirewallSecurityFilter -AssociatedNetFirewallRule $r)
    if ($secs.Count -ne 1) { throw "Security filter association integrity failure for rule '$($r.Name)': expected 1 filter object, got $($secs.Count)" }
    $sec = $secs[0]

    $profStr = if ($r.Profile -is [System.Array]) { ($r.Profile | ForEach-Object { [string]$_ }) -join ',' } elseif ($null -ne $r.Profile) { [string]$r.Profile } else { "" }

    return [PSCustomObject]@{
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
}
"""


def query_matching_firewall_rules(
    rule_identifier: Optional[str] = None,
    policy_store: str = "PersistentStore",
) -> FirewallQueryResult:
    """Queries candidate firewall rules matching rule_identifier or Tsukiko identity using PowerShell NetSecurity.

    Distinguishes:
    - Confirmed absence: success=True, inspection_complete=True, rules=[]
    - Confirmed presence: success=True, inspection_complete=True, rules=[...]
    - Inspection failure: success=False, inspection_complete=False, rules=[], error=...

    Fail-closed policy:
    netsh is NOT used to evaluate or declare security status because it cannot inspect the complete
    18-property NetSecurity CIM filter schema. If PowerShell or NetSecurity is unavailable, this
    function strictly fails closed with success=False, inspection_complete=False.
    """
    if platform.system() != "Windows":
        return FirewallQueryResult(
            schema_version=1,
            success=True,
            inspection_complete=True,
            rules=[],
            error="Non-Windows platform",
            policy_store=policy_store,
        )

    ps_path = shutil.which("powershell") or shutil.which("powershell.exe")
    if not ps_path:
        return FirewallQueryResult(
            schema_version=1,
            success=False,
            inspection_complete=False,
            rules=[],
            error="PowerShell is not available on PATH. PowerShell NetSecurity is required for complete firewall inspection.",
            policy_store=policy_store,
        )

    target_id = (rule_identifier or DEFAULT_RULE_NAME).strip()

    ps_script = PS_CIM_SERIALIZER_SNIPPET + """
$store = $env:TSUKIKO_POLICY_STORE
$ruleId = $env:TSUKIKO_TARGET_RULE_NAME
$group = $env:TSUKIKO_TARGET_GROUP
$stableId = $env:TSUKIKO_STABLE_RULE_ID
$ErrorActionPreference = 'Stop'

try {
    $rules = @(Get-NetFirewallRule -PolicyStore $store | Where-Object {
        $_.Name -eq $ruleId -or $_.DisplayName -eq $ruleId -or $_.Name -eq $stableId -or $_.DisplayGroup -eq $group
    } | ForEach-Object {
        Get-RuleCimRecord $_
    })
    [PSCustomObject]@{
        SchemaVersion = 1
        Success = $true
        InspectionComplete = $true
        PolicyStore = $store
        Profiles = @()
        Rules = $rules
        BypassRules = @()
        Errors = @()
    } | ConvertTo-Json -Depth 6
} catch {
    [PSCustomObject]@{
        SchemaVersion = 1
        Success = $false
        InspectionComplete = $false
        PolicyStore = $store
        Profiles = @()
        Rules = @()
        BypassRules = @()
        Errors = @($_.Exception.Message)
    } | ConvertTo-Json -Depth 3
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

        if res.returncode != 0:
            err_msg = ""
            if res.stdout.strip():
                try:
                    err_data = json.loads(res.stdout.strip())
                    if isinstance(err_data, dict):
                        errors = err_data.get("Errors") or []
                        if errors:
                            err_msg = "; ".join(str(e) for e in errors)
                        elif err_data.get("Error"):
                            err_msg = str(err_data["Error"]).strip()
                except Exception:
                    pass
            if not err_msg:
                err_msg = res.stderr.strip() or res.stdout.strip() or f"PowerShell exited with code {res.returncode}"
            return FirewallQueryResult(
                schema_version=1,
                success=False,
                inspection_complete=False,
                rules=[],
                error=f"PowerShell inspection failed (exit code {res.returncode}): {err_msg}",
                errors=[err_msg],
                policy_store=policy_store,
            )

        raw_out = res.stdout.strip()
        if not raw_out:
            return FirewallQueryResult(
                schema_version=1,
                success=False,
                inspection_complete=False,
                rules=[],
                error="PowerShell query returned empty standard output; missing response envelope.",
                policy_store=policy_store,
            )

        try:
            data = json.loads(raw_out)
        except Exception as json_err:
            return FirewallQueryResult(
                schema_version=1,
                success=False,
                inspection_complete=False,
                rules=[],
                error=f"Malformed PowerShell JSON output: {json_err}",
                policy_store=policy_store,
            )

        ok, err = validate_response_envelope(data, expected_policy_store=policy_store)
        if not ok:
            s_ver = data.get("SchemaVersion") if isinstance(data, dict) and type(data.get("SchemaVersion")) is int else 1
            return FirewallQueryResult(
                schema_version=s_ver,
                success=False,
                inspection_complete=False,
                rules=[],
                error=f"PowerShell response envelope validation failed: {err}",
                errors=[err],
                policy_store=policy_store,
            )

        if data.get("Success") is not True or data.get("InspectionComplete") is not True:
            err_detail = "; ".join(data.get("Errors", [])) or "Inspection not marked complete by PowerShell."
            return FirewallQueryResult(
                schema_version=data.get("SchemaVersion", 1),
                success=False,
                inspection_complete=False,
                rules=[],
                error=f"PowerShell query reported failure: {err_detail}",
                errors=data.get("Errors", [err_detail]),
                policy_store=policy_store,
            )

        try:
            parsed_rules = parse_powershell_rules_json(data, expected_policy_store=policy_store)
        except FirewallParseError as parse_err:
            return FirewallQueryResult(
                schema_version=data.get("SchemaVersion", 1),
                success=False,
                inspection_complete=False,
                rules=[],
                error=f"PowerShell rules parsing failed: {parse_err}",
                errors=[str(parse_err)],
                policy_store=policy_store,
            )

        return FirewallQueryResult(
            schema_version=data.get("SchemaVersion", 1),
            success=True,
            inspection_complete=True,
            rules=parsed_rules,
            bypass_rules=data.get("BypassRules", []),
            policy_store=policy_store,
        )
    except subprocess.TimeoutExpired:
        return FirewallQueryResult(
            schema_version=1,
            success=False,
            inspection_complete=False,
            rules=[],
            error="PowerShell query timed out while inspecting firewall rules",
            policy_store=policy_store,
        )
    except Exception as e:
        return FirewallQueryResult(
            schema_version=1,
            success=False,
            inspection_complete=False,
            rules=[],
            error=f"PowerShell query invocation failed: {e}",
            policy_store=policy_store,
        )


def build_activestore_inspection_powershell_script() -> str:
    """Builds the canonical ActiveStore PowerShell inspection script.

    Inspects:
    1. ActiveStore Firewall Profiles (Name, Enabled, AllowLocalFirewallRules).
    2. ActiveStore rules matching Tsukiko rule name, stable ID, or group using Get-RuleCimRecord.
    3. ActiveStore Outbound Allow Bypass Discovery using NetSecurity security-filter query
       capabilities to enumerate rules with OverrideBlockRules=True, then establishing applicability
       to the Tsukiko executable or unrestricted AllPrograms scope.
    4. Serializes complete versioned response envelope (SchemaVersion: 1).
    """
    return PS_CIM_SERIALIZER_SNIPPET + """
$targetRuleName = $env:TSUKIKO_TARGET_RULE_NAME
$targetGroup = $env:TSUKIKO_TARGET_GROUP
$stableId = $env:TSUKIKO_STABLE_RULE_ID
$targetExe = $env:TSUKIKO_TARGET_EXE
$ErrorActionPreference = 'Stop'

try {
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name, Enabled, AllowLocalFirewallRules)

    $rules = @(Get-NetFirewallRule -PolicyStore ActiveStore | Where-Object {
        $_.DisplayName -eq $targetRuleName -or $_.Name -eq $targetRuleName -or $_.Name -eq $stableId -or $_.DisplayGroup -eq $targetGroup
    } | ForEach-Object {
        Get-RuleCimRecord $_
    })

    # ActiveStore Outbound Allow Bypass Discovery:
    # Query all security filters in ActiveStore with OverrideBlockRules=True without error suppression
    $bypassRules = @()
    $secFilterCandidates = @()
    try {
        $secFilterCandidates = @(Get-NetFirewallSecurityFilter -PolicyStore ActiveStore -OverrideBlockRules $true -ErrorAction Stop)
    } catch [Microsoft.PowerShell.Cmdletization.Cim.CimJobException] {
        if ($_.FullyQualifiedErrorId -like "CmdletizationQuery_NotFound*") {
            $secFilterCandidates = @()
        } else {
            throw
        }
    }

    foreach ($sec in $secFilterCandidates) {
        $assocRules = @(Get-NetFirewallRule -AssociatedNetFirewallSecurityFilter $sec -PolicyStore ActiveStore -ErrorAction Stop)
        if ($assocRules.Count -ne 1) {
            throw "Association integrity violation: Security filter '$($sec.InstanceID)' has $($assocRules.Count) associated rules (expected exactly 1)"
        }
        $cr = $assocRules[0]

        $isEnabled = ($cr.Enabled -eq 1 -or $cr.Enabled -eq $true -or $cr.Enabled -eq 'True')
        $isOutbound = ($cr.Direction -eq 2 -or $cr.Direction -eq 'Outbound' -or $cr.Direction -eq 'Out')
        $isAllow = ($cr.Action -eq 2 -or $cr.Action -eq 'Allow')

        if (-not ($isEnabled -and $isOutbound -and $isAllow)) {
            continue
        }

        $secCheck = @($cr | Get-NetFirewallSecurityFilter -ErrorAction Stop)
        if ($secCheck.Count -ne 1) {
            throw "Association integrity violation: Bypass candidate rule '$($cr.Name)' has $($secCheck.Count) security filters (expected exactly 1)"
        }
        if ($secCheck[0].OverrideBlockRules -ne $true -and $secCheck[0].OverrideBlockRules -ne 1) {
            throw "Security filter OverrideBlockRules mismatch for candidate rule '$($cr.Name)'"
        }

        $appFilters = @($cr | Get-NetFirewallApplicationFilter -ErrorAction Stop)
        if ($appFilters.Count -ne 1) {
            throw "Association integrity violation: Bypass candidate rule '$($cr.Name)' has $($appFilters.Count) application filters (expected exactly 1)"
        }
        $app = $appFilters[0]

        $prog = [string]$app.Program
        $pkg = [string]$app.Package

        $trimmedProg = if ($null -ne $prog) { ([string]$prog).Trim() } else { "" }
        $hasWildcard = $trimmedProg.Contains("?") -or ($trimmedProg.Contains("*") -and $trimmedProg -ne "*")
        if ($hasWildcard) {
            throw "Ambiguous application filter pattern in bypass candidate rule '$($cr.Name)': '$prog'"
        }

        $applies = $false
        $scope = ""

        $normTargetExe = if ($targetExe) { $targetExe.Trim().ToLower() } else { "" }
        $normProg = $trimmedProg.ToLower()

        if ($normProg -ne "" -and $normProg -ne "any" -and $normProg -ne "*") {
            if ($normTargetExe -ne "" -and $normProg -eq $normTargetExe) {
                $applies = $true
                $scope = "ExactExecutable"
            } else {
                $applies = $false
            }
        } else {
            if ($pkg.Trim() -ne "") {
                $applies = $false
            } else {
                $applies = $true
                $scope = "AllPrograms"
            }
        }

        if ($applies) {
            $bypassRules += [PSCustomObject]@{
                Name = [string]$cr.Name
                DisplayName = [string]$cr.DisplayName
                Program = if ($prog) { [string]$prog } else { "Any" }
                Package = if ($pkg) { [string]$pkg } else { $null }
                Scope = $scope
                OverrideBlockRules = $true
            }
        }
    }

    [PSCustomObject]@{
        SchemaVersion = 1
        Success = $true
        InspectionComplete = $true
        PolicyStore = "ActiveStore"
        Profiles = $profiles
        Rules = $rules
        BypassRules = $bypassRules
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


def verify_effective_firewall_policy(
    executable_path: Path | str,
    rule_name: str = DEFAULT_RULE_NAME,
) -> Tuple[bool, str]:
    """Verifies that the outbound block policy is genuinely effective in the Windows Firewall ActiveStore.

    Validates:
    1. PowerShell is available and executable.
    2. ActiveStore firewall profiles (Domain, Private, Public) are all Enabled.
    3. ActiveStore profile policy permits local firewall rules (AllowLocalFirewallRules is True).
    4. ActiveStore has NO conflicting Outbound Allow rules targeting the dedicated executable
       where OverrideBlockRules is True (bypass evaluation).
    5. An active rule matching Tsukiko ownership exists in ActiveStore:
       - DisplayName == 'Tsukiko Outbound Privacy Boundary' OR Name == 'Tsukiko_Privacy_Outbound_Block'
       - Group == 'Tsukiko Desktop Companion'
       - Description contains '[Tsukiko-Privacy-Core:Outbound-Block]'
       - Direction is Outbound
       - Action is Block
       - Enabled is True
       - Program matches normalized executable_path
       - Profiles covers all network profiles (Domain,Private,Public or Any)
    6. All 18 filter properties across all 7 NetSecurity categories are positively verified as unrestricted.
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

    ps_script = build_activestore_inspection_powershell_script()
    env = os.environ.copy()
    env["TSUKIKO_TARGET_RULE_NAME"] = rule_name
    env["TSUKIKO_TARGET_GROUP"] = RULE_GROUPING
    env["TSUKIKO_STABLE_RULE_ID"] = STABLE_RULE_ID
    env["TSUKIKO_TARGET_EXE"] = str(resolved_exe)

    try:
        res = subprocess.run(
            [ps_path, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
            capture_output=True,
            text=True,
            timeout=10,
            env=env,
        )
        if res.returncode != 0:
            err = ""
            if res.stdout.strip():
                try:
                    err_data = json.loads(res.stdout.strip())
                    if isinstance(err_data, dict):
                        errors = err_data.get("Errors") or []
                        if errors:
                            err = "; ".join(str(e) for e in errors)
                        elif err_data.get("Error"):
                            err = str(err_data["Error"]).strip()
                except Exception:
                    pass
            if not err:
                err = res.stderr.strip() or res.stdout.strip() or f"PowerShell exited with code {res.returncode}"
            return False, f"PowerShell ActiveStore inspection failed (exit code {res.returncode}): {err}"

        output = res.stdout.strip()
        if not output:
            return False, "PowerShell ActiveStore query returned empty output; missing response envelope."

        try:
            data = json.loads(output)
        except json.JSONDecodeError as e:
            return False, f"Malformed PowerShell output: unable to parse JSON: {e}"

        ok, err = validate_response_envelope(data, expected_policy_store="ActiveStore")
        if not ok:
            return False, f"PowerShell ActiveStore response envelope validation failed: {err}"

        if data.get("Success") is not True or data.get("InspectionComplete") is not True:
            err_detail = "; ".join(data.get("Errors", [])) or "ActiveStore inspection failed."
            return False, f"ActiveStore inspection failed: {err_detail}"

        # 1. Verify Profiles in ActiveStore
        profiles_raw = data.get("Profiles", [])
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

        # 2. Check Outbound Allow Bypass Rules
        bypass_rules = data.get("BypassRules", [])
        if bypass_rules:
            bypass_descriptions = []
            for b in bypass_rules:
                if isinstance(b, dict):
                    b_name = b.get("DisplayName") or b.get("Name") or "Unknown"
                    b_scope = b.get("Scope") or "Unknown"
                    b_prog = b.get("Program") or "Any"
                    bypass_descriptions.append(f"'{b_name}' (Scope: {b_scope}, Program: {b_prog})")
                else:
                    bypass_descriptions.append(str(b))
            return (
                False,
                f"Conflicting outbound bypass Allow rule(s) {', '.join(bypass_descriptions)} with OverrideBlockRules=True "
                f"detected in ActiveStore for target executable '{resolved_exe}'. Outbound block is overridden."
            )

        # 3. Verify Rules in ActiveStore
        try:
            rules = parse_powershell_rules_json(data, expected_policy_store="ActiveStore")
        except FirewallParseError as parse_err:
            return False, f"ActiveStore rule parsing failed: {parse_err}"

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
    policy_store: str = "PersistentStore",
) -> Tuple[bool, str]:
    """Verifies that an existing persistent Windows Firewall rule protects the specified executable.

    Unified with PowerShell NetSecurity:
    Queries policy_store via query_matching_firewall_rules, verifies rule ownership,
    enabled status, direction=Outbound, action=Block, profile coverage, and all 18
    NetSecurity filter properties via validate_firewall_filters.
    """
    if platform.system() != "Windows":
        return False, "Windows Firewall verification is only available on Windows."

    try:
        resolved_exe = Path(executable_path).resolve()
    except Exception:
        return False, "Invalid executable path provided for verification."

    query_res = query_matching_firewall_rules(rule_identifier=rule_name, policy_store=policy_store)
    if not query_res.success or not query_res.inspection_complete:
        return False, f"Rule verification failed due to inspection failure: {query_res.error}"

    if not query_res.rules:
        return False, f"Rule '{rule_name}' does not exist in Windows Firewall {policy_store}."

    for r in query_res.rules:
        is_owned, own_reason = is_tsukiko_owned_rule(r, expected_exe=resolved_exe)
        if not is_owned:
            continue

        if not r.enabled:
            return False, "Rule exists but is not Enabled."

        if r.direction.lower() not in ("outbound", "out", "2"):
            return False, "Rule exists but Direction is not Outbound."

        if r.action.lower() not in ("block", "2"):
            return False, "Rule exists but Action is not Block."

        prof_ok, prof_msg = validate_firewall_profiles(r.profiles)
        if not prof_ok:
            return False, f"Rule profile validation failed: {prof_msg}"

        flt_ok, flt_msg = validate_firewall_filters(r, resolved_exe)
        if not flt_ok:
            return False, f"Rule filter validation failed: {flt_msg}"

        return True, "Firewall rule verified: Active, Outbound, Block, matching target executable, Tsukiko owned."

    # If rules were returned but none belonged to Tsukiko
    first_rule = query_res.rules[0]
    is_owned, own_err = is_tsukiko_owned_rule(first_rule, expected_exe=resolved_exe)
    if not is_owned:
        return False, own_err

    return False, f"Rule '{rule_name}' does not match verified Tsukiko outbound blocking criteria."


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
    - Post-creation verification re-queries policy store to confirm rule presence and all 18 filter properties.
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

    query_res = query_matching_firewall_rules(rule_identifier=clean_name, policy_store=policy_store)
    if not query_res.success or not query_res.inspection_complete:
        return False, f"Cannot safely inspect firewall rules for deletion due to inspection failure: {query_res.error}"

    if not query_res.rules:
        return False, f"Rule '{rule_name}' does not exist in Windows Firewall {policy_store}."

    owned_candidates = [c for c in query_res.rules if is_tsukiko_owned_rule(c)[0]]

    if len(owned_candidates) == 0:
        return (
            False,
            f"Refusing to delete rule '{rule_name}': rule exists but is not verified as a Tsukiko-owned rule "
            f"(lacks required grouping '{RULE_GROUPING}' and marker '{RULE_OWNERSHIP_MARKER}'). "
            "Foreign rules will not be deleted."
        )

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
