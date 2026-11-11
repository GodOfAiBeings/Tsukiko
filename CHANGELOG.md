# Changelog

All notable changes to the Tsukiko project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.1] - Final Phase 1 Security Acceptance Pass - 2026-11-11

### Added
- **Numeric Loopback Enforcement & Hostname Trust Elimination (`app/core/privacy/enforcement.py`)**:
  - `is_numeric_loopback_ip()` strictly requires numeric loopback IPs (`127.0.0.0/8`, `::1`).
  - Rejects raw `localhost` string from raw connection authorization to prevent DNS hijacking and unexpected resolution.
  - Sockets attempting connections to `localhost` have their destination address converted deterministically to numeric loopback (`127.0.0.1` for AF_INET, `::1` for AF_INET6) before invoking low-level C `connect` or `connect_ex` routines, guaranteeing zero external network DNS queries.
- **Fail-Closed Low-Level DNS Interception (`app/core/privacy/enforcement.py`)**:
  - `getaddrinfo`, `gethostbyname`, `gethostbyname_ex`, `gethostbyaddr`, and `getnameinfo` strictly fail closed with `PrivacyViolationError` for any non-loopback or external destination.
  - Eliminated unrestricted system DNS fallback for `localhost`.
  - Deterministic loopback results for `localhost` and loopback reverse lookups (`127.0.0.1`, `::1`).
- **Socket Family Restrictions (`app/core/privacy/enforcement.py`)**:
  - `_is_allowed_destination` strictly validates socket family (`AF_INET`, `AF_INET6`, `AF_UNIX`).
  - Any unknown or unsupported socket family (e.g. `AF_BLUETOOTH`, `AF_NETLINK`, `AF_PACKET`, or arbitrary integers) fails closed immediately, even if the destination address is formatted as an IP tuple.
- **Platform-Compliant `sendmsg` Argument Forwarding (`app/core/privacy/enforcement.py`)**:
  - Fixed argument forwarding in `_guarded_socket_sendmsg`: for connected sockets where `address is None`, `address` is omitted entirely rather than passed as `address=None`, preserving native C socket API semantics.
  - Explicit address sendmsg calls are validated and normalized.
- **Real AF_UNIX Local IPC Communication Test (`tests/test_privacy_enforcement.py`)**:
  - Added `test_real_af_unix_ipc_exchange` testing genuine socket bind, listen, connect, bidirectional message exchange, and teardown.
  - Automatically skips with clear explanation on Windows Python builds where `hasattr(socket, "AF_UNIX")` is false.
- **Tsukiko Windows Firewall Ownership & Profile Verification (`app/core/privacy/windows_firewall.py`)**:
  - Documented and enforced Tsukiko rule ownership identity:
    - Rule Name: `Tsukiko Outbound Privacy Boundary`
    - Grouping: `Tsukiko Desktop Companion`
    - Description Marker: `[Tsukiko-Privacy-Core:Outbound-Block]`
  - Extended rule verification to inspect Grouping, Description ownership marker, and profile applicability (`Domain,Private,Public` or `Any`).
  - Rejects foreign or unrelated rules sharing the Tsukiko prefix.
  - Safe removal requires verified Tsukiko ownership before deletion.
- **Deployment Binary PE Header Validation (`app/core/privacy/windows_firewall.py`)**:
  - Added binary format validation in `is_safe_target_executable`: reads first 2 bytes and validates the DOS/PE `MZ` executable header magic (`0x4D 0x5A`).
  - Plain text stubs and arbitrary non-PE files are rejected.
  - Documented limitation: PE header check confirms binary format, not cryptographic Authenticode signature verification.
- **Windows Continuous Integration Workflow (`.github/workflows/ci.yml`)**:
  - Established GitHub Actions workflow on `windows-latest` with Python 3.11.
  - Runs full 71-test pytest suite, builds wheel distribution, and executes out-of-tree CLI packaging test.

### Changed
- `app/core/privacy/enforcement.py`: Strict numeric loopback validation, deterministic DNS handling, family-level gating, and fixed sendmsg forwarding.
- `app/core/privacy/windows_firewall.py`: Rule ownership identity, PE header inspection, profile checking, and safe deletion verification.
- `tests/test_privacy_enforcement.py`: Added 5 new regression tests for numeric loopback, sendmsg, real AF_UNIX, and DNS resolution.
- `tests/test_windows_firewall.py`: Updated fixtures with mock PE headers (`b'MZ'`) and added tests for ownership rejection, incomplete profiles, and non-PE executables.
- Total test count expanded to 71 tests (70 passed, 1 skipped on Windows due to platform AF_UNIX absence).

---

## [0.1.0] - Phase 1 Foundation & Engineering Hardening - 2026-11-11

### Added
- **Family-Aware Local IPC & Socket Interception**:
  - Rewrote address validation in `app.core.privacy.enforcement` to inspect socket family (`self.family`) prior to validating addresses.
  - Permitted `AF_UNIX` filesystem paths and abstract socket names as valid local IPC, preventing paths from being misinterpreted as Internet hostnames.
  - Expanded socket interception across all outbound transmission interfaces: `socket.connect`, `connect_ex`, `send`, `sendall`, `sendmsg`, and `sendto` (supporting both calling signatures).
  - Enforced strict loopback address allowlist (`127.0.0.0/8`, `::1`).
  - Strictly rejected unspecified addresses (`0.0.0.0`, `::`), empty strings, and external destinations.
  - Added atomic rollback during guard activation and preserved process-lifetime protection.
- **Strict Windows Firewall Policy Management (`app.core.privacy.windows_firewall`)**:
  - Implemented strict target executable validation requiring the file to exist on disk, resolve to a `.exe`, match the dedicated deployment binary (`tsukiko.exe`), and contain no command-injection characters.
  - Refused to create firewall rules against shared Python interpreters (`python.exe`, `pythonw.exe`, `py.exe`, `pytest.exe`) or shell binaries.
  - Implemented property-level rule verification confirming `Direction=Out`, `Action=Block`, `Enabled=Yes`, and exact normalized executable path.
  - Implemented 4 distinct security status states: `in_process_only`, `os_policy_not_configured`, `os_policy_unverified`, and `os_policy_active`.
  - Required explicit user authorization (`user_authorized=True`) and administrator elevation for rule creation and removal.
- **Fail-Safe VRAM Classification Matrix (`app.core.resource_manager/hardware.py`)**:
  - Fixed GPU data representation to preserve `None` for missing, `[N/A]`, `[Not Supported]`, or malformed metrics rather than converting to zero.
  - Established three distinct VRAM states:
    - `measured`: Known total VRAM and positive free VRAM -> dynamic safe budget `min(total - 1200, free - 400)`.
    - `zero_available`: Known total VRAM and confirmed 0 MB free VRAM -> 0 MB GPU budget and CPU-only fallback.
    - `unavailable`: No GPU, query failed/timed out, or metrics `[N/A]`/malformed -> 0 MB GPU budget and CPU-only fallback.
  - Ensured hardware diagnostic never substitutes positive default budgets when safe VRAM is zero or unavailable.
- **Genuine Wheel Packaging Verification (`tests/test_packaging.py`)**:
  - Implemented integration tests verifying all four packaging milestones:
    1. Wheel successfully built (`tsukiko-0.1.0-py3-none-any.whl`).
    2. Wheel successfully installed into an isolated temporary virtual environment.
    3. Installed console entry point (`tsukiko --check-hardware`) successfully executed outside the repository checkout without `PYTHONPATH`.
    4. Packaged resources (`default_config.yaml`) successfully located without access to repository source checkout.
