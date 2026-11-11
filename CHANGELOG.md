# Changelog

All notable changes to the Tsukiko project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] - Phase 1 Foundation & Engineering Hardening - 2026-11-11

### Added
- **Family-Aware Local IPC & Socket Interception**:
  - Rewrote address validation in `app.core.privacy.enforcement` to inspect socket family (`self.family`) prior to validating addresses.
  - Permitted `AF_UNIX` filesystem paths and abstract socket names as valid local IPC, preventing paths from being misinterpreted as Internet hostnames.
  - Expanded socket interception across all outbound transmission interfaces: `socket.connect`, `connect_ex`, `send`, `sendall`, `sendmsg` (with address and connected checks), and `sendto` (supporting both calling signatures).
  - Enforced strict loopback address allowlist (`127.0.0.0/8`, `::1`, and loopback-resolved `localhost` via `AI_NUMERICHOST` to prevent network DNS lookups).
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
- **Expanded Test Suite**:
  - Test suite expanded from 37 to 63 unit, regression, packaging, and integration tests across 6 test modules, all passing with zero errors and zero warnings.

### Changed
- `app/core/privacy/enforcement.py`: Added family awareness, peer destination tracking on connected sockets, and `AI_NUMERICHOST` localhost resolution.
- `app/core/privacy/windows_firewall.py`: Upgraded verification from name-based existence check to full property inspection.
- `app/core/resource_manager/hardware.py`: Represented VRAM metrics as `Optional[int]` and implemented strict 3-state allocation logic.
- `app/core/resource_manager/diagnostic.py`: Safely reports optional VRAM metrics and explicit CPU-only notice on zero/unavailable budget.
- `pyproject.toml`: Added `wheel>=0.40.0` and `setuptools>=65.0.0` to dev optional dependencies.
