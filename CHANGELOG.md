# Changelog

All notable changes to the Tsukiko project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] - Phase 1 Security, Reliability & Architecture Hardening - 2026-11-11

### Added
- **Low-Level Socket & DNS Interception Hooks**: Expanded `app.core.privacy.enforcement` to hook `socket.connect`, `connect_ex`, `sendto` (UDP datagrams), `create_connection`, `getaddrinfo`, `gethostbyname`, `gethostbyname_ex`, `gethostbyaddr`, and `getnameinfo`. All unauthorized non-loopback calls raise `PrivacyViolationError`.
- **Strict Address Validation**: Implemented strict loopback address validation permitting only genuine IPv4 (`127.0.0.0/8`), IPv6 (`::1`), and loopback-resolved `localhost`. Strictly rejects unspecified addresses (`0.0.0.0`, `::`), empty strings, and external domains.
- **Atomic Guard Rollback & Persistent Lifecycle**: Added atomic rollback if socket patching fails partway through. Ensured normal orchestrator shutdown does not disable the in-process network guard while the process remains alive.
- **Windows Firewall Policy Manager (`app.core.privacy.windows_firewall`)**: Implemented safe, application-specific OS-level firewall rule generation for dedicated application binaries (`tsukiko.exe`). Explicitly refuses to create firewall rules against shared Python interpreters (`python.exe`, `pythonw.exe`) to prevent workstation disruption.
- **Honest Security Status Reporting**: Added `get_security_status()` distinguishing `in_process_only`, `os_policy_not_configured`, and `os_policy_active`.
- **Fail-Safe Dynamic VRAM Budgeting**: In `HardwareInspector.inspect()`, eliminated hardcoded 2800 MB fallbacks. Added `budget_status` categorization: `measured`, `zero_available`, and `unavailable`. If free VRAM is 0 MB or GPU query fails, GPU allocation budget is safely set to 0 MB and CPU-only inference is chosen.
- **Isolated Subprocess Deadlock Tests**: Implemented bounded 5.0-second child-process deadlock tests in `tests/test_entrypoint.py` with automatic process reaping for direct `start()`, repeated `start()`, repeated `stop()`, initialization failure recovery, and guard lifecycle.
- **Clean Virtual Environment Package Verification**: Built wheel `tsukiko-0.1.0-py3-none-any.whl`, installed in an isolated temporary virtual environment outside the repository checkout without `PYTHONPATH`, and verified `tsukiko --check-hardware`.
- **Comprehensive Test Suite**: Expanded test suite to 37 passing unit, regression, packaging, and integration tests.

### Changed
- `app/main.py`: Activates `enable_offline_guard()` prior to subsystem initialization; runs `--check-hardware` cleanly via packaged diagnostic module.
- `app/core/orchestrator/engine.py`: Removed `disable_offline_guard()` call in `stop()`, preserving process-lifetime security invariants.
- `app/core/resource_manager/diagnostic.py`: Removed `profile.recommended_max_vram_mb or 2800` fallback; reports exact `budget_status` and dynamic safe VRAM cap.
- `pyproject.toml`: Configured package data inclusion for YAML configuration files and registered console script entrypoint `tsukiko = app.main:main`.

### Fixed
- Fixed unhooked UDP, `connect_ex`, and extended resolver calls (`gethostbyname_ex`, `gethostbyaddr`, `getnameinfo`).
- Fixed vulnerability allowing unspecified addresses (`0.0.0.0`, `::`) to bypass loopback checks.
- Fixed potential in-thread deadlock testing by executing lifecycle checks in isolated subprocesses with strict timeouts.
- Fixed VRAM budgeting falling back to static ceiling when available VRAM was 0.
