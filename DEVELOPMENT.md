# Tsukiko Developer Guide

This document describes development workflows, hardware constraints, testing methodology, and packaging verification for **Tsukiko**.

---

## 1. Workstation & Environment Constraints

Development must strictly conform to the target workstation profile:
* **OS:** Windows 11 x64
* **Python:** 3.11+
* **CPU:** AMD Ryzen 5 5600H (6 Cores / 12 Threads)
* **RAM:** 16 GB DDR4 (~3.5 GB safe LLM budget)
* **GPU:** NVIDIA GeForce RTX 3050 Laptop GPU (4 GB VRAM)
* **Storage:** ~136 GB Available SSD

### Hard Constraints
* **Zero Cloud Services**: Tsukiko must never require cloud APIs or external telemetry.
* **No Premature Model Downloads**: Do not download large weights or models in Phase 1.
* **Fail-Safe Resource Allocation**: VRAM is constrained. If GPU free VRAM is unknown or 0 MB, allocation must fail closed to CPU inference (`recommended_max_vram_mb = 0`).

---

## 2. Environment Setup

### Virtual Environment Initialization
```powershell
# Create dedicated virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install base dependencies and dev dependencies
pip install -r requirements/base.txt
pip install -e ".[dev]"
```

---

## 3. Running Hardware & Compatibility Audits

Inspect workstation CPU, memory, GPU free VRAM, and runtime state:
```powershell
python -m app.main --check-hardware
```

### VRAM Classification States
The resource allocator computes safe VRAM budgets according to three honest states:
1. **`measured`**: GPU exists, total VRAM is known positive, and free VRAM is positive. Safe budget = `min(total - 1200, free - 400)`.
2. **`zero_available`**: GPU exists, total VRAM is known, but free VRAM is confirmed 0 MB. Safe budget = `0 MB` (CPU-only fallback).
3. **`unavailable`**: No discrete GPU, query failed or timed out, or metrics are `[N/A]` / malformed. Safe budget = `0 MB` (CPU-only fallback).

---

## 4. Running the Test Suite

Execute the complete automated test suite (71 unit, regression, packaging, and integration tests):
```powershell
pytest -v
```

### Key Test Modules
* [`tests/test_privacy_enforcement.py`](tests/test_privacy_enforcement.py): Comprehensive socket, connected UDP, send/sendall/sendmsg, deterministic fail-closed DNS, numeric loopback enforcement, socket family restriction, and real/mock AF_UNIX local IPC tests (19 tests).
* [`tests/test_windows_firewall.py`](tests/test_windows_firewall.py): Property-level firewall rule verification, Tsukiko rule ownership identity, PE binary format validation, shared interpreter protection, and 4-state security reporting (19 tests).
* [`tests/test_hardware.py`](tests/test_hardware.py): Hardware inspection, fail-safe VRAM classification matrix, and approximate model footprint estimation (14 tests).
* [`tests/test_entrypoint.py`](tests/test_entrypoint.py): Subprocess-based bounded 5.0s deadlock tests with automatic child process reaping (8 tests).
* [`tests/test_packaging.py`](tests/test_packaging.py): Genuine wheel build, isolated venv installation, and out-of-tree CLI execution (3 tests).
* [`tests/test_config.py`](tests/test_config.py): Pydantic configuration validation, environment variable parsing, and clean state restoration (6 tests).
* [`tests/test_logging.py`](tests/test_logging.py): Structured logging format and destination reconfiguration (2 tests).

---

## 5. Wheel Building and Clean Virtual Environment Verification

To verify that the application installs and runs correctly outside the source tree:

```powershell
# 1. Build wheel into dist/
pip wheel --no-deps -w dist .

# 2. Test in clean isolated virtual environment
$tmpDir = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "tsukiko_clean_test")
New-Item -ItemType Directory -Path $tmpDir -Force
python -m venv "$tmpDir\venv"
& "$tmpDir\venv\Scripts\pip.exe" install (Resolve-Path dist\tsukiko-0.1.0-py3-none-any.whl)

# 3. Execute console command from outside repository checkout
Push-Location $tmpDir
$env:PYTHONPATH = ""
& "$tmpDir\venv\Scripts\tsukiko.exe" --check-hardware
Pop-Location

# 4. Clean up
Remove-Item -Recurse -Force $tmpDir
```

---

## 6. Security & Firewall Architecture

### In-Process Socket Interception
Enforced in [`app/core/privacy/enforcement.py`](app/core/privacy/enforcement.py). Activated automatically at application startup before any subsystem is loaded. Remains active throughout the process lifetime.
* **Numeric Loopback Enforcement**: Connection authorization strictly requires numeric loopback IPs (`127.0.0.0/8`, `::1`).
* **Deterministic Fail-Closed DNS**: Intercepts `getaddrinfo`, `gethostbyname`, `gethostbyname_ex`, `gethostbyaddr`, and `getnameinfo`. Resolves `localhost` locally with `AI_NUMERICHOST`. External hostnames strictly fail closed with `PrivacyViolationError`.
* **Socket Family Restrictions**: Distinguishes `AF_INET`, `AF_INET6`, and `AF_UNIX`. Unsupported families (e.g. `AF_BLUETOOTH`, `AF_NETLINK`) fail closed immediately.
* **In-Process Scope Limitation**: In-process interception operates within user-space Python. It is defense-in-depth and does not replace an OS-level kernel boundary against external processes or native C extensions.

### Windows Firewall Strategy
Enforced in [`app/core/privacy/windows_firewall.py`](app/core/privacy/windows_firewall.py).
* **Rule Ownership**: Unique rule identity (`Tsukiko Outbound Privacy Boundary`), Grouping (`Tsukiko Desktop Companion`), and Description marker (`[Tsukiko-Privacy-Core:Outbound-Block]`). Rejects foreign or unowned rules sharing the Tsukiko prefix.
* **Shared Interpreter Protection**: Rules targeting `python.exe` / `pythonw.exe` are strictly refused.
* **Dedicated Binary Validation**: Targets must be regular files named `tsukiko.exe` containing the Windows DOS/PE `MZ` binary header.
* **PE Header Limitation**: Validating the PE header confirms binary format, not cryptographic Authenticode signature verification.
* **Explicit User Authorization**: Never runs automatic rule modifications at application startup. User authorization (`user_authorized=True`) and administrator elevation are strictly required.

---

## 7. Continuous Integration (CI)

A dedicated Windows CI workflow is established at [`.github/workflows/ci.yml`](.github/workflows/ci.yml).
* **Runner**: Windows Server (`windows-latest`).
* **Environment**: Python 3.11 x64.
* **Pipeline**:
  1. Installs base and developer dependencies.
  2. Runs full 71-test pytest suite.
  3. Builds distribution wheel (`tsukiko-*.whl`).
  4. Installs wheel and executes `tsukiko --check-hardware` outside source tree.

---

## 8. Change History & Audit Logs

* See [`CHANGELOG.md`](CHANGELOG.md) for versioned release history.
* See [`DEVELOPMENT_LOG.md`](DEVELOPMENT_LOG.md) for detailed audit findings, defects resolved, and verification ledgers.
