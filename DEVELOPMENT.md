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

# Install base dependencies, UI dependencies, and dev dependencies
pip install -r requirements/base.txt
pip install -r requirements/ui.txt
pip install -e ".[dev]"

# Optional: Install local inference engine (llama-cpp-python)
# CPU-only:
pip install -r requirements/ai.txt
# Or CUDA 12.4 accelerated (see MODEL_COMPATIBILITY.md):
# pip install llama-cpp-python --extra-index-url https://abetlen.github.io/llama-cpp-python/whl/cu124
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

Execute the complete automated test suite (403 test items: 399 passed, 4 Unix-specific skipped on Windows; 401 passed, 2 skipped on Linux):
```powershell
pytest -v
```

### Key Test Modules
* [`tests/test_local_brain.py`](tests/test_local_brain.py): Comprehensive verification of the Phase 3 local AI brain subsystem: pure-Python binary GGUF parser and metadata validation, ModelManager 9-state lifecycle machine, safe RAM/VRAM offload calculations, headroom preservation, insufficient memory rejection, engine abstraction, non-thinking personality prompts and reasoning token stripping, temporary in-memory history pruning, ChatWorker QThread streaming, cancellation, error bubbles with retry, clear chat, Settings card model loading/unloading, SystemStatus telemetry, character identity (12 canonical milestones, Sayo, 1814-1846, Ogimachi, Unfinished Atlas, snake dread, practical craft), 4-stage rapport-gated gradual self-disclosure (`ACQUAINTANCE`, `FAMILIAR`, `TRUSTED`, `CONFIDANT`), stage-isolated prompt content, automatic proactive conversation scheduling via `CompanionInitiativeScheduler` and `ProactiveInitiativeWorker(QThread)`, non-repetitive safeguards, silence token handling (`[SILENCE]`), suppression under Game Mode/hidden widget/unloaded model/fullscreen game states, desktop `CompanionSpeechBubble`, reentrant reload safety without deadlocks, and zero-telemetry offline invariants (55 tests).
* [`tests/test_desktop_companion.py`](tests/test_desktop_companion.py): Verifies complete Phase 2 PySide6 desktop companion UI: Moonlight theme styling, procedural vector avatar rendering, floating companion widget, compact left menu ordering and locked states, safe fullscreen detection with Win32 ctypes signatures, speech bubble fullscreen safety policy (immediate dismissal during fullscreen games, suppression during fullscreen, fail-safe on detector errors, safe resumption upon exit), Game Mode animation suspension without game hooking, system tray recovery and fallback mode, dynamic settings application and YAML persistence, SystemStatusView real hardware telemetry, PrivacyView locked sensors, MemoryView zero-database placeholder, SettingsView validation, and CLI/headless execution (54 tests).
* [`tests/test_windows_firewall.py`](tests/test_windows_firewall.py): Windows PE structural binary validation, fail-closed profile validation, ActiveStore effective policy inspection, complete 18-property NetSecurity CIM filter verification across all 7 categories, lossless `CimFieldRecord` deserialization, strict CIM field-state invariants, non-null StringValue consistency checks, filter association integrity (`Count -eq 1`), unmanufactured ActiveStore Outbound Allow bypass evaluation (`OverrideBlockRules=True`) with literal wildcard detection across exact executable and all-programs scopes without error suppression, broad type category preservation, precise rule ownership identity, safe deletion by stable internal Name, strict 8-key response envelope validation, and structured query result parsing (224 tests).
* [`tests/test_privacy_enforcement.py`](tests/test_privacy_enforcement.py): Comprehensive socket, connected UDP, send/sendall/sendmsg, real native sendmsg data exchange, deterministic fail-closed DNS, numeric loopback enforcement, socket family restriction, and real/mock AF_UNIX local IPC tests (22 tests).
* [`tests/test_hardware.py`](tests/test_hardware.py): Hardware inspection, fail-safe VRAM classification matrix, and approximate model footprint estimation (14 tests).
* [`tests/test_entrypoint.py`](tests/test_entrypoint.py): Subprocess-based bounded 5.0s deadlock tests with automatic child process reaping (8 tests).
* [`tests/test_config.py`](tests/test_config.py): Pydantic configuration validation, environment variable parsing, clean state restoration, and safe defaults / integrity regression checks (7 tests).
* [`tests/test_packaging.py`](tests/test_packaging.py): Genuine wheel build, isolated venv installation, and out-of-tree CLI execution (3 tests).
* [`tests/test_logging.py`](tests/test_logging.py): Structured logging format and destination reconfiguration (2 tests).

---

## 5. Dual-Platform CI Matrix

Continuous Integration runs on GitHub Actions across two distinct environments:
1. **Windows 11 (`windows-latest`)**: Validates Windows environment integration, packaging, wheel installation, out-of-tree CLI execution, full desktop companion UI with offscreen Qt platform, local AI brain verification, and real read-only Windows Firewall ActiveStore policy inspection with all 7 filter cmdlets, 18 CIM filter properties, and 26 schema fields (399 passed, 4 Unix-specific skipped).
2. **Linux (`ubuntu-latest`)**: Validates full 403-test suite including genuine native `sendmsg` (TCP/UDP) communication, real `AF_UNIX` domain socket IPC, offscreen PySide6 UI, and local AI brain inference abstractions (401 passed, 2 skipped).

> [!NOTE]
> **Decoupled AI Dependencies in CI**: In CI environments, `llama-cpp-python: installed=False` by design. All test suites exercise the local brain lifecycle, memory budgeting, streaming worker threads, and character disclosure engines using `DeterministicFakeEngine` without requiring heavy native compilation or multi-gigabyte weight downloads. Actual Qwen3.5 neural inference is executed by users on their local workstations with their own downloaded GGUF weights.

---

## 6. Wheel Building and Clean Virtual Environment Verification

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
* **Rule Ownership**: Unique rule identity (`Tsukiko Outbound Privacy Boundary`), Stable Internal ID (`Tsukiko_Privacy_Outbound_Block`), Grouping (`Tsukiko Desktop Companion`), and Description marker (`[Tsukiko-Privacy-Core:Outbound-Block]`). Rejects foreign or unowned rules sharing the Tsukiko prefix.
* **Exact-Name Deletion**: Rule removal strictly targets `-Name Tsukiko_Privacy_Outbound_Block -PolicyStore PersistentStore`. Rules are never deleted by DisplayName alone. Refuses automatic deletion of legacy rules lacking the internal stable ID. Post-deletion inspection re-verifies removal.
* **NetSecurity CIM Filter Verification**:
  * Inspects all 7 filter categories: Application, Address, Port/Protocol, Service, Interface, Interface-Type, and Security.
  * Security filter strictly enforces Microsoft CIM properties: `Authentication == "NotRequired"`, `Encryption == "NotRequired"`, `OverrideBlockRules is False` (genuine boolean), and unrestricted `LocalUser`, `RemoteUser`, and `RemoteMachine` covering `Any`. Legacy plural property names or restrictive values fail closed.
* **Fail-Closed Parsing & Envelopes**:
  * Inspection commands run under `$ErrorActionPreference = 'Stop'` and return structured JSON response envelopes `{ "Success": bool, "InspectionComplete": bool, "Rules": [...], "Error": string|null }`.
  * Python query handlers require `Success=True` and `InspectionComplete=True`. Truncated, empty, or failed queries fail closed and are never conflated with rule absence.
  * Parser preserves missing and null values as `None`, strictly failing closed without manufacturing artificial defaults (`"Any"`).
* **Shared Interpreter Protection**: Rules targeting `python.exe` / `pythonw.exe` are strictly refused.
* **Dedicated Binary Validation**: Targets must be regular files named `tsukiko.exe` containing the Windows DOS/PE `MZ` binary header.
* **PE Header Limitation**: Validating the PE header confirms binary format, not cryptographic Authenticode signature verification.
* **Explicit User Authorization**: Never runs automatic rule modifications at application startup. User authorization (`user_authorized=True`) and administrator elevation are strictly required.
* **Read-Only Inspection Verification**: Windows CI runs [`scripts/verify_windows_firewall_inspection.py`](scripts/verify_windows_firewall_inspection.py) with 6 stages (profiles, unmanufactured bypass discovery, 26-field schema, CIM field-state consistency & boolean fidelity, parser & synthetic rejections, fail-closed cmdlet error behavior) with strictly zero system mutations.

---

## 7. Continuous Integration (CI)

A dual-platform CI workflow is established at [`.github/workflows/ci.yml`](.github/workflows/ci.yml).
* **Matrix Runners**:
  * Windows Server (`windows-latest`, Python 3.11 x64).
  * Ubuntu Linux (`ubuntu-latest`, Python 3.11 x64).
* **Pipeline**:
  1. Installs base and developer dependencies.
  2. Runs full 403-item pytest suite (399 passed, 4 skipped on Windows; 401 passed, 2 skipped on Linux).
  3. Builds distribution wheel (`tsukiko-*.whl`).
  4. Installs wheel in clean environment and executes `tsukiko --check-hardware` outside source tree.
  5. Windows runner executes read-only ActiveStore inspection verification (`scripts/verify_windows_firewall_inspection.py`).

---

## 8. Change History & Audit Logs

* See [`CHANGELOG.md`](CHANGELOG.md) for versioned release history.
* See [`DEVELOPMENT_LOG.md`](DEVELOPMENT_LOG.md) for detailed audit findings, defects resolved, and verification ledgers.
