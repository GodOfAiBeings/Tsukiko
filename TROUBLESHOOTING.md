# Tsukiko Troubleshooting & Diagnostics Guide

This document describes how to diagnose and resolve common issues encountered on Windows 11.

---

## 1. Hardware Inspection Diagnostics

If Tsukiko fails to detect your NVIDIA GPU or reports incorrect VRAM:
1. Run `python scripts/check_hardware.py` in your active virtual environment.
2. Confirm `nvidia-smi` works from PowerShell.
3. If `nvidia-smi` is missing, ensure NVIDIA drivers are installed and `C:\Windows\System32` or the NVIDIA Corporation path is in your system `PATH`.

---

## 2. Virtual Environment & Execution Policy Issues

**Symptom:**
`.\.venv\Scripts\Activate.ps1 cannot be loaded because running scripts is disabled on this system.`

**Solution:**
Allow signed scripts for the current process:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
.\.venv\Scripts\Activate.ps1
```

---

## 3. Windows File Locking During Log Cleanup (WinError 32)

**Symptom:**
`PermissionError: [WinError 32] The process cannot access the file because it is being used by another process: tsukiko.log`

**Solution:**
On Windows, file handlers must be explicitly closed before files can be deleted or rotated. Always call:
```python
from app.core.logging.logger import shutdown_logging
shutdown_logging()
```
before cleaning up temporary directories or terminating test sessions.

---

## 4. CUDA Availability vs. PyTorch Wheels

**Symptom:**
`HardwareInspector.check_cuda_runtime()` returns `False` despite `nvidia-smi` showing CUDA support.

**Explanation:**
The NVIDIA display driver reports the maximum supported CUDA version (e.g. CUDA 13.4), but Python ML frameworks (PyTorch / llama-cpp-python) require precompiled binary wheels linked against CUDA (e.g. cu121 or cu124).
When installing PyTorch, always specify the CUDA wheel index:
```powershell
pip install torch --index-url https://download.pytorch.org/whl/cu124
```
For `llama-cpp-python`, use prebuilt CUDA wheels matching your Python version (cp311).
