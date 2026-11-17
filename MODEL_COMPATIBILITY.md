# Tsukiko Local AI Model Compatibility & Hardware Offloading Guide (Phase 3)

This document provides technical specifications, hardware memory limits, quantization guidance, runtime installation procedures, and compatibility matrices for **Tsukiko Phase 3: Local AI Brain**.

---

## 1. Primary Model Specification

| Attribute | Specification |
|---|---|
| **Model Name** | Qwen/Qwen3.5-2B (Instruction-Tuned) |
| **Original Architecture** | Qwen 2.5 / 3.5 Transformer Architecture |
| **GGUF Repository** | [`https://huggingface.co/gguf/Qwen3.5-2B-GGUF`](https://huggingface.co/gguf/Qwen3.5-2B-GGUF) |
| **Recommended Quantization** | **`Q4_K_M`** (Medium 4-bit K-quantization) |
| **Model Weight File Size** | ~1.31 GB |
| **Default Context Window** | 4,096 tokens (Architecture supports up to 32,768 tokens) |
| **License & Attribution** | **Apache-2.0** (Qwen Team, Alibaba Cloud) |
| **Reasoning Mode** | **Non-Thinking Mode** (Internal `<think>` tokens suppressed) |
| **Multimodal / Vision** | **Disabled** (Vision projector is strictly Phase 5) |

---

## 2. Workstation Hardware Profile & Safe Memory Budgets

### Workstation Target Profile
* **Operating System:** Windows 11 Home/Pro 64-bit
* **Processor (CPU):** AMD Ryzen 5 5600H (6 Cores / 12 Threads, AVX2 support)
* **System RAM:** 16 GB DDR4 (Configured safe LLM ceiling: **3,500 MB**)
* **Dedicated GPU:** NVIDIA GeForce RTX 3050 Laptop GPU (4 GB VRAM)
* **Storage:** ~136 GB Available NVMe SSD

### VRAM & RAM Budget Calculation Rules
Tsukiko applies non-negotiable memory safety rules:
1. **Measured Dynamic Safety**:
   $$\text{Safe VRAM Budget} = \min\left(\text{AIConfig.max\_vram\_mb}, \text{HardwareProfile.recommended\_max\_vram\_mb}\right)$$
   where `recommended_max_vram_mb` is computed as:
   $$\min\left(\max(0, \text{Total VRAM} - 1200\text{ MB}), \max(0, \text{Free VRAM} - 400\text{ MB})\right)$$
2. **Headroom Guarantee**: Maintains at least **400 MB of VRAM headroom** beyond any calculated GPU allocation to prevent OS desktop stutter.
3. **Fail-Safe CPU Fallback**: If `Free VRAM == 0` or GPU state is `unavailable` or `llama_cpp_cuda_supported` is `False`, Tsukiko automatically sets `gpu_layers = 0` (CPU-only AVX2 inference).
4. **Graceful RAM Protection**: If available system RAM is less than model size + 400 MB headroom, model loading is rejected gracefully with `InsufficientMemoryError` rather than crashing the process.

---

## 3. Quantization Evaluation & Sizing Matrix

For a 2B–3B parameter instruction-tuned model within Tsukiko's 2,800 MB safe VRAM ceiling:

| Quantization | File Size | Estimated Weights | KV Cache (4K ctx) | CUDA Overhead | Total VRAM Required | Safe on 4GB RTX 3050? | Recommended Strategy |
|---|---|---|---|---|---|---|---|
| **Q4_K_M** | **~1.31 GB** | **~1,340 MB** | **~450 MB** | **~400 MB** | **~2,190 MB** | **YES (Headroom ~610 MB)** | **Full GPU Offload** (`gpu_layers: -1` or 28) |
| **Q4_0** | ~1.28 GB | ~1,310 MB | ~450 MB | ~400 MB | ~2,160 MB | **YES (Headroom ~640 MB)** | Full GPU Offload |
| **Q5_K_M** | ~1.55 GB | ~1,590 MB | ~450 MB | ~400 MB | ~2,440 MB | **YES (Borderline ~360 MB)** | Hybrid / Partial GPU Offload |
| **Q8_0** | ~2.15 GB | ~2,200 MB | ~450 MB | ~400 MB | ~3,050 MB | **NO (Exceeds 2800 MB)** | CPU-Only or Partial Offload |
| **F16** | ~3.80 GB | ~3,890 MB | ~450 MB | ~400 MB | ~4,740 MB | **NO (Exceeds 4GB Total)** | Not supported on target laptop |

---

## 4. Inference Engine Installation Procedures

Inference libraries are kept completely optional and decoupled from base dependencies. The core application runs cleanly in headless and UI modes without `llama-cpp-python`.

### Option A: Optimized CPU-Only Runtime (Default Fallback)
For lightweight CPU execution using AVX2 instructions:
```powershell
pip install llama-cpp-python --extra-index-url https://abetlen.github.io/llama-cpp-python/whl/cpu
```

### Option B: CUDA 12.x Hardware-Accelerated Runtime (RTX 3050 Laptop)
For GPU offloading via NVIDIA CUDA:
```powershell
# Verify NVIDIA GPU driver and CUDA 12 support
nvidia-smi

# Install prebuilt CUDA 12.4 wheel
pip install llama-cpp-python --extra-index-url https://abetlen.github.io/llama-cpp-python/whl/cu124
```

> [!IMPORTANT]
> Tsukiko never silently installs CUDA wheels or forces source compilation. Check `python -m app.main --check-hardware` after installation to verify `llama_cpp_cuda_supported: True`.

---

## 5. Model Acquisition & Local Path Setup

In accordance with Phase 1 and Phase 3 privacy invariants, Tsukiko **never downloads model weights automatically** over the network.

### Step 1: Download GGUF Weight File
Download the official GGUF release from Hugging Face:
- URL: `https://huggingface.co/gguf/Qwen3.5-2B-GGUF/resolve/main/Qwen3.5-2B-Instruct-Q4_K_M.gguf`
- Save destination (example): `C:\Tsukiko\models\Qwen3.5-2B-Instruct-Q4_K_M.gguf`

### Step 2: Configure Tsukiko Model Path
You can configure the model path via either method:
1. **Via Desktop Companion UI**:
   - Open Tsukiko -> Settings -> **Local AI Brain & Inference**.
   - Click **Browse...** and select your `.gguf` file.
   - Click **Validate GGUF** to inspect metadata.
   - Click **Apply Settings**.
2. **Via Configuration YAML (`config/default_config.yaml`)**:
   ```yaml
   ai:
     engine: "llama_cpp"
     model_path: "C:/Tsukiko/models/Qwen3.5-2B-Instruct-Q4_K_M.gguf"
     context_window: 4096
     threads: 6
     gpu_layers: 0 # 0 for CPU, -1 for auto full-GPU offload
     max_vram_mb: 2800
     max_ram_mb: 3500
     backend: "auto"
     lazy_load: true
     unload_timeout_seconds: 300
   ```

---

## 6. Verification Status & Test Evidence Classification

To maintain scientific integrity and prevent hallucinated benchmark claims, all capabilities are explicitly classified:

| Capability / Subsystem | Verification Level | Details |
|---|---|---|
| **Binary GGUF Parser (`gguf_parser.py`)** | **Implemented & Tested** | Tested against genuine binary GGUF structures. Validates magic `GGUF`, version 2/3, tensor counts, KV metadata, block counts, and quantization formats. |
| **Model Lifecycle State Machine (`lifecycle.py`)** | **Implemented & Tested** | 9 discrete states verified: `NOT_CONFIGURED`, `NOT_INSTALLED`, `VALIDATING`, `READY`, `LOADING`, `LOADED`, `GENERATING`, `UNLOADING`, `ERROR`. |
| **Memory & VRAM Safety Budgeting** | **Implemented & Tested** | Unit tested against simulated low-RAM (rejection) and low-VRAM (safe CPU fallback) hardware profiles. |
| **Inactivity Auto-Unloading** | **Implemented & Tested** | Verified background timer unloading after 300 seconds of inactivity without interrupting active generations. |
| **Streaming UI Worker (`chat.py`)** | **Implemented & Tested** | Offscreen Qt test verifies `ChatWorker(QThread)` non-blocking progressive token emission, auto-scroll, stop generation, and retry button. |
| **Deterministic Test Double (`engine.py`)** | **Implemented & Tested** | `DeterministicFakeEngine` verifies streaming, cancellation, and error handling without external model weights. |
| **Actual GGUF Inference on Physical Hardware** | **Staged for User Testing** | Requires user to download the recommended `Qwen3.5-2B-Instruct-Q4_K_M.gguf` file to their physical laptop. |
| **Token-Per-Second Benchmarks on RTX 3050** | **Pending Physical Measurement** | No synthetic or estimated token-per-second values are claimed prior to physical benchmarking on the user's laptop. |
