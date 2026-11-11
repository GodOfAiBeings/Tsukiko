# Tsukiko Model Compatibility & Hardware Budget Guide

This document benchmarks model candidates against the specific hardware profile of the target workstation:
* **CPU:** AMD Ryzen 5 5600H (6 Cores / 12 Threads, AVX2 enabled)
* **RAM:** 16 GB Total (~6 GB available for application workloads)
* **GPU:** NVIDIA GeForce RTX 3050 Laptop GPU (4096 MB VRAM, ~3600 MB free)
* **Storage:** 137 GB SSD available

---

## 1. VRAM & RAM Budget Breakdown

| Component | VRAM Consumption | System RAM Consumption | Notes |
|---|---|---|---|
| Windows DWM & Background Apps | ~350–500 MB | ~6000–9000 MB | Baseline system footprint |
| Tsukiko PySide6 GUI & Buffers | ~50–100 MB | ~150–250 MB | Low footprint desktop presence |
| Frame Capture Buffer (1080p) | ~20–40 MB | ~50–100 MB | In-memory frame diffing buffer |
| **Safe LLM Inference Ceiling** | **~2800 MB** | **~3500 MB** | Maximum safe model allocation |

---

## 2. Conversational Model Candidates (Evaluated for Phase 3)

| Model Architecture | Quantization | Parameter Count | File Size | Recommended Offload | Compatibility Assessment |
|---|---|---|---|---|---|
| **Llama-3.2-3B-Instruct** | Q4_K_M | 3.2B | ~2.0 GB | Full GPU (all layers) | **Primary Candidate (Fast, fits in 4GB VRAM)** |
| **Qwen2.5-3B-Instruct** | Q4_K_M | 3.0B | ~1.9 GB | Full GPU (all layers) | **Strong Candidate (High coding/reasoning quality)** |
| **Phi-3.5-mini-instruct** | Q4_K_M | 3.8B | ~2.3 GB | Full GPU (~2.3GB VRAM) | **Strong Candidate (Solid reasoning)** |
| **Llama-3.1-8B-Instruct** | Q4_K_M | 8.0B | ~4.9 GB | Hybrid CPU/GPU (~2GB GPU + 3GB RAM) | **Viable with hybrid offload, slower generation** |
| **Mistral-7B-Instruct-v0.3** | Q4_K_M | 7.2B | ~4.4 GB | Hybrid CPU/GPU | **Requires hybrid offload** |

### Decision Rule
* For natural, real-time dialogue responsiveness on a 4GB VRAM laptop, **3B–4B parameter models quantized to Q4_K_M** offer the optimal balance of intelligence, speed (>20 tokens/sec), and memory safety.

---

## 3. Vision Model Candidates (Evaluated for Phase 5)

| Vision Model | Quantization | Size | Offload Strategy | Assessment |
|---|---|---|---|---|
| **Moondream2** | Int8 / Q4 | ~1.5 GB | Dedicated GPU or CPU | Ultra-fast lightweight desktop query answers |
| **Qwen2-VL-2B-Instruct** | Q4_K_M | ~1.8 GB | Sequential GPU load | High visual precision for window & code inspection |
| **MiniCPM-V-2.6** | Q4_K_M | ~5.5 GB | Hybrid CPU/GPU | High capability, high latency on 4GB VRAM |

### Multi-Model Memory Policy
Because the RTX 3050 has 4GB VRAM, **never attempt to run the 3B Conversational LLM and a 2B+ Vision Model simultaneously in GPU VRAM**.
1. Screen perception uses continuous lightweight OCR and change detection.
2. When deep visual reasoning is required, the conversational model state is checkpointed, VRAM is reallocated or vision runs sequentially / on CPU, and findings are fed back to the conversational context.

---

## 4. Voice Model Candidates (Evaluated for Phase 6)

| Component | Engine | Model Size | Hardware Placement | Latency Target |
|---|---|---|---|---|
| **Speech-to-Text (STT)** | Faster-Whisper / Whisper.cpp | `tiny.en` / `base.en` (~75–140 MB) | CPU (multithreaded int8) | < 300 ms |
| **Text-to-Speech (TTS)** | Piper TTS | `en_US-lessac-medium` (~60 MB) | CPU (onnxruntime / direct) | < 200 ms |
| **TTS Fallback** | Windows SAPI5 (`pyttsx3`) | 0 MB (Built into Windows) | CPU | Immediate |
