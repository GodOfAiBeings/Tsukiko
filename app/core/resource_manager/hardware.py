"""
Tsukiko Hardware Inspection and Resource Management
Inspects CPU, RAM, GPU (VRAM), storage, and framework compatibility.
Computes safe memory budgets and realistic offloading recommendations for low-VRAM machines.
"""

from __future__ import annotations

import os
from pathlib import Path
import platform
import shutil
import subprocess
from typing import Any, Dict, List, Optional
import psutil
from pydantic import BaseModel, Field

from app.core.logging.logger import get_logger

logger = get_logger("RESOURCE")


def _safe_parse_int(val: Any, default: int = 0) -> int:
    """Safely parses integer values from CLI outputs (handles [N/A], [Not Supported], non-numeric)."""
    if val is None:
        return default
    try:
        cleaned = str(val).strip()
        if not cleaned or cleaned.startswith("[") or "not" in cleaned.lower() or "n/a" in cleaned.lower():
            return default
        return int(float(cleaned))
    except (ValueError, TypeError):
        return default


def _safe_parse_float(val: Any, default: Optional[float] = None) -> Optional[float]:
    """Safely parses float values from CLI outputs (handles [N/A], [Not Supported], non-numeric)."""
    if val is None:
        return default
    try:
        cleaned = str(val).strip()
        if not cleaned or cleaned.startswith("[") or "not" in cleaned.lower() or "n/a" in cleaned.lower():
            return default
        return float(cleaned)
    except (ValueError, TypeError):
        return default


class GPUInfo(BaseModel):
    name: str = "Unknown GPU"
    driver_version: str = "N/A"
    cuda_driver_version: str = "N/A"
    total_vram_mb: int = 0
    used_vram_mb: int = 0
    free_vram_mb: int = 0
    temperature_c: Optional[int] = None
    power_draw_w: Optional[float] = None
    cuda_runtime_available: bool = False
    details: Dict[str, Any] = Field(default_factory=dict)


class SystemMemoryInfo(BaseModel):
    total_ram_mb: int
    available_ram_mb: int
    used_ram_mb: int
    percent_used: float


class CPUInfo(BaseModel):
    brand: str
    physical_cores: int
    logical_cores: int
    utilization_percent: float


class StorageInfo(BaseModel):
    drive_path: str
    total_gb: float
    free_gb: float
    used_gb: float


class FrameworkSupport(BaseModel):
    llama_cpp_installed: bool = False
    llama_cpp_cuda_supported: bool = False
    torch_installed: bool = False
    torch_cuda_supported: bool = False
    onnxruntime_installed: bool = False
    onnxruntime_cuda_supported: bool = False
    notes: List[str] = Field(default_factory=list)


class ModelMemoryEstimate(BaseModel):
    model_name: str
    file_size_mb: int
    context_window: int
    estimated_weights_vram_mb: int
    estimated_kv_cache_mb: int
    runtime_overhead_mb: int
    total_vram_required_mb: int
    fits_in_vram: bool
    recommended_offload_strategy: str  # "full_gpu", "hybrid_cpu_gpu", "cpu_only"
    is_approximate: bool = True
    disclaimer: str = (
        "Approximate estimate. Actual VRAM depends on model architecture, GGUF tensor layout, "
        "context length, and concurrent desktop GPU workloads."
    )
    details: str


class HardwareProfile(BaseModel):
    os_name: str
    os_version: str
    cpu: CPUInfo
    memory: SystemMemoryInfo
    storage: StorageInfo
    gpus: List[GPUInfo] = Field(default_factory=list)
    has_nvidia_gpu: bool = False
    recommended_max_vram_mb: int = 0
    currently_available_vram_mb: int = 0
    static_vram_ceiling_mb: int = 0
    dynamic_safe_vram_mb: int = 0
    recommended_max_ram_mb: int = 0
    frameworks: FrameworkSupport = Field(default_factory=FrameworkSupport)
    recommendations: List[str] = Field(default_factory=list)


class HardwareInspector:
    """Inspects the local Windows environment, hardware limits, and framework state."""

    @classmethod
    def get_cpu_info(cls) -> CPUInfo:
        cpu_brand = platform.processor() or "AMD/Intel x86_64"
        if platform.system() == "Windows":
            try:
                import winreg
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0")
                cpu_brand, _ = winreg.QueryValueEx(key, "ProcessorNameString")
                winreg.CloseKey(key)
            except Exception:
                pass

        p_cores = psutil.cpu_count(logical=False) or 4
        l_cores = psutil.cpu_count(logical=True) or 8
        usage = psutil.cpu_percent(interval=0.1)
        return CPUInfo(
            brand=cpu_brand.strip(),
            physical_cores=p_cores,
            logical_cores=l_cores,
            utilization_percent=usage,
        )

    @classmethod
    def get_memory_info(cls) -> SystemMemoryInfo:
        mem = psutil.virtual_memory()
        return SystemMemoryInfo(
            total_ram_mb=int(mem.total / (1024 * 1024)),
            available_ram_mb=int(mem.available / (1024 * 1024)),
            used_ram_mb=int(mem.used / (1024 * 1024)),
            percent_used=mem.percent,
        )

    @classmethod
    def get_storage_info(cls, target_path: str = ".") -> StorageInfo:
        path = Path(target_path).resolve()
        drive_root = path.anchor or "C:\\"
        usage = shutil.disk_usage(drive_root)
        return StorageInfo(
            drive_path=drive_root,
            total_gb=round(usage.total / (1024**3), 2),
            free_gb=round(usage.free / (1024**3), 2),
            used_gb=round(usage.used / (1024**3), 2),
        )

    @classmethod
    def parse_nvidia_smi_output(cls, stdout_text: str) -> List[GPUInfo]:
        """Safely parses nvidia-smi CSV output, handling missing fields, [N/A], and non-numeric metrics."""
        gpus: List[GPUInfo] = []
        for line in stdout_text.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 5:
                gpu_name = parts[0]
                driver_ver = parts[1]
                total_mb = _safe_parse_int(parts[2], 0)
                used_mb = _safe_parse_int(parts[3], 0)
                free_mb = _safe_parse_int(parts[4], 0)
                temp_c = _safe_parse_int(parts[5], 0) if len(parts) > 5 and parts[5] not in ("[N/A]", "[Not Supported]") else None
                power_w = _safe_parse_float(parts[6]) if len(parts) > 6 else None

                gpus.append(
                    GPUInfo(
                        name=gpu_name,
                        driver_version=driver_ver,
                        total_vram_mb=total_mb,
                        used_vram_mb=used_mb,
                        free_vram_mb=free_mb,
                        temperature_c=temp_c,
                        power_draw_w=power_w,
                    )
                )
        return gpus

    @classmethod
    def query_nvidia_smi(cls) -> List[GPUInfo]:
        """Queries nvidia-smi for precise VRAM and GPU statistics."""
        nvidia_smi_path = shutil.which("nvidia-smi")
        if not nvidia_smi_path:
            return []

        try:
            cmd = [
                nvidia_smi_path,
                "--query-gpu=name,driver_version,memory.total,memory.used,memory.free,temperature.gpu,power.draw",
                "--format=csv,noheader,nounits",
            ]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
                timeout=5,
            )
            return cls.parse_nvidia_smi_output(result.stdout)
        except Exception as e:
            logger.warning(f"Failed to query nvidia-smi: {e}")
            return []

    @classmethod
    def check_framework_compatibility(cls) -> FrameworkSupport:
        """Inspects actual installed machine learning runtimes for CUDA acceleration."""
        support = FrameworkSupport()

        # 1. llama-cpp-python check (primary target runtime for Tsukiko)
        try:
            import llama_cpp  # type: ignore
            support.llama_cpp_installed = True
            if hasattr(llama_cpp, "llama_supports_gpu_offload"):
                support.llama_cpp_cuda_supported = bool(llama_cpp.llama_supports_gpu_offload())
            support.notes.append(
                f"llama-cpp-python: installed (GPU offload supported: {support.llama_cpp_cuda_supported})"
            )
        except ImportError:
            support.llama_cpp_installed = False
            support.llama_cpp_cuda_supported = False
            support.notes.append("llama-cpp-python: not installed in active environment.")
        except Exception as e:
            support.llama_cpp_installed = True
            support.llama_cpp_cuda_supported = False
            support.notes.append(f"llama-cpp-python: import error ({e})")

        # 2. PyTorch check
        try:
            import torch  # type: ignore
            support.torch_installed = True
            support.torch_cuda_supported = bool(torch.cuda.is_available())
            support.notes.append(f"torch: installed (CUDA available: {support.torch_cuda_supported})")
        except ImportError:
            support.torch_installed = False
            support.torch_cuda_supported = False
            support.notes.append("torch: not installed.")
        except Exception as e:
            support.torch_installed = True
            support.torch_cuda_supported = False
            support.notes.append(f"torch: import error ({e})")

        # 3. ONNX Runtime check
        try:
            import onnxruntime as ort  # type: ignore
            support.onnxruntime_installed = True
            providers = ort.get_available_providers()
            support.onnxruntime_cuda_supported = "CUDAExecutionProvider" in providers
            support.notes.append(
                f"onnxruntime: installed (CUDA provider available: {support.onnxruntime_cuda_supported})"
            )
        except ImportError:
            support.onnxruntime_installed = False
            support.onnxruntime_cuda_supported = False
            support.notes.append("onnxruntime: not installed.")
        except Exception as e:
            support.onnxruntime_installed = True
            support.onnxruntime_cuda_supported = False
            support.notes.append(f"onnxruntime: import error ({e})")

        return support

    @classmethod
    def estimate_model_vram_footprint(
        cls,
        file_size_mb: int,
        context_window: int = 4096,
        model_name: str = "Quantized LLM",
        available_vram_mb: int = 2800,
    ) -> ModelMemoryEstimate:
        """Calculates realistic VRAM requirements including weights, KV cache, activations, and CUDA runtime.

        All estimates are labeled as approximate.
        Total VRAM = Model Weights + Context KV Cache + Compute/Scratch Buffers + CUDA Context Overhead.
        """
        weights_mb = file_size_mb

        # Estimate KV cache footprint (~0.11 MB per token for standard 3B-4B architectures with 4096 context)
        # Baseline: 4096 tokens in FP16 KV cache ~= 450 MB; 2048 tokens ~= 225 MB
        kv_cache_mb = int((context_window / 4096.0) * 450)

        # Compute activation scratch buffers (~200 MB) + CUDA runtime context (~300 MB)
        runtime_overhead_mb = 500

        total_vram_mb = weights_mb + kv_cache_mb + runtime_overhead_mb
        fits = total_vram_mb <= available_vram_mb

        if fits:
            strategy = "full_gpu"
            details = (
                f"[Approximate Estimate] Full GPU offload likely. Total footprint ~{total_vram_mb} MB "
                f"({weights_mb}MB weights + ~{kv_cache_mb}MB KV-cache + ~{runtime_overhead_mb}MB runtime buffers) "
                f"fits within {available_vram_mb} MB available safe VRAM budget."
            )
        elif weights_mb < available_vram_mb:
            strategy = "hybrid_cpu_gpu"
            details = (
                f"[Approximate Estimate] Hybrid CPU/GPU offload required. Estimated footprint (~{total_vram_mb} MB) "
                f"exceeds safe VRAM budget ({available_vram_mb} MB). Offload weights partially or place KV-cache in RAM."
            )
        else:
            strategy = "cpu_only"
            details = (
                f"[Approximate Estimate] CPU-only inference required. Model weights alone ({weights_mb} MB) "
                f"exceed safe VRAM budget ({available_vram_mb} MB)."
            )

        return ModelMemoryEstimate(
            model_name=model_name,
            file_size_mb=file_size_mb,
            context_window=context_window,
            estimated_weights_vram_mb=weights_mb,
            estimated_kv_cache_mb=kv_cache_mb,
            runtime_overhead_mb=runtime_overhead_mb,
            total_vram_required_mb=total_vram_mb,
            fits_in_vram=fits,
            recommended_offload_strategy=strategy,
            is_approximate=True,
            details=details,
        )

    @classmethod
    def inspect(cls) -> HardwareProfile:
        """Performs a comprehensive hardware audit and computes allocation limits taking into account currently free VRAM."""
        cpu = cls.get_cpu_info()
        memory = cls.get_memory_info()
        storage = cls.get_storage_info()
        gpus = cls.query_nvidia_smi()
        frameworks = cls.check_framework_compatibility()

        # Update GPUInfo with framework status
        for gpu in gpus:
            gpu.cuda_runtime_available = frameworks.llama_cpp_cuda_supported or frameworks.torch_cuda_supported

        has_nvidia = len(gpus) > 0

        # Calculate safe VRAM budget for RTX 3050 4GB:
        # 1. Static ceiling: total VRAM minus 1200MB reserved for Windows Desktop Window Manager + UI + Screen capture buffer
        # 2. Dynamic safe cap: currently available (free) VRAM minus 400MB runtime buffer
        if has_nvidia and gpus[0].total_vram_mb > 0:
            total_vram = gpus[0].total_vram_mb
            currently_available_vram = gpus[0].free_vram_mb
            static_ceiling = max(0, total_vram - 1200)

            if currently_available_vram > 0:
                dynamic_safe = max(0, currently_available_vram - 400)
                # Cap the dynamic allocation by the static ceiling
                recommended_max_vram = min(static_ceiling, dynamic_safe)
            else:
                dynamic_safe = static_ceiling
                recommended_max_vram = static_ceiling
        else:
            total_vram = 0
            currently_available_vram = 0
            static_ceiling = 0
            dynamic_safe = 0
            recommended_max_vram = 0

        # Calculate safe RAM budget for 16GB system
        # Keep at least 4GB reserved for Windows OS + background tasks
        recommended_max_ram = max(2048, memory.available_ram_mb - 2048)

        recommendations: List[str] = []
        if has_nvidia:
            recommendations.append(
                f"GPU detected: {gpus[0].name} (Total: {total_vram} MB, Currently Free: {currently_available_vram} MB). "
                f"Dynamic safe VRAM cap: {recommended_max_vram} MB (Static ceiling: {static_ceiling} MB)."
            )
            recommendations.append(
                "Approximate estimates: VRAM footprint depends on model architecture, GGUF tensor layout, context length, and active desktop processes."
            )
            if gpus[0].total_vram_mb <= 4096:
                recommendations.append(
                    "Strict 4GB VRAM constraint: Model weights + KV cache + CUDA overhead must not exceed safe VRAM budget. "
                    "Prioritize 3B–4B quantized models (Q4_K_M). Avoid loading conversational LLM and Vision LLM simultaneously."
                )
                recommendations.append(
                    "Use Lazy Loading and auto-unloading for large weights to prevent Out-Of-Memory (OOM) errors."
                )
        else:
            recommendations.append(
                "No discrete NVIDIA GPU detected via nvidia-smi. Relying on optimized CPU inference (llama.cpp with AVX2)."
            )

        if memory.total_ram_mb <= 16384:
            recommendations.append(
                f"System RAM: {memory.total_ram_mb} MB. Limit conversation context window to <= 4096 tokens to prevent memory ballooning."
            )

        for note in frameworks.notes:
            recommendations.append(f"Framework Status: {note}")

        return HardwareProfile(
            os_name=platform.system(),
            os_version=platform.version(),
            cpu=cpu,
            memory=memory,
            storage=storage,
            gpus=gpus,
            has_nvidia_gpu=has_nvidia,
            recommended_max_vram_mb=recommended_max_vram,
            currently_available_vram_mb=currently_available_vram,
            static_vram_ceiling_mb=static_ceiling,
            dynamic_safe_vram_mb=dynamic_safe,
            recommended_max_ram_mb=recommended_max_ram,
            frameworks=frameworks,
            recommendations=recommendations,
        )


def get_hardware_profile() -> HardwareProfile:
    """Convenience getter for current hardware profile."""
    return HardwareInspector.inspect()
