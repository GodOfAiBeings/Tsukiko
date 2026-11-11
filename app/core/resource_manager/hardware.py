"""
Tsukiko Hardware Inspection and Resource Management
Inspects CPU, RAM, GPU (VRAM), storage, and framework compatibility.
Computes safe memory budgets and offloading recommendations for low-VRAM machines.
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


class HardwareProfile(BaseModel):
    os_name: str
    os_version: str
    cpu: CPUInfo
    memory: SystemMemoryInfo
    storage: StorageInfo
    gpus: List[GPUInfo] = Field(default_factory=list)
    has_nvidia_gpu: bool = False
    recommended_max_vram_mb: int = 0
    recommended_max_ram_mb: int = 0
    recommendations: List[str] = Field(default_factory=list)


class HardwareInspector:
    """Inspects the local Windows environment, hardware limits, and framework state."""

    @classmethod
    def get_cpu_info(cls) -> CPUInfo:
        cpu_brand = platform.processor() or "AMD/Intel x86_64"
        # Try win32 query for clean processor name if on Windows
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
    def query_nvidia_smi(cls) -> List[GPUInfo]:
        """Queries nvidia-smi for precise VRAM and GPU statistics."""
        nvidia_smi_path = shutil.which("nvidia-smi")
        if not nvidia_smi_path:
            return []

        try:
            # Query standard csv fields from nvidia-smi
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
            gpus: List[GPUInfo] = []
            for line in result.stdout.strip().splitlines():
                parts = [p.strip() for p in line.split(",")]
                if len(parts) >= 5:
                    gpu_name = parts[0]
                    driver_ver = parts[1]
                    total_mb = int(float(parts[2]))
                    used_mb = int(float(parts[3]))
                    free_mb = int(float(parts[4]))
                    temp_c = int(float(parts[5])) if len(parts) > 5 and parts[5] != "[N/A]" else None
                    power_w = float(parts[6]) if len(parts) > 6 and parts[6] != "[N/A]" else None

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
        except Exception as e:
            logger.warning(f"Failed to query nvidia-smi: {e}")
            return []

    @classmethod
    def check_cuda_runtime(cls) -> bool:
        """Tests whether PyTorch or an installed ML library actually has active CUDA support."""
        try:
            import torch  # type: ignore
            return bool(torch.cuda.is_available())
        except ImportError:
            return False

    @classmethod
    def inspect(cls) -> HardwareProfile:
        """Performs a comprehensive hardware audit and computes allocation limits."""
        cpu = cls.get_cpu_info()
        memory = cls.get_memory_info()
        storage = cls.get_storage_info()
        gpus = cls.query_nvidia_smi()

        cuda_avail = cls.check_cuda_runtime()
        for gpu in gpus:
            gpu.cuda_runtime_available = cuda_avail

        has_nvidia = len(gpus) > 0

        # Calculate safe VRAM budget for RTX 3050 4GB
        # Keep at least 1000MB for Windows Desktop Window Manager + UI + Screen capture buffer
        if has_nvidia and gpus[0].total_vram_mb > 0:
            total_vram = gpus[0].total_vram_mb
            recommended_max_vram = max(0, total_vram - 1200)
        else:
            recommended_max_vram = 0

        # Calculate safe RAM budget for 16GB system
        # Keep at least 4GB for Windows OS + background tasks
        recommended_max_ram = max(2048, memory.available_ram_mb - 2048)

        recommendations: List[str] = []
        if has_nvidia:
            recommendations.append(
                f"GPU detected: {gpus[0].name} with {gpus[0].total_vram_mb} MB VRAM. Recommended LLM VRAM cap: {recommended_max_vram} MB."
            )
            if gpus[0].total_vram_mb <= 4096:
                recommendations.append(
                    "Strict 4GB VRAM constraint: Prioritize 3B–4B quantized models (Q4_K_M). Avoid loading conversational LLM and Vision LLM simultaneously."
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

        return HardwareProfile(
            os_name=platform.system(),
            os_version=platform.version(),
            cpu=cpu,
            memory=memory,
            storage=storage,
            gpus=gpus,
            has_nvidia_gpu=has_nvidia,
            recommended_max_vram_mb=recommended_max_vram,
            recommended_max_ram_mb=recommended_max_ram,
            recommendations=recommendations,
        )


def get_hardware_profile() -> HardwareProfile:
    """Convenience getter for current hardware profile."""
    return HardwareInspector.inspect()
