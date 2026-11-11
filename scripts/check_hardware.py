"""
Tsukiko Hardware Verification & Compatibility Diagnostic Script
Runs independent environment verification without starting the GUI.
"""

import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app.core.logging.logger import setup_logging, get_logger
from app.core.resource_manager.hardware import HardwareInspector

setup_logging(log_level="INFO")
logger = get_logger("SYSTEM")


def main() -> int:
    print("=" * 65)
    print("           TSUKIKO HARDWARE & ENVIRONMENT AUDIT            ")
    print("=" * 65)

    profile = HardwareInspector.inspect()

    print(f"\n[Operating System]: {profile.os_name} {profile.os_version}")
    print(f"[CPU]:              {profile.cpu.brand}")
    print(f"                    Physical Cores: {profile.cpu.physical_cores}, Threads: {profile.cpu.logical_cores}")
    print(f"                    Current Utilization: {profile.cpu.utilization_percent}%")

    print(f"\n[System Memory]:    Total: {profile.memory.total_ram_mb} MB (~{profile.memory.total_ram_mb//1024} GB)")
    print(f"                    Available: {profile.memory.available_ram_mb} MB")
    print(f"                    Used: {profile.memory.used_ram_mb} MB ({profile.memory.percent_used}%)")

    print(f"\n[Storage Drive]:    Path: {profile.storage.drive_path}")
    print(f"                    Free: {profile.storage.free_gb} GB / {profile.storage.total_gb} GB")

    print("\n[Graphics & VRAM]:")
    if profile.gpus:
        for idx, gpu in enumerate(profile.gpus):
            print(f"  GPU #{idx}:         {gpu.name}")
            print(f"  Driver Version:   {gpu.driver_version}")
            print(f"  Total VRAM:       {gpu.total_vram_mb} MB")
            print(f"  Used VRAM:        {gpu.used_vram_mb} MB")
            print(f"  Free VRAM:        {gpu.free_vram_mb} MB")
            if gpu.temperature_c is not None:
                print(f"  Temperature:      {gpu.temperature_c}°C")
            if gpu.power_draw_w is not None:
                print(f"  Power Usage:      {gpu.power_draw_w} W")
    else:
        print("  No NVIDIA GPU detected or nvidia-smi unavailable.")

    print("\n[Local ML Runtime Support]:")
    print(f"  llama-cpp-python: installed={profile.frameworks.llama_cpp_installed}, cuda_offload={profile.frameworks.llama_cpp_cuda_supported}")
    print(f"  torch:            installed={profile.frameworks.torch_installed}, cuda_available={profile.frameworks.torch_cuda_supported}")
    print(f"  onnxruntime:      installed={profile.frameworks.onnxruntime_installed}, cuda_provider={profile.frameworks.onnxruntime_cuda_supported}")

    print("\n[Realistic Model VRAM Budget Breakdown (Sample 3B Q4_K_M)]:")
    sample_est = HardwareInspector.estimate_model_vram_footprint(
        file_size_mb=2000,
        context_window=4096,
        model_name="Llama-3.2-3B-Instruct-Q4_K_M",
        available_vram_mb=profile.recommended_max_vram_mb or 2800,
    )
    print(f"  Model GGUF File Size:     {sample_est.file_size_mb} MB")
    print(f"  Context Window:           {sample_est.context_window} tokens")
    print(f"  Estimated KV Cache:       +{sample_est.estimated_kv_cache_mb} MB")
    print(f"  CUDA Runtime & Buffers:   +{sample_est.runtime_overhead_mb} MB")
    print(f"  Total VRAM Required:      {sample_est.total_vram_required_mb} MB")
    print(f"  Fits Safe VRAM Budget:    {sample_est.fits_in_vram} ({sample_est.recommended_offload_strategy})")
    print(f"  Assessment:               {sample_est.details}")

    print("\n[Resource Allocator Recommendations]:")
    print(f"  Max Recommended VRAM for LLM:  {profile.recommended_max_vram_mb} MB")
    print(f"  Max Recommended RAM for LLM:   {profile.recommended_max_ram_mb} MB")
    for r in profile.recommendations:
        print(f"  - {r}")

    print("=" * 65)
    return 0


if __name__ == "__main__":
    sys.exit(main())
