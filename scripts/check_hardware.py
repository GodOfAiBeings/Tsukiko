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
    print("=" * 60)
    print("           TSUKIKO HARDWARE & ENVIRONMENT AUDIT            ")
    print("=" * 60)

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

    print("\n[Resource Allocator Recommendations]:")
    print(f"  Max Recommended VRAM for LLM:  {profile.recommended_max_vram_mb} MB")
    print(f"  Max Recommended RAM for LLM:   {profile.recommended_max_ram_mb} MB")
    for r in profile.recommendations:
        print(f"  - {r}")

    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
