"""
Tests for Tsukiko Hardware & Resource Management
Verifies CPU, RAM, VRAM, and storage detection.
"""

from app.core.resource_manager.hardware import HardwareInspector, HardwareProfile


def test_hardware_inspector_execution():
    profile = HardwareInspector.inspect()

    assert isinstance(profile, HardwareProfile)
    assert profile.cpu.physical_cores > 0
    assert profile.cpu.logical_cores >= profile.cpu.physical_cores
    assert profile.memory.total_ram_mb > 0
    assert profile.memory.available_ram_mb > 0
    assert profile.storage.total_gb > 0
    assert profile.storage.free_gb > 0

    # Ensure recommendations are generated
    assert len(profile.recommendations) > 0


def test_safe_budget_calculation():
    profile = HardwareInspector.inspect()

    # VRAM limit should not exceed total VRAM
    if profile.has_nvidia_gpu and profile.gpus:
        total_vram = profile.gpus[0].total_vram_mb
        assert profile.recommended_max_vram_mb < total_vram
        assert profile.recommended_max_vram_mb > 0
