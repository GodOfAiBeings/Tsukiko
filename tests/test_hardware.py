"""
Tests for Tsukiko Hardware & Resource Management
Verifies CPU, RAM, VRAM, storage detection, safe parser fallbacks, and realistic memory models.
"""

from app.core.resource_manager.hardware import (
    HardwareInspector,
    HardwareProfile,
    ModelMemoryEstimate,
)


def test_hardware_inspector_execution():
    profile = HardwareInspector.inspect()

    assert isinstance(profile, HardwareProfile)
    assert profile.cpu.physical_cores > 0
    assert profile.cpu.logical_cores >= profile.cpu.physical_cores
    assert profile.memory.total_ram_mb > 0
    assert profile.memory.available_ram_mb > 0
    assert profile.storage.total_gb > 0
    assert profile.storage.free_gb > 0

    # Ensure recommendations and framework information are generated
    assert len(profile.recommendations) > 0
    assert hasattr(profile, "frameworks")


def test_safe_budget_calculation():
    profile = HardwareInspector.inspect()

    if profile.has_nvidia_gpu and profile.gpus:
        total_vram = profile.gpus[0].total_vram_mb
        assert profile.recommended_max_vram_mb <= profile.static_vram_ceiling_mb
        assert profile.recommended_max_vram_mb <= total_vram
        assert profile.currently_available_vram_mb >= 0
        assert profile.static_vram_ceiling_mb > 0


def test_nvidia_smi_parsing_handles_missing_and_unexpected_metrics():
    """Regression test for Issue 8: Parser must safely handle missing fields, [N/A], [Not Supported], and non-numeric metrics."""
    # Sample line with [Not Supported] for power and temperature, and string non-numeric metrics
    test_csv = (
        "NVIDIA GeForce RTX 3050 Laptop GPU, 616.56, 4096, 350, 3746, [Not Supported], [N/A]\n"
        "NVIDIA Custom Virtual GPU, 550.0, [N/A], [Not Supported], 2048, 45, 12.5\n"
        "\n"
        "Malformed line without enough parts\n"
    )

    gpus = HardwareInspector.parse_nvidia_smi_output(test_csv)
    assert len(gpus) == 2

    gpu0 = gpus[0]
    assert gpu0.name == "NVIDIA GeForce RTX 3050 Laptop GPU"
    assert gpu0.total_vram_mb == 4096
    assert gpu0.used_vram_mb == 350
    assert gpu0.free_vram_mb == 3746
    assert gpu0.temperature_c is None
    assert gpu0.power_draw_w is None

    gpu1 = gpus[1]
    assert gpu1.name == "NVIDIA Custom Virtual GPU"
    assert gpu1.total_vram_mb == 0  # [N/A] safely defaulted to 0
    assert gpu1.used_vram_mb == 0   # [Not Supported] safely defaulted to 0
    assert gpu1.free_vram_mb == 2048
    assert gpu1.temperature_c == 45
    assert gpu1.power_draw_w == 12.5


def test_framework_compatibility_distinguishes_llama_cpp_and_torch():
    """Regression test for Issue 4: HardwareInspector must inspect llama.cpp and PyTorch as distinct runtimes."""
    frameworks = HardwareInspector.check_framework_compatibility()
    assert hasattr(frameworks, "llama_cpp_installed")
    assert hasattr(frameworks, "llama_cpp_cuda_supported")
    assert hasattr(frameworks, "torch_installed")
    assert hasattr(frameworks, "torch_cuda_supported")
    assert hasattr(frameworks, "onnxruntime_installed")
    assert len(frameworks.notes) >= 3


def test_model_vram_estimation_accounts_for_kv_cache_and_overhead():
    """Regression test for Issue 9: VRAM estimation must include KV cache, activations, and CUDA runtime."""
    # 2000 MB model with 4096 context
    est = HardwareInspector.estimate_model_vram_footprint(
        file_size_mb=2000,
        context_window=4096,
        model_name="Test-3B-Q4",
        available_vram_mb=2800,
    )
    assert isinstance(est, ModelMemoryEstimate)
    assert est.file_size_mb == 2000
    assert est.estimated_kv_cache_mb == 450
    assert est.runtime_overhead_mb == 500
    # Total VRAM is 2000 + 450 + 500 = 2950 MB
    assert est.total_vram_required_mb == 2950
    # 2950 MB exceeds 2800 MB safe limit
    assert est.fits_in_vram is False
    assert est.recommended_offload_strategy == "hybrid_cpu_gpu"

    # Smaller model (e.g. 1500 MB with 2048 context)
    est_small = HardwareInspector.estimate_model_vram_footprint(
        file_size_mb=1500,
        context_window=2048,
        model_name="Small-Q4",
        available_vram_mb=2800,
    )
    # KV cache for 2048 context ~= 225 MB
    # Total VRAM = 1500 + 225 + 500 = 2225 MB <= 2800 MB
    assert est_small.total_vram_required_mb == 2225
    assert est_small.fits_in_vram is True
    assert est_small.recommended_offload_strategy == "full_gpu"

    # Regression test for Finding 1: Estimates must be clearly marked as approximate
    assert est.is_approximate is True
    assert "Approximate estimate" in est.disclaimer
    assert "[Approximate Estimate]" in est.details


def test_run_hardware_diagnostic_packaged():
    """Regression test for Finding 3: Packaged diagnostic runs cleanly and returns exit code 0."""
    from app.core.resource_manager.diagnostic import run_hardware_diagnostic
    exit_code = run_hardware_diagnostic()
    assert exit_code == 0
