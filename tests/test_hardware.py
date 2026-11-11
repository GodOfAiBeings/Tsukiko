"""
Tests for Tsukiko Hardware & Resource Management
Verifies CPU, RAM, VRAM, storage detection, safe parser fallbacks, and realistic memory models.
Covers exact VRAM classification matrix: measured, zero_available, and unavailable.
"""

from unittest.mock import patch
import pytest

from app.core.resource_manager.hardware import (
    GPUInfo,
    HardwareInspector,
    HardwareProfile,
    ModelMemoryEstimate,
)
from app.core.resource_manager.diagnostic import run_hardware_diagnostic


def test_hardware_inspector_execution():
    profile = HardwareInspector.inspect()

    assert isinstance(profile, HardwareProfile)
    assert profile.cpu.physical_cores > 0
    assert profile.cpu.logical_cores >= profile.cpu.physical_cores
    assert profile.memory.total_ram_mb > 0
    assert profile.memory.available_ram_mb > 0
    assert profile.storage.total_gb > 0
    assert profile.storage.free_gb > 0
    assert profile.budget_status in ("measured", "zero_available", "unavailable")

    assert len(profile.recommendations) > 0
    assert hasattr(profile, "frameworks")


def test_safe_budget_calculation():
    profile = HardwareInspector.inspect()

    if profile.has_nvidia_gpu and profile.gpus and profile.budget_status == "measured":
        total_vram = profile.gpus[0].total_vram_mb
        assert total_vram is not None
        assert profile.recommended_max_vram_mb <= profile.static_vram_ceiling_mb
        assert profile.recommended_max_vram_mb <= total_vram
        assert profile.currently_available_vram_mb is not None
        assert profile.currently_available_vram_mb >= 0
        assert profile.static_vram_ceiling_mb > 0


def test_nvidia_smi_parsing_preserves_optional_metrics():
    """Parser must preserve None for missing fields, [N/A], [Not Supported], and non-numeric metrics."""
    test_csv = (
        "NVIDIA GeForce RTX 3050 Laptop GPU, 616.56, 4096, 350, 3746, [Not Supported], [N/A]\n"
        "NVIDIA Custom Virtual GPU, 550.0, [N/A], [Not Supported], [N/A], 45, 12.5\n"
        "NVIDIA Malformed GPU, 550.0, 4096, 350, malformed_free, 45, 12.5\n"
        "\n"
        "Malformed line without enough parts\n"
    )

    gpus = HardwareInspector.parse_nvidia_smi_output(test_csv)
    assert len(gpus) == 3

    gpu0 = gpus[0]
    assert gpu0.name == "NVIDIA GeForce RTX 3050 Laptop GPU"
    assert gpu0.total_vram_mb == 4096
    assert gpu0.used_vram_mb == 350
    assert gpu0.free_vram_mb == 3746
    assert gpu0.temperature_c is None
    assert gpu0.power_draw_w is None

    gpu1 = gpus[1]
    assert gpu1.name == "NVIDIA Custom Virtual GPU"
    assert gpu1.total_vram_mb is None  # [N/A] preserved as None
    assert gpu1.used_vram_mb is None   # [Not Supported] preserved as None
    assert gpu1.free_vram_mb is None   # [N/A] preserved as None
    assert gpu1.temperature_c == 45
    assert gpu1.power_draw_w == 12.5

    gpu2 = gpus[2]
    assert gpu2.name == "NVIDIA Malformed GPU"
    assert gpu2.total_vram_mb == 4096
    assert gpu2.free_vram_mb is None   # non-numeric preserved as None


# Exact VRAM Classification Matrix Tests
def test_vram_classification_4096_total_3000_free_measured():
    """4096 MB Total | 3000 MB Free -> measured"""
    mock_gpu = [GPUInfo(name="RTX 3050", total_vram_mb=4096, free_vram_mb=3000)]
    with patch.object(HardwareInspector, "query_nvidia_smi", return_value=mock_gpu):
        profile = HardwareInspector.inspect()
        assert profile.budget_status == "measured"
        assert profile.static_vram_ceiling_mb == 2896
        assert profile.dynamic_safe_vram_mb == 2600
        assert profile.recommended_max_vram_mb == 2600


def test_vram_classification_4096_total_400_free_measured():
    """4096 MB Total | 400 MB Free -> measured (0MB safe budget)"""
    mock_gpu = [GPUInfo(name="RTX 3050", total_vram_mb=4096, free_vram_mb=400)]
    with patch.object(HardwareInspector, "query_nvidia_smi", return_value=mock_gpu):
        profile = HardwareInspector.inspect()
        assert profile.budget_status == "measured"
        assert profile.dynamic_safe_vram_mb == 0
        assert profile.recommended_max_vram_mb == 0


def test_vram_classification_4096_total_0_free_zero_available():
    """4096 MB Total | 0 MB Free -> zero_available"""
    mock_gpu = [GPUInfo(name="RTX 3050", total_vram_mb=4096, free_vram_mb=0)]
    with patch.object(HardwareInspector, "query_nvidia_smi", return_value=mock_gpu):
        profile = HardwareInspector.inspect()
        assert profile.budget_status == "zero_available"
        assert profile.recommended_max_vram_mb == 0
        assert profile.dynamic_safe_vram_mb == 0
        assert any("ZERO_AVAILABLE" in r for r in profile.recommendations)


def test_vram_classification_4096_total_na_free_unavailable():
    """4096 MB Total | N/A Free -> unavailable"""
    mock_gpu = [GPUInfo(name="RTX 3050", total_vram_mb=4096, free_vram_mb=None)]
    with patch.object(HardwareInspector, "query_nvidia_smi", return_value=mock_gpu):
        profile = HardwareInspector.inspect()
        assert profile.budget_status == "unavailable"
        assert profile.recommended_max_vram_mb == 0
        assert profile.dynamic_safe_vram_mb == 0
        assert any("UNAVAILABLE" in r for r in profile.recommendations)


def test_vram_classification_4096_total_malformed_free_unavailable():
    """4096 MB Total | malformed Free -> unavailable"""
    parsed = HardwareInspector.parse_nvidia_smi_output(
        "NVIDIA RTX 3050, 550, 4096, 300, malformed_val, 50, 30\n"
    )
    with patch.object(HardwareInspector, "query_nvidia_smi", return_value=parsed):
        profile = HardwareInspector.inspect()
        assert profile.budget_status == "unavailable"
        assert profile.recommended_max_vram_mb == 0


def test_vram_classification_unknown_total_unknown_free_unavailable():
    """Unknown Total | Unknown Free -> unavailable"""
    mock_gpu = [GPUInfo(name="RTX 3050", total_vram_mb=None, free_vram_mb=None)]
    with patch.object(HardwareInspector, "query_nvidia_smi", return_value=mock_gpu):
        profile = HardwareInspector.inspect()
        assert profile.budget_status == "unavailable"
        assert profile.recommended_max_vram_mb == 0


def test_vram_classification_no_nvidia_gpu_unavailable():
    """No NVIDIA GPU -> unavailable"""
    with patch.object(HardwareInspector, "query_nvidia_smi", return_value=[]):
        profile = HardwareInspector.inspect()
        assert profile.budget_status == "unavailable"
        assert profile.has_nvidia_gpu is False
        assert profile.recommended_max_vram_mb == 0


def test_diagnostic_never_substitutes_positive_budget_on_zero_or_unavailable(capsys):
    """Verify hardware diagnostic never substitutes a positive default when budget is 0 or unavailable."""
    # Test zero_available
    mock_gpu = [GPUInfo(name="RTX 3050", total_vram_mb=4096, free_vram_mb=0)]
    with patch.object(HardwareInspector, "query_nvidia_smi", return_value=mock_gpu):
        code = run_hardware_diagnostic()
        assert code == 0
        captured = capsys.readouterr().out
        assert "Budget Status:                 ZERO_AVAILABLE" in captured
        assert "Dynamic Safe VRAM Cap:         0 MB" in captured
        assert "Safe GPU VRAM budget is 0 MB (status: zero_available)" in captured
        # Verify sample estimation used 0 MB
        assert "CPU-only inference required: Available safe VRAM budget is 0 MB" in captured

    # Test unavailable
    with patch.object(HardwareInspector, "query_nvidia_smi", return_value=[]):
        code = run_hardware_diagnostic()
        assert code == 0
        captured = capsys.readouterr().out
        assert "Budget Status:                 UNAVAILABLE" in captured
        assert "Dynamic Safe VRAM Cap:         0 MB" in captured
        assert "Safe GPU VRAM budget is 0 MB (status: unavailable)" in captured


def test_model_vram_estimation_with_zero_budget():
    est = HardwareInspector.estimate_model_vram_footprint(
        file_size_mb=2000,
        context_window=4096,
        model_name="Test-3B",
        available_vram_mb=0,
    )
    assert est.fits_in_vram is False
    assert est.recommended_offload_strategy == "cpu_only"
    assert "CPU-only inference required" in est.details
    assert est.is_approximate is True


def test_framework_compatibility_distinguishes_llama_cpp_and_torch():
    frameworks = HardwareInspector.check_framework_compatibility()
    assert hasattr(frameworks, "llama_cpp_installed")
    assert hasattr(frameworks, "llama_cpp_cuda_supported")
    assert hasattr(frameworks, "torch_installed")
    assert hasattr(frameworks, "torch_cuda_supported")
    assert hasattr(frameworks, "onnxruntime_installed")
    assert len(frameworks.notes) >= 3


def test_model_vram_estimation_accounts_for_kv_cache_and_overhead():
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
    assert est.total_vram_required_mb == 2950
    assert est.fits_in_vram is False
    assert est.recommended_offload_strategy == "hybrid_cpu_gpu"

    est_small = HardwareInspector.estimate_model_vram_footprint(
        file_size_mb=1500,
        context_window=2048,
        model_name="Small-Q4",
        available_vram_mb=2800,
    )
    assert est_small.total_vram_required_mb == 2225
    assert est_small.fits_in_vram is True
    assert est_small.recommended_offload_strategy == "full_gpu"
    assert est.is_approximate is True
    assert "Approximate estimate" in est.disclaimer
    assert "[Approximate Estimate]" in est.details
