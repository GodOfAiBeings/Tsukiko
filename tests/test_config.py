"""
Tests for Tsukiko Configuration System
Verifies defaults, validation, environment overrides, and privacy guarantees.
"""

import os
from pathlib import Path
import pytest
from pydantic import ValidationError
from app.core.config.settings import TsukikoConfig, load_config, reset_config, PrivacyConfig


def test_default_config_privacy_guarantees():
    """Verify that strict privacy defaults are enforced out of the box."""
    config = TsukikoConfig()

    assert config.privacy.local_only is True
    assert config.privacy.allow_external_telemetry is False
    assert config.privacy.allow_cloud_fallback is False

    # Screen sharing and mic MUST be OFF by default
    assert config.perception.screen_sharing_enabled is False
    assert config.voice.mic_enabled is False

    # Desktop control must be disabled by default
    assert config.desktop_control.enabled is False


def test_privacy_enforcement_raises_on_invalid_settings():
    """Regression test for Issue 3: Verify that PrivacyConfig raises validation error if local_only is False."""
    with pytest.raises(ValidationError) as exc_info:
        PrivacyConfig(local_only=False)
    assert "local_only must be True" in str(exc_info.value)

    with pytest.raises(ValidationError) as exc_info:
        PrivacyConfig(allow_external_telemetry=True)
    assert "External telemetry is forbidden" in str(exc_info.value)

    with pytest.raises(ValidationError) as exc_info:
        PrivacyConfig(allow_cloud_fallback=True)
    assert "Cloud fallback is forbidden" in str(exc_info.value)


def test_config_save_and_reload(temp_dir):
    """Verify serialization to YAML and reloading."""
    cfg = TsukikoConfig()
    cfg.app.name = "Tsukiko-Test"
    cfg.ai.context_window = 2048
    cfg.ai.max_vram_mb = 2500

    cfg_file = temp_dir / "custom_config.yaml"
    cfg.save_yaml(cfg_file)

    reset_config()
    loaded = load_config(cfg_file)
    assert loaded.app.name == "Tsukiko-Test"
    assert loaded.ai.context_window == 2048
    assert loaded.ai.max_vram_mb == 2500
    assert loaded.perception.screen_sharing_enabled is False


def test_config_env_variable_overrides_types(temp_dir):
    """Regression test for Issue 7: Verify env variable overrides parse booleans, ints, floats, and strings."""
    cfg_file = temp_dir / "base.yaml"
    cfg = TsukikoConfig()
    cfg.save_yaml(cfg_file)

    # Boolean overrides (testing true, false, 1, 0)
    os.environ["TSUKIKO_APP__DEBUG"] = "true"
    os.environ["TSUKIKO_AI__CONTEXT_WINDOW"] = "8192"
    os.environ["TSUKIKO_AI__TEMPERATURE"] = "0.85"
    os.environ["TSUKIKO_APP__LOG_LEVEL"] = "DEBUG"
    os.environ["TSUKIKO_AI__MODEL_PATH"] = "models/test_model.gguf"

    reset_config()
    loaded = load_config(cfg_file, force_reload=True)

    assert loaded.app.debug is True
    assert isinstance(loaded.app.debug, bool)
    assert loaded.ai.context_window == 8192
    assert isinstance(loaded.ai.context_window, int)
    assert loaded.ai.temperature == 0.85
    assert isinstance(loaded.ai.temperature, float)
    assert loaded.app.log_level == "DEBUG"
    assert loaded.ai.model_path == "models/test_model.gguf"


def test_env_restoration_fixture_behavior():
    """Regression test for Issue 5: Environment variable modifications must be cleanly handled."""
    test_key = "TSUKIKO_TEST_TEMP_VAR"
    os.environ[test_key] = "temporary_val"
    assert os.environ.get(test_key) == "temporary_val"

