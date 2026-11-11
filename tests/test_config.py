"""
Tests for Tsukiko Configuration System
Verifies defaults, validation, environment overrides, and privacy guarantees.
"""

import os
from pathlib import Path
import pytest
from app.core.config.settings import TsukikoConfig, load_config


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


def test_config_save_and_reload(temp_dir):
    """Verify serialization to YAML and reloading."""
    cfg = TsukikoConfig()
    cfg.app.name = "Tsukiko-Test"
    cfg.ai.context_window = 2048
    cfg.ai.max_vram_mb = 2500

    cfg_file = temp_dir / "custom_config.yaml"
    cfg.save_yaml(cfg_file)

    loaded = load_config(cfg_file)
    assert loaded.app.name == "Tsukiko-Test"
    assert loaded.ai.context_window == 2048
    assert loaded.ai.max_vram_mb == 2500
    assert loaded.perception.screen_sharing_enabled is False


def test_config_env_variable_overrides(temp_dir):
    """Verify environment variables override yaml values correctly."""
    cfg_file = temp_dir / "base.yaml"
    cfg = TsukikoConfig()
    cfg.save_yaml(cfg_file)

    os.environ["TSUKIKO_APP__LOG_LEVEL"] = "DEBUG"
    os.environ["TSUKIKO_AI__CONTEXT_WINDOW"] = "8192"

    loaded = load_config(cfg_file)
    assert loaded.app.log_level == "DEBUG"
    assert loaded.ai.context_window == 8192
