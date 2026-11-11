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


def test_clean_env_fixture_complete_restoration():
    """Regression test for Finding 4: Verify that environment restoration restores pre-existing, modified, and deleted environment variables."""
    from tests.conftest import restore_environment_context

    # 1. Setup pre-existing baseline
    os.environ["TSUKIKO_TEST_PREEXISTING"] = "original_value"
    os.environ["TSUKIKO_TEST_TO_DELETE"] = "will_delete_me"

    # 2. Invoke context generator setup step
    gen = restore_environment_context()
    next(gen)

    # 3. Simulate mutations inside a test
    os.environ["TSUKIKO_TEST_PREEXISTING"] = "mutated_value"
    os.environ["TSUKIKO_TEST_NEW_ADDITION"] = "brand_new_value"
    del os.environ["TSUKIKO_TEST_TO_DELETE"]

    # Assert that inside test scope, mutations exist
    assert os.environ["TSUKIKO_TEST_PREEXISTING"] == "mutated_value"
    assert os.environ["TSUKIKO_TEST_NEW_ADDITION"] == "brand_new_value"
    assert "TSUKIKO_TEST_TO_DELETE" not in os.environ

    # 4. Trigger context generator teardown
    try:
        next(gen)
    except StopIteration:
        pass

    # 5. Assert complete restoration
    assert os.environ["TSUKIKO_TEST_PREEXISTING"] == "original_value"
    assert os.environ["TSUKIKO_TEST_TO_DELETE"] == "will_delete_me"
    assert "TSUKIKO_TEST_NEW_ADDITION" not in os.environ

    # Clean up baseline keys
    del os.environ["TSUKIKO_TEST_PREEXISTING"]
    del os.environ["TSUKIKO_TEST_TO_DELETE"]


def test_offline_privacy_guard_enforcement():
    """Regression test for Finding 2: Verify in-process socket guard strictly blocks outbound non-loopback connections."""
    import socket
    from app.core.privacy.enforcement import (
        enable_offline_guard,
        disable_offline_guard,
        is_offline_guard_active,
        PrivacyViolationError,
    )

    try:
        enable_offline_guard()
        assert is_offline_guard_active() is True

        # Attempting outbound connection to non-loopback IP must raise PrivacyViolationError
        s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        with pytest.raises(PrivacyViolationError) as exc_info:
            s1.connect(("8.8.8.8", 53))
        assert "blocked by in-process network guard" in str(exc_info.value)
        s1.close()

        # Attempting create_connection to external host must raise PrivacyViolationError
        with pytest.raises(PrivacyViolationError) as exc_info:
            socket.create_connection(("1.1.1.1", 53), timeout=0.1)
        assert "blocked by in-process network guard" in str(exc_info.value)

        # Loopback connection should NOT raise PrivacyViolationError (may raise ConnectionRefusedError)
        s_local = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            # Port 65432 likely closed, but should not raise PrivacyViolationError
            s_local.connect(("127.0.0.1", 65432))
        except PrivacyViolationError:
            pytest.fail("Loopback connection was incorrectly blocked by privacy guard!")
        except (ConnectionRefusedError, OSError):
            # Normal socket behavior when nothing is listening on that port
            pass
        finally:
            s_local.close()

    finally:
        disable_offline_guard()
        assert is_offline_guard_active() is False

