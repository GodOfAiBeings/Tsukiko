"""
Pytest configuration and shared fixtures for Tsukiko test suite.
"""

import os
import sys
import tempfile
from pathlib import Path
import pytest

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.core.config.settings import TsukikoConfig, load_config, reset_config
from app.core.logging.logger import setup_logging, shutdown_logging


@pytest.fixture
def temp_dir():
    with tempfile.TemporaryDirectory() as tmp:
        yield Path(tmp)
        shutdown_logging()


@pytest.fixture
def sample_config(temp_dir):
    config = TsukikoConfig()
    config_file = temp_dir / "test_config.yaml"
    config.save_yaml(config_file)
    return config_file


def restore_environment_context():
    """Context generator that cleanly snapshots and restores all environment variables and singletons."""
    old_env = dict(os.environ)
    reset_config()
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(old_env)
        reset_config()
        shutdown_logging()
        from app.core.privacy.enforcement import disable_offline_guard
        disable_offline_guard()


@pytest.fixture(autouse=True)
def clean_env():
    """Deterministic environment fixture that cleanly resets all env vars and config singletons."""
    yield from restore_environment_context()
