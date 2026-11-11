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

from app.core.config.settings import TsukikoConfig, load_config
from app.core.logging.logger import setup_logging


@pytest.fixture
def temp_dir():
    with tempfile.TemporaryDirectory() as tmp:
        yield Path(tmp)
        from app.core.logging.logger import shutdown_logging
        shutdown_logging()


@pytest.fixture
def sample_config(temp_dir):
    config = TsukikoConfig()
    config_file = temp_dir / "test_config.yaml"
    config.save_yaml(config_file)
    return config_file


@pytest.fixture(autouse=True)
def clean_env():
    # Store old env
    old_env = {k: v for k, v in os.environ.items() if k.startswith("TSUKIKO_")}
    yield
    # Restore
    for k in list(os.environ.keys()):
        if k.startswith("TSUKIKO_") and k not in old_env:
            del os.environ[k]
