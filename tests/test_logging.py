"""
Tests for Tsukiko Structured Logging System
Verifies log rotation, component tags, and JSONL formatting.
"""

import json
from pathlib import Path
from app.core.logging.logger import setup_logging, get_logger


def test_structured_logging(temp_dir):
    log_dir = temp_dir / "logs"
    setup_logging(log_dir=log_dir, log_level="DEBUG", enable_jsonl=True)

    sys_logger = get_logger("SYSTEM")
    brain_logger = get_logger("BRAIN")

    sys_logger.info("System initializing")
    brain_logger.debug("Brain debug message")

    text_log = log_dir / "tsukiko.log"
    jsonl_log = log_dir / "tsukiko.jsonl"

    assert text_log.exists()
    assert jsonl_log.exists()

    content = text_log.read_text(encoding="utf-8")
    assert "[SYSTEM]" in content
    assert "System initializing" in content
    assert "[BRAIN]" in content
    assert "Brain debug message" in content

    # Check JSONL parsing
    jsonl_lines = jsonl_log.read_text(encoding="utf-8").strip().splitlines()
    assert len(jsonl_lines) >= 2
    entry0 = json.loads(jsonl_lines[0])
    assert entry0["component"] == "SYSTEM"
    assert entry0["message"] == "System initializing"

    # Close handlers to release file lock on Windows
    from app.core.logging.logger import shutdown_logging
    shutdown_logging()
