"""
Tests for Tsukiko Structured Logging System
Verifies log rotation, component tags, JSONL formatting, clean reconfiguration, and handler shutdown.
"""

import json
from pathlib import Path
from app.core.logging.logger import (
    setup_logging,
    get_logger,
    shutdown_logging,
    get_current_log_dir,
)


def test_structured_logging(temp_dir):
    log_dir = temp_dir / "logs"
    setup_logging(log_dir=log_dir, log_level="DEBUG", enable_jsonl=True, force=True)

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

    shutdown_logging()


def test_logging_reconfiguration_different_destinations(temp_dir):
    """Regression test for Issue 6: Reconfiguring setup_logging must direct subsequent logs to the new directory."""
    dir_a = temp_dir / "logs_a"
    dir_b = temp_dir / "logs_b"

    # 1. Setup in dir_a
    setup_logging(log_dir=dir_a, log_level="INFO", force=True)
    assert get_current_log_dir() == dir_a.resolve()
    logger_a = get_logger("SYSTEM")
    logger_a.info("Message for destination A")

    assert (dir_a / "tsukiko.log").exists()
    content_a = (dir_a / "tsukiko.log").read_text(encoding="utf-8")
    assert "Message for destination A" in content_a

    # 2. Reconfigure to dir_b (without needing manual shutdown)
    setup_logging(log_dir=dir_b, log_level="INFO")
    assert get_current_log_dir() == dir_b.resolve()
    logger_b = get_logger("SYSTEM")
    logger_b.info("Message for destination B")

    assert (dir_b / "tsukiko.log").exists()
    content_b = (dir_b / "tsukiko.log").read_text(encoding="utf-8")
    assert "Message for destination B" in content_b

    # Verify dir_a did NOT receive the message meant for dir_b
    content_a_after = (dir_a / "tsukiko.log").read_text(encoding="utf-8")
    assert "Message for destination B" not in content_a_after

    shutdown_logging()
