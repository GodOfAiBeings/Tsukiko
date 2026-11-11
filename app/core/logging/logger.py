"""
Tsukiko Structured Logging System
Supports colored console output, rotating text logs, and JSONL event streaming.
"""

from __future__ import annotations

import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import sys
import threading
from typing import Any, Dict, Optional

try:
    import colorama
    from colorama import Fore, Style
    colorama.init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False
    class Fore:
        CYAN = ""
        BLUE = ""
        GREEN = ""
        YELLOW = ""
        RED = ""
        MAGENTA = ""
        WHITE = ""
        RESET = ""
    class Style:
        BRIGHT = ""
        RESET_ALL = ""


# Component color mapping for pleasant terminal readability
COMPONENT_COLORS = {
    "SYSTEM": Fore.CYAN,
    "BRAIN": Fore.BLUE + Style.BRIGHT,
    "MEMORY": Fore.MAGENTA,
    "PERCEPTION": Fore.GREEN,
    "VOICE": Fore.YELLOW,
    "UI": Fore.CYAN + Style.BRIGHT,
    "RESOURCE": Fore.WHITE + Style.BRIGHT,
    "CONTROL": Fore.RED + Style.BRIGHT,
}

LEVEL_COLORS = {
    logging.DEBUG: Fore.WHITE,
    logging.INFO: Fore.GREEN,
    logging.WARNING: Fore.YELLOW + Style.BRIGHT,
    logging.ERROR: Fore.RED + Style.BRIGHT,
    logging.CRITICAL: Fore.RED + Style.BRIGHT,
}


class ConsoleFormatter(logging.Formatter):
    """Clean colorized console formatter with component badges."""

    def format(self, record: logging.LogRecord) -> str:
        component = getattr(record, "component", "SYSTEM")
        comp_color = COMPONENT_COLORS.get(component, Fore.WHITE)
        lvl_color = LEVEL_COLORS.get(record.levelno, Fore.WHITE)

        time_str = self.formatTime(record, "%H:%M:%S")
        lvl_name = f"{record.levelname[:4]:<4}"

        if COLORAMA_AVAILABLE:
            header = f"{Fore.WHITE}{time_str}{Style.RESET_ALL} {lvl_color}{lvl_name}{Style.RESET_ALL} {comp_color}[{component:>10}]{Style.RESET_ALL} "
        else:
            header = f"{time_str} {lvl_name} [{component:>10}] "

        msg = record.getMessage()
        if record.exc_info:
            if not record.exc_text:
                record.exc_text = self.formatException(record.exc_info)
            msg += f"\n{record.exc_text}"

        return f"{header}{msg}"


class JSONLFormatter(logging.Formatter):
    """Outputs machine-readable JSONL records for analysis and debugging."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry: Dict[str, Any] = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "component": getattr(record, "component", "SYSTEM"),
            "message": record.getMessage(),
            "module": record.module,
            "line": record.lineno,
            "thread": record.threadName,
        }
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry, ensure_ascii=False)


class TsukikoLogger(logging.LoggerAdapter):
    """Adapter that injects component context into all log statements."""

    def __init__(self, logger: logging.Logger, component: str):
        super().__init__(logger, {"component": component})
        self.component = component

    def process(self, msg: Any, kwargs: Any) -> tuple[Any, Any]:
        extra = kwargs.setdefault("extra", {})
        extra["component"] = self.component
        return msg, kwargs


_INIT_LOCK = threading.Lock()
_INITIALIZED = False


def setup_logging(
    log_dir: str | Path = "logs",
    log_level: str = "INFO",
    max_file_size_bytes: int = 5 * 1024 * 1024,
    backup_count: int = 5,
    enable_jsonl: bool = True,
) -> None:
    """Configures global root logging with rotating text and jsonl files."""
    global _INITIALIZED
    with _INIT_LOCK:
        if _INITIALIZED:
            return

        log_path = Path(log_dir)
        log_path.mkdir(parents=True, exist_ok=True)

        numeric_level = getattr(logging, log_level.upper(), logging.INFO)
        root = logging.getLogger()
        root.setLevel(numeric_level)

        # Clear any existing root handlers to avoid double output
        for h in list(root.handlers):
            root.removeHandler(h)

        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(numeric_level)
        console_handler.setFormatter(ConsoleFormatter())
        root.addHandler(console_handler)

        # Standard rotating text log file
        text_file = log_path / "tsukiko.log"
        file_handler = RotatingFileHandler(
            text_file,
            maxBytes=max_file_size_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        file_handler.setLevel(numeric_level)
        file_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s [%(levelname)s] [%(component)s] %(name)s: %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        root.addHandler(file_handler)

        # JSONL stream log file for telemetry / offline analysis
        if enable_jsonl:
            jsonl_file = log_path / "tsukiko.jsonl"
            jsonl_handler = RotatingFileHandler(
                jsonl_file,
                maxBytes=max_file_size_bytes,
                backupCount=backup_count,
                encoding="utf-8",
            )
            jsonl_handler.setLevel(numeric_level)
            jsonl_handler.setFormatter(JSONLFormatter())
            root.addHandler(jsonl_handler)

        _INITIALIZED = True


def shutdown_logging() -> None:
    """Closes and removes all handlers to release file locks (critical for Windows)."""
    global _INITIALIZED
    with _INIT_LOCK:
        root = logging.getLogger()
        for h in list(root.handlers):
            try:
                h.flush()
                h.close()
            except Exception:
                pass
            root.removeHandler(h)
        _INITIALIZED = False


def get_logger(component: str = "SYSTEM") -> TsukikoLogger:
    """Obtain a component-tagged logger adapter."""
    base_logger = logging.getLogger("tsukiko")
    return TsukikoLogger(base_logger, component)
