"""Tsukiko Local AI Brain — Personality Subsystem.

Provides Tsukiko's grounded persona directives and message conditioning.
"""

from __future__ import annotations

from app.core.personality.engine import PersonalityEngine
from app.core.personality.prompts import TSUKIKO_DEFAULT_SYSTEM_PROMPT

__all__ = [
    "PersonalityEngine",
    "TSUKIKO_DEFAULT_SYSTEM_PROMPT",
]
