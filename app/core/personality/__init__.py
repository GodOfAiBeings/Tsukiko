"""Tsukiko Local AI Brain — Personality Subsystem.

Provides Tsukiko's permanent character identity, gradual self-disclosure,
conversational initiative, and message conditioning.
"""

from __future__ import annotations

from app.core.personality.biography import CharacterBiography, TSUKIKO_BIOGRAPHY
from app.core.personality.disclosure import DisclosureStage, DisclosureTracker
from app.core.personality.engine import PersonalityEngine
from app.core.personality.initiative import ConversationalInitiativeEngine, SILENCE_TOKEN
from app.core.personality.prompts import TSUKIKO_DEFAULT_SYSTEM_PROMPT, build_system_prompt

__all__ = [
    "CharacterBiography",
    "ConversationalInitiativeEngine",
    "DisclosureStage",
    "DisclosureTracker",
    "PersonalityEngine",
    "SILENCE_TOKEN",
    "TSUKIKO_BIOGRAPHY",
    "TSUKIKO_DEFAULT_SYSTEM_PROMPT",
    "build_system_prompt",
]
