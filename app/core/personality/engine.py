"""Tsukiko Local AI Brain — Personality Engine.

Constructs context-aware conversation payloads, applies system prompt policies,
and cleanses internal model artifacts (such as reasoning/thinking tokens).
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional

from app.core.personality.prompts import TSUKIKO_DEFAULT_SYSTEM_PROMPT

THINK_REGEX = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)


class PersonalityEngine:
    """Controls Tsukiko's personality, conversation context packaging, and response filtering."""

    def __init__(self, custom_system_prompt: Optional[str] = None) -> None:
        self._custom_prompt = custom_system_prompt

    def get_system_prompt(self) -> str:
        """Returns the active system prompt."""
        if self._custom_prompt and self._custom_prompt.strip():
            return self._custom_prompt.strip()
        return TSUKIKO_DEFAULT_SYSTEM_PROMPT.strip()

    def set_custom_prompt(self, prompt: Optional[str]) -> None:
        """Updates the custom system prompt."""
        self._custom_prompt = prompt

    def format_messages(
        self,
        history: List[Dict[str, str]],
        new_user_message: str,
    ) -> List[Dict[str, str]]:
        """Formats the full message list for local model inference.
        
        Ensures the system prompt is positioned at the head, existing conversation
        history is preserved, and the new user message is appended cleanly.
        """
        messages: List[Dict[str, str]] = []

        # Head system prompt
        messages.append({"role": "system", "content": self.get_system_prompt()})

        # Append existing turns (skipping redundant system messages)
        for msg in history:
            role = msg.get("role", "user")
            if role == "system":
                continue
            messages.append({"role": role, "content": msg.get("content", "")})

        # Append new user prompt
        messages.append({"role": "user", "content": new_user_message.strip()})

        return messages

    @classmethod
    def clean_response(cls, text: str) -> str:
        """Strips internal thinking tokens and trims response."""
        cleaned = THINK_REGEX.sub("", text).strip()
        return cleaned
