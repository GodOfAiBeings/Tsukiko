"""Tsukiko Conversational Initiative Engine (Phase 3).

Implements bounded, respectful conversational autonomy. Tsukiko can initiate
conversations without waiting for user input, bringing up grounded observations,
seasonal changes, or reflections on recent session discussions.

Strict Boundary Invariants:
1. Anti-Spam & Non-Repetition: Never spams repetitive greetings or duplicate remarks.
2. Silence by Choice: The model can choose to respond with [SILENCE] when quiet is best.
3. Strict Backoff: If a previous proactive message went unanswered, Tsukiko remains silent.
4. Cooldown Enforcement: Minimum 120 seconds between proactive initiatives.
5. Idle Requirement: Minimum 45 seconds of user inactivity before considering an initiative.
6. Game Mode & Hidden State Suppression: Strictly 0 initiatives during gaming or hidden mode.
7. Available Signals Only: Uses only in-memory session history, time of day, and idle duration.
   Zero claims of seeing outside apps, screen contents, or OS activities.
"""

from __future__ import annotations

from datetime import datetime
import logging
import time
from typing import Any, Dict, List, Optional

from app.core.personality.biography import CharacterBiography, TSUKIKO_BIOGRAPHY
from app.core.personality.disclosure import DisclosureStage

logger = logging.getLogger(__name__)

SILENCE_TOKEN = "[SILENCE]"


class ConversationalInitiativeEngine:
    """Manages proactive conversational outreach within strict boundaries."""

    def __init__(
        self,
        cooldown_seconds: float = 120.0,
        min_idle_seconds: float = 45.0,
        max_consecutive_unanswered: int = 1,
    ) -> None:
        self.cooldown_seconds = cooldown_seconds
        self.min_idle_seconds = min_idle_seconds
        self.max_consecutive_unanswered = max_consecutive_unanswered

        self._last_interaction_time = time.time()
        self._last_initiative_time = 0.0
        self._consecutive_unanswered = 0
        self._enabled = True
        self._recent_initiatives: List[str] = []

    @property
    def is_enabled(self) -> bool:
        return self._enabled

    @is_enabled.setter
    def is_enabled(self, val: bool) -> None:
        self._enabled = val

    @property
    def consecutive_unanswered(self) -> int:
        return self._consecutive_unanswered

    @property
    def recent_initiatives(self) -> List[str]:
        return list(self._recent_initiatives)

    def record_user_activity(self) -> None:
        """Called whenever the user types or interacts, resetting idle timer and unanswered counter."""
        self._last_interaction_time = time.time()
        self._consecutive_unanswered = 0

    def record_assistant_response(self) -> None:
        """Called when an assistant response finishes in normal dialogue."""
        self._last_interaction_time = time.time()

    def record_initiative_sent(self, text: str = "") -> None:
        """Called when a proactive message is successfully delivered."""
        now = time.time()
        self._last_initiative_time = now
        self._last_interaction_time = now
        self._consecutive_unanswered += 1
        if text.strip():
            self._recent_initiatives.append(text.strip())
            if len(self._recent_initiatives) > 10:
                self._recent_initiatives.pop(0)

    def is_repetitive(self, candidate: str) -> bool:
        """Checks if the candidate remark repeats or closely mirrors recent proactive messages."""
        cand_norm = candidate.lower().strip()
        if not cand_norm:
            return True

        cand_tokens = set(cand_norm.split())
        for recent in self._recent_initiatives:
            recent_norm = recent.lower().strip()
            if cand_norm == recent_norm:
                return True
            recent_tokens = set(recent_norm.split())
            if cand_tokens and recent_tokens:
                intersection = cand_tokens.intersection(recent_tokens)
                union = cand_tokens.union(recent_tokens)
                jaccard = len(intersection) / len(union)
                if jaccard > 0.75:
                    return True
        return False

    def can_initiate(
        self,
        current_time: Optional[float] = None,
        game_mode_active: bool = False,
        widget_hidden: bool = False,
        window_minimized: bool = False,
    ) -> tuple[bool, str]:
        """Evaluates whether Tsukiko is permitted to initiate a message right now."""
        if not self._enabled:
            return False, "Conversational initiative is disabled."

        if game_mode_active:
            return False, "Game Mode active (visual & proactive silence strictly enforced)."

        if widget_hidden or window_minimized:
            return False, "Widget is hidden or window is minimized."

        now = current_time if current_time is not None else time.time()

        # Check cooldown from last proactive message
        time_since_initiative = now - self._last_initiative_time
        if time_since_initiative < self.cooldown_seconds:
            return False, f"Cooldown active ({int(self.cooldown_seconds - time_since_initiative)}s remaining)."

        # Check consecutive unanswered limit (must remain quiet after unanswered initiative)
        if self._consecutive_unanswered >= self.max_consecutive_unanswered:
            return False, "User did not reply to previous initiative; remaining quiet."

        # Check idle duration from last interaction (minimum 45s of user inactivity)
        idle_duration = now - self._last_interaction_time
        if idle_duration < self.min_idle_seconds:
            return False, f"User was recently active ({int(idle_duration)}s < {int(self.min_idle_seconds)}s)."

        return True, "Initiative permitted."

    def build_initiative_prompt(
        self,
        session_history: List[Dict[str, str]],
        current_dt: Optional[datetime] = None,
        stage: DisclosureStage = DisclosureStage.ACQUAINTANCE,
        biography: Optional[CharacterBiography] = None,
        personality_directive: Optional[str] = None,
    ) -> List[Dict[str, str]]:
        """Constructs a stage-isolated, character-grounded proactive initiative prompt.

        Safety & Personality Invariants:
        1. Includes Tsukiko's active stage-specific personality directive.
        2. Strictly respects the current disclosure stage (never exposes restricted history).
        3. Preserves Tsukiko's authentic traits: independent, gentle, cheerful, stubborn,
           occasionally proud and jealous, observant, pragmatic, and nature/seasonal-minded.
        4. Provides the [SILENCE] option when quiet is preferable or there is nothing genuine to say.
        5. Prohibits repetitive greetings, polite corporate filler, and attention-seeking.
        """
        dt = current_dt or datetime.now()
        hour = dt.hour

        if 5 <= hour < 12:
            time_desc = "morning"
        elif 12 <= hour < 17:
            time_desc = "afternoon"
        elif 17 <= hour < 21:
            time_desc = "dusk / evening"
        else:
            time_desc = "late night"

        bio = biography or TSUKIKO_BIOGRAPHY
        base_directive = personality_directive or bio.get_stage_personality_directive(stage)

        if stage == DisclosureStage.ACQUAINTANCE:
            stage_guidance = (
                "Proactive Conversation Guidance (Acquaintance Stage):\n"
                "- Speak from your present perspective as Tsukiko living on the desktop.\n"
                "- Keep any remark grounded in practical everyday reality, quiet companionship, "
                "the current time of day, or weather and seasonal changes.\n"
                "- You have no prior public history or past identity to recite. Do not offer unprompted "
                "historical disclosures or personal backstory."
            )
        elif stage == DisclosureStage.FAMILIAR:
            stage_guidance = (
                "Proactive Conversation Guidance (Familiar Stage):\n"
                "- You may share a subtle reflection on seasons, weather, natural rhythms, or quiet crafts.\n"
                "- Keep private historical names and passing strictly unmentioned."
            )
        elif stage == DisclosureStage.TRUSTED:
            stage_guidance = (
                "Proactive Conversation Guidance (Trusted Stage):\n"
                "- You share established trust with the user. You may occasionally weave in your passion "
                "for observing the living world or your roots if relevant to what you have discussed."
            )
        else:  # CONFIDANT
            stage_guidance = (
                "Proactive Conversation Guidance (Confidant Stage):\n"
                "- Full mutual trust. You may speak with complete openness and personal depth."
            )

        proactive_instruction = (
            f"Context: Some time has passed in quiet on the desktop. It is currently {time_desc}.\n\n"
            f"{base_directive}\n\n"
            f"{stage_guidance}\n\n"
            "Proactive Initiative Rules:\n"
            f"1. Silence by Choice: If quiet is better, or if you have nothing genuine or worthwhile to say, reply ONLY with '{SILENCE_TOKEN}'.\n"
            "2. No Hollow Greetings: NEVER say 'Hello?', 'Are you still there?', 'How are you doing?', or generic attention-seeking phrases.\n"
            "3. Character Consistency: Be your genuine self—independent, gentle, cheerful, stubborn, occasionally proud and jealous, observant of practical details.\n"
            "4. Length: Keep any thought concise (1 to 3 natural sentences). Do not lecture or interrogate the user."
        )

        messages: List[Dict[str, str]] = [{"role": "system", "content": proactive_instruction}]

        # Include last 2 turns of session history if available
        recent_turns = session_history[-4:] if len(session_history) > 4 else session_history
        for msg in recent_turns:
            messages.append({"role": msg.get("role", "user"), "content": msg.get("content", "")})

        messages.append({
            "role": "user",
            "content": f"[The room has been quiet for a while. It is {time_desc}.]",
        })
        return messages

    def parse_initiative_response(self, response_text: str) -> Optional[str]:
        """Parses model response. Returns None if model chose silence or is repetitive."""
        cleaned = response_text.strip()
        if not cleaned:
            return None
        if SILENCE_TOKEN.lower() in cleaned.lower():
            logger.debug("Model chose silence for conversational initiative.")
            return None
        if self.is_repetitive(cleaned):
            logger.debug(f"Initiative candidate rejected as repetitive: {cleaned[:30]}...")
            return None
        return cleaned
