"""Tsukiko Desktop Companion UI Views.

Phase 2 modular views:
- ChatView: Companion interaction interface (disabled pending Phase 3 AI brain).
- SystemStatusView: Real-time hardware and subsystem metrics from Tsukiko core.
- PrivacyView: Zero-trust privacy verification and locked sensor controls.
- MemoryView: Placeholder view for Phase 4 persistent memory subsystem.
- SettingsView: UI customization (theme, corner, margins, opacity).
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.desktop.companion.views.chat import ChatView
    from app.desktop.companion.views.memory_view import MemoryView
    from app.desktop.companion.views.privacy_view import PrivacyView
    from app.desktop.companion.views.settings_view import SettingsView
    from app.desktop.companion.views.system_status import SystemStatusView

__all__ = [
    "ChatView",
    "SystemStatusView",
    "PrivacyView",
    "MemoryView",
    "SettingsView",
]
