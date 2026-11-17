"""Tsukiko Desktop Companion Subsystem (Phase 2).

Provides the lightweight floating companion widget, compact left menu,
and full Tsukiko main window styled in the Moonlight silver-blue theme.
"""

from __future__ import annotations

import logging
from typing import Any, Optional, Tuple

logger = logging.getLogger(__name__)

try:
    from PySide6.QtWidgets import QApplication
    from app.desktop.companion.avatar import TsukikoAvatarWidget
    from app.desktop.companion.theme import MoonlightTheme
    from app.desktop.companion.widget import CompactCompanionMenu, FloatingCompanionWidget
    from app.desktop.companion.window import CompanionMainWindow
    HAS_PYSIDE6 = True
except ImportError:
    HAS_PYSIDE6 = False
    TsukikoAvatarWidget = None  # type: ignore[assignment,misc]
    MoonlightTheme = None  # type: ignore[assignment,misc]
    CompactCompanionMenu = None  # type: ignore[assignment,misc]
    FloatingCompanionWidget = None  # type: ignore[assignment,misc]
    CompanionMainWindow = None  # type: ignore[assignment,misc]

__all__ = [
    "HAS_PYSIDE6",
    "TsukikoAvatarWidget",
    "MoonlightTheme",
    "CompactCompanionMenu",
    "FloatingCompanionWidget",
    "CompanionMainWindow",
    "launch_companion",
]


def launch_companion(
    config: Optional[Any] = None,
    orchestrator: Optional[Any] = None,
) -> Tuple[Optional[FloatingCompanionWidget], Optional[CompanionMainWindow]]:
    """Initializes and displays the floating companion widget and main window.
    
    Returns (widget, main_window) or (None, None) if PySide6 is unavailable.
    """
    if not HAS_PYSIDE6:
        logger.warning(
            "PySide6 is not installed. Tsukiko desktop companion UI cannot be displayed. "
            "Install UI dependencies via 'pip install -r requirements/ui.txt' or use '--headless'."
        )
        return None, None

    # Instantiate main window (hidden by default)
    main_window = CompanionMainWindow(config=config, orchestrator=orchestrator)

    # Instantiate floating companion widget
    ui_config = config.ui if config else None
    widget = FloatingCompanionWidget(config=ui_config)

    # Connect signals between floating widget and main window
    widget.open_main_requested.connect(lambda: (main_window.show(), main_window.raise_(), main_window.activateWindow()))
    widget.open_settings_requested.connect(lambda: (main_window.show_settings(), main_window.show(), main_window.raise_(), main_window.activateWindow()))

    # Apply settings changes to widget dynamically
    main_window.settings_view.settings_applied.connect(lambda new_cfg: widget._position_to_initial_corner())

    # Show floating widget
    widget.show()
    logger.info("Tsukiko floating desktop companion widget launched successfully.")

    return widget, main_window
