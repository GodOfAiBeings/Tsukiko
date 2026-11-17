"""
Tsukiko Desktop Companion Theme & Design System
Moonlight silver-blue visual palette, stylesheets, and styling utilities.
"""

from __future__ import annotations

from typing import Dict, Any


class MoonlightTheme:
    """Design tokens and palette for Tsukiko's silver-blue-moonlight visual design."""

    # Core Brand Palette
    THEME_NAME = "silver-blue-moonlight"
    ACCENT = "#7FB3D5"          # Moonlit ice blue
    PRIMARY_ACCENT = "#7FB3D5"  # Alias
    ACCENT_HOVER = "#9AC4E2"    # Brighter hover blue
    ACCENT_PRESSED = "#699FC1"  # Deeper pressed blue
    GLOW = "#D4E6F1"            # Soft lunar shimmer
    MOONLIGHT_GLOW = "#D4E6F1"  # Alias
    GLOW_DIM = "#A9CCE3"        # Subtle secondary glow

    # Background Surfaces (Moonlit frosted slate)
    BG_BASE = "#0D131C"         # Deep night sky base
    BG_VOID = "#0D131C"         # Alias
    BG_SURFACE = "#151F2C"      # Primary frosted panel
    BG_CARD = "#1C2A3A"         # Elevated card surface
    BG_CARD_HOVER = "#24354A"   # Card hover state
    BG_INPUT = "#111A24"        # Recessed input fields
    BG_HIGHLIGHT = "#283E56"    # Active row highlight

    # Borders & Dividers
    BORDER_SUBTLE = "#283747"   # Soft container divider
    BORDER_MUTED = "#3D5266"    # Visible section boundary
    BORDER_ACTIVE = "#7FB3D5"   # Focused/active border

    # Typography Colors
    TEXT_PRIMARY = "#F2F4F7"    # Crisp silver-white text
    TEXT_SECONDARY = "#A0B2C6"  # Soft slate-blue secondary text
    TEXT_MUTED = "#6C7D93"      # Dim labels & timestamps
    TEXT_ACCENT = "#99C5E5"     # Emphasized blue text

    # Status & Badges
    STATUS_ACTIVE = "#52BE80"   # Safe / verified / active green
    STATUS_WARNING = "#F5B041"  # Caution / unverified amber
    STATUS_DISABLED = "#5D6D7E" # Inactive / phase-locked slate
    STATUS_LOCKED = "#85929E"   # Security-locked indicator
    STATUS_ERROR = "#EC7063"    # Fault / violation red

    # Opacity & Geometry Defaults
    DEFAULT_OPACITY = 0.92
    RADIUS_LG = 14
    RADIUS_MD = 10
    RADIUS_SM = 6
    RADIUS_PILL = 999

    @classmethod
    def get_stylesheet(
        cls,
        accent: str = ACCENT,
        glow: str = GLOW,
        surface: str = BG_SURFACE,
        card: str = BG_CARD,
        opacity: float = DEFAULT_OPACITY,
    ) -> str:
        """Generates comprehensive Qt Style Sheet (QSS) for the application."""
        return f"""
        /* ── Base Window & Typography ───────────────────────────────── */
        QMainWindow, QWidget#CompanionMainContainer {{
            background-color: {surface};
            color: {cls.TEXT_PRIMARY};
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, 'Inter', sans-serif;
            font-size: 13px;
            font-weight: 400;
        }}

        QWidget {{
            outline: none;
        }}

        /* ── Scrollbars ────────────────────────────────────────────── */
        QScrollBar:vertical {{
            background: transparent;
            width: 8px;
            margin: 0px;
        }}
        QScrollBar::handle:vertical {{
            background: {cls.BORDER_MUTED};
            min-height: 24px;
            border-radius: 4px;
        }}
        QScrollBar::handle:vertical:hover {{
            background: {accent};
        }}
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical,
        QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{
            background: transparent;
            height: 0px;
        }}

        /* ── Push Buttons ─────────────────────────────────────────── */
        QPushButton {{
            background-color: {card};
            color: {cls.TEXT_PRIMARY};
            border: 1px solid {cls.BORDER_SUBTLE};
            border-radius: {cls.RADIUS_SM}px;
            padding: 8px 16px;
            font-weight: 500;
            font-size: 12px;
        }}
        QPushButton:hover {{
            background-color: {cls.BG_CARD_HOVER};
            border-color: {accent};
            color: #FFFFFF;
        }}
        QPushButton:pressed {{
            background-color: {cls.BG_HIGHLIGHT};
            border-color: {cls.ACCENT_PRESSED};
        }}
        QPushButton:disabled {{
            background-color: {cls.BG_INPUT};
            border-color: {cls.BORDER_SUBTLE};
            color: {cls.TEXT_MUTED};
        }}

        /* Primary Accent Buttons */
        QPushButton[primary="true"] {{
            background-color: {accent};
            color: #0B131C;
            border: 1px solid {glow};
            font-weight: 600;
        }}
        QPushButton[primary="true"]:hover {{
            background-color: {cls.ACCENT_HOVER};
            border-color: #FFFFFF;
        }}
        QPushButton[primary="true"]:pressed {{
            background-color: {cls.ACCENT_PRESSED};
        }}
        QPushButton[primary="true"]:disabled {{
            background-color: {cls.BORDER_MUTED};
            border-color: {cls.BORDER_SUBTLE};
            color: {cls.TEXT_MUTED};
        }}

        /* Nav Sidebar Buttons */
        QPushButton[nav="true"] {{
            background-color: transparent;
            color: {cls.TEXT_SECONDARY};
            border: none;
            border-radius: {cls.RADIUS_SM}px;
            padding: 10px 14px;
            text-align: left;
            font-weight: 500;
            font-size: 13px;
        }}
        QPushButton[nav="true"]:hover {{
            background-color: {card};
            color: {cls.TEXT_PRIMARY};
        }}
        QPushButton[nav="true"][active="true"] {{
            background-color: {card};
            color: {accent};
            font-weight: 600;
            border-left: 3px solid {accent};
        }}

        /* ── Input Controls ────────────────────────────────────────── */
        QLineEdit, QTextEdit, QPlainTextEdit {{
            background-color: {cls.BG_INPUT};
            color: {cls.TEXT_PRIMARY};
            border: 1px solid {cls.BORDER_MUTED};
            border-radius: {cls.RADIUS_SM}px;
            padding: 8px 10px;
            selection-background-color: {accent};
            selection-color: #000000;
        }}
        QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus {{
            border: 1px solid {accent};
            background-color: {cls.BG_BASE};
        }}
        QLineEdit:disabled, QTextEdit:disabled, QPlainTextEdit:disabled {{
            background-color: {cls.BG_INPUT};
            border-color: {cls.BORDER_SUBTLE};
            color: {cls.TEXT_MUTED};
        }}

        /* ── Frames & Cards ────────────────────────────────────────── */
        QFrame[card="true"] {{
            background-color: {card};
            border: 1px solid {cls.BORDER_SUBTLE};
            border-radius: {cls.RADIUS_MD}px;
        }}
        QFrame[card="true"]:hover {{
            border-color: {cls.BORDER_MUTED};
        }}

        /* ── Section Titles & Headers ──────────────────────────────── */
        QLabel[heading="h1"] {{
            font-size: 20px;
            font-weight: 700;
            color: {cls.TEXT_PRIMARY};
            margin-bottom: 4px;
        }}
        QLabel[heading="h2"] {{
            font-size: 15px;
            font-weight: 600;
            color: {cls.TEXT_PRIMARY};
        }}
        QLabel[heading="h3"] {{
            font-size: 13px;
            font-weight: 600;
            color: {cls.TEXT_SECONDARY};
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        QLabel[muted="true"] {{
            color: {cls.TEXT_MUTED};
            font-size: 12px;
        }}
        QLabel[accent="true"] {{
            color: {accent};
            font-weight: 600;
        }}

        /* ── Badges ────────────────────────────────────────────────── */
        QLabel[badge="active"] {{
            background-color: rgba(82, 190, 128, 0.15);
            color: {cls.STATUS_ACTIVE};
            border: 1px solid rgba(82, 190, 128, 0.35);
            border-radius: 4px;
            padding: 3px 8px;
            font-size: 11px;
            font-weight: 600;
        }}
        QLabel[badge="warning"] {{
            background-color: rgba(245, 176, 65, 0.15);
            color: {cls.STATUS_WARNING};
            border: 1px solid rgba(245, 176, 65, 0.35);
            border-radius: 4px;
            padding: 3px 8px;
            font-size: 11px;
            font-weight: 600;
        }}
        QLabel[badge="locked"] {{
            background-color: rgba(133, 146, 158, 0.15);
            color: {cls.STATUS_LOCKED};
            border: 1px solid rgba(133, 146, 158, 0.3);
            border-radius: 4px;
            padding: 3px 8px;
            font-size: 11px;
            font-weight: 600;
        }}
        QLabel[badge="disabled"] {{
            background-color: rgba(93, 109, 126, 0.15);
            color: {cls.STATUS_DISABLED};
            border: 1px solid rgba(93, 109, 126, 0.25);
            border-radius: 4px;
            padding: 3px 8px;
            font-size: 11px;
            font-weight: 500;
        }}

        /* ── Progress Bars ─────────────────────────────────────────── */
        QProgressBar {{
            background-color: {cls.BG_INPUT};
            border: 1px solid {cls.BORDER_SUBTLE};
            border-radius: 4px;
            height: 8px;
            text-align: center;
        }}
        QProgressBar::chunk {{
            background-color: {accent};
            border-radius: 3px;
        }}

        /* ── Sliders ───────────────────────────────────────────────── */
        QSlider::groove:horizontal {{
            background: {cls.BG_INPUT};
            height: 6px;
            border-radius: 3px;
        }}
        QSlider::sub-page:horizontal {{
            background: {accent};
            border-radius: 3px;
        }}
        QSlider::handle:horizontal {{
            background: {glow};
            border: 1px solid {accent};
            width: 16px;
            margin-top: -5px;
            margin-bottom: -5px;
            border-radius: 8px;
        }}

        /* ── Combo Boxes ───────────────────────────────────────────── */
        QComboBox {{
            background-color: {cls.BG_INPUT};
            color: {cls.TEXT_PRIMARY};
            border: 1px solid {cls.BORDER_MUTED};
            border-radius: {cls.RADIUS_SM}px;
            padding: 6px 12px;
            min-height: 20px;
        }}
        QComboBox:hover {{
            border-color: {accent};
        }}
        QComboBox::drop-down {{
            border: none;
            width: 20px;
        }}
        QComboBox QAbstractItemView {{
            background-color: {card};
            color: {cls.TEXT_PRIMARY};
            border: 1px solid {cls.BORDER_MUTED};
            selection-background-color: {accent};
            selection-color: #000000;
            padding: 4px;
        }}

        /* ── Check Boxes ───────────────────────────────────────────── */
        QCheckBox {{
            color: {cls.TEXT_PRIMARY};
            spacing: 8px;
        }}
        QCheckBox::indicator {{
            width: 16px;
            height: 16px;
            border: 1px solid {cls.BORDER_MUTED};
            border-radius: 4px;
            background: {cls.BG_INPUT};
        }}
        QCheckBox::indicator:checked {{
            background: {accent};
            border-color: {glow};
        }}
        QCheckBox:disabled {{
            color: {cls.TEXT_MUTED};
        }}
        """

    @classmethod
    def get_full_stylesheet(cls) -> str:
        """Alias for get_stylesheet()."""
        return cls.get_stylesheet()
