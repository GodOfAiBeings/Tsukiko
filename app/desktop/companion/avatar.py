"""
Tsukiko Desktop Companion Avatar Emblem
Graceful, locally-drawn procedural moonlight emblem for Tsukiko.
Renders with anti-aliasing without external assets, images, or font dependencies.
"""

from __future__ import annotations

import math
from typing import Optional

try:
    from PySide6.QtCore import QPointF, QRectF, QTimer, Qt
    from PySide6.QtGui import (
        QBrush,
        QColor,
        QLinearGradient,
        QPainter,
        QPainterPath,
        QPen,
        QRadialGradient,
    )
    from PySide6.QtWidgets import QWidget
    PYSIDE6_AVAILABLE = True
except ImportError:
    PYSIDE6_AVAILABLE = False
    QWidget = object  # type: ignore


class TsukikoAvatarWidget(QWidget):  # type: ignore[misc]
    """Procedural vector moonlight emblem representing Tsukiko.

    Visual motif:
    - Soft outer lunar halo with translucent blue-glow falloff.
    - Silver-blue inner celestial circle with subtle depth gradient.
    - Elegant crescent moon silhouette intersecting an orbital ring.
    - Gentle pulse/shimmer animation during active state.
    """

    def __init__(
        self,
        size: int = 96,
        accent_color: str = "#7FB3D5",
        glow_color: str = "#D4E6F1",
        active: bool = False,
        animate: bool = True,
        fps: int = 30,
        parent: Optional[QWidget] = None,
    ) -> None:
        if not PYSIDE6_AVAILABLE:
            raise ImportError("PySide6 is required to instantiate TsukikoAvatarWidget.")

        super().__init__(parent)
        self._size = size
        self._accent_hex = accent_color
        self._glow_hex = glow_color
        self._active = active
        self._animate = animate
        self._fps = max(10, min(60, fps))
        self._phase = 0.0

        self.setFixedSize(size, size)
        self.setAttribute(Qt.WA_TranslucentBackground, True)

        # Pulse timer for moonlight shimmer
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._on_tick)
        if self._animate:
            self._timer.start(int(1000 / self._fps))

    @property
    def animation_timer(self) -> QTimer:
        return self._timer

    def start_animation(self) -> None:
        self.set_animated(True)

    def stop_animation(self) -> None:
        self.set_animated(False)

    def set_active(self, val: bool) -> None:
        self.is_active = val

    @property
    def is_active(self) -> bool:
        return self._active

    @is_active.setter
    def is_active(self, val: bool) -> None:
        if self._active != val:
            self._active = val
            self.update()

    def set_palette(self, accent_hex: str, glow_hex: str) -> None:
        self._accent_hex = accent_hex
        self._glow_hex = glow_hex
        self.update()

    def set_animated(self, enabled: bool) -> None:
        self._animate = enabled
        if enabled and not self._timer.isActive():
            self._timer.start(int(1000 / self._fps))
        elif not enabled and self._timer.isActive():
            self._timer.stop()
            self._phase = 0.0
            self.update()

    def _on_tick(self) -> None:
        # Subtle gentle oscillation (1.5s per cycle)
        speed = 0.08 if self._active else 0.03
        self._phase = (self._phase + speed) % (2 * math.pi)
        self.update()

    def paintEvent(self, event: Any) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing, True)
        painter.setRenderHint(QPainter.SmoothPixmapTransform, True)

        w = float(self.width())
        h = float(self.height())
        center_x = w / 2.0
        center_y = h / 2.0
        base_radius = min(w, h) * 0.42

        # Compute dynamic pulse factor
        pulse = math.sin(self._phase)
        glow_radius = base_radius * (1.18 + (0.08 * pulse if self._active else 0.03 * pulse))
        glow_alpha = int(90 + 50 * pulse) if self._active else int(45 + 15 * pulse)

        accent_color = QColor(self._accent_hex)
        glow_color = QColor(self._glow_hex)

        # ── 1. Outer Lunar Halo (Radial Gradient) ─────────────────────
        halo_gradient = QRadialGradient(center_x, center_y, glow_radius)
        glow_c = QColor(glow_color)
        glow_c.setAlpha(glow_alpha)
        halo_gradient.setColorAt(0.0, glow_c)
        glow_mid = QColor(accent_color)
        glow_mid.setAlpha(int(glow_alpha * 0.45))
        halo_gradient.setColorAt(0.65, glow_mid)
        halo_gradient.setColorAt(1.0, QColor(0, 0, 0, 0))

        painter.setBrush(QBrush(halo_gradient))
        painter.setPen(Qt.NoPen)
        painter.drawEllipse(QPointF(center_x, center_y), glow_radius, glow_radius)

        # ── 2. Core Lunar Orb Surface ─────────────────────────────────
        orb_gradient = QLinearGradient(
            center_x - base_radius, center_y - base_radius,
            center_x + base_radius, center_y + base_radius,
        )
        orb_top = QColor("#1C2C40")
        orb_bot = QColor("#0E1622")
        orb_gradient.setColorAt(0.0, orb_top)
        orb_gradient.setColorAt(1.0, orb_bot)

        painter.setBrush(QBrush(orb_gradient))
        orb_border = QColor(self._accent_hex)
        orb_border.setAlpha(200 if self._active else 120)
        painter.setPen(QPen(orb_border, 1.8))
        painter.drawEllipse(QPointF(center_x, center_y), base_radius, base_radius)

        # ── 3. Orbital Ring Accent ────────────────────────────────────
        ring_rect = QRectF(
            center_x - base_radius * 0.95,
            center_y - base_radius * 0.40,
            base_radius * 1.9,
            base_radius * 0.8,
        )
        painter.save()
        painter.translate(center_x, center_y)
        painter.rotate(-25.0)
        painter.translate(-center_x, -center_y)

        ring_pen = QPen(accent_color, 1.4)
        ring_pen.setColor(QColor(accent_color.red(), accent_color.green(), accent_color.blue(), 140))
        painter.setPen(ring_pen)
        painter.setBrush(Qt.NoBrush)
        painter.drawEllipse(ring_rect)
        painter.restore()

        # ── 4. Elegant Crescent Moon Motif ────────────────────────────
        moon_path = QPainterPath()
        moon_r = base_radius * 0.62
        offset_x = base_radius * 0.22

        # Outer moon arc
        moon_path.addEllipse(QPointF(center_x - offset_x * 0.3, center_y), moon_r, moon_r)

        # Cutout arc to form the crescent
        cutout = QPainterPath()
        cutout.addEllipse(QPointF(center_x + offset_x * 0.5, center_y - offset_x * 0.2), moon_r * 0.88, moon_r * 0.88)
        crescent = moon_path.subtracted(cutout)

        crescent_grad = QLinearGradient(
            center_x - moon_r, center_y - moon_r,
            center_x + moon_r, center_y + moon_r,
        )
        cres_c1 = QColor(self._glow_hex)
        cres_c1.setAlpha(240 if self._active else 200)
        cres_c2 = QColor(self._accent_hex)
        cres_c2.setAlpha(190 if self._active else 140)
        crescent_grad.setColorAt(0.0, cres_c1)
        crescent_grad.setColorAt(1.0, cres_c2)

        painter.setBrush(QBrush(crescent_grad))
        painter.setPen(Qt.NoPen)
        painter.drawPath(crescent)

        # ── 5. Central Shimmer Star / Moon Eye ────────────────────────
        sparkle_r = 2.2 + (0.8 * pulse if self._active else 0.3 * pulse)
        sparkle_c = QColor("#FFFFFF")
        sparkle_c.setAlpha(240 if self._active else 170)
        painter.setBrush(QBrush(sparkle_c))
        painter.drawEllipse(QPointF(center_x + base_radius * 0.18, center_y - base_radius * 0.22), sparkle_r, sparkle_r)

        painter.end()
