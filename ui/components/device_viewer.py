"""Animated device visualization used by the Scan screen."""

from __future__ import annotations

import math

from PySide6.QtCore import QEasingCurve, QRectF, Qt, QTimer, QVariantAnimation
from PySide6.QtGui import QColor, QFont, QLinearGradient, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import QApplication, QSizePolicy, QWidget


SUPPORTED_DEVICES = (
    "USB Storage",
    "Keyboard",
    "Mouse",
    "SSD",
    "HDD",
    "Phone",
    "USB Hub",
    "Ethernet Adapter",
    "Unknown Device",
)


class AnimatedDeviceViewer(QWidget):
    """Reusable animated stage for supported USB device types."""

    ROTATION_SECONDS = 12.0

    def __init__(
        self,
        parent: QWidget | None = None,
        device_type: str = "Unknown Device",
        connected: bool = False,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("animatedDeviceViewer")
        self.setMinimumHeight(170)
        self.setMaximumHeight(190)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

        self._device_type = self._normalize_device_type(device_type)
        self._connected = connected
        self._phase = 0.0
        self._rotation = 0.0
        self._visibility = 1.0 if connected else 0.28
        self._scale = 1.0 if connected else 0.86

        self._visibility_animation = QVariantAnimation(self)
        self._visibility_animation.setDuration(440)
        self._visibility_animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._visibility_animation.valueChanged.connect(self._set_visibility)

        self._scale_animation = QVariantAnimation(self)
        self._scale_animation.setDuration(480)
        self._scale_animation.setEasingCurve(QEasingCurve.Type.OutBack)
        self._scale_animation.valueChanged.connect(self._set_scale)

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(16)

    @classmethod
    def supported_devices(cls) -> tuple[str, ...]:
        return SUPPORTED_DEVICES

    def device_type(self) -> str:
        return self._device_type

    def is_connected(self) -> bool:
        return self._connected

    def set_device_type(self, device_type: str) -> None:
        self._device_type = self._normalize_device_type(device_type)
        self.update()

    def set_connected(self, connected: bool) -> None:
        if connected:
            self.connect_device()
        else:
            self.disconnect_device()

    def connect_device(self, device_type: str | None = None) -> None:
        if device_type is not None:
            self.set_device_type(device_type)
        self._connected = True
        self._animate_state(visibility=1.0, scale=1.0, duration=460)

    def disconnect_device(self) -> None:
        self._connected = False
        self._animate_state(visibility=0.28, scale=0.84, duration=420)

    def paintEvent(self, event) -> None:  # noqa: ANN001
        del event
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        rect = QRectF(self.rect()).adjusted(10, 8, -10, -8)
        pulse = (math.sin(self._phase) + 1.0) / 2.0
        accent = QColor(47, 191, 113) if self._connected else QColor(209, 75, 87)
        is_dark = self._is_dark_theme()

        self._paint_stage(painter, rect, accent, pulse, is_dark)
        self._paint_rotation_rings(painter, rect, accent, pulse)
        self._paint_device(painter, rect, accent, pulse, is_dark)
        self._paint_caption(painter, rect, accent, is_dark)

    def _paint_stage(
        self,
        painter: QPainter,
        rect: QRectF,
        accent: QColor,
        pulse: float,
        is_dark: bool,
    ) -> None:
        panel_gradient = QLinearGradient(rect.topLeft(), rect.bottomRight())
        panel_gradient.setColorAt(0.0, QColor(255, 255, 255, 46 if is_dark else 86))
        panel_gradient.setColorAt(0.52, QColor(246, 244, 232, 28 if is_dark else 48))
        panel_gradient.setColorAt(1.0, self._with_alpha(accent, 26))

        painter.setPen(QPen(QColor(255, 255, 255, 92 if is_dark else 128), 1.2))
        painter.setBrush(panel_gradient)
        painter.drawRoundedRect(rect, 22, 22)

        glow_rect = rect.adjusted(18, 16, -18, -16)
        glow_alpha = int((50 + pulse * 44) * self._visibility)
        painter.setPen(QPen(self._with_alpha(accent, glow_alpha), 2.0))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawRoundedRect(glow_rect, 18, 18)

        glass_path = QPainterPath()
        glass_path.addRoundedRect(rect, 22, 22)
        painter.save()
        painter.setClipPath(glass_path)
        shimmer_x = rect.left() - rect.width() * 0.25 + rect.width() * 1.5 * pulse
        shimmer = QLinearGradient(shimmer_x - 90, rect.top(), shimmer_x + 90, rect.bottom())
        shimmer.setColorAt(0.0, QColor(255, 255, 255, 0))
        shimmer.setColorAt(0.5, QColor(255, 255, 255, 58))
        shimmer.setColorAt(1.0, QColor(255, 255, 255, 0))
        painter.fillRect(rect, shimmer)
        painter.restore()

    def _paint_rotation_rings(
        self,
        painter: QPainter,
        rect: QRectF,
        accent: QColor,
        pulse: float,
    ) -> None:
        center = rect.center()
        ring_size = min(rect.width(), rect.height()) * 0.78
        ring_rect = QRectF(
            center.x() - ring_size / 2,
            center.y() - ring_size / 2 - 4,
            ring_size,
            ring_size,
        )

        painter.save()
        painter.translate(center)
        painter.rotate(self._rotation)
        painter.translate(-center)
        painter.setPen(QPen(self._with_alpha(accent, int(58 * self._visibility)), 2.0))
        painter.drawArc(ring_rect, 22 * 16, 126 * 16)
        painter.drawArc(ring_rect.adjusted(12, 12, -12, -12), 210 * 16, 96 * 16)
        painter.restore()

        pulse_rect = ring_rect.adjusted(-pulse * 10, -pulse * 10, pulse * 10, pulse * 10)
        painter.setPen(QPen(self._with_alpha(accent, int((28 + pulse * 38) * self._visibility)), 1.4))
        painter.drawEllipse(pulse_rect)

    def _paint_device(
        self,
        painter: QPainter,
        rect: QRectF,
        accent: QColor,
        pulse: float,
        is_dark: bool,
    ) -> None:
        painter.save()
        center = rect.center()
        painter.translate(center)
        scale = self._scale * (1.0 + (0.035 * pulse if self._connected else 0.025 * pulse))
        painter.scale(scale, scale)
        painter.translate(-center)
        painter.setOpacity(self._visibility)

        box = QRectF(center.x() - 54, center.y() - 48, 108, 86)
        draw_method = {
            "USB Storage": self._draw_usb_storage,
            "Keyboard": self._draw_keyboard,
            "Mouse": self._draw_mouse,
            "SSD": self._draw_ssd,
            "HDD": self._draw_hdd,
            "Phone": self._draw_phone,
            "USB Hub": self._draw_usb_hub,
            "Ethernet Adapter": self._draw_ethernet_adapter,
            "Unknown Device": self._draw_unknown_device,
        }[self._device_type]
        draw_method(painter, box, accent, is_dark)
        painter.restore()

    def _paint_caption(
        self,
        painter: QPainter,
        rect: QRectF,
        accent: QColor,
        is_dark: bool,
    ) -> None:
        status = "Connected" if self._connected else "Disconnected"
        text_color = QColor(244, 241, 232) if is_dark else QColor(31, 35, 32)
        painter.setPen(self._with_alpha(text_color, 220))
        font = QFont()
        font.setPointSize(11)
        font.setWeight(QFont.Weight.DemiBold)
        painter.setFont(font)
        painter.drawText(rect.adjusted(18, 14, -18, -14), Qt.AlignmentFlag.AlignLeft, self._device_type)

        painter.setPen(self._with_alpha(accent, 220))
        painter.drawText(
            rect.adjusted(18, 14, -18, -14),
            Qt.AlignmentFlag.AlignRight,
            status,
        )

    def _draw_usb_storage(
        self,
        painter: QPainter,
        box: QRectF,
        accent: QColor,
        is_dark: bool,
    ) -> None:
        body = box.adjusted(18, 24, -16, -22)
        plug = QRectF(body.right() - 4, body.top() + 10, 26, body.height() - 20)
        self._draw_shell(painter, body, accent, is_dark)
        painter.drawRoundedRect(plug, 5, 5)
        painter.drawLine(body.left() + 14, body.center().y(), body.right() - 8, body.center().y())

    def _draw_keyboard(
        self,
        painter: QPainter,
        box: QRectF,
        accent: QColor,
        is_dark: bool,
    ) -> None:
        body = box.adjusted(4, 24, -4, -18)
        self._draw_shell(painter, body, accent, is_dark)
        key_w = body.width() / 8
        for row in range(3):
            for col in range(7):
                key = QRectF(body.left() + 9 + col * key_w, body.top() + 9 + row * 11, key_w - 5, 6)
                painter.drawRoundedRect(key, 2, 2)

    def _draw_mouse(
        self,
        painter: QPainter,
        box: QRectF,
        accent: QColor,
        is_dark: bool,
    ) -> None:
        body = QRectF(box.center().x() - 28, box.top() + 12, 56, 76)
        self._draw_shell(painter, body, accent, is_dark)
        painter.drawLine(body.center().x(), body.top() + 10, body.center().x(), body.top() + 34)
        painter.drawRoundedRect(QRectF(body.center().x() - 5, body.top() + 12, 10, 14), 5, 5)

    def _draw_ssd(
        self,
        painter: QPainter,
        box: QRectF,
        accent: QColor,
        is_dark: bool,
    ) -> None:
        body = box.adjusted(10, 20, -10, -20)
        self._draw_shell(painter, body, accent, is_dark)
        painter.drawText(body, Qt.AlignmentFlag.AlignCenter, "SSD")
        painter.drawLine(body.left() + 14, body.bottom() - 12, body.right() - 14, body.bottom() - 12)

    def _draw_hdd(
        self,
        painter: QPainter,
        box: QRectF,
        accent: QColor,
        is_dark: bool,
    ) -> None:
        body = box.adjusted(18, 8, -18, -8)
        self._draw_shell(painter, body, accent, is_dark)
        painter.drawEllipse(QRectF(body.center().x() - 22, body.top() + 16, 44, 44))
        painter.drawEllipse(QRectF(body.center().x() - 5, body.top() + 33, 10, 10))

    def _draw_phone(
        self,
        painter: QPainter,
        box: QRectF,
        accent: QColor,
        is_dark: bool,
    ) -> None:
        body = QRectF(box.center().x() - 26, box.top() + 2, 52, 84)
        self._draw_shell(painter, body, accent, is_dark)
        painter.drawRoundedRect(body.adjusted(7, 10, -7, -12), 8, 8)
        painter.drawEllipse(QRectF(body.center().x() - 3, body.bottom() - 9, 6, 6))

    def _draw_usb_hub(
        self,
        painter: QPainter,
        box: QRectF,
        accent: QColor,
        is_dark: bool,
    ) -> None:
        body = box.adjusted(18, 22, -18, -18)
        self._draw_shell(painter, body, accent, is_dark)
        for index in range(3):
            x = body.left() + 18 + index * 24
            painter.drawRoundedRect(QRectF(x, body.top() + 14, 14, 16), 3, 3)
            painter.drawLine(x + 7, body.bottom(), x + 7, body.bottom() + 14)

    def _draw_ethernet_adapter(
        self,
        painter: QPainter,
        box: QRectF,
        accent: QColor,
        is_dark: bool,
    ) -> None:
        body = box.adjusted(10, 22, -10, -20)
        jack = QRectF(body.right() - 35, body.top() + 11, 24, 24)
        self._draw_shell(painter, body, accent, is_dark)
        painter.drawRoundedRect(jack, 4, 4)
        painter.drawLine(body.left() + 12, body.center().y(), jack.left() - 8, body.center().y())
        for index in range(4):
            painter.drawLine(jack.left() + 5 + index * 4, jack.top() + 5, jack.left() + 5 + index * 4, jack.top() + 13)

    def _draw_unknown_device(
        self,
        painter: QPainter,
        box: QRectF,
        accent: QColor,
        is_dark: bool,
    ) -> None:
        center = box.center()
        path = QPainterPath()
        path.moveTo(center.x(), box.top() + 10)
        path.lineTo(box.right() - 22, center.y())
        path.lineTo(center.x(), box.bottom() - 10)
        path.lineTo(box.left() + 22, center.y())
        path.closeSubpath()
        self._draw_shell_path(painter, path, path.boundingRect(), accent, is_dark)
        font = painter.font()
        font.setPointSize(28)
        font.setWeight(QFont.Weight.Bold)
        painter.setFont(font)
        painter.drawText(box, Qt.AlignmentFlag.AlignCenter, "?")

    def _draw_shell(
        self,
        painter: QPainter,
        rect: QRectF,
        accent: QColor,
        is_dark: bool,
    ) -> None:
        gradient = QLinearGradient(rect.topLeft(), rect.bottomRight())
        gradient.setColorAt(0.0, QColor(255, 255, 255, 118 if is_dark else 190))
        gradient.setColorAt(1.0, self._with_alpha(accent, 68 if is_dark else 82))
        painter.setBrush(gradient)
        painter.setPen(QPen(self._with_alpha(accent, 190), 2.0))
        painter.drawRoundedRect(rect, 12, 12)

    def _draw_shell_path(
        self,
        painter: QPainter,
        path: QPainterPath,
        bounds: QRectF,
        accent: QColor,
        is_dark: bool,
    ) -> None:
        gradient = QLinearGradient(bounds.topLeft(), bounds.bottomRight())
        gradient.setColorAt(0.0, QColor(255, 255, 255, 118 if is_dark else 190))
        gradient.setColorAt(1.0, self._with_alpha(accent, 68 if is_dark else 82))
        painter.setBrush(gradient)
        painter.setPen(QPen(self._with_alpha(accent, 190), 2.0))
        painter.drawPath(path)

    def _animate_state(self, visibility: float, scale: float, duration: int) -> None:
        self._visibility_animation.stop()
        self._visibility_animation.setDuration(duration)
        self._visibility_animation.setStartValue(self._visibility)
        self._visibility_animation.setEndValue(visibility)
        self._visibility_animation.start()

        self._scale_animation.stop()
        self._scale_animation.setDuration(duration)
        self._scale_animation.setStartValue(self._scale)
        self._scale_animation.setEndValue(scale)
        self._scale_animation.start()

    def _set_visibility(self, value: float) -> None:
        self._visibility = float(value)
        self.update()

    def _set_scale(self, value: float) -> None:
        self._scale = float(value)
        self.update()

    def _tick(self) -> None:
        self._phase = (self._phase + 0.055) % (math.pi * 2)
        self._rotation = (self._rotation + (360.0 / (self.ROTATION_SECONDS * 60.0))) % 360.0
        self.update()

    def _normalize_device_type(self, device_type: str) -> str:
        normalized = device_type.strip()
        supported_by_key = {device.lower(): device for device in SUPPORTED_DEVICES}
        return supported_by_key.get(normalized.lower(), "Unknown Device")

    def _is_dark_theme(self) -> bool:
        app = QApplication.instance()
        return app is not None and app.property("theme_name") == "dark"

    def _with_alpha(self, color: QColor, alpha: int) -> QColor:
        result = QColor(color)
        result.setAlpha(max(0, min(255, alpha)))
        return result
