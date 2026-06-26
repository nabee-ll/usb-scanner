"""Dashboard page for the USB scanner UI."""

from __future__ import annotations

from PySide6.QtCore import QDateTime, QEasingCurve, QPropertyAnimation, QTimer
from PySide6.QtWidgets import (
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from core.context import AppContext
from ui.components import (
    GlassCard,
    PrimaryButton,
    RiskMeter,
    SecondaryButton,
    StatusChip,
)
from ui.widgets import BaseWidget


class DashboardPage(BaseWidget):
    """First dashboard screen with placeholder UI state only."""

    def __init__(self, context: AppContext, parent: QWidget | None = None) -> None:
        self.time_label: QLabel
        self.date_label: QLabel
        self._intro_animations: list[QPropertyAnimation] = []
        super().__init__(context, parent)

    def setup_ui(self) -> None:
        self.setObjectName("dashboardPage")
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 28)
        root.setSpacing(22)

        root.addLayout(self._build_header())
        root.addWidget(self._build_scan_action())

        cards_grid = QGridLayout()
        cards_grid.setHorizontalSpacing(18)
        cards_grid.setVerticalSpacing(18)
        cards_grid.addWidget(self._build_device_status_card(), 0, 0)
        cards_grid.addWidget(self._build_last_scan_card(), 0, 1)
        cards_grid.addWidget(self._build_threat_summary_card(), 0, 2)
        cards_grid.addWidget(self._build_quick_actions_card(), 1, 0)
        cards_grid.addWidget(self._build_recent_activity_card(), 1, 1, 1, 2)
        cards_grid.setColumnStretch(0, 1)
        cards_grid.setColumnStretch(1, 1)
        cards_grid.setColumnStretch(2, 1)
        root.addLayout(cards_grid, stretch=1)

        self._refresh_clock()

    def bind_events(self) -> None:
        self._clock_timer = QTimer(self)
        self._clock_timer.timeout.connect(self._refresh_clock)
        self._clock_timer.start(1000)

    def on_enter(self) -> None:
        self._animate_intro()

    def _build_header(self) -> QHBoxLayout:
        header = QHBoxLayout()
        header.setSpacing(16)

        title_group = QVBoxLayout()
        title_group.setSpacing(2)

        app_name = QLabel(self.context.settings.app_name, self)
        app_name.setObjectName("dashboardTitle")

        subtitle = QLabel("Dashboard", self)
        subtitle.setObjectName("dashboardSubtitle")

        title_group.addWidget(app_name)
        title_group.addWidget(subtitle)

        self.time_label = QLabel(self)
        self.time_label.setObjectName("dashboardTime")
        self.date_label = QLabel(self)
        self.date_label.setObjectName("dashboardDate")

        clock_group = QVBoxLayout()
        clock_group.setSpacing(2)
        clock_group.addWidget(self.time_label)
        clock_group.addWidget(self.date_label)

        notification_button = SecondaryButton("Notifications", self)

        header.addLayout(title_group)
        header.addStretch(1)
        header.addLayout(clock_group)
        header.addWidget(notification_button)
        return header

    def _build_scan_action(self) -> GlassCard:
        card = GlassCard(self)

        layout = QHBoxLayout()
        layout.setSpacing(18)

        copy = QVBoxLayout()
        copy.setSpacing(4)

        title = QLabel("Ready to scan", self)
        title.setObjectName("cardTitle")
        body = QLabel("Connect a USB device and start a manual scan.", self)
        body.setObjectName("cardBody")
        body.setWordWrap(True)

        copy.addWidget(title)
        copy.addWidget(body)

        scan_button = PrimaryButton("Scan Device", self)
        scan_button.setMinimumHeight(64)
        scan_button.setMinimumWidth(220)

        layout.addLayout(copy, stretch=1)
        layout.addWidget(scan_button)
        card.layout.addLayout(layout)
        return card

    def _build_device_status_card(self) -> GlassCard:
        card = self._card("Device Status")
        card.layout.addWidget(StatusChip("No device connected", "neutral", self))
        card.layout.addWidget(self._body("Waiting for a USB storage device."))
        return card

    def _build_last_scan_card(self) -> GlassCard:
        card = self._card("Last Scan")
        card.layout.addWidget(StatusChip("Not scanned yet", "warning", self))
        card.layout.addWidget(self._metric("--"))
        card.layout.addWidget(self._body("Scan history will appear after the first scan."))
        return card

    def _build_threat_summary_card(self) -> GlassCard:
        card = self._card("Threat Summary")
        meter = RiskMeter(0, self)
        meter.setObjectName("dashboardRiskMeter")
        card.layout.addWidget(meter)
        card.layout.addWidget(StatusChip("No active threats", "success", self))
        return card

    def _build_quick_actions_card(self) -> GlassCard:
        card = self._card("Quick Actions")
        card.layout.addWidget(SecondaryButton("View Reports", self))
        card.layout.addWidget(SecondaryButton("Open Settings", self))
        card.layout.addWidget(SecondaryButton("Refresh Status", self))
        return card

    def _build_recent_activity_card(self) -> GlassCard:
        card = self._card("Recent Activity")
        activities = [
            "Application started",
            "Scanner service idle",
            "No removable device detected",
        ]
        for activity in activities:
            card.layout.addWidget(self._activity_row(activity))
        card.layout.addStretch(1)
        return card

    def _card(self, title: str) -> GlassCard:
        card = GlassCard(self)
        card.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        label = QLabel(title, self)
        label.setObjectName("cardTitle")
        card.layout.addWidget(label)
        return card

    def _metric(self, text: str) -> QLabel:
        label = QLabel(text, self)
        label.setObjectName("dashboardMetric")
        return label

    def _body(self, text: str) -> QLabel:
        label = QLabel(text, self)
        label.setObjectName("cardBody")
        label.setWordWrap(True)
        return label

    def _activity_row(self, text: str) -> QLabel:
        label = QLabel(text, self)
        label.setObjectName("activityRow")
        label.setMinimumHeight(36)
        return label

    def _refresh_clock(self) -> None:
        now = QDateTime.currentDateTime()
        self.time_label.setText(now.toString("hh:mm AP"))
        self.date_label.setText(now.toString("dddd, MMMM d"))

    def _animate_intro(self) -> None:
        self._intro_animations.clear()
        delay = 0
        for child in self.findChildren(GlassCard):
            child.setWindowOpacity(0.0)
            animation = QPropertyAnimation(child, b"windowOpacity", self)
            animation.setDuration(420)
            animation.setStartValue(0.0)
            animation.setEndValue(1.0)
            animation.setEasingCurve(QEasingCurve.Type.OutCubic)
            animation.setLoopCount(1)
            QTimer.singleShot(delay, animation.start)
            self._intro_animations.append(animation)
            delay += 70
