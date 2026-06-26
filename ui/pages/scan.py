"""Scan screen layout for the USB scanner UI."""

from __future__ import annotations

from PySide6.QtCore import QEasingCurve, QPropertyAnimation, QTimer, Qt
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
    AnimatedDeviceViewer,
    DangerButton,
    GlassCard,
    GlassProgressBar,
    PrimaryButton,
    RiskMeter,
    SecondaryButton,
    StatusChip,
)
from ui.widgets import BaseWidget


class ScanPage(BaseWidget):
    """Flagship scan screen with UI-only placeholder state."""

    def __init__(self, context: AppContext, parent: QWidget | None = None) -> None:
        self._intro_animations: list[QPropertyAnimation] = []
        super().__init__(context, parent)

    def setup_ui(self) -> None:
        self.setObjectName("scanPage")
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        root = QVBoxLayout(self)
        root.setContentsMargins(22, 18, 22, 18)
        root.setSpacing(12)

        root.addLayout(self._build_header())
        root.addWidget(AnimatedDeviceViewer(self))

        grid = QGridLayout()
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(12)
        grid.addWidget(self._build_device_info_card(), 0, 0)
        grid.addWidget(self._build_progress_section(), 0, 1)
        grid.addWidget(self._build_threat_detection_card(), 0, 2, 2, 1)
        grid.addWidget(self._build_file_statistics_card(), 1, 0)
        grid.addWidget(self._build_live_logs_card(), 1, 1)
        grid.addWidget(self._build_recommendation_card(), 2, 0, 1, 2)
        grid.addWidget(self._build_action_row(), 2, 2)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)
        grid.setColumnStretch(2, 1)
        grid.setRowStretch(0, 1)
        grid.setRowStretch(1, 1)
        grid.setRowStretch(2, 0)
        root.addLayout(grid, stretch=1)

    def on_enter(self) -> None:
        self._animate_intro()

    def _build_header(self) -> QHBoxLayout:
        header = QHBoxLayout()
        header.setSpacing(12)

        title_group = QVBoxLayout()
        title_group.setSpacing(2)

        title = QLabel("Scan Device", self)
        title.setObjectName("scanTitle")
        subtitle = QLabel("Inspect USB files, risk, and next actions.", self)
        subtitle.setObjectName("scanSubtitle")
        subtitle.setWordWrap(True)

        title_group.addWidget(title)
        title_group.addWidget(subtitle)
        header.addLayout(title_group)
        header.addStretch(1)
        header.addWidget(StatusChip("Ready", "neutral", self))
        return header

    def _build_progress_section(self) -> GlassCard:
        card = GlassCard(self)
        card.layout.setSpacing(10)
        top = QHBoxLayout()
        top.setSpacing(12)

        title_group = QVBoxLayout()
        title_group.setSpacing(4)
        title = QLabel("Progress Section", self)
        title.setObjectName("cardTitle")
        status = QLabel("Awaiting device scan", self)
        status.setObjectName("cardBody")
        title_group.addWidget(title)
        title_group.addWidget(status)

        percent = QLabel("0%", self)
        percent.setObjectName("scanMetric")

        top.addLayout(title_group, stretch=1)
        top.addWidget(percent)

        progress = GlassProgressBar(self)
        progress.setValue(0)

        card.layout.addLayout(top)
        card.layout.addWidget(progress)
        return card

    def _build_device_info_card(self) -> GlassCard:
        card = self._card("Device Information")
        rows = [
            ("Name", "No device selected"),
            ("Type", "USB storage"),
            ("Capacity", "--"),
            ("Mount", "--"),
        ]
        for label, value in rows:
            card.layout.addWidget(self._info_row(label, value))
        return card

    def _build_file_statistics_card(self) -> GlassCard:
        card = self._card("File Statistics")
        stats = [
            ("Files scanned", "0"),
            ("Folders checked", "0"),
            ("Skipped files", "0"),
            ("Encrypted files", "0"),
        ]
        for label, value in stats:
            card.layout.addWidget(self._info_row(label, value))
        return card

    def _build_threat_detection_card(self) -> GlassCard:
        card = self._card("Threat Detection")
        meter = RiskMeter(0, self)
        meter.setMaximumSize(118, 118)
        card.layout.addWidget(meter)
        card.layout.addWidget(StatusChip("No threats detected", "success", self))
        card.layout.addWidget(self._body("Threat results will update here."))
        return card

    def _build_live_logs_card(self) -> GlassCard:
        card = self._card("Live Logs")
        logs = [
            "Scanner initialized",
            "Waiting for scan request",
            "No files queued",
        ]
        for line in logs:
            card.layout.addWidget(self._log_row(line))
        card.layout.addStretch(1)
        return card

    def _build_recommendation_card(self) -> GlassCard:
        card = self._card("Recommendation Card")
        card.layout.addWidget(StatusChip("Recommended", "neutral", self))
        card.layout.addWidget(
            self._body("Run a scan before opening files from unknown devices.")
        )
        return card

    def _build_action_row(self) -> GlassCard:
        card = GlassCard(self)
        card.layout.setSpacing(10)
        actions = QVBoxLayout()
        actions.setSpacing(8)
        actions.addWidget(SecondaryButton("Export Report", self))
        actions.addWidget(DangerButton("Quarantine", self))
        actions.addWidget(PrimaryButton("Scan Again", self))
        card.layout.addLayout(actions)
        return card

    def _card(self, title: str) -> GlassCard:
        card = GlassCard(self)
        card.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        card.layout.setContentsMargins(16, 14, 16, 14)
        card.layout.setSpacing(8)
        label = QLabel(title, self)
        label.setObjectName("cardTitle")
        card.layout.addWidget(label)
        return card

    def _info_row(self, label: str, value: str) -> QWidget:
        row = QWidget(self)
        row.setObjectName("scanInfoRow")
        layout = QHBoxLayout(row)
        layout.setContentsMargins(8, 6, 8, 6)
        layout.setSpacing(10)

        name = QLabel(label, row)
        name.setObjectName("scanInfoLabel")
        data = QLabel(value, row)
        data.setObjectName("scanInfoValue")
        data.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

        layout.addWidget(name)
        layout.addStretch(1)
        layout.addWidget(data)
        return row

    def _log_row(self, text: str) -> QLabel:
        label = QLabel(text, self)
        label.setObjectName("scanLogRow")
        label.setMinimumHeight(28)
        return label

    def _body(self, text: str) -> QLabel:
        label = QLabel(text, self)
        label.setObjectName("cardBody")
        label.setWordWrap(True)
        return label

    def _animate_intro(self) -> None:
        self._intro_animations.clear()
        delay = 0
        animated_widgets = [*self.findChildren(GlassCard), *self.findChildren(AnimatedDeviceViewer)]
        for child in animated_widgets:
            child.setWindowOpacity(0.0)
            animation = QPropertyAnimation(child, b"windowOpacity", self)
            animation.setDuration(460)
            animation.setStartValue(0.0)
            animation.setEndValue(1.0)
            animation.setEasingCurve(QEasingCurve.Type.OutCubic)
            QTimer.singleShot(delay, animation.start)
            self._intro_animations.append(animation)
            delay += 65
