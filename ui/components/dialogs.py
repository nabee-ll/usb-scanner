"""Modal dialog component with glass styling."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QDialog, QHBoxLayout, QLabel, QVBoxLayout, QWidget

from ui.components.buttons import PrimaryButton, SecondaryButton
from ui.components.effects import add_shadow


class ModalDialog(QDialog):
    """Reusable modal shell for confirmation and focused workflows."""

    def __init__(
        self,
        title: str,
        message: str = "",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("modalDialog")
        self.setWindowFlag(Qt.WindowType.FramelessWindowHint)
        self.setModal(True)
        self.setMinimumWidth(360)
        self.setMinimumHeight(180)

        self.title_label = QLabel(title, self)
        self.title_label.setObjectName("modalTitle")
        self.title_label.setWordWrap(True)

        self.message_label = QLabel(message, self)
        self.message_label.setObjectName("modalMessage")
        self.message_label.setWordWrap(True)

        self.cancel_button = SecondaryButton("Cancel", self)
        self.confirm_button = PrimaryButton("Confirm", self)
        self.cancel_button.clicked.connect(self.reject)
        self.confirm_button.clicked.connect(self.accept)

        actions = QHBoxLayout()
        actions.addStretch(1)
        actions.addWidget(self.cancel_button)
        actions.addWidget(self.confirm_button)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)
        layout.addWidget(self.title_label)
        layout.addWidget(self.message_label)
        layout.addStretch(1)
        layout.addLayout(actions)
        add_shadow(self, blur_radius=36, y_offset=16)
