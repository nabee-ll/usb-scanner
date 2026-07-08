from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QFrame, QButtonGroup
from PyQt6.QtCore import Qt
from theme import theme_manager
from widgets import GlassCard

class ToggleRow(QFrame):
    def __init__(self, title, description, parent=None):
        super().__init__(parent)
        self.setFixedHeight(64)
        
        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 8, 14, 8)
        
        text_layout = QVBoxLayout()
        text_layout.setSpacing(2)
        
        self.lbl_title = QLabel(title)
        self.lbl_title.setStyleSheet(f"color: {theme_manager.get_color('text_primary')}; font-family: 'Inter'; font-weight: 700; font-size: 13px; background: transparent; border: none;")
        self.lbl_desc = QLabel(description)
        self.lbl_desc.setStyleSheet(f"color: {theme_manager.get_color('text_secondary')}; font-family: 'Inter'; font-size: 11px; background: transparent; border: none;")
        
        text_layout.addWidget(self.lbl_title)
        text_layout.addWidget(self.lbl_desc)
        
        self.btn_toggle = QPushButton("ENABLED")
        self.btn_toggle.setCheckable(True)
        self.btn_toggle.setChecked(True)
        self.btn_toggle.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_toggle.setFixedSize(90, 32)
        self.btn_toggle.clicked.connect(self.on_clicked)
        
        layout.addLayout(text_layout, 1)
        layout.addWidget(self.btn_toggle)
        
        self.update_style()
        theme_manager.theme_changed.connect(self.update_style)

    def on_clicked(self):
        if self.btn_toggle.isChecked():
            self.btn_toggle.setText("ENABLED")
        else:
            self.btn_toggle.setText("DISABLED")
        self.update_style()

    def update_style(self):
        bg = "rgba(255, 255, 255, 6)" if theme_manager.current_theme == "dark" else "rgba(15, 23, 42, 6)"
        border = theme_manager.get_color("glass_border")
        self.setStyleSheet(f"""
            QFrame {{
                background-color: {bg};
                border: 0.5px solid {border};
                border-radius: 12px;
            }}
        """)
        self.lbl_title.setStyleSheet(f"color: {theme_manager.get_color('text_primary')}; font-family: 'Inter'; font-weight: 700; font-size: 13px; background: transparent; border: none;")
        self.lbl_desc.setStyleSheet(f"color: {theme_manager.get_color('text_secondary')}; font-family: 'Inter'; font-size: 11px; background: transparent; border: none;")
        
        accent = theme_manager.get_color("accent")
        text_color = "black" if theme_manager.current_theme == "dark" else "white"
        
        if self.btn_toggle.isChecked():
            self.btn_toggle.setStyleSheet(f"""
                QPushButton {{
                    background-color: {accent};
                    color: {text_color};
                    border-radius: 8px;
                    font-family: 'Inter';
                    font-weight: 800;
                    font-size: 11px;
                    border: none;
                }}
            """)
        else:
            self.btn_toggle.setStyleSheet(f"""
                QPushButton {{
                    background-color: rgba(120, 120, 120, 20);
                    color: {theme_manager.get_color('text_secondary')};
                    border-radius: 8px;
                    font-family: 'Inter';
                    font-weight: 800;
                    font-size: 11px;
                    border: 0.5px solid {theme_manager.get_color('glass_border')};
                }}
            """)

class SettingsPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)
        
        # Header
        lbl_welcome = QLabel("SYSTEM SYSTEM PREFERENCES")
        lbl_welcome.setStyleSheet(f"color: {theme_manager.get_color('text_secondary')}; font-size: 11px; font-weight: 800; font-family: 'Inter'; letter-spacing: 1.5px;")
        self.lbl_status = QLabel("Security settings")
        self.lbl_status.setStyleSheet(f"color: {theme_manager.get_color('text_primary')}; font-size: 24px; font-weight: 800; font-family: 'Inter';")
        
        layout.addWidget(lbl_welcome)
        layout.addWidget(self.lbl_status)
        
        # Settings list
        self.card = GlassCard()
        card_layout = QVBoxLayout(self.card)
        card_layout.setContentsMargins(16, 16, 16, 16)
        card_layout.setSpacing(12)
        
        # Theme Setting
        theme_row = QFrame()
        theme_row.setFixedHeight(64)
        bg = "rgba(255, 255, 255, 6)" if theme_manager.current_theme == "dark" else "rgba(15, 23, 42, 6)"
        theme_row.setStyleSheet(f"background-color: {bg}; border: 0.5px solid {theme_manager.get_color('glass_border')}; border-radius: 12px;")
        theme_layout = QHBoxLayout(theme_row)
        theme_layout.setContentsMargins(14, 8, 14, 8)
        
        lbl_t_title = QLabel("System Style Theme")
        lbl_t_title.setStyleSheet(f"color: {theme_manager.get_color('text_primary')}; font-family: 'Inter'; font-weight: 700; font-size: 13px; background: transparent; border: none;")
        lbl_t_desc = QLabel("Set preferred interface style.")
        lbl_t_desc.setStyleSheet(f"color: {theme_manager.get_color('text_secondary')}; font-family: 'Inter'; font-size: 11px; background: transparent; border: none;")
        
        t_text_layout = QVBoxLayout()
        t_text_layout.setSpacing(2)
        t_text_layout.addWidget(lbl_t_title)
        t_text_layout.addWidget(lbl_t_desc)
        theme_layout.addLayout(t_text_layout, 1)
        
        self.btn_dark = QPushButton("DARK")
        self.btn_dark.setCheckable(True)
        self.btn_light = QPushButton("LIGHT")
        self.btn_light.setCheckable(True)
        
        self.theme_group = QButtonGroup(self)
        self.theme_group.addButton(self.btn_dark)
        self.theme_group.addButton(self.btn_light)
        
        theme_btn_layout = QHBoxLayout()
        theme_btn_layout.setSpacing(6)
        theme_btn_layout.addWidget(self.btn_dark)
        theme_btn_layout.addWidget(self.btn_light)
        theme_layout.addLayout(theme_btn_layout)
        
        card_layout.addWidget(theme_row)
        
        # Toggles
        self.toggle_1 = ToggleRow("Automatic Port Isolation", "Quarantine anomalous USB targets instantly.")
        self.toggle_2 = ToggleRow("Electrical Overcurrent Monitor", "Identify power-surge signature vectors.")
        self.toggle_3 = ToggleRow("Keyboard Rate Throttling", "De-escalate rapid BadUSB physical emulation speeds.")
        self.toggle_4 = ToggleRow("Driver Sandbox Mode", "Launch system classes in container nodes.")
        
        card_layout.addWidget(self.toggle_1)
        card_layout.addWidget(self.toggle_2)
        card_layout.addWidget(self.toggle_3)
        card_layout.addWidget(self.toggle_4)
        
        layout.addWidget(self.card, 1)
        
        # Setup initial theme button checks
        if theme_manager.current_theme == "dark":
            self.btn_dark.setChecked(True)
        else:
            self.btn_light.setChecked(True)
            
        self.btn_dark.clicked.connect(lambda: theme_manager.set_theme("dark"))
        self.btn_light.clicked.connect(lambda: theme_manager.set_theme("light"))
        
        self.update_styles()
        theme_manager.theme_changed.connect(self.update_styles)

    def update_styles(self):
        self.lbl_status.setStyleSheet(f"color: {theme_manager.get_color('text_primary')}; font-size: 24px; font-weight: 800; font-family: 'Inter';")
        
        accent = theme_manager.get_color("accent")
        text_color = "black" if theme_manager.current_theme == "dark" else "white"
        
        for btn, name in [(self.btn_dark, "dark"), (self.btn_light, "light")]:
            if theme_manager.current_theme == name:
                btn.setStyleSheet(f"""
                    QPushButton {{
                        background-color: {accent};
                        color: {text_color};
                        border-radius: 8px;
                        font-family: 'Inter';
                        font-weight: 800;
                        font-size: 11px;
                        padding: 6px 14px;
                        border: none;
                    }}
                """)
            else:
                btn.setStyleSheet(f"""
                    QPushButton {{
                        background-color: rgba(120, 120, 120, 20);
                        color: {theme_manager.get_color('text_secondary')};
                        border-radius: 8px;
                        font-family: 'Inter';
                        font-weight: 800;
                        font-size: 11px;
                        padding: 6px 14px;
                        border: 0.5px solid {theme_manager.get_color('glass_border')};
                    }}
                """)
