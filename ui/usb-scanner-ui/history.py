from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QScrollArea, QFrame
from PyQt6.QtCore import Qt
from theme import theme_manager
from widgets import GlassCard, StatusBadge, draw_category_vector_icon
from PyQt6.QtGui import QPainter, QColor, QFont, QPen

class HistoryItemWidget(QFrame):
    def __init__(self, device, timestamp, status, parent=None):
        super().__init__(parent)
        self.device = device
        self.setFixedHeight(64)
        
        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 8, 14, 8)
        layout.setSpacing(12)
        
        # We draw the icon in a custom painter box on the left
        self.icon_box = QWidget()
        self.icon_box.setFixedSize(40, 40)
        self.icon_box.paintEvent = self.paint_icon
        
        info_layout = QVBoxLayout()
        info_layout.setSpacing(2)
        
        self.lbl_name = QLabel(device['name'])
        self.lbl_name.setStyleSheet(f"color: {theme_manager.get_color('text_primary')}; font-family: 'Inter'; font-weight: 700; font-size: 13px; background: transparent; border: none;")
        self.lbl_meta = QLabel(f"VID: {device['vid']} | PID: {device['pid']} | {timestamp}")
        self.lbl_meta.setStyleSheet(f"color: {theme_manager.get_color('text_secondary')}; font-family: 'Inter'; font-size: 11px; background: transparent; border: none;")
        
        info_layout.addWidget(self.lbl_name)
        info_layout.addWidget(self.lbl_meta)
        
        badge_color = "#00e5ff" if status == "ALLOWED" else "#ff1744"
        self.badge = StatusBadge(status, badge_color)
        
        layout.addWidget(self.icon_box)
        layout.addLayout(info_layout, 1)
        layout.addWidget(self.badge)
        
        self.update_style()
        theme_manager.theme_changed.connect(self.update_style)

    def paint_icon(self, event):
        painter = QPainter(self.icon_box)
        draw_category_vector_icon(painter, self.device['category'], 0, 0, 40)

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
        self.lbl_name.setStyleSheet(f"color: {theme_manager.get_color('text_primary')}; font-family: 'Inter'; font-weight: 700; font-size: 13px; background: transparent; border: none;")
        self.lbl_meta.setStyleSheet(f"color: {theme_manager.get_color('text_secondary')}; font-family: 'Inter'; font-size: 11px; background: transparent; border: none;")

class HistoryPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)
        
        # Header
        lbl_welcome = QLabel("ENDPOINT ACTIVITY LOGS")
        lbl_welcome.setStyleSheet(f"color: {theme_manager.get_color('text_secondary')}; font-size: 11px; font-weight: 800; font-family: 'Inter'; letter-spacing: 1.5px;")
        self.lbl_status = QLabel("System Incident History")
        self.lbl_status.setStyleSheet(f"color: {theme_manager.get_color('text_primary')}; font-size: 24px; font-weight: 800; font-family: 'Inter';")
        
        layout.addWidget(lbl_welcome)
        layout.addWidget(self.lbl_status)
        
        # Log Panel
        self.card = GlassCard()
        card_layout = QVBoxLayout(self.card)
        card_layout.setContentsMargins(16, 16, 16, 16)
        card_layout.setSpacing(10)
        
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setFrameShape(QFrame.Shape.NoFrame)
        self.scroll_area.setStyleSheet("background: transparent;")
        
        self.scroll_content = QWidget()
        self.scroll_content.setStyleSheet("background: transparent;")
        self.scroll_layout = QVBoxLayout(self.scroll_content)
        self.scroll_layout.setContentsMargins(0, 0, 0, 0)
        self.scroll_layout.setSpacing(8)
        self.scroll_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        
        self.scroll_area.setWidget(self.scroll_content)
        card_layout.addWidget(self.scroll_area)
        
        layout.addWidget(self.card, 1)
        
        # Seed initial historic records
        self.add_log_entry({
            "name": "Kingston DataTraveler",
            "category": "USB Flash Drive",
            "vid": "0x0930",
            "pid": "0x6545"
        }, "2026-07-02 22:15:30", "ALLOWED")
        
        self.add_log_entry({
            "name": "Logitech MX Master 3",
            "category": "USB Mouse",
            "vid": "0x046D",
            "pid": "0xC52B"
        }, "2026-07-02 21:04:12", "ALLOWED")
        
        self.add_log_entry({
            "name": "Anomalous Keystroke Payload USB",
            "category": "USB Keyboard",
            "vid": "0x04D9",
            "pid": "0x1702"
        }, "2026-07-02 18:22:45", "BLOCKED")
        
        theme_manager.theme_changed.connect(self.update_styles)

    def update_styles(self):
        self.lbl_status.setStyleSheet(f"color: {theme_manager.get_color('text_primary')}; font-size: 24px; font-weight: 800; font-family: 'Inter';")

    def add_log_entry(self, device, timestamp, status):
        widget = HistoryItemWidget(device, timestamp, status)
        self.scroll_layout.insertWidget(0, widget) # New logs at top
