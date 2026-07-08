import sys
from PyQt6.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QStackedWidget
from PyQt6.QtCore import Qt, QDateTime
from theme import theme_manager
from navigation import BottomNavigationBar
from dashboard import DashboardPage
from scan_page import ScanPage
from history import HistoryPage
from settings import SettingsPage
from backend_manager import BackendManager

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("USB Security Detector && Terminal Sandbox")
        self.resize(800, 600)
        
        # Central Widget & Main Layout
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        
        self.main_layout = QVBoxLayout(self.central_widget)
        self.main_layout.setContentsMargins(16, 16, 16, 16)
        self.main_layout.setSpacing(16)
        
        # Pages Stack
        self.pages_stack = QStackedWidget()
        
        self.page_dashboard = DashboardPage()
        self.page_scan = ScanPage()
        self.page_history = HistoryPage()
        self.page_settings = SettingsPage()
        
        self.pages_stack.addWidget(self.page_dashboard)
        self.pages_stack.addWidget(self.page_scan)
        self.pages_stack.addWidget(self.page_history)
        self.pages_stack.addWidget(self.page_settings)
        
        # Backend Connection
        self.backend = BackendManager()
        self.page_dashboard.set_backend(self.backend)
        self.page_scan.set_backend(self.backend)
        
        # Bottom Navigation
        self.nav_bar = BottomNavigationBar()
        
        # Center the navigation bar inside a layout with flexible spacers
        self.nav_container_layout = QHBoxLayout()
        self.nav_container_layout.setContentsMargins(0, 0, 0, 0)
        self.nav_container_layout.addStretch(1)
        self.nav_container_layout.addWidget(self.nav_bar)
        self.nav_container_layout.addStretch(1)
        
        self.main_layout.addWidget(self.pages_stack, 1)
        self.main_layout.addLayout(self.nav_container_layout)
        
        # Connect navigation switching with transition animation
        self.nav_bar.tab_changed.connect(self.switch_page)
        
        # Connect functional bridges between pages
        self.page_dashboard.device_authorized.connect(self.log_device_authorized)
        self.page_dashboard.device_blocked.connect(self.log_device_blocked)
        self.page_scan.scan_completed.connect(self.page_dashboard.on_scan_completed)
        
        self.update_theme_styles()
        theme_manager.theme_changed.connect(self.update_theme_styles)
        
        # Start Backend Server
        self.backend.start_backend()

    def switch_page(self, idx):
        target_page = self.pages_stack.widget(idx)
        self.pages_stack.setCurrentIndex(idx)
        
        try:
            from animations import setup_fade_in_animation
            # Trigger standard smooth fade-in entrance transition
            self._fade_anim, self._opacity_effect = setup_fade_in_animation(target_page, 250)
            self._fade_anim.finished.connect(lambda: target_page.setGraphicsEffect(None))
            self._fade_anim.start()
        except (ImportError, ModuleNotFoundError):
            # Fallback if animations.py is not available in the user's workspace
            from PyQt6.QtWidgets import QGraphicsOpacityEffect
            from PyQt6.QtCore import QPropertyAnimation, QEasingCurve
            
            opacity_effect = QGraphicsOpacityEffect(target_page)
            target_page.setGraphicsEffect(opacity_effect)
            
            self._fade_anim = QPropertyAnimation(opacity_effect, b"opacity")
            self._fade_anim.setDuration(250)
            self._fade_anim.setStartValue(0.0)
            self._fade_anim.setEndValue(1.0)
            self._fade_anim.setEasingCurve(QEasingCurve.Type.InOutQuad)
            self._opacity_effect = opacity_effect
            self._fade_anim.finished.connect(lambda: target_page.setGraphicsEffect(None))
            self._fade_anim.start()

    def log_device_authorized(self, device):
        timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
        self.page_history.add_log_entry(device, timestamp, "ALLOWED")

    def log_device_blocked(self, device):
        timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
        self.page_history.add_log_entry(device, timestamp, "BLOCKED")

    def update_theme_styles(self):
        bg = theme_manager.get_color("bg")
        self.setStyleSheet(f"background-color: {bg};")

def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
