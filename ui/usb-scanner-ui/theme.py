from PyQt6.QtCore import QObject, pyqtSignal

COLORS_DARK = {
    'bg': '#07080d',
    'glass_bg': 'rgba(20, 24, 38, 180)',
    'glass_border': 'rgba(0, 229, 255, 40)',
    'accent': '#00e5ff',
    'text_primary': '#ffffff',
    'text_secondary': '#8f9cae',
    'btn_bg': 'rgba(255, 255, 255, 12)',
    'btn_hover': 'rgba(0, 229, 255, 50)',
}

COLORS_LIGHT = {
    'bg': '#f0f4f8',
    'glass_bg': 'rgba(255, 255, 255, 200)',
    'glass_border': 'rgba(0, 180, 216, 50)',
    'accent': '#00b4d8',
    'text_primary': '#0f172a',
    'text_secondary': '#475569',
    'btn_bg': 'rgba(15, 23, 42, 10)',
    'btn_hover': 'rgba(0, 180, 216, 40)',
}

class ThemeManager(QObject):
    theme_changed = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.current_theme = "dark"

    def get_color(self, name):
        colors = COLORS_DARK if self.current_theme == "dark" else COLORS_LIGHT
        return colors.get(name, '#ffffff')

    def set_theme(self, theme_name):
        if theme_name in ["dark", "light"] and self.current_theme != theme_name:
            self.current_theme = theme_name
            self.theme_changed.emit(theme_name)

    @property
    def colors(self):
        return COLORS_DARK if self.current_theme == "dark" else COLORS_LIGHT

theme_manager = ThemeManager()
