#!/usr/bin/env python3
"""
UI styling and themes for the email investigator.
"""

from PyQt5.QtGui import QPalette, QColor, QFont
from PyQt5.QtCore import Qt


class ThemeManager:
    """Manages UI themes and styling."""

    @staticmethod
    def apply_dark_theme(app):
        """Apply a professional dark theme."""
        # Create dark palette
        dark_palette = QPalette()

        # Window colors
        dark_palette.setColor(QPalette.Window, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.WindowText, Qt.white)
        dark_palette.setColor(QPalette.Base, QColor(25, 25, 25))
        dark_palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ToolTipBase, Qt.white)
        dark_palette.setColor(QPalette.ToolTipText, Qt.black)
        dark_palette.setColor(QPalette.Text, Qt.white)
        dark_palette.setColor(QPalette.Button, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ButtonText, Qt.white)
        dark_palette.setColor(QPalette.BrightText, Qt.red)

        # Highlight colors
        dark_palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
        dark_palette.setColor(QPalette.HighlightedText, Qt.black)

        # Disabled colors
        dark_palette.setColor(QPalette.Disabled, QPalette.WindowText, QColor(128, 128, 128))
        dark_palette.setColor(QPalette.Disabled, QPalette.Text, QColor(128, 128, 128))
        dark_palette.setColor(QPalette.Disabled, QPalette.ButtonText, QColor(128, 128, 128))

        app.setPalette(dark_palette)

        # Set application-wide font
        app_font = QFont("Segoe UI", 9)
        app.setFont(app_font)

        # Apply dark theme to all widgets
        app.setStyle("Fusion")

    @staticmethod
    def get_button_style():
        """Get professional button styling."""
        return """
        QPushButton {
            background-color: #2A82DA;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            font-weight: bold;
        }
        QPushButton:hover {
            background-color: #1E6BB8;
        }
        QPushButton:pressed {
            background-color: #1A5A96;
        }
        QPushButton:disabled {
            background-color: #666666;
            color: #999999;
        }
        """

    @staticmethod
    def get_tree_style():
        """Get professional tree widget styling."""
        return """
        QTreeWidget {
            background-color: #2D2D2D;
            color: white;
            border: 1px solid #444444;
            border-radius: 4px;
        }
        QTreeWidget::item {
            padding: 4px;
        }
        QTreeWidget::item:selected {
            background-color: #2A82DA;
            color: white;
        }
        QTreeWidget::branch {
            background: transparent;
        }
        """

    @staticmethod
    def get_tab_style():
        """Get professional tab widget styling."""
        return """
        QTabWidget::pane {
            border: 1px solid #444444;
            background-color: #2D2D2D;
            border-radius: 4px;
        }
        QTabBar::tab {
            background-color: #404040;
            color: white;
            padding: 8px 16px;
            margin-right: 2px;
            border-top-left-radius: 4px;
            border-top-right-radius: 4px;
        }
        QTabBar::tab:selected {
            background-color: #2A82DA;
            color: white;
        }
        QTabBar::tab:hover:!selected {
            background-color: #505050;
        }
        """


class IconManager:
    """Manages icons for the application."""

    ICONS = {
        'open': '📂',
        'clipboard': '📋',
        'export': '📤',
        'custody': '🔗',
        'search': '🔍',
        'settings': '⚙️',
        'help': '❓',
        'warning': '⚠️',
        'error': '❌',
        'success': '✅',
        'info': 'ℹ️'
    }

    @staticmethod
    def get_icon(name):
        """Get icon for the given name."""
        return IconManager.ICONS.get(name, '•')
