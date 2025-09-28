#!/usr/bin/env python3
"""
UI components for the email investigator application.
"""

from PyQt5.QtWidgets import (QDialog, QLineEdit, QPlainTextEdit, QFormLayout,
                             QDialogButtonBox, QVBoxLayout)
from PyQt5.QtCore import Qt


class ChainOfCustodyDialog(QDialog):
    """Dialog for documenting chain of custody information."""

    def __init__(self, parent=None, current_data=None):
        super().__init__(parent)
        self.setWindowTitle("Chain of Custody Documentation")
        self.setModal(True)
        self.resize(500, 400)

        layout = QVBoxLayout(self)

        # Form layout for input fields
        form_layout = QFormLayout()

        self.analyst_edit = QLineEdit()
        self.case_number_edit = QLineEdit()
        self.exhibit_number_edit = QLineEdit()
        self.seal_number_edit = QLineEdit()
        self.notes_edit = QPlainTextEdit()

        form_layout.addRow("Analyst Name:", self.analyst_edit)
        form_layout.addRow("Case Number:", self.case_number_edit)
        form_layout.addRow("Exhibit Number:", self.exhibit_number_edit)
        form_layout.addRow("Seal Number:", self.seal_number_edit)
        form_layout.addRow("Notes:", self.notes_edit)

        layout.addLayout(form_layout)

        # Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

        # Load current data if provided
        if current_data:
            self.analyst_edit.setText(current_data.get('analyst', ''))
            self.case_number_edit.setText(current_data.get('case_number', ''))
            self.exhibit_number_edit.setText(current_data.get('exhibit_number', ''))
            self.seal_number_edit.setText(current_data.get('seal_number', ''))
            self.notes_edit.setPlainText(current_data.get('notes', ''))

    def get_data(self):
        """Get the entered chain of custody data."""
        return {
            'analyst': self.analyst_edit.text(),
            'case_number': self.case_number_edit.text(),
            'exhibit_number': self.exhibit_number_edit.text(),
            'seal_number': self.seal_number_edit.text(),
            'notes': self.notes_edit.toPlainText()
        }
