#!/usr/bin/env python3
"""
Utility functions and constants for the email investigator.
"""

import json
import datetime
from pathlib import Path
from PyQt5.QtWidgets import QMessageBox


class Constants:
    """Application constants."""

    # UI Constants
    WINDOW_TITLE = "E-mail Investigator - Forensic Edition"
    WINDOW_WIDTH = 1400
    WINDOW_HEIGHT = 900

    # File Constants
    SUPPORTED_EXTENSIONS = ['.eml']
    MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB

    # Analysis Constants
    SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.top', '.click', '.download']
    COMMON_EMAIL_PROVIDERS = [
        'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com',
        'icloud.com', 'aol.com', 'protonmail.com', 'tutanota.com'
    ]

    # Time Constants
    MAX_EMAIL_AGE_DAYS = 365 * 5  # 5 years
    MAX_RECEIVED_HEADERS = 10

    # Security Constants
    TRACKING_KEYWORDS = [
        'keylogger', 'spyware', 'monitor', 'surveillance', 'tracking',
        'beacon', 'analytics', 'telemetry', 'fingerprint', 'web bug'
    ]

    TRACKING_PARAMS = [
        'utm_', 'ga_', 'fbclid', 'gclid', 'msclkid', 'mc_eid',
        'tracking_id', 'track_id', 'user_id', 'session_id'
    ]


class ReportExporter:
    """Handles exporting forensic reports."""

    @staticmethod
    def export_json_report(data: dict, filepath: str, parent=None):
        """Export forensic analysis data as JSON report."""
        try:
            # Add metadata
            report = {
                "forensic_report": {
                    "generated_at": datetime.datetime.now().isoformat(),
                    "generator": Constants.WINDOW_TITLE,
                    **data
                }
            }

            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)

            if parent:
                QMessageBox.information(
                    parent,
                    "Export Complete",
                    f"Forensic report saved to:\n{filepath}"
                )

            return True

        except Exception as exc:
            if parent:
                QMessageBox.critical(
                    parent,
                    "Export Error",
                    f"Failed to export report:\n{str(exc)}"
                )
            return False


class FileValidator:
    """Validates email files."""

    @staticmethod
    def validate_email_file(filepath: str) -> tuple:
        """
        Validate an email file.

        Returns:
            tuple: (is_valid, error_message)
        """
        if not filepath:
            return False, "No file path provided"

        path = Path(filepath)

        # Check if file exists
        if not path.exists():
            return False, "File does not exist"

        # Check file extension
        if path.suffix.lower() not in Constants.SUPPORTED_EXTENSIONS:
            return False, f"Unsupported file extension: {path.suffix}"

        # Check file size
        try:
            file_size = path.stat().st_size
            if file_size > Constants.MAX_FILE_SIZE:
                return False, f"File too large: {file_size} bytes (max: {Constants.MAX_FILE_SIZE})"
            if file_size == 0:
                return False, "File is empty"
        except OSError as e:
            return False, f"Cannot access file: {str(e)}"

        return True, ""


class MessageBoxHelper:
    """Helper for displaying common message boxes."""

    @staticmethod
    def show_error(parent, title: str, message: str):
        """Show error message box."""
        QMessageBox.critical(parent, title, message)

    @staticmethod
    def show_warning(parent, title: str, message: str):
        """Show warning message box."""
        QMessageBox.warning(parent, title, message)

    @staticmethod
    def show_info(parent, title: str, message: str):
        """Show information message box."""
        QMessageBox.information(parent, title, message)

    @staticmethod
    def show_question(parent, title: str, message: str) -> bool:
        """Show question dialog and return user's choice."""
        reply = QMessageBox.question(
            parent, title, message,
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        return reply == QMessageBox.Yes
