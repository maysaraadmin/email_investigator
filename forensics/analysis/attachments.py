#!/usr/bin/env python3
"""
Advanced attachment analysis module.
"""

import hashlib
import io
from pathlib import Path
from ..core import (
    hash_tlsh, get_magic_bytes, extract_exif_data,
    detect_password_protection, analyze_ole_macros
)


class AttachmentAnalyzer:
    """Advanced analysis of email attachments."""

    def __init__(self, attachments: list):
        """
        Args:
            attachments: List of attachment dictionaries from EmailParser
        """
        self.attachments = attachments
        self.analysis_results = []

    def analyze_all(self) -> list:
        """Analyze all attachments."""
        self.analysis_results = []

        for attachment in self.attachments:
            analysis = self._analyze_attachment(attachment)
            self.analysis_results.append(analysis)

        return self.analysis_results

    def _analyze_attachment(self, attachment: dict) -> dict:
        """Analyze a single attachment."""
        filename = attachment['name']
        data = attachment['data']

        # Basic file info
        analysis = {
            'filename': filename,
            'size': attachment['size'],
            'content_type': attachment['content_type'],
            'md5': attachment['md5'],
            'sha256': attachment['sha256'],
        }

        # Magic bytes analysis
        magic_info = self._analyze_magic_bytes(data)
        analysis.update(magic_info)

        # Extension vs magic bytes comparison
        analysis['extension_match'] = self._check_extension_match(filename, data)

        # TLSH fuzzy hashing
        analysis['tlsh'] = hash_tlsh(data)

        # Password protection detection
        protection = detect_password_protection(data, filename)
        analysis.update(protection)

        # Macro analysis for Office files
        macro_analysis = analyze_ole_macros(data)
        analysis.update(macro_analysis)

        # EXIF data for images
        if filename.lower().endswith(('.jpg', '.jpeg', '.png', '.tiff', '.tif')):
            exif_data = extract_exif_data(data)
            analysis['exif_data'] = exif_data

        return analysis

    def _analyze_magic_bytes(self, data: bytes) -> dict:
        """Analyze magic bytes for file type detection."""
        detected_type = get_magic_bytes(data)

        return {
            'detected_type': detected_type,
            'magic_signature': None,
            'offset': 0
        }

    def _check_extension_match(self, filename: str, data: bytes) -> bool:
        """Check if file extension matches magic bytes."""
        if not filename or '.' not in filename:
            return True  # No extension to check

        extension = filename.split('.')[-1].lower()
        detected_type = get_magic_bytes(data).lower()

        # Extension mapping
        extension_map = {
            'zip': ['zip'],
            'pdf': ['pdf'],
            'exe': ['pe (windows exe/dll)'],
            'dll': ['pe (windows exe/dll)'],
            'doc': ['ole (ms office)'],
            'docx': ['zip'],  # DOCX is actually a ZIP file
            'xls': ['ole (ms office)'],
            'xlsx': ['zip'],  # XLSX is actually a ZIP file
            'ppt': ['ole (ms office)'],
            'pptx': ['zip'],  # PPTX is actually a ZIP file
            'png': ['png'],
            'jpg': ['jpeg'],
            'jpeg': ['jpeg'],
            'gif': ['gif'],
            'tiff': ['tiff'],
            'mp4': ['mp4'],
            'avi': ['riff (avi/wav)'],
            'wav': ['riff (avi/wav)', 'wav']
        }

        expected_types = extension_map.get(extension, [])

        if not expected_types:
            return True  # Unknown extension

        return any(expected_type in detected_type for expected_type in expected_types)

    def get_analysis_by_filename(self, filename: str) -> dict:
        """Get analysis results for a specific attachment."""
        for result in self.analysis_results:
            if result['filename'] == filename:
                return result
        return {}

    def get_suspicious_attachments(self) -> list:
        """Get attachments that have suspicious characteristics."""
        suspicious = []

        for result in self.analysis_results:
            suspicious_indicators = []

            # Check extension mismatch
            if not result.get('extension_match', True):
                suspicious_indicators.append('Extension mismatch')

            # Check password protection
            if result.get('is_protected', False):
                suspicious_indicators.append('Password protected')

            # Check macros
            if result.get('has_macros', False):
                suspicious_indicators.append('Contains macros')

            # Check for executable content disguised as documents
            if (result['detected_type'] in ['PE/EXE', 'ELF'] and
                not result['filename'].lower().endswith(('.exe', '.dll', '.elf'))):
                suspicious_indicators.append('Executable content in document')

            if suspicious_indicators:
                result_copy = result.copy()
                result_copy['suspicious_indicators'] = suspicious_indicators
                suspicious.append(result_copy)

        return suspicious
