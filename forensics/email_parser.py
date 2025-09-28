#!/usr/bin/env python3
"""
Email parsing and analysis module.
"""

import email
from email import policy
from pathlib import Path
import hashlib
import datetime
from .core import hash_bytes, extract_urls, extract_email_addresses, extract_ip_addresses


class EmailParser:
    """Handles email parsing and basic analysis."""

    def __init__(self, raw_email_bytes: bytes):
        self.raw_email = raw_email_bytes
        self.message = None
        self.attachments = []
        self.body_parts = []
        self.metadata = {}

    def parse(self):
        """Parse the email message."""
        try:
            self.message = email.message_from_bytes(self.raw_email, policy=policy.default)
            self._extract_metadata()
            self._extract_attachments()
            self._extract_body_parts()
            return True
        except Exception as e:
            print(f"Error parsing email: {e}")
            return False

    def _extract_metadata(self):
        """Extract basic email metadata."""
        if not self.message:
            return

        self.metadata = {
            'headers': dict(self.message.items()),
            'from': self.message.get('From', ''),
            'to': self.message.get('To', ''),
            'subject': self.message.get('Subject', ''),
            'date': self.message.get('Date', ''),
            'message_id': self.message.get('Message-ID', ''),
            'content_type': self.message.get_content_type(),
            'is_multipart': self.message.is_multipart(),
        }

    def _extract_attachments(self):
        """Extract attachment information."""
        if not self.message:
            return

        self.attachments = []
        for part in self.message.walk():
            if part.get_content_disposition() == "attachment" or \
               (part.get_filename() and part.get_content_maintype() != "text"):
                name = part.get_filename() or "unnamed"
                ctype = part.get_content_type()
                data = part.get_payload(decode=True)
                if data is None:
                    continue
                size = len(data)
                md5 = hash_bytes(data, "md5")
                sha256 = hash_bytes(data, "sha256")

                self.attachments.append({
                    'name': name,
                    'content_type': ctype,
                    'size': size,
                    'md5': md5,
                    'sha256': sha256,
                    'data': data
                })

    def _extract_body_parts(self):
        """Extract body parts and their content."""
        if not self.message:
            return

        self.body_parts = []
        plain_text = ""
        html_text = ""

        for part in self.message.walk():
            if part.is_multipart():
                continue

            content_type = part.get_content_type()
            content = part.get_content()

            if content_type == "text/plain" and content:
                plain_text += content
            elif content_type == "text/html" and content:
                html_text += content

            # Store part information
            part_info = {
                'content_type': content_type,
                'content': content,
                'charset': part.get_content_charset() or 'unknown',
                'filename': part.get_filename(),
                'content_disposition': part.get('Content-Disposition', ''),
                'transfer_encoding': part.get('Content-Transfer-Encoding', 'unknown')
            }
            self.body_parts.append(part_info)

        # Store extracted text
        self.metadata['plain_text'] = plain_text
        self.metadata['html_text'] = html_text

    def get_all_text(self) -> str:
        """Get all text content from the email."""
        return self.metadata.get('plain_text', '') + ' ' + self.metadata.get('html_text', '')

    def get_iocs(self) -> dict:
        """Extract Indicators of Compromise from email."""
        all_text = self.get_all_text()

        return {
            'urls': extract_urls(all_text),
            'emails': extract_email_addresses(all_text),
            'ips': extract_ip_addresses(all_text)
        }

    def get_received_headers(self) -> list:
        """Get parsed received headers."""
        if not self.message:
            return []

        from .core import parse_received_headers
        received_headers = self.message.get_all("Received", [])
        return parse_received_headers(received_headers)

    def get_authentication_results(self) -> dict:
        """Get authentication results."""
        if not self.message:
            return {}

        from .core import parse_authentication_results, parse_dkim_signature

        auth_header = self.message.get("Authentication-Results", "")
        auth_results = parse_authentication_results(auth_header)

        dkim_header = self.message.get("DKIM-Signature", "")
        dkim_info = parse_dkim_signature(dkim_header)

        return {
            'authentication_results': auth_results,
            'dkim_signature': dkim_info
        }

    def get_message_id_analysis(self) -> dict:
        """Get Message-ID domain analysis."""
        if not self.message:
            return {}

        from .core import analyze_message_id_domain
        return analyze_message_id_domain(self.message)

    def get_time_anomalies(self) -> list:
        """Get time-related anomalies."""
        if not self.message:
            return []

        from .core import detect_time_anomalies
        date_header = self.message.get('Date')
        received_headers = self.get_received_headers()
        return detect_time_anomalies(date_header, received_headers)


class FileMetadata:
    """Handles file metadata for email files."""

    def __init__(self, filepath: str = None, raw_bytes: bytes = None):
        self.filepath = filepath
        self.raw_bytes = raw_bytes
        self.metadata = {}

    def extract_metadata(self):
        """Extract file metadata."""
        if not self.raw_bytes:
            return

        # Basic file info
        filename = Path(self.filepath).name if self.filepath else "unknown"
        filesize = len(self.raw_bytes)

        # Calculate hashes
        sha256 = hash_bytes(self.raw_bytes, "sha256")
        sha1 = hash_bytes(self.raw_bytes, "sha1")
        md5 = hash_bytes(self.raw_bytes, "md5")

        # Acquisition info
        acquisition_time = datetime.datetime.now().isoformat()
        acquisition_method = "file_open" if self.filepath else "clipboard"

        self.metadata = {
            'filename': filename,
            'filesize': filesize,
            'sha256': sha256,
            'sha1': sha1,
            'md5': md5,
            'acquisition_time': acquisition_time,
            'acquisition_method': acquisition_method,
            'chain_of_custody': {
                'analyst': None,
                'case_number': None,
                'exhibit_number': None,
                'seal_number': None,
                'notes': None,
                'custody_history': []
            }
        }

    def add_chain_of_custody(self, analyst: str, case_number: str,
                           exhibit_number: str, seal_number: str, notes: str):
        """Add chain of custody information."""
        self.metadata['chain_of_custody'].update({
            'analyst': analyst,
            'case_number': case_number,
            'exhibit_number': exhibit_number,
            'seal_number': seal_number,
            'notes': notes
        })

        # Add to custody history
        history_entry = {
            'timestamp': datetime.datetime.now().isoformat(),
            'action': 'custody_documented',
            'analyst': analyst,
            'case_number': case_number,
            'exhibit_number': exhibit_number
        }
        self.metadata['chain_of_custody']['custody_history'].append(history_entry)

    def get_metadata(self) -> dict:
        """Get all metadata."""
        return self.metadata
