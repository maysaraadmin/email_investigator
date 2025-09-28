#!/usr/bin/env python3
"""
Anti-forensics detection and analysis module.
"""

import re
import datetime
import email.utils
from ..core import extract_urls, detect_time_anomalies


class AntiForensicsAnalyzer:
    """Detects anti-forensics techniques and indicators."""

    def __init__(self, message, body_text: str = None):
        self.message = message
        self.body_text = body_text or ""
        self.detections = []

    def analyze(self) -> list:
        """Perform comprehensive anti-forensics analysis."""
        self.detections = []

        # Header manipulation checks
        self.detections.extend(self._check_header_manipulation())

        # Timestamp manipulation checks
        self.detections.extend(self._check_timestamp_manipulation())

        # Content obfuscation checks
        self.detections.extend(self._check_content_obfuscation())

        # Tracking indicators
        self.detections.extend(self._check_tracking_indicators())

        # Metadata removal indicators
        self.detections.extend(self._check_metadata_removal())

        return self.detections

    def _check_header_manipulation(self) -> list:
        """Check for header manipulation and anti-forensics indicators."""
        checks = []

        # Check for missing or unusual headers
        essential_headers = ['Date', 'From', 'To', 'Subject', 'Message-ID']
        missing_headers = [h for h in essential_headers if not self.message.get(h)]

        if missing_headers:
            checks.append({
                'type': 'Header Manipulation',
                'severity': 'WARNING',
                'indicator': 'Missing Essential Headers',
                'details': f'Missing headers: {", ".join(missing_headers)}'
            })

        # Check for excessive Received headers (potential routing obfuscation)
        received_headers = self.message.get_all('Received', [])
        if len(received_headers) > 10:
            checks.append({
                'type': 'Header Manipulation',
                'severity': 'SUSPICIOUS',
                'indicator': 'Excessive Received Headers',
                'details': f'Found {len(received_headers)} Received headers (potential routing obfuscation)'
            })

        # Check for unusual X-Headers that might indicate anti-forensics tools
        x_headers = [k for k in self.message.keys() if k.startswith('X-')]
        suspicious_x_headers = [h for h in x_headers if any(keyword in h.lower() for keyword in
                                ['track', 'spy', 'hide', 'anon', 'proxy', 'vpn', 'tor'])]

        if suspicious_x_headers:
            checks.append({
                'type': 'Header Manipulation',
                'severity': 'SUSPICIOUS',
                'indicator': 'Suspicious X-Headers',
                'details': f'Found suspicious X-Headers: {", ".join(suspicious_x_headers)}'
            })

        # Check for header inconsistencies
        from_header = self.message.get('From', '')
        reply_to = self.message.get('Reply-To', '')
        if reply_to and from_header.lower() != reply_to.lower():
            checks.append({
                'type': 'Header Manipulation',
                'severity': 'SUSPICIOUS',
                'indicator': 'From/Reply-To Mismatch',
                'details': f'From: {from_header}, Reply-To: {reply_to}'
            })

        return checks

    def _check_timestamp_manipulation(self) -> list:
        """Check for timestamp manipulation and anti-forensics indicators."""
        checks = []

        # Check for missing Date header
        date_header = self.message.get('Date')
        if not date_header:
            checks.append({
                'type': 'Timestamp Manipulation',
                'severity': 'WARNING',
                'indicator': 'Missing Date Header',
                'details': 'No Date header found (potential timestamp removal)'
            })
            return checks

        # Check for future-dated emails
        try:
            email_date = email.utils.parsedate_to_datetime(date_header)
            current_time = datetime.datetime.now(datetime.timezone.utc)

            if email_date > current_time + datetime.timedelta(hours=1):
                checks.append({
                    'type': 'Timestamp Manipulation',
                    'severity': 'SUSPICIOUS',
                    'indicator': 'Future-Dated Email',
                    'details': f'Email date {email_date} is in the future (current: {current_time})'
                })

            # Check for very old emails (potential backdating)
            if email_date < current_time - datetime.timedelta(days=365*5):  # 5 years
                checks.append({
                    'type': 'Timestamp Manipulation',
                    'severity': 'SUSPICIOUS',
                    'indicator': 'Extremely Old Email',
                    'details': f'Email date {email_date} is extremely old (potential backdating)'
                })

        except Exception as e:
            checks.append({
                'type': 'Timestamp Manipulation',
                'severity': 'WARNING',
                'indicator': 'Invalid Date Format',
                'details': f'Date header parsing failed: {str(e)}'
            })

        # Check for inconsistent timestamps in Received headers
        received_headers = self.message.get_all('Received', [])
        if len(received_headers) > 1:
            try:
                from ..core import parse_received_headers
                timestamps = []
                for received in received_headers:
                    parsed = parse_received_headers([received])[0]
                    if parsed['timestamp']:
                        recv_time = email.utils.parsedate_to_datetime(parsed['timestamp'])
                        timestamps.append(recv_time)

                # Check if timestamps are in chronological order
                for i in range(1, len(timestamps)):
                    if timestamps[i] < timestamps[i-1]:
                        checks.append({
                            'type': 'Timestamp Manipulation',
                            'severity': 'SUSPICIOUS',
                            'indicator': 'Timestamp Inconsistency',
                            'details': 'Received headers show non-chronological timestamps (potential manipulation)'
                        })
                        break

            except Exception:
                pass  # Timestamp parsing failed

        return checks

    def _check_content_obfuscation(self) -> list:
        """Check for content obfuscation techniques."""
        checks = []

        # Check for excessive encoding/obfuscation in body
        if not self.body_text:
            return checks

        # Check for excessive base64 encoding in text
        base64_pattern = r'[A-Za-z0-9+/=]{40,}'
        base64_matches = re.findall(base64_pattern, self.body_text)
        if len(base64_matches) > 3:
            checks.append({
                'type': 'Content Obfuscation',
                'severity': 'SUSPICIOUS',
                'indicator': 'Excessive Base64 Encoding',
                'details': f'Found {len(base64_matches)} potential base64 encoded strings (possible obfuscation)'
            })

        # Check for hexadecimal encoding
        hex_pattern = r'[0-9a-fA-F]{8,}'
        hex_matches = re.findall(hex_pattern, self.body_text)
        if len(hex_matches) > 5:
            checks.append({
                'type': 'Content Obfuscation',
                'severity': 'SUSPICIOUS',
                'indicator': 'Excessive Hexadecimal Content',
                'details': f'Found {len(hex_matches)} potential hexadecimal strings (possible obfuscation)'
            })

        # Check for unusual character sets
        for part in self.message.walk():
            if part.get_content_type().startswith('text/'):
                charset = part.get_content_charset()
                if charset and charset.lower() in ['utf-7', 'utf-32', 'iso-2022-jp', 'iso-2022-kr']:
                    checks.append({
                        'type': 'Content Obfuscation',
                        'severity': 'SUSPICIOUS',
                        'indicator': 'Unusual Character Set',
                        'details': f'Part uses unusual character set: {charset} (potential obfuscation)'
                    })

        # Check for excessive whitespace or formatting anomalies
        # Check for excessive line breaks
        line_breaks = self.body_text.count('\n')
        if line_breaks > len(self.body_text) / 10:  # More than 10% line breaks
            checks.append({
                'type': 'Content Obfuscation',
                'severity': 'SUSPICIOUS',
                'indicator': 'Excessive Line Breaks',
                'details': f'Found {line_breaks} line breaks (potential formatting obfuscation)'
            })

        # Check for unusual spacing patterns
        if re.search(r'[\s]{5,}', self.body_text):
            checks.append({
                'type': 'Content Obfuscation',
                'severity': 'SUSPICIOUS',
                'indicator': 'Unusual Spacing Patterns',
                'details': 'Found excessive whitespace patterns (potential steganography or obfuscation)'
            })

        return checks

    def _check_tracking_indicators(self) -> list:
        """Check for tracking and surveillance indicators."""
        checks = []

        # Check for tracking pixels
        tracking_pixel_patterns = [
            r'track\.(gif|png|jpg)',
            r'pixel\.(gif|png|jpg)',
            r'beacon\.(gif|png|jpg)',
            r'open\.(gif|png|jpg)',
            r'\d+x\d+\.gif',
            r'1x1\.(gif|png|jpg)'
        ]

        for pattern in tracking_pixel_patterns:
            if re.search(pattern, self.body_text, re.IGNORECASE):
                checks.append({
                    'type': 'Tracking Indicators',
                    'severity': 'SUSPICIOUS',
                    'indicator': 'Tracking Pixel Detected',
                    'details': f'Found potential tracking pixel pattern: {pattern}'
                })
                break

        # Check for tracking parameters in URLs
        tracking_params = [
            'utm_', 'ga_', 'fbclid', 'gclid', 'msclkid', 'mc_eid',
            'tracking_id', 'track_id', 'user_id', 'session_id'
        ]

        urls = extract_urls(self.body_text)
        for url in urls:
            for param in tracking_params:
                if param in url.lower():
                    checks.append({
                        'type': 'Tracking Indicators',
                        'severity': 'SUSPICIOUS',
                        'indicator': 'Tracking Parameters',
                        'details': f'Found tracking parameter {param} in URL: {url[:50]}...'
                    })
                    break

        # Check for surveillance-related keywords
        surveillance_keywords = [
            'keylogger', 'spyware', 'monitor', 'surveillance', 'tracking',
            'beacon', 'analytics', 'telemetry', 'fingerprint', 'web bug'
        ]

        for keyword in surveillance_keywords:
            if keyword.lower() in self.body_text.lower():
                checks.append({
                    'type': 'Tracking Indicators',
                    'severity': 'SUSPICIOUS',
                    'indicator': 'Surveillance Keywords',
                    'details': f'Found surveillance-related keyword: {keyword}'
                })

        # Check for email read receipts
        if self.message.get('Disposition-Notification-To') or self.message.get('Return-Receipt-To'):
            checks.append({
                'type': 'Tracking Indicators',
                'severity': 'INFO',
                'indicator': 'Read Receipt Request',
                'details': 'Email requests read receipt (tracking mechanism)'
            })

        return checks

    def _check_metadata_removal(self) -> list:
        """Check for indicators of metadata removal or sanitization."""
        checks = []

        # Check for missing User-Agent header (common in sanitized emails)
        user_agent = self.message.get('User-Agent')
        if not user_agent:
            checks.append({
                'type': 'Metadata Removal',
                'severity': 'INFO',
                'indicator': 'Missing User-Agent',
                'details': 'No User-Agent header found (possible metadata removal)'
            })

        # Check for generic User-Agent strings
        generic_agents = ['Mozilla/5.0', 'Mozilla/4.0']
        if user_agent and any(agent in user_agent for agent in generic_agents):
            if len(user_agent) < 30:  # Very generic User-Agent
                checks.append({
                    'type': 'Metadata Removal',
                    'severity': 'INFO',
                    'indicator': 'Generic User-Agent',
                    'details': f'Generic User-Agent: {user_agent} (possible sanitization)'
                })

        # Check for missing X-Mailer header
        x_mailer = self.message.get('X-Mailer')
        if not x_mailer:
            checks.append({
                'type': 'Metadata Removal',
                'severity': 'INFO',
                'indicator': 'Missing X-Mailer',
                'details': 'No X-Mailer header found (possible metadata removal)'
            })

        # Check for missing organization headers
        org_headers = ['Organization', 'X-Originating-IP', 'X-Mailer-Version']
        missing_org = [h for h in org_headers if not self.message.get(h)]
        if len(missing_org) >= 2:  # Multiple missing org headers
            checks.append({
                'type': 'Metadata Removal',
                'severity': 'INFO',
                'indicator': 'Missing Organization Headers',
                'details': f'Missing organization headers: {", ".join(missing_org)} (possible sanitization)'
            })

        # Check for suspiciously clean headers
        all_headers = list(self.message.keys())
        if len(all_headers) < 8:  # Very few headers
            checks.append({
                'type': 'Metadata Removal',
                'severity': 'INFO',
                'indicator': 'Minimal Header Set',
                'details': f'Only {len(all_headers)} headers found (possible header sanitization)'
            })

        return checks

    def get_detections_by_severity(self, severity: str) -> list:
        """Get detections filtered by severity level."""
        return [d for d in self.detections if d['severity'] == severity]

    def get_detections_by_type(self, detection_type: str) -> list:
        """Get detections filtered by type."""
        return [d for d in self.detections if d['type'] == detection_type]
