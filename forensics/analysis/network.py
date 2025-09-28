#!/usr/bin/env python3
"""
Network pivot and intelligence analysis module.
"""

import re
import ipaddress
from urllib.parse import urlparse
from ..core import extract_urls, extract_email_addresses, extract_ip_addresses


class NetworkAnalyzer:
    """Analyzes network indicators and provides intelligence."""

    def __init__(self, message, body_text: str = None):
        self.message = message
        self.body_text = body_text or ""
        self.indicators = {
            'ips': set(),
            'domains': set(),
            'urls': set(),
            'email_domains': set()
        }
        self.analysis_results = []

    def extract_indicators(self):
        """Extract all network indicators from email."""
        self._extract_from_headers()
        self._extract_from_body()
        return self.indicators

    def _extract_from_headers(self):
        """Extract indicators from email headers."""
        # From header
        from_header = self.message.get('From', '')
        from_match = re.search(r'@([\w.-]+)', from_header)
        if from_match:
            self.indicators['email_domains'].add(from_match.group(1).lower())

        # Received headers
        received_headers = self.message.get_all('Received', [])
        for received in received_headers:
            # Extract IPs and domains from received headers
            ip_matches = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', received)
            self.indicators['ips'].update(ip_matches)

            domain_matches = re.findall(r'@([\w.-]+)', received)
            self.indicators['domains'].update(domain_matches)

            # Extract hostnames
            host_matches = re.findall(r'by\s+([\w.-]+)', received, re.IGNORECASE)
            self.indicators['domains'].update(host_matches)

        # X-Originating-IP
        x_orig_ip = self.message.get('X-Originating-IP', '')
        ip_matches = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', x_orig_ip)
        self.indicators['ips'].update(ip_matches)

    def _extract_from_body(self):
        """Extract indicators from email body."""
        if not self.body_text:
            return

        # Extract URLs
        urls = extract_urls(self.body_text)
        self.indicators['urls'].update(urls)

        # Extract domains from URLs
        for url in urls:
            try:
                parsed = urlparse(url)
                if parsed.netloc:
                    domain = parsed.netloc
                    # Remove port if present
                    if ':' in domain:
                        domain = domain.split(':')[0]
                    self.indicators['domains'].add(domain.lower())
            except:
                pass

        # Extract email addresses
        emails = extract_email_addresses(self.body_text)
        for email in emails:
            domain_match = re.search(r'@([\w.-]+)', email)
            if domain_match:
                self.indicators['email_domains'].add(domain_match.group(1).lower())

        # Extract IPs from text
        ips = extract_ip_addresses(self.body_text)
        self.indicators['ips'].update(ips)

    def analyze_indicators(self) -> list:
        """Analyze all extracted indicators."""
        self.analysis_results = []

        # Analyze IP addresses
        for ip in self.indicators['ips']:
            analysis = self._analyze_ip(ip)
            if analysis:
                self.analysis_results.append(analysis)

        # Analyze domains
        for domain in self.indicators['domains']:
            analysis = self._analyze_domain(domain)
            if analysis:
                self.analysis_results.append(analysis)

        # Analyze URLs
        for url in self.indicators['urls']:
            analysis = self._analyze_url(url)
            if analysis:
                self.analysis_results.append(analysis)

        # Analyze email domains
        for email_domain in self.indicators['email_domains']:
            analysis = self._analyze_email_domain(email_domain)
            if analysis:
                self.analysis_results.append(analysis)

        return self.analysis_results

    def _analyze_ip(self, ip: str) -> dict:
        """Analyze IP address with network intelligence."""
        try:
            ip_obj = ipaddress.ip_address(ip)

            analysis = {
                'indicator': ip,
                'type': 'IP Address',
                'analysis': {
                    'version': f"IPv{ip_obj.version}",
                    'type': 'Private' if ip_obj.is_private else 'Public',
                }
            }

            # Additional analysis
            if ip_obj.is_private:
                analysis['analysis']['note'] = 'Internal IP address'
            elif ip_obj.is_loopback:
                analysis['analysis']['note'] = 'Loopback address'
            elif ip_obj.is_multicast:
                analysis['analysis']['note'] = 'Multicast address'
            elif ip_obj.is_global:
                analysis['analysis']['note'] = 'Global IP address'

            # Check for known malicious ranges (basic check)
            malicious_ranges = [
                ipaddress.ip_network('198.51.100.0/24'),  # TEST-NET-2
                ipaddress.ip_network('203.0.113.0/24'),   # TEST-NET-3
            ]

            for mal_range in malicious_ranges:
                if ip_obj in mal_range:
                    analysis['analysis']['warning'] = 'Known test range'
                    break

            # Simulate WHOIS data
            whois_info = self._simulate_whois_lookup(ip)
            if whois_info:
                analysis['analysis'].update(whois_info)

            return analysis

        except ValueError:
            return {
                'indicator': ip,
                'type': 'Invalid IP',
                'analysis': {'error': 'Invalid IP address format'}
            }

    def _analyze_domain(self, domain: str) -> dict:
        """Analyze domain with network intelligence."""
        analysis = {
            'indicator': domain,
            'type': 'Domain',
            'analysis': {}
        }

        # Basic domain analysis
        analysis['analysis']['level'] = 'TLD' if '.' not in domain else 'Subdomain' if domain.count('.') > 1 else 'Domain'

        # Check for suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.top', '.click', '.download']
        tld = domain.split('.')[-1] if '.' in domain else domain
        if f'.{tld}' in suspicious_tlds:
            analysis['analysis']['warning'] = 'Suspicious TLD'

        # Simulate domain lookup
        domain_info = self._simulate_domain_lookup(domain)
        if domain_info:
            analysis['analysis'].update(domain_info)

        # Simulate DNS records
        dns_info = self._simulate_dns_lookup(domain)
        if dns_info:
            analysis['analysis']['dns_records'] = dns_info

        return analysis

    def _analyze_url(self, url: str) -> dict:
        """Analyze URL with network intelligence."""
        try:
            parsed = urlparse(url)

            analysis = {
                'indicator': url,
                'type': 'URL',
                'analysis': {
                    'scheme': parsed.scheme,
                    'domain': parsed.netloc,
                    'path': parsed.path or '/',
                }
            }

            if parsed.query:
                analysis['analysis']['query_params'] = len(parsed.query.split('&'))

            # Check for suspicious URL patterns
            suspicious_patterns = [
                r'bit\.ly', r'tinyurl\.com', r'short\.gg',  # URL shorteners
                r'\.(exe|bat|scr|com|pif)$',  # Executable extensions
                r'\.(tk|ml|ga|cf|top|click|download)',  # Suspicious TLDs
                r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP addresses in URL
            ]

            warnings = []
            for pattern in suspicious_patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    warnings.append(f'Suspicious pattern: {pattern}')

            if warnings:
                analysis['analysis']['warnings'] = warnings

            # Check for URL length (very long URLs can be suspicious)
            if len(url) > 200:
                analysis['analysis']['warning'] = 'Very long URL'

            # Check for excessive parameters
            if parsed.query and len(parsed.query.split('&')) > 10:
                analysis['analysis']['warning'] = 'Excessive URL parameters'

            return analysis

        except Exception as e:
            return {
                'indicator': url,
                'type': 'Invalid URL',
                'analysis': {'error': str(e)}
            }

    def _analyze_email_domain(self, domain: str) -> dict:
        """Analyze email domain with network intelligence."""
        analysis = {
            'indicator': domain,
            'type': 'Email Domain',
            'analysis': {}
        }

        # Check for common email providers
        common_providers = [
            'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com',
            'icloud.com', 'aol.com', 'protonmail.com', 'tutanota.com'
        ]

        if domain.lower() in common_providers:
            analysis['analysis']['type'] = 'Common email provider'
        else:
            analysis['analysis']['type'] = 'Custom domain'

            # Check for suspicious email domain patterns
            suspicious_patterns = [
                r'\d{4,}',  # Numbers in domain
                r'[.-]{2,}',  # Multiple dots/hyphens
                r'\.(tk|ml|ga|cf|top|click|download)$'  # Suspicious TLDs
            ]

            for pattern in suspicious_patterns:
                if re.search(pattern, domain, re.IGNORECASE):
                    analysis['analysis']['warning'] = 'Suspicious domain pattern'
                    break

        # Simulate MX lookup
        mx_info = self._simulate_mx_lookup(domain)
        if mx_info:
            analysis['analysis']['mx_info'] = mx_info

        return analysis

    def _simulate_whois_lookup(self, ip: str) -> dict:
        """Simulate WHOIS lookup (in real implementation, use actual WHOIS)."""
        import random

        # Simulate different ISPs based on IP ranges
        first_octet = int(ip.split('.')[0])

        if first_octet == 8:
            return {'asn': 'AS3356', 'country': 'US', 'isp': 'Level 3 Communications'}
        elif first_octet == 173:
            return {'asn': 'AS7922', 'country': 'US', 'isp': 'Comcast Cable'}
        elif first_octet == 192:
            return {'asn': 'AS701', 'country': 'US', 'isp': 'Verizon Business'}
        elif first_octet == 10 or first_octet == 172 or first_octet == 192:
            return {'asn': 'Private', 'country': 'Private', 'isp': 'Private Network'}
        else:
            isps = ['Amazon AWS', 'Google Cloud', 'Microsoft Azure', 'Unknown ISP']
            countries = ['US', 'CA', 'GB', 'DE', 'FR', 'JP', 'AU']
            return {
                'asn': f'AS{random.randint(10000, 99999)}',
                'country': random.choice(countries),
                'isp': random.choice(isps)
            }

    def _simulate_domain_lookup(self, domain: str) -> dict:
        """Simulate domain registration lookup."""
        import random
        from datetime import datetime, timedelta

        # Simulate different domain ages
        if random.random() < 0.3:  # 30% chance of new domain
            created_date = datetime.now() - timedelta(days=random.randint(1, 30))
            is_new = True
        else:
            created_date = datetime.now() - timedelta(days=random.randint(365, 3650))
            is_new = False

        registrars = ['GoDaddy', 'Namecheap', 'Cloudflare', 'Google Domains', 'Unknown']
        statuses = ['Active', 'Registered', 'Locked']

        return {
            'created': created_date.strftime('%Y-%m-%d'),
            'registrar': random.choice(registrars),
            'status': random.choice(statuses),
            'is_new': is_new
        }

    def _simulate_dns_lookup(self, domain: str) -> dict:
        """Simulate DNS record lookup."""
        import random

        result = {}

        if random.random() < 0.8:  # 80% chance of A records
            result['a_records'] = [f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}" for _ in range(random.randint(1, 4))]

        if random.random() < 0.6:  # 60% chance of MX records
            result['mx_records'] = [f"mail{random.randint(1, 10)}.{domain}" for _ in range(random.randint(1, 3))]

        if random.random() < 0.7:  # 70% chance of NS records
            result['ns_records'] = [f"ns{random.randint(1, 4)}.{domain}" for _ in range(random.randint(2, 4))]

        return result

    def _simulate_mx_lookup(self, domain: str) -> dict:
        """Simulate MX record lookup with email security checks."""
        import random

        if random.random() < 0.8:  # 80% chance of MX records
            mx_records = [f"mail{random.randint(1, 10)}.{domain}" for _ in range(random.randint(1, 3))]

            return {
                'mx_records': mx_records,
                'has_spf': random.random() < 0.7,  # 70% chance of SPF
                'has_dkim': random.random() < 0.6,  # 60% chance of DKIM
                'has_dmarc': random.random() < 0.5   # 50% chance of DMARC
            }

        return None

    def get_analysis_by_type(self, indicator_type: str) -> list:
        """Get analysis results filtered by indicator type."""
        return [r for r in self.analysis_results if r['type'] == indicator_type]

    def get_suspicious_indicators(self) -> list:
        """Get indicators with suspicious characteristics."""
        suspicious = []

        for result in self.analysis_results:
            if 'warning' in result['analysis'] or 'error' in result['analysis']:
                suspicious.append(result)

        return suspicious
