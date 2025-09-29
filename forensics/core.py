#!/usr/bin/env python3
"""
Core forensics utilities for email analysis.
"""

import hashlib
import re
import ipaddress
from urllib.parse import urlparse
import datetime
import email.utils
from pathlib import Path
import base64
import struct
import io


# Try to import optional forensic libraries
try:
    import tlsh
    TLSH_AVAILABLE = True
except ImportError:
    TLSH_AVAILABLE = False

try:
    from PIL import Image
    from PIL.ExifTags import TAGS
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

try:
    import olefile
    OLE_AVAILABLE = True
except ImportError:
    OLE_AVAILABLE = False

try:
    import zipfile
    ZIPFILE_AVAILABLE = True
except ImportError:
    ZIPFILE_AVAILABLE = False


# ---------- Basic Utilities --------------------------------------------------
def human_bytes(n: int) -> str:
    """Convert bytes to human-readable format."""
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def hash_bytes(data: bytes, algo: str = "sha256") -> str:
    """Generate hash of bytes data."""
    h = hashlib.new(algo)
    h.update(data)
    return h.hexdigest()


# ---------- Text Extraction Helpers -----------------------------------------
def extract_urls(text: str) -> list:
    """Extract URLs from text using regex."""
    url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[\w\-\._~:/?#[\]@!$&\'()*+,;=]*'
    urls = re.findall(url_pattern, text)
    return list(set(urls))  # Remove duplicates


def extract_email_addresses(text: str) -> list:
    """Extract email addresses from text."""
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    emails = re.findall(email_pattern, text)
    return list(set(emails))


def extract_ip_addresses(text: str) -> list:
    """Extract IP addresses from text."""
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    ips = re.findall(ip_pattern, text)
    valid_ips = []
    for ip in ips:
        try:
            ipaddress.ip_address(ip)
            valid_ips.append(ip)
        except ValueError:
            continue
    return valid_ips


def extract_cid_urls(text: str) -> list:
    """Extract embedded content IDs (cid:) from text."""
    cid_pattern = r'cid:([^\s\)\]\}]+)'
    cid_matches = re.findall(cid_pattern, text)
    return list(set(cid_matches))


def extract_phone_numbers(text: str) -> list:
    """Extract phone numbers from text.
    
    Supports various formats:
    - (123) 456-7890
    - 123-456-7890
    - 123.456.7890
    - 1234567890
    - +1 123 456 7890
    """
    phone_patterns = [
        r'\(\d{3}\)\s*\d{3}[-.]?\d{4}',  # (123) 456-7890, (123) 456.7890
        r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',  # 123-456-7890, 123.456.7890, 1234567890
        r'\+\d{1,3}\s*\d{3}\s*\d{3}\s*\d{4}',  # +1 123 456 7890
    ]
    
    phone_numbers = []
    for pattern in phone_patterns:
        matches = re.findall(pattern, text)
        phone_numbers.extend(matches)
    
    return list(set(phone_numbers))


def extract_names(text: str) -> list:
    """Extract potential names from text.
    
    This is a basic extraction that looks for:
    - Capitalized words (potential first/last names)
    - Common name patterns
    """
    # Look for capitalized words (2+ letters) that might be names
    name_pattern = r'\b[A-Z][a-z]+\s+[A-Z][a-z]+\b'  # First Last
    names = re.findall(name_pattern, text)
    
    # Also look for single capitalized words that might be first names
    single_name_pattern = r'\b[A-Z][a-z]{2,}\b'
    single_names = re.findall(single_name_pattern, text)
    
    # Filter out common words that aren't names
    common_words = {
        'The', 'This', 'That', 'These', 'Those', 'From', 'To', 'Subject',
        'Date', 'Sent', 'Received', 'Cc', 'Bcc', 'Attachment', 'Please',
        'Thank', 'Thanks', 'Best', 'Regards', 'Sincerely', 'Hello', 'Dear',
        'Yours', 'Truly', 'Cordially', 'Respectfully', 'Faithfully'
    }
    
    filtered_single_names = [name for name in single_names if name not in common_words]
    
    # Combine both types of potential names
    all_names = names + filtered_single_names
    
    return list(set(all_names))


# ---------- Header Parsing Helpers ------------------------------------------
def parse_received_headers(received_headers: list) -> list:
    """Parse Received headers and extract hop information."""
    hops = []
    for header in received_headers:
        hop = {
            'raw': header,
            'from': None,
            'by': None,
            'with': None,
            'id': None,
            'for': None,
            'timestamp': None,
            'ip': None,
            'hostname': None
        }

        # Extract IP addresses
        ips = extract_ip_addresses(header)
        if ips:
            hop['ip'] = ips[0]

        # Extract timestamp - multiple patterns for different formats
        timestamp_patterns = [
            r';\s*(.+?)(?:\s*\(|$)',  # Standard format: ; timestamp (comments)
            r'\s+(\w{3},\s+\d{1,2}\s+\w{3}\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s+[+-]?\d{4})',  # RFC 2822
            r'\s+(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})',  #asctime format
            r'\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:\s*[+-]?\d{4})?)',  # ISO format
            r'\s+(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})',  # US format
            r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)',  # ISO 8601
        ]

        for pattern in timestamp_patterns:
            match = re.search(pattern, header)
            if match:
                hop['timestamp'] = match.group(1).strip()
                break

        # Extract from/by/with/for
        from_match = re.search(r'from\s+([^\s;]+)', header, re.IGNORECASE)
        if from_match:
            hop['from'] = from_match.group(1)

        by_match = re.search(r'by\s+([^\s;]+)', header, re.IGNORECASE)
        if by_match:
            hop['by'] = by_match.group(1)

        with_match = re.search(r'with\s+([^\s;]+)', header, re.IGNORECASE)
        if with_match:
            hop['with'] = with_match.group(1)

        for_match = re.search(r'for\s+([^\s;]+)', header, re.IGNORECASE)
        if for_match:
            hop['for'] = for_match.group(1)

        id_match = re.search(r'id\s+([^\s;]+)', header, re.IGNORECASE)
        if id_match:
            hop['id'] = id_match.group(1)

        hops.append(hop)

    return hops


def parse_authentication_results(auth_header: str) -> dict:
    """Parse Authentication-Results header."""
    results = {
        'spf': None,
        'dkim': None,
        'dmarc': None,
        'raw': auth_header
    }

    if not auth_header:
        return results

    # Parse SPF
    spf_match = re.search(r'spf=([\w.]+)', auth_header, re.IGNORECASE)
    if spf_match:
        results['spf'] = spf_match.group(1)

    # Parse DKIM
    dkim_match = re.search(r'dkim=([\w.]+)', auth_header, re.IGNORECASE)
    if dkim_match:
        results['dkim'] = dkim_match.group(1)

    # Parse DMARC
    dmarc_match = re.search(r'dmarc=([\w.]+)', auth_header, re.IGNORECASE)
    if dmarc_match:
        results['dmarc'] = dmarc_match.group(1)

    return results


def parse_dkim_signature(dkim_header: str) -> dict:
    """Parse DKIM-Signature header."""
    dkim = {
        'version': None,
        'algorithm': None,
        'domain': None,
        'selector': None,
        'raw': dkim_header
    }

    if not dkim_header:
        return dkim

    # Extract DKIM parameters
    version_match = re.search(r'v=([^;]+)', dkim_header)
    if version_match:
        dkim['version'] = version_match.group(1)

    algo_match = re.search(r'a=([^;]+)', dkim_header)
    if algo_match:
        dkim['algorithm'] = algo_match.group(1)

    domain_match = re.search(r'd=([^;]+)', dkim_header)
    if domain_match:
        dkim['domain'] = domain_match.group(1)

    selector_match = re.search(r's=([^;]+)', dkim_header)
    if selector_match:
        dkim['selector'] = selector_match.group(1)

    return dkim


def parse_thread_index(thread_index: str) -> dict:
    """Parse Microsoft Thread-Index header for forensic analysis."""
    analysis = {
        'raw': thread_index,
        'is_valid': False,
        'timestamp': None,
        'composition_time': None,
        'timezone_offset': None,
        'notes': []
    }

    if not thread_index:
        analysis['notes'].append('No Thread-Index header found')
        return analysis

    try:
        # Thread-Index is typically base64 encoded
        decoded = base64.b64decode(thread_index)

        if len(decoded) >= 22:  # Minimum valid length
            analysis['is_valid'] = True

            # Extract timestamp (first 8 bytes, little-endian)
            if len(decoded) >= 8:
                timestamp_bytes = decoded[:8]
                # Convert FILETIME to Unix timestamp
                filetime = struct.unpack('<Q', timestamp_bytes)[0]
                # FILETIME is 100-nanosecond intervals since January 1, 1601
                unix_time = (filetime - 116444736000000000) // 10000000
                analysis['timestamp'] = datetime.datetime.fromtimestamp(unix_time, tz=datetime.timezone.utc)

                # Calculate composition time (typically 6 bytes before timestamp)
                if len(decoded) >= 14:
                    comp_time_bytes = decoded[8:14]
                    comp_filetime = struct.unpack('<Q', comp_time_bytes + b'\x00\x00')[0]
                    comp_unix_time = (comp_filetime - 116444736000000000) // 10000000
                    analysis['composition_time'] = datetime.datetime.fromtimestamp(comp_unix_time, tz=datetime.timezone.utc)

                    # Calculate composition duration
                    if analysis['timestamp'] and analysis['composition_time']:
                        duration = analysis['timestamp'] - analysis['composition_time']
                        analysis['notes'].append(f'Composition duration: {duration.total_seconds():.1f} seconds')

            # Extract timezone information (bytes 14-22)
            if len(decoded) >= 22:
                timezone_bytes = decoded[14:22]
                # Parse timezone offset (implementation varies)
                analysis['timezone_offset'] = f'Timezone data: {timezone_bytes.hex()}'

        else:
            analysis['notes'].append('Thread-Index too short to be valid')

    except Exception as e:
        analysis['notes'].append(f'Error parsing Thread-Index: {str(e)}')

    return analysis


# ---------- Advanced Forensic Helpers ---------------------------------------
def hash_tlsh(data: bytes) -> str:
    """Generate TLSH fuzzy hash if available."""
    if TLSH_AVAILABLE:
        try:
            # TLSH requires at least 50 bytes of data
            if len(data) < 50:
                return "insufficient_data"
            hash_result = tlsh.hash(data)
            return hash_result if hash_result else "null"
        except:
            return "null"
    return "null"


def get_magic_bytes(data: bytes) -> str:
    """Identify file type from magic bytes."""
    if len(data) < 4:
        return "unknown"

    # Common file signatures
    magic_signatures = {
        b'\x50\x4B\x03\x04': 'ZIP',
        b'\x50\x4B\x05\x06': 'ZIP (empty)',
        b'\x50\x4B\x07\x08': 'ZIP (spanned)',
        b'\x25\x50\x44\x46': 'PDF',
        b'\xD0\xCF\x11\xE0': 'OLE/MS Office',
        b'\x7F\x45\x4C\x46': 'ELF',
        b'\x4D\x5A': 'PE/EXE',
        b'\x89\x50\x4E\x47': 'PNG',
        b'\xFF\xD8\xFF': 'JPEG',
        b'\x47\x49\x46\x38': 'GIF',
        b'\x49\x49\x2A\x00': 'TIFF (little endian)',
        b'\x4D\x4D\x00\x2A': 'TIFF (big endian)',
        b'\x00\x00\x01\x00': 'ICO',
        b'\x00\x00\x02\x00': 'CUR',
        b'\x1A\x45\xDF\xA3': 'Matroska',
        b'\x66\x74\x79\x70': 'MP4',
        b'\x52\x49\x46\x46': 'RIFF (WAV/AVI)',
        b'\x57\x41\x56\x45': 'WAV',
        b'\x41\x56\x49\x20': 'AVI'
    }

    for signature, file_type in magic_signatures.items():
        if data.startswith(signature):
            return file_type

    return "unknown"


def extract_exif_data(data: bytes) -> dict:
    """Extract EXIF metadata from image data."""
    if not PIL_AVAILABLE:
        return {}

    try:
        image = Image.open(io.BytesIO(data))
        exif_data = image._getexif()

        if not exif_data:
            return {}

        exif_dict = {}
        for tag_id, value in exif_data.items():
            tag = TAGS.get(tag_id, tag_id)
            exif_dict[tag] = str(value)

        return exif_dict
    except:
        return {}


def detect_password_protection(data: bytes, filename: str) -> dict:
    """Detect password protection in various file types."""
    result = {
        'is_protected': False,
        'protection_type': None,
        'has_password_hint': False
    }

    # ZIP file detection
    if filename.lower().endswith('.zip') or data.startswith(b'\x50\x4B'):
        try:
            with zipfile.ZipFile(io.BytesIO(data), 'r') as zip_file:
                for info in zip_file.infolist():
                    if info.flag_bits & 0x1:  # Password protected bit
                        result['is_protected'] = True
                        result['protection_type'] = 'ZIP password'
                        break
        except:
            pass

    # Office document detection (basic)
    if filename.lower().endswith(('.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx')):
        if OLE_AVAILABLE:
            try:
                if olefile.isOleFile(io.BytesIO(data)):
                    result['is_protected'] = True
                    result['protection_type'] = 'Office document (potential)'
            except:
                pass

    # PDF password detection (basic)
    if filename.lower().endswith('.pdf') and data.startswith(b'\x25\x50\x44\x46'):
        if b'/Encrypt' in data:
            result['is_protected'] = True
            result['protection_type'] = 'PDF encryption'

    return result


def analyze_ole_macros(data: bytes) -> dict:
    """Analyze OLE files for macros and embedded content."""
    if not OLE_AVAILABLE:
        return {}

    try:
        if not olefile.isOleFile(io.BytesIO(data)):
            return {}

        ole = olefile.OleFileIO(io.BytesIO(data))
        analysis = {
            'has_macros': False,
            'macro_count': 0,
            'embedded_objects': [],
            'vba_detected': False
        }

        # Check for macro storage
        if ole.exists('Macros') or ole.exists('\x01Macros'):
            analysis['has_macros'] = True
            analysis['vba_detected'] = True

        # List all streams
        for path in ole.listdir():
            if isinstance(path, str):
                if 'macro' in path.lower() or 'vba' in path.lower():
                    analysis['has_macros'] = True
                    analysis['macro_count'] += 1
                analysis['embedded_objects'].append(path)

        ole.close()
        return analysis
    except:
        return {}


def analyze_message_id_domain(msg) -> dict:
    """Analyze Message-ID domain for spoofing detection."""
    message_id = msg.get('Message-ID', '')
    from_header = msg.get('From', '')

    analysis = {
        'message_id': message_id,
        'message_id_domain': None,
        'from_domain': None,
        'domains_match': False,
        'suspicious': False
    }

    # Extract domain from Message-ID
    msg_id_match = re.search(r'@([^>\s]+)', message_id)
    if msg_id_match:
        analysis['message_id_domain'] = msg_id_match.group(1)

    # Extract domain from From header
    from_match = re.search(r'@([^>\s]+)', from_header)
    if from_match:
        analysis['from_domain'] = from_match.group(1)

    # Check if domains match
    if analysis['message_id_domain'] and analysis['from_domain']:
        analysis['domains_match'] = (analysis['message_id_domain'].lower() ==
                                   analysis['from_domain'].lower())
        analysis['suspicious'] = not analysis['domains_match']

    return analysis


def detect_time_anomalies(date_header: str, received_headers: list) -> list:
    """Detect time-related anomalies."""
    anomalies = []

    try:
        # Parse Date header
        if date_header:
            try:
                # Try to parse the date header with email.utils
                date_time = email.utils.parsedate_to_datetime(date_header)
            except Exception as parse_error:
                # Try alternative parsing methods
                try:
                    # Try parsing with dateutil.parser as fallback
                    from dateutil import parser
                    date_time = parser.parse(date_header)
                except ImportError:
                    anomalies.append(f"Could not parse date header (dateutil not available): {date_header}")
                    return anomalies
                except Exception as fallback_error:
                    anomalies.append(f"Could not parse date header '{date_header}': {str(parse_error)}")
                    return anomalies

            # Check if date is in future or too far in past
            now = datetime.datetime.now(datetime.timezone.utc)
            if date_time > now:
                anomalies.append(f"Future date detected: {date_header}")
            elif (now - date_time).days > 365:
                anomalies.append(f"Ancient date detected: {date_header}")

            # Compare with first Received header
            if received_headers:
                try:
                    first_received = parse_received_headers([received_headers[0]])[0]
                    timestamp = first_received['timestamp']
                    
                    # Handle case where timestamp might not be a string
                    if timestamp:
                        if isinstance(timestamp, dict):
                            timestamp = timestamp.get('raw', '') if 'raw' in timestamp else str(timestamp)
                        elif not isinstance(timestamp, str):
                            timestamp = str(timestamp) if timestamp is not None else ''
                        
                        if timestamp:  # Only try to parse if we have a non-empty string
                            try:
                                # Try to parse the timestamp with email.utils
                                received_time = email.utils.parsedate_to_datetime(timestamp)
                                time_diff = abs((date_time - received_time).total_seconds())
                                if time_diff > 86400:  # More than 24 hours difference
                                    anomalies.append(f"Large time difference between Date header and first Received: {time_diff/3600:.1f} hours")
                            except Exception as parse_error:
                                # Try alternative parsing methods
                                try:
                                    # Try parsing with dateutil.parser as fallback
                                    from dateutil import parser
                                    received_time = parser.parse(timestamp)
                                    time_diff = abs((date_time - received_time).total_seconds())
                                    if time_diff > 86400:  # More than 24 hours difference
                                        anomalies.append(f"Large time difference between Date header and first Received: {time_diff/3600:.1f} hours")
                                except ImportError:
                                    anomalies.append(f"Could not parse timestamp (dateutil not available): {timestamp}")
                                except Exception as fallback_error:
                                    anomalies.append(f"Could not parse timestamp '{timestamp}': {str(parse_error)}")
                except Exception as e:
                    anomalies.append(f"Could not parse first Received timestamp: {str(e)}")

    except Exception as e:
        anomalies.append(f"Error parsing Date header: {str(e)}")

    return anomalies
