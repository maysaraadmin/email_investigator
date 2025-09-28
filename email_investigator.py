#!/usr/bin/env python3
"""
PyQt5 GUI e-mail forensics utility.
Author : you
License: MIT
"""

import sys, os, hashlib, datetime, email, mimetypes, traceback, re, json, ipaddress, base64, quopri, zipfile, struct
from email import policy
from pathlib import Path
from urllib.parse import urlparse
import dns.resolver
import requests
import threading
from collections import defaultdict

# Try to import optional forensic libraries
try:
    import tlsh
    TLSH_AVAILABLE = True
except ImportError:
    TLSH_AVAILABLE = False
    print("Warning: tlsh not available. Fuzzy hashing disabled.")

try:
    from PIL import Image
    from PIL.ExifTags import TAGS
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    print("Warning: Pillow not available. EXIF extraction disabled.")

try:
    import olefile
    OLE_AVAILABLE = True
except ImportError:
    OLE_AVAILABLE = False
    print("Warning: olefile not available. OLE analysis disabled.")

from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QSplitter, QTextEdit, QTreeWidget,
                             QTreeWidgetItem, QPushButton, QLabel, QFileDialog,
                             QMessageBox, QGroupBox, QTabWidget, QHeaderView, QMenu,
                             QDialog, QLineEdit, QTextEdit as QPlainTextEdit, QDialogButtonBox,
                             QFormLayout)
from PyQt5.QtCore import Qt, QMimeData
from PyQt5.QtGui import QFont, QClipboard


# ---------- helpers ----------------------------------------------------------
def human_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def hash_bytes(data: bytes, algo: str = "sha256") -> str:
    h = hashlib.new(algo)
    h.update(data)
    return h.hexdigest()


# ---------- forensic helpers -------------------------------------------------
def extract_urls(text: str) -> list:
    """Extract URLs from text using regex"""
    url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[\w\-\._~:/?#[\]@!$&\'()*+,;=]*'
    urls = re.findall(url_pattern, text)
    return list(set(urls))  # Remove duplicates


def extract_email_addresses(text: str) -> list:
    """Extract email addresses from text"""
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    emails = re.findall(email_pattern, text)
    return list(set(emails))


def extract_ip_addresses(text: str) -> list:
    """Extract IP addresses from text"""
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


def parse_received_headers(received_headers: list) -> list:
    """Parse Received headers and extract hop information"""
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
        
        # Extract timestamp
        # Look for common timestamp patterns
        timestamp_patterns = [
            r';\s*(.+?)(?:\s*\(|$)',  # Standard format: ; timestamp (comments)
            r'\s+(\w{3},\s+\d{1,2}\s+\w{3}\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s+[+-]?\d{4})',
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
    """Parse Authentication-Results header"""
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
    """Parse DKIM-Signature header"""
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


def detect_time_anomalies(date_header: str, received_headers: list) -> list:
    """Detect time-related anomalies"""
    anomalies = []
    
    try:
        # Parse Date header
        if date_header:
            date_time = email.utils.parsedate_to_datetime(date_header)
            
            # Check if date is in future or too far in past
            now = datetime.datetime.now(datetime.timezone.utc)
            if date_time > now:
                anomalies.append(f"Future date detected: {date_header}")
            elif (now - date_time).days > 365:
                anomalies.append(f"Ancient date detected: {date_header}")
            
            # Compare with first Received header
            if received_headers:
                first_received = parse_received_headers([received_headers[0]])[0]
                if first_received['timestamp']:
                    try:
                        received_time = email.utils.parsedate_to_datetime(first_received['timestamp'])
                        time_diff = abs((date_time - received_time).total_seconds())
                        if time_diff > 86400:  # More than 24 hours difference
                            anomalies.append(f"Large time difference between Date header and first Received: {time_diff/3600:.1f} hours")
                    except:
                        anomalies.append("Could not parse first Received timestamp")
                        
    except Exception as e:
        anomalies.append(f"Error parsing Date header: {str(e)}")
    
    return anomalies


def parse_thread_index(thread_index: str) -> dict:
    """Parse Microsoft Thread-Index header for forensic analysis"""
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
        import base64
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


# ---------- advanced forensic helpers ---------------------------------------
def hash_tlsh(data: bytes) -> str:
    """Generate TLSH fuzzy hash if available"""
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
    """Identify file type from magic bytes"""
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
    """Extract EXIF metadata from image data"""
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
    """Detect password protection in various file types"""
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
    """Analyze OLE files for macros and embedded content"""
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


def extract_cid_urls(text: str) -> list:
    """Extract embedded content IDs (cid:) from text"""
    cid_pattern = r'cid:([^\s\)\]\}]+)'
    cid_matches = re.findall(cid_pattern, text)
    return list(set(cid_matches))


def analyze_message_id_domain(msg: email.message.EmailMessage) -> dict:
    """Analyze Message-ID domain for spoofing detection"""
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


def check_virustotal_hash(file_hash: str, api_key: str = None) -> dict:
    """Check file hash against VirusTotal (requires API key)"""
    if not api_key:
        return {'error': 'No API key provided'}
    
    try:
        url = f"https://www.virustotal.com/vtapi/v2/file/report"
        params = {'apikey': api_key, 'resource': file_hash}
        response = requests.get(url, params=params, timeout=10)
        
        if response.status_code == 200:
            return response.json()
        else:
            return {'error': f'API request failed: {response.status_code}'}
    except Exception as e:
        return {'error': str(e)}


# Add missing import for io
import io


# ---------- chain-of-custody dialog ------------------------------------------
class ChainOfCustodyDialog(QDialog):
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
        return {
            'analyst': self.analyst_edit.text(),
            'case_number': self.case_number_edit.text(),
            'exhibit_number': self.exhibit_number_edit.text(),
            'seal_number': self.seal_number_edit.text(),
            'notes': self.notes_edit.toPlainText()
        }


# ---------- main window ------------------------------------------------------
class MailInvestigator(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("E-mail Investigator - Forensic Edition")
        self.resize(1400, 900)
        self._build_ui()
        self.current_msg = None
        self.current_attachments = []  # list of (name, ctype, data)
        self.file_metadata = {
            'filename': None,
            'filesize': None,
            'sha256': None,
            'sha1': None,
            'md5': None,
            'acquisition_time': None,
            'acquisition_method': None,
            'chain_of_custody': {
                'analyst': None,
                'case_number': None,
                'exhibit_number': None,
                'seal_number': None,
                'notes': None,
                'custody_history': []
            }
        }
        
        self.forensic_data = {
            'urls': [],
            'emails': [],
            'ips': [],
            'received_hops': [],
            'authentication': {},
            'dkim': {},
            'time_anomalies': [],
            'body_hashes': {}
        }
        
        self.advanced_forensic_data = {
            'body_parts': [],
            'embedded_content': [],
            'attachment_analysis': [],
            'exif_metadata': {},
            'password_protection': {},
            'macro_analysis': {},
            'magic_bytes_analysis': {},
            'message_id_analysis': {},
            'virustotal_results': {},
            'anti_forgery': {}
        }
        
        self.virustotal_api_key = None  # VirusTotal API key

    # -------------------------------------------------------------------------
    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        lay = QVBoxLayout(central)

        # top toolbar
        toolbar = QHBoxLayout()
        btn_open = QPushButton("Open .eml …")
        btn_open.clicked.connect(self.open_eml)
        btn_paste = QPushButton("Parse from clipboard")
        btn_paste.clicked.connect(self.parse_clipboard)
        btn_export = QPushButton("Export Forensic Report")
        btn_export.clicked.connect(self.export_forensic_report)
        btn_custody = QPushButton("Chain of Custody")
        btn_custody.clicked.connect(self.edit_chain_of_custody)
        toolbar.addWidget(btn_open)
        toolbar.addWidget(btn_paste)
        toolbar.addWidget(btn_custody)
        toolbar.addWidget(btn_export)
        toolbar.addStretch()
        lay.addLayout(toolbar)

        # main horizontal splitter
        splitter = QSplitter(Qt.Horizontal)
        lay.addWidget(splitter)

        # left: tree with headers / parts
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Field", "Value"])
        self.tree.header().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        splitter.addWidget(self.tree)

        # right: notebook (plain, html, raw, attachments, forensic)
        self.nb = QTabWidget()
        splitter.addWidget(self.nb)

        # plain text tab
        self.txt_plain = QTextEdit()
        self.txt_plain.setReadOnly(True)
        self.txt_plain.setFont(QFont("Consolas", 9))
        self.nb.addTab(self.txt_plain, "Plain text")

        # html tab
        self.txt_html = QTextEdit()
        self.txt_html.setReadOnly(True)
        self.nb.addTab(self.txt_html, "HTML source")

        # raw headers tab
        self.txt_raw = QTextEdit()
        self.txt_raw.setReadOnly(True)
        self.txt_raw.setFont(QFont("Consolas", 9))
        self.nb.addTab(self.txt_raw, "Raw headers")

        # attachments tab
        self.attach_list = QTreeWidget()
        self.attach_list.setHeaderLabels(["Name", "Content-Type", "Size", "MD5", "SHA-256"])
        self.attach_list.setRootIsDecorated(False)
        self.attach_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.attach_list.customContextMenuRequested.connect(self._attach_context)
        self.nb.addTab(self.attach_list, "Attachments")
        
        # forensic analysis tabs
        self.tree_file_meta = QTreeWidget()
        self.tree_file_meta.setHeaderLabels(["Property", "Value"])
        self.tree_file_meta.setRootIsDecorated(False)
        self.nb.addTab(self.tree_file_meta, "File Metadata")
        
        self.tree_received = QTreeWidget()
        self.tree_received.setHeaderLabels(["Hop", "From", "By", "IP", "Timestamp", "ID"])
        self.tree_received.setRootIsDecorated(False)
        self.nb.addTab(self.tree_received, "Received Headers")
        
        self.tree_auth = QTreeWidget()
        self.tree_auth.setHeaderLabels(["Authentication", "Result"])
        self.tree_auth.setRootIsDecorated(False)
        self.nb.addTab(self.tree_auth, "Authentication")
        
        self.tree_iocs = QTreeWidget()
        self.tree_iocs.setHeaderLabels(["Type", "Value"])
        self.tree_iocs.setRootIsDecorated(False)
        self.nb.addTab(self.tree_iocs, "IOCs")
        
        self.tree_anomalies = QTreeWidget()
        self.tree_anomalies.setHeaderLabels(["Anomaly Type", "Description"])
        self.tree_anomalies.setRootIsDecorated(False)
        self.nb.addTab(self.tree_anomalies, "Anomalies")
        
        self.tree_transport = QTreeWidget()
        self.tree_transport.setHeaderLabels(["Analysis Type", "Details"])
        self.tree_transport.setRootIsDecorated(False)
        self.nb.addTab(self.tree_transport, "Transport Metadata")
        
        self.tree_timestamps = QTreeWidget()
        self.tree_timestamps.setHeaderLabels(["Timestamp Type", "Value", "Analysis"])
        self.tree_timestamps.setRootIsDecorated(False)
        self.nb.addTab(self.tree_timestamps, "Timestamp Analytics")
        
        self.tree_network = QTreeWidget()
        self.tree_network.setHeaderLabels(["Indicator", "Type", "Network Intelligence"])
        self.tree_network.setRootIsDecorated(False)
        self.nb.addTab(self.tree_network, "Network Pivots")
        
        # advanced forensic tabs
        self.tree_body_parts = QTreeWidget()
        self.tree_body_parts.setHeaderLabels(["Part", "Content-Type", "Charset", "Size", "MD5", "SHA-256"])
        self.tree_body_parts.setRootIsDecorated(False)
        self.nb.addTab(self.tree_body_parts, "Body Parts")
        
        self.tree_embedded = QTreeWidget()
        self.tree_embedded.setHeaderLabels(["CID", "Type", "Found In"])
        self.tree_embedded.setRootIsDecorated(False)
        self.nb.addTab(self.tree_embedded, "Embedded Content")
        
        self.tree_advanced_attach = QTreeWidget()
        self.tree_advanced_attach.setHeaderLabels(["Name", "Magic Bytes", "Extension Match", "SSDEEP", "Protected", "Macros"])
        self.tree_advanced_attach.setRootIsDecorated(False)
        self.nb.addTab(self.tree_advanced_attach, "Advanced Attachments")
        
        self.tree_exif = QTreeWidget()
        self.tree_exif.setHeaderLabels(["Image", "EXIF Tag", "Value"])
        self.tree_exif.setRootIsDecorated(False)
        self.nb.addTab(self.tree_exif, "EXIF Metadata")
        
        self.tree_anti_forgery = QTreeWidget()
        self.tree_anti_forgery.setHeaderLabels(["Check", "Result", "Details"])
        self.tree_anti_forgery.setRootIsDecorated(False)
        self.nb.addTab(self.tree_anti_forgery, "Anti-Forgery")
        
        self.tree_anti_forensics = QTreeWidget()
        self.tree_anti_forensics.setHeaderLabels(["Detection Type", "Severity", "Indicator", "Details"])
        self.tree_anti_forensics.setRootIsDecorated(False)
        self.nb.addTab(self.tree_anti_forensics, "Anti-Forensics")
        
        self.tree_virustotal = QTreeWidget()
        self.tree_virustotal.setHeaderLabels(["File", "Hash", "VT Result", "Positives/Total"])
        self.tree_virustotal.setRootIsDecorated(False)
        self.nb.addTab(self.tree_virustotal, "VirusTotal")

        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 2)

        # status bar
        self.status = QLabel("Ready")
        self.statusBar().addWidget(self.status)

    # -------------------------------------------------------------------------
    def open_eml(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select RFC-822 message", "", "E-mail files (*.eml);;All files (*.*)")
        if not path:
            return
        try:
            with open(path, "rb") as fh:
                raw = fh.read()
            
            # Capture file metadata
            self.file_metadata['filename'] = Path(path).name
            self.file_metadata['filesize'] = len(raw)
            self.file_metadata['sha256'] = hash_bytes(raw, "sha256")
            self.file_metadata['sha1'] = hash_bytes(raw, "sha1")
            self.file_metadata['md5'] = hash_bytes(raw, "md5")
            self.file_metadata['acquisition_time'] = datetime.datetime.now().isoformat()
            self.file_metadata['acquisition_method'] = "file_open"
            
            self._parse(raw)
            self.status.setText(f"Loaded: {Path(path).name} | SHA-256: {self.file_metadata['sha256'][:16]}...")
        except Exception as exc:
            QMessageBox.critical(self, "Error", str(exc))

    # -------------------------------------------------------------------------
    def parse_clipboard(self):
        clip = QApplication.clipboard()
        raw = clip.text(mode=QClipboard.Clipboard).encode("utf-8", errors="replace")
        if not raw.strip():
            QMessageBox.warning(self, "Nothing to do", "Clipboard is empty.")
            return
        try:
            # Capture file metadata for clipboard content
            self.file_metadata['filename'] = "clipboard_content.eml"
            self.file_metadata['filesize'] = len(raw)
            self.file_metadata['sha256'] = hash_bytes(raw, "sha256")
            self.file_metadata['sha1'] = hash_bytes(raw, "sha1")
            self.file_metadata['md5'] = hash_bytes(raw, "md5")
            self.file_metadata['acquisition_time'] = datetime.datetime.now().isoformat()
            self.file_metadata['acquisition_method'] = "clipboard"
            
            self._parse(raw)
            self.status.setText(f"Parsed from clipboard | SHA-256: {self.file_metadata['sha256'][:16]}...")
        except Exception as exc:
            QMessageBox.critical(self, "Parse error", traceback.format_exc())

    # -------------------------------------------------------------------------
    def _parse(self, raw: bytes):
        msg = email.message_from_bytes(raw, policy=policy.default)
        self.current_msg = msg
        self._populate_tree(msg)
        self._populate_body(msg)
        self._populate_raw(msg)
        self._populate_attachments(msg)
        
        # Populate forensic analysis tabs
        self._populate_file_metadata()
        self._populate_forensic_analysis(msg)
        self._populate_advanced_forensic_analysis(msg, raw)

    # -------------------------------------------------------------------------
    def _populate_tree(self, msg: email.message.EmailMessage):
        self.tree.clear()
        root = QTreeWidgetItem(self.tree)
        root.setText(0, "Headers")

        def add(parent, key, val):
            item = QTreeWidgetItem(parent)
            item.setText(0, key)
            item.setText(1, val)

        # basic headers
        for key in ["From", "To", "Cc", "Bcc", "Date", "Subject",
                    "Message-ID", "Reply-To", "Return-Path"]:
            val = msg.get(key)
            if val:
                add(root, key, str(val))
        
        # transport metadata headers
        transport_headers = ["Sender", "In-Reply-To", "References", "Thread-Index",
                           "X-Mailer", "User-Agent", "X-Originating-IP", 
                           "X-Originating-Time", "Content-Type", "MIME-Version",
                           "Authentication-Results", "DKIM-Signature"]
        
        transport_group = QTreeWidgetItem(root)
        transport_group.setText(0, "Transport Metadata")
        
        for key in transport_headers:
            val = msg.get(key)
            if val:
                add(transport_group, key, str(val))

        # extra headers
        extra = QTreeWidgetItem(root)
        extra.setText(0, "Other")
        
        # Exclude basic and transport headers
        excluded_headers = {"From", "To", "Cc", "Bcc", "Date", "Subject",
                          "Message-ID", "Reply-To", "Return-Path", "Sender", 
                          "In-Reply-To", "References", "Thread-Index", "X-Mailer", 
                          "User-Agent", "X-Originating-IP", "X-Originating-Time", 
                          "Content-Type", "MIME-Version", "Authentication-Results", 
                          "DKIM-Signature"}
        
        for key, val in msg.items():
            if key not in excluded_headers:
                add(extra, key, str(val))

        self.tree.expandAll()

    # -------------------------------------------------------------------------
    def _populate_body(self, msg: email.message.EmailMessage):
        plain = html = ""
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype == "text/plain":
                content = part.get_content()
                if content:
                    plain += content
            elif ctype == "text/html":
                content = part.get_content()
                if content:
                    html += content
        self.txt_plain.setPlainText(plain)
        self.txt_html.setPlainText(html)

    # -------------------------------------------------------------------------
    def _populate_raw(self, msg: email.message.EmailMessage):
        self.txt_raw.setPlainText(str(msg))

    # -------------------------------------------------------------------------
    def _populate_attachments(self, msg: email.message.EmailMessage):
        self.attach_list.clear()
        self.current_attachments.clear()
        for part in msg.walk():
            if part.get_content_disposition() == "attachment" or \
               (part.get_filename() and part.get_content_maintype() != "text"):
                name = part.get_filename() or "unnamed"
                ctype = part.get_content_type()
                data = part.get_payload(decode=True)
                if data is None:
                    continue
                size = len(data)
                md5 = hash_bytes(data, "md5")
                sha = hash_bytes(data, "sha256")
                item = QTreeWidgetItem()
                item.setText(0, name)
                item.setText(1, ctype)
                item.setText(2, human_bytes(size))
                item.setText(3, md5)
                item.setText(4, sha)
                item.setData(0, Qt.UserRole, data)  # store bytes
                self.attach_list.addTopLevelItem(item)
                self.current_attachments.append((name, ctype, data))
    
    # -------------------------------------------------------------------------
    def _populate_file_metadata(self):
        """Populate the file metadata tab"""
        self.tree_file_meta.clear()
        
        # Basic file metadata
        metadata_items = [
            ("Filename", self.file_metadata['filename'] or "null"),
            ("File Size", f"{self.file_metadata['filesize']} bytes ({human_bytes(self.file_metadata['filesize'])})" if self.file_metadata['filesize'] else "null"),
            ("MD5", self.file_metadata['md5'] or "null"),
            ("SHA-1", self.file_metadata['sha1'] or "null"),
            ("SHA-256", self.file_metadata['sha256'] or "null"),
            ("Acquisition Time", self.file_metadata['acquisition_time'] or "null"),
            ("Acquisition Method", self.file_metadata['acquisition_method'] or "null")
        ]
        
        for key, value in metadata_items:
            item = QTreeWidgetItem()
            item.setText(0, key)
            item.setText(1, str(value))
            self.tree_file_meta.addTopLevelItem(item)
        
        # Chain of custody information
        custody = self.file_metadata['chain_of_custody']
        if any(custody.values()):
            # Add separator
            separator = QTreeWidgetItem()
            separator.setText(0, "--- Chain of Custody ---")
            separator.setText(1, "")
            self.tree_file_meta.addTopLevelItem(separator)
            
            custody_items = [
                ("Analyst", custody['analyst'] or "null"),
                ("Case Number", custody['case_number'] or "null"),
                ("Exhibit Number", custody['exhibit_number'] or "null"),
                ("Seal Number", custody['seal_number'] or "null"),
                ("Notes", custody['notes'] or "null"[:50] + "..." if len(custody['notes'] or "") > 50 else custody['notes'] or "null")
            ]
            
            for key, value in custody_items:
                item = QTreeWidgetItem()
                item.setText(0, key)
                item.setText(1, str(value))
                self.tree_file_meta.addTopLevelItem(item)
            
            # Custody history
            if custody['custody_history']:
                history_item = QTreeWidgetItem()
                history_item.setText(0, "Custody History Entries")
                history_item.setText(1, str(len(custody['custody_history'])))
                self.tree_file_meta.addTopLevelItem(history_item)
    
    # -------------------------------------------------------------------------
    def _populate_forensic_analysis(self, msg: email.message.EmailMessage):
        """Populate all forensic analysis tabs"""
        # Extract and analyze all forensic data
        self._extract_iocs(msg)
        self._analyze_received_headers(msg)
        self._analyze_authentication(msg)
        self._detect_anomalies(msg)
        self._analyze_transport_metadata(msg)
        self._analyze_body_parts(msg)
        self._analyze_attachments_advanced(msg)
        self._analyze_timestamps(msg)
        self._analyze_network_pivots(msg)
        self._analyze_anti_forensics(msg)
    
    # -------------------------------------------------------------------------
    def _extract_iocs(self, msg: email.message.EmailMessage):
        """Extract Indicators of Compromise from email"""
        self.tree_iocs.clear()
        self.forensic_data['urls'] = []
        self.forensic_data['emails'] = []
        self.forensic_data['ips'] = []
        
        # Extract from all text content
        all_text = ""
        for part in msg.walk():
            if part.get_content_type() in ["text/plain", "text/html"]:
                content = part.get_content()
                if content:
                    all_text += content + " "
        
        # Extract URLs
        urls = extract_urls(all_text)
        for url in urls:
            self.forensic_data['urls'].append(url)
            item = QTreeWidgetItem()
            item.setText(0, "URL")
            item.setText(1, url)
            self.tree_iocs.addTopLevelItem(item)
        
        # Extract email addresses
        emails = extract_email_addresses(all_text)
        for email in emails:
            self.forensic_data['emails'].append(email)
            item = QTreeWidgetItem()
            item.setText(0, "Email")
            item.setText(1, email)
            self.tree_iocs.addTopLevelItem(item)
        
        # Extract IP addresses
        ips = extract_ip_addresses(all_text)
        for ip in ips:
            self.forensic_data['ips'].append(ip)
            item = QTreeWidgetItem()
            item.setText(0, "IP Address")
            item.setText(1, ip)
            self.tree_iocs.addTopLevelItem(item)
    
    # -------------------------------------------------------------------------
    def _analyze_received_headers(self, msg: email.message.EmailMessage):
        """Analyze Received headers"""
        self.tree_received.clear()
        received_headers = msg.get_all("Received", [])
        
        if not received_headers:
            item = QTreeWidgetItem()
            item.setText(0, "No Received headers found")
            self.tree_received.addTopLevelItem(item)
            return
        
        # Parse received headers (bottom to top = first to last)
        hops = parse_received_headers(received_headers)
        self.forensic_data['received_hops'] = hops
        
        for i, hop in enumerate(reversed(hops)):  # Reverse to show chronological order
            item = QTreeWidgetItem()
            item.setText(0, str(i + 1))
            item.setText(1, hop['from'] or "null")
            item.setText(2, hop['by'] or "null")
            item.setText(3, hop['ip'] or "null")
            item.setText(4, hop['timestamp'] or "null")
            item.setText(5, hop['id'] or "null")
            self.tree_received.addTopLevelItem(item)
    
    # -------------------------------------------------------------------------
    def _analyze_authentication(self, msg: email.message.EmailMessage):
        """Analyze authentication headers"""
        self.tree_auth.clear()
        
        # Authentication-Results
        auth_header = msg.get("Authentication-Results", "")
        auth_results = parse_authentication_results(auth_header)
        self.forensic_data['authentication'] = auth_results
        
        auth_items = [
            ("SPF", auth_results['spf'] or "null"),
            ("DKIM", auth_results['dkim'] or "null"),
            ("DMARC", auth_results['dmarc'] or "null")
        ]
        
        for auth_type, result in auth_items:
            item = QTreeWidgetItem()
            item.setText(0, auth_type)
            item.setText(1, result)
            self.tree_auth.addTopLevelItem(item)
        
        # DKIM-Signature
        dkim_header = msg.get("DKIM-Signature", "")
        dkim_info = parse_dkim_signature(dkim_header)
        self.forensic_data['dkim'] = dkim_info
        
        dkim_items = [
            ("DKIM Version", dkim_info['version'] or "null"),
            ("DKIM Algorithm", dkim_info['algorithm'] or "null"),
            ("DKIM Domain", dkim_info['domain'] or "null"),
            ("DKIM Selector", dkim_info['selector'] or "null")
        ]
        
        for dkim_key, dkim_value in dkim_items:
            item = QTreeWidgetItem()
            item.setText(0, dkim_key)
            item.setText(1, dkim_value)
            self.tree_auth.addTopLevelItem(item)
    
    # -------------------------------------------------------------------------
    def _detect_anomalies(self, msg: email.message.EmailMessage):
        """Detect email anomalies"""
        self.tree_anomalies.clear()
        self.forensic_data['time_anomalies'] = []
        
        # Time anomalies
        date_header = msg.get("Date", "")
        received_headers = msg.get_all("Received", [])
        time_anomalies = detect_time_anomalies(date_header, received_headers)
        self.forensic_data['time_anomalies'] = time_anomalies
        
        for anomaly in time_anomalies:
            item = QTreeWidgetItem()
            item.setText(0, "Time Anomaly")
            item.setText(1, anomaly)
            self.tree_anomalies.addTopLevelItem(item)
        
        # Header anomalies
        if not received_headers:
            item = QTreeWidgetItem()
            item.setText(0, "Header Anomaly")
            item.setText(1, "Missing Received headers - possible header stripping")
            self.tree_anomalies.addTopLevelItem(item)
        
        # Check for missing essential headers
        essential_headers = ["From", "Date", "Message-ID"]
        for header in essential_headers:
            if not msg.get(header):
                item = QTreeWidgetItem()
                item.setText(0, "Header Anomaly")
                item.setText(1, f"Missing essential header: {header}")
                self.tree_anomalies.addTopLevelItem(item)
    
    # -------------------------------------------------------------------------
    def _analyze_transport_metadata(self, msg: email.message.EmailMessage):
        """Analyze transport metadata headers"""
        self.tree_transport.clear()
        
        # Analyze Thread-Index
        thread_index = msg.get('Thread-Index')
        if thread_index:
            analysis = parse_thread_index(thread_index)
            
            thread_item = QTreeWidgetItem(self.tree_transport)
            thread_item.setText(0, "Thread-Index Analysis")
            
            # Add analysis results
            add_child = lambda parent, key, value: QTreeWidgetItem(parent, [key, str(value)])
            
            add_child(thread_item, "Raw Value", analysis['raw'])
            add_child(thread_item, "Valid", analysis['is_valid'])
            
            if analysis['timestamp']:
                add_child(thread_item, "Timestamp", analysis['timestamp'].isoformat())
            
            if analysis['composition_time']:
                add_child(thread_item, "Composition Time", analysis['composition_time'].isoformat())
            
            if analysis['timezone_offset']:
                add_child(thread_item, "Timezone Offset", analysis['timezone_offset'])
            
            # Add notes
            if analysis['notes']:
                notes_item = QTreeWidgetItem(thread_item)
                notes_item.setText(0, "Notes")
                for note in analysis['notes']:
                    add_child(notes_item, "Note", note)
        
        # Analyze X-Originating-IP
        x_orig_ip = msg.get('X-Originating-IP')
        if x_orig_ip:
            ip_item = QTreeWidgetItem(self.tree_transport)
            ip_item.setText(0, "X-Originating-IP Analysis")
            
            # Clean IP address (remove brackets if present)
            ip_clean = x_orig_ip.strip('[]')
            
            add_child = lambda parent, key, value: QTreeWidgetItem(parent, [key, str(value)])
            
            add_child(ip_item, "Raw Value", x_orig_ip)
            add_child(ip_item, "Cleaned IP", ip_clean)
            
            try:
                ip_obj = ipaddress.ip_address(ip_clean)
                add_child(ip_item, "IP Version", f"IPv{ip_obj.version}")
                add_child(ip_item, "Is Private", ip_obj.is_private)
                add_child(ip_item, "Is Global", ip_obj.is_global)
                add_child(ip_item, "Is Multicast", ip_obj.is_multicast)
                
                # Check for suspicious IPs
                if ip_obj.is_private:
                    add_child(ip_item, "Note", "Private IP address - may indicate internal routing")
                elif ip_obj.is_loopback:
                    add_child(ip_item, "Note", "Loopback address - suspicious for external email")
                elif ip_obj.is_multicast:
                    add_child(ip_item, "Note", "Multicast address - unusual for email")
                    
            except ValueError:
                add_child(ip_item, "Error", "Invalid IP address format")
        
        # Analyze X-Mailer/User-Agent
        x_mailer = msg.get('X-Mailer') or msg.get('User-Agent')
        if x_mailer:
            mailer_item = QTreeWidgetItem(self.tree_transport)
            mailer_item.setText(0, "Mail Client Analysis")
            
            add_child = lambda parent, key, value: QTreeWidgetItem(parent, [key, str(value)])
            
            add_child(mailer_item, "Client", x_mailer)
            
            # Check for common mail clients
            mailer_lower = x_mailer.lower()
            if any(keyword in mailer_lower for keyword in ['outlook', 'microsoft']):
                add_child(mailer_item, "Type", "Microsoft Outlook")
            elif any(keyword in mailer_lower for keyword in ['thunderbird', 'mozilla']):
                add_child(mailer_item, "Type", "Mozilla Thunderbird")
            elif any(keyword in mailer_lower for keyword in ['apple', 'mac']):
                add_child(mailer_item, "Type", "Apple Mail")
            elif any(keyword in mailer_lower for keyword in ['gmail', 'google']):
                add_child(mailer_item, "Type", "Gmail")
            elif any(keyword in mailer_lower for keyword in ['iphone', 'ipad', 'ios']):
                add_child(mailer_item, "Type", "iOS Mail")
            elif any(keyword in mailer_lower for keyword in ['android']):
                add_child(mailer_item, "Type", "Android Mail")
            else:
                add_child(mailer_item, "Type", "Unknown/Custom")
            
            # Check for suspicious mailers
            suspicious_indicators = ['bot', 'script', 'automated', 'mass mailer', 'bulk']
            if any(indicator in mailer_lower for indicator in suspicious_indicators):
                add_child(mailer_item, "Suspicious", "Potential automated/bulk mailer detected")
        
        # Analyze References header
        references = msg.get('References')
        if references:
            refs_item = QTreeWidgetItem(self.tree_transport)
            refs_item.setText(0, "References Analysis")
            
            add_child = lambda parent, key, value: QTreeWidgetItem(parent, [key, str(value)])
            
            # Split references (usually space-separated Message-IDs)
            ref_list = references.split()
            add_child(refs_item, "Reference Count", len(ref_list))
            
            # Show first few references
            for i, ref in enumerate(ref_list[:5]):
                add_child(refs_item, f"Reference {i+1}", ref)
            
            if len(ref_list) > 5:
                add_child(refs_item, "Note", f"... and {len(ref_list) - 5} more references")
            
            # Analyze thread depth
            thread_depth = len(ref_list)
            if thread_depth > 10:
                add_child(refs_item, "Thread Depth", f"Deep thread ({thread_depth} messages)")
            elif thread_depth > 5:
                add_child(refs_item, "Thread Depth", f"Moderate thread ({thread_depth} messages)")
            else:
                add_child(refs_item, "Thread Depth", f"Shallow thread ({thread_depth} messages)")
        
        # Store transport analysis in forensic data
        self.forensic_data['transport_analysis'] = {
            'thread_index': thread_index,
            'x_originating_ip': x_orig_ip,
            'mailer': x_mailer,
            'references': references
        }
    
    # -------------------------------------------------------------------------
    def _analyze_body_parts(self, msg: email.message.EmailMessage):
        """Analyze email body parts with character set detection"""
        self.tree_body_parts.clear()
        self.forensic_data['body_parts'] = []
        
        part_counter = 1
        
        for part in msg.walk():
            # Skip multipart containers
            if part.is_multipart():
                continue
            
            content_type = part.get_content_type()
            content_disposition = part.get('Content-Disposition', '')
            filename = part.get_filename()
            charset = part.get_content_charset() or 'unknown'
            content_transfer_encoding = part.get('Content-Transfer-Encoding', 'unknown')
            
            # Get payload
            try:
                payload = part.get_payload(decode=True)
                if payload is None:
                    payload = b''
                payload_size = len(payload)
            except Exception:
                payload = b''
                payload_size = 0
            
            # Calculate hashes
            md5_hash = hashlib.md5(payload).hexdigest() if payload else 'null'
            sha256_hash = hashlib.sha256(payload).hexdigest() if payload else 'null'
            
            # Analyze character set
            charset_analysis = self._analyze_charset(payload, charset)
            
            # Create tree item
            part_item = QTreeWidgetItem(self.tree_body_parts)
            part_item.setText(0, f"Part {part_counter}")
            part_item.setText(1, content_type)
            part_item.setText(2, charset)
            part_item.setText(3, f"{payload_size} bytes")
            part_item.setText(4, md5_hash)
            part_item.setText(5, sha256_hash)
            
            # Add detailed analysis as children
            add_child = lambda parent, key, value: QTreeWidgetItem(parent, [key, str(value)])
            
            # Content disposition
            if content_disposition:
                disp_item = QTreeWidgetItem(part_item)
                disp_item.setText(0, "Content-Disposition")
                add_child(disp_item, "Value", content_disposition)
                if filename:
                    add_child(disp_item, "Filename", filename)
            
            # Transfer encoding
            enc_item = QTreeWidgetItem(part_item)
            enc_item.setText(0, "Transfer Encoding")
            add_child(enc_item, "Encoding", content_transfer_encoding)
            
            # Character set analysis
            if charset_analysis:
                charset_item = QTreeWidgetItem(part_item)
                charset_item.setText(0, "Charset Analysis")
                for key, value in charset_analysis.items():
                    add_child(charset_item, key, value)
            
            # Content preview (first 100 chars)
            if payload and content_type.startswith('text/'):
                try:
                    # Try to decode with detected charset
                    if charset != 'unknown' and charset != 'binary':
                        text_preview = payload.decode(charset, errors='replace')[:100]
                    else:
                        # Try common charsets
                        for test_charset in ['utf-8', 'latin-1', 'ascii']:
                            try:
                                text_preview = payload.decode(test_charset, errors='replace')[:100]
                                break
                            except UnicodeDecodeError:
                                continue
                        else:
                            text_preview = "[Binary content or unknown encoding]"
                    
                    preview_item = QTreeWidgetItem(part_item)
                    preview_item.setText(0, "Content Preview")
                    add_child(preview_item, "Preview", text_preview + "...")
                    
                except Exception as e:
                    preview_item = QTreeWidgetItem(part_item)
                    preview_item.setText(0, "Content Preview")
                    add_child(preview_item, "Error", f"Could not decode: {str(e)}")
            
            # Store in forensic data
            part_data = {
                'part_number': part_counter,
                'content_type': content_type,
                'charset': charset,
                'size': payload_size,
                'md5': md5_hash,
                'sha256': sha256_hash,
                'content_disposition': content_disposition,
                'filename': filename,
                'transfer_encoding': content_transfer_encoding,
                'charset_analysis': charset_analysis
            }
            self.forensic_data['body_parts'].append(part_data)
            
            part_counter += 1
    
    def _analyze_charset(self, payload: bytes, declared_charset: str) -> dict:
        """Analyze character set of text content"""
        analysis = {
            'declared_charset': declared_charset,
            'detected_charset': 'unknown',
            'encoding_issues': [],
            'confidence': 'low'
        }
        
        if not payload:
            return analysis
        
        # Try to detect encoding using chardet if available
        try:
            import chardet
            detection = chardet.detect(payload)
            if detection['confidence'] > 0.7:
                analysis['detected_charset'] = detection['encoding']
                analysis['confidence'] = 'high'
            elif detection['confidence'] > 0.5:
                analysis['detected_charset'] = detection['encoding']
                analysis['confidence'] = 'medium'
        except ImportError:
            # chardet not available, use basic detection
            pass
        
        # Check for encoding issues
        if declared_charset and declared_charset != 'unknown':
            try:
                payload.decode(declared_charset)
                analysis['encoding_issues'].append('No decoding issues with declared charset')
            except UnicodeDecodeError as e:
                analysis['encoding_issues'].append(f'Decoding error with declared charset: {str(e)}')
        
        # Check for common encoding patterns
        if payload.startswith(b'\xff\xfe') or payload.startswith(b'\xfe\xff'):
            analysis['encoding_issues'].append('UTF-16 BOM detected')
        elif payload.startswith(b'\xef\xbb\xbf'):
            analysis['encoding_issues'].append('UTF-8 BOM detected')
        
        # Check for null bytes (suspicious in text content)
        if b'\x00' in payload:
            analysis['encoding_issues'].append('Null bytes detected - may indicate binary content or encoding issues')
        
        # Check for high bit characters
        high_bit_chars = sum(1 for byte in payload if byte & 0x80)
        if high_bit_chars > len(payload) * 0.1:  # More than 10% high-bit characters
            analysis['encoding_issues'].append('High percentage of high-bit characters - likely non-ASCII content')
        
        return analysis
    
    # -------------------------------------------------------------------------
    def _analyze_attachments_advanced(self, msg: email.message.EmailMessage):
        """Advanced attachment analysis with SSDEEP, EXIF, and password protection"""
        self.tree_advanced_attach.clear()
        self.tree_exif.clear()
        self.forensic_data['advanced_attachments'] = []
        
        for part in msg.walk():
            # Skip multipart containers and non-attachments
            if part.is_multipart():
                continue
            
            content_disposition = part.get('Content-Disposition', '')
            if 'attachment' not in content_disposition.lower():
                continue
            
            filename = part.get_filename() or 'unnamed_attachment'
            content_type = part.get_content_type()
            
            # Get payload
            try:
                payload = part.get_payload(decode=True)
                if payload is None:
                    payload = b''
            except Exception:
                payload = b''
            
            if not payload:
                continue
            
            # Advanced analysis
            analysis = {
                'filename': filename,
                'content_type': content_type,
                'size': len(payload),
                'md5': hashlib.md5(payload).hexdigest(),
                'sha256': hashlib.sha256(payload).hexdigest(),
                'tlsh': hash_tlsh(payload),
                'magic_bytes': self._detect_magic_bytes(payload),
                'extension_match': self._check_extension_match(filename, payload),
                'password_protected': self._check_password_protection(filename, content_type, payload),
                'has_macros': self._check_macros(filename, content_type, payload),
                'exif_data': self._extract_exif_data(filename, payload)
            }
            
            # Add to advanced attachments tree
            attach_item = QTreeWidgetItem(self.tree_advanced_attach)
            attach_item.setText(0, filename)
            attach_item.setText(1, analysis['magic_bytes']['detected_type'])
            attach_item.setText(2, str(analysis['extension_match']))
            attach_item.setText(3, analysis['tlsh'])
            attach_item.setText(4, str(analysis['password_protected']))
            attach_item.setText(5, str(analysis['has_macros']))
            
            # Add to EXIF tree if EXIF data exists
            if analysis['exif_data']:
                exif_item = QTreeWidgetItem(self.tree_exif)
                exif_item.setText(0, filename)
                
                for tag, value in analysis['exif_data'].items():
                    tag_item = QTreeWidgetItem(exif_item)
                    tag_item.setText(1, tag)
                    tag_item.setText(2, str(value))
            
            self.forensic_data['advanced_attachments'].append(analysis)
    
    def _detect_magic_bytes(self, payload: bytes) -> dict:
        """Detect file type using magic bytes"""
        magic_signatures = {
            b'\x50\x4B\x03\x04': 'ZIP',
            b'\x50\x4B\x05\x06': 'ZIP (empty)',
            b'\x50\x4B\x07\x08': 'ZIP (spanned)',
            b'\x25\x50\x44\x46': 'PDF',
            b'\x7F\x45\x4C\x46': 'ELF',
            b'\x4D\x5A': 'PE (Windows EXE/DLL)',
            b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1': 'OLE (MS Office)',
            b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A': 'PNG',
            b'\xFF\xD8\xFF': 'JPEG',
            b'\x47\x49\x46\x38': 'GIF',
            b'\x49\x49\x2A\x00': 'TIFF (little-endian)',
            b'\x4D\x4D\x00\x2A': 'TIFF (big-endian)',
            b'\x00\x00\x01\x00': 'ICO',
            b'\x00\x00\x02\x00': 'CUR',
            b'\x1A\x45\xDF\xA3': 'Matroska (MKV)',
            b'\x66\x74\x79\x70': 'MP4',
            b'\x4F\x67\x67\x53': 'OGG',
            b'\x52\x49\x46\x46': 'RIFF (AVI/WAV)',
            b'\x57\x41\x56\x45': 'WAV',
            b'\x41\x56\x49\x20': 'AVI'
        }
        
        result = {
            'detected_type': 'Unknown',
            'signature': None,
            'offset': None
        }
        
        for signature, file_type in magic_signatures.items():
            if payload.startswith(signature):
                result['detected_type'] = file_type
                result['signature'] = signature.hex()
                result['offset'] = 0
                break
        
        return result
    
    def _check_extension_match(self, filename: str, payload: bytes) -> bool:
        """Check if file extension matches magic bytes"""
        if not filename or '.' not in filename:
            return True  # No extension to check
        
        extension = filename.split('.')[-1].lower()
        magic_result = self._detect_magic_bytes(payload)
        detected_type = magic_result['detected_type'].lower()
        
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
    
    def _check_password_protection(self, filename: str, content_type: str, payload: bytes) -> bool:
        """Check if file appears to be password protected"""
        # Check by filename patterns
        filename_lower = filename.lower()
        password_indicators = ['password', 'protected', 'encrypted', 'secure']
        if any(indicator in filename_lower for indicator in password_indicators):
            return True
        
        # Check by content type
        if content_type in ['application/encrypted', 'application/x-encrypted']:
            return True
        
        # Check ZIP files for password protection indicators
        if payload.startswith(b'PK\x03\x04') or payload.startswith(b'PK\x05\x06'):
            # Look for encrypted flag in ZIP headers
            try:
                # Simple check for encrypted entries in ZIP
                if b'\x01\x00' in payload[:100]:  # Encrypted flag
                    return True
            except:
                pass
        
        # Check Office documents
        if payload.startswith(b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1'):
            # OLE documents - check for encryption indicators
            try:
                if b'Encrypt' in payload[:1000]:
                    return True
            except:
                pass
        
        return False
    
    def _check_macros(self, filename: str, content_type: str, payload: bytes) -> bool:
        """Check if Office document contains macros"""
        filename_lower = filename.lower()
        
        # Only check Office documents
        office_extensions = ['.doc', '.docm', '.dotm', '.xls', '.xlsm', '.xltm', '.ppt', '.pptm']
        if not any(filename_lower.endswith(ext) for ext in office_extensions):
            return False
        
        # Check OLE format documents
        if payload.startswith(b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1'):
            try:
                # Look for macro indicators
                macro_indicators = [
                    b'\x01\x00\x00\x00\x01\x00\x00\x00',  # Macro storage signature
                    b'Macro',
                    b'VBA',
                    b'\x01\x00\x00\x00\x02\x00\x00\x00'   # Another macro signature
                ]
                
                for indicator in macro_indicators:
                    if indicator in payload:
                        return True
                        
            except:
                pass
        
        # Check Office Open XML format (ZIP-based)
        if payload.startswith(b'PK\x03\x04'):
            try:
                # Extract ZIP entries in memory
                import io
                import zipfile
                
                zip_file = io.BytesIO(payload)
                with zipfile.ZipFile(zip_file, 'r') as zf:
                    # Look for macro-related files
                    macro_files = [
                        'word/vbaProject.bin',
                        'xl/vbaProject.bin',
                        'ppt/vbaProject.bin'
                    ]
                    
                    for macro_file in macro_files:
                        if macro_file in zf.namelist():
                            return True
                            
            except:
                pass
        
        return False
    
    def _extract_exif_data(self, filename: str, payload: bytes) -> dict:
        """Extract EXIF data from image files"""
        if not PIL_AVAILABLE:
            return {}
        
        filename_lower = filename.lower()
        image_extensions = ['.jpg', '.jpeg', '.tiff', '.tif']
        
        if not any(filename_lower.endswith(ext) for ext in image_extensions):
            return {}
        
        try:
            import io
            from PIL import Image
            from PIL.ExifTags import TAGS
            
            image = Image.open(io.BytesIO(payload))
            exif_data = image._getexif()
            
            if not exif_data:
                return {}
            
            result = {}
            for tag_id, value in exif_data.items():
                tag = TAGS.get(tag_id, tag_id)
                result[tag] = value
            
            return result
            
        except Exception:
            return {}
    
    # -------------------------------------------------------------------------
    def _analyze_timestamps(self, msg: email.message.EmailMessage):
        """Comprehensive timestamp analytics and comparison"""
        self.tree_timestamps.clear()
        self.forensic_data['timestamps'] = []
        
        # Extract all timestamps
        timestamps = {}
        
        # Date header
        date_header = msg.get('Date')
        if date_header:
            try:
                date_time = email.utils.parsedate_to_datetime(date_header)
                timestamps['Date Header'] = {
                    'value': date_time,
                    'raw': date_header,
                    'source': 'header',
                    'timezone': str(date_time.tzinfo) if date_time.tzinfo else 'UTC'
                }
            except Exception as e:
                timestamps['Date Header'] = {
                    'value': None,
                    'raw': date_header,
                    'source': 'header',
                    'error': f'Parse error: {str(e)}'
                }
        
        # Received headers
        received_headers = msg.get_all('Received', [])
        for i, received in enumerate(received_headers):
            parsed = parse_received_headers([received])[0]
            if parsed['timestamp']:
                try:
                    recv_time = email.utils.parsedate_to_datetime(parsed['timestamp'])
                    timestamps[f'Received {i+1}'] = {
                        'value': recv_time,
                        'raw': parsed['timestamp'],
                        'source': 'received',
                        'from': parsed['from'],
                        'by': parsed['by'],
                        'timezone': str(recv_time.tzinfo) if recv_time.tzinfo else 'UTC'
                    }
                except Exception as e:
                    timestamps[f'Received {i+1}'] = {
                        'value': None,
                        'raw': parsed['timestamp'],
                        'source': 'received',
                        'error': f'Parse error: {str(e)}'
                    }
        
        # Thread-Index timestamp (if available)
        thread_index = msg.get('Thread-Index')
        if thread_index:
            thread_analysis = parse_thread_index(thread_index)
            if thread_analysis['timestamp']:
                timestamps['Thread-Index'] = {
                    'value': thread_analysis['timestamp'],
                    'raw': thread_index,
                    'source': 'thread_index',
                    'composition_time': thread_analysis['composition_time']
                }
        
        # Message-ID (extract timestamp if possible)
        message_id = msg.get('Message-ID')
        if message_id:
            # Try to extract timestamp from Message-ID (some formats include it)
            import re
            timestamp_match = re.search(r'\d{10,}', message_id)
            if timestamp_match:
                try:
                    timestamp_int = int(timestamp_match.group())
                    # Check if it's a Unix timestamp
                    if 1000000000 <= timestamp_int <= 2000000000:  # Reasonable range
                        msg_id_time = datetime.datetime.fromtimestamp(timestamp_int, tz=datetime.timezone.utc)
                        timestamps['Message-ID'] = {
                            'value': msg_id_time,
                            'raw': message_id,
                            'source': 'message_id',
                            'note': 'Timestamp extracted from Message-ID'
                        }
                except:
                    pass
        
        # File acquisition time
        if self.file_metadata['acquisition_time']:
            try:
                acq_time = datetime.datetime.fromisoformat(self.file_metadata['acquisition_time'])
                timestamps['File Acquisition'] = {
                    'value': acq_time,
                    'raw': self.file_metadata['acquisition_time'],
                    'source': 'acquisition',
                    'method': self.file_metadata['acquisition_method']
                }
            except Exception as e:
                timestamps['File Acquisition'] = {
                    'value': None,
                    'raw': self.file_metadata['acquisition_time'],
                    'source': 'acquisition',
                    'error': f'Parse error: {str(e)}'
                }
        
        # Display timestamps
        for ts_name, ts_data in timestamps.items():
            ts_item = QTreeWidgetItem(self.tree_timestamps)
            ts_item.setText(0, ts_name)
            
            if ts_data['value']:
                ts_item.setText(1, ts_data['value'].isoformat())
            else:
                ts_item.setText(1, ts_data['raw'])
            
            # Analysis column
            analysis_parts = []
            
            if 'error' in ts_data:
                analysis_parts.append(f"ERROR: {ts_data['error']}")
            else:
                analysis_parts.append(f"Source: {ts_data['source']}")
                
                if 'timezone' in ts_data:
                    analysis_parts.append(f"TZ: {ts_data['timezone']}")
                
                if 'from' in ts_data:
                    analysis_parts.append(f"From: {ts_data['from']}")
                
                if 'by' in ts_data:
                    analysis_parts.append(f"By: {ts_data['by']}")
                
                if 'note' in ts_data:
                    analysis_parts.append(f"Note: {ts_data['note']}")
                
                if 'method' in ts_data:
                    analysis_parts.append(f"Method: {ts_data['method']}")
            
            ts_item.setText(2, " | ".join(analysis_parts))
            
            # Store in forensic data
            self.forensic_data['timestamps'].append({
                'name': ts_name,
                'data': ts_data
            })
        
        # Add timestamp comparison analysis
        if len(timestamps) > 1:
            comparison_item = QTreeWidgetItem(self.tree_timestamps)
            comparison_item.setText(0, "=== TIMESTAMP COMPARISON ===")
            comparison_item.setText(1, "")
            comparison_item.setText(2, "")
            
            # Sort timestamps by value
            valid_timestamps = [(name, data) for name, data in timestamps.items() if data['value']]
            valid_timestamps.sort(key=lambda x: x[1]['value'])
            
            if len(valid_timestamps) > 1:
                # Time differences
                for i in range(len(valid_timestamps) - 1):
                    ts1_name, ts1_data = valid_timestamps[i]
                    ts2_name, ts2_data = valid_timestamps[i + 1]
                    
                    time_diff = ts2_data['value'] - ts1_data['value']
                    diff_seconds = time_diff.total_seconds()
                    
                    diff_item = QTreeWidgetItem(self.tree_timestamps)
                    diff_item.setText(0, f"{ts1_name} → {ts2_name}")
                    diff_item.setText(1, f"{diff_seconds:.1f}s")
                    
                    # Analyze the difference
                    if abs(diff_seconds) < 60:
                        analysis = "Normal (fast processing)"
                    elif abs(diff_seconds) < 300:
                        analysis = "Normal (moderate processing)"
                    elif abs(diff_seconds) < 3600:
                        analysis = "Slight delay"
                    elif abs(diff_seconds) < 86400:
                        analysis = "Significant delay"
                    else:
                        analysis = "Major delay (suspicious)"
                    
                    diff_item.setText(2, analysis)
            
            # Check for chronological consistency
            received_times = [data for name, data in valid_timestamps if 'received' in data['source']]
            if len(received_times) > 1:
                # Received headers should be in reverse chronological order
                for i in range(len(received_times) - 1):
                    if received_times[i]['value'] < received_times[i + 1]['value']:
                        consistency_item = QTreeWidgetItem(self.tree_timestamps)
                        consistency_item.setText(0, "Chronological Issue")
                        consistency_item.setText(1, "Received headers out of order")
                        consistency_item.setText(2, "SUSPICIOUS - Headers should be reverse chronological")
                        break
    
    # -------------------------------------------------------------------------
    def _analyze_network_pivots(self, msg: email.message.EmailMessage):
        """Network pivot data extraction with WHOIS and DNS analysis"""
        self.tree_network.clear()
        self.forensic_data['network_pivots'] = []
        
        # Extract all network indicators
        indicators = {
            'ips': set(),
            'domains': set(),
            'urls': set(),
            'email_domains': set()
        }
        
        # Extract from headers
        # From header
        from_header = msg.get('From', '')
        from_match = re.search(r'@([\w.-]+)', from_header)
        if from_match:
            indicators['email_domains'].add(from_match.group(1).lower())
        
        # Received headers
        received_headers = msg.get_all('Received', [])
        for received in received_headers:
            # Extract IPs and domains from received headers
            ip_matches = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', received)
            indicators['ips'].update(ip_matches)
            
            domain_matches = re.findall(r'@([\w.-]+)', received)
            indicators['domains'].update(domain_matches)
            
            # Extract hostnames
            host_matches = re.findall(r'by\s+([\w.-]+)', received, re.IGNORECASE)
            indicators['domains'].update(host_matches)
        
        # X-Originating-IP
        x_orig_ip = msg.get('X-Originating-IP', '')
        ip_matches = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', x_orig_ip)
        indicators['ips'].update(ip_matches)
        
        # Extract from body content
        for part in msg.walk():
            if part.is_multipart():
                continue
            
            content_type = part.get_content_type()
            if content_type.startswith('text/'):
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        text_content = payload.decode('utf-8', errors='ignore')
                        
                        # Extract URLs
                        url_pattern = r'https?://[\w.-]+(?:\.[\w.-]+)+[\w\-._~:/?#[\]@!$&\'()*+,;=]*'
                        url_matches = re.findall(url_pattern, text_content)
                        indicators['urls'].update(url_matches)
                        
                        # Extract domains from URLs
                        for url in url_matches:
                            try:
                                from urllib.parse import urlparse
                                parsed = urlparse(url)
                                if parsed.netloc:
                                    domain = parsed.netloc
                                    # Remove port if present
                                    if ':' in domain:
                                        domain = domain.split(':')[0]
                                    indicators['domains'].add(domain.lower())
                            except:
                                pass
                        
                        # Extract email addresses
                        email_pattern = r'\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Z|a-z]{2,})\b'
                        email_matches = re.findall(email_pattern, text_content)
                        indicators['email_domains'].update([domain.lower() for domain in email_matches])
                        
                        # Extract IPs from text
                        ip_matches = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text_content)
                        indicators['ips'].update(ip_matches)
                        
                except Exception:
                    pass
        
        # Analyze each indicator
        for ip in indicators['ips']:
            self._analyze_ip_indicator(ip)
        
        for domain in indicators['domains']:
            self._analyze_domain_indicator(domain)
        
        for url in indicators['urls']:
            self._analyze_url_indicator(url)
        
        for email_domain in indicators['email_domains']:
            self._analyze_email_domain_indicator(email_domain)
    
    def _analyze_ip_indicator(self, ip: str):
        """Analyze IP address with network intelligence"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            ip_item = QTreeWidgetItem(self.tree_network)
            ip_item.setText(0, ip)
            ip_item.setText(1, "IP Address")
            
            analysis_parts = []
            
            # Basic IP analysis
            analysis_parts.append(f"Version: IPv{ip_obj.version}")
            analysis_parts.append(f"Type: {'Private' if ip_obj.is_private else 'Public'}")
            
            if ip_obj.is_private:
                analysis_parts.append("Note: Internal IP address")
            elif ip_obj.is_loopback:
                analysis_parts.append("Note: Loopback address")
            elif ip_obj.is_multicast:
                analysis_parts.append("Note: Multicast address")
            elif ip_obj.is_global:
                analysis_parts.append("Note: Global IP address")
            
            # Check for known malicious ranges (basic check)
            malicious_ranges = [
                ipaddress.ip_network('198.51.100.0/24'),  # TEST-NET-2
                ipaddress.ip_network('203.0.113.0/24'),   # TEST-NET-3
            ]
            
            for mal_range in malicious_ranges:
                if ip_obj in mal_range:
                    analysis_parts.append("WARNING: Known test range")
                    break
            
            # Simulated WHOIS data (in real implementation, use actual WHOIS lookup)
            whois_info = self._simulate_whois_lookup(ip)
            if whois_info:
                analysis_parts.append(f"ASN: {whois_info.get('asn', 'Unknown')}")
                analysis_parts.append(f"Country: {whois_info.get('country', 'Unknown')}")
                analysis_parts.append(f"ISP: {whois_info.get('isp', 'Unknown')}")
            
            ip_item.setText(2, " | ".join(analysis_parts))
            
            # Store in forensic data
            self.forensic_data['network_pivots'].append({
                'indicator': ip,
                'type': 'ip',
                'analysis': {
                    'version': ip_obj.version,
                    'is_private': ip_obj.is_private,
                    'is_global': ip_obj.is_global,
                    'whois': whois_info
                }
            })
            
        except ValueError:
            # Invalid IP address
            ip_item = QTreeWidgetItem(self.tree_network)
            ip_item.setText(0, ip)
            ip_item.setText(1, "Invalid IP")
            ip_item.setText(2, "ERROR: Invalid IP address format")
    
    def _analyze_domain_indicator(self, domain: str):
        """Analyze domain with network intelligence"""
        domain_item = QTreeWidgetItem(self.tree_network)
        domain_item.setText(0, domain)
        domain_item.setText(1, "Domain")
        
        analysis_parts = []
        
        # Basic domain analysis
        analysis_parts.append(f"Level: {'TLD' if '.' not in domain else 'Subdomain' if domain.count('.') > 1 else 'Domain'}")
        
        # Check for suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.top', '.click', '.download']
        tld = domain.split('.')[-1] if '.' in domain else domain
        if f'.{tld}' in suspicious_tlds:
            analysis_parts.append("WARNING: Suspicious TLD")
        
        # Check for domain age simulation
        domain_info = self._simulate_domain_lookup(domain)
        if domain_info:
            analysis_parts.append(f"Created: {domain_info.get('created', 'Unknown')}")
            analysis_parts.append(f"Registrar: {domain_info.get('registrar', 'Unknown')}")
            analysis_parts.append(f"Status: {domain_info.get('status', 'Unknown')}")
            
            if domain_info.get('is_new', False):
                analysis_parts.append("WARNING: Recently registered domain")
        
        # Simulated DNS records
        dns_info = self._simulate_dns_lookup(domain)
        if dns_info:
            if dns_info.get('a_records'):
                analysis_parts.append(f"A: {len(dns_info['a_records'])} records")
            if dns_info.get('mx_records'):
                analysis_parts.append(f"MX: {len(dns_info['mx_records'])} records")
            if dns_info.get('ns_records'):
                analysis_parts.append(f"NS: {len(dns_info['ns_records'])} records")
        
        domain_item.setText(2, " | ".join(analysis_parts))
        
        # Store in forensic data
        self.forensic_data['network_pivots'].append({
            'indicator': domain,
            'type': 'domain',
            'analysis': {
                'domain_info': domain_info,
                'dns_info': dns_info
            }
        })
    
    def _analyze_url_indicator(self, url: str):
        """Analyze URL with network intelligence"""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            
            url_item = QTreeWidgetItem(self.tree_network)
            url_item.setText(0, url[:50] + '...' if len(url) > 50 else url)
            url_item.setText(1, "URL")
            
            analysis_parts = []
            
            # Basic URL analysis
            analysis_parts.append(f"Scheme: {parsed.scheme}")
            analysis_parts.append(f"Domain: {parsed.netloc}")
            analysis_parts.append(f"Path: {parsed.path or '/'}")
            
            if parsed.query:
                analysis_parts.append(f"Query: {len(parsed.query)} chars")
            
            # Check for suspicious URL patterns
            suspicious_patterns = [
                r'bit\.ly', r'tinyurl\.com', r'short\.gg',  # URL shorteners
                r'\.(exe|bat|scr|com|pif)$',  # Executable extensions
                r'\.(tk|ml|ga|cf|top|click|download)',  # Suspicious TLDs
                r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP addresses in URL
            ]
            
            for pattern in suspicious_patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    analysis_parts.append("WARNING: Suspicious pattern detected")
                    break
            
            # Check for URL length (very long URLs can be suspicious)
            if len(url) > 200:
                analysis_parts.append("WARNING: Very long URL")
            
            # Check for excessive parameters
            if parsed.query and len(parsed.query.split('&')) > 10:
                analysis_parts.append("WARNING: Excessive URL parameters")
            
            url_item.setText(2, " | ".join(analysis_parts))
            
            # Store in forensic data
            self.forensic_data['network_pivots'].append({
                'indicator': url,
                'type': 'url',
                'analysis': {
                    'scheme': parsed.scheme,
                    'netloc': parsed.netloc,
                    'path': parsed.path,
                    'query': parsed.query,
                    'warnings': [part for part in analysis_parts if 'WARNING:' in part]
                }
            })
            
        except Exception as e:
            url_item = QTreeWidgetItem(self.tree_network)
            url_item.setText(0, url[:50] + '...' if len(url) > 50 else url)
            url_item.setText(1, "Invalid URL")
            url_item.setText(2, f"ERROR: {str(e)}")
    
    def _analyze_email_domain_indicator(self, domain: str):
        """Analyze email domain with network intelligence"""
        domain_item = QTreeWidgetItem(self.tree_network)
        domain_item.setText(0, domain)
        domain_item.setText(1, "Email Domain")
        
        analysis_parts = []
        
        # Check for common email providers
        common_providers = [
            'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com',
            'icloud.com', 'aol.com', 'protonmail.com', 'tutanota.com'
        ]
        
        if domain.lower() in common_providers:
            analysis_parts.append("Type: Common email provider")
        else:
            analysis_parts.append("Type: Custom domain")
            
            # Check for suspicious email domain patterns
            suspicious_patterns = [
                r'\d{4,}',  # Numbers in domain
                r'[.-]{2,}',  # Multiple dots/hyphens
                r'\.(tk|ml|ga|cf|top|click|download)$'  # Suspicious TLDs
            ]
            
            for pattern in suspicious_patterns:
                if re.search(pattern, domain, re.IGNORECASE):
                    analysis_parts.append("WARNING: Suspicious domain pattern")
                    break
        
        # Check MX records simulation
        mx_info = self._simulate_mx_lookup(domain)
        if mx_info:
            analysis_parts.append(f"MX: {len(mx_info)} records")
            if mx_info.get('has_spf', False):
                analysis_parts.append("SPF: Configured")
            if mx_info.get('has_dkim', False):
                analysis_parts.append("DKIM: Configured")
            if mx_info.get('has_dmarc', False):
                analysis_parts.append("DMARC: Configured")
        else:
            analysis_parts.append("MX: No records found")
        
        domain_item.setText(2, " | ".join(analysis_parts))
        
        # Store in forensic data
        self.forensic_data['network_pivots'].append({
            'indicator': domain,
            'type': 'email_domain',
            'analysis': {
                'is_common_provider': domain.lower() in common_providers,
                'mx_info': mx_info
            }
        })
    
    def _simulate_whois_lookup(self, ip: str) -> dict:
        """Simulate WHOIS lookup (in real implementation, use actual WHOIS)"""
        # This is a simulation - in real implementation, use python-whois or similar
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
        """Simulate domain registration lookup"""
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
        """Simulate DNS record lookup"""
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
        """Simulate MX record lookup with email security checks"""
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

    # -------------------------------------------------------------------------
    def _attach_context(self, pos):
        item = self.attach_list.itemAt(pos)
        if not item:
            return
        menu = QMenu()
        save_act = menu.addAction("Save as …")
        copy_md5 = menu.addAction("Copy MD5")
        copy_sha = menu.addAction("Copy SHA-256")
        action = menu.exec_(self.attach_list.mapToGlobal(pos))
        if action == save_act:
            name = item.text(0)
            path, _ = QFileDialog.getSaveFileName(self, "Save attachment", name)
            if path:
                data = item.data(0, Qt.UserRole)
                if data:
                    with open(path, "wb") as fh:
                        fh.write(data)
                    self.status.setText(f"Saved: {Path(path).name}")
        elif action == copy_md5:
            QApplication.clipboard().setText(item.text(3))
        elif action == copy_sha:
            QApplication.clipboard().setText(item.text(4))
    
    # -------------------------------------------------------------------------
    def _populate_advanced_forensic_analysis(self, msg: email.message.EmailMessage, raw: bytes):
        """Populate advanced forensic analysis tabs"""
        self._analyze_body_parts(msg)
        self._analyze_embedded_content(msg)
        self._analyze_advanced_attachments(msg)
        self._analyze_exif_metadata(msg)
        self._analyze_password_protection(msg)
        self._analyze_macros(msg)
        self._analyze_magic_bytes(msg)
        self._analyze_message_id(msg)
        self._analyze_anti_forgery(msg)
        self._analyze_virustotal(msg, raw)
    
    def _analyze_body_parts(self, msg: email.message.EmailMessage):
        """Analyze body parts with hashing and charset analysis"""
        self.tree_body_parts.clear()
        self.advanced_forensic_data['body_parts'] = []
        
        part_num = 0
        for part in msg.walk():
            if part.get_content_maintype() == 'multipart':
                continue
                
            part_num += 1
            content = part.get_content()
            content_bytes = part.get_payload(decode=True)
            
            if content_bytes:
                # Calculate hashes
                md5_hash = hashlib.md5(content_bytes).hexdigest()
                sha256_hash = hashlib.sha256(content_bytes).hexdigest()
                
                # Get charset
                charset = part.get_content_charset() or 'unknown'
                
                # Store analysis
                analysis = {
                    'part': f"Part {part_num}",
                    'content_type': part.get_content_type(),
                    'charset': charset,
                    'size': len(content_bytes),
                    'md5': md5_hash,
                    'sha256': sha256_hash
                }
                self.advanced_forensic_data['body_parts'].append(analysis)
                
                # Add to tree
                item = QTreeWidgetItem()
                item.setText(0, analysis['part'])
                item.setText(1, analysis['content_type'])
                item.setText(2, analysis['charset'])
                item.setText(3, f"{analysis['size']} bytes")
                item.setText(4, analysis['md5'][:8] + "...")
                item.setText(5, analysis['sha256'][:8] + "...")
                self.tree_body_parts.addTopLevelItem(item)
    
    def _analyze_embedded_content(self, msg: email.message.EmailMessage):
        """Analyze embedded content (cid: references)"""
        self.tree_embedded.clear()
        self.advanced_forensic_data['embedded_content'] = []
        
        # Extract all CID references from text content
        all_text = ""
        for part in msg.walk():
            if part.get_content_type() in ["text/plain", "text/html"]:
                content = part.get_content()
                if content:
                    all_text += content + " "
        
        cid_refs = extract_cid_urls(all_text)
        
        # Find corresponding attachments
        for cid in cid_refs:
            found = False
            found_in = []
            
            # Check which parts contain this CID
            for part in msg.walk():
                if part.get_content_type() in ["text/plain", "text/html"]:
                    content = part.get_content()
                    if content and f"cid:{cid}" in content:
                        found_in.append(part.get_content_type())
            
            # Find the actual attachment with this Content-ID
            content_type = "unknown"
            for part in msg.walk():
                if part.get('Content-ID') and cid in part.get('Content-ID'):
                    content_type = part.get_content_type()
                    found = True
                    break
            
            analysis = {
                'cid': cid,
                'type': content_type,
                'found_in': ", ".join(found_in),
                'resolved': found
            }
            self.advanced_forensic_data['embedded_content'].append(analysis)
            
            # Add to tree
            item = QTreeWidgetItem()
            item.setText(0, cid)
            item.setText(1, content_type)
            item.setText(2, ", ".join(found_in))
            self.tree_embedded.addTopLevelItem(item)
    
    def _analyze_advanced_attachments(self, msg: email.message.EmailMessage):
        """Analyze attachments with advanced forensic techniques"""
        self.tree_advanced_attach.clear()
        self.advanced_forensic_data['attachment_analysis'] = []
        
        for part in msg.walk():
            if part.get_filename():
                filename = part.get_filename()
                content_bytes = part.get_payload(decode=True)
                
                if not content_bytes:
                    continue
                
                # Magic bytes analysis
                magic_type = get_magic_bytes(content_bytes)
                
                # Extension vs magic bytes comparison
                ext = Path(filename).suffix.lower()
                ext_match = "Yes" if (ext and magic_type.lower() in ext.lower()) or magic_type == "unknown" else "No"
                
                # TLSH fuzzy hashing
                tlsh_hash = hash_tlsh(content_bytes)
                
                # Password protection detection
                protection = detect_password_protection(content_bytes, filename)
                
                # Macro analysis
                macro_analysis = analyze_ole_macros(content_bytes)
                
                analysis = {
                    'filename': filename,
                    'magic_type': magic_type,
                    'extension_match': ext_match,
                    'tlsh': tlsh_hash,
                    'is_protected': protection['is_protected'],
                    'protection_type': protection['protection_type'],
                    'has_macros': macro_analysis.get('has_macros', False),
                    'macro_count': macro_analysis.get('macro_count', 0),
                    'macro_languages': macro_analysis.get('languages', []),
                    'suspicious_keywords': macro_analysis.get('suspicious_keywords', [])
                }
                
                # Add to tree
                item = QTreeWidgetItem()
                item.setText(0, filename)
                item.setText(1, magic_type)
                item.setText(2, ext_match)
                item.setText(3, tlsh_hash[:16] + "..." if tlsh_hash != "null" else "N/A")
                item.setText(4, "Yes" if protection['is_protected'] else "No")
                item.setText(5, f"{macro_analysis.get('macro_count', 0)}" if macro_analysis.get('has_macros') else "No")
                self.tree_advanced_attach.addTopLevelItem(item)
    
    def _analyze_exif_metadata(self, msg: email.message.EmailMessage):
        """Extract EXIF metadata from image attachments"""
        self.tree_exif.clear()
        self.advanced_forensic_data['exif_metadata'] = {}
        
        for part in msg.walk():
            if part.get_filename():
                filename = part.get_filename()
                content_bytes = part.get_payload(decode=True)
                
                if not content_bytes:
                    continue
                
                # Only process image files
                if filename.lower().endswith(('.jpg', '.jpeg', '.png', '.tiff', '.tif')):
                    exif_data = extract_exif_data(content_bytes)
                    
                    if exif_data:
                        self.advanced_forensic_data['exif_metadata'][filename] = exif_data
                        
                        # Add to tree
                        for tag, value in exif_data.items():
                            item = QTreeWidgetItem()
                            item.setText(0, filename)
                            item.setText(1, str(tag))
                            item.setText(2, str(value)[:100] + "..." if len(str(value)) > 100 else str(value))
                            self.tree_exif.addTopLevelItem(item)
    
    def _analyze_password_protection(self, msg: email.message.EmailMessage):
        """Analyze password protection in attachments"""
        self.advanced_forensic_data['password_protection'] = {}
        
        for part in msg.walk():
            if part.get_filename():
                filename = part.get_filename()
                content_bytes = part.get_payload(decode=True)
                
                if content_bytes:
                    protection = detect_password_protection(content_bytes, filename)
                    self.advanced_forensic_data['password_protection'][filename] = protection
    
    def _analyze_macros(self, msg: email.message.EmailMessage):
        """Analyze macros in Office documents"""
        self.advanced_forensic_data['macro_analysis'] = {}
        
        for part in msg.walk():
            if part.get_filename():
                filename = part.get_filename()
                content_bytes = part.get_payload(decode=True)
                
                if content_bytes:
                    macro_analysis = analyze_ole_macros(content_bytes)
                    self.advanced_forensic_data['macro_analysis'][filename] = macro_analysis
    
    def _analyze_magic_bytes(self, msg: email.message.EmailMessage):
        """Analyze magic bytes vs file extensions"""
        self.advanced_forensic_data['magic_bytes_analysis'] = {}
        
        for part in msg.walk():
            if part.get_filename():
                filename = part.get_filename()
                content_bytes = part.get_payload(decode=True)
                
                if content_bytes:
                    magic_type = get_magic_bytes(content_bytes)
                    ext = Path(filename).suffix.lower()
                    
                    analysis = {
                        'filename': filename,
                        'extension': ext,
                        'magic_type': magic_type,
                        'match': ext and magic_type.lower() in ext.lower() or magic_type == "unknown"
                    }
                    self.advanced_forensic_data['magic_bytes_analysis'][filename] = analysis
    
    def _analyze_message_id(self, msg: email.message.EmailMessage):
        """Analyze Message-ID for spoofing detection"""
        analysis = analyze_message_id_domain(msg)
        self.advanced_forensic_data['message_id_analysis'] = analysis
    
    def _analyze_anti_forgery(self, msg: email.message.EmailMessage):
        """Perform anti-forgery analysis"""
        self.tree_anti_forgery.clear()
        self.advanced_forensic_data['anti_forgery'] = {}
        
        checks = []
        
        # Message-ID domain analysis
        msg_id_analysis = self.advanced_forensic_data.get('message_id_analysis', {})
        if msg_id_analysis:
            check = {
                'check': 'Message-ID Domain Match',
                'result': 'PASS' if msg_id_analysis.get('domains_match') else 'FAIL',
                'details': f"Message-ID domain: {msg_id_analysis.get('message_id_domain')}, From domain: {msg_id_analysis.get('from_domain')}"
            }
            checks.append(check)
        
        # DKIM signature presence
        dkim_sig = msg.get('DKIM-Signature', '')
        check = {
            'check': 'DKIM Signature Present',
            'result': 'PASS' if dkim_sig else 'FAIL',
            'details': 'DKIM signature found' if dkim_sig else 'No DKIM signature'
        }
        checks.append(check)
        
        # Authentication-Results header
        auth_results = msg.get('Authentication-Results', '')
        check = {
            'check': 'Authentication Results Present',
            'result': 'PASS' if auth_results else 'FAIL',
            'details': 'Authentication-Results header found' if auth_results else 'No Authentication-Results header'
        }
        checks.append(check)
        
        # SPF validation (from Authentication-Results)
        if auth_results:
            spf_match = re.search(r'spf=([\w.]+)', auth_results, re.IGNORECASE)
            if spf_match:
                spf_result = spf_match.group(1)
                check = {
                    'check': 'SPF Validation',
                    'result': 'PASS' if spf_result.lower() in ['pass', 'none'] else 'FAIL',
                    'details': f'SPF result: {spf_result}'
                }
                checks.append(check)
        
        # DMARC validation (from Authentication-Results)
        if auth_results:
            dmarc_match = re.search(r'dmarc=([\w.]+)', auth_results, re.IGNORECASE)
            if dmarc_match:
                dmarc_result = dmarc_match.group(1)
                check = {
                    'check': 'DMARC Validation',
                    'result': 'PASS' if dmarc_result.lower() in ['pass', 'none'] else 'FAIL',
                    'details': f'DMARC result: {dmarc_result}'
                }
                checks.append(check)
        
        # Store all checks
        for check in checks:
            self.advanced_forensic_data['anti_forgery'][check['check']] = check
            
            # Add to tree
            item = QTreeWidgetItem()
            item.setText(0, check['check'])
            item.setText(1, check['result'])
            item.setText(2, check['details'][:100] + "..." if len(check['details']) > 100 else check['details'])
            self.tree_anti_forgery.addTopLevelItem(item)
    
    def _analyze_anti_forensics(self, msg: email.message.EmailMessage):
        """Comprehensive anti-forensics detection capabilities"""
        self.tree_anti_forensics.clear()
        self.advanced_forensic_data['anti_forensics'] = {}
        
        # First, perform anti-forgery analysis (existing functionality)
        self._analyze_anti_forgery(msg)
        
        # Add additional anti-forensics detection
        self._detect_anti_forensics_techniques(msg)
    
    def _detect_anti_forensics_techniques(self, msg: email.message.EmailMessage):
        """Detect specific anti-forensics techniques and indicators"""
        # Add anti-forensics indicators to the dedicated anti-forensics tree
        anti_forensics_checks = []
        
        # Check for header manipulation indicators
        anti_forensics_checks.extend(self._check_header_manipulation(msg))
        
        # Check for timestamp manipulation
        anti_forensics_checks.extend(self._check_timestamp_manipulation(msg))
        
        # Check for content obfuscation
        anti_forensics_checks.extend(self._check_content_obfuscation(msg))
        
        # Check for tracking and surveillance indicators
        anti_forensics_checks.extend(self._check_tracking_indicators(msg))
        
        # Check for metadata removal indicators
        anti_forensics_checks.extend(self._check_metadata_removal(msg))
        
        # Add anti-forensics checks to the dedicated tree
        for check in anti_forensics_checks:
            item = QTreeWidgetItem()
            item.setText(0, "Anti-Forensics")  # Detection Type
            item.setText(1, check['result'])    # Severity
            item.setText(2, check['check'])     # Indicator
            item.setText(3, check['details'][:100] + "..." if len(check['details']) > 100 else check['details'])  # Details
            self.tree_anti_forensics.addTopLevelItem(item)
            
            # Store in advanced forensic data
            self.advanced_forensic_data['anti_forensics'][check['check']] = check
    
    def _check_header_manipulation(self, msg: email.message.EmailMessage) -> list:
        """Check for header manipulation and anti-forensics indicators"""
        checks = []
        
        # Check for missing or unusual headers
        essential_headers = ['Date', 'From', 'To', 'Subject', 'Message-ID']
        missing_headers = [h for h in essential_headers if not msg.get(h)]
        
        if missing_headers:
            checks.append({
                'check': 'Missing Essential Headers',
                'result': 'WARNING',
                'details': f'Missing headers: {", ".join(missing_headers)}'
            })
        
        # Check for excessive Received headers (potential routing obfuscation)
        received_headers = msg.get_all('Received', [])
        if len(received_headers) > 10:
            checks.append({
                'check': 'Excessive Received Headers',
                'result': 'SUSPICIOUS',
                'details': f'Found {len(received_headers)} Received headers (potential routing obfuscation)'
            })
        
        # Check for unusual X-Headers that might indicate anti-forensics tools
        x_headers = [k for k in msg.keys() if k.startswith('X-')]
        suspicious_x_headers = [h for h in x_headers if any(keyword in h.lower() for keyword in 
                                ['track', 'spy', 'hide', 'anon', 'proxy', 'vpn', 'tor'])]
        
        if suspicious_x_headers:
            checks.append({
                'check': 'Suspicious X-Headers',
                'result': 'SUSPICIOUS',
                'details': f'Found suspicious X-Headers: {", ".join(suspicious_x_headers)}'
            })
        
        # Check for header inconsistencies
        from_header = msg.get('From', '')
        reply_to = msg.get('Reply-To', '')
        if reply_to and from_header.lower() != reply_to.lower():
            checks.append({
                'check': 'From/Reply-To Mismatch',
                'result': 'SUSPICIOUS',
                'details': f'From: {from_header}, Reply-To: {reply_to}'
            })
        
        return checks
    
    def _check_timestamp_manipulation(self, msg: email.message.EmailMessage) -> list:
        """Check for timestamp manipulation and anti-forensics indicators"""
        checks = []
        
        # Check for missing Date header
        date_header = msg.get('Date')
        if not date_header:
            checks.append({
                'check': 'Missing Date Header',
                'result': 'WARNING',
                'details': 'No Date header found (potential timestamp removal)'
            })
            return checks
        
        # Check for future-dated emails
        try:
            email_date = email.utils.parsedate_to_datetime(date_header)
            current_time = datetime.datetime.now(datetime.timezone.utc)
            
            if email_date > current_time + datetime.timedelta(hours=1):
                checks.append({
                    'check': 'Future-Dated Email',
                    'result': 'SUSPICIOUS',
                    'details': f'Email date {email_date} is in the future (current: {current_time})'
                })
            
            # Check for very old emails (potential backdating)
            if email_date < current_time - datetime.timedelta(days=365*5):  # 5 years
                checks.append({
                    'check': 'Extremely Old Email',
                    'result': 'SUSPICIOUS',
                    'details': f'Email date {email_date} is extremely old (potential backdating)'
                })
                
        except Exception as e:
            checks.append({
                'check': 'Invalid Date Format',
                'result': 'WARNING',
                'details': f'Date header parsing failed: {str(e)}'
            })
        
        # Check for inconsistent timestamps in Received headers
        received_headers = msg.get_all('Received', [])
        if len(received_headers) > 1:
            try:
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
                            'check': 'Timestamp Inconsistency',
                            'result': 'SUSPICIOUS',
                            'details': f'Received headers show non-chronological timestamps (potential manipulation)'
                        })
                        break
                        
            except Exception:
                pass  # Timestamp parsing failed
        
        return checks
    
    def _check_content_obfuscation(self, msg: email.message.EmailMessage) -> list:
        """Check for content obfuscation techniques"""
        checks = []
        
        # Check for excessive encoding/obfuscation in body
        body_text = ""
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        body_text += payload.decode('utf-8', errors='ignore')
                except:
                    continue
        
        # Check for excessive base64 encoding in text
        base64_pattern = r'[A-Za-z0-9+/=]{40,}'
        base64_matches = re.findall(base64_pattern, body_text)
        if len(base64_matches) > 3:
            checks.append({
                'check': 'Excessive Base64 Encoding',
                'result': 'SUSPICIOUS',
                'details': f'Found {len(base64_matches)} potential base64 encoded strings (possible obfuscation)'
            })
        
        # Check for hexadecimal encoding
        hex_pattern = r'[0-9a-fA-F]{8,}'
        hex_matches = re.findall(hex_pattern, body_text)
        if len(hex_matches) > 5:
            checks.append({
                'check': 'Excessive Hexadecimal Content',
                'result': 'SUSPICIOUS',
                'details': f'Found {len(hex_matches)} potential hexadecimal strings (possible obfuscation)'
            })
        
        # Check for unusual character sets
        for part in msg.walk():
            if part.get_content_type().startswith('text/'):
                charset = part.get_content_charset()
                if charset and charset.lower() in ['utf-7', 'utf-32', 'iso-2022-jp', 'iso-2022-kr']:
                    checks.append({
                        'check': 'Unusual Character Set',
                        'result': 'SUSPICIOUS',
                        'details': f'Part uses unusual character set: {charset} (potential obfuscation)'
                    })
        
        # Check for excessive whitespace or formatting anomalies
        if body_text:
            # Check for excessive line breaks
            line_breaks = body_text.count('\n')
            if line_breaks > len(body_text) / 10:  # More than 10% line breaks
                checks.append({
                    'check': 'Excessive Line Breaks',
                    'result': 'SUSPICIOUS',
                    'details': f'Found {line_breaks} line breaks (potential formatting obfuscation)'
                })
            
            # Check for unusual spacing patterns
            if re.search(r'[\s]{5,}', body_text):
                checks.append({
                    'check': 'Unusual Spacing Patterns',
                    'result': 'SUSPICIOUS',
                    'details': 'Found excessive whitespace patterns (potential steganography or obfuscation)'
                })
        
        return checks
    
    def _check_tracking_indicators(self, msg: email.message.EmailMessage) -> list:
        """Check for tracking and surveillance indicators"""
        checks = []
        
        # Extract all text content for analysis
        all_text = ""
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        all_text += payload.decode('utf-8', errors='ignore')
                except:
                    continue
            elif part.get_content_type() == "text/html":
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        all_text += payload.decode('utf-8', errors='ignore')
                except:
                    continue
        
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
            if re.search(pattern, all_text, re.IGNORECASE):
                checks.append({
                    'check': 'Tracking Pixel Detected',
                    'result': 'SUSPICIOUS',
                    'details': f'Found potential tracking pixel pattern: {pattern}'
                })
                break
        
        # Check for tracking parameters in URLs
        tracking_params = [
            'utm_', 'ga_', 'fbclid', 'gclid', 'msclkid', 'mc_eid',
            'tracking_id', 'track_id', 'user_id', 'session_id'
        ]
        
        urls = extract_urls(all_text)
        for url in urls:
            for param in tracking_params:
                if param in url.lower():
                    checks.append({
                        'check': 'Tracking Parameters',
                        'result': 'SUSPICIOUS',
                        'details': f'Found tracking parameter {param} in URL: {url[:50]}...'
                    })
                    break
        
        # Check for surveillance-related keywords
        surveillance_keywords = [
            'keylogger', 'spyware', 'monitor', 'surveillance', 'tracking',
            'beacon', 'analytics', 'telemetry', 'fingerprint', 'web bug'
        ]
        
        for keyword in surveillance_keywords:
            if keyword.lower() in all_text.lower():
                checks.append({
                    'check': 'Surveillance Keywords',
                    'result': 'SUSPICIOUS',
                    'details': f'Found surveillance-related keyword: {keyword}'
                })
        
        # Check for email read receipts
        if msg.get('Disposition-Notification-To') or msg.get('Return-Receipt-To'):
            checks.append({
                'check': 'Read Receipt Request',
                'result': 'INFO',
                'details': 'Email requests read receipt (tracking mechanism)'
            })
        
        return checks
    
    def _check_metadata_removal(self, msg: email.message.EmailMessage) -> list:
        """Check for indicators of metadata removal or sanitization"""
        checks = []
        
        # Check for missing User-Agent header (common in sanitized emails)
        user_agent = msg.get('User-Agent')
        if not user_agent:
            checks.append({
                'check': 'Missing User-Agent',
                'result': 'INFO',
                'details': 'No User-Agent header found (possible metadata removal)'
            })
        
        # Check for generic User-Agent strings
        generic_agents = ['Mozilla/5.0', 'Mozilla/4.0']
        if user_agent and any(agent in user_agent for agent in generic_agents):
            if len(user_agent) < 30:  # Very generic User-Agent
                checks.append({
                    'check': 'Generic User-Agent',
                    'result': 'INFO',
                    'details': f'Generic User-Agent: {user_agent} (possible sanitization)'
                })
        
        # Check for missing X-Mailer header
        x_mailer = msg.get('X-Mailer')
        if not x_mailer:
            checks.append({
                'check': 'Missing X-Mailer',
                'result': 'INFO',
                'details': 'No X-Mailer header found (possible metadata removal)'
            })
        
        # Check for missing organization headers
        org_headers = ['Organization', 'X-Originating-IP', 'X-Mailer-Version']
        missing_org = [h for h in org_headers if not msg.get(h)]
        if len(missing_org) >= 2:  # Multiple missing org headers
            checks.append({
                'check': 'Missing Organization Headers',
                'result': 'INFO',
                'details': f'Missing organization headers: {", ".join(missing_org)} (possible sanitization)'
            })
        
        # Check for suspiciously clean headers
        all_headers = list(msg.keys())
        if len(all_headers) < 8:  # Very few headers
            checks.append({
                'check': 'Minimal Header Set',
                'result': 'INFO',
                'details': f'Only {len(all_headers)} headers found (possible header sanitization)'
            })
        
        return checks
    
    def _analyze_virustotal(self, msg: email.message.EmailMessage, raw: bytes):
        """Analyze files with VirusTotal (if API key available)"""
        self.tree_virustotal.clear()
        self.advanced_forensic_data['virustotal_results'] = {}
        
        if not self.virustotal_api_key:
            # Add placeholder item
            item = QTreeWidgetItem()
            item.setText(0, "VirusTotal API")
            item.setText(1, "Not configured")
            item.setText(2, "Set API key to enable scanning")
            item.setText(3, "N/A")
            self.tree_virustotal.addTopLevelItem(item)
            return
        
        # Check main email file
        main_hash = hashlib.sha256(raw).hexdigest()
        vt_result = check_virustotal_hash(main_hash, self.virustotal_api_key)
        
        if 'error' not in vt_result:
            positives = vt_result.get('positives', 0)
            total = vt_result.get('total', 0)
            scan_date = vt_result.get('scan_date', 'Unknown')
            
            analysis = {
                'filename': 'email.eml',
                'hash': main_hash,
                'positives': positives,
                'total': total,
                'scan_date': scan_date,
                'permalink': vt_result.get('permalink', '')
            }
            self.advanced_forensic_data['virustotal_results']['email.eml'] = analysis
            
            # Add to tree
            item = QTreeWidgetItem()
            item.setText(0, 'email.eml')
            item.setText(1, main_hash[:16] + "...")
            item.setText(2, f"{positives}/{total} detections" if total > 0 else "Clean")
            item.setText(3, f"{positives}/{total}")
            self.tree_virustotal.addTopLevelItem(item)
        else:
            # Add error item
            item = QTreeWidgetItem()
            item.setText(0, 'email.eml')
            item.setText(1, main_hash[:16] + "...")
            item.setText(2, "API Error")
            item.setText(3, "N/A")
            self.tree_virustotal.addTopLevelItem(item)
        
        # Check attachments
        for part in msg.walk():
            if part.get_filename():
                filename = part.get_filename()
                content_bytes = part.get_payload(decode=True)
                
                if content_bytes and len(content_bytes) < 32 * 1024 * 1024:  # 32MB limit
                    attach_hash = hashlib.sha256(content_bytes).hexdigest()
                    vt_result = check_virustotal_hash(attach_hash, self.virustotal_api_key)
                    
                    if 'error' not in vt_result:
                        positives = vt_result.get('positives', 0)
                        total = vt_result.get('total', 0)
                        scan_date = vt_result.get('scan_date', 'Unknown')
                        
                        analysis = {
                            'filename': filename,
                            'hash': attach_hash,
                            'positives': positives,
                            'total': total,
                            'scan_date': scan_date,
                            'permalink': vt_result.get('permalink', '')
                        }
                        self.advanced_forensic_data['virustotal_results'][filename] = analysis
                        
                        # Add to tree
                        item = QTreeWidgetItem()
                        item.setText(0, filename)
                        item.setText(1, attach_hash[:16] + "...")
                        item.setText(2, f"{positives}/{total} detections" if total > 0 else "Clean")
                        item.setText(3, f"{positives}/{total}")
                        self.tree_virustotal.addTopLevelItem(item)
                    else:
                        # Add error item
                        item = QTreeWidgetItem()
                        item.setText(0, filename)
                        item.setText(1, attach_hash[:16] + "...")
                        item.setText(2, "API Error")
                        item.setText(3, "N/A")
                        self.tree_virustotal.addTopLevelItem(item)
    
    def set_virustotal_api_key(self, api_key: str):
        """Set VirusTotal API key"""
        self.virustotal_api_key = api_key
        QMessageBox.information(self, "API Key Set", "VirusTotal API key has been configured.")
    
    # -------------------------------------------------------------------------
    def export_forensic_report(self):
        """Export comprehensive forensic report"""
        if not self.current_msg:
            QMessageBox.warning(self, "No Data", "Please load an email first.")
            return
        
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Forensic Report", "forensic_report.json", "JSON files (*.json);;All files (*.*)")
        
        if not path:
            return
        
        try:
            report = {
                "forensic_report": {
                    "generated_at": datetime.datetime.now().isoformat(),
                    "generator": "Email Investigator - Forensic Edition",
                    "file_metadata": self.file_metadata,
                    "email_headers": dict(self.current_msg.items()),
                    "forensic_analysis": {
                        "iocs": {
                            "urls": self.forensic_data['urls'],
                            "email_addresses": self.forensic_data['emails'],
                            "ip_addresses": self.forensic_data['ips']
                        },
                        "received_headers": self.forensic_data['received_hops'],
                        "authentication": {
                            "authentication_results": self.forensic_data['authentication'],
                            "dkim_signature": self.forensic_data['dkim']
                        },
                        "anomalies": {
                            "time_anomalies": self.forensic_data['time_anomalies'],
                            "header_anomalies": []
                        }
                    },
                    "attachments": [
                        {
                            "filename": name,
                            "content_type": ctype,
                            "size": len(data),
                            "md5": hash_bytes(data, "md5"),
                            "sha256": hash_bytes(data, "sha256")
                        }
                        for name, ctype, data in self.current_attachments
                    ]
                }
            }
            
            # Add header anomalies
            essential_headers = ["From", "Date", "Message-ID"]
            for header in essential_headers:
                if not self.current_msg.get(header):
                    report["forensic_report"]["forensic_analysis"]["anomalies"]["header_anomalies"].append(
                        f"Missing essential header: {header}"
                    )
            
            if not self.current_msg.get_all("Received", []):
                report["forensic_report"]["forensic_analysis"]["anomalies"]["header_anomalies"].append(
                    "Missing Received headers - possible header stripping"
                )
            
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            
            self.status.setText(f"Forensic report exported: {Path(path).name}")
            QMessageBox.information(self, "Export Complete", f"Forensic report saved to:\n{path}")
            
        except Exception as exc:
            QMessageBox.critical(self, "Export Error", f"Failed to export report:\n{str(exc)}")
    
    def edit_chain_of_custody(self):
        """Open chain of custody dialog"""
        dialog = ChainOfCustodyDialog(self, self.file_metadata['chain_of_custody'])
        if dialog.exec_() == QDialog.Accepted:
            # Update chain of custody data
            custody_data = dialog.get_data()
            self.file_metadata['chain_of_custody'].update(custody_data)
            
            # Add to custody history
            history_entry = {
                'timestamp': datetime.datetime.now().isoformat(),
                'action': 'custody_documented',
                'analyst': custody_data['analyst'],
                'case_number': custody_data['case_number'],
                'exhibit_number': custody_data['exhibit_number']
            }
            self.file_metadata['chain_of_custody']['custody_history'].append(history_entry)
            
            # Refresh the file metadata display
            self._populate_file_metadata()
            
            self.status.setText("Chain of custody documentation updated")


# ---------- entry point ------------------------------------------------------
if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = MailInvestigator()
    win.show()
    sys.exit(app.exec_())