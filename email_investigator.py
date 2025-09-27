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
    import ssdeep
    SSDEEP_AVAILABLE = True
except ImportError:
    SSDEEP_AVAILABLE = False
    print("Warning: ssdeep not available. Fuzzy hashing disabled.")

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
                             QMessageBox, QGroupBox, QTabWidget, QHeaderView, QMenu)
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


# ---------- advanced forensic helpers ---------------------------------------
def hash_ssdeep(data: bytes) -> str:
    """Generate SSDEEP fuzzy hash if available"""
    if SSDEEP_AVAILABLE:
        try:
            return ssdeep.hash(data)
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
            'md5': None,
            'acquisition_time': None,
            'acquisition_method': None
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
        toolbar.addWidget(btn_open)
        toolbar.addWidget(btn_paste)
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

        # extra headers
        extra = QTreeWidgetItem(root)
        extra.setText(0, "Other")
        for key, val in msg.items():
            if key not in {"From", "To", "Cc", "Bcc", "Date", "Subject",
                           "Message-ID", "Reply-To", "Return-Path"}:
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
        
        metadata_items = [
            ("Filename", self.file_metadata['filename'] or "null"),
            ("File Size", f"{self.file_metadata['filesize']} bytes ({human_bytes(self.file_metadata['filesize'])})" if self.file_metadata['filesize'] else "null"),
            ("MD5", self.file_metadata['md5'] or "null"),
            ("SHA-256", self.file_metadata['sha256'] or "null"),
            ("Acquisition Time", self.file_metadata['acquisition_time'] or "null"),
            ("Acquisition Method", self.file_metadata['acquisition_method'] or "null")
        ]
        
        for key, value in metadata_items:
            item = QTreeWidgetItem()
            item.setText(0, key)
            item.setText(1, str(value))
            self.tree_file_meta.addTopLevelItem(item)
    
    # -------------------------------------------------------------------------
    def _populate_forensic_analysis(self, msg: email.message.EmailMessage):
        """Populate all forensic analysis tabs"""
        # Extract and analyze all forensic data
        self._extract_iocs(msg)
        self._analyze_received_headers(msg)
        self._analyze_authentication(msg)
        self._detect_anomalies(msg)
    
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
                
                # SSDEEP fuzzy hashing
                ssdeep_hash = hash_ssdeep(content_bytes)
                
                # Password protection detection
                protection = detect_password_protection(content_bytes, filename)
                
                # Macro analysis
                macro_analysis = analyze_ole_macros(content_bytes)
                
                analysis = {
                    'filename': filename,
                    'magic_type': magic_type,
                    'extension_match': ext_match,
                    'ssdeep': ssdeep_hash,
                    'is_protected': protection['is_protected'],
                    'protection_type': protection['protection_type'],
                    'has_macros': macro_analysis.get('has_macros', False),
                    'macro_count': macro_analysis.get('macro_count', 0)
                }
                self.advanced_forensic_data['attachment_analysis'].append(analysis)
                
                # Add to tree
                item = QTreeWidgetItem()
                item.setText(0, filename)
                item.setText(1, magic_type)
                item.setText(2, ext_match)
                item.setText(3, ssdeep_hash[:16] + "..." if ssdeep_hash != "null" else "N/A")
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


# ---------- entry point ------------------------------------------------------
if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = MailInvestigator()
    win.show()
    sys.exit(app.exec_())