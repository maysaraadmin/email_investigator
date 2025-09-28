#!/usr/bin/env python3
"""
Main email investigator application.
"""

import sys
import traceback
from pathlib import Path
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QSplitter, QTextEdit, QTreeWidget,
                             QTreeWidgetItem, QPushButton, QLabel, QFileDialog,
                             QTabWidget, QHeaderView, QMenu, QProgressBar,
                             QStatusBar, QLineEdit, QDialog, QFormLayout,
                             QDialogButtonBox, QMessageBox, QInputDialog,
                             QShortcut, QMenuBar)
from PyQt5.QtCore import Qt, QMimeData, QTimer, QSize
from PyQt5.QtGui import QFont, QClipboard, QKeySequence, QDragEnterEvent, QDropEvent

# Import our modular components
from forensics.core import hash_bytes, human_bytes
from forensics.email_parser import EmailParser, FileMetadata
from forensics.analysis.attachments import AttachmentAnalyzer
from forensics.analysis.anti_forensics import AntiForensicsAnalyzer
from forensics.analysis.network import NetworkAnalyzer
from ui.components import ChainOfCustodyDialog
from ui.styles import ThemeManager, IconManager
from utils.constants import Constants, MessageBoxHelper


class MailInvestigator(QMainWindow):
    """Main email investigator application window."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle(Constants.WINDOW_TITLE)
        self.resize(Constants.WINDOW_WIDTH, Constants.WINDOW_HEIGHT)

        # Initialize data storage
        self.current_msg = None
        self.current_attachments = []
        self.file_metadata = {}
        self.forensic_data = {}
        self.advanced_forensic_data = {}

        # Initialize analyzers
        self.attachment_analyzer = None
        self.anti_forensics_analyzer = None
        self.network_analyzer = None

        # UI enhancements
        self.progress_bar = None
        self.search_boxes = {}
        self.recent_files = []

        # Apply theme
        self._apply_theme()

        # Build enhanced UI
        self._build_ui()

        # Setup drag and drop
        self._setup_drag_drop()

        # Setup keyboard shortcuts
        self._setup_shortcuts()

    def _apply_theme(self):
        """Apply professional dark theme to the application."""
        # Apply dark theme to the application
        ThemeManager.apply_dark_theme(QApplication.instance())

        # Set window properties
        self.setStyleSheet(f"""
        {ThemeManager.get_button_style()}
        {ThemeManager.get_tree_style()}
        {ThemeManager.get_tab_style()}
        """)

    def _setup_drag_drop(self):
        """Setup drag and drop functionality."""
        self.setAcceptDrops(True)

    def _setup_shortcuts(self):
        """Setup keyboard shortcuts."""
        # Ctrl+O for open file
        open_shortcut = QShortcut(QKeySequence("Ctrl+O"), self)
        open_shortcut.activated.connect(self.open_eml)

        # Ctrl+E for export
        export_shortcut = QShortcut(QKeySequence("Ctrl+E"), self)
        export_shortcut.activated.connect(self.export_forensic_report)

        # F1 for help
        help_shortcut = QShortcut(QKeySequence("F1"), self)
        help_shortcut.activated.connect(self.show_help)

        # Ctrl+F for search
        search_shortcut = QShortcut(QKeySequence("Ctrl+F"), self)
        search_shortcut.activated.connect(self.focus_search)

    def _build_ui(self):
        """Build the main user interface."""
        central = QWidget()
        self.setCentralWidget(central)
        lay = QVBoxLayout(central)

        # Menu bar
        self._create_menu_bar()

        # Top toolbar
        toolbar = self._create_toolbar()
        lay.addLayout(toolbar)

        # Main horizontal splitter
        splitter = QSplitter(Qt.Horizontal)
        lay.addWidget(splitter)

        # Left: tree with headers / parts
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Field", "Value"])
        self.tree.header().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        splitter.addWidget(self.tree)

        # Right: notebook with analysis tabs
        self.nb = self._create_analysis_tabs()
        splitter.addWidget(self.nb)

        # Configure splitter
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 2)

        # Enhanced status bar
        self._create_status_bar()

    def _create_menu_bar(self):
        """Create the menu bar."""
        menubar = self.menuBar()

        # File menu
        file_menu = menubar.addMenu('&File')

        open_action = file_menu.addAction(f'&Open .eml File\tCtrl+O')
        open_action.triggered.connect(self.open_eml)
        open_action.setToolTip('Open an email file for analysis')

        file_menu.addSeparator()

        export_action = file_menu.addAction('&Export Report\tCtrl+E')
        export_action.triggered.connect(self.export_forensic_report)
        export_action.setToolTip('Export forensic analysis report')

        file_menu.addSeparator()

        exit_action = file_menu.addAction('E&xit')
        exit_action.triggered.connect(self.close)
        exit_action.setToolTip('Exit the application')

        # Edit menu
        edit_menu = menubar.addMenu('&Edit')

        custody_action = edit_menu.addAction('&Chain of Custody')
        custody_action.triggered.connect(self.edit_chain_of_custody)
        custody_action.setToolTip('Document chain of custody information')

        # View menu
        view_menu = menubar.addMenu('&View')

        search_action = view_menu.addAction('&Search\tCtrl+F')
        search_action.triggered.connect(self.focus_search)
        search_action.setToolTip('Search in current tab')

        # Help menu
        help_menu = menubar.addMenu('&Help')

        help_action = help_menu.addAction('&Help\tF1')
        help_action.triggered.connect(self.show_help)
        help_action.setToolTip('Show help information')

        about_action = help_menu.addAction('&About')
        about_action.triggered.connect(self.show_about)
        about_action.setToolTip('About this application')

    def _create_toolbar(self) -> QHBoxLayout:
        """Create the top toolbar."""
        toolbar = QHBoxLayout()

        # Open file button
        btn_open = QPushButton(f"{IconManager.get_icon('open')} Open .eml File")
        btn_open.clicked.connect(self.open_eml)
        btn_open.setToolTip('Open an email file for analysis (Ctrl+O)')
        btn_open.setMinimumHeight(32)
        toolbar.addWidget(btn_open)

        # Parse clipboard button
        btn_paste = QPushButton(f"{IconManager.get_icon('clipboard')} Parse Clipboard")
        btn_paste.clicked.connect(self.parse_clipboard)
        btn_paste.setToolTip('Parse email content from clipboard')
        btn_paste.setMinimumHeight(32)
        toolbar.addWidget(btn_paste)

        # Export report button
        btn_export = QPushButton(f"{IconManager.get_icon('export')} Export Report")
        btn_export.clicked.connect(self.export_forensic_report)
        btn_export.setToolTip('Export forensic analysis report (Ctrl+E)')
        btn_export.setMinimumHeight(32)
        toolbar.addWidget(btn_export)

        # Chain of custody button
        btn_custody = QPushButton(f"{IconManager.get_icon('custody')} Chain of Custody")
        btn_custody.clicked.connect(self.edit_chain_of_custody)
        btn_custody.setToolTip('Document chain of custody information')
        btn_custody.setMinimumHeight(32)
        toolbar.addWidget(btn_custody)

        toolbar.addStretch()
        return toolbar

    def _create_analysis_tabs(self) -> QTabWidget:
        """Create the analysis tabs with organized groups."""
        nb = QTabWidget()

        # 1. Content Analysis Tab
        content_tab = self._create_content_tab()
        nb.addTab(content_tab, f"{IconManager.get_icon('info')} Content")

        # 2. Attachments Tab
        self.attach_list = QTreeWidget()
        self.attach_list.setHeaderLabels(["Name", "Content-Type", "Size", "MD5", "SHA-256"])
        self.attach_list.setRootIsDecorated(False)
        self.attach_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.attach_list.customContextMenuRequested.connect(self._attach_context)
        nb.addTab(self.attach_list, f"{IconManager.get_icon('open')} Attachments")

        # 3. Forensics Analysis Tab
        forensics_tab = self._create_forensics_tab()
        nb.addTab(forensics_tab, f"{IconManager.get_icon('search')} Forensics")

        # 4. Security Analysis Tab
        security_tab = self._create_security_tab()
        nb.addTab(security_tab, f"{IconManager.get_icon('warning')} Security")

        # 5. Network Intelligence Tab
        network_tab = self._create_network_tab()
        nb.addTab(network_tab, f"{IconManager.get_icon('info')} Network")

        return nb

    def _create_content_tab(self) -> QWidget:
        """Create tab for basic email content."""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Create sub-tabs for content
        content_tabs = QTabWidget()

        # Plain text tab
        self.txt_plain = QTextEdit()
        self.txt_plain.setReadOnly(True)
        self.txt_plain.setFont(QFont("Consolas", 9))
        content_tabs.addTab(self.txt_plain, "Plain Text")

        # HTML source tab
        self.txt_html = QTextEdit()
        self.txt_html.setReadOnly(True)
        content_tabs.addTab(self.txt_html, "HTML Source")

        # Enhanced raw headers tab
        headers_widget = self._create_enhanced_headers_display()
        content_tabs.addTab(headers_widget, "Raw Headers")

        layout.addWidget(content_tabs)
        return tab

    def _create_forensics_tab(self) -> QWidget:
        """Create tab for forensic analysis."""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Create sub-tabs for forensics
        forensics_tabs = QTabWidget()

        # File metadata tab
        self.tree_file_meta = QTreeWidget()
        self.tree_file_meta.setHeaderLabels(["Property", "Value"])
        self.tree_file_meta.setRootIsDecorated(False)
        forensics_tabs.addTab(self.tree_file_meta, "File Metadata")

        # Received headers tab
        self.tree_received = QTreeWidget()
        self.tree_received.setHeaderLabels(["Hop", "From", "By", "IP", "Timestamp", "ID"])
        self.tree_received.setRootIsDecorated(False)
        forensics_tabs.addTab(self.tree_received, "Received Headers")

        # Authentication tab
        self.tree_auth = QTreeWidget()
        self.tree_auth.setHeaderLabels(["Authentication", "Result"])
        self.tree_auth.setRootIsDecorated(False)
        forensics_tabs.addTab(self.tree_auth, "Authentication")

        layout.addWidget(forensics_tabs)
        return tab

    def _create_security_tab(self) -> QWidget:
        """Create tab for security analysis."""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Create sub-tabs for security
        security_tabs = QTabWidget()

        # IOCs tab
        self.tree_iocs = QTreeWidget()
        self.tree_iocs.setHeaderLabels(["Type", "Value"])
        self.tree_iocs.setRootIsDecorated(False)
        security_tabs.addTab(self.tree_iocs, "IOCs")

        # Anomalies tab
        self.tree_anomalies = QTreeWidget()
        self.tree_anomalies.setHeaderLabels(["Anomaly Type", "Description"])
        self.tree_anomalies.setRootIsDecorated(False)
        security_tabs.addTab(self.tree_anomalies, "Anomalies")

        # Anti-forensics tab
        self.tree_anti_forensics = QTreeWidget()
        self.tree_anti_forensics.setHeaderLabels(["Detection Type", "Severity", "Indicator", "Details"])
        self.tree_anti_forensics.setRootIsDecorated(False)
        security_tabs.addTab(self.tree_anti_forensics, "Anti-Forensics")

        layout.addWidget(security_tabs)
        return tab

    def _create_network_tab(self) -> QWidget:
        """Create tab for network intelligence."""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Network pivots tree
        self.tree_network = QTreeWidget()
        self.tree_network.setHeaderLabels(["Indicator", "Type", "Network Intelligence"])
        self.tree_network.setRootIsDecorated(False)

        layout.addWidget(self.tree_network)
        return tab

    def _create_enhanced_headers_display(self) -> QWidget:
        """Create enhanced headers display widget."""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Create splitter for headers tree and raw text
        splitter = QSplitter(Qt.Vertical)

        # Headers tree widget
        self.headers_tree = QTreeWidget()
        self.headers_tree.setHeaderLabels(["Header", "Value"])
        self.headers_tree.setRootIsDecorated(True)
        self.headers_tree.setAlternatingRowColors(True)
        splitter.addWidget(self.headers_tree)

        # Raw headers text (collapsible)
        raw_container = QWidget()
        raw_layout = QVBoxLayout(raw_container)

        self.raw_headers_toggle = QPushButton("Show Raw Headers")
        self.raw_headers_toggle.setCheckable(True)
        self.raw_headers_toggle.clicked.connect(self._toggle_raw_headers)
        raw_layout.addWidget(self.raw_headers_toggle)

        self.txt_raw = QTextEdit()
        self.txt_raw.setReadOnly(True)
        self.txt_raw.setFont(QFont("Consolas", 10))  # Increased from 8 to 10
        self.txt_raw.setVisible(False)
        self.txt_raw.setMinimumHeight(150)  # Minimum height for readability
        self.txt_raw.setMaximumHeight(400)  # Increased from 200 to 400
        raw_layout.addWidget(self.txt_raw)

        splitter.addWidget(raw_container)

        # Set splitter proportions
        splitter.setStretchFactor(0, 2)  # Tree gets more space
        splitter.setStretchFactor(1, 1)  # Raw text gets less space

        layout.addWidget(splitter)
        return widget

    def _toggle_raw_headers(self):
        """Toggle raw headers visibility."""
        if self.raw_headers_toggle.isChecked():
            self.txt_raw.setVisible(True)
            self.raw_headers_toggle.setText("Hide Raw Headers")
        else:
            self.txt_raw.setVisible(False)
            self.raw_headers_toggle.setText("Show Raw Headers")

    def _populate_headers_tree(self, msg):
        """Populate headers tree with organized structure."""
        self.headers_tree.clear()

        # Define header categories
        header_categories = {
            "Core Headers": [
                "Return-Path", "Received", "Message-ID", "Date", "From", "Sender",
                "Reply-To", "To", "Cc", "Bcc", "Subject", "In-Reply-To", "References"
            ],
            "Transport Metadata": [
                "X-Mailer", "User-Agent", "X-Originating-IP", "X-Originating-Time",
                "X-Priority", "X-MSMail-Priority", "Thread-Index", "Thread-Topic"
            ],
            "Authentication": [
                "Authentication-Results", "DKIM-Signature", "ARC-Authentication-Results",
                "ARC-Message-Signature", "ARC-Seal", "SPF", "DMARC"
            ],
            "Content Headers": [
                "MIME-Version", "Content-Type", "Content-Transfer-Encoding",
                "Content-Disposition", "Content-Description", "Content-Language"
            ],
            "Security Headers": [
                "List-ID", "List-Unsubscribe", "List-Post", "List-Archive",
                "X-Spam-Flag", "X-Spam-Score", "X-Virus-Scanned"
            ],
            "Other Headers": []
        }

        # Create category items
        category_items = {}
        for category_name in header_categories.keys():
            category_item = QTreeWidgetItem(self.headers_tree)
            category_item.setText(0, category_name)
            category_item.setExpanded(True)
            category_items[category_name] = category_item

        # Add headers to appropriate categories
        for key, value in msg.items():
            header_name = key
            header_value = str(value) if value else "null"

            # Find appropriate category
            placed = False
            for category_name, headers_list in header_categories.items():
                if header_name in headers_list:
                    self._add_header_to_category(category_items[category_name], header_name, header_value)
                    placed = True
                    break

            # Add to "Other Headers" if not categorized
            if not placed:
                self._add_header_to_category(category_items["Other Headers"], header_name, header_value)

    def _add_header_to_category(self, category_item, header_name, header_value):
        """Add a header to a category."""
        header_item = QTreeWidgetItem(category_item)
        header_item.setText(0, header_name)

        # Truncate very long values for display
        if len(header_value) > 200:
            display_value = header_value[:200] + "... [truncated]"
        else:
            display_value = header_value

        header_item.setText(1, display_value)

        # Store full value as tooltip
        header_item.setToolTip(1, header_value.strip())

    def _format_raw_headers(self, msg):
        """Format raw headers for better readability."""
        formatted = []
        formatted.append("=" * 60)
        formatted.append("RAW EMAIL HEADERS")
        formatted.append("=" * 60)
        formatted.append("")

        # Group headers by functionality
        core_headers = []
        received_headers = []
        auth_headers = []
        other_headers = []

        # Use msg.keys() and msg.get() to access headers
        for key in msg.keys():
            value = msg.get(key, "")

            if key.lower() in ['from', 'to', 'cc', 'bcc', 'subject', 'date', 'message-id']:
                core_headers.append(f"{key}: {value}")
            elif key.lower() == 'received':
                received_headers.append(f"{key}: {value}")
            elif key.lower() in ['authentication-results', 'dkim-signature', 'spf', 'dmarc']:
                auth_headers.append(f"{key}: {value}")
            else:
                other_headers.append(f"{key}: {value}")

        # Add sections with clear separation
        if core_headers:
            formatted.append("CORE HEADERS:")
            formatted.append("-" * 40)
            formatted.extend(core_headers)
            formatted.append("")

        if received_headers:
            formatted.append("RECEIVED HEADERS:")
            formatted.append("-" * 40)
            formatted.extend(received_headers)
            formatted.append("")

        if auth_headers:
            formatted.append("AUTHENTICATION HEADERS:")
            formatted.append("-" * 40)
            formatted.extend(auth_headers)
            formatted.append("")

        if other_headers:
            formatted.append("OTHER HEADERS:")
            formatted.append("-" * 40)
            formatted.extend(other_headers)
            formatted.append("")

        formatted.append("=" * 60)
        formatted.append("END OF HEADERS")
        formatted.append("=" * 60)

        return "\n".join(formatted)

    def parse_clipboard(self):
        """Parse email content from clipboard."""
        clip = QApplication.clipboard()
        raw = clip.text(mode=QClipboard.Clipboard).encode("utf-8", errors="replace")

        if not raw.strip():
            MessageBoxHelper.show_warning(self, "Nothing to do", "Clipboard is empty.")
            return

        try:
            # Extract file metadata for clipboard content
            file_meta = FileMetadata(raw_bytes=raw)
            file_meta.extract_metadata()
            self.file_metadata = file_meta.get_metadata()

            # Parse email
            self._parse_email(raw)
            self.status_label.setText("Parsed from clipboard")

        except Exception as exc:
            MessageBoxHelper.show_error(self, "Parse error", traceback.format_exc())

    def _validate_file(self, filepath: str) -> tuple:
        """Validate the email file."""
        return FileValidator.validate_email_file(filepath)

    def _parse_email(self, raw: bytes):
        """Parse the email and populate all analysis tabs."""
        # Parse email
        parser = EmailParser(raw)
        if not parser.parse():
            raise Exception("Failed to parse email")

        self.current_msg = parser.message
        self.current_attachments = parser.attachments

        # Populate basic UI elements
        self._populate_tree(parser.message)
        self._populate_body(parser.message)
        self._populate_raw(parser.message)
        self._populate_attachments()

        # Populate forensic analysis
        self._populate_file_metadata()
        self._populate_forensic_analysis(parser)

    def _populate_tree(self, msg):
        """Populate the headers tree."""
        self.tree.clear()
        root = QTreeWidgetItem(self.tree)
        root.setText(0, "Headers")

        def add(parent, key, val):
            item = QTreeWidgetItem(parent)
            item.setText(0, key)
            item.setText(1, val)

        # Basic headers
        for key in ["From", "To", "Cc", "Bcc", "Date", "Subject",
                    "Message-ID", "Reply-To", "Return-Path"]:
            val = msg.get(key)
            if val:
                add(root, key, str(val))

        # Transport metadata headers
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

        # Extra headers
        extra = QTreeWidgetItem(root)
        extra.setText(0, "Other")

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

    def _populate_body(self, msg):
        """Populate body text tabs."""
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

        # Update the enhanced headers display
        self._populate_raw(msg)

    def _populate_raw(self, msg):
        """Populate raw headers tab with enhanced formatting."""
        # Format raw headers for better readability
        formatted_headers = self._format_raw_headers(msg)
        self.txt_raw.setPlainText(formatted_headers)

    def _populate_attachments(self):
        """Populate attachments tab."""
        self.attach_list.clear()
        for attachment in self.current_attachments:
            item = QTreeWidgetItem()
            item.setText(0, attachment['name'])
            item.setText(1, attachment['content_type'])
            item.setText(2, human_bytes(attachment['size']))
            item.setText(3, attachment['md5'])
            item.setText(4, attachment['sha256'])
            item.setData(0, Qt.UserRole, attachment['data'])  # store bytes
            self.attach_list.addTopLevelItem(item)

    def _populate_file_metadata(self):
        """Populate the file metadata tab."""
        self.tree_file_meta.clear()

        # Basic file metadata
        metadata_items = [
            ("Filename", self.file_metadata.get('filename', 'null')),
            ("File Size", f"{self.file_metadata.get('filesize', 0)} bytes ({human_bytes(self.file_metadata.get('filesize', 0))})"),
            ("MD5", self.file_metadata.get('md5', 'null')),
            ("SHA-1", self.file_metadata.get('sha1', 'null')),
            ("SHA-256", self.file_metadata.get('sha256', 'null')),
            ("Acquisition Time", self.file_metadata.get('acquisition_time', 'null')),
            ("Acquisition Method", self.file_metadata.get('acquisition_method', 'null'))
        ]

        for key, value in metadata_items:
            item = QTreeWidgetItem()
            item.setText(0, key)
            item.setText(1, str(value))
            self.tree_file_meta.addTopLevelItem(item)

        # Chain of custody information
        custody = self.file_metadata.get('chain_of_custody', {})
        if any(custody.values()):
            # Add separator
            separator = QTreeWidgetItem()
            separator.setText(0, "--- Chain of Custody ---")
            separator.setText(1, "")
            self.tree_file_meta.addTopLevelItem(separator)

            custody_items = [
                ("Analyst", custody.get('analyst', 'null')),
                ("Case Number", custody.get('case_number', 'null')),
                ("Exhibit Number", custody.get('exhibit_number', 'null')),
                ("Seal Number", custody.get('seal_number', 'null')),
                ("Notes", custody.get('notes', 'null')[:50] + "..." if len(custody.get('notes', "")) > 50 else custody.get('notes', 'null'))
            ]

            for key, value in custody_items:
                item = QTreeWidgetItem()
                item.setText(0, key)
                item.setText(1, str(value))
                self.tree_file_meta.addTopLevelItem(item)

    def _populate_forensic_analysis(self, parser: EmailParser):
        """Populate forensic analysis tabs."""
        # Extract IOCs
        self._populate_iocs(parser.get_iocs())

        # Analyze received headers
        self._populate_received_headers(parser.get_received_headers())

        # Analyze authentication
        self._populate_authentication(parser.get_authentication_results())

        # Detect anomalies
        self._populate_anomalies(parser)

        # Network analysis
        self._populate_network_analysis()

        # Anti-forensics analysis
        self._populate_anti_forensics_analysis()

    def _populate_iocs(self, iocs: dict):
        """Populate IOCs tab."""
        self.tree_iocs.clear()

        # URLs
        for url in iocs['urls']:
            item = QTreeWidgetItem()
            item.setText(0, "URL")
            item.setText(1, url)
            self.tree_iocs.addTopLevelItem(item)

        # Email addresses
        for email in iocs['emails']:
            item = QTreeWidgetItem()
            item.setText(0, "Email")
            item.setText(1, email)
            self.tree_iocs.addTopLevelItem(item)

        # IP addresses
        for ip in iocs['ips']:
            item = QTreeWidgetItem()
            item.setText(0, "IP Address")
            item.setText(1, ip)
            self.tree_iocs.addTopLevelItem(item)

    def _populate_received_headers(self, received_headers: list):
        """Populate received headers tab."""
        self.tree_received.clear()

        if not received_headers:
            item = QTreeWidgetItem()
            item.setText(0, "No Received headers found")
            self.tree_received.addTopLevelItem(item)
            return

        for i, hop in enumerate(reversed(received_headers)):  # Reverse to show chronological order
            item = QTreeWidgetItem()
            item.setText(0, str(i + 1))
            item.setText(1, hop['from'] or "null")
            item.setText(2, hop['by'] or "null")
            item.setText(3, hop['ip'] or "null")
            item.setText(4, hop['timestamp'] or "null")
            item.setText(5, hop['id'] or "null")
            self.tree_received.addTopLevelItem(item)

    def _populate_authentication(self, auth_results: dict):
        """Populate authentication tab."""
        self.tree_auth.clear()

        auth_items = [
            ("SPF", auth_results['authentication_results'].get('spf', 'null')),
            ("DKIM", auth_results['authentication_results'].get('dkim', 'null')),
            ("DMARC", auth_results['authentication_results'].get('dmarc', 'null'))
        ]

        for auth_type, result in auth_items:
            item = QTreeWidgetItem()
            item.setText(0, auth_type)
            item.setText(1, result)
            self.tree_auth.addTopLevelItem(item)

        dkim_items = [
            ("DKIM Version", auth_results['dkim_signature'].get('version', 'null')),
            ("DKIM Algorithm", auth_results['dkim_signature'].get('algorithm', 'null')),
            ("DKIM Domain", auth_results['dkim_signature'].get('domain', 'null')),
            ("DKIM Selector", auth_results['dkim_signature'].get('selector', 'null'))
        ]

        for dkim_key, dkim_value in dkim_items:
            item = QTreeWidgetItem()
            item.setText(0, dkim_key)
            item.setText(1, dkim_value)
            self.tree_auth.addTopLevelItem(item)

    def _populate_anomalies(self, parser: EmailParser):
        """Populate anomalies tab."""
        self.tree_anomalies.clear()

        # Time anomalies
        time_anomalies = parser.get_time_anomalies()
        for anomaly in time_anomalies:
            item = QTreeWidgetItem()
            item.setText(0, "Time Anomaly")
            item.setText(1, anomaly)
            self.tree_anomalies.addTopLevelItem(item)

        # Header anomalies
        if not parser.get_received_headers():
            item = QTreeWidgetItem()
            item.setText(0, "Header Anomaly")
            item.setText(1, "Missing Received headers - possible header stripping")
            self.tree_anomalies.addTopLevelItem(item)

        # Check for missing essential headers
        essential_headers = ["From", "Date", "Message-ID"]
        for header in essential_headers:
            if not self.current_msg.get(header):
                item = QTreeWidgetItem()
                item.setText(0, "Header Anomaly")
                item.setText(1, f"Missing essential header: {header}")
                self.tree_anomalies.addTopLevelItem(item)

    def _populate_network_analysis(self):
        """Populate network analysis tab."""
        if not self.current_msg:
            return

        # Initialize network analyzer
        all_text = self.txt_plain.toPlainText() + ' ' + self.txt_html.toPlainText()
        self.network_analyzer = NetworkAnalyzer(self.current_msg, all_text)
        self.network_analyzer.extract_indicators()
        analysis_results = self.network_analyzer.analyze_indicators()

        # Populate network tab
        self.tree_network.clear()
        for result in analysis_results:
            item = QTreeWidgetItem()
            item.setText(0, result['indicator'])
            item.setText(1, result['type'])

            # Analysis details
            analysis_parts = []
            for key, value in result['analysis'].items():
                if key not in ['warning', 'error']:  # These go in separate logic
                    analysis_parts.append(f"{key}: {value}")

            if 'warning' in result['analysis']:
                analysis_parts.append(f"WARNING: {result['analysis']['warning']}")

            item.setText(2, " | ".join(analysis_parts))
            self.tree_network.addTopLevelItem(item)

    def _populate_anti_forensics_analysis(self):
        """Populate anti-forensics analysis tab."""
        if not self.current_msg:
            return

        # Initialize anti-forensics analyzer
        all_text = self.txt_plain.toPlainText() + ' ' + self.txt_html.toPlainText()
        self.anti_forensics_analyzer = AntiForensicsAnalyzer(self.current_msg, all_text)
        detections = self.anti_forensics_analyzer.analyze()

        # Populate anti-forensics tab
        self.tree_anti_forensics.clear()
        for detection in detections:
            item = QTreeWidgetItem()
            item.setText(0, detection['type'])
            item.setText(1, detection['severity'])
            item.setText(2, detection['indicator'])
            item.setText(3, detection['details'][:100] + "..." if len(detection['details']) > 100 else detection['details'])
            self.tree_anti_forensics.addTopLevelItem(item)

    def _attach_context(self, pos):
        """Handle attachment context menu."""
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
                    self.status_label.setText(f"Saved: {Path(path).name}")

        elif action == copy_md5:
            QApplication.clipboard().setText(item.text(3))
        elif action == copy_sha:
            QApplication.clipboard().setText(item.text(4))

    def export_forensic_report(self):
        """Export comprehensive forensic report."""
        if not self.current_msg:
            MessageBoxHelper.show_warning(self, "No Data", "Please load an email first.")
            return

        path, _ = QFileDialog.getSaveFileName(
            self, "Export Forensic Report", "forensic_report.json",
            "JSON files (*.json);;All files (*.*)"
        )

        if not path:
            return

        # Prepare report data
        report_data = {
            "file_metadata": self.file_metadata,
            "email_headers": dict(self.current_msg.items()),
            "iocs": {
                "urls": [item.text(1) for item in self._get_tree_items(self.tree_iocs) if item.text(0) == "URL"],
                "emails": [item.text(1) for item in self._get_tree_items(self.tree_iocs) if item.text(0) == "Email"],
                "ips": [item.text(1) for item in self._get_tree_items(self.tree_iocs) if item.text(0) == "IP Address"]
            },
            "attachments": [
                {
                    "filename": attachment['name'],
                    "content_type": attachment['content_type'],
                    "size": attachment['size'],
                    "md5": attachment['md5'],
                    "sha256": attachment['sha256']
                }
                for attachment in self.current_attachments
            ]
        }

        # Export report
        from utils.constants import ReportExporter
        ReportExporter.export_json_report(report_data, path, self)

        self.status_label.setText(f"Forensic report exported: {Path(path).name}")

    def _get_tree_items(self, tree):
        """Get all items from a tree widget."""
        items = []
        for i in range(tree.topLevelItemCount()):
            items.append(tree.topLevelItem(i))
        return items

    def edit_chain_of_custody(self):
        """Open chain of custody dialog."""
        dialog = ChainOfCustodyDialog(self, self.file_metadata.get('chain_of_custody', {}))
        if dialog.exec_() == dialog.Accepted:
            # Update chain of custody data
            custody_data = dialog.get_data()

            # Update file metadata
            if 'chain_of_custody' not in self.file_metadata:
                self.file_metadata['chain_of_custody'] = {}

            self.file_metadata['chain_of_custody'].update(custody_data)

            # Add to custody history
            import datetime
            history_entry = {
                'timestamp': datetime.datetime.now().isoformat(),
                'action': 'custody_documented',
                'analyst': custody_data['analyst'],
                'case_number': custody_data['case_number'],
                'exhibit_number': custody_data['exhibit_number']
            }
            if 'custody_history' not in self.file_metadata['chain_of_custody']:
                self.file_metadata['chain_of_custody']['custody_history'] = []
            self.file_metadata['chain_of_custody']['custody_history'].append(history_entry)

            # Refresh the file metadata display
            self._populate_file_metadata()

        self.status_label.setText("Chain of custody documentation updated")


# ---------- UI Enhancement Methods ------------------------------------------
    def _create_status_bar(self):
        """Create enhanced status bar."""
        self.status_bar = self.statusBar()

        # Status message
        self.status_label = QLabel("Ready")
        self.status_bar.addWidget(self.status_label, 1)

        # Progress bar for long operations
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setMaximumWidth(200)
        self.status_bar.addPermanentWidget(self.progress_bar)

        # File info
        self.file_info_label = QLabel("")
        self.status_bar.addPermanentWidget(self.file_info_label)

    def show_progress(self, visible=True, message="Processing..."):
        """Show/hide progress bar."""
        self.progress_bar.setVisible(visible)
        if visible:
            self.progress_bar.setRange(0, 0)  # Indeterminate progress
            self.status_label.setText(message)
        else:
            self.progress_bar.setRange(0, 100)
            self.progress_bar.setValue(0)
            self.status_label.setText("Ready")

    def update_status(self, message):
        """Update status bar message."""
        self.status_label.setText(message)

    def dragEnterEvent(self, event: QDragEnterEvent):
        """Handle drag enter events."""
        if event.mimeData().hasUrls():
            # Check if any URLs are local files
            for url in event.mimeData().urls():
                if url.isLocalFile() and url.toLocalFile().lower().endswith('.eml'):
                    event.acceptProposedAction()
                    return
        event.ignore()

    def dropEvent(self, event: QDropEvent):
        """Handle file drop events."""
        for url in event.mimeData().urls():
            if url.isLocalFile():
                filepath = url.toLocalFile()
                if filepath.lower().endswith('.eml'):
                    self.load_email_file(filepath)
                    break

    def load_email_file(self, filepath):
        """Load an email file (used by drag and drop)."""
        try:
            # Validate file
            is_valid, error_msg = FileValidator.validate_email_file(filepath)
            if not is_valid:
                MessageBoxHelper.show_error(self, "Invalid File", error_msg)
                return

            # Read and parse file
            with open(filepath, "rb") as fh:
                raw = fh.read()

            # Extract file metadata
            file_meta = FileMetadata(filepath, raw)
            file_meta.extract_metadata()
            self.file_metadata = file_meta.get_metadata()

            # Parse email
            self._parse_email(raw)
            self.status_label.setText(f"Loaded: {Path(filepath).name}")
            self.update_file_info()

        except Exception as exc:
            MessageBoxHelper.show_error(self, "Error", str(exc))
            print(traceback.format_exc())

    def update_file_info(self):
        """Update file information in status bar."""
        if self.file_metadata:
            filename = self.file_metadata.get('filename', 'Unknown')
            filesize = human_bytes(self.file_metadata.get('filesize', 0))
            self.file_info_label.setText(f"{filename} ({filesize})")
        else:
            self.file_info_label.setText("")

    def focus_search(self):
        """Focus on search box in current tab."""
        current_tab = self.nb.currentWidget()
        if hasattr(current_tab, 'findChild'):
            search_box = current_tab.findChild(QLineEdit)
            if search_box:
                search_box.setFocus()
                return

        # If no search box found, show message
        MessageBoxHelper.show_info(self, "Search", "Search is not available in the current tab.")

    def show_help(self):
        """Show help dialog."""
        help_text = """
        <h3>Email Investigator - Help</h3>
        <p><strong>Keyboard Shortcuts:</strong></p>
        <ul>
            <li><kbd>Ctrl+O</kbd> - Open email file</li>
            <li><kbd>Ctrl+E</kbd> - Export forensic report</li>
            <li><kbd>Ctrl+F</kbd> - Search in current tab</li>
            <li><kbd>F1</kbd> - Show this help</li>
        </ul>
        <p><strong>Features:</strong></p>
        <ul>
            <li>Comprehensive email forensics analysis</li>
            <li>Chain of custody documentation</li>
            <li>Anti-forensics detection</li>
            <li>Network intelligence analysis</li>
            <li>Export forensic reports</li>
        </ul>
        <p><strong>Drag & Drop:</strong> Drag .eml files onto the application to load them.</p>
        """

        QMessageBox.information(self, "Help", help_text)

    def show_about(self):
        """Show about dialog."""
        about_text = f"""
        <h3>{Constants.WINDOW_TITLE}</h3>
        <p><strong>Version:</strong> 1.0.0</p>
        <p><strong>Description:</strong> Professional email forensics analysis tool</p>
        <p><strong>Features:</strong></p>
        <ul>
            <li>Modular architecture for maintainability</li>
            <li>Comprehensive forensic analysis</li>
            <li>Chain of custody documentation</li>
            <li>Anti-forensics detection</li>
            <li>Network intelligence analysis</li>
        </ul>
        <p><strong>Technologies:</strong> PyQt5, Python 3.7+</p>
        """

        QMessageBox.about(self, "About", about_text)


# Import the FileValidator class for the validation method
from utils.constants import FileValidator


def main():
    """Main entry point."""
    app = QApplication(sys.argv)
    win = MailInvestigator()
    win.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
