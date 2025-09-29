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
                             QShortcut, QMenuBar, QProgressDialog)
from PyQt5.QtCore import Qt, QMimeData, QTimer, QSize
from PyQt5.QtGui import QFont, QClipboard, QKeySequence, QDragEnterEvent, QDropEvent

# Import our modular components
from forensics.core import hash_bytes, human_bytes
from forensics.email_parser import EmailParser, FileMetadata
from forensics.analysis.attachments import AttachmentAnalyzer
from forensics.analysis.anti_forensics import AntiForensicsAnalyzer
from forensics.analysis.network import NetworkAnalyzer
from database import get_database
from ui.components import ChainOfCustodyDialog
from ui.styles import ThemeManager, IconManager
from utils.constants import Constants, MessageBoxHelper
from database_manager_simple import DatabaseManager


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
        
        # Initialize database manager
        self.database_manager = None

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

        # Left: enhanced headers tree with categories
        self.headers_tree = QTreeWidget()
        self.headers_tree.setHeaderLabels(["Header", "Value"])
        self.headers_tree.setRootIsDecorated(True)
        self.headers_tree.setAlternatingRowColors(True)
        splitter.addWidget(self.headers_tree)

        # Right: notebook with analysis tabs
        self.nb = self._create_analysis_tabs()
        splitter.addWidget(self.nb)

        # Configure splitter
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 2)

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

        # Database menu
        database_menu = menubar.addMenu('&Database')

        db_manager_action = database_menu.addAction('&Database Manager')
        db_manager_action.triggered.connect(self.open_database_manager)
        db_manager_action.setToolTip('Open database manager to view and manage stored emails')

        database_menu.addSeparator()

        batch_upload_action = database_menu.addAction('&Batch Upload Emails')
        batch_upload_action.triggered.connect(self.batch_upload_emails)
        batch_upload_action.setToolTip('Upload and process multiple email files at once')
        
        # Group analysis action
        group_analysis_action = database_menu.addAction('&Group Analysis')
        group_analysis_action.triggered.connect(self.perform_group_analysis)
        group_analysis_action.setToolTip('Perform group analysis on stored emails')
        
        database_menu.addSeparator()
        
        # Database management actions
        clear_db_action = database_menu.addAction('&Clear Database')
        clear_db_action.triggered.connect(self.clear_database)
        clear_db_action.setToolTip('Clear all stored emails from database')
        
        backup_db_action = database_menu.addAction('&Backup Database')
        backup_db_action.triggered.connect(self.backup_database)
        backup_db_action.setToolTip('Create backup of database')

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
        
        # 6. Extracted Data Tab
        extracted_tab = self._create_extracted_data_tab()
        nb.addTab(extracted_tab, f"{IconManager.get_icon('list')} Extracted Data")

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

    def _create_extracted_data_tab(self) -> QWidget:
        """Create tab for displaying extracted data (URLs, emails, phones, names)."""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Create text areas for different types of extracted data
        self.urls_text = QTextEdit()
        self.urls_text.setReadOnly(True)
        self.urls_text.setFont(QFont("Consolas", 9))
        self.urls_text.setPlaceholderText("No URLs found")
        
        self.emails_text = QTextEdit()
        self.emails_text.setReadOnly(True)
        self.emails_text.setFont(QFont("Consolas", 9))
        self.emails_text.setPlaceholderText("No email addresses found")
        
        self.phones_text = QTextEdit()
        self.phones_text.setReadOnly(True)
        self.phones_text.setFont(QFont("Consolas", 9))
        self.phones_text.setPlaceholderText("No phone numbers found")
        
        self.names_text = QTextEdit()
        self.names_text.setReadOnly(True)
        self.names_text.setFont(QFont("Consolas", 9))
        self.names_text.setPlaceholderText("No names found")
        
        self.ips_text = QTextEdit()
        self.ips_text.setReadOnly(True)
        self.ips_text.setFont(QFont("Consolas", 9))
        self.ips_text.setPlaceholderText("No IP addresses found")

        # Create sub-tabs for different data types
        extracted_tabs = QTabWidget()
        extracted_tabs.addTab(self.urls_text, "🌐 URLs")
        extracted_tabs.addTab(self.emails_text, "📧 Email Addresses")
        extracted_tabs.addTab(self.phones_text, "📞 Phone Numbers")
        extracted_tabs.addTab(self.names_text, "👤 Names")
        extracted_tabs.addTab(self.ips_text, "🌍 IP Addresses")
        
        layout.addWidget(extracted_tabs)
        return tab

    def _create_database_manager_tab(self) -> QWidget:
        """Create tab for database manager interface."""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Database manager interface will be added here
        # For now, create a placeholder
        placeholder = QLabel("Database Manager Interface\n\nSelect 'Database Manager' from the Database menu to access email database management features.")
        placeholder.setAlignment(Qt.AlignCenter)
        placeholder.setStyleSheet("font-size: 14px; color: #666; padding: 50px;")
        layout.addWidget(placeholder)

        return tab

    def open_database_manager(self):
        """Open database manager as a tab instead of dialog."""
        try:
            # Switch to the database manager tab
            tab_index = self.nb.indexOf(self.nb.findChild(QWidget, "database_manager_tab"))
            if tab_index >= 0:
                self.nb.setCurrentIndex(tab_index)
                self.status_label.setText("Database Manager opened")
            else:
                MessageBoxHelper.show_error(self, "Error", "Database Manager tab not found")
        except Exception as e:
            MessageBoxHelper.show_error(self, "Database Error", f"Failed to open database manager: {str(e)}")

    def perform_group_analysis(self):
        """Perform group analysis and display results in main window tabs."""
        try:
            # Get all emails for group analysis
            db = get_database()
            emails = db.get_all_emails(limit=1000)

            if len(emails) < 2:
                MessageBoxHelper.show_info(self, "Insufficient Data",
                    "At least 2 emails are required for group analysis.")
                return

            # Perform group analysis
            self._perform_group_analysis(emails)
            self.status_label.setText(f"Group analysis completed for {len(emails)} emails")

        except Exception as e:
            MessageBoxHelper.show_error(self, "Error", f"Group analysis failed: {str(e)}")

    def _perform_group_analysis(self, emails):
        """Perform comprehensive group analysis on multiple emails."""
        try:
            # Clear current analysis data
            self._clear_group_analysis()

            # Perform group analysis
            group_stats = self._analyze_group_statistics(emails)
            group_iocs = self._analyze_group_iocs(emails)
            group_senders = self._analyze_group_senders(emails)
            group_subjects = self._analyze_group_subjects(emails)
            group_content = self._analyze_group_content(emails)

            # Populate main window tabs with group analysis results
            self._populate_group_content_tab(group_stats, group_content)
            self._populate_group_security_tab(group_iocs)
            self._populate_group_network_tab(group_senders)
            self._populate_group_extracted_tab(group_subjects)

            # Switch to content tab to show results
            self.nb.setCurrentIndex(0)  # Content tab

        except Exception as e:
            print(f"Error in group analysis: {e}")

    def _clear_group_analysis(self):
        """Clear all group analysis data from tabs."""
        # Clear content tab
        self.txt_plain.clear()
        self.txt_html.clear()

        # Clear security tab
        self.tree_iocs.clear()
        self.tree_anomalies.clear()
        self.tree_anti_forensics.clear()

        # Clear network tab
        self.tree_network.clear()

        # Clear extracted data tab
        self.urls_text.clear()
        self.emails_text.clear()
        self.phones_text.clear()
        self.names_text.clear()
        self.ips_text.clear()

    def _analyze_group_statistics(self, emails):
        """Analyze group statistics."""
        total_emails = len(emails)
        total_size = sum(email.get('file_size', 0) for email in emails)

        # Count unique senders
        senders = [email.get('sender', '') for email in emails]
        unique_senders = len(set(senders))

        # Count unique domains
        domains = []
        for sender in senders:
            if sender and '@' in sender:
                domain = sender.split('@')[1]
                domains.append(domain)
        unique_domains = len(set(domains))

        return {
            'total_emails': total_emails,
            'total_size': total_size,
            'unique_senders': unique_senders,
            'unique_domains': unique_domains
        }

    def _analyze_group_iocs(self, emails):
        """Analyze IOCs across all emails."""
        all_iocs = {
            'urls': set(),
            'emails': set(),
            'ips': set()
        }

        for email in emails:
            email_iocs = email.get('iocs', {})
            if isinstance(email_iocs, dict):
                all_iocs['urls'].update(email_iocs.get('urls', []))
                all_iocs['emails'].update(email_iocs.get('emails', []))
                all_iocs['ips'].update(email_iocs.get('ips', []))

        return {
            'urls': list(all_iocs['urls']),
            'emails': list(all_iocs['emails']),
            'ips': list(all_iocs['ips'])
        }

    def _analyze_group_senders(self, emails):
        """Analyze sender patterns."""
        sender_patterns = {}
        domain_patterns = {}

        for email in emails:
            sender = email.get('sender', 'Unknown')
            if sender and '@' in sender:
                domain = sender.split('@')[1]

                # Count sender occurrences
                sender_patterns[sender] = sender_patterns.get(sender, 0) + 1

                # Count domain occurrences
                domain_patterns[domain] = domain_patterns.get(domain, 0) + 1

        return {
            'senders': sender_patterns,
            'domains': domain_patterns
        }

    def _analyze_group_subjects(self, emails):
        """Analyze subject line patterns."""
        subjects = [email.get('subject', '') for email in emails if email.get('subject')]

        # Find common subject patterns
        subject_patterns = {}
        for subject in subjects:
            # Simple pattern matching - look for common prefixes
            if len(subject) > 10:
                prefix = subject[:10].lower()
                subject_patterns[prefix] = subject_patterns.get(prefix, 0) + 1

        return {
            'subjects': subjects,
            'patterns': subject_patterns
        }

    def _analyze_group_content(self, emails):
        """Analyze content patterns across emails."""
        # Analyze email sizes
        sizes = [email.get('file_size', 0) for email in emails]
        if sizes:
            min_size = min(sizes)
            max_size = max(sizes)
            avg_size = sum(sizes) / len(sizes)
        else:
            min_size = max_size = avg_size = 0

        return {
            'size_stats': {
                'min': min_size,
                'max': max_size,
                'avg': avg_size
            }
        }

    def _populate_group_content_tab(self, stats, content):
        """Populate content tab with group analysis results."""
        content_text = "GROUP EMAIL ANALYSIS\n"
        content_text += "=" * 50 + "\n\n"

        # Statistics
        content_text += "📊 STATISTICS:\n"
        content_text += "-" * 20 + "\n"
        content_text += f"Total Emails: {stats['total_emails']}\n"
        content_text += f"Total Size: {stats['total_size']} bytes\n"
        content_text += f"Unique Senders: {stats['unique_senders']}\n"
        content_text += f"Unique Domains: {stats['unique_domains']}\n\n"

        # Content analysis
        content_text += "📝 CONTENT ANALYSIS:\n"
        content_text += "-" * 25 + "\n"
        content_text += "📏 Email Size Distribution:\n"
        content_text += f"• Smallest: {content['size_stats']['min']} bytes\n"
        content_text += f"• Largest: {content['size_stats']['max']} bytes\n"
        content_text += f"• Average: {content['size_stats']['avg']:.0f} bytes\n"

        self.txt_plain.setPlainText(content_text)

    def _populate_group_security_tab(self, iocs):
        """Populate security tab with group IOC analysis."""
        # Populate IOCs
        self._populate_iocs(iocs)

        # Add group-level IOC analysis
        group_ioc_text = f"GROUP IOC ANALYSIS\n"
        group_ioc_text += "=" * 30 + "\n\n"

        group_ioc_text += f"URLs Found: {len(iocs['urls'])}\n"
        group_ioc_text += f"Email Addresses Found: {len(iocs['emails'])}\n"
        group_ioc_text += f"IP Addresses Found: {len(iocs['ips'])}\n\n"

        # Show top IOCs
        if iocs['urls']:
            group_ioc_text += "TOP URLs:\n"
            group_ioc_text += "-" * 15 + "\n"
            for url in iocs['urls'][:10]:  # Show top 10
                group_ioc_text += f"• {url}\n"
            group_ioc_text += "\n"

        if iocs['emails']:
            group_ioc_text += "TOP EMAIL ADDRESSES:\n"
            group_ioc_text += "-" * 25 + "\n"
            for email in iocs['emails'][:10]:  # Show top 10
                group_ioc_text += f"• {email}\n"
            group_ioc_text += "\n"

        if iocs['ips']:
            group_ioc_text += "TOP IP ADDRESSES:\n"
            group_ioc_text += "-" * 20 + "\n"
            for ip in iocs['ips'][:10]:  # Show top 10
                group_ioc_text += f"• {ip}\n"
            group_ioc_text += "\n"

        # Set the text in the anomalies tab since it's part of security
        self.tree_anomalies.clear()
        anomaly_item = QTreeWidgetItem()
        anomaly_item.setText(0, "Group Analysis")
        anomaly_item.setText(1, group_ioc_text)
        self.tree_anomalies.addTopLevelItem(anomaly_item)

    def _populate_group_network_tab(self, senders):
        """Populate network tab with sender analysis."""
        network_text = "GROUP SENDER ANALYSIS\n"
        network_text += "=" * 30 + "\n\n"

        # Top senders
        sorted_senders = sorted(senders['senders'].items(), key=lambda x: x[1], reverse=True)
        if sorted_senders:
            network_text += "TOP SENDERS:\n"
            network_text += "-" * 15 + "\n"
            for sender, count in sorted_senders[:10]:  # Show top 10
                network_text += f"• {sender}: {count} emails\n"
            network_text += "\n"

        # Top domains
        sorted_domains = sorted(senders['domains'].items(), key=lambda x: x[1], reverse=True)
        if sorted_domains:
            network_text += "TOP DOMAINS:\n"
            network_text += "-" * 15 + "\n"
            for domain, count in sorted_domains[:10]:  # Show top 10
                network_text += f"• {domain}: {count} emails\n"
            network_text += "\n"

        # Populate network tree
        self.tree_network.clear()

        # Add sender analysis
        sender_item = QTreeWidgetItem()
        sender_item.setText(0, "Sender Analysis")
        sender_item.setText(1, "Group")
        sender_item.setText(2, f"{len(senders['senders'])} unique senders, {len(senders['domains'])} unique domains")
        self.tree_network.addTopLevelItem(sender_item)

    def _populate_group_extracted_tab(self, subjects):
        """Populate extracted data tab with subject analysis."""
        # Populate URLs tab with subject patterns
        subject_patterns_text = "SUBJECT LINE ANALYSIS\n"
        subject_patterns_text += "=" * 30 + "\n\n"

        if subjects['patterns']:
            subject_patterns_text += "COMMON SUBJECT PATTERNS:\n"
            subject_patterns_text += "-" * 30 + "\n"
            sorted_patterns = sorted(subjects['patterns'].items(), key=lambda x: x[1], reverse=True)
            for pattern, count in sorted_patterns[:10]:  # Show top 10 patterns
                subject_patterns_text += f"• '{pattern}...': {count} emails\n"
            subject_patterns_text += "\n"

        subject_patterns_text += f"TOTAL SUBJECTS ANALYZED: {len(subjects['subjects'])}\n"

        self.urls_text.setPlainText(subject_patterns_text)

        # Clear other extracted data tabs since they're not relevant for group analysis
        self.emails_text.clear()
        self.phones_text.clear()
        self.names_text.clear()
        self.ips_text.clear()

    def _create_database_manager_tab(self) -> QWidget:
        """Create tab for database manager interface."""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Database manager interface will be added here
        # For now, create a placeholder
        placeholder = QLabel("Database Manager Interface\n\nSelect 'Database Manager' from the Database menu to access email database management features.")
        placeholder.setAlignment(Qt.AlignCenter)
        placeholder.setStyleSheet("font-size: 14px; color: #666; padding: 50px;")
        layout.addWidget(placeholder)

        return tab

    def open_database_manager(self):
        """Open database manager as a tab instead of dialog."""
        try:
            # Switch to the database manager tab
            tab_index = self.nb.indexOf(self.nb.findChild(QWidget, "database_manager_tab"))
            if tab_index >= 0:
                self.nb.setCurrentIndex(tab_index)
                self.status_label.setText("Database Manager opened")
            else:
                MessageBoxHelper.show_error(self, "Error", "Database Manager tab not found")
        except Exception as e:
            MessageBoxHelper.show_error(self, "Database Error", f"Failed to open database manager: {str(e)}")

    def perform_group_analysis(self):
        """Perform group analysis and display results in main window tabs."""
        try:
            # Get all emails for group analysis
            db = get_database()
            emails = db.get_all_emails(limit=1000)

            if len(emails) < 2:
                MessageBoxHelper.show_info(self, "Insufficient Data",
                    "At least 2 emails are required for group analysis.")
                return

            # Perform group analysis
            self._perform_group_analysis(emails)
            self.status_label.setText(f"Group analysis completed for {len(emails)} emails")

        except Exception as e:
            MessageBoxHelper.show_error(self, "Error", f"Group analysis failed: {str(e)}")

    def _perform_group_analysis(self, emails):
        """Perform comprehensive group analysis on multiple emails."""
        try:
            # Clear current analysis data
            self._clear_group_analysis()

            # Perform group analysis
            group_stats = self._analyze_group_statistics(emails)
            group_iocs = self._analyze_group_iocs(emails)
            group_senders = self._analyze_group_senders(emails)
            group_subjects = self._analyze_group_subjects(emails)
            group_content = self._analyze_group_content(emails)

            # Populate main window tabs with group analysis results
            self._populate_group_content_tab(group_stats, group_content)
            self._populate_group_security_tab(group_iocs)
            self._populate_group_network_tab(group_senders)
            self._populate_group_extracted_tab(group_subjects)

            # Switch to content tab to show results
            self.nb.setCurrentIndex(0)  # Content tab

        except Exception as e:
            print(f"Error in group analysis: {e}")

    def _clear_group_analysis(self):
        """Clear all group analysis data from tabs."""
        # Clear content tab
        self.txt_plain.clear()
        self.txt_html.clear()

        # Clear security tab
        self.tree_iocs.clear()
        self.tree_anomalies.clear()
        self.tree_anti_forensics.clear()

        # Clear network tab
        self.tree_network.clear()

        # Clear extracted data tab
        self.urls_text.clear()
        self.emails_text.clear()
        self.phones_text.clear()
        self.names_text.clear()
        self.ips_text.clear()

    def _analyze_group_statistics(self, emails):
        """Analyze group statistics."""
        total_emails = len(emails)
        total_size = sum(email.get('file_size', 0) for email in emails)

        # Count unique senders
        senders = [email.get('sender', '') for email in emails]
        unique_senders = len(set(senders))

        # Count unique domains
        domains = []
        for sender in senders:
            if sender and '@' in sender:
                domain = sender.split('@')[1]
                domains.append(domain)
        unique_domains = len(set(domains))

        return {
            'total_emails': total_emails,
            'total_size': total_size,
            'unique_senders': unique_senders,
            'unique_domains': unique_domains
        }

    def _analyze_group_iocs(self, emails):
        """Analyze IOCs across all emails."""
        all_iocs = {
            'urls': set(),
            'emails': set(),
            'ips': set()
        }

        for email in emails:
            email_iocs = email.get('iocs', {})
            if isinstance(email_iocs, dict):
                all_iocs['urls'].update(email_iocs.get('urls', []))
                all_iocs['emails'].update(email_iocs.get('emails', []))
                all_iocs['ips'].update(email_iocs.get('ips', []))

        return {
            'urls': list(all_iocs['urls']),
            'emails': list(all_iocs['emails']),
            'ips': list(all_iocs['ips'])
        }

    def _analyze_group_senders(self, emails):
        """Analyze sender patterns."""
        sender_patterns = {}
        domain_patterns = {}

        for email in emails:
            sender = email.get('sender', 'Unknown')
            if sender and '@' in sender:
                domain = sender.split('@')[1]

                # Count sender occurrences
                sender_patterns[sender] = sender_patterns.get(sender, 0) + 1

                # Count domain occurrences
                domain_patterns[domain] = domain_patterns.get(domain, 0) + 1

        return {
            'senders': sender_patterns,
            'domains': domain_patterns
        }

    def _analyze_group_subjects(self, emails):
        """Analyze subject line patterns."""
        subjects = [email.get('subject', '') for email in emails if email.get('subject')]

        # Find common subject patterns
        subject_patterns = {}
        for subject in subjects:
            # Simple pattern matching - look for common prefixes
            if len(subject) > 10:
                prefix = subject[:10].lower()
                subject_patterns[prefix] = subject_patterns.get(prefix, 0) + 1

        return {
            'subjects': subjects,
            'patterns': subject_patterns
        }

    def _analyze_group_content(self, emails):
        """Analyze content patterns across emails."""
        # Analyze email sizes
        sizes = [email.get('file_size', 0) for email in emails]
        if sizes:
            min_size = min(sizes)
            max_size = max(sizes)
            avg_size = sum(sizes) / len(sizes)
        else:
            min_size = max_size = avg_size = 0

        return {
            'size_stats': {
                'min': min_size,
                'max': max_size,
                'avg': avg_size
            }
        }

    def _populate_group_content_tab(self, stats, content):
        """Populate content tab with group analysis results."""
        content_text = "GROUP EMAIL ANALYSIS\n"
        content_text += "=" * 50 + "\n\n"

        # Statistics
        content_text += "📊 STATISTICS:\n"
        content_text += "-" * 20 + "\n"
        content_text += f"Total Emails: {stats['total_emails']}\n"
        content_text += f"Total Size: {stats['total_size']} bytes\n"
        content_text += f"Unique Senders: {stats['unique_senders']}\n"
        content_text += f"Unique Domains: {stats['unique_domains']}\n\n"

        # Content analysis
        content_text += "📝 CONTENT ANALYSIS:\n"
        content_text += "-" * 25 + "\n"
        content_text += "📏 Email Size Distribution:\n"
        content_text += f"• Smallest: {content['size_stats']['min']} bytes\n"
        content_text += f"• Largest: {content['size_stats']['max']} bytes\n"
        content_text += f"• Average: {content['size_stats']['avg']:.0f} bytes\n"

        self.txt_plain.setPlainText(content_text)

    def _populate_group_security_tab(self, iocs):
        """Populate security tab with group IOC analysis."""
        # Populate IOCs
        self._populate_iocs(iocs)

        # Add group-level IOC analysis
        group_ioc_text = f"GROUP IOC ANALYSIS\n"
        group_ioc_text += "=" * 30 + "\n\n"

        group_ioc_text += f"URLs Found: {len(iocs['urls'])}\n"
        group_ioc_text += f"Email Addresses Found: {len(iocs['emails'])}\n"
        group_ioc_text += f"IP Addresses Found: {len(iocs['ips'])}\n\n"

        # Show top IOCs
        if iocs['urls']:
            group_ioc_text += "TOP URLs:\n"
            group_ioc_text += "-" * 15 + "\n"
            for url in iocs['urls'][:10]:  # Show top 10
                group_ioc_text += f"• {url}\n"
            group_ioc_text += "\n"

        if iocs['emails']:
            group_ioc_text += "TOP EMAIL ADDRESSES:\n"
            group_ioc_text += "-" * 25 + "\n"
            for email in iocs['emails'][:10]:  # Show top 10
                group_ioc_text += f"• {email}\n"
            group_ioc_text += "\n"

        if iocs['ips']:
            group_ioc_text += "TOP IP ADDRESSES:\n"
            group_ioc_text += "-" * 20 + "\n"
            for ip in iocs['ips'][:10]:  # Show top 10
                group_ioc_text += f"• {ip}\n"
            group_ioc_text += "\n"

        # Set the text in the anomalies tab since it's part of security
        self.tree_anomalies.clear()
        anomaly_item = QTreeWidgetItem()
        anomaly_item.setText(0, "Group Analysis")
        anomaly_item.setText(1, group_ioc_text)
        self.tree_anomalies.addTopLevelItem(anomaly_item)

    def _populate_group_network_tab(self, senders):
        """Populate network tab with sender analysis."""
        network_text = "GROUP SENDER ANALYSIS\n"
        network_text += "=" * 30 + "\n\n"

        # Top senders
        sorted_senders = sorted(senders['senders'].items(), key=lambda x: x[1], reverse=True)
        if sorted_senders:
            network_text += "TOP SENDERS:\n"
            network_text += "-" * 15 + "\n"
            for sender, count in sorted_senders[:10]:  # Show top 10
                network_text += f"• {sender}: {count} emails\n"
            network_text += "\n"

        # Top domains
        sorted_domains = sorted(senders['domains'].items(), key=lambda x: x[1], reverse=True)
        if sorted_domains:
            network_text += "TOP DOMAINS:\n"
            network_text += "-" * 15 + "\n"
            for domain, count in sorted_domains[:10]:  # Show top 10
                network_text += f"• {domain}: {count} emails\n"
            network_text += "\n"

        # Populate network tree
        self.tree_network.clear()

        # Add sender analysis
        sender_item = QTreeWidgetItem()
        sender_item.setText(0, "Sender Analysis")
        sender_item.setText(1, "Group")
        sender_item.setText(2, f"{len(senders['senders'])} unique senders, {len(senders['domains'])} unique domains")
        self.tree_network.addTopLevelItem(sender_item)

    def _populate_group_extracted_tab(self, subjects):
        """Populate extracted data tab with subject analysis."""
        # Populate URLs tab with subject patterns
        subject_patterns_text = "SUBJECT LINE ANALYSIS\n"
        subject_patterns_text += "=" * 30 + "\n\n"

        if subjects['patterns']:
            subject_patterns_text += "COMMON SUBJECT PATTERNS:\n"
            subject_patterns_text += "-" * 30 + "\n"
            sorted_patterns = sorted(subjects['patterns'].items(), key=lambda x: x[1], reverse=True)
            for pattern, count in sorted_patterns[:10]:  # Show top 10 patterns
                subject_patterns_text += f"• '{pattern}...': {count} emails\n"
            subject_patterns_text += "\n"

        subject_patterns_text += f"TOTAL SUBJECTS ANALYZED: {len(subjects['subjects'])}\n"

        self.urls_text.setPlainText(subject_patterns_text)

        # Clear other extracted data tabs since they're not relevant for group analysis
        self.emails_text.clear()
        self.phones_text.clear()
        self.names_text.clear()
        self.ips_text.clear()

    def _create_enhanced_headers_display(self) -> QWidget:
        """Create enhanced headers display widget."""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Headers tree widget
        self.headers_tree = QTreeWidget()
        self.headers_tree.setHeaderLabels(["Header", "Value"])
        self.headers_tree.setRootIsDecorated(True)
        self.headers_tree.setAlternatingRowColors(True)
        layout.addWidget(self.headers_tree)

        return widget


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

    def open_eml(self):
        """Open and parse an .eml file."""
        path, _ = QFileDialog.getOpenFileName(
            self, "Select RFC-822 message", "",
            "E-mail files (*.eml);;All files (*.*)"
        )

        if not path:
            return

        try:
            # Validate file
            is_valid, error_msg = FileValidator.validate_email_file(path)
            if not is_valid:
                MessageBoxHelper.show_error(self, "Invalid File", error_msg)
                return

            # Read and parse file
            with open(path, "rb") as fh:
                raw = fh.read()

            # Extract file metadata
            file_meta = FileMetadata(path, raw)
            file_meta.extract_metadata()
            self.file_metadata = file_meta.get_metadata()

            # Parse email
            self._parse_email(raw)
            self.status_label.setText(f"Loaded: {Path(path).name}")

        except Exception as exc:
            MessageBoxHelper.show_error(self, "Error", str(exc))
            print(traceback.format_exc())

    def batch_upload_emails(self):
        """Upload and process multiple email files at once."""
        files, _ = QFileDialog.getOpenFileNames(
            self, "Select Email Files for Batch Processing", "",
            "E-mail files (*.eml);;All files (*.*)"
        )

        if not files:
            return

        # Show progress dialog
        progress = QProgressDialog("Processing emails...", "Cancel", 0, len(files), self)
        progress.setWindowModality(Qt.WindowModal)
        progress.setMinimumDuration(0)
        progress.show()

        processed_count = 0
        failed_files = []
        database = get_database()

        try:
            for i, file_path in enumerate(files):
                if progress.wasCanceled():
                    break

                progress.setValue(i)
                progress.setLabelText(f"Processing {Path(file_path).name}...")
                QApplication.processEvents()  # Keep UI responsive

                try:
                    # Validate file first
                    is_valid, error_msg = FileValidator.validate_email_file(file_path)
                    if not is_valid:
                        failed_files.append((file_path, error_msg))
                        continue

                    # Read and parse file
                    with open(file_path, "rb") as fh:
                        raw = fh.read()

                    # Extract file metadata
                    file_meta = FileMetadata(file_path, raw)
                    file_meta.extract_metadata()
                    metadata = file_meta.get_metadata()

                    # Parse email
                    parser = EmailParser(raw)
                    if not parser.parse():
                        failed_files.append((file_path, "Failed to parse email"))
                        continue

                    # Store in database
                    email_data = {
                        'subject': parser.message.get('Subject', ''),
                        'sender': parser.message.get('From', ''),
                        'recipients': parser.message.get('To', ''),
                        'date_sent': parser.message.get('Date', ''),
                        'date_received': parser.message.get('Received', ''),
                        'message_id': parser.message.get('Message-ID', ''),
                        'raw_headers': str(parser.message),
                        'file_path': file_path,
                        'file_size': len(raw),
                        'acquisition_time': metadata.get('acquisition_time', ''),
                        'attachments': parser.attachments,
                        'iocs': parser.get_iocs(),
                        'analysis_results': {
                            'forensic': {
                                'received_headers': parser.get_received_headers(),
                                'authentication': parser.get_authentication_results(),
                                'anomalies': parser.get_time_anomalies()
                            },
                            'advanced': {
                                'network_analysis': self._get_network_analysis_data(parser),
                                'anti_forensics': self._get_anti_forensics_data(parser)
                            }
                        }
                    }

                    # Save to database
                    email_id = database.store_email(email_data)
                    if email_id:
                        processed_count += 1
                    else:
                        failed_files.append((file_path, "Failed to save to database"))

                except Exception as e:
                    failed_files.append((file_path, str(e)))
                    continue

            progress.setValue(len(files))

            # Show results
            self._show_batch_results(processed_count, failed_files)
            self.status_label.setText(f"Batch processing completed: {processed_count} emails processed")

        except Exception as exc:
            MessageBoxHelper.show_error(self, "Batch Processing Error", str(exc))
            print(traceback.format_exc())
        finally:
            progress.close()

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
        self._populate_headers_tree(parser.message)
        self._populate_body(parser.message)
        self._populate_attachments()

        # Populate forensic analysis
        self._populate_file_metadata()
        self._populate_forensic_analysis(parser)
        
        # Populate extracted data
        self._populate_extracted_data(parser)
        
        # Store email in database
        self._store_email_in_database(parser, raw)

    def _store_email_in_database(self, parser, raw_data):
        """Store email analysis results in database."""
        try:
            db = get_database()
            
            # Prepare email data
            email_data = {
                'message_id': parser.message.get('Message-ID', ''),
                'subject': parser.message.get('Subject', ''),
                'sender': parser.message.get('From', ''),
                'recipients': parser.message.get('To', ''),
                'date_sent': parser.message.get('Date', ''),
                'date_received': '',
                'raw_headers': str(parser.message.items()),
                'raw_body': raw_data.decode('utf-8', errors='ignore'),
                'raw_data': raw_data,
                'file_path': self.file_metadata.get('filename', '') if self.file_metadata else '',
                'file_size': self.file_metadata.get('filesize', 0) if self.file_metadata else 0,
                'acquisition_time': self.file_metadata.get('acquisition_time', '') if self.file_metadata else '',
                'attachments': self.current_attachments,
                'analysis_results': {
                    'iocs': parser.get_iocs(),
                    'received_headers': parser.get_received_headers(),
                    'authentication': parser.get_authentication_results(),
                    'time_anomalies': parser.get_time_anomalies()
                },
                'iocs': self._prepare_iocs_for_storage(parser.get_iocs()),
                'chain_of_custody': self.file_metadata.get('chain_of_custody', {}) if self.file_metadata else {}
            }
            
            # Store in database
            email_id = db.store_email(email_data)
            
            if email_id:
                self.update_status(f"Email stored in database (ID: {email_id})")
            else:
                self.update_status("Email already exists in database")
                
        except Exception as e:
            print(f"Error storing email in database: {e}")
            self.update_status("Failed to store email in database")
    
    def _prepare_iocs_for_storage(self, iocs):
        """Prepare IOCs for database storage."""
        stored_iocs = []
        
        # Add URLs
        for url in iocs.get('urls', []):
            stored_iocs.append({
                'type': 'URL',
                'value': url,
                'severity': 'medium',
                'description': 'URL found in email content'
            })
        
        # Add email addresses
        for email in iocs.get('emails', []):
            stored_iocs.append({
                'type': 'Email',
                'value': email,
                'severity': 'medium',
                'description': 'Email address found in content'
            })
        
        # Add IP addresses
        for ip in iocs.get('ips', []):
            stored_iocs.append({
                'type': 'IP',
                'value': ip,
                'severity': 'medium',
                'description': 'IP address found in email'
            })
        
        return stored_iocs
    
    def load_email_from_database(self, email_data):
        """Load email from database into analyzer."""
        try:
            # Update current message and attachments
            self.current_msg = email_data.get('message_obj')
            self.current_attachments = email_data.get('attachments', [])
            
            # Update file metadata
            self.file_metadata = {
                'filename': email_data.get('file_path', ''),
                'filesize': email_data.get('file_size', 0),
                'acquisition_time': email_data.get('acquisition_time', ''),
                'chain_of_custody': email_data.get('chain_of_custody', {})
            }
            
            # Populate UI elements
            self._populate_headers_tree(self.current_msg)
            self._populate_body(self.current_msg)
            self._populate_attachments()
            self._populate_file_metadata()
            
            # Note: Forensic analysis would need to be reconstructed from stored results
            # This is a simplified version
            
            self.update_status(f"Loaded email from database: {email_data.get('subject', 'No Subject')}")
            
        except Exception as e:
            MessageBoxHelper.show_error(self, "Error", f"Failed to load email from database: {str(e)}")
    
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

    def _populate_analysis_tabs(self):
        """Populate all analysis tabs with loaded data."""
        try:
            # Populate forensic analysis tabs
            if self.current_msg:
                # Create a temporary parser to get analysis data
                from forensics.email_parser import EmailParser
                parser = EmailParser()
                parser.message = self.current_msg
                parser.attachments = self.current_attachments

                # Populate forensic analysis
                self._populate_forensic_analysis(parser)

                # Populate extracted data
                self._populate_extracted_data(parser)
            else:
                # Clear all analysis tabs if no message
                self._clear_analysis_tabs()

        except Exception as e:
            print(f"Error populating analysis tabs: {e}")

    def _clear_analysis_tabs(self):
        """Clear all analysis tabs."""
        # Clear IOCs
        self.tree_iocs.clear()

        # Clear received headers
        self.tree_received.clear()

        # Clear authentication
        self.tree_auth.clear()

        # Clear anomalies
        self.tree_anomalies.clear()

        # Clear network analysis
        self.tree_network.clear()

        # Clear anti-forensics
        self.tree_anti_forensics.clear()

        # Clear extracted data
        self.urls_text.clear()
        self.emails_text.clear()
        self.phones_text.clear()
        self.names_text.clear()
        self.ips_text.clear()

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

    def _populate_extracted_data(self, parser: EmailParser):
        """Populate extracted data tabs with URLs, emails, phones, names, and IPs."""
        # Get all text content from the email
        all_text = self.txt_plain.toPlainText() + ' ' + self.txt_html.toPlainText()
        
        # Extract URLs
        urls = self._extract_urls_from_text(all_text)
        self.urls_text.setPlainText("\n".join(urls) if urls else "No URLs found")
        
        # Extract email addresses
        emails = self._extract_emails_from_text(all_text)
        self.emails_text.setPlainText("\n".join(emails) if emails else "No email addresses found")
        
        # Extract phone numbers
        phones = self._extract_phone_numbers_from_text(all_text)
        self.phones_text.setPlainText("\n".join(phones) if phones else "No phone numbers found")
        
        # Extract names
        names = self._extract_names_from_text(all_text)
        self.names_text.setPlainText("\n".join(names) if names else "No names found")
        
        # Extract IP addresses
        ips = self._extract_ips_from_text(all_text)
        self.ips_text.setPlainText("\n".join(ips) if ips else "No IP addresses found")
    
    def _extract_urls_from_text(self, text: str) -> list:
        """Extract URLs from text."""
        import re
        url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[\w\-\._~:/?#[\]@!\$&\'\(\)\*\+,;=.]*'
        urls = re.findall(url_pattern, text)
        return list(set(urls))
    
    def _extract_emails_from_text(self, text: str) -> list:
        """Extract email addresses from text."""
        import re
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = re.findall(email_pattern, text)
        return list(set(emails))
    
    def _extract_phone_numbers_from_text(self, text: str) -> list:
        """Extract phone numbers from text."""
        import re
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
    
    def _extract_names_from_text(self, text: str) -> list:
        """Extract potential names from text."""
        import re
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
    
    def _extract_ips_from_text(self, text: str) -> list:
        """Extract IP addresses from text."""
        import re
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ips = re.findall(ip_pattern, text)
        
        # Filter out invalid IPs (e.g., 999.999.999.999)
        valid_ips = []
        for ip in ips:
            parts = ip.split('.')
            if all(0 <= int(part) <= 255 for part in parts):
                valid_ips.append(ip)
        
        return list(set(valid_ips))

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

    def open_database_manager(self):
        """Open database manager dialog."""
        try:
            # Create database manager dialog if not exists
            if self.database_manager is None:
                self.database_manager = DatabaseManager(self)
            
            # Show database manager as a dialog
            self.database_manager.show()
            self.database_manager.raise_()
            self.database_manager.activateWindow()
            
            self.status_label.setText("Database manager opened")
        except Exception as e:
            MessageBoxHelper.show_error(self, "Database Error", f"Failed to open database manager: {str(e)}")

    def load_email_from_database(self, email_data):
        """Load email data from database into the analyzer.
        
        Args:
            email_data (dict): Email data from database
        """
        try:
            # Clear current data
            self.current_msg = None
            self.current_attachments = []
            self.file_metadata = {}
            self.forensic_data = {}
            self.advanced_forensic_data = {}
            
            # Parse email from raw headers
            from forensics.email_parser import EmailParser
            parser = EmailParser()
            
            # Create email message from database data
            raw_email = email_data.get('raw_headers', '')
            if raw_email:
                success = parser.parse_from_string(raw_email)
                if success:
                    self.current_msg = parser.message
                else:
                    self.current_msg = None
            else:
                # Create minimal email message from structured data
                from email.message import EmailMessage
                self.current_msg = EmailMessage()
                self.current_msg['Subject'] = email_data.get('subject', '')
                self.current_msg['From'] = email_data.get('sender', '')
                self.current_msg['To'] = email_data.get('recipients', '')
                self.current_msg['Date'] = email_data.get('date_sent', '')
                self.current_msg['Message-ID'] = email_data.get('message_id', '')
            
            # Load attachments from database
            self.current_attachments = email_data.get('attachments', [])
            
            # Load file metadata
            self.file_metadata = {
                'file_path': email_data.get('file_path', ''),
                'file_size': email_data.get('file_size', 0),
                'acquisition_time': email_data.get('acquisition_time', ''),
                'created_at': email_data.get('created_at', '')
            }
            
            # Load analysis results
            analysis_results = email_data.get('analysis_results', {})
            self.forensic_data = analysis_results.get('forensic', {})
            self.advanced_forensic_data = analysis_results.get('advanced_forensic', {})
            
            # Update UI
            self._populate_headers_tree(self.current_msg)
            self._populate_analysis_tabs()
            self._populate_file_metadata()
            
            # Update status
            subject = email_data.get('subject', 'No Subject')
            self.status_label.setText(f"Loaded email from database: {subject}")
            
        except Exception as e:
            MessageBoxHelper.show_error(self, "Load Error", f"Failed to load email from database: {str(e)}")
    
    def clear_database(self):
        """Clear all stored emails from database."""
        try:
            # Confirm with user
            reply = QMessageBox.question(
                self, 'Clear Database',
                'Are you sure you want to clear all stored emails from the database?\nThis action cannot be undone.',
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                db = get_database()
                db.clear_all_emails()
                self.status_label.setText("Database cleared successfully")
                MessageBoxHelper.show_info(self, "Success", "Database has been cleared successfully.")
                
        except Exception as e:
            MessageBoxHelper.show_error(self, "Database Error", f"Failed to clear database: {str(e)}")
    
    def backup_database(self):
        """Create backup of database."""
        try:
            # Ask user for backup location
            backup_path, _ = QFileDialog.getSaveFileName(
                self, "Select Backup Location", "",
                "Database Files (*.db *.sqlite);;All Files (*.*)"
            )
            
            if backup_path:
                db = get_database()
                db.create_backup(backup_path)
                self.status_label.setText(f"Database backup created: {Path(backup_path).name}")
                MessageBoxHelper.show_info(self, "Success", f"Database backup created successfully:\n{backup_path}")
                
        except Exception as e:
            MessageBoxHelper.show_error(self, "Backup Error", f"Failed to create backup: {str(e)}")

    def _get_network_analysis_data(self, parser):
        """Get network analysis data from parser.
        
        Args:
            parser (EmailParser): The email parser instance
            
        Returns:
            dict: Network analysis data
        """
        try:
            network_analyzer = NetworkAnalyzer()
            return network_analyzer.analyze(parser.message)
        except Exception:
            return {}

    def _get_anti_forensics_data(self, parser):
        """Get anti-forensics analysis data from parser.
        
        Args:
            parser (EmailParser): The email parser instance
            
        Returns:
            dict: Anti-forensics analysis data
        """
        try:
            anti_forensics_analyzer = AntiForensicsAnalyzer()
            return anti_forensics_analyzer.analyze(parser.message)
        except Exception:
            return {}


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

    def _show_batch_results(self, processed_count, failed_files):
        """Show batch processing results dialog.
        
        Args:
            processed_count (int): Number of successfully processed emails
            failed_files (list): List of tuples (file_path, error_message) for failed files
        """
        dialog = QDialog(self)
        dialog.setWindowTitle("Batch Processing Results")
        dialog.setMinimumWidth(500)
        dialog.setMinimumHeight(400)
        
        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(10)
        
        # Title
        title_label = QLabel("📁 Batch Processing Results")
        title_label.setStyleSheet("font-size: 16px; font-weight: bold; color: #2c3e50; margin-bottom: 10px;")
        layout.addWidget(title_label)
        
        # Summary
        summary_text = f"✅ Successfully processed: {processed_count} emails\n"
        summary_text += f"❌ Failed to process: {len(failed_files)} emails"
        
        summary_label = QLabel(summary_text)
        summary_label.setStyleSheet("font-size: 14px; padding: 10px; background-color: #f8f9fa; border-radius: 4px;")
        layout.addWidget(summary_label)
        
        # Failed files details
        if failed_files:
            failed_label = QLabel("❌ Failed Files:")
            failed_label.setStyleSheet("font-size: 14px; font-weight: bold; margin-top: 10px;")
            layout.addWidget(failed_label)
            
            # Create scrollable area for failed files
            scroll_area = QTextEdit()
            scroll_area.setReadOnly(True)
            scroll_area.setMaximumHeight(200)
            
            failed_text = ""
            for file_path, error in failed_files:
                failed_text += f"📄 {Path(file_path).name}\n"
                failed_text += f"   Error: {error}\n\n"
            
            scroll_text = QTextEdit()
            scroll_text.setReadOnly(True)
            scroll_text.setMaximumHeight(200)
            scroll_text.setPlainText(failed_text)
            scroll_text.setStyleSheet("""
                QTextEdit {
                    border: 1px solid #dee2e6;
                    border-radius: 4px;
                    padding: 10px;
                    background-color: #f8f9fa;
                    font-family: 'Consolas', monospace;
                    font-size: 12px;
                }
            """)
            layout.addWidget(scroll_text)
        
        # Close button
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dialog.accept)
        close_btn.setStyleSheet("""
            QPushButton {
                background-color: #007bff;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: bold;
                min-width: 80px;
            }
            QPushButton:hover {
                background-color: #0056b3;
            }
        """)
        
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        button_layout.addWidget(close_btn)
        layout.addLayout(button_layout)
        
        dialog.exec_()

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
from database import get_database


def main():
    """Main entry point."""
    app = QApplication(sys.argv)
    win = MailInvestigator()
    win.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
