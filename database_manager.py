"""
Database Manager UI for Email Investigator.
Provides interface to manage stored email messages.
"""

import sys
from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QTabWidget,
                             QTableWidget, QTableWidgetItem, QHeaderView,
                             QPushButton, QLabel, QTextEdit, QComboBox,
                             QProgressBar, QMessageBox, QSplitter, QWidget,
                             QScrollArea, QGroupBox, QLineEdit, QDateEdit,
                             QCheckBox, QRadioButton, QButtonGroup, QFrame)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from database import get_database
from datetime import datetime
from pathlib import Path
from group_analysis import GroupAnalysisDialog


class DatabaseManager(QDialog):
    """Database manager dialog for email investigator."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        
        # Configure dialog properties
        self.setWindowTitle("Email Database Manager")
        self.setModal(False)  # Allow interaction with main window
        self.setMinimumSize(1000, 700)
        self.resize(1200, 800)
        
        self.db = get_database()
        self.current_email_id = None
        self.init_ui()
        self.load_emails()
    
    def init_ui(self):
        """Initialize the UI with simple, clean design."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(10)
        
        # Title
        title = QLabel("Database Manager")
        title.setStyleSheet("font-size: 16px; font-weight: bold; color: #333;")
        layout.addWidget(title)
        
        # Simple search bar
        search_layout = QHBoxLayout()
        search_label = QLabel("Search:")
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search emails...")
        self.search_input.textChanged.connect(self.search_emails)
        search_layout.addWidget(search_label)
        search_layout.addWidget(self.search_input)
        layout.addLayout(search_layout)
        
        # Main splitter with better styling
        splitter = QSplitter(Qt.Horizontal)
        splitter.setStyleSheet("QSplitter::handle { background-color: #dee2e6; }")
        
        # Email list with better styling
        list_container = QWidget()
        list_layout = QVBoxLayout(list_container)
        list_layout.setContentsMargins(0, 0, 0, 0)
        
        # Simple filter and sort
        filter_layout = QHBoxLayout()
        
        filter_layout.addWidget(QLabel("Date:"))
        self.date_filter = QComboBox()
        self.date_filter.addItems(["All Time", "Today", "Last 7 Days", "Last 30 Days", "Last 90 Days"])
        self.date_filter.currentTextChanged.connect(self.apply_filters)
        filter_layout.addWidget(self.date_filter)
        
        filter_layout.addWidget(QLabel("Sort:"))
        self.sort_combo = QComboBox()
        self.sort_combo.addItems(["Date (Newest)", "Date (Oldest)", "Subject (A-Z)", "Subject (Z-A)", "Sender (A-Z)", "Sender (Z-A)"])
        self.sort_combo.currentTextChanged.connect(self.apply_filters)
        filter_layout.addWidget(self.sort_combo)
        
        filter_layout.addStretch()
        list_layout.addLayout(filter_layout)
        
        # Simple email table
        self.email_table = QTableWidget()
        self.email_table.setColumnCount(4)
        self.email_table.setHorizontalHeaderLabels(["Subject", "Sender", "Date", "ID"])
        self.email_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.email_table.itemSelectionChanged.connect(self.on_email_selected)
        self.email_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.email_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.email_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.email_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.email_table.setAlternatingRowColors(True)
        self.email_table.setSortingEnabled(True)
        list_layout.addWidget(self.email_table)
        layout.addWidget(self.email_table)
        
        # Email details
        details_group = QWidget()
        details_layout = QVBoxLayout(details_group)
        details_layout.setContentsMargins(0, 0, 0, 0)
        
        # Details tabs
        self.details_tabs = QTabWidget()
        
        # Basic info tab
        self.basic_info_text = QTextEdit()
        self.basic_info_text.setReadOnly(True)
        self.basic_info_text.setMaximumHeight(150)
        self.details_tabs.addTab(self.basic_info_text, "Info")
        
        # Headers tab
        self.headers_text = QTextEdit()
        self.headers_text.setReadOnly(True)
        self.details_tabs.addTab(self.headers_text, "Headers")
        
        # Attachments tab
        self.attachments_table = QTableWidget()
        self.attachments_table.setColumnCount(3)
        self.attachments_table.setHorizontalHeaderLabels(["Filename", "Size", "Type"])
        self.attachments_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.attachments_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.attachments_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.details_tabs.addTab(self.attachments_table, "Attachments")
        
        # Analysis results tab
        self.analysis_text = QTextEdit()
        self.analysis_text.setReadOnly(True)
        self.details_tabs.addTab(self.analysis_text, "Analysis")
        
        details_layout.addWidget(self.details_tabs)
        # Analysis toolbar - simplified version
        analysis_toolbar = QWidget()
        analysis_toolbar.setStyleSheet("background-color: #f8f9fa; border: 1px solid #dee2e6; border-radius: 4px; padding: 5px;")
        analysis_layout = QVBoxLayout(analysis_toolbar)
        analysis_layout.setContentsMargins(5, 5, 5, 5)

        # Simple analysis tabs
        self.analysis_tabs = QTabWidget()

        # Content Analysis Tab
        self.content_text = QTextEdit()
        self.content_text.setReadOnly(True)
        self.content_text.setStyleSheet("font-family: 'Consolas', monospace; font-size: 12px;")
        self.analysis_tabs.addTab(self.content_text, "📝 Content")

        # Attachments Analysis Tab
        self.attachments_analysis_table = QTableWidget()
        self.attachments_analysis_table.setColumnCount(4)
        self.attachments_analysis_table.setHorizontalHeaderLabels(["Filename", "Size", "Type", "Hash"])
        self.attachments_analysis_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.attachments_analysis_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.attachments_analysis_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.attachments_analysis_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.analysis_tabs.addTab(self.attachments_analysis_table, "📎 Attachments")

        # Forensics Analysis Tab
        self.forensics_text = QTextEdit()
        self.forensics_text.setReadOnly(True)
        self.forensics_text.setStyleSheet("font-family: 'Consolas', monospace; font-size: 12px;")
        self.analysis_tabs.addTab(self.forensics_text, "🔍 Forensics")

        # Network Analysis Tab
        self.network_text = QTextEdit()
        self.network_text.setReadOnly(True)
        self.network_text.setStyleSheet("font-family: 'Consolas', monospace; font-size: 12px;")
        self.analysis_tabs.addTab(self.network_text, "🌐 Network")

        # Extracted Data Tab
        self.extracted_text = QTextEdit()
        self.extracted_text.setReadOnly(True)
        self.extracted_text.setStyleSheet("font-family: 'Consolas', monospace; font-size: 12px;")
        self.analysis_tabs.addTab(self.extracted_text, "📊 Extracted Data")

        analysis_layout.addWidget(self.analysis_tabs)

        # Analysis control buttons
        analysis_buttons = QHBoxLayout()

        self.analyze_btn = QPushButton("🔍 Analyze Email")
        self.analyze_btn.clicked.connect(self.analyze_selected_email)
        self.analyze_btn.setStyleSheet("QPushButton { padding: 8px 16px; font-weight: bold; }")

        self.export_analysis_btn = QPushButton("📄 Export Analysis")
        self.export_analysis_btn.clicked.connect(self.export_analysis)
        self.export_analysis_btn.setStyleSheet("QPushButton { padding: 8px 16px; }")

        analysis_buttons.addWidget(self.analyze_btn)
        analysis_buttons.addWidget(self.export_analysis_btn)
        analysis_buttons.addStretch()

        analysis_layout.addLayout(analysis_buttons)

        layout.addWidget(analysis_toolbar, stretch=1)
        
        # Action buttons
        button_layout = QHBoxLayout()

        self.load_btn = QPushButton("Load in Analyzer")
        self.load_btn.clicked.connect(self.load_email_in_analyzer)

        self.export_btn = QPushButton("Export")
        self.export_btn.clicked.connect(self.export_email)

        self.group_analysis_btn = QPushButton("Group Analysis")
        self.group_analysis_btn.clicked.connect(self.open_group_analysis)

        self.delete_btn = QPushButton("Delete")
        self.delete_btn.clicked.connect(self.delete_email)

        button_layout.addWidget(self.load_btn)
        button_layout.addWidget(self.export_btn)
        button_layout.addWidget(self.group_analysis_btn)
        button_layout.addWidget(self.delete_btn)
        button_layout.addStretch()
        layout.addLayout(button_layout)
        
        # Status bar with better styling
        status_container = QWidget()
        status_container.setStyleSheet("background-color: #e9ecef; border: 1px solid #dee2e6; border-radius: 4px; padding: 8px;")
        status_layout = QHBoxLayout(status_container)
        status_layout.setContentsMargins(10, 5, 10, 5)
        
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #495057; font-size: 12px;")
        
        status_layout.addWidget(self.status_label)
        status_layout.addStretch()
        
        layout.addWidget(status_container)
        
        # Initially disable action buttons
        self.load_btn.setEnabled(False)
        self.export_btn.setEnabled(False)
        self.delete_btn.setEnabled(False)
    
    def load_emails(self):
        """Load all emails from database."""
        try:
            self.current_emails = self.db.get_all_emails(limit=1000)
            self.populate_email_table(self.current_emails)
            self.status_label.setText(f"Loaded {len(self.current_emails)} emails")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load emails: {str(e)}")
    
    def populate_email_table(self, emails):
        """Populate the email table."""
        self.email_table.setRowCount(len(emails))
        
        for row, email in enumerate(emails):
            self.email_table.setItem(row, 0, QTableWidgetItem(str(email['id'])))
            self.email_table.setItem(row, 1, QTableWidgetItem(email['subject'] or 'No Subject'))
            self.email_table.setItem(row, 2, QTableWidgetItem(email['sender'] or 'Unknown'))
            self.email_table.setItem(row, 3, QTableWidgetItem(email['date_sent'] or 'Unknown'))
            self.email_table.setItem(row, 4, QTableWidgetItem(email['message_id'] or 'Unknown'))
    
    def search_emails(self):
        """Search emails based on query."""
        query = self.search_input.text().strip()
        if not query:
            self.load_emails()
            return
        
        try:
            search_field = self.search_field.currentText()
            search_fields = None
            
            if search_field != "All Fields":
                field_mapping = {
                    "Subject": ["subject"],
                    "Sender": ["sender"],
                    "Recipients": ["recipients"],
                    "Headers": ["raw_headers"]
                }
                search_fields = field_mapping.get(search_field)
            
            emails = self.db.search_emails(query, search_fields)
            self.populate_email_table(emails)
            self.status_label.setText(f"Found {len(emails)} emails matching '{query}'")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Search failed: {str(e)}")
    
    def on_email_selected(self):
        """Handle email selection."""
        selected_items = self.email_table.selectedItems()
        if not selected_items:
            # Disable action buttons when no email is selected
            self.load_btn.setEnabled(False)
            self.export_btn.setEnabled(False)
            self.group_analysis_btn.setEnabled(False)
            self.delete_btn.setEnabled(False)
            return
        
        row = selected_items[0].row()
        email_id = int(self.email_table.item(row, 0).text())
        self.current_email_id = email_id
        
        # Enable action buttons when email is selected
        self.load_btn.setEnabled(True)
        self.export_btn.setEnabled(True)
        self.group_analysis_btn.setEnabled(True)
        self.delete_btn.setEnabled(True)
        
        self.load_email_details(email_id)
    
    def load_email_details(self, email_id):
        """Load detailed information for an email."""
        try:
            email = self.db.get_email_by_id(email_id)
            if not email:
                return
            
            # Basic info
            basic_info = f"""Message ID: {email.get('message_id', 'N/A')}
Subject: {email.get('subject', 'N/A')}
Sender: {email.get('sender', 'N/A')}
Recipients: {email.get('recipients', 'N/A')}
Date Sent: {email.get('date_sent', 'N/A')}
Date Received: {email.get('date_received', 'N/A')}
File Path: {email.get('file_path', 'N/A')}
File Size: {email.get('file_size', 0)} bytes
Acquisition Time: {email.get('acquisition_time', 'N/A')}
Created: {email.get('created_at', 'N/A')}"""
            
            self.basic_info_text.setPlainText(basic_info)
            
            # Headers
            self.headers_text.setPlainText(email.get('raw_headers', 'No headers available'))
            
            # Attachments
            self.populate_attachments_table(email.get('attachments', []))
            
            # IOCs
            self.populate_iocs_table(email.get('iocs', []))
            
            # Analysis results
            analysis_text = ""
            for analysis_type, results in email.get('analysis_results', {}).items():
                analysis_text += f"=== {analysis_type.upper()} ===\n"
                if isinstance(results, dict):
                    for key, value in results.items():
                        analysis_text += f"{key}: {value}\n"
                else:
                    analysis_text += str(results) + "\n"
                analysis_text += "\n"
            
            self.analysis_text.setPlainText(analysis_text if analysis_text else "No analysis results available")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load email details: {str(e)}")
    
    def on_email_selected(self):
        """Handle email selection and populate analysis tabs."""
        selected_items = self.email_table.selectedItems()
        if not selected_items:
            # Disable action buttons when no email is selected
            self.load_btn.setEnabled(False)
            self.export_btn.setEnabled(False)
            self.group_analysis_btn.setEnabled(False)
            self.delete_btn.setEnabled(False)
            self.analyze_btn.setEnabled(False)
            self.export_analysis_btn.setEnabled(False)
            # Clear analysis tabs
            self.clear_analysis_tabs()
            return
        
        row = selected_items[0].row()
        email_id = int(self.email_table.item(row, 0).text())
        self.current_email_id = email_id
        
        # Enable action buttons when email is selected
        self.load_btn.setEnabled(True)
        self.export_btn.setEnabled(True)
        self.group_analysis_btn.setEnabled(True)
        self.delete_btn.setEnabled(True)
        self.analyze_btn.setEnabled(True)
        self.export_analysis_btn.setEnabled(True)
        
        self.load_email_details(email_id)
    
    def populate_iocs_table(self, iocs):
        """Populate the IOCs table."""
        self.iocs_table.setRowCount(len(iocs))
        
        for row, ioc in enumerate(iocs):
            self.iocs_table.setItem(row, 0, QTableWidgetItem(ioc.get('ioc_type', 'N/A')))
            self.iocs_table.setItem(row, 1, QTableWidgetItem(ioc.get('value', 'N/A')))
            self.iocs_table.setItem(row, 2, QTableWidgetItem(ioc.get('severity', 'N/A')))
            self.iocs_table.setItem(row, 3, QTableWidgetItem(ioc.get('description', 'N/A')))
    
    def load_email_in_analyzer(self):
        """Load selected email in the main analyzer."""
        if not self.current_email_id:
            QMessageBox.warning(self, "Warning", "Please select an email first")
            return
        
        try:
            email = self.db.get_email_by_id(self.current_email_id)
            if not email:
                return
            
            # Signal to parent to load this email
            if hasattr(self.parent(), 'load_email_from_database'):
                self.parent().load_email_from_database(email)
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load email: {str(e)}")
    
    def export_email(self):
        """Export selected email."""
        if not self.current_email_id:
            QMessageBox.warning(self, "Warning", "Please select an email first")
            return
        
        try:
            # Get email data
            email = self.db.get_email_by_id(self.current_email_id)
            if not email:
                QMessageBox.warning(self, "Warning", "Email data not found")
                return
            
            # Ask for export location and format
            from PyQt5.QtWidgets import QFileDialog
            file_path, _ = QFileDialog.getSaveFileName(
                self, "Export Email", f"email_{self.current_email_id}", 
                "JSON Files (*.json);;Text Files (*.txt);;All Files (*.*)"
            )
            
            if file_path:
                if file_path.endswith('.json'):
                    self._export_as_json(email, file_path)
                else:
                    self._export_as_text(email, file_path)
                
                self.status_label.setText(f"Email exported to {Path(file_path).name}")
                QMessageBox.information(self, "Success", f"Email exported successfully to:\n{file_path}")
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to export email: {str(e)}")
    
    def open_group_analysis(self):
        """Open group analysis dialog for analyzing multiple emails."""
        try:
            # Get all emails for group analysis
            emails = self.db.get_all_emails(limit=1000)
            if len(emails) < 2:
                QMessageBox.information(self, "Insufficient Data",
                    "At least 2 emails are required for group analysis.")
                return

            # Create and show group analysis dialog
            dialog = GroupAnalysisDialog(emails, self)
            dialog.exec_()

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to open group analysis: {str(e)}")
    
    def _export_as_json(self, email, file_path):
        """Export email as JSON format."""
        import json
        from pathlib import Path
        
        # Prepare export data
        export_data = {
            'email': {
                'id': email.get('id'),
                'message_id': email.get('message_id'),
                'subject': email.get('subject'),
                'sender': email.get('sender'),
                'recipients': email.get('recipients'),
                'date_sent': email.get('date_sent'),
                'date_received': email.get('date_received'),
                'raw_headers': email.get('raw_headers'),
                'raw_body': email.get('raw_body'),
                'file_path': email.get('file_path'),
                'file_size': email.get('file_size'),
                'acquisition_time': email.get('acquisition_time'),
                'created_at': email.get('created_at')
            },
            'attachments': email.get('attachments', []),
            'analysis_results': email.get('analysis_results', {}),
            'iocs': email.get('iocs', []),
            'chain_of_custody': email.get('chain_of_custody', {})
        }
        
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
    
    def _export_as_text(self, email, file_path):
        """Export email as text format."""
        from pathlib import Path
        
        text_content = f"""
EMAIL EXPORT REPORT
==================

Email ID: {email.get('id')}
Message ID: {email.get('message_id')}
Subject: {email.get('subject')}
Sender: {email.get('sender')}
Recipients: {email.get('recipients')}
Date Sent: {email.get('date_sent')}
Date Received: {email.get('date_received')}
File Path: {email.get('file_path')}
File Size: {email.get('file_size')} bytes
Acquisition Time: {email.get('acquisition_time')}

EMAIL HEADERS
-------------
{email.get('raw_headers', 'No headers available')}

EMAIL BODY
----------
{email.get('raw_body', 'No body available')}

ATTACHMENTS
------------
"""
        
        for i, attachment in enumerate(email.get('attachments', []), 1):
            text_content += f"""
Attachment {i}:
  Filename: {attachment.get('filename', 'N/A')}
  Type: {attachment.get('content_type', 'N/A')}
  Size: {attachment.get('size', 0)} bytes
  MD5: {attachment.get('md5_hash', 'N/A')}
"""
        
        text_content += """
INDICATORS OF COMPROMISE (IOCs)
--------------------------------
"""
        
        for i, ioc in enumerate(email.get('iocs', []), 1):
            text_content += f"""
IOC {i}:
  Type: {ioc.get('ioc_type', 'N/A')}
  Value: {ioc.get('value', 'N/A')}
  Severity: {ioc.get('severity', 'N/A')}
  Description: {ioc.get('description', 'N/A')}
"""
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(text_content)
    
    def delete_email(self):
        """Delete selected email."""
        if not self.current_email_id:
            QMessageBox.warning(self, "Warning", "Please select an email first")
            return
        
        reply = QMessageBox.question(
            self, "Confirm Delete",
            "Are you sure you want to delete this email and all related data?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            try:
                success = self.db.delete_email(self.current_email_id)
                if success:
                    self.load_emails()
                    self.clear_details()
                    self.status_label.setText("Email deleted successfully")
                else:
                    QMessageBox.warning(self, "Warning", "Failed to delete email")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Delete failed: {str(e)}")
    
    def clear_details(self):
        """Clear all detail views."""
        self.current_email_id = None
        self.basic_info_text.clear()
        self.headers_text.clear()
        self.attachments_table.setRowCount(0)
        self.iocs_table.setRowCount(0)
        self.analysis_text.clear()
        
        # Disable action buttons
        self.load_btn.setEnabled(False)
        self.export_btn.setEnabled(False)
        self.group_analysis_btn.setEnabled(False)
        self.delete_btn.setEnabled(False)
    
    def apply_filters(self):
        """Apply date and sorting filters to the email list."""
        try:
            # Get current emails or reload if needed
            if not hasattr(self, 'current_emails'):
                self.current_emails = self.db.get_all_emails(limit=1000)
            
            filtered_emails = self.current_emails.copy()
            
            # Apply date filter
            date_filter = self.date_filter.currentText()
            if date_filter != "All Time":
                from datetime import datetime, timedelta
                now = datetime.now()
                
                if date_filter == "Today":
                    start_date = now.replace(hour=0, minute=0, second=0, microsecond=0)
                elif date_filter == "Last 7 Days":
                    start_date = now - timedelta(days=7)
                elif date_filter == "Last 30 Days":
                    start_date = now - timedelta(days=30)
                elif date_filter == "Last 90 Days":
                    start_date = now - timedelta(days=90)
                
                filtered_emails = [
                    email for email in filtered_emails
                    if email.get('date_sent') and 
                    datetime.fromisoformat(email['date_sent'].replace('Z', '+00:00')) >= start_date
                ]
            
            # Apply sorting
            sort_option = self.sort_combo.currentText()
            reverse_sort = False
            
            if sort_option == "Date (Newest)":
                sort_key = 'date_sent'
                reverse_sort = True
            elif sort_option == "Date (Oldest)":
                sort_key = 'date_sent'
            elif sort_option == "Subject (A-Z)":
                sort_key = 'subject'
            elif sort_option == "Subject (Z-A)":
                sort_key = 'subject'
                reverse_sort = True
            elif sort_option == "Sender (A-Z)":
                sort_key = 'sender'
            elif sort_option == "Sender (Z-A)":
                sort_key = 'sender'
                reverse_sort = True
            
            # Sort emails
            if sort_option != "Date (Newest)":  # Default is already newest first
                filtered_emails.sort(
                    key=lambda x: (x.get(sort_key, '') or '').lower(), 
                    reverse=reverse_sort
                )
            
            self.populate_email_table(filtered_emails)
            self.status_label.setText(f"Showing {len(filtered_emails)} emails ({date_filter}, {sort_option})")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to apply filters: {str(e)}")
    
    def on_header_clicked(self, column):
        """Handle header click for sorting."""
        # This is handled by the built-in QTableWidget sorting
        pass
    
    def analyze_selected_email(self):
        """Analyze the currently selected email."""
        if not self.current_email_id:
            QMessageBox.warning(self, "Warning", "Please select an email first")
            return

        try:
            # Get email data
            email = self.db.get_email_by_id(self.current_email_id)
            if not email:
                QMessageBox.warning(self, "Warning", "Email data not found")
                return

            # Perform analysis
            self.perform_email_analysis(email)
            self.status_label.setText(f"Analysis completed for email: {email.get('subject', 'No Subject')}")

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Analysis failed: {str(e)}")

    def perform_email_analysis(self, email_data):
        """Perform comprehensive analysis on email data."""
        try:
            # Create email message from stored data
            from email.message import EmailMessage
            msg = EmailMessage()

            # Set basic headers
            if email_data.get('subject'):
                msg['Subject'] = email_data['subject']
            if email_data.get('sender'):
                msg['From'] = email_data['sender']
            if email_data.get('recipients'):
                msg['To'] = email_data['recipients']
            if email_data.get('date_sent'):
                msg['Date'] = email_data['date_sent']
            if email_data.get('message_id'):
                msg['Message-ID'] = email_data['message_id']

            # Set raw headers if available
            if email_data.get('raw_headers'):
                # Parse and set headers from raw headers string
                import email
                try:
                    parsed_msg = email.message_from_string(email_data['raw_headers'])
                    for key, value in parsed_msg.items():
                        if key not in msg:
                            msg[key] = value
                except:
                    pass  # Use basic headers if parsing fails

            # Populate content analysis
            self.populate_content_analysis(email_data)

            # Populate attachments analysis
            self.populate_attachments_analysis(email_data.get('attachments', []))

            # Populate forensics analysis
            self.populate_forensics_analysis(email_data, msg)

            # Populate network analysis
            self.populate_network_analysis(email_data)

            # Populate extracted data
            self.populate_extracted_data_analysis(email_data)

        except Exception as e:
            print(f"Error in email analysis: {e}")

    def populate_content_analysis(self, email_data):
        """Populate content analysis tab."""
        content = ""

        # Basic info
        content += "EMAIL CONTENT ANALYSIS\n"
        content += "=" * 50 + "\n\n"
        content += f"Subject: {email_data.get('subject', 'N/A')}\n"
        content += f"From: {email_data.get('sender', 'N/A')}\n"
        content += f"To: {email_data.get('recipients', 'N/A')}\n"
        content += f"Date: {email_data.get('date_sent', 'N/A')}\n"
        content += f"Message-ID: {email_data.get('message_id', 'N/A')}\n\n"

        # Body content
        body = email_data.get('raw_body', '')
        if body:
            content += "EMAIL BODY:\n"
            content += "-" * 20 + "\n"
            # Show first 1000 characters
            if len(body) > 1000:
                content += body[:1000] + "\n\n[... Content truncated - full body available in raw data ...]\n"
            else:
                content += body + "\n"
        else:
            content += "No body content available\n"

        self.content_text.setPlainText(content)

    def populate_attachments_analysis(self, attachments):
        """Populate attachments analysis tab."""
        self.attachments_analysis_table.setRowCount(len(attachments))

        for row, attachment in enumerate(attachments):
            filename = attachment.get('filename', 'N/A')
            content_type = attachment.get('content_type', 'N/A')
            size = attachment.get('size', 0)
            md5_hash = attachment.get('md5_hash', 'N/A')

            self.attachments_analysis_table.setItem(row, 0, QTableWidgetItem(filename))
            self.attachments_analysis_table.setItem(row, 1, QTableWidgetItem(f"{size} bytes"))
            self.attachments_analysis_table.setItem(row, 2, QTableWidgetItem(content_type))
            self.attachments_analysis_table.setItem(row, 3, QTableWidgetItem(md5_hash))

    def populate_forensics_analysis(self, email_data, msg):
        """Populate forensics analysis tab - simplified version."""
        forensics_text = "FORENSICS ANALYSIS\n"
        forensics_text += "=" * 30 + "\n\n"

        # IOCs
        iocs = email_data.get('iocs', [])
        if iocs:
            forensics_text += f"INDICATORS OF COMPROMISE ({len(iocs)}):\n"
            forensics_text += "-" * 40 + "\n"
            for ioc in iocs:
                forensics_text += f"• {ioc.get('ioc_type', 'Unknown')}: {ioc.get('value', 'N/A')}"
                forensics_text += f" (Severity: {ioc.get('severity', 'Unknown')})\n"
            forensics_text += "\n"
        else:
            forensics_text += "No IOCs found\n\n"

        # Received headers
        received_headers = msg.get_all('Received', [])
        if received_headers:
            forensics_text += f"RECEIVED HEADERS ({len(received_headers)}):\n"
            forensics_text += "-" * 40 + "\n"
            for i, header in enumerate(reversed(received_headers), 1):
                forensics_text += f"Hop {i}: {header[:100]}...\n"
            forensics_text += "\n"
        else:
            forensics_text += "No received headers found\n\n"

        # Authentication
        auth_results = msg.get('Authentication-Results', '')
        if auth_results:
            forensics_text += f"AUTHENTICATION RESULTS:\n"
            forensics_text += "-" * 40 + "\n"
            forensics_text += f"{auth_results}\n\n"
        else:
            forensics_text += "No authentication results found\n\n"

        # Anomalies
        anomalies = email_data.get('analysis_results', {}).get('forensic', {}).get('anomalies', [])
        if anomalies:
            forensics_text += f"ANOMALIES DETECTED ({len(anomalies)}):\n"
            forensics_text += "-" * 40 + "\n"
            for anomaly in anomalies:
                forensics_text += f"• {anomaly}\n"
            forensics_text += "\n"
        else:
            forensics_text += "No anomalies detected\n\n"

        self.forensics_text.setPlainText(forensics_text)

    def populate_network_analysis(self, email_data):
        """Populate network analysis tab."""
        network_text = "NETWORK ANALYSIS\n"
        network_text += "=" * 30 + "\n\n"

        # IP addresses from IOCs
        iocs = email_data.get('iocs', [])
        ips = [ioc.get('value', '') for ioc in iocs if ioc.get('ioc_type') == 'IP']
        if ips:
            network_text += f"IP Addresses Found ({len(ips)}):\n"
            for ip in ips:
                network_text += f"• {ip}\n"
            network_text += "\n"

        # URLs from IOCs
        urls = [ioc.get('value', '') for ioc in iocs if ioc.get('ioc_type') == 'URL']
        if urls:
            network_text += f"URLs Found ({len(urls)}):\n"
            for url in urls:
                network_text += f"• {url}\n"
            network_text += "\n"

        # Email domains
        sender = email_data.get('sender', '')
        if sender and '@' in sender:
            domain = sender.split('@')[1]
            network_text += f"Sender Domain: {domain}\n"

        recipients = email_data.get('recipients', '')
        if recipients and '@' in recipients:
            domain = recipients.split('@')[1]
            network_text += f"Recipient Domain: {domain}\n"

        self.network_text.setPlainText(network_text)

    def populate_extracted_data_analysis(self, email_data):
        """Populate extracted data analysis tab."""
        extracted_text = "EXTRACTED DATA ANALYSIS\n"
        extracted_text += "=" * 30 + "\n\n"

        # URLs
        iocs = email_data.get('iocs', [])
        urls = [ioc.get('value', '') for ioc in iocs if ioc.get('ioc_type') == 'URL']
        if urls:
            extracted_text += f"URLs ({len(urls)}):\n"
            extracted_text += "-" * 15 + "\n"
            for url in urls:
                extracted_text += f"• {url}\n"
            extracted_text += "\n"

        # Emails
        emails = [ioc.get('value', '') for ioc in iocs if ioc.get('ioc_type') == 'Email']
        if emails:
            extracted_text += f"Email Addresses ({len(emails)}):\n"
            extracted_text += "-" * 25 + "\n"
            for email in emails:
                extracted_text += f"• {email}\n"
            extracted_text += "\n"

        # IPs
        ips = [ioc.get('value', '') for ioc in iocs if ioc.get('ioc_type') == 'IP']
        if ips:
            extracted_text += f"IP Addresses ({len(ips)}):\n"
            extracted_text += "-" * 20 + "\n"
            for ip in ips:
                extracted_text += f"• {ip}\n"
            extracted_text += "\n"

        if not (urls or emails or ips):
            extracted_text += "No extracted data found\n"

        self.extracted_text.setPlainText(extracted_text)

    def export_analysis(self):
        """Export current analysis results."""
        if not self.current_email_id:
            QMessageBox.warning(self, "Warning", "Please select an email first")
            return

        try:
            from PyQt5.QtWidgets import QFileDialog
            file_path, _ = QFileDialog.getSaveFileName(
                self, "Export Analysis", f"analysis_{self.current_email_id}.txt",
                "Text Files (*.txt);;All Files (*.*)"
            )

            if file_path:
                email = self.db.get_email_by_id(self.current_email_id)
                if email:
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write("EMAIL ANALYSIS REPORT\n")
                        f.write("=" * 50 + "\n\n")

                        # Basic info
                        f.write("BASIC INFORMATION\n")
                        f.write("-" * 20 + "\n")
                        f.write(f"Subject: {email.get('subject', 'N/A')}\n")
                        f.write(f"From: {email.get('sender', 'N/A')}\n")
                        f.write(f"To: {email.get('recipients', 'N/A')}\n")
                        f.write(f"Date: {email.get('date_sent', 'N/A')}\n\n")

                        # Content
                        f.write("CONTENT ANALYSIS\n")
                        f.write("-" * 20 + "\n")
                        body = email.get('raw_body', 'No content available')
                        f.write(body[:500] + ("..." if len(body) > 500 else "") + "\n\n")

                        # Attachments
                        f.write("ATTACHMENTS\n")
                        f.write("-" * 20 + "\n")
                        attachments = email.get('attachments', [])
                        if attachments:
                            for i, att in enumerate(attachments, 1):
                                f.write(f"{i}. {att.get('filename', 'Unknown')} - {att.get('size', 0)} bytes\n")
                        else:
                            f.write("No attachments found\n")
                        f.write("\n")

                        # IOCs
                        f.write("INDICATORS OF COMPROMISE\n")
                        f.write("-" * 30 + "\n")
                        iocs = email.get('iocs', [])
                        if iocs:
                            for ioc in iocs:
                                f.write(f"• {ioc.get('ioc_type', 'Unknown')}: {ioc.get('value', 'N/A')}\n")
                        else:
                            f.write("No IOCs found\n")

                    QMessageBox.information(self, "Success", f"Analysis exported to:\n{file_path}")

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Export failed: {str(e)}")

    def clear_analysis_tabs(self):
        """Clear all analysis tabs."""
        self.content_text.clear()
        self.attachments_analysis_table.setRowCount(0)
        self.forensics_text.clear()
        self.network_text.clear()
        self.extracted_text.clear()
    
    def show_statistics(self):
        """Show database statistics dialog."""
        try:
            dialog = DatabaseStatsDialog(self)
            dialog.exec_()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to show statistics: {str(e)}")


class DatabaseStatsDialog(QDialog):
    """Dialog showing database statistics."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.db = get_database()
        self.setWindowTitle("Database Statistics")
        self.setModal(True)
        self.resize(500, 400)
        self.init_ui()
        self.load_stats()
    
    def init_ui(self):
        """Initialize the UI with improved styling."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(10)
        
        # Status bar
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("font-size: 11px; color: #666;")
        layout.addWidget(self.status_label)
        
        # Initially disable action buttons
        self.load_btn.setEnabled(False)
        self.export_btn.setEnabled(False)
        self.delete_btn.setEnabled(False)
