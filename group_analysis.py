#!/usr/bin/env python3
"""
Group Analysis Dialog for analyzing multiple emails together.
"""

import sys
from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QTabWidget,
                             QTableWidget, QTableWidgetItem, QHeaderView,
                             QPushButton, QLabel, QTextEdit, QComboBox,
                             QProgressBar, QMessageBox, QSplitter, QWidget)
from PyQt5.QtCore import Qt
from collections import Counter, defaultdict
from datetime import datetime
import json
from pathlib import Path


class GroupAnalysisDialog(QDialog):
    """Dialog for analyzing multiple emails as a group."""

    def __init__(self, emails, parent=None):
        super().__init__(parent)
        self.emails = emails
        self.setWindowTitle("Group Email Analysis")
        self.setModal(True)
        self.resize(1200, 800)
        self.init_ui()
        self.analyze_emails()

    def init_ui(self):
        """Initialize the UI components."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(10)

        # Title
        title = QLabel("📊 Group Email Analysis")
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #2c3e50; margin-bottom: 10px;")
        layout.addWidget(title)

        # Summary
        summary_text = f"Analyzing {len(self.emails)} emails"
        summary_label = QLabel(summary_text)
        summary_label.setStyleSheet("font-size: 14px; color: #666; margin-bottom: 15px;")
        layout.addWidget(summary_label)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        # Create tab widget for different analysis views
        self.tab_widget = QTabWidget()

        # Overview tab
        self.create_overview_tab()

        # IOCs tab
        self.create_iocs_tab()

        # Senders tab
        self.create_senders_tab()

        # Timeline tab
        self.create_timeline_tab()

        # Content analysis tab
        self.create_content_tab()

        layout.addWidget(self.tab_widget)

        # Buttons
        button_layout = QHBoxLayout()

        self.export_btn = QPushButton("Export Report")
        self.export_btn.clicked.connect(self.export_report)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)

        button_layout.addStretch()
        button_layout.addWidget(self.export_btn)
        button_layout.addWidget(close_btn)

        layout.addLayout(button_layout)

    def create_overview_tab(self):
        """Create overview tab with summary statistics."""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Statistics table
        stats_table = QTableWidget()
        stats_table.setColumnCount(2)
        stats_table.setHorizontalHeaderLabels(["Metric", "Value"])
        stats_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        stats_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        stats_table.setAlternatingRowColors(True)
        stats_table.setMaximumHeight(300)

        # Calculate statistics
        total_size = sum(email.get('file_size', 0) for email in self.emails)
        senders = [email.get('sender', 'Unknown') for email in self.emails]
        sender_domains = [self.extract_domain(sender) for sender in senders]
        subjects = [email.get('subject', 'No Subject') for email in self.emails]

        # Date range
        dates = []
        for email in self.emails:
            date_str = email.get('date_sent')
            if date_str:
                try:
                    dates.append(datetime.fromisoformat(date_str.replace('Z', '+00:00')))
                except:
                    pass

        date_range = "N/A"
        if dates:
            min_date = min(dates)
            max_date = max(dates)
            date_range = f"{min_date.strftime('%Y-%m-%d')} to {max_date.strftime('%Y-%m-%d')}"

        # Statistics data
        stats_data = [
            ("Total Emails", str(len(self.emails))),
            ("Total Size", f"{total_size} bytes"),
            ("Unique Senders", str(len(set(senders)))),
            ("Unique Domains", str(len(set(sender_domains)))),
            ("Date Range", date_range),
            ("Attachments", str(sum(len(email.get('attachments', [])) for email in self.emails))),
        ]

        stats_table.setRowCount(len(stats_data))
        for row, (metric, value) in enumerate(stats_data):
            stats_table.setItem(row, 0, QTableWidgetItem(metric))
            stats_table.setItem(row, 1, QTableWidgetItem(value))

        layout.addWidget(stats_table)
        self.tab_widget.addTab(tab, "📈 Overview")

    def create_iocs_tab(self):
        """Create IOCs aggregation tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # IOCs table
        iocs_table = QTableWidget()
        iocs_table.setColumnCount(4)
        iocs_table.setHorizontalHeaderLabels(["IOC Type", "Value", "Count", "Emails"])
        iocs_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        iocs_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        iocs_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        iocs_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        iocs_table.setAlternatingRowColors(True)

        # Aggregate IOCs
        ioc_counts = defaultdict(lambda: {'count': 0, 'emails': set()})

        for email in self.emails:
            email_iocs = email.get('iocs', [])
            for ioc in email_iocs:
                ioc_type = ioc.get('ioc_type', 'Unknown')
                ioc_value = ioc.get('value', '')
                key = f"{ioc_type}:{ioc_value}"
                ioc_counts[key]['count'] += 1
                ioc_counts[key]['emails'].add(email.get('id', 'Unknown'))

        # Sort by count (descending)
        sorted_iocs = sorted(ioc_counts.items(), key=lambda x: x[1]['count'], reverse=True)

        iocs_table.setRowCount(len(sorted_iocs))
        for row, (key, data) in enumerate(sorted_iocs):
            ioc_type, ioc_value = key.split(':', 1)
            iocs_table.setItem(row, 0, QTableWidgetItem(ioc_type))
            iocs_table.setItem(row, 1, QTableWidgetItem(ioc_value))
            iocs_table.setItem(row, 2, QTableWidgetItem(str(data['count'])))
            iocs_table.setItem(row, 3, QTableWidgetItem(str(len(data['emails']))))

        layout.addWidget(iocs_table)
        self.tab_widget.addTab(tab, "🎯 IOCs")

    def create_senders_tab(self):
        """Create senders analysis tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Senders table
        senders_table = QTableWidget()
        senders_table.setColumnCount(3)
        senders_table.setHorizontalHeaderLabels(["Sender", "Domain", "Count"])
        senders_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        senders_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        senders_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        senders_table.setAlternatingRowColors(True)

        # Count senders
        sender_counts = Counter()
        domain_counts = Counter()

        for email in self.emails:
            sender = email.get('sender', 'Unknown')
            sender_counts[sender] += 1
            domain = self.extract_domain(sender)
            domain_counts[domain] += 1

        # Add sender data
        senders_data = []
        for sender, count in sender_counts.most_common():
            domain = self.extract_domain(sender)
            senders_data.append((sender, domain, count))

        senders_table.setRowCount(len(senders_data))
        for row, (sender, domain, count) in enumerate(senders_data):
            senders_table.setItem(row, 0, QTableWidgetItem(sender))
            senders_table.setItem(row, 1, QTableWidgetItem(domain))
            senders_table.setItem(row, 2, QTableWidgetItem(str(count)))

        layout.addWidget(senders_table)
        self.tab_widget.addTab(tab, "👥 Senders")

    def create_timeline_tab(self):
        """Create timeline analysis tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Timeline table
        timeline_table = QTableWidget()
        timeline_table.setColumnCount(4)
        timeline_table.setHorizontalHeaderLabels(["Date", "Sender", "Subject", "Size"])
        timeline_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        timeline_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        timeline_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        timeline_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        timeline_table.setAlternatingRowColors(True)

        # Sort emails by date
        sorted_emails = []
        for email in self.emails:
            date_str = email.get('date_sent')
            if date_str:
                try:
                    date_obj = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
                    sorted_emails.append((date_obj, email))
                except:
                    sorted_emails.append((datetime.min, email))

        sorted_emails.sort(key=lambda x: x[0], reverse=True)

        timeline_table.setRowCount(len(sorted_emails))
        for row, (date_obj, email) in enumerate(sorted_emails):
            date_str = date_obj.strftime('%Y-%m-%d %H:%M') if date_obj != datetime.min else 'Unknown'
            timeline_table.setItem(row, 0, QTableWidgetItem(date_str))
            timeline_table.setItem(row, 1, QTableWidgetItem(email.get('sender', 'Unknown')))
            timeline_table.setItem(row, 2, QTableWidgetItem(email.get('subject', 'No Subject')))
            timeline_table.setItem(row, 3, QTableWidgetItem(str(email.get('file_size', 0))))

        layout.addWidget(timeline_table)
        self.tab_widget.addTab(tab, "📅 Timeline")

    def create_content_tab(self):
        """Create content analysis tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Content analysis text
        content_text = QTextEdit()
        content_text.setReadOnly(True)

        # Analyze content patterns
        subjects = [email.get('subject', '') for email in self.emails]
        common_subjects = self.find_common_patterns(subjects)

        content_text.append("🔍 Content Analysis Results\n")
        content_text.append("=" * 50 + "\n\n")

        content_text.append("📧 Subject Line Patterns:\n")
        content_text.append("-" * 30 + "\n")
        if common_subjects:
            for pattern, count in common_subjects:
                content_text.append(f"• '{pattern}' (found in {count} emails)\n")
        else:
            content_text.append("No common subject patterns found.\n")

        content_text.append("\n📊 Email Size Distribution:\n")
        content_text.append("-" * 30 + "\n")
        sizes = [email.get('file_size', 0) for email in self.emails]
        if sizes:
            min_size = min(sizes)
            max_size = max(sizes)
            avg_size = sum(sizes) / len(sizes)
            content_text.append(f"• Smallest: {min_size} bytes\n")
            content_text.append(f"• Largest: {max_size} bytes\n")
            content_text.append(f"• Average: {avg_size:.0f} bytes\n")

        layout.addWidget(content_text)
        self.tab_widget.addTab(tab, "📝 Content")

    def analyze_emails(self):
        """Perform the group analysis."""
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate progress

        # Analysis is already done in tab creation
        # This could be extended to do more complex analysis

        self.progress_bar.setVisible(False)

    def extract_domain(self, email_address):
        """Extract domain from email address."""
        if '@' in email_address:
            return email_address.split('@')[1].lower()
        return 'Unknown'

    def find_common_patterns(self, strings, min_length=3):
        """Find common patterns in a list of strings."""
        if len(strings) < 2:
            return []

        # Simple pattern matching - look for common substrings
        patterns = Counter()

        for string in strings:
            words = string.lower().split()
            for word in words:
                if len(word) >= min_length:
                    patterns[word] += 1

        # Return patterns that appear in multiple emails
        return [(pattern, count) for pattern, count in patterns.most_common() if count > 1]

    def export_report(self):
        """Export group analysis report."""
        try:
            from PyQt5.QtWidgets import QFileDialog

            file_path, _ = QFileDialog.getSaveFileName(
                self, "Export Group Analysis Report", "group_analysis.json",
                "JSON Files (*.json);;Text Files (*.txt);;All Files (*.*)"
            )

            if not file_path:
                return

            # Prepare report data
            report_data = {
                'analysis_summary': {
                    'total_emails': len(self.emails),
                    'analysis_date': datetime.now().isoformat(),
                    'email_ids': [email.get('id') for email in self.emails]
                },
                'statistics': self.get_statistics(),
                'ioc_analysis': self.get_ioc_analysis(),
                'sender_analysis': self.get_sender_analysis(),
                'timeline': self.get_timeline_data(),
                'content_analysis': self.get_content_analysis()
            }

            if file_path.endswith('.json'):
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(report_data, f, indent=2, ensure_ascii=False)
            else:
                self.export_as_text(report_data, file_path)

            QMessageBox.information(self, "Success",
                f"Group analysis report exported successfully to:\n{file_path}")

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to export report: {str(e)}")

    def get_statistics(self):
        """Get basic statistics."""
        total_size = sum(email.get('file_size', 0) for email in self.emails)
        senders = [email.get('sender', 'Unknown') for email in self.emails]
        sender_domains = [self.extract_domain(sender) for sender in senders]

        return {
            'total_emails': len(self.emails),
            'total_size': total_size,
            'unique_senders': len(set(senders)),
            'unique_domains': len(set(sender_domains)),
        }

    def get_ioc_analysis(self):
        """Get IOC analysis data."""
        ioc_counts = defaultdict(lambda: {'count': 0, 'emails': set()})

        for email in self.emails:
            email_iocs = email.get('iocs', [])
            for ioc in email_iocs:
                ioc_type = ioc.get('ioc_type', 'Unknown')
                ioc_value = ioc.get('value', '')
                key = f"{ioc_type}:{ioc_value}"
                ioc_counts[key]['count'] += 1
                ioc_counts[key]['emails'].add(email.get('id', 'Unknown'))

        return dict(ioc_counts)

    def get_sender_analysis(self):
        """Get sender analysis data."""
        sender_counts = Counter()
        domain_counts = Counter()

        for email in self.emails:
            sender = email.get('sender', 'Unknown')
            sender_counts[sender] += 1
            domain = self.extract_domain(sender)
            domain_counts[domain] += 1

        return {
            'senders': dict(sender_counts.most_common()),
            'domains': dict(domain_counts.most_common())
        }

    def get_timeline_data(self):
        """Get timeline analysis data."""
        timeline = []

        for email in self.emails:
            date_str = email.get('date_sent')
            if date_str:
                try:
                    date_obj = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
                    timeline.append({
                        'email_id': email.get('id'),
                        'date': date_obj.isoformat(),
                        'sender': email.get('sender'),
                        'subject': email.get('subject'),
                        'size': email.get('file_size', 0)
                    })
                except:
                    pass

        return sorted(timeline, key=lambda x: x['date'], reverse=True)

    def get_content_analysis(self):
        """Get content analysis data."""
        subjects = [email.get('subject', '') for email in self.emails]
        return {
            'common_subjects': self.find_common_patterns(subjects),
            'subject_word_count': dict(Counter(word.lower() for subject in subjects for word in subject.split() if len(word) > 3))
        }

    def export_as_text(self, report_data, file_path):
        """Export report as text format."""
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write("GROUP EMAIL ANALYSIS REPORT\n")
            f.write("=" * 50 + "\n\n")

            stats = report_data['statistics']
            f.write(f"Total Emails: {stats['total_emails']}\n")
            f.write(f"Total Size: {stats['total_size']} bytes\n")
            f.write(f"Unique Senders: {stats['unique_senders']}\n")
            f.write(f"Unique Domains: {stats['unique_domains']}\n\n")

            # IOC Analysis
            f.write("INDICATORS OF COMPROMISE\n")
            f.write("-" * 30 + "\n")
            ioc_analysis = report_data['ioc_analysis']
            for ioc_key, ioc_data in ioc_analysis.items():
                ioc_type, ioc_value = ioc_key.split(':', 1)
                f.write(f"• {ioc_type}: {ioc_value} (found in {ioc_data['count']} emails)\n")

            f.write("\nTOP SENDERS\n")
            f.write("-" * 30 + "\n")
            sender_analysis = report_data['sender_analysis']
            for sender, count in list(sender_analysis['senders'].items())[:10]:
                f.write(f"• {sender}: {count} emails\n")


if __name__ == "__main__":
    # Test the dialog
    from PyQt5.QtWidgets import QApplication
    import sys

    app = QApplication(sys.argv)
    emails = [
        {'id': 1, 'sender': 'test@example.com', 'subject': 'Test Subject', 'file_size': 1000},
        {'id': 2, 'sender': 'test@example.com', 'subject': 'Another Test', 'file_size': 1500},
    ]
    dialog = GroupAnalysisDialog(emails)
    dialog.show()
    sys.exit(app.exec_())
