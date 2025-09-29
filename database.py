"""
Database module for storing and retrieving email messages.
"""

import sqlite3
import json
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any


class EmailDatabase:
    """SQLite database for storing email messages and analysis results."""
    
    def __init__(self, db_path: str = "email_investigator.db"):
        """Initialize database connection."""
        self.db_path = db_path
        self.conn = None
        self.connect()
        self.create_tables()
    
    def connect(self):
        """Connect to SQLite database."""
        try:
            self.conn = sqlite3.connect(self.db_path)
            self.conn.row_factory = sqlite3.Row  # Return rows as dictionaries
        except sqlite3.Error as e:
            print(f"Database connection error: {e}")
            raise
    
    def create_tables(self):
        """Create database tables if they don't exist."""
        try:
            cursor = self.conn.cursor()
            
            # Emails table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS emails (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    message_id TEXT UNIQUE,
                    subject TEXT,
                    sender TEXT,
                    recipients TEXT,
                    date_sent TEXT,
                    date_received TEXT,
                    raw_headers TEXT,
                    raw_body TEXT,
                    file_hash TEXT,
                    file_path TEXT,
                    file_size INTEGER,
                    acquisition_time TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Attachments table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS attachments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email_id INTEGER,
                    filename TEXT,
                    content_type TEXT,
                    size INTEGER,
                    md5_hash TEXT,
                    sha256_hash TEXT,
                    data BLOB,
                    FOREIGN KEY (email_id) REFERENCES emails (id) ON DELETE CASCADE
                )
            ''')
            
            # Analysis results table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS analysis_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email_id INTEGER,
                    analysis_type TEXT,
                    results TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (email_id) REFERENCES emails (id) ON DELETE CASCADE
                )
            ''')
            
            # IOCs table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS iocs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email_id INTEGER,
                    ioc_type TEXT,
                    value TEXT,
                    severity TEXT,
                    description TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (email_id) REFERENCES emails (id) ON DELETE CASCADE
                )
            ''')
            
            # Chain of custody table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS chain_of_custody (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email_id INTEGER,
                    analyst TEXT,
                    case_number TEXT,
                    exhibit_number TEXT,
                    seal_number TEXT,
                    notes TEXT,
                    timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (email_id) REFERENCES emails (id) ON DELETE CASCADE
                )
            ''')
            
            # Create indexes for better performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_emails_message_id ON emails(message_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_emails_sender ON emails(sender)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_emails_date ON emails(date_sent)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_attachments_email_id ON attachments(email_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_analysis_email_id ON analysis_results(email_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_iocs_email_id ON iocs(email_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(ioc_type)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value)')
            
            self.conn.commit()
            
        except sqlite3.Error as e:
            print(f"Error creating tables: {e}")
            raise
    
    def store_email(self, email_data: Dict[str, Any]) -> int:
        """Store email message and return email ID."""
        try:
            cursor = self.conn.cursor()
            
            # Calculate file hash for deduplication
            file_hash = self._calculate_hash(email_data.get('raw_data', b''))
            
            # Check if email already exists
            existing = self.get_email_by_message_id(email_data.get('message_id'))
            if existing:
                return existing['id']
            
            # Insert email
            cursor.execute('''
                INSERT INTO emails (
                    message_id, subject, sender, recipients, date_sent, date_received,
                    raw_headers, raw_body, file_hash, file_path, file_size, acquisition_time
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                email_data.get('message_id'),
                email_data.get('subject'),
                email_data.get('sender'),
                email_data.get('recipients'),
                email_data.get('date_sent'),
                email_data.get('date_received'),
                email_data.get('raw_headers'),
                email_data.get('raw_body'),
                file_hash,
                email_data.get('file_path'),
                email_data.get('file_size'),
                email_data.get('acquisition_time', datetime.now().isoformat())
            ))
            
            email_id = cursor.lastrowid
            
            # Store attachments
            for attachment in email_data.get('attachments', []):
                cursor.execute('''
                    INSERT INTO attachments (
                        email_id, filename, content_type, size, md5_hash, sha256_hash, data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    email_id,
                    attachment.get('name'),
                    attachment.get('content_type'),
                    attachment.get('size'),
                    attachment.get('md5'),
                    attachment.get('sha256'),
                    attachment.get('data')
                ))
            
            # Store analysis results
            for analysis_type, results in email_data.get('analysis_results', {}).items():
                cursor.execute('''
                    INSERT INTO analysis_results (email_id, analysis_type, results)
                    VALUES (?, ?, ?)
                ''', (email_id, analysis_type, json.dumps(results)))
            
            # Store IOCs
            for ioc in email_data.get('iocs', []):
                cursor.execute('''
                    INSERT INTO iocs (email_id, ioc_type, value, severity, description)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    email_id,
                    ioc.get('type'),
                    ioc.get('value'),
                    ioc.get('severity', 'medium'),
                    ioc.get('description', '')
                ))
            
            # Store chain of custody
            custody_data = email_data.get('chain_of_custody', {})
            if custody_data:
                cursor.execute('''
                    INSERT INTO chain_of_custody (
                        email_id, analyst, case_number, exhibit_number, seal_number, notes
                    ) VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    email_id,
                    custody_data.get('analyst'),
                    custody_data.get('case_number'),
                    custody_data.get('exhibit_number'),
                    custody_data.get('seal_number'),
                    custody_data.get('notes')
                ))
            
            self.conn.commit()
            return email_id
            
        except sqlite3.Error as e:
            print(f"Error storing email: {e}")
            self.conn.rollback()
            raise
    
    def get_email_by_id(self, email_id: int) -> Optional[Dict[str, Any]]:
        """Retrieve email by ID."""
        try:
            cursor = self.conn.cursor()
            cursor.execute('SELECT * FROM emails WHERE id = ?', (email_id,))
            row = cursor.fetchone()
            
            if row:
                email = dict(row)
                email['attachments'] = self.get_attachments(email_id)
                email['analysis_results'] = self.get_analysis_results(email_id)
                email['iocs'] = self.get_iocs(email_id)
                email['chain_of_custody'] = self.get_chain_of_custody(email_id)
                return email
            
            return None
            
        except sqlite3.Error as e:
            print(f"Error retrieving email: {e}")
            return None
    
    def get_email_by_message_id(self, message_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve email by message ID."""
        try:
            cursor = self.conn.cursor()
            cursor.execute('SELECT * FROM emails WHERE message_id = ?', (message_id,))
            row = cursor.fetchone()
            
            if row:
                email = dict(row)
                email['attachments'] = self.get_attachments(email['id'])
                email['analysis_results'] = self.get_analysis_results(email['id'])
                email['iocs'] = self.get_iocs(email['id'])
                email['chain_of_custody'] = self.get_chain_of_custody(email['id'])
                return email
            
            return None
            
        except sqlite3.Error as e:
            print(f"Error retrieving email: {e}")
            return None
    
    def get_all_emails(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """Get all emails with pagination."""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                SELECT id, message_id, subject, sender, date_sent, created_at 
                FROM emails 
                ORDER BY date_sent DESC 
                LIMIT ? OFFSET ?
            ''', (limit, offset))
            
            emails = []
            for row in cursor.fetchall():
                emails.append(dict(row))
            
            return emails
            
        except sqlite3.Error as e:
            print(f"Error retrieving emails: {e}")
            return []
    
    def search_emails(self, query: str, search_fields: List[str] = None) -> List[Dict[str, Any]]:
        """Search emails by query."""
        try:
            cursor = self.conn.cursor()
            
            if search_fields is None:
                search_fields = ['subject', 'sender', 'recipients', 'raw_headers']
            
            where_conditions = []
            params = []
            
            for field in search_fields:
                where_conditions.append(f"{field} LIKE ?")
                params.append(f"%{query}%")
            
            where_clause = " OR ".join(where_conditions)
            
            cursor.execute(f'''
                SELECT id, message_id, subject, sender, date_sent, created_at 
                FROM emails 
                WHERE {where_clause}
                ORDER BY date_sent DESC
                LIMIT 100
            ''', params)
            
            emails = []
            for row in cursor.fetchall():
                emails.append(dict(row))
            
            return emails
            
        except sqlite3.Error as e:
            print(f"Error searching emails: {e}")
            return []
    
    def get_attachments(self, email_id: int) -> List[Dict[str, Any]]:
        """Get attachments for an email."""
        try:
            cursor = self.conn.cursor()
            cursor.execute('SELECT * FROM attachments WHERE email_id = ?', (email_id,))
            
            attachments = []
            for row in cursor.fetchall():
                attachments.append(dict(row))
            
            return attachments
            
        except sqlite3.Error as e:
            print(f"Error retrieving attachments: {e}")
            return []
    
    def get_analysis_results(self, email_id: int) -> Dict[str, Any]:
        """Get analysis results for an email."""
        try:
            cursor = self.conn.cursor()
            cursor.execute('SELECT analysis_type, results FROM analysis_results WHERE email_id = ?', (email_id,))
            
            results = {}
            for row in cursor.fetchall():
                results[row['analysis_type']] = json.loads(row['results'])
            
            return results
            
        except sqlite3.Error as e:
            print(f"Error retrieving analysis results: {e}")
            return {}
    
    def get_iocs(self, email_id: int) -> List[Dict[str, Any]]:
        """Get IOCs for an email."""
        try:
            cursor = self.conn.cursor()
            cursor.execute('SELECT * FROM iocs WHERE email_id = ?', (email_id,))
            
            iocs = []
            for row in cursor.fetchall():
                iocs.append(dict(row))
            
            return iocs
            
        except sqlite3.Error as e:
            print(f"Error retrieving IOCs: {e}")
            return []
    
    def get_chain_of_custody(self, email_id: int) -> Dict[str, Any]:
        """Get chain of custody for an email."""
        try:
            cursor = self.conn.cursor()
            cursor.execute('SELECT * FROM chain_of_custody WHERE email_id = ? ORDER BY timestamp DESC', (email_id,))
            
            row = cursor.fetchone()
            return dict(row) if row else {}
            
        except sqlite3.Error as e:
            print(f"Error retrieving chain of custody: {e}")
            return {}
    
    def update_email(self, email_id: int, email_data: Dict[str, Any]) -> bool:
        """Update email record."""
        try:
            cursor = self.conn.cursor()
            
            cursor.execute('''
                UPDATE emails SET
                    subject = ?, sender = ?, recipients = ?, date_sent = ?, date_received = ?,
                    raw_headers = ?, raw_body = ?, file_path = ?, file_size = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (
                email_data.get('subject'),
                email_data.get('sender'),
                email_data.get('recipients'),
                email_data.get('date_sent'),
                email_data.get('date_received'),
                email_data.get('raw_headers'),
                email_data.get('raw_body'),
                email_data.get('file_path'),
                email_data.get('file_size'),
                email_id
            ))
            
            self.conn.commit()
            return cursor.rowcount > 0
            
        except sqlite3.Error as e:
            print(f"Error updating email: {e}")
            self.conn.rollback()
            return False
    
    def delete_email(self, email_id: int) -> bool:
        """Delete email and all related records."""
        try:
            cursor = self.conn.cursor()
            cursor.execute('DELETE FROM emails WHERE id = ?', (email_id,))
            self.conn.commit()
            return cursor.rowcount > 0
            
        except sqlite3.Error as e:
            print(f"Error deleting email: {e}")
            self.conn.rollback()
            return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get database statistics."""
        try:
            cursor = self.conn.cursor()
            
            stats = {}
            
            # Total emails
            cursor.execute('SELECT COUNT(*) FROM emails')
            stats['total_emails'] = cursor.fetchone()[0]
            
            # Total attachments
            cursor.execute('SELECT COUNT(*) FROM attachments')
            stats['total_attachments'] = cursor.fetchone()[0]
            
            # Total IOCs
            cursor.execute('SELECT COUNT(*) FROM iocs')
            stats['total_iocs'] = cursor.fetchone()[0]
            
            # IOCs by type
            cursor.execute('SELECT ioc_type, COUNT(*) FROM iocs GROUP BY ioc_type')
            stats['iocs_by_type'] = dict(cursor.fetchall())
            
            # Emails by date (last 30 days)
            cursor.execute('''
                SELECT DATE(date_sent) as date, COUNT(*) 
                FROM emails 
                WHERE date_sent >= date('now', '-30 days')
                GROUP BY DATE(date_sent)
                ORDER BY date
            ''')
            stats['emails_by_date'] = dict(cursor.fetchall())
            
            return stats
            
        except sqlite3.Error as e:
            print(f"Error getting statistics: {e}")
            return {}
    
    def _calculate_hash(self, data: bytes) -> str:
        """Calculate SHA-256 hash of data."""
        return hashlib.sha256(data).hexdigest()
    
    def clear_all_emails(self) -> bool:
        """Clear all emails and related data from database."""
        try:
            cursor = self.conn.cursor()
            cursor.execute('DELETE FROM emails')
            self.conn.commit()
            return True
        except sqlite3.Error as e:
            print(f"Error clearing emails: {e}")
            self.conn.rollback()
            return False
    
    def create_backup(self, backup_path: str) -> bool:
        """Create backup of database to specified path."""
        try:
            import shutil
            shutil.copy2(self.db_path, backup_path)
            return True
        except Exception as e:
            print(f"Error creating backup: {e}")
            return False
    
    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()
    
    def __del__(self):
        """Destructor to close database connection."""
        self.close()


# Database manager singleton
_db_instance = None

def get_database() -> EmailDatabase:
    """Get database instance (singleton)."""
    global _db_instance
    if _db_instance is None:
        _db_instance = EmailDatabase()
    return _db_instance
