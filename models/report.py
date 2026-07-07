"""
Report model for storing generated reports
"""
import sqlite3
import config
from datetime import datetime

class Report:
    """Report model for handling report storage and retrieval"""
    
    def __init__(self, id=None, generated_on=None, filename=None, summary=None):
        self.id = id
        self.generated_on = generated_on
        self.filename = filename
        self.summary = summary
    
    @staticmethod
    def get_db():
        """Get database connection"""
        conn = sqlite3.connect(config.SQLALCHEMY_DATABASE_URI.replace('sqlite:///', ''))
        conn.row_factory = sqlite3.Row
        return conn
    
    @staticmethod
    def create_reports_table():
        """Create reports table if not exists"""
        conn = Report.get_db()
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                generated_on TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                filename TEXT NOT NULL,
                summary TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
        conn.close()
    
    def save(self):
        """Save report to database"""
        conn = Report.get_db()
        cursor = conn.cursor()
        
        self.generated_on = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        cursor.execute('''
            INSERT INTO reports (generated_on, filename, summary)
            VALUES (?, ?, ?)
        ''', (self.generated_on, self.filename, self.summary))
        
        conn.commit()
        self.id = cursor.lastrowid
        conn.close()
        return True
    
    @staticmethod
    def get_all_reports():
        """Get all reports"""
        conn = Report.get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM reports ORDER BY generated_on DESC')
        rows = cursor.fetchall()
        conn.close()
        
        reports = []
        for row in rows:
            report = Report(id=row['id'], generated_on=row['generated_on'],
                          filename=row['filename'], summary=row['summary'])
            reports.append(report)
        return reports
    
    @staticmethod
    def get_total_count():
        """Get total number of reports"""
        conn = Report.get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) as count FROM reports')
        row = cursor.fetchone()
        conn.close()
        return row['count'] if row else 0
    
    @staticmethod
    def delete_report(report_id):
        """Delete a report"""
        conn = Report.get_db()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM reports WHERE id = ?', (report_id,))
        conn.commit()
        conn.close()
        return True
