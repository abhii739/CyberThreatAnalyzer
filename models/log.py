"""
Log model for storing security logs
"""
import sqlite3
import config
from datetime import datetime

class Log:
    """Log model for handling security log storage and retrieval"""
    
    def __init__(self, id=None, timestamp=None, username=None, source_ip=None,
                 destination_ip=None, country=None, port=None, protocol=None,
                 status=None, attack_type=None):
        self.id = id
        self.timestamp = timestamp
        self.username = username
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.country = country
        self.port = port
        self.protocol = protocol
        self.status = status
        self.attack_type = attack_type
    
    @staticmethod
    def get_db():
        """Get database connection"""
        conn = sqlite3.connect(config.SQLALCHEMY_DATABASE_URI.replace('sqlite:///', ''))
        conn.row_factory = sqlite3.Row
        return conn
    
    @staticmethod
    def create_logs_table():
        """Create logs table if not exists"""
        conn = Log.get_db()
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                username TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                destination_ip TEXT NOT NULL,
                country TEXT,
                port INTEGER,
                protocol TEXT,
                status TEXT,
                attack_type TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
        conn.close()
    
    def save(self):
        """Save log to database"""
        conn = Log.get_db()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO logs (timestamp, username, source_ip, destination_ip,
                            country, port, protocol, status, attack_type)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (self.timestamp, self.username, self.source_ip, self.destination_ip,
              self.country, self.port, self.protocol, self.status, self.attack_type))
        
        conn.commit()
        self.id = cursor.lastrowid
        conn.close()
        return True
    
    @staticmethod
    def save_batch(logs):
        """Save multiple logs to database"""
        conn = Log.get_db()
        cursor = conn.cursor()
        
        data = [(log.timestamp, log.username, log.source_ip, log.destination_ip,
                log.country, log.port, log.protocol, log.status, log.attack_type)
                for log in logs]
        
        cursor.executemany('''
            INSERT INTO logs (timestamp, username, source_ip, destination_ip,
                            country, port, protocol, status, attack_type)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', data)
        
        conn.commit()
        conn.close()
        return True
    
    @staticmethod
    def get_all_logs(limit=None, offset=0):
        """Get all logs with pagination"""
        conn = Log.get_db()
        cursor = conn.cursor()
        
        if limit:
            cursor.execute('''
                SELECT * FROM logs ORDER BY timestamp DESC LIMIT ? OFFSET ?
            ''', (limit, offset))
        else:
            cursor.execute('SELECT * FROM logs ORDER BY timestamp DESC')
        
        rows = cursor.fetchall()
        conn.close()
        
        logs = []
        for row in rows:
            log = Log(id=row['id'], timestamp=row['timestamp'], username=row['username'],
                     source_ip=row['source_ip'], destination_ip=row['destination_ip'],
                     country=row['country'], port=row['port'], protocol=row['protocol'],
                     status=row['status'], attack_type=row['attack_type'])
            logs.append(log)
        return logs
    
    @staticmethod
    def get_total_count():
        """Get total number of logs"""
        conn = Log.get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) as count FROM logs')
        row = cursor.fetchone()
        conn.close()
        return row['count'] if row else 0
    
    @staticmethod
    def search_logs(search_type, search_value, limit=None, offset=0):
        """Search logs by username, IP, country, attack type, or risk level"""
        conn = Log.get_db()
        cursor = conn.cursor()
        
        query = 'SELECT * FROM logs WHERE '
        params = []
        
        if search_type == 'username':
            query += 'username LIKE ?'
            params.append(f'%{search_value}%')
        elif search_type == 'ip':
            query += 'source_ip LIKE ? OR destination_ip LIKE ?'
            params.extend([f'%{search_value}%', f'%{search_value}%'])
        elif search_type == 'country':
            query += 'country LIKE ?'
            params.append(f'%{search_value}%')
        elif search_type == 'attack_type':
            query += 'attack_type LIKE ?'
            params.append(f'%{search_value}%')
        
        query += ' ORDER BY timestamp DESC'
        
        if limit:
            query += ' LIMIT ? OFFSET ?'
            params.extend([limit, offset])
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        
        logs = []
        for row in rows:
            log = Log(id=row['id'], timestamp=row['timestamp'], username=row['username'],
                     source_ip=row['source_ip'], destination_ip=row['destination_ip'],
                     country=row['country'], port=row['port'], protocol=row['protocol'],
                     status=row['status'], attack_type=row['attack_type'])
            logs.append(log)
        return logs
    
    @staticmethod
    def delete_all_logs():
        """Delete all logs"""
        conn = Log.get_db()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM logs')
        conn.commit()
        conn.close()
        return True
