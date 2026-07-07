"""
User model for authentication
"""
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import config

class User:
    """User model for handling user authentication and storage"""
    
    def __init__(self, id=None, name=None, email=None, password=None):
        self.id = id
        self.name = name
        self.email = email
        self.password = password
    
    @staticmethod
    def get_db():
        """Get database connection"""
        conn = sqlite3.connect(config.SQLALCHEMY_DATABASE_URI.replace('sqlite:///', ''))
        conn.row_factory = sqlite3.Row
        return conn
    
    @staticmethod
    def create_users_table():
        """Create users table if not exists"""
        conn = User.get_db()
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
        conn.close()
    
    def save(self):
        """Save user to database"""
        conn = User.get_db()
        cursor = conn.cursor()
        
        hashed_password = generate_password_hash(self.password, method=config.PASSWORD_HASH_METHOD)
        
        try:
            cursor.execute('''
                INSERT INTO users (name, email, password)
                VALUES (?, ?, ?)
            ''', (self.name, self.email, hashed_password))
            conn.commit()
            self.id = cursor.lastrowid
            return True
        except sqlite3.IntegrityError:
            return False
        finally:
            conn.close()
    
    @staticmethod
    def find_by_email(email):
        """Find user by email"""
        conn = User.get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            user = User(id=row['id'], name=row['name'], email=row['email'], password=row['password'])
            return user
        return None
    
    @staticmethod
    def find_by_id(user_id):
        """Find user by ID"""
        conn = User.get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            user = User(id=row['id'], name=row['name'], email=row['email'], password=row['password'])
            return user
        return None
    
    def verify_password(self, password):
        """Verify password"""
        return check_password_hash(self.password, password)
    
    @staticmethod
    def get_all_users():
        """Get all users"""
        conn = User.get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users ORDER BY created_at DESC')
        rows = cursor.fetchall()
        conn.close()
        
        users = []
        for row in rows:
            user = User(id=row['id'], name=row['name'], email=row['email'])
            users.append(user)
        return users
