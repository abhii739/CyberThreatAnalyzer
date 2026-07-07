"""
Configuration file for Cyber Threat Log Analyzer
"""
import os
from datetime import timedelta

# Application settings
SECRET_KEY = 'your-secret-key-change-in-production'
DEBUG = False
TESTING = False

# Database settings
DATABASE_TYPE = 'sqlite'  # 'sqlite' or 'mysql'
SQLALCHEMY_DATABASE_URI = 'sqlite:///database.db'
SQLALCHEMY_TRACK_MODIFICATIONS = False

# MySQL configuration (optional)
MYSQL_HOST = 'localhost'
MYSQL_USER = 'root'
MYSQL_PASSWORD = 'password'
MYSQL_DB = 'cyber_threat_analyzer'

# Session settings
PERMANENT_SESSION_LIFETIME = timedelta(hours=24)
SESSION_REFRESH_EACH_REQUEST = True

# Upload settings
UPLOAD_FOLDER = 'uploads'
REPORTS_FOLDER = 'reports'
SAMPLE_LOGS_FOLDER = 'sample_logs'
MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50MB max file size
ALLOWED_EXTENSIONS = {'csv'}

# Security settings
PASSWORD_MIN_LENGTH = 6
PASSWORD_HASH_METHOD = 'pbkdf2:sha256'

# Analysis settings
BRUTE_FORCE_THRESHOLD = 10
PORT_SCAN_THRESHOLD = 20
FAILED_LOGIN_TIME_WINDOW = 3600  # seconds (1 hour)

# Dashboard settings
ITEMS_PER_PAGE = 10
MAX_CHART_ITEMS = 10

# Paths
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_PATH = os.path.join(BASE_DIR, UPLOAD_FOLDER)
REPORTS_PATH = os.path.join(BASE_DIR, REPORTS_FOLDER)
SAMPLE_LOGS_PATH = os.path.join(BASE_DIR, SAMPLE_LOGS_FOLDER)
