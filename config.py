import os
from dotenv import load_dotenv

# Base directory of the project
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Load environment variables from .env file
load_dotenv(os.path.join(BASE_DIR, '.env'))

class Config:
    """Base configuration."""
    SECRET_KEY = os.environ.get('SECRET_KEY', 'super-secret-cyber-key-9988')
    
    # SQLite Database configuration - absolute path for Windows compatibility
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(BASE_DIR, 'instance', 'network_sniffer.db').replace('\\', '/')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Packet Capture Settings
    MAX_PACKET_STORAGE = 100000  # Prevent SQLite database from growing too large
    PORT_SCAN_THRESHOLD = 20    # Number of unique ports before triggering scan alert
    EXPORT_DIRECTORY = os.path.join(BASE_DIR, 'exports')
    
    # Create necessary directories if they don't exist
    @staticmethod
    def init_app(app):
        os.makedirs(Config.EXPORT_DIRECTORY, exist_ok=True)
        os.makedirs(os.path.join(BASE_DIR, 'instance'), exist_ok=True)