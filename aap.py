from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
from config import Config
import os

# Initialize Extensions globally
db = SQLAlchemy()
socketio = SocketIO()
login_manager = LoginManager()
bcrypt = Bcrypt()

def create_app(config_class=Config):
    """Application Factory to create and configure the Flask app."""
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize directories setup in config
    config_class.init_app(app)

    # Bind extensions to the app
    db.init_app(app)
    # Use async_mode='eventlet' for production-grade real-time capabilities
    socketio.init_app(app, async_mode='eventlet', cors_allowed_origins="*")
    
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message_category = 'info'
    bcrypt.init_app(app)

    # Import Blueprints (We will create these in Module 5)
    # from routes.auth_routes import auth_bp
    # from routes.main_routes import main_bp
    # from routes.api_routes import api_bp

    # Register Blueprints
    # app.register_blueprint(auth_bp)
    # app.register_blueprint(main_bp)
    # app.register_blueprint(api_bp)

    return app

# Create the application instance
app = create_app()

if __name__ == '__main__':
    # Print startup banner
    print("="*50)
    print("🛡️  Starting Network Sniffer & Traffic Analyzer 🛡️")
    print("="*50)
    
    # Run using SocketIO (required for real-time WebSockets instead of standard app.run)
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)