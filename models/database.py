from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    
    def __repr__(self):
        return f'<User {self.username}>'

class PacketLog(db.Model):
    __tablename__ = 'packet_logs'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    src_ip = db.Column(db.String(50), nullable=False)
    dst_ip = db.Column(db.String(50), nullable=False)
    protocol = db.Column(db.String(20), nullable=False)
    src_port = db.Column(db.Integer, nullable=True)
    dst_port = db.Column(db.Integer, nullable=True)
    length = db.Column(db.Integer, default=0)
    ttl = db.Column(db.Integer, nullable=True)
    flags = db.Column(db.String(20), nullable=True)
    summary = db.Column(db.Text, nullable=True)
    raw_hex = db.Column(db.Text, nullable=True)
    raw_ascii = db.Column(db.Text, nullable=True)

class AlertLog(db.Model):
    __tablename__ = 'alert_logs'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    alert_type = db.Column(db.String(50), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    description = db.Column(db.Text, nullable=False)
    src_ip = db.Column(db.String(50), nullable=True)
