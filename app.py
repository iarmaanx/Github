import csv
import json
from flask import render_template, redirect, url_for, request, flash, jsonify, Response
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import psutil

from config import Config
from models.database import db, User, PacketLog, AlertLog
from services.sniffer import LiveSniffer

# Initialize Flask-SocketIO Engine under production global factory
from flask import Flask
from flask_socketio import SocketIO
from flask_login import LoginManager
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
Config.init_app(app)  # Ensure directories exist
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Global Sniffer State Accessor
# Instantiate sniffer service so endpoints and templates can reference it
sniffer_service = LiveSniffer(socketio, app)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# ================= AUTHENTICATION PATHS =================
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form.get('username')).first()
        if user and check_password_hash(user.password_hash, request.form.get('password')):
            login_user(user, remember=True)
            return redirect(url_for('dashboard'))
        flash('Invalid security credentials provided.', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        hashed_pw = generate_password_hash(request.form.get('password'))
        new_user = User(username=request.form.get('username'), email=request.form.get('email'), password_hash=hashed_pw)
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Account provisioning successful! Securely sign in now.', 'success')
            return redirect(url_for('login'))
        except Exception:
            db.session.rollback()
            flash('Error: Username or Email identifier already exists.', 'danger')
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# ================= APP ROUTING AND METRICS =================
@app.route('/')
@app.route('/dashboard')
@login_required
def dashboard():
    interfaces = list(psutil.net_if_addrs().keys())
    active_iface = sniffer_service.interface if sniffer_service else None
    return render_template('dashboard.html', interfaces=interfaces, active_iface=active_iface)

@app.route('/api/packets', methods=['GET'])
@login_required
def get_packet_logs():
    logs = PacketLog.query.order_by(PacketLog.id.desc()).limit(250).all()
    out = []
    for l in logs:
        out.append({
            "id": l.id, "timestamp": l.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": l.src_ip, "dst_ip": l.dst_ip, "protocol": l.protocol,
            "src_port": l.src_port or "-", "dst_port": l.dst_port or "-",
            "length": l.length, "ttl": l.ttl, "flags": l.flags, "summary": l.summary,
            "hex": l.raw_hex, "ascii": l.raw_ascii
        })
    return jsonify(out)

@app.route('/api/alerts', methods=['GET'])
@login_required
def get_alerts():
    alerts = AlertLog.query.order_by(AlertLog.id.desc()).all()
    return jsonify([{
        "timestamp": a.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "alert_type": a.alert_type, "severity": a.severity, "description": a.description, "src_ip": a.src_ip
    } for a in alerts])

# ================= ACTION CONTROL PATHS =================
@app.route('/api/control/<action>', methods=['POST'])
@login_required
def sniffer_control(action):
    # Ensure sniffer service exists
    global sniffer_service
    if not sniffer_service:
        sniffer_service = LiveSniffer(socketio, app)

    if action == "start":
        iface = request.json.get('interface')
        sniffer_service.start(interface=iface)
    elif action == "stop":
        sniffer_service.stop()
    elif action == "clear":
        sniffer_service.clear()
    return jsonify({"status": "success", "sniffer_running": sniffer_service.is_running})

# ================= DATA EXPORT CHANNELS =================
@app.route('/api/export/<fmt>', methods=['GET'])
@login_required
def export_logs(fmt):
    logs = PacketLog.query.all()
    if fmt == 'csv':
        def generate():
            data = ["ID,Timestamp,SrcIP,DstIP,Protocol,SrcPort,DstPort,Length\n"]
            yield "".join(data)
            for l in logs:
                yield f"{l.id},{l.timestamp},{l.src_ip},{l.dst_ip},{l.protocol},{l.src_port},{l.dst_port},{l.length}\n"
        return Response(generate(), mimetype="text/csv", headers={"Content-Disposition": "attachment;filename=traffic_capture.csv"})
        
    elif fmt == 'json':
        res = [{
            "timestamp": str(l.timestamp), "src_ip": l.src_ip, "dst_ip": l.dst_ip,
            "protocol": l.protocol, "length": l.length, "summary": l.summary
        } for l in logs]
        return Response(json.dumps(res, indent=2), mimetype="application/json", headers={"Content-Disposition": "attachment;filename=traffic_capture.json"})
    
    return jsonify({"error": "Unsupported dynamic operational format."}), 400

# ================= STATS API =================
@app.route('/api/stats', methods=['GET'])
@login_required
def get_stats():
    global sniffer_service
    if sniffer_service:
        return jsonify({
            "sniffer_running": sniffer_service.is_running,
            "stats": sniffer_service.stats
        })
    return jsonify({
        "sniffer_running": False,
        "stats": {"total": 0, "incoming": 0, "outgoing": 0, "tcp": 0, "udp": 0,
                  "icmp": 0, "arp": 0, "dns": 0, "http": 0, "https": 0, "bandwidth": 0}
    })

# ================= SOCKET WEBSOCKET TRIGGERS =================
@socketio.on('connect')
def handle_connect():
    # Socket.IO runs outside Flask request context, so current_user is unreliable.
    # Instead, emit status_update directly using the sniffer_service state.
    global sniffer_service
    if sniffer_service:
        socketio.emit('status_update', {'sniffer_running': sniffer_service.is_running, 'stats': sniffer_service.stats})
    else:
        socketio.emit('status_update', {'sniffer_running': False, 'stats': {}})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    
    print("\n" + "="*50)
    print("SERVER STARTED SUCCESSFULLY!")
    print("CLICK HERE TO OPEN: http://127.0.0.1:5000")
    print("="*50 + "\n")
    
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)