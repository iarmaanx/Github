import threading
import time
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP
from models.database import db, PacketLog, AlertLog
from config import Config

class LiveSniffer:
    def __init__(self, socketio, app):
        self.socketio = socketio
        self.app = app
        self.is_running = False
        self.sniff_thread = None
        self.interface = None
        
        # Real-time stats
        self.stats = {
            "total": 0, "incoming": 0, "outgoing": 0, 
            "tcp": 0, "udp": 0, "icmp": 0, "arp": 0, "dns": 0, "http": 0, "https": 0,
            "bandwidth": 0, "cpu": 0, "ram": 0,
            "top_ips": [],
            "rate_history": [0] * 15,
            "rx_speed": 0, "tx_speed": 0, "avg_frame_size": 0,
            "port_counts": {"443": 0, "80": 0, "53": 0, "other": 0}
        }
        
        # Threat & Metrics state
        self.port_scan_tracker = {} # {src_ip: set(dst_ports)}
        self.ip_counts = {} # {ip: count}
        self.recent_packet_count = 0
        self.recent_rx_bytes = 0
        self.recent_tx_bytes = 0
        self.last_rate_check = time.time()

        # Performance optimization: batching & rate limiting
        self.packet_buffer = []
        self.last_status_emit = 0
        self.last_db_flush = time.time()
        self.buffer_lock = threading.Lock()

    def start(self, interface=None):
        if self.is_running:
            if interface and interface != self.interface:
                self.stop()
                self.socketio.sleep(0.2)
            else:
                return

        self.interface = interface
        self.is_running = True
        self.sniff_thread = self.socketio.start_background_task(target=self._run_sniffer)
        self._emit_status()

    def stop(self):
        self.is_running = False
        self.sniff_thread = None
        self._emit_status()

    def clear(self):
        with self.app.app_context():
            PacketLog.query.delete()
            AlertLog.query.delete()
            db.session.commit()
        
        self.stats = {
            "total": 0, "incoming": 0, "outgoing": 0, 
            "tcp": 0, "udp": 0, "icmp": 0, "arp": 0, "dns": 0, "http": 0, "https": 0,
            "bandwidth": 0
        }
        self.port_scan_tracker.clear()
        self._emit_status()

    def _run_sniffer(self):
        while self.is_running:
            try:
                kwargs = {}
                if self.interface:
                    kwargs['iface'] = self.interface
                
                # Non-blocking batch sniff with 0.2s max timeout to keep Eventlet loop responsive
                sniff(prn=self._process_packet, store=False, count=10, timeout=0.2, **kwargs)
                self.socketio.sleep(0.01)
            except Exception as e:
                print(f"Sniffer Error: {e}")
                self.is_running = False
                self._emit_status()
                break

    def _process_packet(self, packet):
        if not self.is_running:
            return

        packet_data = {
            "timestamp": datetime.utcnow(),
            "src_ip": "-",
            "dst_ip": "-",
            "protocol": "-",
            "src_port": None,
            "dst_port": None,
            "length": len(packet),
            "ttl": None,
            "flags": "-",
            "summary": packet.summary(),
            "raw_hex": None,
            "raw_ascii": None
        }

        # Update bandwidth stat
        self.stats['bandwidth'] += packet_data['length']

        if IP in packet:
            packet_data['src_ip'] = packet[IP].src
            packet_data['dst_ip'] = packet[IP].dst
            packet_data['ttl'] = packet[IP].ttl
            
            # Track IP Talkers
            self.ip_counts[packet_data['src_ip']] = self.ip_counts.get(packet_data['src_ip'], 0) + 1
            
            # Simple incoming/outgoing heuristic
            self.stats['total'] += 1
            self.recent_packet_count += 1
            if packet_data['dst_ip'].startswith(('192.168.', '10.', '172.')):
                self.stats['incoming'] += 1
                self.recent_rx_bytes += packet_data['length']
            else:
                self.stats['outgoing'] += 1
                self.recent_tx_bytes += packet_data['length']

            if TCP in packet:
                packet_data['protocol'] = "TCP"
                packet_data['src_port'] = packet[TCP].sport
                packet_data['dst_port'] = packet[TCP].dport
                packet_data['flags'] = str(packet[TCP].flags)
                self.stats['tcp'] += 1
                
                if packet_data['dst_port'] == 80 or packet_data['src_port'] == 80:
                    self.stats['http'] += 1
                    self.stats['port_counts']['80'] += 1
                elif packet_data['dst_port'] == 443 or packet_data['src_port'] == 443:
                    self.stats['https'] += 1
                    self.stats['port_counts']['443'] += 1
                else:
                    self.stats['port_counts']['other'] += 1
                    
                self._check_port_scan(packet_data['src_ip'], packet_data['dst_port'])

            elif UDP in packet:
                packet_data['protocol'] = "UDP"
                packet_data['src_port'] = packet[UDP].sport
                packet_data['dst_port'] = packet[UDP].dport
                self.stats['udp'] += 1
                
                if packet_data['dst_port'] == 53 or packet_data['src_port'] == 53:
                    self.stats['dns'] += 1
                    self.stats['port_counts']['53'] += 1
                else:
                    self.stats['port_counts']['other'] += 1

            elif ICMP in packet:
                packet_data['protocol'] = "ICMP"
                self.stats['icmp'] += 1

        # Optionally extract raw payload
        if hasattr(packet, 'load') and packet.load:
            packet_data['raw_hex'] = packet.load.hex()
            # Try to decode ascii safely
            try:
                packet_data['raw_ascii'] = packet.load.decode('utf-8', 'ignore')
            except Exception:
                pass

        # Save to DB buffer & emit to frontend
        self._save_packet(packet_data)
        
        # Prepare data for frontend emission (serialize datetime)
        emit_data = packet_data.copy()
        emit_data['timestamp'] = emit_data['timestamp'].strftime("%Y-%m-%d %H:%M:%S")
        self.socketio.emit('new_packet', emit_data)
        self.socketio.sleep(0)
        
        # Rate-limit status updates to at most once per 300ms
        now = time.time()
        if now - self.last_status_emit > 0.3:
            self._emit_status()
            self.last_status_emit = now

    def _check_port_scan(self, src_ip, dst_port):
        if src_ip not in self.port_scan_tracker:
            self.port_scan_tracker[src_ip] = set()
            
        self.port_scan_tracker[src_ip].add(dst_port)
        
        # Trigger alert if scanning 8+ unique ports or accessing high-risk ports (SSH 22, SMB 445, Telnet 23)
        if len(self.port_scan_tracker[src_ip]) >= 8:
            self._trigger_alert(
                alert_type="Port Scan Detected",
                severity="High",
                description=f"Host {src_ip} scanned {len(self.port_scan_tracker[src_ip])} unique ports.",
                src_ip=src_ip
            )
            self.port_scan_tracker[src_ip] = set()
        elif dst_port in [22, 23, 445, 3389]:
            self._trigger_alert(
                alert_type="Suspicious Port Access",
                severity="Medium",
                description=f"Connection attempt to high-risk Port {dst_port} from {src_ip}.",
                src_ip=src_ip
            )

    def _trigger_alert(self, alert_type, severity, description, src_ip):
        with self.app.app_context():
            new_alert = AlertLog(
                alert_type=alert_type,
                severity=severity,
                description=description,
                src_ip=src_ip
            )
            db.session.add(new_alert)
            db.session.commit()
            
            # Emit to frontend
            self.socketio.emit('new_alert', {
                'timestamp': datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                'alert_type': alert_type,
                'severity': severity,
                'description': description,
                'src_ip': src_ip
            })

    def _save_packet(self, data):
        with self.buffer_lock:
            self.packet_buffer.append(data)
            now = time.time()
            if len(self.packet_buffer) >= 30 or (now - self.last_db_flush) > 2.0:
                self._flush_buffer()

    def _flush_buffer(self):
        if not self.packet_buffer:
            return
        to_save = list(self.packet_buffer)
        self.packet_buffer.clear()
        self.last_db_flush = time.time()

        def db_write():
            with self.app.app_context():
                try:
                    db.session.bulk_insert_mappings(PacketLog, to_save)
                    db.session.commit()
                except Exception as e:
                    db.session.rollback()

        # Run DB write in detached thread to avoid stalling sniffer loop
        threading.Thread(target=db_write, daemon=True).start()

    def _emit_status(self):
        import psutil
        now = time.time()
        time_diff = now - self.last_rate_check
        if time_diff >= 1.0:
            # Update PPS rate history & speeds
            pps = int(self.recent_packet_count / time_diff)
            self.stats['rate_history'].pop(0)
            self.stats['rate_history'].append(pps)
            
            self.stats['rx_speed'] = round(self.recent_rx_bytes / time_diff / 1024, 1) # KB/s
            self.stats['tx_speed'] = round(self.recent_tx_bytes / time_diff / 1024, 1) # KB/s
            if self.stats['total'] > 0:
                self.stats['avg_frame_size'] = int(self.stats['bandwidth'] / self.stats['total'])
            
            self.recent_packet_count = 0
            self.recent_rx_bytes = 0
            self.recent_tx_bytes = 0
            self.last_rate_check = now

        # Top 5 Talkers
        sorted_ips = sorted(self.ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        self.stats['top_ips'] = [{"ip": ip, "count": count} for ip, count in sorted_ips]

        # System Hardware Metrics
        try:
            self.stats['cpu'] = round(psutil.cpu_percent(interval=None), 1)
            self.stats['ram'] = round(psutil.virtual_memory().percent, 1)
        except Exception:
            pass

        self.socketio.emit('status_update', {
            'sniffer_running': self.is_running,
            'stats': self.stats
        })
