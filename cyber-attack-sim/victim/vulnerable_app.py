from flask import Flask, request, jsonify
import sqlite3
import time
from datetime import datetime
from collections import defaultdict
import threading

app = Flask(__name__)

# ============ FIREWALL CONFIGURATION ============
class Firewall:
    def __init__(self):
        self.request_counts = defaultdict(list)  # IP -> [timestamps]
        self.blocked_ips = set()  # Blacklisted IPs
        self.suspicious_patterns = defaultdict(int)  # IP -> suspicious count
        
        # Thresholds
        self.RATE_LIMIT = 100  # requests per minute
        self.RATE_LIMIT_WINDOW = 60  # seconds
        self.BLOCK_THRESHOLD = 3  # suspicious attempts before block
        self.BLOCK_DURATION = 300  # 5 minutes
        
        # SQL Injection patterns
        self.SQL_PATTERNS = [
            "' OR '", "' or '", "1=1", "1' = '1", 
            "--", "/*", "*/", "UNION", "SELECT", 
            "DROP", "INSERT", "DELETE", "UPDATE"
        ]
        
        self.alerts = []  # Store alerts
        
    def check_rate_limit(self, ip):
        """Check if IP is exceeding rate limit"""
        current_time = time.time()
        
        # Remove old requests outside the window
        self.request_counts[ip] = [
            t for t in self.request_counts[ip] 
            if current_time - t < self.RATE_LIMIT_WINDOW
        ]
        
        # Add current request
        self.request_counts[ip].append(current_time)
        
        request_count = len(self.request_counts[ip])
        
        # Log to file
        with open('/app/logs/firewall.log', 'a') as f:
            f.write(f"[{datetime.now()}] Rate Check: {ip} - {request_count} req/min\n")
        
        # Check if exceeding limit
        if request_count > self.RATE_LIMIT:
            self.add_alert(f"RATE LIMIT EXCEEDED: {ip} ({request_count} req/min)")
            self.suspicious_patterns[ip] += 1
            
            # Block if too many violations
            if self.suspicious_patterns[ip] >= self.BLOCK_THRESHOLD:
                self.block_ip(ip)
            
            return False  # Block request
        
        return True  # Allow request
    
    def check_sql_injection(self, data, ip):
        """Detect SQL injection attempts"""
        if not data:
            return True
        
        data_str = str(data).upper()
        
        for pattern in self.SQL_PATTERNS:
            if pattern.upper() in data_str:
                self.add_alert(f"SQL INJECTION DETECTED: {ip} | Pattern: {pattern}")
                self.suspicious_patterns[ip] += 1
                
                with open('/app/logs/firewall.log', 'a') as f:
                    f.write(f"[{datetime.now()}] SQL Injection: {ip} - Pattern: {pattern} - Data: {data}\n")
                
                # Block after threshold
                if self.suspicious_patterns[ip] >= self.BLOCK_THRESHOLD:
                    self.block_ip(ip)
                
                return False  # Block request
        
        return True  # Allow request
    
    def block_ip(self, ip):
        """Add IP to blacklist"""
        if ip not in self.blocked_ips:
            self.blocked_ips.add(ip)
            self.add_alert(f"IP BLACKLISTED: {ip}")
            
            with open('/app/logs/firewall.log', 'a') as f:
                f.write(f"[{datetime.now()}] BLACKLIST: {ip} blocked for {self.BLOCK_DURATION}s\n")
            
            # Auto-unblock after duration
            def unblock():
                time.sleep(self.BLOCK_DURATION)
                if ip in self.blocked_ips:
                    self.blocked_ips.remove(ip)
                    self.add_alert(f"IP UNBLOCKED: {ip}")
            
            threading.Thread(target=unblock, daemon=True).start()
    
    def is_blocked(self, ip):
        """Check if IP is blacklisted"""
        return ip in self.blocked_ips
    
    def add_alert(self, message):
        """Add alert to queue"""
        alert = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'message': message
        }
        self.alerts.append(alert)
        
        # Keep only last 100 alerts
        if len(self.alerts) > 100:
            self.alerts.pop(0)
        
        print(f"🚨 FIREWALL ALERT: {message}")
    
    def get_stats(self):
        """Get firewall statistics"""
        return {
            'total_ips_tracked': len(self.request_counts),
            'blocked_ips': list(self.blocked_ips),
            'blocked_count': len(self.blocked_ips),
            'suspicious_ips': dict(self.suspicious_patterns),
            'recent_alerts': self.alerts[-10:],  # Last 10 alerts
            'total_alerts': len(self.alerts)
        }

# Initialize firewall
firewall = Firewall()

# ============ DATABASE SETUP ============
def init_db():
    conn = sqlite3.connect('vulnerable.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT)''')
    c.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin123', 'admin@test.com')")
    c.execute("INSERT OR IGNORE INTO users VALUES (2, 'user1', 'pass123', 'user1@test.com')")
    conn.commit()
    conn.close()

init_db()

# ============ FLASK REQUEST HANDLING ============
@app.before_request
def firewall_check():
    """Firewall checks before processing request"""
    ip = request.remote_addr
    
    # Check if IP is blacklisted
    if firewall.is_blocked(ip):
        with open('/app/logs/firewall.log', 'a') as f:
            f.write(f"[{datetime.now()}] BLOCKED REQUEST: {ip} - {request.path}\n")
        return jsonify({
            'error': 'Access Denied',
            'message': 'Your IP has been blocked by the firewall',
            'reason': 'Suspicious activity detected'
        }), 403
    
    # Rate limiting check
    if not firewall.check_rate_limit(ip):
        return jsonify({
            'error': 'Rate Limit Exceeded',
            'message': 'Too many requests',
            'retry_after': 60
        }), 429

@app.route('/')
def index():
    return jsonify({
        'status': 'running',
        'service': 'Vulnerable Web Server',
        'version': '1.0',
        'firewall': 'active'
    })

@app.route('/login', methods=['POST'])
def login():
    ip = request.remote_addr
    
    try:
        data = request.get_json()
        username = data.get('username', '')
        password = data.get('password', '')
        
        # SQL Injection Detection
        if not firewall.check_sql_injection(username, ip):
            return jsonify({
                'success': False,
                'error': 'Blocked by WAF',
                'message': 'SQL injection pattern detected',
                'blocked': True
            }), 403
        
        if not firewall.check_sql_injection(password, ip):
            return jsonify({
                'success': False,
                'error': 'Blocked by WAF',
                'message': 'SQL injection pattern detected',
                'blocked': True
            }), 403
        
        # Vulnerable query (still exploitable if firewall bypassed)
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        
        with open('/app/logs/victim.log', 'a') as f:
            f.write(f"[{datetime.now()}] Login attempt: {ip} - Query: {query}\n")
        
        conn = sqlite3.connect('vulnerable.db')
        c = conn.cursor()
        c.execute(query)
        result = c.fetchone()
        conn.close()
        
        if result:
            return jsonify({
                'success': True,
                'user': result[1],
                'message': 'Login successful'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Invalid credentials'
            })
            
    except Exception as e:
        with open('/app/logs/firewall.log', 'a') as f:
            f.write(f"[{datetime.now()}] ERROR: {ip} - {str(e)}\n")
        
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/stats')
def stats():
    """General stats"""
    return jsonify({
        'active_ips': len(firewall.request_counts),
        'total_requests': sum(len(v) for v in firewall.request_counts.values()),
        'request_counts': {k: len(v) for k, v in firewall.request_counts.items()}
    })

@app.route('/firewall/stats')
def firewall_stats():
    """Detailed firewall statistics"""
    return jsonify(firewall.get_stats())

@app.route('/firewall/alerts')
def firewall_alerts():
    """Get recent firewall alerts"""
    return jsonify({
        'alerts': firewall.alerts[-50:],  # Last 50 alerts
        'total': len(firewall.alerts)
    })

if __name__ == '__main__':
    print("🛡️  Firewall initialized")
    print(f"   - Rate limit: {firewall.RATE_LIMIT} req/min")
    print(f"   - Block threshold: {firewall.BLOCK_THRESHOLD} violations")
    print(f"   - SQL injection detection: Active")
    app.run(host='0.0.0.0', port=5000, debug=True)