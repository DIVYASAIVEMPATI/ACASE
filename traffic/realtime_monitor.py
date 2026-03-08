"""
Real-time AitM Monitoring with Alert Persistence
"""
import threading
import time
import json
from pathlib import Path
from datetime import datetime
from modules.arp_detection import detect_arp_spoofing
from modules.rogue_gateway import detect_rogue_gateway

ALERT_FILE = Path("reports/realtime_alerts.json")
BASELINE_FILE = Path("reports/arp_baseline.json")

class RealTimeMonitor:
    def __init__(self, interval=15):
        self.interval = interval
        self.running = False
        self.alerts = []
        
    def save_baseline(self):
        """Save initial network state"""
        try:
            arp_result = detect_arp_spoofing()
            with open(BASELINE_FILE, "w") as f:
                json.dump(arp_result, f, indent=2)
        except:
            pass
    
    def save_alert(self, alert):
        """Save alert to persistent storage"""
        try:
            if ALERT_FILE.exists():
                with open(ALERT_FILE, "r") as f:
                    data = json.load(f)
            else:
                data = []
            
            data.append(alert)
            
            with open(ALERT_FILE, "w") as f:
                json.dump(data, f, indent=2)
        except:
            pass
        
    def start(self):
        """Start background monitoring"""
        self.running = True
        
        # Save baseline before monitoring
        self.save_baseline()
        
        thread = threading.Thread(target=self.monitor_loop, daemon=True)
        thread.start()
        print(f"[+] Real-time monitoring started (interval: {self.interval}s)")
        
    def monitor_loop(self):
        """Continuous monitoring loop"""
        while self.running:
            try:
                # Check ARP spoofing
                arp_result = detect_arp_spoofing()
                if arp_result.get("vulnerabilities"):
                    for vuln in arp_result["vulnerabilities"]:
                        alert = {
                            "timestamp": datetime.now().strftime("%H:%M:%S"),
                            "type": "ARP_SPOOFING",
                            "severity": vuln["severity"],
                            "message": vuln["message"]
                        }
                        self.alerts.append(alert)
                        self.save_alert(alert)
                        print(f"[!] ALERT: {vuln['message']}")
                
                # Check rogue gateway
                gateway_result = detect_rogue_gateway()
                if gateway_result.get("vulnerabilities"):
                    for vuln in gateway_result["vulnerabilities"]:
                        alert = {
                            "timestamp": datetime.now().strftime("%H:%M:%S"),
                            "type": "ROGUE_GATEWAY",
                            "severity": vuln["severity"],
                            "message": vuln["message"]
                        }
                        self.alerts.append(alert)
                        self.save_alert(alert)
                        print(f"[!] ALERT: {vuln['message']}")
                
            except Exception as e:
                pass
            
            time.sleep(self.interval)
    
    def stop(self):
        """Stop monitoring"""
        self.running = False
        
    def get_alerts(self):
        """Get all alerts"""
        return self.alerts
