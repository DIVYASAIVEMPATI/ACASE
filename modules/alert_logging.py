"""
Real-time Alerting and Logging System
Generates timestamped logs and alerts for all findings
"""
import json
from datetime import datetime
from pathlib import Path


class AlertLogger:
    def __init__(self, log_file="reports/security_alerts.log"):
        self.log_file = log_file
        self.alerts = []
        self.start_time = datetime.now()
        
    def log_alert(self, severity, module, message, details=None):
        """Log a security alert with timestamp"""
        
        alert = {
            "timestamp": datetime.now().isoformat(),
            "elapsed_time": str(datetime.now() - self.start_time),
            "severity": severity,
            "module": module,
            "message": message,
            "details": details or {}
        }
        
        self.alerts.append(alert)
        
        # Console output
        severity_colors = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🔵",
            "INFO": "ℹ️"
        }
        
        icon = severity_colors.get(severity, "•")
        print(f"{icon} [{severity}] {module}: {message}")
        
        # Write to log file immediately
        self._write_to_file(alert)
        
    def _write_to_file(self, alert):
        """Append alert to log file"""
        log_entry = f"[{alert['timestamp']}] [{alert['severity']}] {alert['module']}: {alert['message']}\n"
        
        with open(self.log_file, "a") as f:
            f.write(log_entry)
    
    def generate_summary(self):
        """Generate alert summary"""
        
        summary = {
            "scan_start": self.start_time.isoformat(),
            "scan_end": datetime.now().isoformat(),
            "total_duration": str(datetime.now() - self.start_time),
            "total_alerts": len(self.alerts),
            "by_severity": {},
            "by_module": {},
            "alerts": self.alerts
        }
        
        # Count by severity
        for alert in self.alerts:
            severity = alert["severity"]
            summary["by_severity"][severity] = summary["by_severity"].get(severity, 0) + 1
        
        # Count by module
        for alert in self.alerts:
            module = alert["module"]
            summary["by_module"][module] = summary["by_module"].get(module, 0) + 1
        
        return summary
    
    def save_summary(self, filepath="reports/alert_summary.json"):
        """Save alert summary to JSON"""
        summary = self.generate_summary()
        
        with open(filepath, "w") as f:
            json.dump(summary, f, indent=2)
        
        print(f"\n[+] Alert summary saved: {filepath}")
    
    def print_summary(self):
        """Print alert summary to console"""
        summary = self.generate_summary()
        
        print(f"\n{'='*70}")
        print(f"  SECURITY ALERT SUMMARY")
        print(f"{'='*70}")
        print(f"Scan Duration: {summary['total_duration']}")
        print(f"Total Alerts: {summary['total_alerts']}")
        print(f"\nBy Severity:")
        for severity, count in sorted(summary["by_severity"].items()):
            print(f"  {severity}: {count}")
        print(f"\nBy Module:")
        for module, count in sorted(summary["by_module"].items()):
            print(f"  {module}: {count}")
        print(f"{'='*70}\n")


def initialize_logging():
    """Initialize logging system and clear old logs"""
    log_file = "reports/security_alerts.log"
    
    # Create new log file
    with open(log_file, "w") as f:
        f.write(f"=== ACASE SECURITY SCAN LOG ===\n")
        f.write(f"Started: {datetime.now().isoformat()}\n")
        f.write(f"="*50 + "\n\n")
    
    return AlertLogger(log_file)
