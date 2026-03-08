"""
Advanced Status Code Analyzer
Tracks, analyzes and detects attack patterns
"""

from collections import defaultdict
from datetime import datetime


class StatusCodeAnalyzer:

    def __init__(self):
        self.status_log = []
        self.status_counts = defaultdict(int)

    def record_status(self, url, method, status_code, endpoint_type="unknown"):
        entry = {
            "url": url,
            "method": method,
            "status_code": status_code,
            "endpoint_type": endpoint_type,
            "timestamp": datetime.now().isoformat()
        }

        self.status_log.append(entry)
        self.status_counts[status_code] += 1

    def get_analysis(self):
        analysis = {
            "total_requests": len(self.status_log),
            "status_breakdown": dict(self.status_counts),
            "findings": [],
            "timeline": self.status_log
        }

        # Basic pattern checks
        if self.status_counts.get(403, 0) > 3:
            analysis['findings'].append("Possible WAF or blocking detected (Multiple 403)")

        if self.status_counts.get(401, 0) > 0:
            analysis['findings'].append("Authentication required (401 detected)")

        if self.status_counts.get(500, 0) > 0:
            analysis['findings'].append("Server errors detected (500 series)")

        if self.status_counts.get(404, 0) > 5:
            analysis['findings'].append("Multiple 404 responses - invalid endpoints")

        # Brute-force detection logic
        login_attempts = [
            entry for entry in self.status_log
            if entry["endpoint_type"] == "auth"
        ]

        if len(login_attempts) > 10:
            analysis['findings'].append("High number of authentication attempts - possible brute force")

        # Redirect loop detection
        if self.status_counts.get(302, 0) > 10:
            analysis['findings'].append("Multiple redirects detected - possible redirect loop")

        # Rate limiting detection
        if self.status_counts.get(429, 0) > 0:
            analysis['findings'].append("Rate limiting detected (429 Too Many Requests)")

        # Success rate
        success = sum(self.status_counts[code] for code in range(200, 300))
        if len(self.status_log) > 0:
            success_rate = (success / len(self.status_log)) * 100
            analysis['success_rate'] = f"{success_rate:.1f}%"

        return analysis

    def print_summary(self):
        analysis = self.get_analysis()

        print("\n" + "="*60)
        print("HTTP STATUS CODE ANALYSIS")
        print("="*60)
        print(f"Total Requests: {analysis['total_requests']}")
        print(f"Success Rate: {analysis.get('success_rate', 'N/A')}")

        print("\nStatus Breakdown:")
        for code in sorted(analysis['status_breakdown'].keys()):
            print(f"  {code}: {analysis['status_breakdown'][code]} times")

        if analysis['findings']:
            print("\nFindings:")
            for finding in analysis['findings']:
                print(f"  [!] {finding}")

        print("="*60 + "\n")

    def save_to_file(self, filepath):
        import json
        analysis = self.get_analysis()
        with open(filepath, 'w') as f:
            json.dump(analysis, f, indent=2)
        print(f"[+] Status analysis saved: {filepath}")


# Global analyzer instance
_analyzer = StatusCodeAnalyzer()


def get_analyzer():
    return _analyzer


def record_status(url, method, status_code, endpoint_type="unknown"):
    _analyzer.record_status(url, method, status_code, endpoint_type)
