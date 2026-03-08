import json
import sys
from datetime import datetime
from urllib.parse import urlparse
from pathlib import Path

SCOPE_FILE = Path(__file__).parent / "scope.json"

def load_scope():
    if not SCOPE_FILE.exists():
        print("[!] scope/scope.json not found.")
        sys.exit(1)
    with open(SCOPE_FILE) as f:
        return json.load(f)

def validate_scope(target):
    scope = load_scope()
    parsed = urlparse(target)
    domain = parsed.hostname or target
    allowed = scope.get("allowed_domains", [])
    if domain not in allowed:
        print(f"[!] Target '{domain}' is NOT in your authorized scope.")
        print(f"    Allowed: {', '.join(allowed)}")
        sys.exit(1)
    working_hours = scope.get("working_hours", "00:00-23:59")
    start_str, end_str = working_hours.split("-")
    now = datetime.now().strftime("%H:%M")
    if not (start_str <= now <= end_str):
        print(f"[!] Outside working hours ({working_hours}). Exiting.")
        sys.exit(1)
    print(f"[+] Scope validated: {domain} is authorized")
    return scope
