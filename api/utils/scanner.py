"""
Scanner Integration - Connects ACASE scanner with API
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from modules.mapper import discover_auth
from modules.enumerator import check_username_enumeration
from modules.session import analyze_session_cookies
from modules.email_validator import test_email_enumeration
from core.planner import Planner
from scope.validator import validate_scope

DEFAULT_TEST_USERS = ["admin", "test", "nonexistentuser_xyz123", "user"]

def run_scan(scan_id, target, email, callback=None):
    """
    Run complete ACASE scan
    
    Args:
        scan_id: Unique scan identifier
        target: Target URL
        email: Email to test
        callback: Function to call with progress updates
    
    Returns:
        dict: Scan results
    """
    results = {
        "scan_id": scan_id,
        "target": target,
        "email": email,
        "status": "running",
        "progress": 0,
        "findings": [],
        "attack_path": [],
        "risk_score": 0
    }
    
    try:
        # Update: Starting
        if callback:
            callback(scan_id, "running", 10, "Validating scope...")
        
        scope = validate_scope(target)
        delay_ms = scope.get("request_delay_ms", 1500)
        
        # Update: Discovery
        if callback:
            callback(scan_id, "running", 20, "Discovering endpoints...")
        
        auth_info = discover_auth(target)
        
        if auth_info.get("error"):
            results["status"] = "failed"
            results["error"] = auth_info["error"]
            if callback:
                callback(scan_id, "failed", 100, f"Error: {auth_info['error']}")
            return results
        
        login_url = None
        if auth_info["auth_forms"]:
            login_url = auth_info["auth_forms"][0]["url"]
            results["findings"].append({
                "type": "discovery",
                "message": f"Login endpoint found: {login_url}"
            })
        
        # Update: Testing session
        if callback:
            callback(scan_id, "running", 40, "Testing session security...")
        
        session_result = analyze_session_cookies(target)
        results["attack_path"].append("TEST_SESSION")
        
        # Update: Testing enumeration
        if callback:
            callback(scan_id, "running", 60, "Testing username enumeration...")
        
        if login_url:
            enum_result = check_username_enumeration(login_url, DEFAULT_TEST_USERS, delay_ms)
            results["attack_path"].append("ENUM_USER")
            
            if enum_result.get("enumeration_possible"):
                results["findings"].append({
                    "type": "vulnerability",
                    "severity": "HIGH",
                    "message": "Username enumeration possible"
                })
                results["risk_score"] += 25
        
        # Update: Testing email
        if callback:
            callback(scan_id, "running", 80, "Validating email...")
        
        email_result = test_email_enumeration(target, email, delay_ms)
        
        if email_result.get("vulnerabilities"):
            for vuln in email_result["vulnerabilities"]:
                results["findings"].append({
                    "type": "vulnerability",
                    "severity": "HIGH",
                    "message": vuln
                })
                results["risk_score"] += 20
        
        # Calculate final risk score
        results["risk_score"] = min(results["risk_score"], 100)
        
        # Update: Complete
        results["status"] = "complete"
        results["progress"] = 100
        
        if callback:
            callback(scan_id, "complete", 100, "Scan complete!")
        
    except Exception as e:
        results["status"] = "failed"
        results["error"] = str(e)
        if callback:
            callback(scan_id, "failed", 100, f"Error: {str(e)}")
    
    return results
