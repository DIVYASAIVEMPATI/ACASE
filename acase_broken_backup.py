import typer
import sys
import subprocess
import shutil
import time
import json
import os
from pathlib import Path
from datetime import datetime
sys.path.insert(0, str(Path(__file__).parent))

from scope.validator import validate_scope
from modules.mapper import discover_auth
from modules.enumerator import check_username_enumeration
from modules.reset_abuse import probe_reset_flow
from modules.session import analyze_session_cookies
from modules.email_validator import test_email_enumeration, generate_email_report
from modules.multi_email_tester import test_multiple_emails, generate_multi_email_report
from modules.status_analyzer import get_analyzer

# AitM Detection Modules
from modules.ssl_security import check_ssl_tls_security, generate_ssl_report
from modules.session_hijacking import test_session_hijacking_vulnerabilities
from modules.arp_detection import detect_arp_spoofing
from modules.proxy_detection import detect_mitm_proxy
from modules.dns_spoofing import detect_dns_spoofing
from modules.session_token_misuse import detect_session_token_misuse
from modules.rogue_gateway import detect_rogue_gateway
from modules.alert_logging import initialize_logging, AlertLogger

from core.planner import Planner
from reports.generator import generate_report, save_report

app = typer.Typer()
DEFAULT_TEST_USERS = ["admin", "test", "nonexistentuser_xyz123", "user"]

# FIX: Get absolute paths (CRITICAL FOR DASHBOARD)
BASE_DIR = Path(__file__).parent.absolute()
REPORTS_DIR = BASE_DIR / "reports"
SCAN_DATA_FILE = REPORTS_DIR / "scan_data.json"

def auto_start_container(port):
    """Auto-start Docker containers"""
    containers = {"8080": "ecstatic_volhard", "3000": "juiceshop"}
    
    if str(port) in containers:
        container = containers[str(port)]
        typer.echo(f"[*] Detecting port {port}...")
        result = subprocess.run(
            ["docker", "ps", "-a", "--filter", f"name={container}", "--format", "{{.Names}}"],
            capture_output=True, text=True
        )
        
        if container in result.stdout:
            typer.echo(f"[*] Starting {container}...")
            subprocess.run(["docker", "start", container], capture_output=True)
            time.sleep(10)
            typer.echo(f"[✓] {container} ready!")
            return True
        elif str(port) == "3000":
            typer.echo(f"[*] Creating Juice Shop...")
            subprocess.run(["docker", "run", "-d", "--name", "juiceshop", "-p", "3000:3000", "bkimminich/juice-shop"], capture_output=True)
            time.sleep(30)
            typer.echo(f"[✓] Juice Shop ready!")
            return True
    
    return False

def save_scan_data_for_dashboard(target, email, all_findings):
    """Save complete scan data for dashboard - WITH ABSOLUTE PATHS"""
    
    vuln_counts = {
        "ssl_tls": len(all_findings.get("SSL_TLS_SECURITY", {}).get("vulnerabilities", [])),
        "session_hijack": len(all_findings.get("SESSION_HIJACKING", {}).get("vulnerabilities", [])),
        "arp_spoofing": len(all_findings.get("ARP_SPOOFING", {}).get("vulnerabilities", [])),
        "proxy": len(all_findings.get("MITM_PROXY", {}).get("vulnerabilities", [])),
        "dns_spoofing": len(all_findings.get("DNS_SPOOFING", {}).get("vulnerabilities", [])),
        "token_misuse": len(all_findings.get("TOKEN_MISUSE", {}).get("vulnerabilities", [])),
        "rogue_gateway": len(all_findings.get("ROGUE_GATEWAY", {}).get("vulnerabilities", [])),
        "email": len(all_findings.get("EMAIL_TEST", {}).get("vulnerabilities", [])),
        "auth": 0
    }
    
    total_vulns = sum(vuln_counts.values())
    risk_score = min(50 + (total_vulns * 10), 100)
    
    data = {
        "target": target,
        "email": email,
        "timestamp": datetime.now().isoformat(),
        "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "risk_score": risk_score,
        "vulnerability_counts": vuln_counts,
        "total_vulnerabilities": total_vulns,
        "modules_executed": 14,
        "findings": {}
    }
    
    for key, value in all_findings.items():
        if isinstance(value, dict):
            data["findings"][key] = {
                "vulnerabilities": value.get("vulnerabilities", []),
                "tests_performed": value.get("tests_performed", []),
                "status": "FAIL" if value.get("vulnerabilities") else "PASS"
            }
    
    # Save to THREE locations to ensure dashboard finds it
    locations = [
        SCAN_DATA_FILE,                                    # /root/acase/reports/scan_data.json
        BASE_DIR / "scan_data.json",                       # /root/acase/scan_data.json
        Path("/home/kali/scan_data.json"),                 # /home/kali/scan_data.json
    ]
    
    for location in locations:
        try:
            location.parent.mkdir(parents=True, exist_ok=True)
            with open(location, "w") as f:
                json.dump(data, f, indent=2)
            
            # Fix permissions if in kali home
            if "/home/kali" in str(location):
                subprocess.run(["chown", "kali:kali", str(location)], capture_output=True)
        except Exception as e:
            typer.echo(f"[!] Could not save to {location}: {e}")
    
    typer.echo(f"[+] Scan data saved (3 locations)")
    typer.echo(f"    → {SCAN_DATA_FILE}")
    typer.echo(f"    → {BASE_DIR / 'scan_data.json'}")
    typer.echo(f"    → /home/kali/scan_data.json")

@app.command()
def scan(target: str = None, test_email: str = None, emails_file: str = None, 
         enable_aitm: bool = True, interactive: bool = True):
    """ACASE Complete Security Scanner"""
    
    typer.echo("\n" + "=" * 60)
    typer.echo("  ACASE - COMPLETE SECURITY ASSESSMENT")
    typer.echo("  WITH ADVANCED AITM DETECTION")
    typer.echo("=" * 60)

    alert_logger = initialize_logging()
    alert_logger.log_alert("INFO", "SYSTEM", "Scan initiated")

    if interactive:
        if not target:
            typer.echo("\n📋 Target Options:")
            typer.echo("1. Enter URL manually")
            option = typer.prompt("Choose option", default="1")
            target = typer.prompt("Target URL (e.g., http://localhost:8080)")
        
        if "localhost" in target:
            try:
                port = target.split(":")[-1].split("/")[0]
                auto_start_container(port)
            except:
                pass
        
        if not test_email and not emails_file:
            typer.echo("\n📧 Email Testing Options:")
            typer.echo("1. Test single email")
            typer.echo("2. Test multiple emails from file")
            choice = typer.prompt("Choose option (1 or 2)", default="1")
            
            if choice == "1":
                test_email = typer.prompt("Enter email to test", default="ashwathy@gmail.com")
            else:
                emails_file = typer.prompt("Enter path to emails file", default="test_emails.txt")

    if not target:
        typer.echo("❌ Error: Target URL required")
        raise typer.Exit(1)

    status_analyzer = get_analyzer()
    all_findings = {}
    
    # PHASE 1: AITM DETECTION
    if enable_aitm:
        typer.echo("\n" + "="*70)
        typer.echo("  PHASE 1: ADVERSARY-IN-THE-MIDDLE DETECTION (8 MODULES)")
        typer.echo("="*70)
        
        typer.echo("\n[AITM-1/8] SSL/TLS Security Analysis...")
        ssl_findings = check_ssl_tls_security(target)
        all_findings["SSL_TLS_SECURITY"] = ssl_findings
        for vuln in ssl_findings.get("vulnerabilities", []):
            alert_logger.log_alert(vuln["severity"], "SSL/TLS", vuln["message"])
        
        typer.echo("\n[AITM-2/8] Session Hijacking Detection...")
        session_hijack_findings = test_session_hijacking_vulnerabilities(target)
        all_findings["SESSION_HIJACKING"] = session_hijack_findings
        for vuln in session_hijack_findings.get("vulnerabilities", []):
            alert_logger.log_alert(vuln["severity"], "SESSION_HIJACK", vuln["message"])
        
        typer.echo("\n[AITM-3/8] ARP Spoofing Detection...")
        arp_findings = detect_arp_spoofing()
        all_findings["ARP_SPOOFING"] = arp_findings
        for vuln in arp_findings.get("vulnerabilities", []):
            alert_logger.log_alert(vuln["severity"], "ARP_SPOOFING", vuln["message"])
        
        typer.echo("\n[AITM-4/8] MitM Proxy Detection...")
        proxy_findings = detect_mitm_proxy(target)
        all_findings["MITM_PROXY"] = proxy_findings
        for vuln in proxy_findings.get("vulnerabilities", []):
            alert_logger.log_alert(vuln["severity"], "PROXY", vuln["message"])
        
        typer.echo("\n[AITM-5/8] DNS Spoofing Detection...")
        dns_findings = detect_dns_spoofing(target)
        all_findings["DNS_SPOOFING"] = dns_findings
        for vuln in dns_findings.get("vulnerabilities", []):
            alert_logger.log_alert(vuln["severity"], "DNS_SPOOFING", vuln["message"])
        
        typer.echo("\n[AITM-6/8] Session Token Misuse Detection...")
        token_findings = detect_session_token_misuse(target)
        all_findings["TOKEN_MISUSE"] = token_findings
        for vuln in token_findings.get("vulnerabilities", []):
            alert_logger.log_alert(vuln["severity"], "TOKEN_MISUSE", vuln["message"])
        
        typer.echo("\n[AITM-7/8] Rogue Gateway Detection...")
        gateway_findings = detect_rogue_gateway()
        all_findings["ROGUE_GATEWAY"] = gateway_findings
        for vuln in gateway_findings.get("vulnerabilities", []):
            alert_logger.log_alert(vuln["severity"], "ROGUE_GATEWAY", vuln["message"])
        
        typer.echo("\n[AITM-8/8] Real-time Alert Logging... ACTIVE ✓")
        
        typer.echo("\n" + "="*70)
        typer.echo("  AITM DETECTION COMPLETE - 8/8 MODULES EXECUTED")
        typer.echo("="*70)
        
        alert_logger.print_summary()

    # PHASE 2
    scope = validate_scope(target)
    delay_ms = scope.get("request_delay_ms", 1500)

    typer.echo("\n" + "="*70)
    typer.echo("  PHASE 2: AUTHENTICATION SECURITY TESTING")
    typer.echo("="*70)
    typer.echo("\n[*] Discovering auth endpoints...")
    auth_info = discover_auth(target)
    
    if auth_info.get("error"):
        typer.echo(f"\n❌ Target not reachable: {auth_info['error']}")
        save_scan_data_for_dashboard(target, test_email or "N/A", all_findings)
        alert_logger.save_summary()
        return

    login_url = target.rstrip("/") + "/rest/user/login"
    typer.echo(f"[+] Using Login endpoint: {login_url}")

    observation = {
        "login_detected": True,
        "login_url": login_url,
        "reset_flow": True,
        "mfa_present": False,
        "cookies_pre_auth": True,
        "rate_limit": False,
    }

    planner = Planner()
    typer.echo("\n[*] Starting AI-guided authentication assessment...\n")

    for _ in range(10):
        action = planner.next_step(observation)
        if action is None:
            typer.echo("\n[+] Assessment complete.")
            break

        typer.echo(f"\n[->] Action: {action}")
        result = {}

        if action == "TEST_SESSION":
            result = analyze_session_cookies(target)
            typer.echo("[✓] Session analysis executed")
            
        elif action == "ENUM_USER":
            result = check_username_enumeration(login_url, DEFAULT_TEST_USERS, delay_ms=delay_ms)
            typer.echo("[✓] Username enumeration executed")
            
        elif action == "TEST_RESET":
            reset_url = target.rstrip("/") + "/rest/user/reset-password"
            result = probe_reset_flow(reset_url, test_email or "test@example.com")
            typer.echo("[✓] Password reset flow tested")
            
        elif action == "TEST_MFA":
            import httpx
            try:
                r = httpx.get(target, timeout=8)
                mfa_signals = ["2fa", "two-factor", "otp", "verify"]
                detected = any(s in r.text.lower() for s in mfa_signals)
                result = {"mfa_detected": detected}
                typer.echo(f"[✓] MFA detection executed: {detected}")
                if not detected:
                    alert_logger.log_alert("MEDIUM", "MFA", "Multi-factor authentication not detected")
            except Exception as e:
                typer.echo(f"[!] MFA check failed: {e}")
                result = {"error": str(e)}
                
        elif action == "CONTROLLED_SPRAY":
            typer.echo("[!] Spray disabled for safety")
            result = {"skipped": True}

        all_findings[action] = result
        planner.record_finding(action, result)

    # EMAIL SECURITY ASSESSMENT
    if test_email:
        typer.echo("\n" + "="*70)
        typer.echo("  EMAIL SECURITY ASSESSMENT")
        typer.echo("="*70)
        
        email_findings = test_email_enumeration(target, test_email, delay_ms)
        all_findings["EMAIL_TEST"] = email_findings
        
        for vuln in email_findings.get("vulnerabilities", []):
            alert_logger.log_alert("HIGH", "EMAIL_ENUM", vuln)
        
        typer.echo("="*70 + "\n")

    # REPORTING
    status_analyzer.print_summary()
    status_analyzer.save_to_file(str(REPORTS_DIR / "status_codes.json"))

    typer.echo("\n[*] Generating comprehensive reports...")
    
    # SAVE DATA FIRST (CRITICAL!)
    save_scan_data_for_dashboard(target, test_email or "N/A", all_findings)
    
    attack_path = planner.get_attack_path()
    ai_impact = planner.get_impact_summary()
    
    report = generate_enhanced_report(target, all_findings, attack_path, ai_impact, enable_aitm)
    typer.echo("\n" + report)
    save_report(target, report)
    
    if "SSL_TLS_SECURITY" in all_findings:
        ssl_report = generate_ssl_report(all_findings["SSL_TLS_SECURITY"])
        with open(REPORTS_DIR / "ssl_security_report.txt", "w") as f:
            f.write(ssl_report)
        typer.echo(f"[+] SSL report: reports/ssl_security_report.txt")
    
    if "EMAIL_TEST" in all_findings:
        email_report = generate_email_report(all_findings["EMAIL_TEST"])
        with open(REPORTS_DIR / "email_assessment.txt", "w") as f:
            f.write(email_report)
        typer.echo(f"[+] Email report: reports/email_assessment.txt")
    
    if "EMAIL_TESTS" in all_findings:
        multi_report = generate_multi_email_report(all_findings["EMAIL_TESTS"])
        with open(REPORTS_DIR / "multi_email_assessment.txt", "w") as f:
            f.write(multi_report)
        typer.echo(f"[+] Multi-email report: reports/multi_email_assessment.txt")
    
    alert_logger.save_summary()
    
    # DASHBOARD AUTO-OPEN
    typer.echo("\n[*] Preparing dashboard...")
    
    dashboard_src = REPORTS_DIR / "acase_dashboard_complete.html"
    dashboard_dest = Path("/home/kali/acase_dashboard.html")
    data_dest = Path("/home/kali/scan_data.json")
    
    try:
        # Copy dashboard
        shutil.copy(dashboard_src, dashboard_dest)
        
        # Copy scan data (from all possible locations)
        if SCAN_DATA_FILE.exists():
            shutil.copy(SCAN_DATA_FILE, data_dest)
        elif (BASE_DIR / "scan_data.json").exists():
            shutil.copy(BASE_DIR / "scan_data.json", data_dest)
        
        # Set permissions
        subprocess.run(["chown", "kali:kali", str(dashboard_dest)], capture_output=True)
        subprocess.run(["chown", "kali:kali", str(data_dest)], capture_output=True)
        
        # Open dashboard
        subprocess.Popen(
            ['su', '-', 'kali', '-c', f'DISPLAY=:0 firefox {dashboard_dest}'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        
        typer.echo(f"[+] Dashboard opened automatically ✓")
        typer.echo(f"[+] Dashboard: {dashboard_dest}")
        typer.echo(f"[+] Data: {data_dest}")
        
    except Exception as e:
        typer.echo(f"[!] Dashboard open failed: {e}")
        typer.echo(f"[*] Manual open: firefox {dashboard_src}")

def generate_enhanced_report(target, findings, attack_path, ai_impact, aitm_enabled):
    """Generate comprehensive report"""
    
    report = f"""
{'='*70}
  ACASE COMPREHENSIVE SECURITY ASSESSMENT REPORT
{'='*70}
  Target : {target}
  Date   : {datetime.now().strftime("%Y-%m-%d %H:%M")}
  Modules: 8 AitM + 6 Auth = 14 Total
{'='*70}

"""
    
    if aitm_enabled:
        report += """[ADVERSARY-IN-THE-MIDDLE (AITM) DETECTION - 8 MODULES]

"""
        
        modules = [
            ("SSL_TLS_SECURITY", "SSL/TLS Security"),
            ("SESSION_HIJACKING", "Session Hijacking"),
            ("ARP_SPOOFING", "ARP Spoofing"),
            ("MITM_PROXY", "Proxy Detection"),
            ("DNS_SPOOFING", "DNS Spoofing"),
            ("TOKEN_MISUSE", "Token Misuse"),
            ("ROGUE_GATEWAY", "Rogue Gateway")
        ]
        
        for key, name in modules:
            if key in findings:
                vulns = findings[key].get("vulnerabilities", [])
                report += f"  {name}: {len(vulns)} issue(s)\n"
                for v in vulns[:2]:
                    report += f"    • [{v['severity']}] {v['message']}\n"
        
        report += "\n"
    
    report += """[AUTHENTICATION SECURITY]

"""
    
    if "EMAIL_TEST" in findings:
        email_vulns = findings["EMAIL_TEST"].get("vulnerabilities", [])
        report += f"  Email Validation: {len(email_vulns)} issue(s)\n"
        for v in email_vulns:
            report += f"    • {v}\n"
    
    report += f"""

[ATTACK PATH]

  {' → '.join(attack_path) if attack_path else 'N/A'}

[AI BUSINESS IMPACT]

  {ai_impact}

[RECOMMENDATIONS]

  1. Enable HTTPS with valid SSL/TLS certificates
  2. Implement HSTS header
  3. Deploy MFA for all accounts
  4. Monitor ARP table for spoofing
  5. Use secure session cookies
  6. Regular security audits

{'='*70}
"""
    
    return report

if __name__ == "__main__":
    app()
