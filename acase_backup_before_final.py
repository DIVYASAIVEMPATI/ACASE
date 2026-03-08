import typer
import sys
import subprocess
import shutil
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from scope.validator import validate_scope
from modules.mapper import discover_auth
from modules.enumerator import check_username_enumeration
from modules.reset_abuse import probe_reset_flow
from modules.session import analyze_session_cookies
from modules.email_validator import test_email_enumeration, generate_email_report
from modules.multi_email_tester import test_multiple_emails, generate_multi_email_report
from modules.status_analyzer import get_analyzer

# NEW: AitM Detection Modules
from modules.ssl_security import check_ssl_tls_security, generate_ssl_report
from modules.session_hijacking import test_session_hijacking_vulnerabilities
from modules.arp_detection import detect_arp_spoofing
from modules.proxy_detection import detect_mitm_proxy

from core.planner import Planner
from reports.generator import generate_report, save_report

app = typer.Typer()
DEFAULT_TEST_USERS = ["admin", "test", "nonexistentuser_xyz123", "user"]

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

def start_custom_docker():
    """Start custom Docker container"""
    typer.echo("\n╔════════════════════════════════════════════╗")
    typer.echo("║  CUSTOM DOCKER CONTAINER SETUP             ║")
    typer.echo("╚════════════════════════════════════════════╝")
    typer.echo("\nPopular vulnerable apps:")
    typer.echo("  1. webgoat/webgoat (WebGoat)")
    typer.echo("  2. raesene/bwapp (bWAPP)")
    typer.echo("  3. citizenstig/nowasp (Mutillidae)")
    typer.echo("  4. vulnerables/web-dvwa (DVWA)")
    typer.echo("  5. Custom image\n")
    
    choice = typer.prompt("Select option (1-5) or press Enter to skip", default="skip")
    
    if choice == "skip":
        return None, None
    
    images = {
        "1": ("webgoat/webgoat", "8080"),
        "2": ("raesene/bwapp", "80"),
        "3": ("citizenstig/nowasp", "80"),
        "4": ("vulnerables/web-dvwa", "80")
    }
    
    if choice in images:
        image, default_port = images[choice]
        port = typer.prompt("Port to expose", default=default_port)
    elif choice == "5":
        image = typer.prompt("Docker image name")
        port = typer.prompt("Port to expose")
    else:
        return None, None
    
    container_name = f"acase_custom_{int(time.time())}"
    
    typer.echo(f"\n[*] Starting {image}...")
    result = subprocess.run([
        "docker", "run", "-d", "--name", container_name,
        "-p", f"{port}:{port}", image
    ], capture_output=True, text=True)
    
    if result.returncode != 0:
        typer.echo(f"[!] Failed: {result.stderr}")
        return None, None
    
    typer.echo(f"[*] Waiting 30 seconds...")
    time.sleep(30)
    
    target_url = f"http://localhost:{port}"
    typer.echo(f"[✓] Ready at {target_url}")
    
    return target_url, container_name

@app.command()
def scan(target: str = None, test_email: str = None, emails_file: str = None, 
         enable_aitm: bool = True, interactive: bool = True):
    """
    ACASE Security Scanner - Complete AitM Detection
    
    Args:
        target: Target URL
        test_email: Email to test
        enable_aitm: Enable AitM detection modules (default: True)
        interactive: Interactive mode (default: True)
    """
    
    typer.echo("\n" + "=" * 50)
    typer.echo("  ACASE - Auth Security Assessment")
    typer.echo("  WITH AITM ATTACK DETECTION")
    typer.echo("=" * 50)

    # STEP 1: INPUT
    if interactive:
        if not target:
            typer.echo("\n📋 Target Options:")
            typer.echo("1. Enter URL manually")
            typer.echo("2. Start custom Docker container")
            
            option = typer.prompt("Choose option (1 or 2)", default="1")
            
            if option == "2":
                target, container = start_custom_docker()
                if not target:
                    typer.echo("[!] No container started. Exiting.")
                    return
            else:
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

    # Initialize
    status_analyzer = get_analyzer()
    all_findings = {}
    
    # STEP 2: AITM DETECTION PHASE (NEW!)
    if enable_aitm:
        typer.echo("\n" + "="*60)
        typer.echo("  PHASE 1: ADVERSARY-IN-THE-MIDDLE DETECTION")
        typer.echo("="*60)
        
        # Test 1: SSL/TLS Security
        typer.echo("\n[AITM-1] SSL/TLS Security Analysis...")
        ssl_findings = check_ssl_tls_security(target)
        all_findings["SSL_TLS_SECURITY"] = ssl_findings
        
        # Test 2: Session Hijacking
        typer.echo("\n[AITM-2] Session Hijacking Vulnerability Test...")
        session_hijack_findings = test_session_hijacking_vulnerabilities(target)
        all_findings["SESSION_HIJACKING"] = session_hijack_findings
        
        # Test 3: ARP Spoofing Detection
        typer.echo("\n[AITM-3] ARP Spoofing Detection...")
        arp_findings = detect_arp_spoofing()
        all_findings["ARP_SPOOFING"] = arp_findings
        
        # Test 4: Proxy Detection
        typer.echo("\n[AITM-4] Man-in-the-Middle Proxy Detection...")
        proxy_findings = detect_mitm_proxy(target)
        all_findings["MITM_PROXY"] = proxy_findings
        
        typer.echo("\n" + "="*60)
        typer.echo("  AITM DETECTION COMPLETE")
        typer.echo("="*60)
        
        # Count AitM vulnerabilities
        aitm_vulns = 0
        for key in ["SSL_TLS_SECURITY", "SESSION_HIJACKING", "ARP_SPOOFING", "MITM_PROXY"]:
            if key in all_findings:
                aitm_vulns += len(all_findings[key].get("vulnerabilities", []))
        
        if aitm_vulns > 0:
            typer.echo(f"\n⚠ {aitm_vulns} AitM vulnerabilities detected!")
        else:
            typer.echo(f"\n✓ No AitM attacks detected")

    # STEP 3: SCOPE VALIDATION
    scope = validate_scope(target)
    delay_ms = scope.get("request_delay_ms", 1500)

    # STEP 4: ENDPOINT DISCOVERY
    typer.echo("\n" + "="*60)
    typer.echo("  PHASE 2: AUTHENTICATION SECURITY TESTING")
    typer.echo("="*60)
    typer.echo("\n[*] Discovering auth endpoints...")
    auth_info = discover_auth(target)
    
    if auth_info.get("error"):
        typer.echo(f"\n❌ Target not reachable: {auth_info['error']}")
        
        # Generate AitM-only report
        if enable_aitm and all_findings:
            typer.echo("\n[*] Generating AitM detection report...")
            aitm_report = generate_aitm_report(target, all_findings)
            save_report(target, aitm_report)
            typer.echo("[+] AitM report saved")
        
        return

    login_url = None
    if auth_info["auth_forms"]:
        login_url = auth_info["auth_forms"][0]["url"]
        typer.echo(f"[+] Login endpoint: {login_url}")
    else:
        typer.echo("[~] No auth forms found")

    # STEP 5: AI-GUIDED TESTING
    observation = {
        "login_detected": bool(auth_info["auth_forms"]),
        "login_url": login_url,
        "mfa_present": False,
        "reset_flow": True,
        "cookies_pre_auth": True,
        "rate_limit": False,
    }

    planner = Planner()

    typer.echo("\n[*] Starting AI-guided assessment...\n")

    for _ in range(10):
        action = planner.next_step(observation)
        if action is None:
            typer.echo("\n[+] Assessment complete.")
            break

        typer.echo(f"\n[->] Action: {action}")
        result = {}

        if action == "TEST_SESSION":
            result = analyze_session_cookies(target)
            observation["cookies_pre_auth"] = bool(result.get("cookies_found"))

        elif action == "ENUM_USER" and login_url:
            result = check_username_enumeration(login_url, DEFAULT_TEST_USERS, delay_ms=delay_ms)
            observation["error_message_diff"] = result.get("enumeration_possible", False)
            
            if emails_file:
                typer.echo(f"\n[*] Testing emails from: {emails_file}")
                try:
                    with open(emails_file, 'r') as f:
                        email_list = [line.strip() for line in f if line.strip()]
                    multi_results = test_multiple_emails(target, email_list, delay_ms)
                    all_findings["EMAIL_TESTS"] = multi_results
                except FileNotFoundError:
                    typer.echo(f"[!] File not found: {emails_file}")
            elif test_email:
                typer.echo(f"\n[*] Testing email: {test_email}")
                email_findings = test_email_enumeration(target, test_email, delay_ms)
                all_findings["EMAIL_TEST"] = email_findings
                if email_findings.get("vulnerabilities"):
                    result["email_vulnerabilities"] = email_findings["vulnerabilities"]

        elif action == "TEST_RESET":
            reset_url = target.rstrip("/") + "/password-reset"
            result = probe_reset_flow(reset_url, test_email or "test@example.com")

        elif action == "TEST_MFA":
            import httpx
            try:
                r = httpx.get(login_url or target, timeout=8)
                status_analyzer.record_status(login_url or target, "GET", r.status_code, "mfa_check")
                mfa_signals = ["2fa", "two-factor", "authenticator", "otp", "verify"]
                observation["mfa_present"] = any(s in r.text.lower() for s in mfa_signals)
                result = {"mfa_detected": observation["mfa_present"]}
                print(f"  MFA present: {observation['mfa_present']}")
            except Exception as e:
                print(f"  [!] MFA check failed: {e}")

        elif action == "CONTROLLED_SPRAY":
            typer.echo("[!] Spray disabled for safety")
            result = {"skipped": True}

        all_findings[action] = result
        planner.record_finding(action, result)

    # STEP 6: STATUS ANALYSIS
    status_analyzer.print_summary()
    status_analyzer.save_to_file("reports/status_codes.json")

    # STEP 7: REPORT GENERATION
    typer.echo("\n[*] Generating comprehensive reports...")
    attack_path = planner.get_attack_path()
    ai_impact = planner.get_impact_summary()
    
    # Main report with AitM findings
    report = generate_enhanced_report(target, all_findings, attack_path, ai_impact, enable_aitm)
    typer.echo("\n" + report)
    save_report(target, report)
    
    # SSL/TLS report
    if "SSL_TLS_SECURITY" in all_findings:
        ssl_report = generate_ssl_report(all_findings["SSL_TLS_SECURITY"])
        with open("reports/ssl_security_report.txt", "w") as f:
            f.write(ssl_report)
        typer.echo(f"[+] SSL report: reports/ssl_security_report.txt")
    
    # Email report
    if "EMAIL_TEST" in all_findings:
        email_report = generate_email_report(all_findings["EMAIL_TEST"])
        with open("reports/email_assessment.txt", "w") as f:
            f.write(email_report)
        typer.echo(f"[+] Email report: reports/email_assessment.txt")
    
    if "EMAIL_TESTS" in all_findings:
        multi_report = generate_multi_email_report(all_findings["EMAIL_TESTS"])
        with open("reports/multi_email_assessment.txt", "w") as f:
            f.write(multi_report)
        typer.echo(f"[+] Multi-email report: reports/multi_email_assessment.txt")
    
    # STEP 8: DASHBOARD
    typer.echo("\n[*] Opening ML Dashboard...")
    dashboard_path = Path(__file__).parent / "reports" / "acase_dashboard.html"
    if dashboard_path.exists():
        try:
            shutil.copy(dashboard_path, "/tmp/acase_dashboard.html")
            subprocess.Popen(['su', '-', 'kali', '-c', 'DISPLAY=:0 firefox /tmp/acase_dashboard.html'], 
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            typer.echo(f"[+] Dashboard opened in Firefox ✓")
        except Exception as e:
            typer.echo(f"[!] Auto-open failed: {e}")

def generate_enhanced_report(target, findings, attack_path, ai_impact, aitm_enabled):
    """Generate enhanced report with AitM findings"""
    from datetime import datetime
    
    report = f"""
{'='*70}
  ACASE COMPREHENSIVE SECURITY ASSESSMENT REPORT
{'='*70}
  Target : {target}
  Date   : {datetime.now().strftime("%Y-%m-%d %H:%M")}
{'='*70}

"""
    
    if aitm_enabled:
        report += """
[ADVERSARY-IN-THE-MIDDLE (AITM) DETECTION RESULTS]

"""
        
        # SSL/TLS findings
        if "SSL_TLS_SECURITY" in findings:
            ssl_vulns = findings["SSL_TLS_SECURITY"].get("vulnerabilities", [])
            report += f"  SSL/TLS Security: {len(ssl_vulns)} issues found\n"
            for v in ssl_vulns[:3]:
                report += f"    • [{v['severity']}] {v['message']}\n"
        
        # Session hijacking
        if "SESSION_HIJACKING" in findings:
            session_vulns = findings["SESSION_HIJACKING"].get("vulnerabilities", [])
            report += f"  Session Security: {len(session_vulns)} issues found\n"
            for v in session_vulns[:3]:
                report += f"    • [{v['severity']}] {v['message']}\n"
        
        # ARP spoofing
        if "ARP_SPOOFING" in findings:
            arp_vulns = findings["ARP_SPOOFING"].get("vulnerabilities", [])
            if arp_vulns:
                report += f"  ARP Spoofing: {len(arp_vulns)} issues found\n"
                for v in arp_vulns[:3]:
                    report += f"    • [{v['severity']}] {v['message']}\n"
            else:
                report += "  ARP Spoofing: No issues detected ✓\n"
        
        # Proxy detection
        if "MITM_PROXY" in findings:
            proxy_vulns = findings["MITM_PROXY"].get("vulnerabilities", [])
            if proxy_vulns:
                report += f"  Proxy Detection: {len(proxy_vulns)} indicators found\n"
                for v in proxy_vulns[:3]:
                    report += f"    • [{v['severity']}] {v['message']}\n"
            else:
                report += "  Proxy Detection: No proxy detected ✓\n"
        
        report += "\n"
    
    report += """
[AUTHENTICATION SECURITY FINDINGS]

"""
    
    # Regular findings
    auth_findings = [k for k in findings.keys() if k not in ["SSL_TLS_SECURITY", "SESSION_HIJACKING", "ARP_SPOOFING", "MITM_PROXY"]]
    
    if auth_findings:
        for key in auth_findings:
            if isinstance(findings[key], dict) and findings[key]:
                report += f"  {key}: Tested\n"
    else:
        report += "  [+] No significant authentication issues detected.\n"
    
    report += f"""

[ATTACK PATH]

  {' → '.join(attack_path) if attack_path else 'N/A'}

[BUSINESS IMPACT]

  {ai_impact}

[RECOMMENDATIONS]

  1. Enable HTTPS with valid SSL/TLS certificates
  2. Implement HSTS to prevent SSL stripping
  3. Use secure, HttpOnly, SameSite cookies
  4. Monitor ARP table for spoofing attacks
  5. Implement MFA for all sensitive accounts
  6. Use generic error messages
  7. Regular security audits

{'='*70}
"""
    
    return report

def generate_aitm_report(target, findings):
    """Generate AitM-only report when target unreachable"""
    from datetime import datetime
    
    report = f"""
{'='*70}
  AITM DETECTION REPORT (Target Unreachable)
{'='*70}
  Target : {target}
  Date   : {datetime.now().strftime("%Y-%m-%d %H:%M")}
{'='*70}

Note: Full security assessment could not be completed as target
was not reachable. AitM detection modules were executed.

"""
    
    for key in ["SSL_TLS_SECURITY", "SESSION_HIJACKING", "ARP_SPOOFING", "MITM_PROXY"]:
        if key in findings:
            vulns = findings[key].get("vulnerabilities", [])
            report += f"\n{key}:\n"
            if vulns:
                for v in vulns:
                    report += f"  • [{v['severity']}] {v['message']}\n"
            else:
                report += "  No issues detected\n"
    
    report += f"\n{'='*70}\n"
    return report

if __name__ == "__main__":
    app()

def save_scan_data_for_dashboard(target, email):
    """Save scan data to be loaded by dashboard"""
    import json
    from datetime import datetime
    
    data = {
        "target": target,
        "email": email,
        "timestamp": datetime.now().isoformat(),
        "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M")
    }
    
    # Save to a JSON file that dashboard can read
    with open("reports/scan_data.json", "w") as f:
        json.dump(data, f, indent=2)
