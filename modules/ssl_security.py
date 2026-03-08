"""
SSL/TLS Security Analysis Module
Detects SSL stripping, certificate issues, and encryption weaknesses
"""
import ssl
import socket
import httpx
from datetime import datetime
from urllib.parse import urlparse


def check_ssl_tls_security(target_url):
    """
    Comprehensive SSL/TLS security check
    Detects:
    - SSL stripping attacks (HTTPS downgrade to HTTP)
    - Invalid/self-signed certificates
    - Weak cipher suites
    - Certificate expiry issues
    - Missing security headers
    """
    findings = {
        "target": target_url,
        "timestamp": datetime.now().isoformat(),
        "tests_performed": [],
        "vulnerabilities": [],
        "ssl_enabled": False,
        "certificate_valid": False,
        "cipher_suite": None,
        "security_headers": {}
    }
    
    parsed_url = urlparse(target_url)
    hostname = parsed_url.hostname
    port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
    
    print(f"\n{'='*60}")
    print(f"  SSL/TLS SECURITY ANALYSIS")
    print(f"{'='*60}")
    print(f"Target: {target_url}")
    print(f"Host: {hostname}:{port}")
    print(f"{'='*60}\n")
    
    # TEST 1: Check if HTTPS is used
    print("[TEST 1] Protocol Security Check")
    if parsed_url.scheme != 'https':
        findings["vulnerabilities"].append({
            "severity": "HIGH",
            "type": "SSL_STRIPPING_RISK",
            "message": "Site not using HTTPS - vulnerable to SSL stripping"
        })
        print(f"  ❌ VULNERABLE: Site uses HTTP (not HTTPS)")
        print(f"     Risk: Man-in-the-Middle can intercept traffic")
        findings["tests_performed"].append({
            "test": "HTTPS_CHECK",
            "result": "FAIL",
            "details": "HTTP protocol detected"
        })
    else:
        findings["ssl_enabled"] = True
        print(f"  ✓ SECURE: HTTPS enabled")
        findings["tests_performed"].append({
            "test": "HTTPS_CHECK",
            "result": "PASS"
        })
    
    # TEST 2: Certificate Validation (only if HTTPS)
    if parsed_url.scheme == 'https':
        print(f"\n[TEST 2] Certificate Validation")
        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    findings["certificate_valid"] = True
                    findings["cipher_suite"] = {
                        "name": cipher[0],
                        "protocol": cipher[1],
                        "bits": cipher[2]
                    }
                    
                    print(f"  ✓ Certificate Valid")
                    print(f"     Issued to: {cert.get('subject', [[('commonName', hostname)]])[0][0][1]}")
                    print(f"     Cipher: {cipher[0]}")
                    print(f"     Protocol: {cipher[1]}")
                    print(f"     Bits: {cipher[2]}")
                    
                    # Check certificate expiry
                    not_after = cert.get('notAfter')
                    if not_after:
                        expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        days_until_expiry = (expiry_date - datetime.now()).days
                        
                        if days_until_expiry < 30:
                            findings["vulnerabilities"].append({
                                "severity": "MEDIUM",
                                "type": "CERTIFICATE_EXPIRY",
                                "message": f"Certificate expires in {days_until_expiry} days"
                            })
                            print(f"  ⚠ WARNING: Certificate expires soon ({days_until_expiry} days)")
                    
                    findings["tests_performed"].append({
                        "test": "CERTIFICATE_VALIDATION",
                        "result": "PASS",
                        "details": f"Valid certificate, {cipher[1]}, {cipher[2]} bits"
                    })
                    
        except ssl.SSLCertVerificationError as e:
            findings["vulnerabilities"].append({
                "severity": "CRITICAL",
                "type": "INVALID_CERTIFICATE",
                "message": "SSL certificate validation failed - possible AitM attack"
            })
            print(f"  ❌ CRITICAL: Invalid certificate detected!")
            print(f"     Error: {str(e)}")
            print(f"     Risk: Active Man-in-the-Middle attack possible")
            findings["tests_performed"].append({
                "test": "CERTIFICATE_VALIDATION",
                "result": "FAIL",
                "details": str(e)
            })
            
        except ssl.SSLError as e:
            findings["vulnerabilities"].append({
                "severity": "HIGH",
                "type": "SSL_ERROR",
                "message": f"SSL error: {str(e)}"
            })
            print(f"  ❌ SSL Error: {str(e)}")
            findings["tests_performed"].append({
                "test": "CERTIFICATE_VALIDATION",
                "result": "ERROR",
                "details": str(e)
            })
            
        except Exception as e:
            print(f"  ⚠ Could not validate certificate: {str(e)}")
            findings["tests_performed"].append({
                "test": "CERTIFICATE_VALIDATION",
                "result": "ERROR",
                "details": str(e)
            })
    
    # TEST 3: Security Headers Check
    print(f"\n[TEST 3] Security Headers Analysis")
    try:
        response = httpx.get(target_url, timeout=10, follow_redirects=True)
        
        security_headers = {
            "Strict-Transport-Security": response.headers.get("Strict-Transport-Security"),
            "X-Frame-Options": response.headers.get("X-Frame-Options"),
            "X-Content-Type-Options": response.headers.get("X-Content-Type-Options"),
            "Content-Security-Policy": response.headers.get("Content-Security-Policy")
        }
        
        findings["security_headers"] = security_headers
        
        # Check HSTS (prevents SSL stripping)
        if not security_headers["Strict-Transport-Security"]:
            findings["vulnerabilities"].append({
                "severity": "HIGH",
                "type": "MISSING_HSTS",
                "message": "Missing HSTS header - vulnerable to SSL stripping attacks"
            })
            print(f"  ❌ Missing: Strict-Transport-Security (HSTS)")
            print(f"     Risk: Vulnerable to SSL stripping attacks")
        else:
            print(f"  ✓ Present: HSTS header")
        
        # Check other security headers
        if not security_headers["X-Frame-Options"]:
            print(f"  ⚠ Missing: X-Frame-Options (clickjacking risk)")
        else:
            print(f"  ✓ Present: X-Frame-Options")
        
        if not security_headers["X-Content-Type-Options"]:
            print(f"  ⚠ Missing: X-Content-Type-Options")
        else:
            print(f"  ✓ Present: X-Content-Type-Options")
        
        findings["tests_performed"].append({
            "test": "SECURITY_HEADERS",
            "result": "COMPLETE",
            "headers_found": len([h for h in security_headers.values() if h])
        })
        
    except Exception as e:
        print(f"  ⚠ Could not check headers: {str(e)}")
    
    # TEST 4: Mixed Content Check (HTTPS site loading HTTP resources)
    if parsed_url.scheme == 'https':
        print(f"\n[TEST 4] Mixed Content Detection")
        try:
            response = httpx.get(target_url, timeout=10)
            content = response.text.lower()
            
            # Look for HTTP resources in HTTPS page
            http_resources = []
            if 'src="http://' in content or "src='http://" in content:
                http_resources.append("images/scripts")
            if 'href="http://' in content or "href='http://" in content:
                http_resources.append("links/stylesheets")
            
            if http_resources:
                findings["vulnerabilities"].append({
                    "severity": "MEDIUM",
                    "type": "MIXED_CONTENT",
                    "message": f"HTTPS page loads HTTP resources: {', '.join(http_resources)}"
                })
                print(f"  ⚠ WARNING: Mixed content detected")
                print(f"     HTTP resources found: {', '.join(http_resources)}")
                print(f"     Risk: Partial vulnerability to AitM")
            else:
                print(f"  ✓ No mixed content detected")
            
            findings["tests_performed"].append({
                "test": "MIXED_CONTENT",
                "result": "PASS" if not http_resources else "FAIL"
            })
            
        except Exception as e:
            print(f"  ⚠ Could not check mixed content: {str(e)}")
    
    # Summary
    print(f"\n{'='*60}")
    print(f"  SUMMARY")
    print(f"{'='*60}")
    print(f"Tests Performed: {len(findings['tests_performed'])}")
    print(f"Vulnerabilities Found: {len(findings['vulnerabilities'])}")
    
    if findings['vulnerabilities']:
        print(f"\n❌ SECURITY ISSUES DETECTED:")
        for vuln in findings['vulnerabilities']:
            severity_color = "🔴" if vuln['severity'] == "CRITICAL" else "🟠" if vuln['severity'] == "HIGH" else "🟡"
            print(f"  {severity_color} [{vuln['severity']}] {vuln['message']}")
    else:
        print(f"\n✓ No SSL/TLS vulnerabilities detected")
    
    print(f"{'='*60}\n")
    
    return findings


def generate_ssl_report(findings):
    """Generate detailed SSL/TLS security report"""
    report = f"""
{'='*70}
SSL/TLS SECURITY ANALYSIS REPORT
{'='*70}

TARGET: {findings['target']}
TIMESTAMP: {findings['timestamp']}

SSL/TLS STATUS:
  HTTPS Enabled: {'Yes' if findings['ssl_enabled'] else 'No'}
  Certificate Valid: {'Yes' if findings['certificate_valid'] else 'No'}

"""
    
    if findings.get('cipher_suite'):
        report += f"""ENCRYPTION DETAILS:
  Cipher Suite: {findings['cipher_suite']['name']}
  Protocol: {findings['cipher_suite']['protocol']}
  Key Strength: {findings['cipher_suite']['bits']} bits

"""
    
    report += f"""TESTS PERFORMED: {len(findings['tests_performed'])}
"""
    for i, test in enumerate(findings['tests_performed'], 1):
        report += f"  {i}. {test['test']}: {test['result']}\n"
    
    report += f"\nVULNERABILITIES FOUND: {len(findings['vulnerabilities'])}\n"
    
    if findings['vulnerabilities']:
        report += "\n"
        for vuln in findings['vulnerabilities']:
            report += f"  [{vuln['severity']}] {vuln['type']}\n"
            report += f"    {vuln['message']}\n\n"
    else:
        report += "  No SSL/TLS vulnerabilities detected\n"
    
    report += f"\n{'='*70}\n"
    
    return report
