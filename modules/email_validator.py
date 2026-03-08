"""
Email Validator - Validates and tests emails for vulnerabilities
Enhanced with offline validation and detailed status reporting
"""
import re
import httpx
from datetime import datetime


AUTHORIZED_DOMAINS = [
    "gmail.com",
    "yahoo.com", 
    "outlook.com",
    "hotmail.com",
    "protonmail.com",
    "icloud.com",
    "company.com",
    "example.com"
]


def validate_email_format(email):
    """Check if email format is valid"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def check_domain_authorized(email):
    """Check if email domain is in authorized list"""
    try:
        domain = email.split('@')[1].lower()
        return domain in AUTHORIZED_DOMAINS
    except:
        return False


def get_email_domain(email):
    """Extract domain from email"""
    try:
        return email.split('@')[1].lower()
    except:
        return "unknown"


def validate_email_offline(email):
    """
    Validate email without needing target connection
    Returns detailed validation status
    """
    print(f"\n{'='*60}")
    print(f"  OFFLINE EMAIL VALIDATION")
    print(f"{'='*60}")
    print(f"Email: {email}")
    
    result = {
        "email": email,
        "timestamp": datetime.now().isoformat(),
        "validations": []
    }
    
    # Test 1: Format validation
    print(f"\n[TEST 1] Email Format Validation")
    is_valid = validate_email_format(email)
    result["validations"].append({
        "test": "FORMAT_CHECK",
        "status": "PASS" if is_valid else "FAIL",
        "details": "Valid email format" if is_valid else "Invalid email format"
    })
    print(f"  Status: {'✓ PASS' if is_valid else '✗ FAIL'}")
    print(f"  Result: {result['validations'][-1]['details']}")
    
    if not is_valid:
        print(f"\n{'='*60}\n")
        return result
    
    # Test 2: Domain extraction
    print(f"\n[TEST 2] Domain Extraction")
    domain = get_email_domain(email)
    result["validations"].append({
        "test": "DOMAIN_EXTRACTION",
        "status": "PASS",
        "details": f"Domain: {domain}"
    })
    print(f"  Status: ✓ PASS")
    print(f"  Domain: {domain}")
    
    # Test 3: Domain authorization
    print(f"\n[TEST 3] Domain Authorization Check")
    is_authorized = check_domain_authorized(email)
    result["validations"].append({
        "test": "DOMAIN_AUTHORIZATION",
        "status": "PASS" if is_authorized else "WARNING",
        "details": f"Domain {domain} is {'authorized' if is_authorized else 'not in authorized list'}"
    })
    print(f"  Status: {'✓ PASS' if is_authorized else '⚠ WARNING'}")
    print(f"  Result: {result['validations'][-1]['details']}")
    
    # Test 4: Domain reputation (basic check)
    print(f"\n[TEST 4] Domain Reputation Check")
    known_domains = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com"]
    is_reputable = domain in known_domains
    result["validations"].append({
        "test": "DOMAIN_REPUTATION",
        "status": "PASS" if is_reputable else "INFO",
        "details": f"Domain is {'a well-known provider' if is_reputable else 'custom/corporate domain'}"
    })
    print(f"  Status: {'✓ PASS' if is_reputable else 'ℹ INFO'}")
    print(f"  Result: {result['validations'][-1]['details']}")
    
    # Test 5: Email structure analysis
    print(f"\n[TEST 5] Email Structure Analysis")
    local_part = email.split('@')[0]
    has_dots = '.' in local_part
    has_numbers = any(c.isdigit() for c in local_part)
    has_special = any(c in local_part for c in ['+', '-', '_'])
    
    structure_details = []
    if has_dots: structure_details.append("contains dots")
    if has_numbers: structure_details.append("contains numbers")
    if has_special: structure_details.append("contains special chars")
    if not structure_details: structure_details.append("simple format")
    
    result["validations"].append({
        "test": "STRUCTURE_ANALYSIS",
        "status": "INFO",
        "details": f"Local part {', '.join(structure_details)}"
    })
    print(f"  Status: ℹ INFO")
    print(f"  Local part: {local_part}")
    print(f"  Properties: {', '.join(structure_details)}")
    
    print(f"\n{'='*60}")
    print(f"  VALIDATION SUMMARY")
    print(f"{'='*60}")
    
    passed = sum(1 for v in result["validations"] if v["status"] == "PASS")
    warnings = sum(1 for v in result["validations"] if v["status"] == "WARNING")
    
    print(f"Tests Performed: {len(result['validations'])}")
    print(f"Passed: {passed}")
    print(f"Warnings: {warnings}")
    print(f"\n{'='*60}\n")
    
    return result


def test_email_enumeration(target_url, email, delay_ms=1500):
    """
    Test if email can be enumerated via reset/login endpoints
    Now includes offline validation first
    """
    import time
    
    # ALWAYS do offline validation first
    offline_result = validate_email_offline(email)
    
    findings = {
        "email": email,
        "is_valid_format": validate_email_format(email),
        "is_authorized_domain": check_domain_authorized(email),
        "offline_validations": offline_result["validations"],
        "tests_performed": [],
        "vulnerabilities": [],
        "status_codes": {},
        "timestamp": datetime.now().isoformat()
    }
    
    # Only proceed with online tests if target is reachable
    print(f"\n{'='*60}")
    print(f"  ONLINE EMAIL ENUMERATION TESTS")
    print(f"{'='*60}")
    print(f"Email: {email}")
    print(f"Target: {target_url}")
    print(f"{'='*60}\n")
    
    # Test 1: Password Reset Endpoint
    print("[ONLINE TEST 1] Testing password reset endpoint...")
    reset_url = target_url.rstrip('/') + '/setup.php'
    
    try:
        time.sleep(delay_ms / 1000)
        response = httpx.post(
            reset_url,
            data={"email": email, "action": "reset"},
            timeout=10,
            follow_redirects=True
        )
        
        findings['status_codes']['reset_request'] = response.status_code
        findings['tests_performed'].append({
            "test": "password_reset",
            "url": reset_url,
            "status_code": response.status_code,
            "timestamp": datetime.now().isoformat()
        })
        
        print(f"  → Status Code: {response.status_code} ({get_status_name(response.status_code)})")
        
        body_lower = response.text.lower()
        
        if "email not found" in body_lower or "user does not exist" in body_lower:
            findings['vulnerabilities'].append("Email enumeration via error message")
            print(f"  → [VULN] Email enumeration possible - 'not found' message detected")
        elif "reset link sent" in body_lower or "check your email" in body_lower:
            findings['vulnerabilities'].append("Email enumeration via success message")
            print(f"  → [VULN] Email enumeration possible - different success message")
        else:
            print(f"  → [OK] Generic response - no obvious enumeration")
            
    except httpx.ConnectError:
        print(f"  → [ERROR] Connection refused - target not reachable")
        findings['tests_performed'].append({
            "test": "password_reset",
            "error": "Connection refused"
        })
    except Exception as e:
        print(f"  → [ERROR] {e}")
        findings['tests_performed'].append({
            "test": "password_reset",
            "error": str(e)
        })
    
    # Test 2: Login Endpoint
    print("\n[ONLINE TEST 2] Testing login endpoint...")
    login_url = target_url.rstrip('/') + '/login.php'
    
    try:
        time.sleep(delay_ms / 1000)
        response = httpx.post(
            login_url,
            data={"username": email, "password": "test123", "Login": "Login"},
            timeout=10,
            follow_redirects=True
        )
        
        findings['status_codes']['login_attempt'] = response.status_code
        findings['tests_performed'].append({
            "test": "login_attempt",
            "url": login_url,
            "status_code": response.status_code,
            "timestamp": datetime.now().isoformat()
        })
        
        print(f"  → Status Code: {response.status_code} ({get_status_name(response.status_code)})")
        
        body_lower = response.text.lower()
        
        if "username" in body_lower and ("invalid" in body_lower or "incorrect" in body_lower):
            print(f"  → Error message mentions username/email")
        if "password" in body_lower and ("invalid" in body_lower or "incorrect" in body_lower):
            print(f"  → Error message mentions password")
            
    except httpx.ConnectError:
        print(f"  → [ERROR] Connection refused - target not reachable")
        findings['tests_performed'].append({
            "test": "login_attempt",
            "error": "Connection refused"
        })
    except Exception as e:
        print(f"  → [ERROR] {e}")
    
    # Test 3: Registration Endpoint
    print("\n[ONLINE TEST 3] Testing registration endpoint...")
    register_url = target_url.rstrip('/') + '/register.php'
    
    try:
        time.sleep(delay_ms / 1000)
        response = httpx.get(register_url, timeout=10)
        
        findings['status_codes']['registration_page'] = response.status_code
        findings['tests_performed'].append({
            "test": "registration_check",
            "url": register_url,
            "status_code": response.status_code,
            "timestamp": datetime.now().isoformat()
        })
        
        print(f"  → Status Code: {response.status_code} ({get_status_name(response.status_code)})")
        
        if response.status_code == 200:
            print(f"  → Registration endpoint accessible")
        else:
            print(f"  → Registration endpoint not found or disabled")
            
    except httpx.ConnectError:
        print(f"  → [ERROR] Connection refused - target not reachable")
        findings['tests_performed'].append({
            "test": "registration_check",
            "error": "Connection refused"
        })
    except Exception as e:
        print(f"  → [ERROR] {e}")
    
    print(f"\n{'='*60}")
    print(f"  SUMMARY")
    print(f"{'='*60}")
    print(f"Offline Validations: {len(findings['offline_validations'])}")
    print(f"Online Tests Attempted: 3")
    print(f"Online Tests Completed: {len(findings['tests_performed'])}")
    print(f"Vulnerabilities Found: {len(findings['vulnerabilities'])}")
    
    if findings['vulnerabilities']:
        print(f"\n[!] VULNERABILITIES DETECTED:")
        for vuln in findings['vulnerabilities']:
            print(f"  - {vuln}")
    else:
        print(f"\n[✓] No vulnerabilities detected")
    
    print(f"{'='*60}\n")
    
    return findings


def get_status_name(code):
    """Get HTTP status code name"""
    names = {
        200: "OK", 201: "Created", 204: "No Content",
        301: "Moved Permanently", 302: "Found", 304: "Not Modified",
        400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
        404: "Not Found", 405: "Method Not Allowed",
        500: "Internal Server Error", 502: "Bad Gateway",
        503: "Service Unavailable"
    }
    return names.get(code, "Unknown")


def generate_email_report(findings):
    """Generate detailed email testing report"""
    report = f"""
{'='*70}
EMAIL SECURITY ASSESSMENT REPORT
{'='*70}

EMAIL TESTED: {findings['email']}
TIMESTAMP: {findings['timestamp']}

OFFLINE VALIDATIONS:
"""
    
    for validation in findings.get('offline_validations', []):
        status_symbol = "✓" if validation['status'] == "PASS" else "⚠" if validation['status'] == "WARNING" else "ℹ"
        report += f"  {status_symbol} {validation['test']}: {validation['details']}\n"
    
    report += f"\nONLINE TESTS PERFORMED: {len(findings['tests_performed'])}\n"
    
    for i, test in enumerate(findings['tests_performed'], 1):
        report += f"\n  {i}. {test.get('test', 'unknown').upper()}\n"
        report += f"     URL: {test.get('url', 'N/A')}\n"
        report += f"     Status: {test.get('status_code', 'ERROR')}\n"
        if 'error' in test:
            report += f"     Error: {test['error']}\n"
    
    report += f"\nSTATUS CODES CAPTURED:\n"
    for endpoint, code in findings.get('status_codes', {}).items():
        report += f"  {endpoint}: {code} ({get_status_name(code)})\n"
    
    report += f"\nVULNERABILITIES FOUND: {len(findings['vulnerabilities'])}\n"
    
    if findings['vulnerabilities']:
        report += "\n"
        for vuln in findings['vulnerabilities']:
            report += f"  [!] {vuln}\n"
    else:
        report += "  [✓] No vulnerabilities detected\n"
    
    report += f"\n{'='*70}\n"
    
    return report
