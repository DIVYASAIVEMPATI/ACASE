"""
Advanced Session Hijacking Detection
"""

import httpx
import math
from datetime import datetime
from modules.status_analyzer import record_status


def calculate_entropy(token):
    if not token:
        return 0
    prob = [float(token.count(c)) / len(token) for c in set(token)]
    return -sum([p * math.log2(p) for p in prob])


def test_session_hijacking_vulnerabilities(target_url):
    findings = {
        "target": target_url,
        "timestamp": datetime.now().isoformat(),
        "tests_performed": [],
        "vulnerabilities": []
    }

    print("\n" + "="*60)
    print("SESSION HIJACKING TESTS")
    print("="*60)

    try:
        response = httpx.get(target_url, timeout=10, follow_redirects=True)
        record_status(target_url, "GET", response.status_code, "session")

        cookies = response.cookies

        if not cookies:
            print("No session cookies detected.")
            return findings

        # TEST 1: Transmission Security
        print("\n[TEST 1] Cookie Transmission Security")

        for cookie in cookies.jar:
            name = cookie.name
            value = cookie.value

            if not target_url.startswith("https"):
                findings["vulnerabilities"].append({
                    "severity": "CRITICAL",
                    "type": "SESSION_OVER_HTTP",
                    "message": f"Cookie '{name}' transmitted over HTTP"
                })
                print(f"❌ Cookie '{name}' sent over HTTP")
            else:
                print(f"✓ Cookie '{name}' over HTTPS")

            if not cookie.secure:
                findings["vulnerabilities"].append({
                    "severity": "HIGH",
                    "type": "COOKIE_NOT_SECURE",
                    "message": f"Cookie '{name}' missing Secure flag"
                })

            if not cookie.has_nonstandard_attr("HttpOnly") and not cookie._rest.get("HttpOnly"):
                findings["vulnerabilities"].append({
                    "severity": "HIGH",
                    "type": "COOKIE_NOT_HTTPONLY",
                    "message": f"Cookie '{name}' missing HttpOnly flag"
                })

        findings["tests_performed"].append({"test": "TRANSMISSION_SECURITY", "result": "COMPLETE"})

        # TEST 2: Token Entropy
        print("\n[TEST 2] Token Entropy Analysis")

        for cookie in cookies.jar:
            entropy = calculate_entropy(cookie.value)
            print(f"Cookie '{cookie.name}' entropy: {entropy:.2f}")

            if entropy < 3.5:
                findings["vulnerabilities"].append({
                    "severity": "MEDIUM",
                    "type": "LOW_ENTROPY",
                    "message": f"Low entropy token '{cookie.name}'"
                })

        findings["tests_performed"].append({"test": "TOKEN_ENTROPY", "result": "COMPLETE"})

        # TEST 3: Token in URL
        print("\n[TEST 3] Token Exposure in URL")

        if "session" in str(response.url).lower():
            findings["vulnerabilities"].append({
                "severity": "HIGH",
                "type": "SESSION_IN_URL",
                "message": "Session token appears in URL"
            })
            print("❌ Session token exposed in URL")
        else:
            print("✓ No session token in URL")

        findings["tests_performed"].append({"test": "TOKEN_LOCATION", "result": "COMPLETE"})

    except Exception as e:
        print(f"Error during testing: {str(e)}")

    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    print(f"Vulnerabilities: {len(findings['vulnerabilities'])}")

    if findings["vulnerabilities"]:
        for v in findings["vulnerabilities"]:
            print(f"🔴 [{v['severity']}] {v['message']}")
    else:
        print("✓ No hijacking vulnerabilities detected")

    print("="*60 + "\n")

    return findings
