"""
Advanced Session Token Misuse Detection
Tests authenticated session behavior
"""

import httpx
import time
from datetime import datetime
from modules.status_analyzer import record_status


def detect_session_token_misuse(target_url, login_url=None, username=None, password=None):
    findings = {
        "target": target_url,
        "timestamp": datetime.now().isoformat(),
        "tests_performed": [],
        "vulnerabilities": [],
        "alerts": []
    }

    print("\n" + "="*60)
    print("SESSION TOKEN MISUSE DETECTION")
    print("="*60)

    if not login_url or not username or not password:
        print("[!] Authentication required for accurate testing.")
        findings["alerts"].append({
            "type": "INFO",
            "message": "Authenticated session required for full testing"
        })
        return findings

    try:
        # STEP 1: Login to obtain session
        client = httpx.Client(follow_redirects=True)

        login_resp = client.post(
            login_url,
            data={"username": username, "password": password},
            timeout=10
        )

        record_status(login_url, "POST", login_resp.status_code, "auth")

        if login_resp.status_code not in [200, 302]:
            print("[!] Login failed. Cannot test session.")
            return findings

        print("[✓] Authenticated session established.")

        session_cookies = client.cookies.jar

        if not session_cookies:
            print("[!] No session cookies found.")
            return findings

        # TEST 1: Token reuse after logout
        print("\n[TEST 1] Token Reuse After Logout")

        logout_url = target_url.rstrip("/") + "/logout"
        try:
            client.get(logout_url, timeout=5)
        except:
            pass

        time.sleep(1)

        reuse_resp = client.get(target_url, timeout=10)
        record_status(target_url, "GET", reuse_resp.status_code, "auth")

        if reuse_resp.status_code == 200:
            findings["vulnerabilities"].append({
                "severity": "HIGH",
                "type": "TOKEN_REUSE_AFTER_LOGOUT",
                "message": "Session token still valid after logout"
            })
            print("  ❌ Token still works after logout")
        else:
            print("  ✓ Token invalidated after logout")

        findings["tests_performed"].append({"test": "TOKEN_REUSE", "result": "COMPLETE"})

        # TEST 2: Parallel session detection
        print("\n[TEST 2] Parallel Session Test")

        client2 = httpx.Client(follow_redirects=True)

        login_resp2 = client2.post(
            login_url,
            data={"username": username, "password": password},
            timeout=10
        )

        record_status(login_url, "POST", login_resp2.status_code, "auth")

        if login_resp2.status_code in [200, 302]:
            findings["alerts"].append({
                "type": "INFO",
                "message": "Multiple concurrent sessions allowed"
            })
            print("  ℹ Multiple concurrent sessions allowed")

        findings["tests_performed"].append({"test": "PARALLEL_SESSION", "result": "COMPLETE"})

    except Exception as e:
        print(f"[!] Error during session testing: {str(e)}")

    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    print(f"Tests Performed: {len(findings['tests_performed'])}")
    print(f"Vulnerabilities: {len(findings['vulnerabilities'])}")
    print(f"Alerts: {len(findings['alerts'])}")
    print("="*60 + "\n")

    return findings
