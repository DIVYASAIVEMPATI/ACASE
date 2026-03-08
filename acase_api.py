"""
ACASE Flask API Wrapper
"""
from flask import Flask, jsonify, request
from flask_cors import CORS
import threading
import json
import uuid
import sys
import random
import string
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent))

app = Flask(__name__)
CORS(app)

scan_jobs = {}
otp_store = {}
api_keys = {}


def generate_api_key():
    chars = string.ascii_uppercase + string.digits
    segments = [''.join(random.choices(chars, k=6)) for _ in range(4)]
    return "ACASE-" + "-".join(segments)


def generate_otp():
    return str(random.randint(100000, 999999))


def run_scan_background(scan_id, target, email):
    job = scan_jobs[scan_id]
    try:
        all_findings = {}

        from modules.ssl_security         import check_ssl_tls_security
        from modules.session_hijacking    import test_session_hijacking_vulnerabilities
        from modules.arp_detection        import detect_arp_spoofing
        from modules.proxy_detection      import detect_mitm_proxy
        from modules.dns_spoofing         import detect_dns_spoofing
        from modules.session_token_misuse import detect_session_token_misuse
        from modules.rogue_gateway        import detect_rogue_gateway
        from modules.email_validator      import test_email_enumeration
        from modules.enumerator           import check_username_enumeration
        from modules.reset_abuse          import probe_reset_flow
        from modules.session              import analyze_session_cookies

        STEPS = [
            (8,   "Checking SSL/TLS security...",      lambda: check_ssl_tls_security(target)),
            (18,  "Testing session hijacking...",       lambda: test_session_hijacking_vulnerabilities(target)),
            (28,  "Detecting ARP spoofing...",          lambda: detect_arp_spoofing()),
            (38,  "Detecting MITM proxy...",            lambda: detect_mitm_proxy(target)),
            (48,  "Detecting DNS spoofing...",          lambda: detect_dns_spoofing(target)),
            (56,  "Checking session token misuse...",   lambda: detect_session_token_misuse(target)),
            (64,  "Detecting rogue gateway...",         lambda: detect_rogue_gateway()),
            (72,  "Testing email enumeration...",       lambda: test_email_enumeration(target, email, 1500)),
            (80,  "Analyzing session cookies...",       lambda: analyze_session_cookies(target)),
            (88,  "Checking username enumeration...",   lambda: check_username_enumeration(
                target.rstrip("/") + "/rest/user/login",
                ["admin", "test", "nonexistentuser_xyz123", "user"],
                delay_ms=1500
            )),
            (94,  "Probing password reset flow...",     lambda: probe_reset_flow(
                target.rstrip("/") + "/rest/user/reset-password", email
            )),
            (100, "Scan complete!", None),
        ]

        MODULE_KEYS = [
            "SSL_TLS_SECURITY", "SESSION_HIJACKING", "ARP_SPOOFING",
            "MITM_PROXY", "DNS_SPOOFING", "TOKEN_MISUSE", "ROGUE_GATEWAY",
            "EMAIL_TEST", "SESSION", "ENUM_USER", "TEST_RESET"
        ]

        for i, (progress, message, fn) in enumerate(STEPS):
            job["progress"] = progress
            job["message"]  = message
            if fn is not None:
                result = fn()
                if i < len(MODULE_KEYS):
                    all_findings[MODULE_KEYS[i]] = result

        vuln_counts = {
            "ssl_tls":        len(all_findings.get("SSL_TLS_SECURITY",  {}).get("vulnerabilities", [])),
            "session_hijack": len(all_findings.get("SESSION_HIJACKING", {}).get("vulnerabilities", [])),
            "arp_spoofing":   len(all_findings.get("ARP_SPOOFING",      {}).get("vulnerabilities", [])),
            "proxy":          len(all_findings.get("MITM_PROXY",        {}).get("vulnerabilities", [])),
            "dns_spoofing":   len(all_findings.get("DNS_SPOOFING",      {}).get("vulnerabilities", [])),
            "token_misuse":   len(all_findings.get("TOKEN_MISUSE",      {}).get("vulnerabilities", [])),
            "rogue_gateway":  len(all_findings.get("ROGUE_GATEWAY",     {}).get("vulnerabilities", [])),
            "email":          len(all_findings.get("EMAIL_TEST",        {}).get("vulnerabilities", [])),
            "auth":           0,
        }

        total_vulns = sum(vuln_counts.values())
        risk_score  = min(50 + (total_vulns * 8), 100)

        scan_data = {
            "target":                target,
            "email":                 email,
            "timestamp":             datetime.now().isoformat(),
            "scan_date":             datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "risk_score":            risk_score,
            "vulnerability_counts":  vuln_counts,
            "total_vulnerabilities": total_vulns,
            "modules_executed":      14,
            "findings":              {}
        }

        for key, value in all_findings.items():
            if isinstance(value, dict):
                scan_data["findings"][key] = {
                    "vulnerabilities": value.get("vulnerabilities", []),
                    "tests_performed": value.get("tests_performed", []),
                    "status": "FAIL" if value.get("vulnerabilities") else "PASS"
                }

        reports_path = Path(__file__).parent / "reports" / "scan_data.json"
        reports_path.parent.mkdir(exist_ok=True)
        with open(reports_path, "w") as f:
            json.dump(scan_data, f, indent=2)

        try:
            with open("/home/kali/scan_data.json", "w") as f:
                json.dump(scan_data, f, indent=2)
        except PermissionError:
            pass

        job["status"] = "done"
        job["result"] = scan_data

    except Exception as e:
        job["status"] = "error"
        job["error"]  = str(e)
        print(f"[ACASE API ERROR] {e}")


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "ACASE API", "version": "1.0"})


@app.route("/api/register", methods=["POST"])
def register():
    body     = request.get_json()
    username = body.get("username", "").strip()
    email    = body.get("email",    "").strip()
    password = body.get("password", "").strip()
    url      = body.get("url",      "").strip()

    if not all([username, email, password, url]):
        return jsonify({"error": "All fields required"}), 400
    if "@" not in email:
        return jsonify({"error": "Invalid email"}), 400
    if not url.startswith("http"):
        return jsonify({"error": "URL must start with http://"}), 400

    api_key = generate_api_key()
    api_keys[api_key] = {
        "email":      email,
        "username":   username,
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "scan_count": 0,
        "last_used":  "Never"
    }

    otp = generate_otp()
    otp_store[email] = {
        "otp":        otp,
        "target":     url,
        "api_key":    api_key,
        "expires_at": datetime.now().timestamp() + 120
    }

    print(f"\n[ACASE] API Key: {api_key} | OTP: {otp} | Email: {email}\n")

    return jsonify({
        "api_key":  api_key,
        "otp":      otp,
        "otp_sent": True,
        "message":  f"OTP ready for {email}"
    })


@app.route("/api/validate-key", methods=["POST"])
def validate_key():
    body    = request.get_json()
    api_key = body.get("api_key", "").strip()
    if api_key not in api_keys:
        return jsonify({"valid": False, "error": "Invalid API key"}), 401
    info = api_keys[api_key]
    return jsonify({
        "valid":      True,
        "email":      info["email"],
        "username":   info["username"],
        "scan_count": info.get("scan_count", 0),
        "created_at": info["created_at"],
        "last_used":  info.get("last_used", "Never"),
    })


@app.route("/api/key-stats/<api_key>", methods=["GET"])
def key_stats(api_key):
    if api_key not in api_keys:
        return jsonify({"error": "Invalid API key"}), 404
    info = api_keys[api_key]
    user_scans = [
        {"scan_id": sid, "target": job["target"], "status": job["status"], "progress": job["progress"]}
        for sid, job in scan_jobs.items()
        if job.get("email") == info["email"]
    ]
    return jsonify({
        "api_key":    api_key,
        "email":      info["email"],
        "username":   info["username"],
        "scan_count": info.get("scan_count", 0),
        "created_at": info["created_at"],
        "last_used":  info.get("last_used", "Never"),
        "scans":      user_scans,
    })


@app.route("/api/verify-otp", methods=["POST"])
def verify_otp():
    body    = request.get_json()
    email   = body.get("email",   "").strip()
    entered = body.get("otp",     "").strip()
    api_key = body.get("api_key", "").strip()

    if api_key not in api_keys:
        return jsonify({"error": "Invalid API key — please register again"}), 401

    if email not in otp_store:
        return jsonify({"error": "No OTP found for this email"}), 400

    stored = otp_store[email]

    if datetime.now().timestamp() > stored["expires_at"]:
        del otp_store[email]
        return jsonify({"error": "OTP expired — please register again"}), 400

    if entered != stored["otp"]:
        return jsonify({"error": "Invalid OTP"}), 401

    api_keys[api_key]["scan_count"] = api_keys[api_key].get("scan_count", 0) + 1
    api_keys[api_key]["last_used"]  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    del otp_store[email]

    scan_id = str(uuid.uuid4())
    scan_jobs[scan_id] = {
        "status":   "running",
        "progress": 0,
        "message":  "Initializing scan...",
        "result":   None,
        "error":    None,
        "target":   stored["target"],
        "email":    email,
        "api_key":  api_key,
    }

    thread = threading.Thread(
        target=run_scan_background,
        args=(scan_id, stored["target"], email),
        daemon=True
    )
    thread.start()

    return jsonify({
        "scan_id": scan_id,
        "message": "Scan started",
        "target":  stored["target"]
    })


@app.route("/api/scan-status/<scan_id>", methods=["GET"])
def scan_status(scan_id):
    job = scan_jobs.get(scan_id)
    if not job:
        return jsonify({"error": "Scan not found"}), 404
    response = {
        "status":   job["status"],
        "progress": job["progress"],
        "message":  job["message"],
    }
    if job["status"] == "done":
        response["result"] = job["result"]
    elif job["status"] == "error":
        response["error"] = job["error"]
    return jsonify(response)


@app.route("/api/scan-result/<scan_id>", methods=["GET"])
def scan_result(scan_id):
    job = scan_jobs.get(scan_id)
    if not job:
        return jsonify({"error": "Scan not found"}), 404
    if job["status"] != "done":
        return jsonify({"error": "Scan not complete yet", "status": job["status"]}), 202
    return jsonify(job["result"])


@app.route("/reports/scan_data.json", methods=["GET"])
def serve_scan_data():
    path = Path(__file__).parent / "reports" / "scan_data.json"
    if not path.exists():
        return jsonify({"error": "No scan data yet"}), 404
    with open(path) as f:
        return jsonify(json.load(f))


if __name__ == "__main__":
    print("""
  ╔══════════════════════════════════════╗
  ║   ACASE API SERVER — v2.0            ║
  ║   Running on http://localhost:5000   ║
  ╚══════════════════════════════════════╝
  NEW: API key validation + scan tracking
    POST /api/register
    POST /api/verify-otp
    POST /api/validate-key
    GET  /api/key-stats/<key>
    GET  /api/scan-status/<id>
    GET  /api/health
    """)
    app.run(host="0.0.0.0", port=5000, debug=True)
