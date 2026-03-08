import math
import base64
import json
import httpx

def token_entropy(token):
    if not token:
        return 0.0
    prob = [float(token.count(c)) / len(token) for c in set(token)]
    return -sum(p * math.log2(p) for p in prob)

def is_weak_session(cookie_value):
    issues = []
    entropy = token_entropy(cookie_value)
    if entropy < 3.5:
        issues.append(f"Low entropy ({entropy:.2f}) - token may be predictable.")
    if len(cookie_value) < 16:
        issues.append(f"Short token ({len(cookie_value)} chars).")
    if cookie_value.isdigit():
        issues.append("Numeric-only token - very weak.")
    try:
        decoded = base64.b64decode(cookie_value + "==").decode("utf-8", errors="ignore")
        if any(kw in decoded.lower() for kw in ["user", "id", "admin", "role"]):
            issues.append("Token contains plaintext user data - not secure.")
    except Exception:
        pass
    return (len(issues) > 0, issues)

def analyze_session_cookies(target_url):
    result = {
        "cookies_found": [],
        "issues": [],
        "secure_flags_missing": [],
        "httponly_flags_missing": [],
        "samesite_missing": [],
    }
    try:
        r = httpx.get(target_url, timeout=8, follow_redirects=True)
        for name, value in r.cookies.items():
            result["cookies_found"].append(name)
            print(f"[~] Cookie: {name} = {value[:20]}...")
            weak, issues = is_weak_session(value)
            if weak:
                for issue in issues:
                    result["issues"].append(f"{name}: {issue}")
                    print(f"  [!] {name}: {issue}")
    except httpx.RequestError as e:
        print(f"[!] Session analysis failed: {e}")
    return result
