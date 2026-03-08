"""
Auth Mapper - Advanced Authentication Surface Discovery
"""

import httpx
from bs4 import BeautifulSoup
from urllib.parse import urljoin


def discover_auth(base_url, timeout=10):
    result = {
        "auth_forms": [],
        "endpoints": [],
        "reset_flows": [],
        "mfa_indicators": [],
        "base_url": base_url,
        "error": None
    }

    print(f"[*] Checking target: {base_url}")

    try:
        response = httpx.get(base_url, timeout=timeout, follow_redirects=True)
        print(f"[✓] Target reachable (HTTP {response.status_code})")
    except Exception as e:
        result["error"] = f"Connection failed: {str(e)}"
        return result

    auth_paths = [
        "/login", "/login.php", "/signin", "/auth",
        "/account/login", "/admin/login",
        "/reset", "/forgot", "/forgot-password",
        "/password-reset", "/mfa", "/2fa"
    ]

    for path in auth_paths:
        try:
            url = urljoin(base_url, path)
            r = httpx.get(url, timeout=timeout, follow_redirects=True)

            if r.status_code == 200:
                result["endpoints"].append(url)

                soup = BeautifulSoup(r.text, "html.parser")

                # Detect login forms
                forms = soup.find_all("form")
                for form in forms:
                    password_fields = form.find_all("input", {"type": "password"})
                    if password_fields:
                        action = form.get("action", "")
                        form_url = urljoin(url, action) if action else url
                        result["auth_forms"].append({
                            "url": form_url,
                            "method": form.get("method", "POST").upper(),
                            "fields": len(form.find_all("input"))
                        })

                # Detect password reset keywords
                if "reset" in r.text.lower() or "forgot" in r.text.lower():
                    result["reset_flows"].append(url)

                # Detect MFA indicators
                if "otp" in r.text.lower() or "2fa" in r.text.lower() or "multi-factor" in r.text.lower():
                    result["mfa_indicators"].append(url)

        except:
            continue

    print(f"[✓] Auth forms found: {len(result['auth_forms'])}")
    print(f"[✓] Reset flows found: {len(result['reset_flows'])}")
    print(f"[✓] MFA indicators found: {len(result['mfa_indicators'])}")

    return result
