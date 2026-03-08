import httpx
import time
from datetime import datetime
from modules.status_analyzer import record_status

USER_NOT_FOUND_SIGNALS = [
    "user not found", "account does not exist",
    "no account with that email", "invalid username", "username not found",
]

WRONG_PASSWORD_SIGNALS = [
    "incorrect password", "wrong password",
    "invalid password", "invalid credentials", "password is wrong",
]


def analyze_error(response_text):
    text = response_text.lower()
    for signal in USER_NOT_FOUND_SIGNALS:
        if signal in text:
            return "user_not_found"
    for signal in WRONG_PASSWORD_SIGNALS:
        if signal in text:
            return "wrong_password"
    if "invalid" in text or "error" in text:
        return "generic_error"
    return "unknown"


def check_username_enumeration(login_url, test_usernames,
                               password_field_val="WrongPass!99",
                               delay_ms=1500):

    findings = {
        "target": login_url,
        "timestamp": datetime.now().isoformat(),
        "enumeration_possible": False,
        "vulnerabilities": [],
        "evidence": [],
        "responses": []
    }

    seen_errors = set()
    response_lengths = []
    response_times = []

    print("\n[USERNAME ENUMERATION TEST]\n")

    for username in test_usernames:
        try:
            start = time.time()

            r = httpx.post(
                login_url,
                data={"username": username, "password": password_field_val},
                timeout=8,
                follow_redirects=True,
            )

            end = time.time()

            record_status(login_url, "POST", r.status_code, "auth")

            error_class = analyze_error(r.text)

            resp_len = len(r.text)
            resp_time = end - start

            response_lengths.append(resp_len)
            response_times.append(resp_time)

            findings["responses"].append({
                "username": username,
                "status_code": r.status_code,
                "error_class": error_class,
                "response_length": resp_len,
                "response_time": round(resp_time, 3)
            })

            seen_errors.add(error_class)

            print(f"  [{username}] -> {error_class} "
                  f"(HTTP {r.status_code}, len={resp_len}, t={resp_time:.2f}s)")

        except httpx.RequestError as e:
            print(f"  [!] Request failed for {username}: {e}")

        time.sleep(delay_ms / 1000)

    # Error message based enumeration
    if "user_not_found" in seen_errors and "wrong_password" in seen_errors:
        findings["enumeration_possible"] = True
        findings["vulnerabilities"].append({
            "severity": "HIGH",
            "type": "USERNAME_ENUMERATION",
            "message": "Different error messages for valid vs invalid users"
        })
        findings["evidence"].append("Distinct error responses observed")

    # Length based enumeration
    if len(set(response_lengths)) > 1:
        findings["vulnerabilities"].append({
            "severity": "MEDIUM",
            "type": "RESPONSE_LENGTH_DIFFERENCE",
            "message": "Response lengths differ between usernames"
        })

    # Timing based enumeration
    if len(response_times) >= 2:
        if max(response_times) - min(response_times) > 0.5:
            findings["vulnerabilities"].append({
                "severity": "MEDIUM",
                "type": "TIMING_DIFFERENCE",
                "message": "Significant response time variation detected"
            })

    if findings["vulnerabilities"]:
        print("\n[!] Username enumeration POSSIBLE")
    else:
        print("\n[+] No username enumeration detected")

    return findings
