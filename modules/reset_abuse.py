import httpx
import time
from modules.status_analyzer import record_status

RESET_SUCCESS_SIGNALS = ["sent", "check your email", "reset link", "instructions"]
RESET_ERROR_SIGNALS = ["no account", "not found", "invalid email"]


def probe_reset_flow(reset_url, valid_email="test@example.com", fake_email="fake123456@example.com"):
    result = {
        "reset_flow_present": False,
        "email_enumeration_possible": False,
        "timing_difference": False,
        "issues": []
    }

    try:
        # Test valid email
        start_valid = time.time()
        r_valid = httpx.post(reset_url, data={"email": valid_email}, timeout=8, follow_redirects=True)
        end_valid = time.time()

        record_status(reset_url, "POST", r_valid.status_code, "reset")

        # Test fake email
        start_fake = time.time()
        r_fake = httpx.post(reset_url, data={"email": fake_email}, timeout=8, follow_redirects=True)
        end_fake = time.time()

        record_status(reset_url, "POST", r_fake.status_code, "reset")

        valid_text = r_valid.text.lower()
        fake_text = r_fake.text.lower()

        # Detect reset presence
        if any(s in valid_text for s in RESET_SUCCESS_SIGNALS):
            result["reset_flow_present"] = True

        # Email enumeration detection
        if valid_text != fake_text:
            result["email_enumeration_possible"] = True
            result["issues"].append("Different responses for valid vs invalid email (enumeration risk)")

        # Timing difference detection
        valid_time = end_valid - start_valid
        fake_time = end_fake - start_fake

        if abs(valid_time - fake_time) > 0.5:
            result["timing_difference"] = True
            result["issues"].append("Response timing differs significantly (timing enumeration risk)")

        print(f"[+] Reset flow tested at: {reset_url}")

        if result["email_enumeration_possible"]:
            print("[!] Email enumeration possible via reset endpoint")

        if result["timing_difference"]:
            print("[!] Timing-based enumeration risk detected")

    except httpx.RequestError as e:
        print(f"[!] Reset request failed: {e}")

    return result
