from playwright.sync_api import sync_playwright
import time

def attempt_login(url, username, password, delay_ms=1500):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        try:
            page.goto(url, timeout=10000)
            page.fill('input[type="text"]', username)
            time.sleep(delay_ms / 1000)
            page.fill('input[type="password"]', password)
            time.sleep(delay_ms / 1000)
            page.click('button[type="submit"]')
            page.wait_for_timeout(3000)
            content = page.content()
            print(f"  [browser] Login attempted for: {username}")
        except Exception as e:
            print(f"  [!] Browser error: {e}")
            content = ""
        finally:
            browser.close()
    return content

def check_mfa_page(url):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        try:
            page.goto(url, timeout=10000)
            page.wait_for_timeout(2000)
            content = page.content().lower()
            mfa_signals = ["2fa", "two-factor", "authenticator", "otp", "verify code"]
            found = [s for s in mfa_signals if s in content]
            if found:
                print(f"  [browser] MFA signals found: {found}")
                return True
            else:
                print(f"  [browser] No MFA signals detected")
                return False
        except Exception as e:
            print(f"  [!] Browser MFA check error: {e}")
            return False
        finally:
            browser.close()
