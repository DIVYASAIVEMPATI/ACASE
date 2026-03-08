"""
Traffic Interceptor - Captures HTTP traffic and extracts tokens
Uses mitmproxy to intercept requests/responses during testing
"""
import json
import re
from mitmproxy import http
from datetime import datetime


class TokenExtractor:
    """Extracts authentication tokens from HTTP traffic"""
    
    def __init__(self):
        self.captured_tokens = []
        self.session_cookies = {}
        self.auth_headers = []
        
    def request(self, flow: http.HTTPFlow):
        """Intercept outgoing requests"""
        if "Authorization" in flow.request.headers:
            auth = flow.request.headers["Authorization"]
            self.auth_headers.append({
                "url": flow.request.pretty_url,
                "method": flow.request.method,
                "auth_header": auth,
                "timestamp": datetime.now().isoformat()
            })
        if "Cookie" in flow.request.headers:
            cookies = flow.request.headers["Cookie"]
            self._parse_cookies(cookies, flow.request.pretty_url)
    
    def response(self, flow: http.HTTPFlow):
        """Intercept incoming responses"""
        if "Set-Cookie" in flow.response.headers:
            set_cookie = flow.response.headers["Set-Cookie"]
            self._parse_set_cookie(set_cookie, flow.request.pretty_url)
        try:
            body = flow.response.text
            tokens = self._extract_tokens_from_body(body)
            if tokens:
                for token in tokens:
                    self.captured_tokens.append({
                        "url": flow.request.pretty_url,
                        "token": token,
                        "source": "response_body",
                        "timestamp": datetime.now().isoformat()
                    })
        except:
            pass
    
    def _parse_cookies(self, cookie_string, url):
        pairs = cookie_string.split("; ")
        for pair in pairs:
            if "=" in pair:
                name, value = pair.split("=", 1)
                self.session_cookies[name] = {
                    "value": value,
                    "url": url,
                    "timestamp": datetime.now().isoformat()
                }
    
    def _parse_set_cookie(self, set_cookie, url):
        match = re.match(r'([^=]+)=([^;]+)', set_cookie)
        if match:
            name, value = match.groups()
            self.session_cookies[name] = {
                "value": value,
                "url": url,
                "secure": "Secure" in set_cookie,
                "httponly": "HttpOnly" in set_cookie,
                "samesite": self._extract_samesite(set_cookie),
                "timestamp": datetime.now().isoformat()
            }
    
    def _extract_samesite(self, set_cookie):
        match = re.search(r'SameSite=([^;]+)', set_cookie, re.IGNORECASE)
        return match.group(1) if match else "None"
    
    def _extract_tokens_from_body(self, body):
        tokens = []
        jwt_pattern = r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'
        tokens.extend(re.findall(jwt_pattern, body))
        try:
            data = json.loads(body)
            token_fields = ["token", "access_token", "auth_token", "session_token", "csrf_token"]
            for field in token_fields:
                if field in data:
                    tokens.append(data[field])
        except:
            pass
        return tokens
    
    def get_summary(self):
        return {
            "total_tokens": len(self.captured_tokens),
            "total_cookies": len(self.session_cookies),
            "total_auth_headers": len(self.auth_headers),
            "tokens": self.captured_tokens,
            "cookies": self.session_cookies,
            "auth_headers": self.auth_headers
        }
    
    def save_to_file(self, filepath):
        with open(filepath, "w") as f:
            json.dump(self.get_summary(), f, indent=2)


addons = [TokenExtractor()]


def analyze_captured_traffic(json_file):
    with open(json_file, 'r') as f:
        data = json.load(f)
    findings = []
    for name, cookie in data.get("cookies", {}).items():
        if not cookie.get("secure"):
            findings.append(f"Cookie '{name}' lacks Secure flag")
        if not cookie.get("httponly"):
            findings.append(f"Cookie '{name}' lacks HttpOnly flag")
        if cookie.get("samesite", "").lower() in ["none", ""]:
            findings.append(f"Cookie '{name}' has weak SameSite policy")
    for token_data in data.get("tokens", []):
        token = token_data.get("token", "")
        if token.startswith("eyJ"):
            parts = token.split(".")
            if len(parts) == 3:
                findings.append(f"JWT token found - verify signature algorithm")
    return findings
