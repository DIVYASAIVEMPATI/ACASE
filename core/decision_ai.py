import json
import requests
from pathlib import Path

OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
VALID_ACTIONS = {"ENUM_USER","TEST_RESET","TEST_SESSION","TEST_MFA","CONTROLLED_SPRAY","STOP"}

def decide(observation, history):
    prompt = f"""You are an authentication security analyst.
Goal: Find auth vulnerabilities using safe minimal tests.
Rules:
1. Prefer logic flaws over password guessing
2. Never repeat same action twice
3. Stop when takeover path is proven

Observation:
{json.dumps(observation, indent=2)}

Actions taken so far: {history if history else 'None'}

Possible actions: ENUM_USER, TEST_RESET, TEST_SESSION, TEST_MFA, CONTROLLED_SPRAY, STOP
Return ONLY the action name.
"""
    try:
        response = requests.post(
            OLLAMA_URL,
            json={"model": "mistral", "prompt": prompt, "stream": False},
            timeout=120,
        )
        response.raise_for_status()
        raw = response.json().get("response", "").strip().upper()
        for action in VALID_ACTIONS:
            if action in raw:
                return action
        print(f"[!] AI returned unknown action - using fallback.")
    except Exception as e:
        print(f"[!] Ollama not reachable ({e}) - using rule-based fallback.")
    return _fallback(observation, history)

def _fallback(observation, history):
    if "TEST_SESSION" not in history:
        return "TEST_SESSION"
    if "ENUM_USER" not in history and observation.get("login_detected"):
        return "ENUM_USER"
    if "TEST_RESET" not in history and observation.get("reset_flow"):
        return "TEST_RESET"
    if "TEST_MFA" not in history:
        return "TEST_MFA"
    return "STOP"

def explain_impact(attack_path):
    prompt = f"""Explain business impact of this auth vulnerability path in under 80 words:
Path: {' -> '.join(attack_path)}
Consider: customer data, account takeover, financial risk."""
    try:
        r = requests.post(OLLAMA_URL, json={"model":"mistral","prompt":prompt,"stream":False}, timeout=30)
        return r.json().get("response","").strip()
    except Exception:
        return "AI impact summary unavailable - Ollama not running."
