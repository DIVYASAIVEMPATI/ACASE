"""
Enhanced AI Decision Engine - Better prompts and reasoning
Improved version with more sophisticated AI guidance
"""
import json
import requests


OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
MODEL = "mistral"
TIMEOUT = 120


ENHANCED_SYSTEM_PROMPT = """You are an expert penetration tester specializing in authentication security.

Your role is to analyze authentication systems and decide the next best test to perform.
You must be strategic, methodical, and avoid repeating ineffective actions.

AVAILABLE ACTIONS:
1. TEST_SESSION - Analyze session cookies and tokens for security issues
2. ENUM_USER - Test if username enumeration is possible via error messages
3. TEST_RESET - Probe password reset flow for vulnerabilities
4. TEST_MFA - Check if multi-factor authentication is present
5. CONTROLLED_SPRAY - Carefully test credential combinations (use sparingly)
6. STOP - End the assessment when sufficient data is collected

DECISION STRATEGY:
- Start with passive reconnaissance (TEST_SESSION)
- Move to detection tests (ENUM_USER, TEST_RESET, TEST_MFA)
- Only use active tests (CONTROLLED_SPRAY) if justified
- Stop when you have enough evidence or hit 10 actions
- Never repeat the same action more than twice
- Consider policy constraints and safety

Respond ONLY with a JSON object containing:
{
  "action": "ACTION_NAME",
  "reasoning": "Why you chose this action",
  "expected_outcome": "What you expect to find",
  "risk_level": "LOW|MEDIUM|HIGH"
}
"""


def decide_enhanced(observation, history):
    """
    Enhanced AI decision with better prompting and context
    
    Args:
        observation: Current state of the assessment
        history: List of previous actions taken
        
    Returns:
        dict with action and reasoning, or None if AI fails
    """
    
    # Build context for AI
    context = f"""
CURRENT OBSERVATION:
{json.dumps(observation, indent=2)}

ACTIONS TAKEN SO FAR:
{json.dumps(history, indent=2)}

ANALYSIS NEEDED:
Based on the current findings and previous actions, what should be the next test?
Consider:
- What vulnerabilities have we found so far?
- What gaps remain in our assessment?
- Are we repeating ourselves?
- Is it time to stop?

Remember: You can only choose from the available actions.
Respond with valid JSON only.
"""
    
    prompt = ENHANCED_SYSTEM_PROMPT + "\n\n" + context
    
    try:
        response = requests.post(
            OLLAMA_URL,
            json={
                "model": MODEL,
                "prompt": prompt,
                "stream": False,
                "temperature": 0.3,  # Lower temperature for more consistent decisions
                "top_p": 0.9
            },
            timeout=TIMEOUT
        )
        
        if response.status_code == 200:
            data = response.json()
            ai_text = data.get("response", "")
            
            # Extract JSON from response
            ai_text = ai_text.strip()
            if "```json" in ai_text:
                ai_text = ai_text.split("```json")[1].split("```")[0].strip()
            elif "```" in ai_text:
                ai_text = ai_text.split("```")[1].split("```")[0].strip()
            
            decision = json.loads(ai_text)
            
            # Validate decision
            valid_actions = ["TEST_SESSION", "ENUM_USER", "TEST_RESET", "TEST_MFA", "CONTROLLED_SPRAY", "STOP"]
            if decision.get("action") in valid_actions:
                return decision
            else:
                print(f"[!] AI returned invalid action: {decision.get('action')}")
                return None
                
        else:
            print(f"[!] AI API error: {response.status_code}")
            return None
            
    except requests.exceptions.RequestException as e:
        print(f"[!] AI connection error: {e}")
        return None
    except json.JSONDecodeError as e:
        print(f"[!] AI response not valid JSON: {e}")
        return None
    except Exception as e:
        print(f"[!] Unexpected AI error: {e}")
        return None


def explain_impact_enhanced(findings, attack_path):
    """
    Enhanced business impact explanation with better context
    
    Args:
        findings: Dictionary of findings from assessment
        attack_path: List of actions taken
        
    Returns:
        String with business impact analysis
    """
    
    findings_summary = []
    for action, result in findings.items():
        if result:
            findings_summary.append(f"- {action}: {str(result)[:100]}")
    
    prompt = f"""You are a security consultant explaining technical findings to business executives.

TECHNICAL FINDINGS:
{chr(10).join(findings_summary)}

ATTACK PATH:
{' → '.join(attack_path)}

TASK:
Write a concise business impact statement (3-4 sentences) that explains:
1. What vulnerabilities were found in plain business terms
2. What could an attacker do with these vulnerabilities
3. What is the business risk (data breach, financial loss, reputation damage)
4. How urgent is remediation

Write in professional but accessible language. No technical jargon.
Focus on business impact, not technical details.
"""
    
    try:
        response = requests.post(
            OLLAMA_URL,
            json={
                "model": MODEL,
                "prompt": prompt,
                "stream": False,
                "temperature": 0.5
            },
            timeout=TIMEOUT
        )
        
        if response.status_code == 200:
            data = response.json()
            return data.get("response", "AI impact summary unavailable.").strip()
        else:
            return "AI impact summary unavailable - API error."
            
    except Exception as e:
        return f"AI impact summary unavailable - {str(e)}"


def get_remediation_advice(finding_type):
    """
    Get specific remediation advice for a finding type
    
    Args:
        finding_type: Type of vulnerability found
        
    Returns:
        String with remediation guidance
    """
    
    remediation_map = {
        "username_enum": "Implement generic error messages that don't reveal whether a username exists. Use the same response time for valid and invalid usernames.",
        
        "email_enum": "Return the same success message whether the email exists or not. Send password reset emails only to registered addresses without confirming existence.",
        
        "weak_session": "Use cryptographically random session tokens (minimum 32 bytes). Set Secure, HttpOnly, and SameSite=Strict flags on all cookies.",
        
        "no_mfa": "Implement multi-factor authentication for all accounts. Support TOTP, hardware keys (WebAuthn), or SMS as a fallback.",
        
        "csrf_vulnerable": "Implement CSRF tokens on all state-changing requests. Use the Synchronizer Token Pattern or Double Submit Cookie pattern.",
        
        "weak_reset_token": "Generate cryptographically random password reset tokens (minimum 32 bytes). Set short expiration times (15-30 minutes).",
        
        "rate_limit_missing": "Implement rate limiting on authentication endpoints. Add exponential backoff and temporary account locks after repeated failures."
    }
    
    return remediation_map.get(finding_type, "Consult security best practices for this vulnerability type.")


# Backward compatibility with original function names
def decide(observation, history):
    """Wrapper for backward compatibility"""
    result = decide_enhanced(observation, history)
    if result:
        return result.get("action")
    return None


def explain_impact(findings, attack_path):
    """Wrapper for backward compatibility"""
    return explain_impact_enhanced(findings, attack_path)
