"""
LLM-based Security Analysis using Ollama/Mistral
"""
import requests
import json

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "mistral"

def analyze_with_llm(scan_data):
    """Analyze scan results with structured output"""
    
    prompt = f"""You are a cybersecurity expert. Analyze this security scan and provide EXACTLY 4 sections:

Target: {scan_data.get('target')}
Risk Score: {scan_data.get('risk_score')}/100
Total Vulnerabilities: {scan_data.get('total_vulnerabilities')}

Format your response as:

EXECUTIVE SUMMARY:
[2-3 sentences for management]

TECHNICAL SUMMARY:
[Key findings for security team]

CRITICAL ISSUES:
[Top 3 issues numbered]

REMEDIATION PRIORITY:
[Top 3 actions numbered]"""

    try:
        print("[*] Analyzing with Mistral LLM...")
        response = requests.post(
            OLLAMA_URL,
            json={
                "model": MODEL,
                "prompt": prompt,
                "stream": False
            },
            timeout=60
        )
        
        if response.status_code == 200:
            result = response.json().get("response", "")
            print("[+] LLM analysis complete")
            
            # Parse structured output
            sections = {
                "executive_summary": "",
                "technical_summary": "",
                "critical_issues": "",
                "remediation_priority": ""
            }
            
            current_section = None
            for line in result.split('\n'):
                if "EXECUTIVE SUMMARY:" in line:
                    current_section = "executive_summary"
                elif "TECHNICAL SUMMARY:" in line:
                    current_section = "technical_summary"
                elif "CRITICAL ISSUES:" in line:
                    current_section = "critical_issues"
                elif "REMEDIATION PRIORITY:" in line:
                    current_section = "remediation_priority"
                elif current_section and line.strip():
                    sections[current_section] += line + "\n"
            
            return sections
        else:
            return {"error": f"LLM service error: {response.status_code}"}
            
    except requests.exceptions.ConnectionError:
        return {"error": "Ollama not running. Start with: ollama serve"}
    except Exception as e:
        return {"error": f"LLM analysis failed: {str(e)}"}

def check_ollama_status():
    """Check if Ollama is running"""
    try:
        response = requests.get("http://localhost:11434/api/tags", timeout=5)
        return response.status_code == 200
    except:
        return False
