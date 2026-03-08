"""
Enhanced Report Generator - HTML reports with embedded charts
Professional security assessment reports
"""
import json
from datetime import datetime
from pathlib import Path


def generate_html_report(target, findings, attack_path, ai_impact, risk_score=72):
    """
    Generate professional HTML report with charts and styling
    
    Args:
        target: Target URL
        findings: Dict of findings from modules
        attack_path: List of actions taken
        ai_impact: AI-generated business impact text
        risk_score: Overall risk score 0-100
        
    Returns:
        HTML string
    """
    
    # Calculate finding counts
    vuln_count = 0
    for action, result in findings.items():
        if result and isinstance(result, dict):
            if result.get("enumeration_possible") or result.get("email_enumeration"):
                vuln_count += 1
    
    # Build findings list
    findings_html = ""
    if vuln_count == 0:
        findings_html = "<tr><td colspan='4' style='text-align:center;color:#00ff9d;'>No critical vulnerabilities detected</td></tr>"
    else:
        for action, result in findings.items():
            if result and isinstance(result, dict):
                if result.get("enumeration_possible"):
                    findings_html += f"""
                    <tr>
                        <td>Username Enumeration</td>
                        <td>{action}</td>
                        <td><span class="badge high">HIGH</span></td>
                        <td>Error messages reveal valid usernames</td>
                    </tr>
                    """
                if result.get("email_enumeration"):
                    findings_html += f"""
                    <tr>
                        <td>Email Enumeration</td>
                        <td>{action}</td>
                        <td><span class="badge high">HIGH</span></td>
                        <td>Reset flow reveals registered emails</td>
                    </tr>
                    """
    
    # Build attack path HTML
    path_html = ""
    for i, action in enumerate(attack_path):
        arrow = " → " if i < len(attack_path) - 1 else ""
        path_html += f"<span class='path-step'>{action}</span>{arrow}"
    
    # Determine risk level text
    if risk_score >= 70:
        risk_level = "HIGH RISK"
        risk_color = "#ff3e6c"
    elif risk_score >= 40:
        risk_level = "MEDIUM RISK"
        risk_color = "#ffb700"
    else:
        risk_level = "LOW RISK"
        risk_color = "#00ff9d"
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    
    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ACASE Security Report - {target}</title>
    <link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap" rel="stylesheet">
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            background: #020b12;
            color: #c8e6f5;
            font-family: 'Rajdhani', sans-serif;
            padding: 40px;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: #061420;
            border: 1px solid #0e3a55;
            padding: 40px;
        }}
        h1 {{
            font-family: 'Share Tech Mono', monospace;
            color: #00d4ff;
            font-size: 32px;
            margin-bottom: 10px;
            letter-spacing: 3px;
        }}
        h2 {{
            color: #00d4ff;
            font-size: 20px;
            margin-top: 30px;
            margin-bottom: 15px;
            border-bottom: 2px solid #0e3a55;
            padding-bottom: 8px;
            letter-spacing: 2px;
        }}
        .header {{
            border-bottom: 3px solid #00d4ff;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .meta {{
            font-family: 'Share Tech Mono', monospace;
            font-size: 13px;
            color: #4a7a99;
            margin-top: 10px;
        }}
        .risk-score {{
            background: #0a1e2e;
            border-left: 4px solid {risk_color};
            padding: 20px;
            margin: 20px 0;
        }}
        .risk-number {{
            font-size: 48px;
            color: {risk_color};
            font-weight: 700;
        }}
        .risk-label {{
            color: #4a7a99;
            font-size: 14px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            font-size: 14px;
        }}
        th {{
            background: #0a1e2e;
            color: #00d4ff;
            padding: 12px;
            text-align: left;
            font-family: 'Share Tech Mono', monospace;
            font-size: 12px;
            letter-spacing: 1px;
        }}
        td {{
            padding: 12px;
            border-bottom: 1px solid #0e3a55;
        }}
        tr:hover {{
            background: #0a1e2e;
        }}
        .badge {{
            padding: 4px 12px;
            font-size: 11px;
            font-family: 'Share Tech Mono', monospace;
            border-radius: 3px;
            display: inline-block;
        }}
        .badge.high {{
            background: rgba(255, 62, 108, 0.2);
            color: #ff3e6c;
            border: 1px solid #ff3e6c;
        }}
        .badge.medium {{
            background: rgba(255, 183, 0, 0.2);
            color: #ffb700;
            border: 1px solid #ffb700;
        }}
        .badge.low {{
            background: rgba(0, 212, 255, 0.2);
            color: #00d4ff;
            border: 1px solid #00d4ff;
        }}
        .impact-box {{
            background: #0a1e2e;
            border-left: 4px solid #ff3e6c;
            padding: 20px;
            margin: 20px 0;
            font-size: 15px;
            line-height: 1.8;
        }}
        .impact-label {{
            color: #ff3e6c;
            font-family: 'Share Tech Mono', monospace;
            font-size: 11px;
            letter-spacing: 2px;
            margin-bottom: 10px;
        }}
        .path-step {{
            display: inline-block;
            background: #0a1e2e;
            padding: 6px 14px;
            margin: 4px;
            border: 1px solid #0e3a55;
            font-family: 'Share Tech Mono', monospace;
            font-size: 12px;
            color: #00d4ff;
        }}
        .recommendations {{
            background: #0a1e2e;
            padding: 20px;
            margin: 20px 0;
        }}
        .rec-item {{
            padding: 10px 0;
            border-bottom: 1px solid #0e3a55;
        }}
        .rec-item:last-child {{
            border-bottom: none;
        }}
        .footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #0e3a55;
            font-family: 'Share Tech Mono', monospace;
            font-size: 11px;
            color: #4a7a99;
            text-align: center;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>ACASE SECURITY ASSESSMENT REPORT</h1>
            <div class="meta">
                <div>TARGET: {target}</div>
                <div>GENERATED: {timestamp}</div>
                <div>ENGINE: MISTRAL AI + RULE-BASED ANALYSIS</div>
            </div>
        </div>

        <div class="risk-score">
            <div class="risk-label">OVERALL RISK SCORE</div>
            <div class="risk-number">{risk_score}/100</div>
            <div class="risk-label">{risk_level}</div>
        </div>

        <h2>EXECUTIVE SUMMARY</h2>
        <p>Automated authentication security assessment completed on {target}. 
        The assessment identified {vuln_count} vulnerabilities requiring immediate attention. 
        Testing was performed using AI-guided methodology with {len(attack_path)} assessment steps.</p>

        <h2>DETAILED FINDINGS</h2>
        <table>
            <thead>
                <tr>
                    <th>FINDING</th>
                    <th>MODULE</th>
                    <th>RISK LEVEL</th>
                    <th>DESCRIPTION</th>
                </tr>
            </thead>
            <tbody>
                {findings_html}
            </tbody>
        </table>

        <h2>ATTACK PATH ANALYSIS</h2>
        <p style="margin-bottom: 15px;">The following assessment flow was executed:</p>
        <div style="padding: 20px; background: #0a1e2e;">
            {path_html}
        </div>

        <h2>AI-GENERATED BUSINESS IMPACT</h2>
        <div class="impact-box">
            <div class="impact-label">MISTRAL AI // BUSINESS RISK ANALYSIS</div>
            <div>{ai_impact}</div>
        </div>

        <h2>REMEDIATION RECOMMENDATIONS</h2>
        <div class="recommendations">
            <div class="rec-item">
                <strong>1.</strong> Implement generic error messages for all authentication failures
            </div>
            <div class="rec-item">
                <strong>2.</strong> Enforce multi-factor authentication (MFA) for all user accounts
            </div>
            <div class="rec-item">
                <strong>3.</strong> Use cryptographically random tokens for password reset (min 32 bytes)
            </div>
            <div class="rec-item">
                <strong>4.</strong> Set Secure, HttpOnly, and SameSite=Strict flags on all session cookies
            </div>
            <div class="rec-item">
                <strong>5.</strong> Implement rate limiting and CAPTCHA after repeated auth failures
            </div>
        </div>

        <div class="footer">
            ACASE - AUTHENTICATION SECURITY ASSESSMENT CLI ENGINE<br>
            AUTHORIZED LAB TESTING ONLY // MISTRAL AI-POWERED ANALYSIS
        </div>
    </div>
</body>
</html>
    """
    
    return html


def save_html_report(target, findings, attack_path, ai_impact, risk_score=72):
    """Save HTML report to file"""
    html = generate_html_report(target, findings, attack_path, ai_impact, risk_score)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    filename = f"reports/acase_report_{timestamp}.html"
    
    Path("reports").mkdir(exist_ok=True)
    
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)
    
    print(f"[+] HTML report saved: {filename}")
    return filename
