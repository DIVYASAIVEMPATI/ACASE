from datetime import datetime

def generate_report(target, findings, attack_path, ai_impact):
    lines = []
    lines.append("=" * 60)
    lines.append("  ACASE SECURITY ASSESSMENT REPORT")
    lines.append("=" * 60)
    lines.append(f"  Target : {target}")
    lines.append(f"  Date   : {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    lines.append("=" * 60)
    lines.append("\n[FINDINGS]\n")
    has_findings = False
    for action, result in findings.items():
        if not result:
            continue
        issues = result.get("issues", []) + result.get("evidence", [])
        if result.get("enumeration_possible"):
            issues.append("Username enumeration confirmed.")
        if result.get("email_enumeration_possible"):
            issues.append("Email enumeration via reset endpoint.")
        if result.get("token_looks_weak"):
            issues.append("Reset token appears weak or predictable.")
        for issue in issues:
            has_findings = True
            lines.append(f"  [!] {issue}")
    if not has_findings:
        lines.append("  [+] No significant issues detected.")
    if attack_path:
        lines.append("\n[ATTACK PATH]\n")
        for i, step in enumerate(attack_path):
            connector = "\n  |\n  v" if i < len(attack_path) - 1 else ""
            lines.append(f"  {step}{connector}")
    if ai_impact:
        lines.append("\n[BUSINESS IMPACT]\n")
        for line in ai_impact.split("\n"):
            lines.append(f"  {line}")
    lines.append("\n[RECOMMENDATIONS]\n")
    lines.append("  1. Use generic error messages for all auth failures.")
    lines.append("  2. Use cryptographically random reset tokens (min 32 bytes).")
    lines.append("  3. Set Secure, HttpOnly, SameSite=Strict on all cookies.")
    lines.append("  4. Implement lockout or CAPTCHA after repeated failures.")
    lines.append("  5. Enforce MFA for all sensitive accounts.")
    lines.append("\n" + "=" * 60)
    return "\n".join(lines)

def save_report(target, report_text):
    import os
    os.makedirs("reports", exist_ok=True)
    filename = f"reports/acase_report_{datetime.now().strftime('%Y%m%d_%H%M')}.txt"
    with open(filename, "w") as f:
        f.write(report_text)
    print(f"\n[+] Report saved: {filename}")
    return filename
