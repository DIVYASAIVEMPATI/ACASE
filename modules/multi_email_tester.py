"""
Multi Email Tester - Test multiple emails in one scan
"""
from modules.email_validator import test_email_enumeration, generate_email_report


def test_multiple_emails(target, email_list, delay_ms=1500):
    """
    Test multiple emails and return combined results
    
    Args:
        target: Target URL
        email_list: List of email addresses to test
        delay_ms: Delay between requests
        
    Returns:
        Dict with results for each email
    """
    all_results = {}
    
    print(f"\n{'='*70}")
    print(f"  TESTING {len(email_list)} EMAIL ADDRESSES")
    print(f"{'='*70}\n")
    
    for i, email in enumerate(email_list, 1):
        print(f"[{i}/{len(email_list)}] Testing: {email}")
        result = test_email_enumeration(target, email, delay_ms)
        all_results[email] = result
        print()
    
    return all_results


def generate_multi_email_report(results):
    """Generate combined report for multiple emails"""
    report = f"""
{'='*70}
MULTI-EMAIL SECURITY ASSESSMENT REPORT
{'='*70}

TOTAL EMAILS TESTED: {len(results)}

"""
    
    for email, findings in results.items():
        report += f"\n{'─'*70}\n"
        report += f"EMAIL: {email}\n"
        report += f"Format Valid: {'YES ✓' if findings['is_valid_format'] else 'NO ✗'}\n"
        report += f"Authorized: {'YES ✓' if findings['is_authorized_domain'] else 'NO ✗'}\n"
        report += f"Tests Performed: {len(findings['tests_performed'])}\n"
        report += f"Vulnerabilities: {len(findings['vulnerabilities'])}\n"
        
        if findings['vulnerabilities']:
            report += f"\nVULNERABILITIES:\n"
            for vuln in findings['vulnerabilities']:
                report += f"  [!] {vuln}\n"
        else:
            report += f"  [✓] No vulnerabilities\n"
    
    report += f"\n{'='*70}\n"
    report += f"\nSUMMARY:\n"
    
    total_vulns = sum(len(r['vulnerabilities']) for r in results.values())
    report += f"Total Vulnerabilities Found: {total_vulns}\n"
    
    vulnerable_emails = [e for e, r in results.items() if r['vulnerabilities']]
    if vulnerable_emails:
        report += f"\nVulnerable Emails:\n"
        for email in vulnerable_emails:
            report += f"  - {email}\n"
    
    report += f"\n{'='*70}\n"
    
    return report
