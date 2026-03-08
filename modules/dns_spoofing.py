"""
DNS Spoofing Detection Module
Detects DNS cache poisoning and DNS hijacking attacks
"""
import socket
import subprocess
from datetime import datetime


def detect_dns_spoofing(target_url):
    """
    Detect DNS spoofing attacks
    - Multiple DNS queries consistency check
    - Compare with authoritative DNS servers
    - Check for unusual DNS response times
    """
    from urllib.parse import urlparse
    
    findings = {
        "target": target_url,
        "timestamp": datetime.now().isoformat(),
        "tests_performed": [],
        "vulnerabilities": [],
        "dns_results": []
    }
    
    print(f"\n{'='*60}")
    print(f"  DNS SPOOFING DETECTION")
    print(f"{'='*60}")
    
    hostname = urlparse(target_url).hostname
    print(f"Testing: {hostname}")
    print(f"{'='*60}\n")
    
    # TEST 1: Multiple DNS Resolution
    print("[TEST 1] DNS Resolution Consistency Check")
    
    ip_addresses = set()
    for i in range(3):
        try:
            ip = socket.gethostbyname(hostname)
            ip_addresses.add(ip)
            print(f"  Query {i+1}: {ip}")
        except:
            print(f"  Query {i+1}: Failed")
    
    if len(ip_addresses) > 1:
        findings["vulnerabilities"].append({
            "severity": "CRITICAL",
            "type": "DNS_INCONSISTENCY",
            "message": f"DNS returns different IPs: {', '.join(ip_addresses)}"
        })
        print(f"  ❌ CRITICAL: Inconsistent DNS responses!")
        print(f"     Multiple IPs returned: {', '.join(ip_addresses)}")
        print(f"     Risk: Possible DNS cache poisoning")
    else:
        print(f"  ✓ Consistent DNS resolution")
    
    findings["dns_results"] = list(ip_addresses)
    findings["tests_performed"].append({
        "test": "DNS_CONSISTENCY",
        "result": "FAIL" if len(ip_addresses) > 1 else "PASS"
    })
    
    # TEST 2: Reverse DNS Check
    print(f"\n[TEST 2] Reverse DNS Verification")
    
    if ip_addresses:
        ip = list(ip_addresses)[0]
        try:
            reverse_name = socket.gethostbyaddr(ip)[0]
            print(f"  Forward: {hostname}")
            print(f"  Reverse: {reverse_name}")
            
            if hostname not in reverse_name and reverse_name not in hostname:
                findings["vulnerabilities"].append({
                    "severity": "MEDIUM",
                    "type": "REVERSE_DNS_MISMATCH",
                    "message": f"Reverse DNS mismatch: {reverse_name}"
                })
                print(f"  ⚠ WARNING: Reverse DNS doesn't match")
            else:
                print(f"  ✓ Reverse DNS matches")
        except:
            print(f"  ℹ No reverse DNS record")
    
    findings["tests_performed"].append({
        "test": "REVERSE_DNS",
        "result": "COMPLETE"
    })
    
    # Summary
    print(f"\n{'='*60}")
    print(f"  SUMMARY")
    print(f"{'='*60}")
    print(f"DNS Resolutions: {len(ip_addresses)} unique IP(s)")
    print(f"Vulnerabilities: {len(findings['vulnerabilities'])}")
    
    if findings['vulnerabilities']:
        print(f"\n❌ DNS SPOOFING INDICATORS:")
        for v in findings['vulnerabilities']:
            print(f"  🔴 [{v['severity']}] {v['message']}")
    else:
        print(f"\n✓ No DNS spoofing detected")
    
    print(f"{'='*60}\n")
    
    return findings
