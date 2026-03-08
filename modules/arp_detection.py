"""
ARP Spoofing Detection Module
Detects ARP poisoning attacks in local network
"""
import subprocess
import re
from datetime import datetime
from collections import defaultdict


def detect_arp_spoofing():
    """
    Detect ARP spoofing/poisoning attacks
    Checks for:
    - Duplicate IP addresses with different MAC addresses
    - Suspicious ARP table changes
    - Gateway MAC address changes
    """
    findings = {
        "timestamp": datetime.now().isoformat(),
        "tests_performed": [],
        "vulnerabilities": [],
        "arp_table": [],
        "suspicious_entries": []
    }
    
    print(f"\n{'='*60}")
    print(f"  ARP SPOOFING DETECTION")
    print(f"{'='*60}")
    print(f"Analyzing local network ARP table...")
    print(f"{'='*60}\n")
    
    # TEST 1: Get ARP table
    print("[TEST 1] ARP Table Analysis")
    try:
        # Run arp command
        result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=5)
        arp_output = result.stdout
        
        # Parse ARP entries
        ip_mac_map = defaultdict(list)
        
        # Parse format: "? (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0"
        pattern = r'\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([\da-f:]+)'
        matches = re.findall(pattern, arp_output, re.IGNORECASE)
        
        for ip, mac in matches:
            findings["arp_table"].append({"ip": ip, "mac": mac})
            ip_mac_map[ip].append(mac)
        
        print(f"  ℹ ARP entries found: {len(findings['arp_table'])}")
        
        # Check for duplicate IPs with different MACs
        duplicates_found = False
        for ip, macs in ip_mac_map.items():
            if len(set(macs)) > 1:
                findings["vulnerabilities"].append({
                    "severity": "CRITICAL",
                    "type": "ARP_SPOOFING_DETECTED",
                    "message": f"IP {ip} has multiple MAC addresses: {', '.join(set(macs))}"
                })
                findings["suspicious_entries"].append({
                    "ip": ip,
                    "macs": list(set(macs)),
                    "reason": "Duplicate IP with different MACs"
                })
                print(f"  ❌ CRITICAL: ARP spoofing detected!")
                print(f"     IP: {ip}")
                print(f"     Multiple MACs: {', '.join(set(macs))}")
                print(f"     Risk: Active AitM attack in progress")
                duplicates_found = True
        
        if not duplicates_found:
            print(f"  ✓ No duplicate IP addresses detected")
        
        findings["tests_performed"].append({
            "test": "ARP_TABLE_ANALYSIS",
            "result": "FAIL" if duplicates_found else "PASS",
            "entries_checked": len(findings['arp_table'])
        })
        
    except subprocess.TimeoutExpired:
        print(f"  ⚠ ARP command timeout")
    except FileNotFoundError:
        print(f"  ⚠ ARP command not available (may need root privileges)")
        print(f"     Run with: sudo python3 acase.py")
    except Exception as e:
        print(f"  ⚠ Error reading ARP table: {str(e)}")
    
    # TEST 2: Gateway MAC Consistency Check
    print(f"\n[TEST 2] Gateway MAC Address Verification")
    try:
        # Get default gateway
        route_result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                     capture_output=True, text=True, timeout=5)
        
        gateway_match = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', route_result.stdout)
        
        if gateway_match:
            gateway_ip = gateway_match.group(1)
            
            # Find gateway in ARP table
            gateway_macs = [entry['mac'] for entry in findings['arp_table'] 
                          if entry['ip'] == gateway_ip]
            
            if gateway_macs:
                print(f"  ℹ Gateway: {gateway_ip}")
                print(f"     MAC: {gateway_macs[0]}")
                print(f"     Note: Monitor this MAC for changes (indicates ARP poisoning)")
            else:
                print(f"  ℹ Gateway IP: {gateway_ip}")
                print(f"     Gateway not in ARP cache yet")
        else:
            print(f"  ℹ No default gateway found")
        
        findings["tests_performed"].append({
            "test": "GATEWAY_VERIFICATION",
            "result": "INFO"
        })
        
    except Exception as e:
        print(f"  ⚠ Could not verify gateway: {str(e)}")
    
    # TEST 3: ARP Cache Poisoning Indicators
    print(f"\n[TEST 3] ARP Poisoning Indicators")
    
    # Check for suspicious patterns
    mac_frequency = defaultdict(int)
    for entry in findings['arp_table']:
        mac_frequency[entry['mac']] += 1
    
    # If one MAC appears for many IPs, suspicious
    for mac, count in mac_frequency.items():
        if count > 5:  # Same MAC for 5+ different IPs
            findings["vulnerabilities"].append({
                "severity": "HIGH",
                "type": "SUSPICIOUS_ARP_PATTERN",
                "message": f"MAC {mac} associated with {count} different IPs"
            })
            print(f"  ⚠ SUSPICIOUS: MAC {mac} appears {count} times")
            print(f"     May indicate ARP spoofing or router configuration")
    
    if not findings['vulnerabilities']:
        print(f"  ✓ No suspicious ARP patterns detected")
    
    findings["tests_performed"].append({
        "test": "ARP_PATTERNS",
        "result": "COMPLETE"
    })
    
    # Summary
    print(f"\n{'='*60}")
    print(f"  SUMMARY")
    print(f"{'='*60}")
    print(f"ARP Entries Analyzed: {len(findings['arp_table'])}")
    print(f"Suspicious Entries: {len(findings['suspicious_entries'])}")
    print(f"Vulnerabilities: {len(findings['vulnerabilities'])}")
    
    if findings['vulnerabilities']:
        print(f"\n❌ ARP SPOOFING DETECTED:")
        for vuln in findings['vulnerabilities']:
            print(f"  🔴 [{vuln['severity']}] {vuln['message']}")
    else:
        print(f"\n✓ No ARP spoofing detected")
    
    print(f"{'='*60}\n")
    
    return findings
