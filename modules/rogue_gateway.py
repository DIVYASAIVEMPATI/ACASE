import subprocess
import re
from datetime import datetime
import time


def detect_rogue_gateway():
    findings = {
        "gateway_info": {},
        "vulnerabilities": [],
        "alerts": [],
        "tests_performed": []
    }

    print("[TEST 1] Gateway Identification")

    try:
        route_result = subprocess.run(
            ['ip', 'route', 'show', 'default'],
            capture_output=True, text=True, timeout=5
        )

        gateway_match = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', route_result.stdout)

        if not gateway_match:
            print("  ⚠ No default gateway found")
            return findings

        gateway_ip = gateway_match.group(1)
        findings["gateway_info"]["ip"] = gateway_ip
        print(f"  ℹ Gateway IP: {gateway_ip}")

        neigh_result = subprocess.run(
            ['ip', 'neigh', 'show', gateway_ip],
            capture_output=True, text=True, timeout=5
        )

        mac_match = re.search(r'([0-9a-fA-F:]{17})', neigh_result.stdout)

        if mac_match:
            gateway_mac = mac_match.group(1)
            findings["gateway_info"]["mac"] = gateway_mac
            print(f"  ℹ Gateway MAC: {gateway_mac}")

            findings["alerts"].append({
                "type": "INFO",
                "message": f"Gateway detected: {gateway_ip} ({gateway_mac})",
                "timestamp": datetime.now().isoformat()
            })
        else:
            print("  ⚠ Could not determine gateway MAC")
            return findings

        findings["tests_performed"].append({
            "test": "GATEWAY_IDENTIFICATION",
            "result": "COMPLETE"
        })

    except Exception as e:
        print(f"  ⚠ Error: {str(e)}")
        return findings

    print("\n[TEST 2] Gateway Stability Monitoring")

    try:
        mac_samples = []

        for _ in range(3):
            neigh_result = subprocess.run(
                ['ip', 'neigh', 'show', gateway_ip],
                capture_output=True, text=True, timeout=5
            )

            mac_match = re.search(r'([0-9a-fA-F:]{17})', neigh_result.stdout)
            if mac_match:
                mac_samples.append(mac_match.group(1))

            time.sleep(1)

        unique_macs = set(mac_samples)

        if len(unique_macs) > 1:
            findings["vulnerabilities"].append({
                "severity": "CRITICAL",
                "type": "GATEWAY_MAC_CHANGE",
                "message": f"Gateway MAC changed: {', '.join(unique_macs)}"
            })
            print("  ❌ CRITICAL: Gateway MAC is changing!")
        else:
            print("  ✓ Gateway MAC stable")

        findings["tests_performed"].append({
            "test": "GATEWAY_STABILITY",
            "result": "FAIL" if len(unique_macs) > 1 else "PASS"
        })

    except Exception as e:
        print(f"  ⚠ Error: {str(e)}")

    print("\n[TEST 3] Routing Table Integrity")

    try:
        route_result = subprocess.run(
            ['ip', 'route'],
            capture_output=True, text=True, timeout=5
        )

        routes = route_result.stdout.strip().split('\n')
        default_routes = [r for r in routes if r.startswith('default')]

        if len(default_routes) > 1:
            findings["vulnerabilities"].append({
                "severity": "HIGH",
                "type": "MULTIPLE_DEFAULT_ROUTES",
                "message": f"Multiple default routes detected ({len(default_routes)})"
            })
            print("  ⚠ WARNING: Multiple default routes")
        else:
            print("  ✓ Single default route")

        findings["tests_performed"].append({
            "test": "ROUTING_TABLE",
            "result": "COMPLETE"
        })

    except Exception as e:
        print(f"  ⚠ Error: {str(e)}")

    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    print(f"Gateway IP: {findings['gateway_info'].get('ip', 'Unknown')}")
    print(f"Gateway MAC: {findings['gateway_info'].get('mac', 'Unknown')}")
    print(f"Vulnerabilities: {len(findings['vulnerabilities'])}")
    print(f"Alerts: {len(findings['alerts'])}")

    if findings['vulnerabilities']:
        print("\n❌ ROGUE GATEWAY DETECTED:")
        for v in findings['vulnerabilities']:
            print(f"  🔴 [{v['severity']}] {v['message']}")
    else:
        print("\n✓ No rogue gateway detected")

    print("="*60 + "\n")

    return findings


if __name__ == "__main__":
    check_rogue_gateway()
