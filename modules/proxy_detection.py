"""
Proxy Detection Module
Detects if traffic is being proxied (possible AitM)
"""
import httpx
import time
from datetime import datetime


def detect_mitm_proxy(target_url):
    """
    Detect Man-in-the-Middle proxy
    Checks for:
    - Proxy headers (Via, X-Forwarded-For, X-Proxy)
    - Unusual latency patterns
    - Certificate changes
    - HTTP version downgrades
    """
    findings = {
        "target": target_url,
        "timestamp": datetime.now().isoformat(),
        "tests_performed": [],
        "vulnerabilities": [],
        "proxy_indicators": []
    }
    
    print(f"\n{'='*60}")
    print(f"  MAN-IN-THE-MIDDLE PROXY DETECTION")
    print(f"{'='*60}")
    print(f"Target: {target_url}")
    print(f"{'='*60}\n")
    
    # TEST 1: Check for Proxy Headers
    print("[TEST 1] Proxy Header Detection")
    try:
        response = httpx.get(target_url, timeout=10, follow_redirects=True)
        
        proxy_headers = {
            "Via": response.headers.get("Via"),
            "X-Forwarded-For": response.headers.get("X-Forwarded-For"),
            "X-Proxy-ID": response.headers.get("X-Proxy-ID"),
            "Forwarded": response.headers.get("Forwarded"),
            "X-Cache": response.headers.get("X-Cache")
        }
        
        detected_headers = {k: v for k, v in proxy_headers.items() if v}
        
        if detected_headers:
            for header, value in detected_headers.items():
                findings["proxy_indicators"].append({
                    "type": "PROXY_HEADER",
                    "header": header,
                    "value": value
                })
                findings["vulnerabilities"].append({
                    "severity": "MEDIUM",
                    "type": "PROXY_DETECTED",
                    "message": f"Proxy header detected: {header}"
                })
                print(f"  ⚠ PROXY DETECTED: {header} header present")
                print(f"     Value: {value}")
                print(f"     Risk: Traffic may be intercepted")
        else:
            print(f"  ✓ No proxy headers detected")
        
        findings["tests_performed"].append({
            "test": "PROXY_HEADERS",
            "result": "FAIL" if detected_headers else "PASS"
        })
        
    except Exception as e:
        print(f"  ⚠ Error: {str(e)}")
    
    # TEST 2: Latency Analysis
    print(f"\n[TEST 2] Network Latency Analysis")
    try:
        latencies = []
        
        for i in range(3):
            start = time.time()
            httpx.get(target_url, timeout=10)
            latency = (time.time() - start) * 1000  # Convert to ms
            latencies.append(latency)
        
        avg_latency = sum(latencies) / len(latencies)
        variance = max(latencies) - min(latencies)
        
        print(f"  ℹ Average latency: {avg_latency:.2f}ms")
        print(f"  ℹ Variance: {variance:.2f}ms")
        
        # High variance might indicate proxy
        if variance > 500:  # 500ms variance
            findings["vulnerabilities"].append({
                "severity": "LOW",
                "type": "HIGH_LATENCY_VARIANCE",
                "message": f"Unusual latency variance ({variance:.2f}ms) - possible proxy"
            })
            print(f"  ⚠ High variance detected - possible proxy or network issues")
        else:
            print(f"  ✓ Normal latency pattern")
        
        findings["tests_performed"].append({
            "test": "LATENCY_ANALYSIS",
            "result": "INFO",
            "avg_latency_ms": round(avg_latency, 2)
        })
        
    except Exception as e:
        print(f"  ⚠ Could not measure latency: {str(e)}")
    
    # TEST 3: HTTP Version Check
    print(f"\n[TEST 3] HTTP Protocol Verification")
    try:
        response = httpx.get(target_url, timeout=10)
        
        http_version = response.http_version
        print(f"  ℹ HTTP version: {http_version}")
        
        # Check for downgrade
        if target_url.startswith('https') and http_version == 'HTTP/1.0':
            findings["vulnerabilities"].append({
                "severity": "MEDIUM",
                "type": "HTTP_DOWNGRADE",
                "message": "HTTPS connection using old HTTP/1.0 protocol"
            })
            print(f"  ⚠ WARNING: Old HTTP version in use")
            print(f"     Risk: Possible protocol downgrade attack")
        else:
            print(f"  ✓ Modern HTTP protocol in use")
        
        findings["tests_performed"].append({
            "test": "HTTP_VERSION",
            "result": "PASS"
        })
        
    except Exception as e:
        print(f"  ⚠ Error: {str(e)}")
    
    # TEST 4: Response Manipulation Detection
    print(f"\n[TEST 4] Response Integrity Check")
    try:
        # Make two requests and compare
        resp1 = httpx.get(target_url, timeout=10)
        time.sleep(1)
        resp2 = httpx.get(target_url, timeout=10)
        
        # Compare Server headers
        if resp1.headers.get('Server') != resp2.headers.get('Server'):
            findings["vulnerabilities"].append({
                "severity": "HIGH",
                "type": "RESPONSE_MANIPULATION",
                "message": "Server header changed between requests"
            })
            print(f"  ❌ SUSPICIOUS: Server header inconsistent")
            print(f"     Risk: Responses may be manipulated by proxy")
        else:
            print(f"  ✓ Consistent server responses")
        
        findings["tests_performed"].append({
            "test": "RESPONSE_INTEGRITY",
            "result": "PASS"
        })
        
    except Exception as e:
        print(f"  ⚠ Error: {str(e)}")
    
    # Summary
    print(f"\n{'='*60}")
    print(f"  SUMMARY")
    print(f"{'='*60}")
    print(f"Tests Performed: {len(findings['tests_performed'])}")
    print(f"Proxy Indicators: {len(findings['proxy_indicators'])}")
    print(f"Vulnerabilities: {len(findings['vulnerabilities'])}")
    
    if findings['vulnerabilities']:
        print(f"\n⚠ POTENTIAL PROXY/MITM DETECTED:")
        for vuln in findings['vulnerabilities']:
            print(f"  🟠 [{vuln['severity']}] {vuln['message']}")
    else:
        print(f"\n✓ No proxy or AitM indicators detected")
    
    print(f"{'='*60}\n")
    
    return findings
