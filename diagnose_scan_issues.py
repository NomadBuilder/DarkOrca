#!/usr/bin/env python3
"""
Diagnostic tool to identify why scans might not be fully running on a target.
Checks for common issues like Cloudflare blocking, rate limiting, timeouts, etc.
"""

import sys
import requests
import time
from urllib.parse import urlparse

def check_target_accessibility(url):
    """Check basic accessibility and response times."""
    print(f"\n{'='*60}")
    print(f"1. TARGET ACCESSIBILITY CHECK")
    print(f"{'='*60}")
    
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
    })
    
    try:
        start = time.time()
        response = session.get(url, timeout=10, allow_redirects=True)
        elapsed = time.time() - start
        
        print(f"✓ URL accessible: {url}")
        print(f"  Status: {response.status_code}")
        print(f"  Response time: {elapsed:.2f}s")
        print(f"  Content length: {len(response.content)} bytes")
        
        # Check headers
        server = response.headers.get('Server', 'Unknown')
        cf_ray = response.headers.get('CF-Ray', None)
        
        print(f"  Server: {server}")
        if cf_ray:
            print(f"  ⚠️  CLOUDFLARE DETECTED (CF-Ray: {cf_ray})")
            print(f"     Cloudflare can block aggressive scans!")
        
        return True
    except Exception as e:
        print(f"✗ URL not accessible: {e}")
        return False

def check_rate_limiting(url):
    """Check if site has rate limiting."""
    print(f"\n{'='*60}")
    print(f"2. RATE LIMITING CHECK")
    print(f"{'='*60}")
    
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
    })
    
    print("Sending 10 rapid requests to test rate limiting...")
    rate_limited = False
    
    for i in range(10):
        try:
            start = time.time()
            response = session.get(url, timeout=5)
            elapsed = time.time() - start
            
            if response.status_code == 429:
                print(f"  ⚠️  Request {i+1}: HTTP 429 (Rate Limited)")
                rate_limited = True
                retry_after = response.headers.get('Retry-After', 'N/A')
                print(f"     Retry-After: {retry_after}")
                break
            elif response.status_code == 403:
                print(f"  ⚠️  Request {i+1}: HTTP 403 (Forbidden/Blocked)")
                rate_limited = True
                break
            else:
                print(f"  Request {i+1}: {response.status_code} ({elapsed:.2f}s)")
            
            time.sleep(0.3)  # Small delay between requests
        except Exception as e:
            print(f"  ✗ Request {i+1} failed: {e}")
            break
    
    if not rate_limited:
        print("✓ No rate limiting detected in 10 requests")
    else:
        print("\n⚠️  WARNING: Rate limiting detected! Scans may be incomplete.")
    
    return rate_limited

def check_common_endpoints(url):
    """Check if common endpoints return 404/429."""
    print(f"\n{'='*60}")
    print(f"3. COMMON ENDPOINTS CHECK")
    print(f"{'='*60}")
    
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
    })
    
    endpoints = ['/api', '/admin', '/wp-admin', '/upload', '/api/v1', '/robots.txt']
    
    results = {'200': 0, '404': 0, '403': 0, '429': 0, 'other': 0}
    
    for endpoint in endpoints:
        test_url = f"{base_url}{endpoint}"
        try:
            response = session.get(test_url, timeout=5, allow_redirects=False)
            status = response.status_code
            status_category = str(status)
            
            if status == 200:
                results['200'] += 1
                print(f"  ✓ {endpoint}: {status}")
            elif status == 404:
                results['404'] += 1
                print(f"  - {endpoint}: {status} (not found)")
            elif status == 403:
                results['403'] += 1
                print(f"  ⚠️  {endpoint}: {status} (forbidden)")
            elif status == 429:
                results['429'] += 1
                print(f"  ⚠️  {endpoint}: {status} (rate limited)")
            else:
                results['other'] += 1
                print(f"  ? {endpoint}: {status}")
        except Exception as e:
            print(f"  ✗ {endpoint}: Error - {e}")
    
    if results['429'] > 0:
        print(f"\n⚠️  WARNING: {results['429']} endpoint(s) returned 429 (rate limited)")

def check_scanner_timeouts():
    """Check scanner tool availability."""
    print(f"\n{'='*60}")
    print(f"4. SCANNER TOOLS CHECK")
    print(f"{'='*60}")
    
    import shutil
    
    tools = {
        'nmap': 'nmap',
        'nuclei': 'nuclei',
        'wpscan': 'wpscan',
    }
    
    all_available = True
    for name, cmd in tools.items():
        path = shutil.which(cmd)
        if path:
            print(f"  ✓ {name}: Found at {path}")
        else:
            print(f"  ✗ {name}: Not found in PATH")
            all_available = False
    
    if not all_available:
        print("\n⚠️  WARNING: Some scanner tools are missing. Scans may be incomplete.")
    
    return all_available

def check_cloudflare_protection(url):
    """Check for Cloudflare-specific protections."""
    print(f"\n{'='*60}")
    print(f"5. CLOUDFLARE PROTECTION CHECK")
    print(f"{'='*60}")
    
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'python-requests/2.31.0'  # Tool-like UA
    })
    
    try:
        response = session.get(url, timeout=10)
        
        # Check for Cloudflare indicators
        cf_ray = response.headers.get('CF-Ray')
        server = response.headers.get('Server', '').lower()
        cf_cache = response.headers.get('CF-Cache-Status')
        
        if 'cloudflare' in server or cf_ray:
            print("⚠️  CLOUDFLARE PROTECTED SITE DETECTED")
            print(f"   Server: {response.headers.get('Server', 'Unknown')}")
            print(f"   CF-Ray: {cf_ray or 'Not present'}")
            print(f"   CF-Cache: {cf_cache or 'Not present'}")
            
            # Test with different User-Agents
            print("\n   Testing different User-Agents...")
            
            test_uas = [
                ('Python requests', 'python-requests/2.31.0'),
                ('curl', 'curl/8.7.1'),
                ('Browser', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'),
            ]
            
            for name, ua in test_uas:
                test_session = requests.Session()
                test_session.headers['User-Agent'] = ua
                try:
                    r = test_session.get(url, timeout=5)
                    print(f"     {name:20s}: Status {r.status_code}")
                    if r.status_code == 403:
                        print(f"       ⚠️  BLOCKED by Cloudflare!")
                except Exception as e:
                    print(f"     {name:20s}: Error - {e}")
            
            print("\n   ⚠️  Cloudflare can block:")
            print("      - Tool-like User-Agents")
            print("      - Aggressive scanning patterns")
            print("      - Too many requests too quickly")
            print("      - Requests that look automated")
            
            return True
        else:
            print("✓ Site is not behind Cloudflare (or using different CDN)")
            return False
            
    except Exception as e:
        print(f"✗ Error checking Cloudflare: {e}")
        return False

def recommendations(url, has_cf, rate_limited):
    """Provide recommendations based on findings."""
    print(f"\n{'='*60}")
    print(f"RECOMMENDATIONS")
    print(f"{'='*60}")
    
    recommendations_list = []
    
    if has_cf:
        recommendations_list.append("""
1. CLOUDFLARE PROTECTION DETECTED
   - Use realistic browser User-Agents (enable OPSEC mode)
   - Add delays between requests
   - Consider using --exhaustive mode OFF (slower but less likely to trigger blocks)
   - Some scanners may timeout or fail - this is normal
   """)
    
    if rate_limited:
        recommendations_list.append("""
2. RATE LIMITING DETECTED
   - The site limits request frequency
   - Scans may take longer or some scanners may fail
   - Consider scanning during off-peak hours
   - Use defensive mode instead of offensive mode
   """)
    
    if not has_cf and not rate_limited:
        recommendations_list.append("""
3. GENERAL SCAN TIPS
   - Try running with --verbose flag to see detailed output
   - Check scan logs for specific scanner errors
   - Some scanners may timeout on slow sites
   - Use defensive mode for faster scans
   """)
    
    recommendations_list.append("""
4. VERIFYING SCAN COMPLETION
   - Check the scan results for scanner_errors field
   - Look for "timed out" or "failed" messages
   - Compare scanners_run vs total expected scanners
   - Some scanners may complete with 0 findings (this is OK)
   """)
    
    for rec in recommendations_list:
        print(rec)

def main():
    if len(sys.argv) < 2:
        print("Usage: python diagnose_scan_issues.py <url>")
        print("Example: python diagnose_scan_issues.py https://alan.com/en-ca")
        sys.exit(1)
    
    url = sys.argv[1]
    
    print(f"\n🔍 DIAGNOSING SCAN ISSUES FOR: {url}")
    print(f"{'='*60}")
    
    # Run checks
    accessible = check_target_accessibility(url)
    if not accessible:
        print("\n✗ Target is not accessible. Cannot continue diagnostics.")
        sys.exit(1)
    
    rate_limited = check_rate_limiting(url)
    check_common_endpoints(url)
    tools_available = check_scanner_timeouts()
    has_cf = check_cloudflare_protection(url)
    
    # Provide recommendations
    recommendations(url, has_cf, rate_limited)
    
    print(f"\n{'='*60}")
    print("Diagnostics complete!")
    print(f"{'='*60}\n")

if __name__ == '__main__':
    main()
