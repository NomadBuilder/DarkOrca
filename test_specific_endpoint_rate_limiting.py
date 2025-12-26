#!/usr/bin/env python3
"""
Test rate limiting on a specific login API endpoint.
Usage: python test_specific_endpoint_rate_limiting.py <endpoint_url>
Example: python test_specific_endpoint_rate_limiting.py https://api.alan.com/v1/auth/login
"""

import requests
import time
import sys
import json

def test_rate_limiting(url, attempts=50, use_oauth2=False):
    """Test rate limiting on a specific endpoint."""
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
        'Origin': 'https://ca.alan.com',
        'Referer': 'https://ca.alan.com/en/login',
    })
    
    if use_oauth2:
        session.headers['Content-Type'] = 'application/x-www-form-urlencoded'
    else:
        session.headers['Content-Type'] = 'application/json'
    
    print('='*70)
    print('RATE LIMITING TEST')
    print('='*70)
    print(f'Endpoint: {url}')
    print(f'Attempts: {attempts}')
    print('='*70)
    print(f'\nSending {attempts} rapid login attempts...\n')
    
    rate_limited = False
    status_codes = {}
    response_times = []
    blocked_count = 0
    first_429_at = None
    
    for i in range(attempts):
        try:
            if use_oauth2:
                # OAuth2/OIDC password grant format
                payload = {
                    'grant_type': 'password',
                    'username': f'test{i}@example.com',
                    'password': 'testpassword123',
                    'client_id': 'alan-ca'  # May need to be discovered
                }
            else:
                payload = {
                    'email': f'test{i}@example.com',
                    'password': 'testpassword123'
                }
            
            start_time = time.time()
            if use_oauth2:
                response = session.post(url, data=payload, timeout=10, allow_redirects=False)
            else:
                response = session.post(url, json=payload, timeout=10, allow_redirects=False)
            elapsed = time.time() - start_time
            response_times.append(elapsed)
            
            status = response.status_code
            status_codes[status] = status_codes.get(status, 0) + 1
            
            if status == 429:
                if first_429_at is None:
                    first_429_at = i + 1
                print(f'Request {i+1:3d}: ✓ HTTP 429 (Rate Limited) - {elapsed:.3f}s')
                rate_limited = True
                blocked_count += 1
                retry_after = response.headers.get('Retry-After', 'N/A')
                cf_ray = response.headers.get('CF-Ray', 'N/A')
                x_rate_limit = response.headers.get('X-RateLimit-Limit', 'N/A')
                x_rate_limit_remaining = response.headers.get('X-RateLimit-Remaining', 'N/A')
                print(f'              Retry-After: {retry_after}, CF-Ray: {cf_ray[:30]}')
                if x_rate_limit != 'N/A':
                    print(f'              X-RateLimit-Limit: {x_rate_limit}, Remaining: {x_rate_limit_remaining}')
                if blocked_count >= 5:
                    print('              ... (continuing to test)')
            elif status == 403:
                if i < 5:
                    print(f'Request {i+1:3d}: ⚠ HTTP 403 (Blocked) - {elapsed:.3f}s')
                blocked_count += 1
            elif status == 401:
                if i < 5 or i % 10 == 0:
                    print(f'Request {i+1:3d}: • HTTP 401 (Invalid credentials) - {elapsed:.3f}s')
            elif status == 422:
                if i < 5 or i % 10 == 0:
                    print(f'Request {i+1:3d}: • HTTP 422 (Validation error) - {elapsed:.3f}s')
            elif status == 404:
                print(f'Request {i+1:3d}: ✗ HTTP 404 (Endpoint not found)')
                print(f'\n✗ ERROR: Endpoint returned 404. Check the URL.')
                return
            elif status in [200, 302]:
                if i < 5:
                    print(f'Request {i+1:3d}: ⚠ HTTP {status} (Accepted) - {elapsed:.3f}s')
            else:
                if i < 5:
                    print(f'Request {i+1:3d}: ? HTTP {status} - {elapsed:.3f}s')
            
            time.sleep(0.1)
            
        except requests.exceptions.Timeout:
            if i < 3:
                print(f'Request {i+1:3d}: ✗ Timeout')
        except Exception as e:
            if i < 3:
                print(f'Request {i+1:3d}: ✗ Error - {str(e)[:50]}')
    
    # Results
    print(f'\n{"="*70}')
    print('RESULTS')
    print(f'{"="*70}')
    print(f'Total requests: {attempts}')
    print(f'Status codes: {dict(status_codes)}')
    
    if response_times:
        avg_time = sum(response_times) / len(response_times)
        min_time = min(response_times)
        max_time = max(response_times)
        print(f'\nResponse times:')
        print(f'  Average: {avg_time:.3f}s')
        print(f'  Min: {min_time:.3f}s')
        print(f'  Max: {max_time:.3f}s')
    
    print(f'\n{"="*70}')
    
    if rate_limited:
        print('✓ RATE LIMITING DETECTED')
        print(f'  First rate limit triggered at request #{first_429_at}')
        print(f'  Total HTTP 429 responses: {blocked_count}')
        print(f'  Rate limit threshold: ~{first_429_at-1} requests')
        print(f'\n  The login endpoint has proper rate limiting protection.')
    elif blocked_count > 0:
        print('⚠ PARTIAL PROTECTION')
        print(f'  Some requests blocked (HTTP 403): {blocked_count}')
        print(f'  May indicate Cloudflare/WAF protection.')
    elif 401 in status_codes or 422 in status_codes:
        print('⚠ NO RATE LIMITING DETECTED')
        print(f'  All requests accepted (returned {list(status_codes.keys())})')
        print(f'  This indicates NO rate limiting protection on login endpoint.')
        print(f'  Security concern: Login form vulnerable to brute force attacks.')
    else:
        print('? UNKNOWN STATUS')
        print(f'  Unexpected status codes: {list(status_codes.keys())}')
    
    print(f'{"="*70}\n')

def main():
    if len(sys.argv) < 2:
        print('Usage: python test_specific_endpoint_rate_limiting.py <endpoint_url> [attempts] [--oauth2]')
        print('\nExample:')
        print('  python test_specific_endpoint_rate_limiting.py https://api.alan.com/v1/auth/login')
        print('  python test_specific_endpoint_rate_limiting.py https://idp.alan.com/realms/alan/protocol/openid-connect/token --oauth2')
        print('\nTo find the endpoint:')
        print('  1. Open Chrome DevTools (F12)')
        print('  2. Go to Network tab')
        print('  3. Filter by "Fetch/XHR"')
        print('  4. Clear the log')
        print('  5. Attempt to log in (with any credentials)')
        print('  6. Look for POST request in Network tab')
        print('  7. Copy the Request URL')
        print('  8. Run this script with that URL')
        sys.exit(1)
    
    endpoint_url = sys.argv[1]
    attempts = 50
    use_oauth2 = False
    
    for arg in sys.argv[2:]:
        if arg == '--oauth2':
            use_oauth2 = True
        elif arg.isdigit():
            attempts = int(arg)
    
    test_rate_limiting(endpoint_url, attempts, use_oauth2)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\n\nTest interrupted by user.')
    except Exception as e:
        print(f'\n\nError: {e}')
        import traceback
        traceback.print_exc()

