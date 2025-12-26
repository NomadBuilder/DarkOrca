#!/usr/bin/env python3
"""
Test rate limiting on login API endpoints for ca.alan.com
This script tests common authentication API endpoints that SPA login forms typically use.
"""

import requests
import time
import json

def test_endpoint_rate_limiting(url, endpoint_name, use_json=True):
    """Test rate limiting on a specific endpoint."""
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
        'Origin': 'https://ca.alan.com',
        'Referer': 'https://ca.alan.com/en/login'
    })
    
    if use_json:
        session.headers['Content-Type'] = 'application/json'
    
    print(f'\n{"="*70}')
    print(f'Testing: {endpoint_name}')
    print(f'Endpoint: {url}')
    print(f'{"="*70}')
    
    rate_limited = False
    status_codes = {}
    response_times = []
    blocked_count = 0
    
    print(f'Sending 30 rapid login attempts...\n')
    
    for i in range(30):
        try:
            # Try different payload formats
            if use_json:
                payload = {
                    'email': f'test{i}@example.com',
                    'password': 'testpassword123'
                }
                response = session.post(url, json=payload, timeout=10, allow_redirects=False)
            else:
                payload = {
                    'email': f'test{i}@example.com',
                    'password': 'testpassword123'
                }
                response = session.post(url, data=payload, timeout=10, allow_redirects=False)
            
            elapsed = time.time() - time.time() + 0.1  # Placeholder for actual timing
            
            status = response.status_code
            status_codes[status] = status_codes.get(status, 0) + 1
            
            if status == 429:
                print(f'Request {i+1:2d}: ✓ HTTP 429 (Rate Limited)')
                rate_limited = True
                blocked_count += 1
                retry_after = response.headers.get('Retry-After', 'N/A')
                cf_ray = response.headers.get('CF-Ray', 'N/A')
                print(f'              Retry-After: {retry_after}, CF-Ray: {cf_ray}')
                if blocked_count >= 3:
                    break
            elif status == 403:
                print(f'Request {i+1:2d}: ⚠ HTTP 403 (Blocked)')
                blocked_count += 1
            elif status == 401:
                if i < 5 or i % 10 == 0:
                    print(f'Request {i+1:2d}: • HTTP 401 (Invalid credentials - expected)')
            elif status == 422:
                if i < 5 or i % 10 == 0:
                    print(f'Request {i+1:2d}: • HTTP 422 (Validation error - expected)')
            elif status == 404:
                if i < 3:
                    print(f'Request {i+1:2d}: ✗ HTTP 404 (Not found)')
                return False  # Endpoint doesn't exist
            elif status in [200, 302]:
                if i < 5:
                    print(f'Request {i+1:2d}: ⚠ HTTP {status} (Accepted)')
            else:
                if i < 3:
                    print(f'Request {i+1:2d}: ? HTTP {status}')
            
            time.sleep(0.1)
            
        except Exception as e:
            if i < 3:
                print(f'Request {i+1:2d}: ✗ Error - {str(e)[:50]}')
    
    print(f'\nResults:')
    print(f'  Status codes: {dict(status_codes)}')
    
    if rate_limited:
        print(f'\n  ✓ RATE LIMITING DETECTED - HTTP 429 responses: {blocked_count}')
        return True
    elif blocked_count > 0:
        print(f'\n  ⚠ PARTIAL PROTECTION - HTTP 403 responses: {blocked_count}')
        return True
    elif 401 in status_codes or 422 in status_codes:
        print(f'\n  ⚠ NO RATE LIMITING - All requests accepted (401/422)')
        return False
    else:
        print(f'\n  ✗ Endpoint not found or no response')
        return False

def main():
    print('='*70)
    print('LOGIN API RATE LIMITING TEST - ca.alan.com')
    print('='*70)
    print('\nTesting common authentication API endpoints...')
    
    base_url = 'https://ca.alan.com'
    
    # Common login API endpoints to test
    endpoints_to_test = [
        (f'{base_url}/api/login', 'API Login (JSON)', True),
        (f'{base_url}/api/auth/login', 'API Auth Login (JSON)', True),
        (f'{base_url}/api/authentication/login', 'API Authentication Login (JSON)', True),
        (f'{base_url}/api/v1/login', 'API v1 Login (JSON)', True),
        (f'{base_url}/api/v1/auth/login', 'API v1 Auth Login (JSON)', True),
        (f'{base_url}/auth/login', 'Auth Login (JSON)', True),
        (f'{base_url}/login/api', 'Login API (JSON)', True),
        (f'{base_url}/api/login', 'API Login (Form)', False),
        (f'{base_url}/api/auth/login', 'API Auth Login (Form)', False),
    ]
    
    found_endpoint = False
    rate_limiting_detected = False
    
    for url, name, use_json in endpoints_to_test:
        result = test_endpoint_rate_limiting(url, name, use_json)
        if result is not None:
            if not result:  # Endpoint exists but no rate limiting
                found_endpoint = True
            else:  # Rate limiting detected
                found_endpoint = True
                rate_limiting_detected = True
                break
    
    print(f'\n{"="*70}')
    print('SUMMARY')
    print(f'{"="*70}')
    
    if rate_limiting_detected:
        print('✓ RATE LIMITING DETECTED on login endpoint')
        print('  The login form has proper protection against brute force attacks.')
    elif found_endpoint:
        print('⚠ NO RATE LIMITING DETECTED')
        print('  Login endpoint found but rate limiting not triggered.')
        print('  This may indicate:')
        print('    - Rate limiting is disabled')
        print('    - Rate limiting requires more attempts (>30)')
        print('    - Rate limiting is IP-based and not triggered from single IP')
        print('    - Rate limiting is account-based (locks specific accounts)')
    else:
        print('✗ LOGIN ENDPOINT NOT FOUND')
        print('  Could not identify the authentication API endpoint.')
        print('\n  To find the endpoint manually:')
        print('  1. Open Chrome DevTools (F12)')
        print('  2. Go to Network tab')
        print('  3. Filter by "Fetch/XHR"')
        print('  4. Attempt to log in with any credentials')
        print('  5. Look for the API call (usually POST request)')
        print('  6. Check the Request URL in the Network tab')
        print('  7. Run this script with that endpoint URL')
    
    print(f'{"="*70}')

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\n\nTest interrupted by user.')
    except Exception as e:
        print(f'\n\nError: {e}')
        import traceback
        traceback.print_exc()

