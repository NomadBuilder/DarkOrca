#!/usr/bin/env python3
"""
Test rate limiting on login form at https://ca.alan.com/en/login
"""

import requests
import re
import time
from urllib.parse import urljoin

def test_login_rate_limiting():
    url = 'https://ca.alan.com/en/login'
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
    })
    
    print('=' * 70)
    print('LOGIN FORM RATE LIMITING TEST')
    print('=' * 70)
    print(f'Target: {url}\n')
    
    # Step 1: Fetch login page and find form endpoint
    print('1. Analyzing login page...')
    try:
        response = session.get(url, timeout=10)
        print(f'   Status: {response.status_code}')
        
        # Parse HTML with regex to find form action
        form_match = re.search(r'<form[^>]*action=["\']([^"\']+)["\']', response.text, re.IGNORECASE)
        if form_match:
            action = form_match.group(1)
            if action.startswith('http'):
                login_endpoint = action
            else:
                login_endpoint = urljoin(url, action)
            print(f'   ✓ Found form action: {login_endpoint}')
        else:
            # Look for API endpoint in JavaScript
            api_match = re.search(r'["\']([^"\']*api[^"\']*login[^"\']*)["\']', response.text, re.IGNORECASE)
            if api_match:
                api_path = api_match.group(1)
                if api_path.startswith('http'):
                    login_endpoint = api_path
                else:
                    login_endpoint = urljoin(url, api_path)
                print(f'   ✓ Found API endpoint in page: {login_endpoint}')
            else:
                # Try common login endpoints
                common_endpoints = [
                    urljoin(url, '/api/login'),
                    urljoin(url, '/api/auth/login'),
                    urljoin(url, '/login'),
                    'https://ca.alan.com/api/login',
                    'https://ca.alan.com/api/auth/login',
                ]
                login_endpoint = common_endpoints[0]
                print(f'   ⚠ Form action not found, will try: {login_endpoint}')
    except Exception as e:
        print(f'   ✗ Error fetching page: {e}')
        return
    
    # Step 2: Test rate limiting
    print(f'\n2. Testing rate limiting with rapid login attempts...')
    print(f'   Target endpoint: {login_endpoint}')
    print(f'   Sending 30 login requests rapidly...\n')
    
    rate_limited = False
    successful = 0
    blocked = 0
    errors = 0
    status_codes = {}
    response_times = []
    
    for i in range(30):
        try:
            login_data = {
                'email': f'test{i}@example.com',
                'password': 'testpassword123'
            }
            
            start_time = time.time()
            response = session.post(login_endpoint, data=login_data, json=None, timeout=10, allow_redirects=False)
            elapsed = time.time() - start_time
            response_times.append(elapsed)
            
            status = response.status_code
            status_codes[status] = status_codes.get(status, 0) + 1
            
            if status == 429:
                print(f'   Request {i+1:2d}: ✓ HTTP 429 (Rate Limited) - {elapsed:.3f}s')
                rate_limited = True
                blocked += 1
                retry_after = response.headers.get('Retry-After', 'N/A')
                cf_ray = response.headers.get('CF-Ray', 'N/A')
                print(f'              Retry-After: {retry_after}, CF-Ray: {cf_ray}')
                # Continue to see how many get blocked
            elif status == 403:
                print(f'   Request {i+1:2d}: ⚠ HTTP 403 (Blocked) - {elapsed:.3f}s')
                blocked += 1
            elif status == 401:
                # 401 is expected for invalid credentials
                if i < 5 or i % 5 == 0:  # Print every 5th or first few
                    print(f'   Request {i+1:2d}: • HTTP 401 (Invalid credentials - expected) - {elapsed:.3f}s')
                successful += 1
            elif status == 422:
                # 422 Unprocessable Entity - also expected for invalid credentials
                if i < 5 or i % 5 == 0:
                    print(f'   Request {i+1:2d}: • HTTP 422 (Validation error - expected) - {elapsed:.3f}s')
                successful += 1
            elif status == 404:
                if i < 3:
                    print(f'   Request {i+1:2d}: ✗ HTTP 404 (Wrong endpoint?) - {elapsed:.3f}s')
                successful += 1
            elif status in [200, 302, 301, 303]:
                if i < 5 or i % 5 == 0:
                    print(f'   Request {i+1:2d}: ⚠ HTTP {status} (Accepted) - {elapsed:.3f}s')
                successful += 1
            else:
                if i < 5 or i % 5 == 0:
                    print(f'   Request {i+1:2d}: ? HTTP {status} - {elapsed:.3f}s')
                successful += 1
            
            time.sleep(0.1)  # Small delay
            
        except Exception as e:
            errors += 1
            if i < 5:
                print(f'   Request {i+1:2d}: ✗ Error - {str(e)[:50]}')
    
    # Step 3: Results analysis
    print(f'\n' + '=' * 70)
    print('TEST RESULTS')
    print('=' * 70)
    print(f'Status codes received: {dict(status_codes)}')
    print(f'Total requests: 30')
    print(f'  - Successful responses: {successful}')
    print(f'  - Blocked/rate limited: {blocked}')
    print(f'  - Errors: {errors}')
    
    if response_times:
        avg_time = sum(response_times) / len(response_times)
        max_time = max(response_times)
        min_time = min(response_times)
        print(f'\nResponse times:')
        print(f'  - Average: {avg_time:.3f}s')
        print(f'  - Min: {min_time:.3f}s')
        print(f'  - Max: {max_time:.3f}s')
    
    print(f'\n' + '=' * 70)
    if rate_limited:
        print('✓ RATE LIMITING DETECTED')
        print('  The login form has proper rate limiting protection.')
        print(f'  HTTP 429 responses received after {blocked} request(s).')
    elif blocked > 0:
        print('⚠ PARTIAL PROTECTION DETECTED')
        print('  Some requests were blocked (HTTP 403).')
        print('  This may indicate Cloudflare or WAF protection.')
    elif 401 in status_codes or 422 in status_codes:
        print('⚠ NO RATE LIMITING DETECTED')
        print('  All login attempts returned expected error codes (401/422).')
        print('  However, no rate limiting (HTTP 429) was triggered.')
        print('  This may indicate:')
        print('    - Rate limiting is disabled or lenient')
        print('    - Rate limiting only triggers after more attempts')
        print('    - Rate limiting is IP-based and requires more requests')
    elif 404 in status_codes:
        print('✗ ENDPOINT NOT FOUND')
        print('  The login endpoint could not be determined.')
        print('  This test may need manual endpoint identification.')
    else:
        print('⚠ NO RATE LIMITING DETECTED')
        print('  All requests were accepted without rate limiting.')
        print('  This is a security concern for login forms.')
    
    print('=' * 70)

if __name__ == '__main__':
    try:
        test_login_rate_limiting()
    except KeyboardInterrupt:
        print('\n\nTest interrupted by user.')
    except Exception as e:
        print(f'\n\nError: {e}')
        import traceback
        traceback.print_exc()

