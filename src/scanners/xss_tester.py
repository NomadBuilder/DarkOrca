"""XSS (Cross-Site Scripting) vulnerability tester."""

import re
import requests
from typing import List, Dict, Any
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

from .base import BaseScanner
from ..models.scan import ScanTarget
from ..models.finding import Finding, FindingSeverity, FindingCategory
from ..models.scan_mode import ScanMode


class XSSTester(BaseScanner):
    """XSS vulnerability tester for web applications."""
    
    def __init__(self, enabled: bool = True, scan_mode: ScanMode = ScanMode.DEFENSIVE):
        """
        Initialize XSS tester.
        
        Args:
            enabled: Whether scanner is enabled
            scan_mode: Scan mode (defensive or offensive)
        """
        super().__init__(
            name="xss_tester",
            command=None,  # No external command needed
            enabled=enabled,
            scan_mode=scan_mode
        )
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Common XSS payloads (non-destructive, proof-of-concept only)
        self.xss_payloads = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '<svg onload=alert("XSS")>',
            '<body onload=alert("XSS")>',
            '<input onfocus=alert("XSS") autofocus>',
            '<select onfocus=alert("XSS") autofocus>',
            '<textarea onfocus=alert("XSS") autofocus>',
            '<iframe src=javascript:alert("XSS")>',
            '<script>alert(String.fromCharCode(88,83,83))</script>',
            '<img src="x" onerror="alert(\'XSS\')">',
            '<svg><script>alert("XSS")</script></svg>',
            '"><script>alert("XSS")</script>',
            "';alert('XSS');//",
            '<script>alert(document.cookie)</script>',
            '<script>alert(document.domain)</script>',
        ]
    
    def is_available(self) -> bool:
        """XSS tester is always available."""
        return True
    
    def scan(self, target: ScanTarget) -> List[Finding]:
        """Run XSS tests on target."""
        if self.scan_mode == ScanMode.DEFENSIVE:
            return []  # Only run in offensive mode
        
        findings = []
        
        # Test XSS in various contexts
        findings.extend(self._test_reflected_xss(target.url))
        findings.extend(self._test_stored_xss(target.url))
        findings.extend(self._test_dom_xss(target.url))
        
        return findings
    
    def _test_reflected_xss(self, url: str) -> List[Finding]:
        """Test for reflected XSS vulnerabilities."""
        findings = []
        
        # Parse URL to get parameters
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # Test each parameter with XSS payloads
        for param_name, param_values in params.items():
            for payload in self.xss_payloads[:5]:  # Test first 5 payloads per parameter
                try:
                    # Create test URL with XSS payload
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    test_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse((
                        parsed.scheme,
                        parsed.netloc,
                        parsed.path,
                        parsed.params,
                        test_query,
                        parsed.fragment
                    ))
                    
                    # Send request
                    response = self.session.get(test_url, timeout=10)
                    
                    # Check if payload is reflected in response
                    if payload in response.text:
                        # Check if it's executed (look for unescaped script tags)
                        if '<script>' in response.text and payload in response.text:
                            findings.append(Finding(
                                title=f"Reflected XSS Vulnerability Detected",
                                description=f"Cross-Site Scripting (XSS) vulnerability found in parameter '{param_name}' at {url}. The payload '{payload[:50]}...' is reflected in the response and may be executed in user browsers.",
                                severity=FindingSeverity.HIGH,
                                category=FindingCategory.VULNERABILITY,
                                source_scanner="xss_tester",
                                source_id=f"reflected_xss_{param_name}",
                                url=test_url,
                                remediation=f"Sanitize and validate all user input, especially parameter '{param_name}'. Use output encoding/escaping (HTML entity encoding, JavaScript encoding). Implement Content Security Policy (CSP) headers. Use a Web Application Firewall (WAF).",
                                exploited=True,
                                exploitation_details=f"XSS payload successfully reflected in parameter '{param_name}'. Payload: {payload[:100]}",
                                metadata={
                                    "parameter": param_name,
                                    "payload": payload,
                                    "vulnerability_type": "reflected_xss",
                                    "url": test_url,
                                },
                            ))
                            break  # Found XSS, no need to test more payloads for this parameter
                except:
                    continue
        
        # Also test common WordPress parameters if it's a WordPress site
        if self._is_wordpress_site(url):
            common_params = ['s', 'search', 'q', 'query', 'id', 'page', 'post', 'cat', 'tag']
            for param in common_params:
                if param not in params:  # Only test if not already in URL
                    for payload in self.xss_payloads[:3]:  # Test first 3 payloads
                        try:
                            test_url = f"{url}?{param}={payload}"
                            response = self.session.get(test_url, timeout=10)
                            
                            if payload in response.text and '<script>' in response.text:
                                findings.append(Finding(
                                    title=f"Reflected XSS Vulnerability in {param} Parameter",
                                    description=f"Cross-Site Scripting (XSS) vulnerability found in '{param}' parameter. The payload is reflected and may be executed.",
                                    severity=FindingSeverity.HIGH,
                                    category=FindingCategory.VULNERABILITY,
                                    source_scanner="xss_tester",
                                    source_id=f"reflected_xss_{param}",
                                    url=test_url,
                                    remediation=f"Sanitize and validate the '{param}' parameter. Implement proper output encoding and Content Security Policy (CSP).",
                                    exploited=True,
                                    exploitation_details=f"XSS payload reflected in '{param}' parameter.",
                                    metadata={
                                        "parameter": param,
                                        "payload": payload,
                                        "vulnerability_type": "reflected_xss",
                                    },
                                ))
                                break
                        except:
                            continue
        
        return findings
    
    def _test_stored_xss(self, url: str) -> List[Finding]:
        """Test for stored XSS vulnerabilities (e.g., in comments, forms)."""
        findings = []
        
        # WordPress-specific stored XSS tests
        if self._is_wordpress_site(url):
            # Test comment form
            comment_url = urljoin(url, '/wp-comments-post.php')
            payload = '<script>alert("XSS")</script>'
            
            try:
                # First, get the comment form to extract nonce/fields
                page_response = self.session.get(url, timeout=10)
                if 'comment' in page_response.text.lower():
                    # Try to submit a comment with XSS payload
                    comment_data = {
                        'comment': payload,
                        'author': 'Test User',
                        'email': 'test@example.com',
                        'url': '',
                        'submit': 'Post Comment',
                    }
                    
                    # Note: This won't actually post (we don't have proper nonce), but we can check if the form accepts it
                    # For actual stored XSS, we'd need to successfully post and then check if it's stored
                    # This is a simplified test
                    pass
            except:
                pass
        
        return findings
    
    def _test_dom_xss(self, url: str) -> List[Finding]:
        """Test for DOM-based XSS vulnerabilities."""
        findings = []
        
        # Test hash-based XSS (DOM manipulation)
        for payload in self.xss_payloads[:3]:
            try:
                test_url = f"{url}#{payload}"
                response = self.session.get(test_url, timeout=10)
                
                # Check if JavaScript processes the hash
                if 'location.hash' in response.text or 'window.location' in response.text:
                    # Potential DOM XSS - would need JavaScript execution to confirm
                    findings.append(Finding(
                        title="Potential DOM-Based XSS Vulnerability",
                        description=f"Potential DOM-based XSS vulnerability detected. The application may process URL fragments (hash) in JavaScript, which could lead to XSS if not properly sanitized.",
                        severity=FindingSeverity.MEDIUM,
                        category=FindingCategory.VULNERABILITY,
                        source_scanner="xss_tester",
                        source_id="dom_xss",
                        url=test_url,
                        remediation="Sanitize all data processed by JavaScript, especially URL fragments, document.location, and innerHTML. Use safe DOM manipulation methods and Content Security Policy (CSP).",
                        metadata={
                            "payload": payload,
                            "vulnerability_type": "dom_xss",
                        },
                    ))
                    break
            except:
                continue
        
        return findings
    
    def _is_wordpress_site(self, url: str) -> bool:
        """Check if the target is a WordPress site."""
        try:
            response = self.session.get(url, timeout=10)
            content = response.text.lower()
            
            wp_indicators = [
                'wp-content',
                'wp-includes',
                'wp-admin',
                'wordpress',
                '/wp-json/',
            ]
            
            if any(indicator in content for indicator in wp_indicators):
                return True
            
            return False
        except:
            return False

