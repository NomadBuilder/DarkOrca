"""WebSocket Security Testing Scanner."""

import re
import requests
import json
import time
from typing import List, Optional, Dict, Any
from urllib.parse import urljoin, urlparse

from .base import BaseScanner
from ..models.scan import ScanTarget
from ..models.finding import Finding, FindingSeverity, FindingCategory
from ..models.scan_mode import ScanMode

import logging
logger = logging.getLogger(__name__)


class WebSocketSecurityScanner(BaseScanner):
    """Scanner for WebSocket security vulnerabilities."""
    
    def __init__(self, enabled: bool = True, scan_mode: ScanMode = ScanMode.DEFENSIVE):
        """
        Initialize WebSocket security scanner.
        
        Args:
            enabled: Whether scanner is enabled
            scan_mode: Scan mode (defensive or offensive)
        """
        super().__init__(
            name="websocket_security",
            command=None,  # Python-based (can use websockets library if available)
            enabled=enabled,
            scan_mode=scan_mode
        )
        # Use OPSEC-enabled session helper
        from ..utils.scanner_session import create_scanner_session
        self.session = create_scanner_session()
    
    def is_available(self) -> bool:
        """WebSocket security scanner is always available (uses requests for detection)."""
        return True
    
    def scan(self, target: ScanTarget) -> List[Finding]:
        """Run WebSocket security tests."""
        if self.scan_mode == ScanMode.DEFENSIVE:
            return []  # Only run in offensive mode
        
        findings = []
        
        try:
            # Step 1: Detect WebSocket endpoints
            ws_endpoints = self._discover_websocket_endpoints(target.url)
            
            if not ws_endpoints:
                # Test for WebSocket upgrade in HTTP
                findings.extend(self._test_websocket_upgrade(target.url))
                return findings
            
            for endpoint in ws_endpoints:
                findings.extend(self._test_websocket_endpoint(target.url, endpoint))
        
        except Exception as e:
            logger.debug(f"WebSocket security scan error: {e}")
        
        return findings
    
    def _discover_websocket_endpoints(self, url: str) -> List[str]:
        """Discover WebSocket endpoints from page source and common paths."""
        endpoints = []
        
        try:
            # Check page source for WebSocket connections
            response = self.session.get(url, timeout=10)
            content = response.text
            
            # Look for WebSocket connections in JavaScript
            ws_patterns = [
                r'new\s+WebSocket\s*\(\s*["\']([^"\']+)["\']',
                r'ws://[^\s"\']+',
                r'wss://[^\s"\']+',
                r'websocket://[^\s"\']+',
            ]
            
            for pattern in ws_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0] if match else ''
                    if match and (match.startswith('ws://') or match.startswith('wss://')):
                        endpoints.append(match)
            
            # Also check common WebSocket paths
            common_paths = [
                '/ws',
                '/websocket',
                '/socket.io',
                '/socket',
                '/api/ws',
                '/api/websocket',
            ]
            
            parsed = urlparse(url)
            for path in common_paths:
                test_url = f"{parsed.scheme}://{parsed.netloc}{path}"
                # Try WebSocket upgrade request
                try:
                    headers = {
                        'Upgrade': 'websocket',
                        'Connection': 'Upgrade',
                        'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
                        'Sec-WebSocket-Version': '13',
                    }
                    response = self.session.get(test_url, headers=headers, timeout=5)
                    
                    # Check for WebSocket upgrade response
                    if response.status_code == 101 or 'upgrade' in response.headers.get('Connection', '').lower():
                        endpoints.append(test_url)
                except:
                    pass
        
        except Exception as e:
            logger.debug(f"Error discovering WebSocket endpoints: {e}")
        
        return list(set(endpoints))  # Remove duplicates
    
    def _test_websocket_upgrade(self, url: str) -> List[Finding]:
        """Test for WebSocket upgrade support."""
        findings = []
        
        try:
            # Try WebSocket upgrade request
            headers = {
                'Upgrade': 'websocket',
                'Connection': 'Upgrade',
                'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
                'Sec-WebSocket-Version': '13',
            }
            response = self.session.get(url, headers=headers, timeout=5)
            
            if response.status_code == 101:
                # WebSocket upgrade successful
                # Check for security issues
                if 'Sec-WebSocket-Protocol' not in response.headers:
                    findings.append(Finding(
                        title="WebSocket Without Authentication",
                        description=f"WebSocket endpoint at {url} accepts connections without authentication. This may allow unauthorized access.",
                        severity=FindingSeverity.MEDIUM,
                        category=FindingCategory.WEAK_SECURITY,
                        source_scanner=self.name,
                        url=url,
                        evidence=f"WebSocket upgrade successful (101 status) without authentication",
                        remediation="Implement WebSocket authentication. Use tokens, cookies, or subprotocol negotiation for authentication.",
                        metadata={'status_code': response.status_code}
                    ))
        
        except Exception as e:
            logger.debug(f"WebSocket upgrade test error: {e}")
        
        return findings
    
    def _test_websocket_endpoint(self, base_url: str, ws_url: str) -> List[Finding]:
        """Test WebSocket endpoint for security vulnerabilities."""
        findings = []
        
        # Note: Full WebSocket testing requires websockets library
        # For now, we do basic detection and provide findings based on endpoint discovery
        
        # Test 1: Insecure WebSocket (ws:// instead of wss://)
        if ws_url.startswith('ws://'):
            findings.append(Finding(
                title="Insecure WebSocket Connection",
                description=f"WebSocket endpoint uses insecure ws:// protocol instead of wss:// at {ws_url}. Data transmitted is not encrypted.",
                severity=FindingSeverity.MEDIUM,
                category=FindingCategory.WEAK_SECURITY,
                source_scanner=self.name,
                url=ws_url,
                remediation="Use wss:// (WebSocket Secure) instead of ws:// to encrypt WebSocket communications. WSS uses TLS/SSL encryption.",
                metadata={'protocol': 'ws', 'secure': False}
            ))
        
        # Test 2: WebSocket origin validation
        # This would require actual WebSocket connection testing
        # For now, document the finding
        findings.append(Finding(
            title="WebSocket Endpoint Detected",
            description=f"WebSocket endpoint found at {ws_url}. Manual testing recommended for: authentication, origin validation, message validation, and DoS protection.",
            severity=FindingSeverity.INFO,
            category=FindingCategory.INFORMATION_DISCLOSURE,
            source_scanner=self.name,
            url=ws_url,
            remediation="Ensure WebSocket endpoints: 1) Require authentication, 2) Validate Origin header to prevent CSWSH, 3) Validate and sanitize all messages, 4) Implement rate limiting, 5) Use wss:// in production.",
            references=["https://owasp.org/www-community/vulnerabilities/Cross_Site_WebSocket_Hijacking"],
            metadata={'endpoint': ws_url, 'requires_manual_testing': True}
        ))
        
        return findings
