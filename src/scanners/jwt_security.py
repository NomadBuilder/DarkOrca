"""JWT/Token Security Testing Scanner."""

import re
import requests
import base64
import json
from typing import List, Optional, Dict, Any
from urllib.parse import urljoin

from .base import BaseScanner
from ..models.scan import ScanTarget
from ..models.finding import Finding, FindingSeverity, FindingCategory
from ..models.scan_mode import ScanMode
from ..utils.evidence_collector import EvidenceCollector

import logging
logger = logging.getLogger(__name__)


class JWTSecurityScanner(BaseScanner):
    """Scanner for JWT/Token security vulnerabilities."""
    
    def __init__(self, enabled: bool = True, scan_mode: ScanMode = ScanMode.DEFENSIVE):
        """
        Initialize JWT security scanner.
        
        Args:
            enabled: Whether scanner is enabled
            scan_mode: Scan mode (defensive or offensive)
        """
        super().__init__(
            name="jwt_security",
            command=None,  # Python-based
            enabled=enabled,
            scan_mode=scan_mode
        )
        # Use OPSEC-enabled session helper
        from ..utils.scanner_session import create_scanner_session
        self.session = create_scanner_session()
    
    def is_available(self) -> bool:
        """JWT security scanner is always available."""
        return True
    
    def scan(self, target: ScanTarget) -> List[Finding]:
        """Run JWT security tests."""
        if self.scan_mode == ScanMode.DEFENSIVE:
            return []  # Only run in offensive mode
        
        findings = []
        
        try:
            # Step 1: Try to find JWT tokens in cookies, headers, or URL parameters
            jwt_tokens = self._extract_jwt_tokens(target.url)
            
            if not jwt_tokens:
                # Try to trigger JWT generation by attempting login/auth
                jwt_tokens.extend(self._try_obtain_jwt(target.url))
            
            if jwt_tokens:
                for token in jwt_tokens:
                    findings.extend(self._test_jwt_vulnerabilities(target.url, token))
            else:
                # Test for common JWT endpoints that might expose tokens
                findings.extend(self._test_jwt_endpoints(target.url))
        
        except Exception as e:
            logger.debug(f"JWT security scan error: {e}")
        
        return findings
    
    def _extract_jwt_tokens(self, url: str) -> List[str]:
        """Extract JWT tokens from response cookies and headers."""
        tokens = []
        
        try:
            response = self.session.get(url, timeout=10)
            
            # Check cookies
            for cookie_name, cookie_value in response.cookies.items():
                if self._is_jwt_token(cookie_value):
                    tokens.append(cookie_value)
                    logger.debug(f"Found JWT in cookie: {cookie_name}")
            
            # Check headers (Authorization, X-Auth-Token, etc.)
            auth_headers = [
                'Authorization',
                'X-Auth-Token',
                'X-Access-Token',
                'X-JWT-Token',
                'Token',
                'Access-Token',
            ]
            
            for header in auth_headers:
                if header in response.headers:
                    value = response.headers[header]
                    # Extract token from "Bearer <token>" format
                    if 'Bearer ' in value:
                        token = value.split('Bearer ')[1].strip()
                        if self._is_jwt_token(token):
                            tokens.append(token)
                    elif self._is_jwt_token(value):
                        tokens.append(value)
            
            # Check response body for JWT patterns
            jwt_pattern = r'\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b'
            matches = re.findall(jwt_pattern, response.text)
            for match in matches:
                if self._is_jwt_token(match):
                    tokens.append(match)
        
        except Exception as e:
            logger.debug(f"Error extracting JWT tokens: {e}")
        
        return list(set(tokens))  # Remove duplicates
    
    def _is_jwt_token(self, token: str) -> bool:
        """Check if a string is a JWT token."""
        if not token or len(token) < 10:
            return False
        
        # JWT format: header.payload.signature (3 parts separated by dots)
        parts = token.split('.')
        if len(parts) != 3:
            return False
        
        # Try to decode header (should be valid base64url JSON)
        try:
            header = parts[0]
            # Add padding if needed
            header += '=' * (4 - len(header) % 4)
            header_json = json.loads(base64.urlsafe_b64decode(header))
            # Check for JWT indicator
            if 'typ' in header_json and header_json['typ'].upper() in ['JWT', 'JWE']:
                return True
        except:
            pass
        
        # If it has 3 dot-separated base64url-like parts, likely JWT
        if all(len(part) > 10 and all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_' for c in part) for part in parts):
            return True
        
        return False
    
    def _decode_jwt(self, token: str) -> Optional[Dict[str, Any]]:
        """Decode JWT token and return header and payload."""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None
            
            header_part = parts[0]
            payload_part = parts[1]
            signature = parts[2]
            
            # Add padding
            header_part += '=' * (4 - len(header_part) % 4)
            payload_part += '=' * (4 - len(payload_part) % 4)
            
            header = json.loads(base64.urlsafe_b64decode(header_part))
            payload = json.loads(base64.urlsafe_b64decode(payload_part))
            
            return {
                'header': header,
                'payload': payload,
                'signature': signature,
                'raw': token
            }
        except Exception as e:
            logger.debug(f"Error decoding JWT: {e}")
            return None
    
    def _test_jwt_vulnerabilities(self, url: str, token: str) -> List[Finding]:
        """Test JWT token for security vulnerabilities."""
        findings = []
        
        decoded = self._decode_jwt(token)
        if not decoded:
            return findings
        
        header = decoded['header']
        payload = decoded['payload']
        
        # Test 1: Algorithm "none" vulnerability
        alg = header.get('alg', '').upper()
        if alg == 'NONE' or alg == '':
            # Get response for evidence collection
            try:
                test_response = self.session.get(url, timeout=5)
                evidence_data = EvidenceCollector.collect_request_response(test_response, request_url=url)
                evidence_str = EvidenceCollector.format_evidence_string(evidence_data)
                evidence_str += f"\nJWT Header: {json.dumps(header)}\nJWT Algorithm: {alg}"
            except:
                evidence_str = f"JWT header: {json.dumps(header)}. Algorithm: {alg}"
            
            findings.append(Finding(
                title="JWT Algorithm 'none' Vulnerability",
                description=f"JWT token uses 'none' algorithm, which allows signature verification to be bypassed. This enables token forgery attacks.",
                severity=FindingSeverity.CRITICAL,
                category=FindingCategory.VULNERABILITY,
                source_scanner=self.name,
                url=url,
                evidence=evidence_str,
                exploitation_details=f"Token uses algorithm '{alg}'. An attacker can forge tokens by setting algorithm to 'none' and removing the signature.",
                remediation="Never accept 'none' algorithm. Always verify the algorithm matches the expected value. Use RS256 or ES256 instead of HS256 when possible.",
                references=["https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/"],
                metadata={'algorithm': alg, 'header': header}
            ))
        
        # Test 2: Weak HMAC key (HS256 with weak/predictable secret)
        if alg == 'HS256':
            # Try common weak secrets
            weak_secrets = ['secret', 'password', '123456', 'admin', 'key', 'test', 'changeme']
            findings.append(Finding(
                title="JWT Using HS256 Algorithm",
                description=f"JWT uses HS256 (symmetric) algorithm. Verify the secret key is strong and not predictable. Weak keys enable token forgery.",
                severity=FindingSeverity.HIGH,
                category=FindingCategory.WEAK_SECURITY,
                source_scanner=self.name,
                url=url,
                evidence=f"Algorithm: {alg}",
                remediation="Use RS256 (asymmetric) when possible. If using HS256, ensure the secret is cryptographically random and sufficiently long (at least 256 bits).",
                metadata={'algorithm': alg}
            ))
        
        # Test 3: Missing expiration (exp claim)
        if 'exp' not in payload:
            findings.append(Finding(
                title="JWT Missing Expiration Claim",
                description=f"JWT token does not include 'exp' (expiration) claim, allowing tokens to remain valid indefinitely.",
                severity=FindingSeverity.MEDIUM,
                category=FindingCategory.WEAK_SECURITY,
                source_scanner=self.name,
                url=url,
                remediation="Always include 'exp' claim with appropriate expiration time. Implement token refresh mechanisms.",
                metadata={'payload_keys': list(payload.keys())}
            ))
        
        # Test 4: Expired but still accepted
        # This would require testing if expired tokens are rejected - complex, skip for now
        
        # Test 5: Algorithm confusion attack (try to use RS256 public key with HS256)
        # This requires public key - skip for automated testing
        
        # Test 6: Sensitive data in payload
        sensitive_keys = ['password', 'secret', 'key', 'private', 'ssn', 'credit_card', 'cvv']
        found_sensitive = [key for key in payload.keys() if any(s in key.lower() for s in sensitive_keys)]
        if found_sensitive:
            findings.append(Finding(
                title="Sensitive Data in JWT Payload",
                description=f"JWT payload contains potentially sensitive fields: {', '.join(found_sensitive)}. JWT tokens are often logged or exposed in client-side code.",
                severity=FindingSeverity.MEDIUM,
                category=FindingCategory.INFORMATION_DISCLOSURE,
                source_scanner=self.name,
                url=url,
                remediation="Avoid storing sensitive data in JWT payload. JWTs are base64-encoded (not encrypted) and often logged. Store only necessary identifiers.",
                metadata={'sensitive_fields': found_sensitive}
            ))
        
        # Test 7: Missing signature verification
        # Test by creating tampered token and seeing if it's accepted
        tampered_token = self._create_tampered_token(token)
        if tampered_token and self._test_token_accepted(url, tampered_token):
            findings.append(Finding(
                title="JWT Signature Verification Bypass",
                description=f"Application accepts JWT tokens with tampered signatures, indicating missing or weak signature verification.",
                severity=FindingSeverity.CRITICAL,
                category=FindingCategory.VULNERABILITY,
                source_scanner=self.name,
                url=url,
                evidence=f"Tampered token was accepted by the application",
                exploitation_details=f"Token signature was modified but still accepted. This allows token forgery attacks.",
                remediation="Always verify JWT signatures on the server side. Never trust client-provided algorithm claims. Use strong, cryptographically random secrets for HS256.",
                references=["https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/"],
            ))
        
        return findings
    
    def _create_tampered_token(self, original_token: str) -> Optional[str]:
        """Create a tampered JWT token with modified payload."""
        try:
            parts = original_token.split('.')
            if len(parts) != 3:
                return None
            
            header_part = parts[0]
            payload_part = parts[1]
            
            # Decode payload
            payload_part += '=' * (4 - len(payload_part) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_part))
            
            # Modify payload (change a field)
            if 'iat' in payload:
                payload['iat'] = payload.get('iat', 0) + 999999
            elif 'exp' in payload:
                payload['exp'] = payload.get('exp', 0) + 999999
            else:
                payload['tampered'] = True
            
            # Re-encode
            new_payload = base64.urlsafe_b64encode(
                json.dumps(payload, separators=(',', ':')).encode()
            ).decode().rstrip('=')
            
            # Create token with modified payload but original signature (invalid)
            return f"{header_part}.{new_payload}.TAMPERED_SIGNATURE"
        except:
            return None
    
    def _test_token_accepted(self, url: str, token: str) -> bool:
        """Test if a token is accepted by the application."""
        try:
            # Try using token in Authorization header
            test_session = requests.Session()
            test_session.headers['Authorization'] = f'Bearer {token}'
            response = test_session.get(url, timeout=5)
            
            # If we get 200 or similar (not 401/403), token might be accepted
            # This is a simple check - in reality, we'd need to test authenticated endpoints
            return response.status_code < 400
        except:
            return False
    
    def _try_obtain_jwt(self, url: str) -> List[str]:
        """Try to obtain JWT by attempting common authentication endpoints."""
        tokens = []
        auth_endpoints = [
            '/api/login',
            '/api/auth/login',
            '/login',
            '/auth/login',
            '/api/token',
            '/token',
            '/oauth/token',
            '/api/authenticate',
        ]
        
        for endpoint in auth_endpoints:
            try:
                test_url = urljoin(url, endpoint)
                # Try POST with common credentials
                response = self.session.post(
                    test_url,
                    json={'username': 'test', 'password': 'test'},
                    timeout=5
                )
                
                # Check response for JWT
                jwt_tokens_found = self._extract_jwt_tokens_from_response(response)
                tokens.extend(jwt_tokens_found)
            except:
                continue
        
        return tokens
    
    def _extract_jwt_tokens_from_response(self, response: requests.Response) -> List[str]:
        """Extract JWT tokens from a response."""
        tokens = []
        
        # Check JSON response
        try:
            data = response.json()
            if isinstance(data, dict):
                for value in data.values():
                    if isinstance(value, str) and self._is_jwt_token(value):
                        tokens.append(value)
        except:
            pass
        
        # Check response text
        jwt_pattern = r'\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b'
        matches = re.findall(jwt_pattern, response.text)
        for match in matches:
            if self._is_jwt_token(match):
                tokens.append(match)
        
        return tokens
    
    def _test_jwt_endpoints(self, url: str) -> List[Finding]:
        """Test for exposed JWT endpoints or information disclosure."""
        findings = []
        endpoints = [
            '/.well-known/jwks.json',
            '/.well-known/oauth-authorization-server',
            '/.well-known/openid-configuration',
            '/jwks',
            '/oauth/keys',
        ]
        
        for endpoint in endpoints:
            try:
                test_url = urljoin(url, endpoint)
                response = self.session.get(test_url, timeout=5)
                
                if response.status_code == 200:
                    findings.append(Finding(
                        title=f"JWT/OpenID Configuration Endpoint Exposed",
                        description=f"JWT configuration endpoint found at {test_url}. This may expose public keys or configuration information.",
                        severity=FindingSeverity.INFO,
                        category=FindingCategory.INFORMATION_DISCLOSURE,
                        source_scanner=self.name,
                        url=test_url,
                        evidence=f"Endpoint returned status {response.status_code}",
                        remediation="Ensure exposed endpoints do not reveal sensitive information. Public key endpoints are acceptable but should be reviewed.",
                        metadata={'endpoint': endpoint, 'status_code': response.status_code}
                    ))
            except:
                continue
        
        return findings
