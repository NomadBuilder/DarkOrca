"""Comprehensive security headers analyzer."""

import requests
import logging
from typing import List, Dict, Optional
from urllib.parse import urlparse

from .base import BaseScanner
from ..models.scan import ScanTarget
from ..models.finding import Finding, FindingSeverity, FindingCategory
from ..models.scan_mode import ScanMode

logger = logging.getLogger(__name__)


class SecurityHeadersAnalyzer(BaseScanner):
    """Analyze security headers comprehensively."""
    
    # Security headers and their recommended values
    SECURITY_HEADERS = {
        'Content-Security-Policy': {
            'required': True,
            'severity': FindingSeverity.LOW,  # Changed from HIGH - missing CSP is hardening, not vulnerability
            'description': 'Prevents XSS attacks by controlling which resources can be loaded (hardening measure)',
            'recommended': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
        },
        'Strict-Transport-Security': {
            'required': True,
            'severity': FindingSeverity.MEDIUM,  # Changed from HIGH - hardening measure
            'description': 'Forces browsers to use HTTPS connections (hardening measure)',
            'recommended': 'max-age=31536000; includeSubDomains; preload',
        },
        'X-Content-Type-Options': {
            'required': True,
            'severity': FindingSeverity.MEDIUM,
            'description': 'Prevents MIME type sniffing attacks',
            'recommended': 'nosniff',
        },
        'X-Frame-Options': {
            'required': True,
            'severity': FindingSeverity.MEDIUM,
            'description': 'Prevents clickjacking attacks',
            'recommended': 'DENY or SAMEORIGIN',
        },
        'X-XSS-Protection': {
            'required': False,  # Deprecated but still used
            'severity': FindingSeverity.LOW,
            'description': 'Legacy XSS protection (deprecated, CSP is preferred)',
            'recommended': '1; mode=block',
        },
        'Referrer-Policy': {
            'required': True,
            'severity': FindingSeverity.LOW,
            'description': 'Controls referrer information sent with requests',
            'recommended': 'strict-origin-when-cross-origin',
        },
        'Permissions-Policy': {
            'required': True,
            'severity': FindingSeverity.LOW,
            'description': 'Controls browser features and APIs',
            'recommended': "geolocation=(), microphone=(), camera=()",
        },
        'Cross-Origin-Embedder-Policy': {
            'required': False,
            'severity': FindingSeverity.INFO,
            'description': 'Isolates browsing context for better security',
            'recommended': 'require-corp',
        },
        'Cross-Origin-Opener-Policy': {
            'required': False,
            'severity': FindingSeverity.INFO,
            'description': 'Isolates browsing context from cross-origin documents',
            'recommended': 'same-origin',
        },
        'Cross-Origin-Resource-Policy': {
            'required': False,
            'severity': FindingSeverity.INFO,
            'description': 'Prevents other sites from embedding resources',
            'recommended': 'same-origin',
        },
    }
    
    def __init__(self, enabled: bool = True, scan_mode: ScanMode = ScanMode.DEFENSIVE):
        """Initialize security headers analyzer."""
        super().__init__(
            name="security_headers",
            command=None,  # Python-based
            enabled=enabled,
            scan_mode=scan_mode
        )
    
    def scan(self, target: ScanTarget) -> List[Finding]:
        """Analyze security headers."""
        findings = []
        
        if not self.is_available():
            return findings
        
        try:
            # Make request to get headers
            response = requests.get(
                target.url,
                timeout=10,
                allow_redirects=True,
                verify=False,  # Don't verify SSL for header checking
                headers={'User-Agent': 'SecurityScan/1.0'}
            )
            
            headers = response.headers
            missing_headers = []
            weak_headers = []
            
            # Check each security header
            for header_name, header_config in self.SECURITY_HEADERS.items():
                header_value = headers.get(header_name, '').strip()
                
                if not header_value:
                    if header_config['required']:
                        missing_headers.append({
                            'name': header_name,
                            'severity': header_config['severity'],
                            'description': header_config['description'],
                            'recommended': header_config['recommended'],
                        })
                else:
                    # Check for weak configurations
                    weak = self._check_weak_configuration(header_name, header_value, header_config)
                    if weak:
                        weak_headers.append({
                            'name': header_name,
                            'value': header_value,
                            'issue': weak,
                            'recommended': header_config['recommended'],
                        })
            
            # Create findings
            if missing_headers:
                # Group missing headers by severity
                high_missing = [h for h in missing_headers if h['severity'] == FindingSeverity.HIGH]
                medium_missing = [h for h in missing_headers if h['severity'] == FindingSeverity.MEDIUM]
                low_missing = [h for h in missing_headers if h['severity'] == FindingSeverity.LOW]
                
                if high_missing:
                    findings.append(Finding(
                        title=f"Missing Critical Security Headers ({len(high_missing)})",
                        description=f"Missing high-priority security headers: {', '.join([h['name'] for h in high_missing])}",
                        severity=FindingSeverity.HIGH,
                        category=FindingCategory.MISCONFIGURATION,
                        source_scanner=self.name,
                        url=target.url,
                        remediation=self._generate_header_remediation(missing_headers),
                        metadata={'missing_headers': [h['name'] for h in missing_headers]},
                    ))
                elif medium_missing:
                    findings.append(Finding(
                        title=f"Missing Security Headers ({len(medium_missing)})",
                        description=f"Missing security headers: {', '.join([h['name'] for h in medium_missing])}",
                        severity=FindingSeverity.MEDIUM,
                        category=FindingCategory.MISCONFIGURATION,
                        source_scanner=self.name,
                        url=target.url,
                        remediation=self._generate_header_remediation(missing_headers),
                    ))
                elif low_missing:
                    findings.append(Finding(
                        title=f"Missing Optional Security Headers ({len(low_missing)})",
                        description=f"Missing optional security headers: {', '.join([h['name'] for h in low_missing])}",
                        severity=FindingSeverity.LOW,
                        category=FindingCategory.MISCONFIGURATION,
                        source_scanner=self.name,
                        url=target.url,
                        remediation=self._generate_header_remediation(missing_headers),
                    ))
            
            # Report weak configurations (reduce severity - these are hardening recommendations)
            for weak_header in weak_headers:
                # Determine severity based on actual risk
                if weak_header['name'] == 'Strict-Transport-Security':
                    # HSTS issues are generally LOW - hardening recommendations
                    severity = FindingSeverity.LOW
                elif weak_header['name'] in ['Content-Security-Policy', 'X-Frame-Options']:
                    # CSP and X-Frame-Options weak configs are LOW - hardening
                    severity = FindingSeverity.LOW
                else:
                    severity = FindingSeverity.LOW  # Default to LOW for hardening items
                
                findings.append(Finding(
                    title=f"{weak_header['name']} Configuration Recommendation",
                    description=f"{weak_header['name']} is set but could be improved: {weak_header['issue']}. Current value: {weak_header['value']}",
                    severity=severity,
                    category=FindingCategory.WEAK_SECURITY,
                    source_scanner=self.name,
                    url=target.url,
                    remediation=f"Consider updating {weak_header['name']} to: {weak_header['recommended']}",
                ))
            
            # Report present headers (informational)
            present_headers = [h for h in self.SECURITY_HEADERS.keys() if headers.get(h)]
            if present_headers:
                findings.append(Finding(
                    title="Security Headers Present",
                    description=f"Found {len(present_headers)} security headers: {', '.join(present_headers)}",
                    severity=FindingSeverity.INFO,
                    category=FindingCategory.FINGERPRINTING,
                    source_scanner=self.name,
                    url=target.url,
                    metadata={'present_headers': present_headers},
                ))
            
        except requests.exceptions.RequestException as e:
            logger.debug(f"Security headers check failed for {target.url}: {e}")
        except Exception as e:
            logger.error(f"Security headers analysis error: {e}", exc_info=True)
        
        return findings
    
    def _check_weak_configuration(self, header_name: str, header_value: str, config: Dict) -> Optional[str]:
        """Check if header has weak configuration."""
        value_lower = header_value.lower()
        
        if header_name == 'Strict-Transport-Security':
            if 'max-age=0' in value_lower:
                return "HSTS max-age is 0, which disables HSTS"
            if 'max-age' not in value_lower:
                return "HSTS missing max-age directive"
            # Missing includeSubDomains is LOW severity - only matters if you have subdomains
            # Don't report this as a weak configuration, it's a hardening recommendation
            # Removed: if 'includesubdomains' not in value_lower check
        
        elif header_name == 'X-Frame-Options':
            # SAMEORIGIN is valid - don't flag it
            # Only flag invalid values
            if value_lower not in ['deny', 'sameorigin', 'same-origin', 'allow-from']:
                return f"X-Frame-Options has invalid value: {header_value}"
            # Note: Duplicate headers (SAMEORIGIN, SAMEORIGIN) are cosmetic - don't report
        
        elif header_name == 'X-Content-Type-Options':
            if value_lower != 'nosniff':
                return f"X-Content-Type-Options should be 'nosniff', got: {header_value}"
        
        elif header_name == 'Content-Security-Policy':
            if "'unsafe-inline'" in value_lower and "'unsafe-eval'" in value_lower:
                return "CSP allows unsafe-inline and unsafe-eval, which reduces security"
            if "default-src *" in value_lower:
                return "CSP default-src is too permissive (allows all sources)"
        
        elif header_name == 'Referrer-Policy':
            weak_policies = ['no-referrer-when-downgrade', 'unsafe-url']
            if any(policy in value_lower for policy in weak_policies):
                return f"Referrer-Policy '{header_value}' is less secure than recommended"
        
        return None
    
    def _generate_header_remediation(self, missing_headers: List[Dict]) -> str:
        """Generate remediation guidance for missing headers."""
        lines = ["Add the following security headers to your web server configuration:"]
        for header in missing_headers:
            lines.append(f"\n{header['name']}: {header['recommended']}")
            lines.append(f"  ({header['description']})")
        
        lines.append("\nFor Apache, add to .htaccess or httpd.conf:")
        lines.append("  Header set Content-Security-Policy \"default-src 'self'\"")
        lines.append("\nFor Nginx, add to server block:")
        lines.append("  add_header Content-Security-Policy \"default-src 'self'\";")
        
        return "\n".join(lines)
    
    def is_available(self) -> bool:
        """Security headers analyzer is always available."""
        return True

