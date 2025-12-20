"""SSL/TLS security analyzer for defensive scanning."""

import ssl
import socket
import logging
from typing import List, Optional
from urllib.parse import urlparse
import requests
from datetime import datetime

from .base import BaseScanner
from ..models.scan import ScanTarget
from ..models.finding import Finding, FindingSeverity, FindingCategory
from ..models.scan_mode import ScanMode

logger = logging.getLogger(__name__)


class SSLAnalyzer(BaseScanner):
    """Analyze SSL/TLS configuration and security."""
    
    def __init__(self, enabled: bool = True, scan_mode: ScanMode = ScanMode.DEFENSIVE):
        """Initialize SSL analyzer."""
        super().__init__(
            name="ssl_analyzer",
            command=None,  # Python-based, no external command
            enabled=enabled,
            scan_mode=scan_mode
        )
    
    def scan(self, target: ScanTarget) -> List[Finding]:
        """Analyze SSL/TLS configuration."""
        findings = []
        
        if not self.is_available():
            return findings
        
        try:
            parsed = urlparse(target.url)
            hostname = parsed.hostname or parsed.netloc
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            
            if parsed.scheme != 'https':
                # Try HTTPS even if URL is HTTP
                port = 443
            
            findings.extend(self._analyze_ssl_config(hostname, port, target.url))
            findings.extend(self._check_certificate_info(hostname, port, target.url))
            findings.extend(self._check_tls_versions(hostname, port, target.url))
            findings.extend(self._check_cipher_suites(hostname, port, target.url))
            
        except Exception as e:
            logger.error(f"SSL analysis failed: {e}", exc_info=True)
        
        return findings
    
    def _analyze_ssl_config(self, hostname: str, port: int, base_url: str) -> List[Finding]:
        """Analyze SSL configuration."""
        findings = []
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    protocol = ssock.version()
                    
                    # Check TLS version
                    if protocol in ['TLSv1', 'TLSv1.1']:
                        findings.append(Finding(
                            title="Weak TLS Version",
                            description=f"Server uses {protocol}, which is deprecated and vulnerable. Should use TLS 1.2 or higher.",
                            severity=FindingSeverity.HIGH,
                            category=FindingCategory.WEAK_SECURITY,
                            source_scanner=self.name,
                            url=base_url,
                            remediation="Upgrade to TLS 1.2 or TLS 1.3. Disable TLS 1.0 and TLS 1.1.",
                            references=[
                                "https://owasp.org/www-community/vulnerabilities/Weak_Cryptographic_Algorithm",
                                "https://tools.ietf.org/html/rfc8996"
                            ]
                        ))
                    elif protocol == 'TLSv1.2':
                        findings.append(Finding(
                            title="TLS 1.2 Detected",
                            description=f"Server uses TLS 1.2. Consider upgrading to TLS 1.3 for better security.",
                            severity=FindingSeverity.INFO,
                            category=FindingCategory.FINGERPRINTING,
                            source_scanner=self.name,
                            url=base_url,
                            remediation="Upgrade to TLS 1.3 for improved security and performance.",
                        ))
                    elif protocol == 'TLSv1.3':
                        findings.append(Finding(
                            title="TLS 1.3 Detected",
                            description=f"Server uses modern TLS 1.3 protocol.",
                            severity=FindingSeverity.INFO,
                            category=FindingCategory.FINGERPRINTING,
                            source_scanner=self.name,
                            url=base_url,
                        ))
                    
                    # Check certificate validity
                    if cert:
                        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        days_until_expiry = (not_after - datetime.now()).days
                        
                        if days_until_expiry < 30:
                            findings.append(Finding(
                                title="SSL Certificate Expiring Soon",
                                description=f"SSL certificate expires in {days_until_expiry} days. Certificate should be renewed.",
                                severity=FindingSeverity.MEDIUM,
                                category=FindingCategory.MISCONFIGURATION,
                                source_scanner=self.name,
                                url=base_url,
                                remediation=f"Renew SSL certificate before expiration ({not_after.strftime('%Y-%m-%d')}).",
                            ))
                        
                        # Check certificate issuer
                        issuer = dict(x[0] for x in cert.get('issuer', []))
                        issuer_name = issuer.get('commonName', 'Unknown')
                        
                        findings.append(Finding(
                            title="SSL Certificate Information",
                            description=f"Certificate issued by {issuer_name}, expires {not_after.strftime('%Y-%m-%d')}.",
                            severity=FindingSeverity.INFO,
                            category=FindingCategory.FINGERPRINTING,
                            source_scanner=self.name,
                            url=base_url,
                            metadata={'issuer': issuer_name, 'expires': not_after.isoformat(), 'days_until_expiry': days_until_expiry}
                        ))
        
        except ssl.SSLError as e:
            findings.append(Finding(
                title="SSL/TLS Connection Error",
                description=f"Failed to establish SSL/TLS connection: {str(e)}",
                severity=FindingSeverity.MEDIUM,
                category=FindingCategory.MISCONFIGURATION,
                source_scanner=self.name,
                url=base_url,
            ))
        except (socket.timeout, ConnectionRefusedError, OSError):
            # Not an HTTPS endpoint or not reachable
            pass
        except Exception as e:
            logger.debug(f"SSL analysis error for {hostname}:{port}: {e}")
        
        return findings
    
    def _check_certificate_info(self, hostname: str, port: int, base_url: str) -> List[Finding]:
        """Check certificate details."""
        findings = []
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check for wildcard certificate
                    subject = dict(x[0] for x in cert.get('subject', []))
                    common_name = subject.get('commonName', '')
                    
                    if '*' in common_name:
                        findings.append(Finding(
                            title="Wildcard SSL Certificate",
                            description=f"Server uses wildcard certificate ({common_name}). This is acceptable but limits certificate scope.",
                            severity=FindingSeverity.INFO,
                            category=FindingCategory.FINGERPRINTING,
                            source_scanner=self.name,
                            url=base_url,
                        ))
                    
                    # Check subject alternative names
                    san = cert.get('subjectAltName', [])
                    if san:
                        domains = [name[1] for name in san if name[0] == 'DNS']
                        if len(domains) > 1:
                            findings.append(Finding(
                                title="Multi-Domain SSL Certificate",
                                description=f"Certificate covers {len(domains)} domains: {', '.join(domains[:3])}{'...' if len(domains) > 3 else ''}",
                                severity=FindingSeverity.INFO,
                                category=FindingCategory.FINGERPRINTING,
                                source_scanner=self.name,
                                url=base_url,
                                metadata={'domains': domains}
                            ))
        
        except Exception as e:
            logger.debug(f"Certificate info check error: {e}")
        
        return findings
    
    def _check_tls_versions(self, hostname: str, port: int, base_url: str) -> List[Finding]:
        """Check supported TLS versions."""
        findings = []
        
        tls_versions = {
            'PROTOCOL_TLSv1': 'TLS 1.0',
            'PROTOCOL_TLSv1_1': 'TLS 1.1',
            'PROTOCOL_TLSv1_2': 'TLS 1.2',
            'PROTOCOL_TLSv1_3': 'TLS 1.3',
        }
        
        supported_versions = []
        
        for version_name, version_display in tls_versions.items():
            try:
                if hasattr(ssl, version_name):
                    version_constant = getattr(ssl, version_name)
                    context = ssl.SSLContext(version_constant)
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                    with socket.create_connection((hostname, port), timeout=3) as sock:
                        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                            supported_versions.append(version_display)
            except:
                pass
        
        if supported_versions:
            # Check for weak versions
            weak_versions = [v for v in supported_versions if v in ['TLS 1.0', 'TLS 1.1']]
            if weak_versions:
                findings.append(Finding(
                    title="Weak TLS Versions Supported",
                    description=f"Server supports deprecated TLS versions: {', '.join(weak_versions)}. These should be disabled.",
                    severity=FindingSeverity.HIGH,
                    category=FindingCategory.WEAK_SECURITY,
                    source_scanner=self.name,
                    url=base_url,
                    remediation="Disable TLS 1.0 and TLS 1.1. Only allow TLS 1.2 and TLS 1.3.",
                    references=["https://tools.ietf.org/html/rfc8996"]
                ))
            
            findings.append(Finding(
                title="Supported TLS Versions",
                description=f"Server supports: {', '.join(supported_versions)}",
                severity=FindingSeverity.INFO,
                category=FindingCategory.FINGERPRINTING,
                source_scanner=self.name,
                url=base_url,
                metadata={'supported_versions': supported_versions}
            ))
        
        return findings
    
    def _check_cipher_suites(self, hostname: str, port: int, base_url: str) -> List[Finding]:
        """Check cipher suite configuration."""
        findings = []
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    if cipher:
                        cipher_name, version, bits = cipher
                        
                        # Check for weak ciphers
                        weak_ciphers = ['RC4', 'DES', 'MD5', 'SHA1']
                        if any(weak in cipher_name for weak in weak_ciphers):
                            findings.append(Finding(
                                title="Weak Cipher Suite",
                                description=f"Server uses weak cipher suite: {cipher_name}",
                                severity=FindingSeverity.HIGH,
                                category=FindingCategory.WEAK_SECURITY,
                                source_scanner=self.name,
                                url=base_url,
                                remediation="Disable weak cipher suites. Use only strong, modern ciphers.",
                                references=["https://owasp.org/www-community/vulnerabilities/Weak_Cryptographic_Algorithm"]
                            ))
                        
                        findings.append(Finding(
                            title="Cipher Suite Information",
                            description=f"Active cipher: {cipher_name} ({bits} bits)",
                            severity=FindingSeverity.INFO,
                            category=FindingCategory.FINGERPRINTING,
                            source_scanner=self.name,
                            url=base_url,
                            metadata={'cipher': cipher_name, 'version': version, 'bits': bits}
                        ))
        except Exception as e:
            logger.debug(f"Cipher suite check error: {e}")
        
        return findings
    
    def is_available(self) -> bool:
        """SSL analyzer is always available (uses Python standard library)."""
        return True

