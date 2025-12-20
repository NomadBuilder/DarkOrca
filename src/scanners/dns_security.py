"""DNS security and configuration analyzer."""

import logging
from typing import List, Optional
from urllib.parse import urlparse

from .base import BaseScanner
from ..models.scan import ScanTarget
from ..models.finding import Finding, FindingSeverity, FindingCategory
from ..models.scan_mode import ScanMode

logger = logging.getLogger(__name__)

# Optional DNS resolver import
try:
    import dns.resolver
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


class DNSSecurityAnalyzer(BaseScanner):
    """Analyze DNS security configuration."""
    
    def __init__(self, enabled: bool = True, scan_mode: ScanMode = ScanMode.DEFENSIVE):
        """Initialize DNS security analyzer."""
        super().__init__(
            name="dns_security",
            command=None,  # Python-based
            enabled=enabled,
            scan_mode=scan_mode
        )
    
    def scan(self, target: ScanTarget) -> List[Finding]:
        """Analyze DNS security."""
        findings = []
        
        if not self.is_available():
            return findings
        
        try:
            parsed = urlparse(target.url)
            domain = parsed.hostname or parsed.netloc
            
            if not domain:
                return findings
            
            # Remove port if present
            domain = domain.split(':')[0]
            
            findings.extend(self._check_dnssec(domain, target.url))
            findings.extend(self._check_spf_record(domain, target.url))
            findings.extend(self._check_dmarc_record(domain, target.url))
            findings.extend(self._check_dkim_record(domain, target.url))
            findings.extend(self._check_caa_record(domain, target.url))
            findings.extend(self._check_dns_over_https(domain, target.url))
            
        except Exception as e:
            logger.error(f"DNS security analysis failed: {e}", exc_info=True)
        
        return findings
    
    def _check_dnssec(self, domain: str, base_url: str) -> List[Finding]:
        """Check if DNSSEC is enabled."""
        findings = []
        
        try:
            # Try to get DNSKEY record (indicates DNSSEC)
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            
            try:
                answers = resolver.resolve(domain, 'DNSKEY')
                if answers:
                    findings.append(Finding(
                        title="DNSSEC Enabled",
                        description=f"Domain {domain} has DNSSEC enabled, providing DNS authentication.",
                        severity=FindingSeverity.INFO,
                        category=FindingCategory.FINGERPRINTING,
                        source_scanner=self.name,
                        url=base_url,
                    ))
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
                findings.append(Finding(
                    title="DNSSEC Not Detected",
                    description=f"Domain {domain} does not appear to have DNSSEC enabled. DNSSEC provides DNS authentication and prevents DNS spoofing.",
                    severity=FindingSeverity.LOW,
                    category=FindingCategory.MISCONFIGURATION,
                    source_scanner=self.name,
                    url=base_url,
                    remediation="Enable DNSSEC through your DNS provider to prevent DNS spoofing attacks.",
                    references=["https://www.cloudflare.com/learning/dns/dnssec/"]
                ))
        except Exception as e:
            logger.debug(f"DNSSEC check error for {domain}: {e}")
        
        return findings
    
    def _check_spf_record(self, domain: str, base_url: str) -> List[Finding]:
        """Check SPF record for email security."""
        findings = []
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            
            try:
                answers = resolver.resolve(domain, 'TXT')
                spf_found = False
                
                for rdata in answers:
                    txt_record = ''.join([s.decode() if isinstance(s, bytes) else str(s) for s in rdata.strings])
                    if txt_record.startswith('v=spf1'):
                        spf_found = True
                        
                        # Check for weak SPF
                        if '~all' in txt_record or '-all' not in txt_record:
                            findings.append(Finding(
                                title="SPF Record Present (Weak Configuration)",
                                description=f"SPF record found but uses '~all' or missing '-all', which is less secure.",
                                severity=FindingSeverity.MEDIUM,
                                category=FindingCategory.WEAK_SECURITY,
                                source_scanner=self.name,
                                url=base_url,
                                remediation="Update SPF record to use '-all' instead of '~all' for stricter email validation.",
                                metadata={'spf_record': txt_record}
                            ))
                        else:
                            findings.append(Finding(
                                title="SPF Record Present",
                                description=f"Domain has SPF record configured: {txt_record[:100]}",
                                severity=FindingSeverity.INFO,
                                category=FindingCategory.FINGERPRINTING,
                                source_scanner=self.name,
                                url=base_url,
                                metadata={'spf_record': txt_record}
                            ))
                        break
                
                if not spf_found:
                    findings.append(Finding(
                        title="SPF Record Missing",
                        description=f"Domain {domain} does not have an SPF record. This allows email spoofing.",
                        severity=FindingSeverity.MEDIUM,
                        category=FindingCategory.MISCONFIGURATION,
                        source_scanner=self.name,
                        url=base_url,
                        remediation="Add SPF record: v=spf1 include:_spf.google.com ~all (adjust for your email provider)",
                        references=["https://www.cloudflare.com/learning/dns/dns-records/dns-spf-record/"]
                    ))
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                findings.append(Finding(
                    title="SPF Record Missing",
                    description=f"Domain {domain} does not have an SPF record.",
                    severity=FindingSeverity.MEDIUM,
                    category=FindingCategory.MISCONFIGURATION,
                    source_scanner=self.name,
                    url=base_url,
                    remediation="Add SPF record to prevent email spoofing.",
                ))
        except Exception as e:
            logger.debug(f"SPF check error for {domain}: {e}")
        
        return findings
    
    def _check_dmarc_record(self, domain: str, base_url: str) -> List[Finding]:
        """Check DMARC record for email security."""
        findings = []
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            
            try:
                answers = resolver.resolve(f'_dmarc.{domain}', 'TXT')
                dmarc_found = False
                
                for rdata in answers:
                    txt_record = ''.join([s.decode() if isinstance(s, bytes) else str(s) for s in rdata.strings])
                    if txt_record.startswith('v=DMARC1'):
                        dmarc_found = True
                        
                        # Check policy
                        if 'p=none' in txt_record:
                            findings.append(Finding(
                                title="DMARC Record Present (Weak Policy)",
                                description=f"DMARC record found but uses 'p=none' policy, which does not enforce email authentication.",
                                severity=FindingSeverity.MEDIUM,
                                category=FindingCategory.WEAK_SECURITY,
                                source_scanner=self.name,
                                url=base_url,
                                remediation="Update DMARC policy to 'p=quarantine' or 'p=reject' for better email security.",
                                metadata={'dmarc_record': txt_record}
                            ))
                        else:
                            findings.append(Finding(
                                title="DMARC Record Present",
                                description=f"Domain has DMARC record configured: {txt_record[:100]}",
                                severity=FindingSeverity.INFO,
                                category=FindingCategory.FINGERPRINTING,
                                source_scanner=self.name,
                                url=base_url,
                                metadata={'dmarc_record': txt_record}
                            ))
                        break
                
                if not dmarc_found:
                    findings.append(Finding(
                        title="DMARC Record Missing",
                        description=f"Domain {domain} does not have a DMARC record. This reduces email security.",
                        severity=FindingSeverity.MEDIUM,
                        category=FindingCategory.MISCONFIGURATION,
                        source_scanner=self.name,
                        url=base_url,
                        remediation="Add DMARC record: v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com",
                        references=["https://www.cloudflare.com/learning/email-security/what-is-dmarc/"]
                    ))
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                findings.append(Finding(
                    title="DMARC Record Missing",
                    description=f"Domain {domain} does not have a DMARC record.",
                    severity=FindingSeverity.MEDIUM,
                    category=FindingCategory.MISCONFIGURATION,
                    source_scanner=self.name,
                    url=base_url,
                    remediation="Add DMARC record to improve email security.",
                ))
        except Exception as e:
            logger.debug(f"DMARC check error for {domain}: {e}")
        
        return findings
    
    def _check_dkim_record(self, domain: str, base_url: str) -> List[Finding]:
        """Check for DKIM record."""
        findings = []
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            
            # Check common DKIM selectors
            common_selectors = ['default', 'google', 'selector1', 'dkim']
            dkim_found = False
            
            for selector in common_selectors:
                try:
                    answers = resolver.resolve(f'{selector}._domainkey.{domain}', 'TXT')
                    if answers:
                        dkim_found = True
                        findings.append(Finding(
                            title="DKIM Record Present",
                            description=f"Domain has DKIM record configured (selector: {selector}).",
                            severity=FindingSeverity.INFO,
                            category=FindingCategory.FINGERPRINTING,
                            source_scanner=self.name,
                            url=base_url,
                        ))
                        break
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    continue
            
            if not dkim_found:
                findings.append(Finding(
                    title="DKIM Record Not Detected",
                    description=f"Domain {domain} does not appear to have DKIM configured (checked common selectors).",
                    severity=FindingSeverity.LOW,
                    category=FindingCategory.MISCONFIGURATION,
                    source_scanner=self.name,
                    url=base_url,
                    remediation="Configure DKIM for your email provider to sign outgoing emails.",
                    references=["https://www.cloudflare.com/learning/email-security/what-is-dkim/"]
                ))
        except Exception as e:
            logger.debug(f"DKIM check error for {domain}: {e}")
        
        return findings
    
    def _check_caa_record(self, domain: str, base_url: str) -> List[Finding]:
        """Check CAA (Certificate Authority Authorization) record."""
        findings = []
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            
            try:
                answers = resolver.resolve(domain, 'CAA')
                if answers:
                    findings.append(Finding(
                        title="CAA Record Present",
                        description=f"Domain has CAA record configured, restricting which CAs can issue certificates.",
                        severity=FindingSeverity.INFO,
                        category=FindingCategory.FINGERPRINTING,
                        source_scanner=self.name,
                        url=base_url,
                    ))
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                findings.append(Finding(
                    title="CAA Record Missing",
                    description=f"Domain {domain} does not have a CAA record. CAA records restrict which certificate authorities can issue certificates for your domain.",
                    severity=FindingSeverity.LOW,
                    category=FindingCategory.MISCONFIGURATION,
                    source_scanner=self.name,
                    url=base_url,
                    remediation="Add CAA record: 0 issue \"letsencrypt.org\" (or your preferred CA)",
                    references=["https://www.cloudflare.com/learning/ssl/what-is-caa-record/"]
                ))
        except Exception as e:
            logger.debug(f"CAA check error for {domain}: {e}")
        
        return findings
    
    def _check_dns_over_https(self, domain: str, base_url: str) -> List[Finding]:
        """Check if DNS over HTTPS is supported (informational)."""
        findings = []
        
        # This is informational - we can't easily test DoH support
        # But we can note it as a best practice
        findings.append(Finding(
            title="DNS Security Best Practices",
            description="Consider using DNS over HTTPS (DoH) or DNS over TLS (DoT) for encrypted DNS queries.",
            severity=FindingSeverity.INFO,
            category=FindingCategory.FINGERPRINTING,
            source_scanner=self.name,
            url=base_url,
            remediation="Configure DoH/DoT for enhanced DNS privacy and security.",
        ))
        
        return findings
    
    def is_available(self) -> bool:
        """Check if dnspython is available."""
        return DNS_AVAILABLE

