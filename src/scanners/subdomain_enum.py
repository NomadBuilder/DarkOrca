"""Subdomain enumeration scanner."""

import os
import re
import subprocess
import json
from typing import List, Optional, Set, Dict, Any

# Optional DNS resolver import
try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

from .base import BaseScanner
from ..models.scan import ScanTarget
from ..models.finding import Finding, FindingSeverity, FindingCategory
from ..models.scan_mode import ScanMode

import logging
logger = logging.getLogger(__name__)


class SubdomainEnum(BaseScanner):
    """Subdomain enumeration using multiple methods."""
    
    def __init__(self, enabled: bool = True, scan_mode: ScanMode = ScanMode.DEFENSIVE):
        """
        Initialize subdomain enumeration scanner.
        
        Args:
            enabled: Whether scanner is enabled
            scan_mode: Scan mode (defensive or offensive)
        """
        super().__init__(
            name="subdomain_enum",
            command="subfinder",  # Primary tool
            enabled=enabled,
            scan_mode=scan_mode
        )
        self.fallback_tools = ["amass", "dnsrecon"]
        self.common_subdomains = [
            "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
            "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
            "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn",
            "ns3", "mail2", "new", "mysql", "old", "lists", "support", "mobile", "mx",
            "static", "docs", "beta", "web", "lb", "lb1", "web2", "demo", "ipv4",
            "api", "www1", "cdn", "api-www", "www-api", "www3", "admin2", "shop",
            "secure", "server", "mx1", "chat", "wap", "m2", "api1", "srv", "ad",
            "clients", "blog2", "mx2", "www4", "crm", "mail1", "sip", "dns2",
            "api2", "media", "ns4", "www5", "portal", "static1", "mx3", "www6",
            "email", "images", "img", "www7", "host", "smtp2", "proxy", "dns1",
            "api3", "big", "mx4", "cdn2", "api4", "ns5", "www8", "www9", "feeds",
            "mail3", "www10", "ftp2", "staging", "stage", "test2", "dev2", "stg",
            "preprod", "pre-prod", "preprod2", "staging2", "stage2", "stg2",
            "uat", "qa", "qa2", "test3", "demo2", "sandbox", "sandbox2"
        ]
    
    def is_available(self) -> bool:
        """Check if subdomain enumeration tools are available."""
        try:
            import shutil
            # Check for subfinder
            if shutil.which("subfinder") or shutil.which(os.path.expanduser("~/go/bin/subfinder")):
                return True
            # Check for amass
            if shutil.which("amass") or shutil.which(os.path.expanduser("~/go/bin/amass")):
                return True
            # Check for dnsrecon
            if shutil.which("dnsrecon"):
                return True
            # Check for dnspython (for DNS brute forcing fallback)
            if DNS_AVAILABLE:
                return True
            return False
        except:
            return False
    
    def scan(self, target: ScanTarget) -> List[Finding]:
        """Enumerate subdomains for target domain."""
        if not target.domain:
            # Extract domain from URL
            from urllib.parse import urlparse
            parsed = urlparse(target.url)
            domain = parsed.netloc or parsed.path.split("/")[0]
            if not domain:
                logger.warning("Could not extract domain for subdomain enumeration")
                return []
        else:
            domain = target.domain
        
        # Remove port if present
        domain = domain.split(':')[0]
        
        findings = []
        subdomains: Set[str] = set()
        
        # Method 1: Use subfinder (fastest, most comprehensive)
        if self._check_tool("subfinder"):
            try:
                subdomains.update(self._subfinder_enum(domain))
            except Exception as e:
                logger.warning(f"Subfinder enumeration failed: {e}")
        
        # Method 2: Use amass (comprehensive but slower)
        if len(subdomains) < 5 and self._check_tool("amass"):
            try:
                subdomains.update(self._amass_enum(domain))
            except Exception as e:
                logger.warning(f"Amass enumeration failed: {e}")
        
        # Method 3: DNS brute forcing (fallback)
        if len(subdomains) < 5:
            try:
                subdomains.update(self._dns_bruteforce(domain))
            except Exception as e:
                logger.warning(f"DNS brute forcing failed: {e}")
        
        # Filter out the main domain itself
        subdomains = {s for s in subdomains if s != domain and not s.endswith(f'.{domain}')}
        
        # Always report subdomain enumeration results (even if none found)
        if subdomains:
            # Group by type (staging, dev, test, etc.)
            staging_subs = [s for s in subdomains if any(x in s.lower() for x in ['staging', 'stage', 'stg', 'preprod', 'pre-prod'])]
            dev_subs = [s for s in subdomains if any(x in s.lower() for x in ['dev', 'development', 'sandbox'])]
            test_subs = [s for s in subdomains if any(x in s.lower() for x in ['test', 'qa', 'uat'])]
            other_subs = [s for s in subdomains if s not in staging_subs + dev_subs + test_subs]
            
            # Create finding with subdomain list
            description = f"Discovered {len(subdomains)} subdomain(s) for {domain}. "
            if staging_subs:
                description += f"Staging subdomains: {', '.join(staging_subs[:5])}{'...' if len(staging_subs) > 5 else ''}. "
            if dev_subs:
                description += f"Development subdomains: {', '.join(dev_subs[:5])}{'...' if len(dev_subs) > 5 else ''}. "
            if test_subs:
                description += f"Test subdomains: {', '.join(test_subs[:5])}{'...' if len(test_subs) > 5 else ''}. "
            description += "These subdomains may have different security configurations and should be tested separately."
            
            findings.append(Finding(
                title=f"Subdomains Discovered ({len(subdomains)} found)",
                description=description,
                severity=FindingSeverity.INFO,
                category=FindingCategory.FINGERPRINTING,
                source_scanner="subdomain_enum",
                source_id=f"subdomains_{domain}",
                url=target.url,
                remediation="Review all discovered subdomains for security configurations. Ensure staging/dev/test environments are properly secured and kept up to date.",
                metadata={
                    "domain": domain,
                    "subdomain_count": len(subdomains),
                    "subdomains": sorted(list(subdomains)),
                    "staging_subdomains": staging_subs,
                    "dev_subdomains": dev_subs,
                    "test_subdomains": test_subs,
                    "other_subdomains": other_subs,
                    "test_passed": False,  # Found subdomains
                },
                references=[],
            ))
        else:
            # No subdomains found - report as passed test
            findings.append(Finding(
                title="Subdomain Enumeration",
                description=f"No additional subdomains discovered for {domain}. This is a positive security indicator as it reduces the attack surface.",
                severity=FindingSeverity.INFO,
                category=FindingCategory.FINGERPRINTING,
                source_scanner="subdomain_enum",
                source_id=f"subdomains_none_{domain}",
                url=target.url,
                remediation="No action needed. Continue monitoring for new subdomain registrations.",
                metadata={
                    "domain": domain,
                    "subdomain_count": 0,
                    "test_passed": True,  # No subdomains found = good
                },
                references=[],
            ))
        
        return findings
    
    def _check_tool(self, tool_name: str) -> bool:
        """Check if a tool is available."""
        try:
            import shutil
            if shutil.which(tool_name):
                return True
            if shutil.which(os.path.expanduser(f"~/go/bin/{tool_name}")):
                return True
            return False
        except:
            return False
    
    def _subfinder_enum(self, domain: str) -> Set[str]:
        """Enumerate subdomains using subfinder."""
        subdomains: Set[str] = set()
        
        try:
            # Find subfinder path
            import shutil
            subfinder_path = shutil.which("subfinder")
            if not subfinder_path:
                subfinder_path = os.path.expanduser("~/go/bin/subfinder")
                if not os.path.exists(subfinder_path):
                    return subdomains
            
            # Run subfinder
            args = [
                "-d", domain,
                "-silent",
                "-o", "-",  # Output to stdout
            ]
            
            result = subprocess.run(
                [subfinder_path] + args,
                capture_output=True,
                text=True,
                timeout=60,
                errors='replace',
            )
            
            if result.returncode == 0 and result.stdout:
                for line in result.stdout.strip().split('\n'):
                    subdomain = line.strip()
                    if subdomain and '.' in subdomain:
                        subdomains.add(subdomain)
        except subprocess.TimeoutExpired:
            logger.warning("Subfinder enumeration timed out")
        except Exception as e:
            logger.debug(f"Subfinder enumeration error: {e}")
        
        return subdomains
    
    def _amass_enum(self, domain: str) -> Set[str]:
        """Enumerate subdomains using amass."""
        subdomains: Set[str] = set()
        
        try:
            import shutil
            amass_path = shutil.which("amass")
            if not amass_path:
                amass_path = os.path.expanduser("~/go/bin/amass")
                if not os.path.exists(amass_path):
                    return subdomains
            
            # Run amass (passive mode for speed)
            args = [
                "enum",
                "-passive",
                "-d", domain,
                "-json", "-",
            ]
            
            result = subprocess.run(
                [amass_path] + args,
                capture_output=True,
                text=True,
                timeout=90,
                errors='replace',
            )
            
            if result.returncode == 0 and result.stdout:
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        try:
                            data = json.loads(line)
                            if 'name' in data:
                                subdomains.add(data['name'])
                        except json.JSONDecodeError:
                            continue
        except subprocess.TimeoutExpired:
            logger.warning("Amass enumeration timed out")
        except Exception as e:
            logger.debug(f"Amass enumeration error: {e}")
        
        return subdomains
    
    def _dns_bruteforce(self, domain: str) -> Set[str]:
        """Brute force subdomains using DNS queries."""
        subdomains: Set[str] = set()
        
        if not DNS_AVAILABLE:
            return subdomains
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 2
            
            # Try common subdomains
            for subdomain in self.common_subdomains:
                try:
                    full_domain = f"{subdomain}.{domain}"
                    answers = resolver.resolve(full_domain, 'A')
                    if answers:
                        subdomains.add(full_domain)
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                    continue
                except Exception:
                    continue
        except Exception as e:
            logger.debug(f"DNS brute forcing error: {e}")
        
        return subdomains
    
    def get_subdomains_for_scanning(self, target: ScanTarget) -> List[str]:
        """Get list of subdomains that should be scanned (returns URLs)."""
        if not target.domain:
            return []
        
        domain = target.domain.split(':')[0]
        subdomains: Set[str] = set()
        
        # Quick enumeration
        if self._check_tool("subfinder"):
            try:
                subdomains.update(self._subfinder_enum(domain))
            except:
                pass
        
        # Also try DNS brute force for common ones
        try:
            subdomains.update(self._dns_bruteforce(domain))
        except:
            pass
        
        # Convert to URLs
        urls = []
        protocol = target.protocol or "https"
        for subdomain in subdomains:
            if subdomain != domain:
                urls.append(f"{protocol}://{subdomain}")
        
        return urls

