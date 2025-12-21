"""Comprehensive website information gathering - DNS, IP, WHOIS, CDN, CMS, etc."""

import socket
import requests
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
import logging

from .base import BaseScanner
from ..models.scan import ScanTarget
from ..models.finding import Finding, FindingSeverity, FindingCategory
from ..models.scan_mode import ScanMode

logger = logging.getLogger(__name__)

# Optional DNS resolver import
try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

# Optional WHOIS import
try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False


class WebsiteInfo(BaseScanner):
    """Comprehensive website information gathering."""
    
    def __init__(self, enabled: bool = True, scan_mode: ScanMode = ScanMode.DEFENSIVE):
        """
        Initialize website info scanner.
        
        Args:
            enabled: Whether scanner is enabled
            scan_mode: Scan mode (defensive or offensive)
        """
        super().__init__(
            name="website_info",
            command=None,  # No external command needed
            enabled=enabled,
            scan_mode=scan_mode
        )
        # Use OPSEC-enabled session helper
        from ..utils.scanner_session import create_scanner_session
        self.session = create_scanner_session()
    
    def is_available(self) -> bool:
        """Website info scanner is always available."""
        return True
    
    def scan(self, target: ScanTarget) -> List[Finding]:
        """Gather comprehensive website information."""
        findings = []
        
        domain = target.domain or self._extract_domain(target.url)
        if not domain:
            return findings
        
        # Gather all information
        info = {
            'domain': domain,
            'ip_address': None,
            'ip_addresses': [],
            'ipv6_addresses': [],
            'name_servers': [],
            'mx_records': [],
            'cname_records': [],
            'cdn': None,
            'cms': None,
            'web_server': None,
            'technology_stack': [],
            'registrar': None,
            'creation_date': None,
            'expiration_date': None,
            'whois_status': None,
            'country': None,
            'city': None,
            'isp': None,
            'asn': None,
        }
        
        # DNS lookups
        info.update(self._dns_lookup(domain))
        
        # IP geolocation
        if info.get('ip_address'):
            info.update(self._ip_geolocation(info['ip_address']))
        
        # HTTP headers analysis
        info.update(self._analyze_headers(target.url))
        
        # WHOIS lookup
        info.update(self._whois_lookup(domain))
        
        # Create findings for all collected information
        findings.extend(self._create_info_findings(target.url, info))
        
        return findings
    
    def _extract_domain(self, url: str) -> Optional[str]:
        """Extract domain from URL."""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc or parsed.path.split('/')[0]
            if domain:
                # Remove port
                domain = domain.split(':')[0]
                # Remove www
                domain = domain.replace('www.', '')
                return domain
        except:
            pass
        return None
    
    def _dns_lookup(self, domain: str) -> Dict[str, Any]:
        """Perform DNS lookups."""
        result = {
            'ip_address': None,
            'ip_addresses': [],
            'ipv6_addresses': [],
            'name_servers': [],
            'mx_records': [],
            'cname_records': [],
        }
        
        # Basic socket lookup (A record)
        try:
            ip = socket.gethostbyname(domain)
            result['ip_address'] = ip
            result['ip_addresses'] = [ip]
        except socket.gaierror:
            pass
        
        if not DNS_AVAILABLE:
            return result
        
        # DNS resolver lookups
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            
            # A records
            try:
                answers = resolver.resolve(domain, 'A')
                result['ip_addresses'] = [str(answer) for answer in answers]
                if result['ip_addresses']:
                    result['ip_address'] = result['ip_addresses'][0]
            except:
                pass
            
            # AAAA records (IPv6)
            try:
                answers = resolver.resolve(domain, 'AAAA')
                result['ipv6_addresses'] = [str(answer) for answer in answers]
            except:
                pass
            
            # NS records
            try:
                answers = resolver.resolve(domain, 'NS')
                result['name_servers'] = [str(answer).rstrip('.') for answer in answers]
            except:
                pass
            
            # MX records
            try:
                answers = resolver.resolve(domain, 'MX')
                mx_list = []
                for answer in answers:
                    mx_list.append(f"{answer.preference} {str(answer.exchange).rstrip('.')}")
                result['mx_records'] = mx_list
            except:
                pass
            
            # CNAME records
            try:
                answers = resolver.resolve(domain, 'CNAME')
                result['cname_records'] = [str(answer).rstrip('.') for answer in answers]
            except:
                pass
        except Exception as e:
            logger.debug(f"DNS lookup failed for {domain}: {e}")
        
        return result
    
    def _ip_geolocation(self, ip: str) -> Dict[str, Any]:
        """Get IP geolocation and hosting info."""
        result = {
            'country': None,
            'city': None,
            'isp': None,
            'asn': None,
        }
        
        # Use free ip-api.com
        try:
            url = f"http://ip-api.com/json/{ip}"
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    result['country'] = data.get('country')
                    result['city'] = data.get('city')
                    result['isp'] = data.get('isp')
                    result['asn'] = data.get('as')
        except Exception as e:
            logger.debug(f"IP geolocation failed for {ip}: {e}")
        
        return result
    
    def _analyze_headers(self, url: str) -> Dict[str, Any]:
        """Analyze HTTP headers for server, CDN, CMS, technology."""
        result = {
            'web_server': None,
            'cdn': None,
            'cms': None,
            'technology_stack': [],
        }
        
        try:
            response = self.session.get(url, timeout=10)
            headers = response.headers
            
            # Web server
            server = headers.get('Server', '').strip()
            if server:
                result['web_server'] = server
            
            # CDN detection
            cdn_indicators = {
                'CF-Ray': 'Cloudflare',
                'X-Cache': 'CDN Cache',
                'X-CDN': 'CDN',
                'Server': None,  # Check Server header
            }
            
            for header_name, cdn_name in cdn_indicators.items():
                header_value = headers.get(header_name, '').strip()
                if header_value:
                    if header_name == 'Server':
                        server_lower = header_value.lower()
                        if 'cloudflare' in server_lower:
                            result['cdn'] = 'Cloudflare'
                        elif 'cloudfront' in server_lower:
                            result['cdn'] = 'AWS CloudFront'
                        elif 'fastly' in server_lower:
                            result['cdn'] = 'Fastly'
                        elif 'akamai' in server_lower:
                            result['cdn'] = 'Akamai'
                    else:
                        result['cdn'] = cdn_name or header_value
                    break
            
            # Technology stack
            tech_headers = {
                'X-Powered-By': 'Backend Framework',
                'X-AspNet-Version': 'ASP.NET',
                'X-AspNetMvc-Version': 'ASP.NET MVC',
                'X-Drupal-Cache': 'Drupal',
                'X-Generator': 'CMS Generator',
            }
            
            for header_name, tech_name in tech_headers.items():
                header_value = headers.get(header_name, '').strip()
                if header_value:
                    result['technology_stack'].append(f"{tech_name}: {header_value}")
            
            # CMS detection from content
            content = response.text.lower()
            if 'wp-content' in content or 'wp-includes' in content or 'wp-admin' in content:
                result['cms'] = 'WordPress'
            elif 'drupal' in content:
                result['cms'] = 'Drupal'
            elif 'joomla' in content:
                result['cms'] = 'Joomla'
            elif 'shopify' in content:
                result['cms'] = 'Shopify'
        except Exception as e:
            logger.debug(f"Header analysis failed for {url}: {e}")
        
        return result
    
    def _whois_lookup(self, domain: str) -> Dict[str, Any]:
        """Perform WHOIS lookup."""
        result = {
            'registrar': None,
            'creation_date': None,
            'expiration_date': None,
            'whois_status': None,
        }
        
        if not WHOIS_AVAILABLE:
            return result
        
        try:
            whois_data = whois.whois(domain)
            
            if whois_data:
                result['registrar'] = whois_data.get('registrar')
                
                # Creation date
                creation = whois_data.get('creation_date')
                if creation:
                    if isinstance(creation, list):
                        creation = creation[0]
                    result['creation_date'] = str(creation)
                
                # Expiration date
                expiration = whois_data.get('expiration_date')
                if expiration:
                    if isinstance(expiration, list):
                        expiration = expiration[0]
                    result['expiration_date'] = str(expiration)
                
                # Status
                status = whois_data.get('status')
                if status:
                    if isinstance(status, list):
                        result['whois_status'] = ', '.join(str(s) for s in status)
                    else:
                        result['whois_status'] = str(status)
        except Exception as e:
            logger.debug(f"WHOIS lookup failed for {domain}: {e}")
        
        return result
    
    def _create_info_findings(self, url: str, info: Dict[str, Any]) -> List[Finding]:
        """Create findings from gathered information."""
        findings = []
        
        # Always create a comprehensive finding, even if minimal data
        description_parts = []
        
        if info.get('ip_address'):
            description_parts.append(f"IP Address: {info['ip_address']}")
        if info.get('ip_addresses') and len(info['ip_addresses']) > 1:
            description_parts.append(f"IP Addresses: {', '.join(info['ip_addresses'])}")
        if info.get('ipv6_addresses'):
            description_parts.append(f"IPv6: {', '.join(info['ipv6_addresses'])}")
        if info.get('web_server'):
            description_parts.append(f"Web Server: {info['web_server']}")
        if info.get('cdn'):
            description_parts.append(f"CDN: {info['cdn']}")
        if info.get('cms'):
            description_parts.append(f"CMS: {info['cms']}")
        if info.get('name_servers'):
            description_parts.append(f"Name Servers: {', '.join(info['name_servers'][:3])}{'...' if len(info['name_servers']) > 3 else ''}")
        if info.get('mx_records'):
            description_parts.append(f"MX Records: {len(info['mx_records'])} record(s)")
        if info.get('registrar'):
            description_parts.append(f"Registrar: {info['registrar']}")
        if info.get('country'):
            location = info['country']
            if info.get('city'):
                location = f"{info['city']}, {location}"
            description_parts.append(f"Location: {location}")
        if info.get('isp'):
            description_parts.append(f"ISP: {info['isp']}")
        if info.get('asn'):
            description_parts.append(f"ASN: {info['asn']}")
        if info.get('technology_stack'):
            description_parts.append(f"Technology: {', '.join(info['technology_stack'])}")
        
        # Always create finding, even if minimal
        if not description_parts:
            description_parts.append("Basic website information gathered")
        
        findings.append(Finding(
            title="Website Information",
            description=" | ".join(description_parts),
            severity=FindingSeverity.INFO,
            category=FindingCategory.FINGERPRINTING,
            source_scanner="website_info",
            source_id="website_info_comprehensive",
            url=url,
            metadata=info,
        ))
        
        return findings

