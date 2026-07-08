"""Scan orchestrator to coordinate multiple scanners."""

import logging
from datetime import datetime
from typing import List, Optional, Dict, Callable

from .models.scan import ScanTarget, ScanResult
from .models.finding import Finding
from .models.risk import RiskScore
from .models.scan_mode import ScanMode
from .scanners.base import BaseScanner
from .scanners.wpscan import WPScanAdapter
from .scanners.nuclei import NucleiAdapter
from .scanners.nmap import NmapAdapter
from .scanners.sqlmap import SQLMapAdapter
from .scanners.wordpress_analyzer import WordPressAnalyzer
from .scanners.directory_bruteforcer import DirectoryBruteforcer
from .scanners.parameter_discovery import ParameterDiscovery
from .scanners.exploit_intel import ExploitIntel
from .scanners.wordpress_offensive import WordPressOffensive
from .scanners.xss_tester import XSSTester
from .scanners.subdomain_enum import SubdomainEnum
from .scanners.website_info import WebsiteInfo
from .scanners.command_injection import CommandInjectionScanner
from .scanners.file_upload import FileUploadScanner
from .scanners.path_traversal import PathTraversalScanner
from .scanners.wordpress_vulnerabilities import WordPressVulnerabilities
from .scanners.ssl_analyzer import SSLAnalyzer
from .scanners.security_headers import SecurityHeadersAnalyzer
from .scanners.dns_security import DNSSecurityAnalyzer
from .scanners.http_security import HTTPSecurityAnalyzer
from .scanners.cookie_security import CookieSecurityAnalyzer
from .scanners.rate_limiting import RateLimitingAnalyzer
from .scanners.ssrf_scanner import SSRFScanner
from .scanners.xxe_scanner import XXEScanner
from .scanners.idor_scanner import IDORScanner
from .scanners.csrf_scanner import CSRFScanner
from .scanners.template_injection import TemplateInjectionScanner
from .scanners.backup_files import BackupFilesScanner
from .scanners.api_security import APISecurityAnalyzer
from .scanners.content_security import ContentSecurityAnalyzer
from .scanners.jwt_security import JWTSecurityScanner
from .scanners.graphql_security import GraphQLSecurityScanner
from .scanners.deserialization_scanner import DeserializationScanner
from .scanners.websocket_security import WebSocketSecurityScanner
from .scanners.auth_bypass import AuthenticationBypassScanner
from .scoring.engine import RiskScoringEngine

logger = logging.getLogger(__name__)


class ScanOrchestrator:
    """Orchestrates multiple security scanners and aggregates results."""
    
    def __init__(
        self,
        enable_wpscan: bool = True,
        enable_nuclei: bool = True,
        enable_nmap: bool = True,
        enable_sqlmap: bool = False,  # Offensive only
        wpscan_api_token: Optional[str] = None,
        scan_mode: ScanMode = ScanMode.DEFENSIVE,
        exhaustive: bool = False,  # Exhaustive mode for thorough scanning
        progress_callback: Optional[Callable[[Dict], None]] = None,
        preset: Optional[str] = None,
    ):
        """
        Initialize orchestrator with scanner configuration.
        
        Args:
            enable_wpscan: Enable WPScan scanner
            enable_nuclei: Enable Nuclei scanner
            enable_nmap: Enable Nmap scanner
            enable_sqlmap: Enable SQLMap scanner (offensive only)
            wpscan_api_token: WPScan API token (optional)
            scan_mode: Scan mode (defensive or offensive)
            exhaustive: If True, use exhaustive mode for scanners that support it (slower but more thorough)
        """
        self.scan_mode = scan_mode
        self.exhaustive = exhaustive
        self.preset = preset
        self.scanners: List[BaseScanner] = []
        self.progress_callback = progress_callback
        
        # Warn about offensive mode
        if scan_mode == ScanMode.OFFENSIVE:
            logger.warning("=" * 60)
            logger.warning("OFFENSIVE MODE ENABLED")
            logger.warning("=" * 60)
            logger.warning("This mode will attempt to EXPLOIT vulnerabilities.")
            logger.warning("Only use on systems you own or have explicit authorization to test.")
            logger.warning("Unauthorized use may be illegal and unethical.")
            logger.warning("=" * 60)
        
        if enable_wpscan:
            try:
                wpscan = WPScanAdapter(api_token=wpscan_api_token, enabled=True, scan_mode=scan_mode)
                if wpscan.is_available():
                    self.scanners.append(wpscan)
                    logger.info("WPScan scanner enabled")
                else:
                    logger.warning("WPScan not available, skipping")
            except Exception as e:
                logger.warning(f"Failed to initialize WPScan: {e}")
        
        if enable_nuclei:
            try:
                nuclei = NucleiAdapter(enabled=True, scan_mode=scan_mode)
                if nuclei.is_available():
                    self.scanners.append(nuclei)
                    logger.info("Nuclei scanner enabled")
                else:
                    logger.warning("Nuclei not available, skipping")
            except Exception as e:
                logger.warning(f"Failed to initialize Nuclei: {e}")
        
        if enable_nmap:
            try:
                nmap = NmapAdapter(enabled=True, scan_mode=scan_mode)
                if nmap.is_available():
                    self.scanners.append(nmap)
                    logger.info("Nmap scanner enabled")
                else:
                    logger.warning("Nmap not available, skipping")
            except Exception as e:
                logger.warning(f"Failed to initialize Nmap: {e}")
        
        # WordPress Analyzer (runs after WPScan if enabled, or independently)
        # This provides additional WordPress-specific security checks
        try:
            wp_analyzer = WordPressAnalyzer(enabled=True, scan_mode=scan_mode)
            if wp_analyzer.is_available():
                self.scanners.append(wp_analyzer)
                logger.info("WordPress Analyzer enabled (will run if WordPress detected)")
            else:
                logger.warning("WordPress Analyzer not available, skipping")
        except Exception as e:
            logger.warning(f"Failed to initialize WordPress Analyzer: {e}")
        
        # Website information gathering (comprehensive DNS, IP, WHOIS, CDN, CMS, etc.)
        try:
            website_info = WebsiteInfo(enabled=True, scan_mode=scan_mode)
            if website_info.is_available():
                self.scanners.append(website_info)
                logger.info("Website Information gathering enabled")
        except Exception as e:
            logger.warning(f"Failed to initialize Website Information: {e}")
        
        # Subdomain enumeration (defensive and offensive)
        try:
            subdomain_enum = SubdomainEnum(enabled=True, scan_mode=scan_mode)
            if subdomain_enum.is_available():
                self.scanners.append(subdomain_enum)
                logger.info("Subdomain Enumeration enabled")
            else:
                logger.info("Subdomain Enumeration not available (subfinder/amass/dnspython not found), skipping")
        except Exception as e:
            logger.warning(f"Failed to initialize Subdomain Enumeration: {e}")
        
        # SSL/TLS Security Analyzer (defensive)
        try:
            ssl_analyzer = SSLAnalyzer(enabled=True, scan_mode=scan_mode)
            if ssl_analyzer.is_available():
                self.scanners.append(ssl_analyzer)
                logger.info("SSL/TLS Analyzer enabled")
        except Exception as e:
            logger.warning(f"Failed to initialize SSL Analyzer: {e}")
        
        # Security Headers Analyzer (defensive)
        try:
            security_headers = SecurityHeadersAnalyzer(enabled=True, scan_mode=scan_mode)
            if security_headers.is_available():
                self.scanners.append(security_headers)
                logger.info("Security Headers Analyzer enabled")
        except Exception as e:
            logger.warning(f"Failed to initialize Security Headers Analyzer: {e}")
        
        # DNS Security Analyzer (defensive)
        try:
            dns_security = DNSSecurityAnalyzer(enabled=True, scan_mode=scan_mode)
            if dns_security.is_available():
                self.scanners.append(dns_security)
                logger.info("DNS Security Analyzer enabled")
            else:
                logger.info("DNS Security Analyzer not available (dnspython not found), skipping")
        except Exception as e:
            logger.warning(f"Failed to initialize DNS Security Analyzer: {e}")
        
        # HTTP Security Analyzer (defensive)
        try:
            http_security = HTTPSecurityAnalyzer(enabled=True, scan_mode=scan_mode)
            if http_security.is_available():
                self.scanners.append(http_security)
                logger.info("HTTP Security Analyzer enabled")
        except Exception as e:
            logger.warning(f"Failed to initialize HTTP Security Analyzer: {e}")
        
        # Cookie Security Analyzer (defensive)
        try:
            cookie_security = CookieSecurityAnalyzer(enabled=True, scan_mode=scan_mode)
            if cookie_security.is_available():
                self.scanners.append(cookie_security)
                logger.info("Cookie Security Analyzer enabled")
        except Exception as e:
            logger.warning(f"Failed to initialize Cookie Security Analyzer: {e}")
        
        # Rate Limiting Analyzer (defensive)
        try:
            rate_limiting = RateLimitingAnalyzer(enabled=True, scan_mode=scan_mode)
            if rate_limiting.is_available():
                self.scanners.append(rate_limiting)
                logger.info("Rate Limiting Analyzer enabled")
        except Exception as e:
            logger.warning(f"Failed to initialize Rate Limiting Analyzer: {e}")
        
        # Backup Files Scanner (defensive)
        try:
            backup_files = BackupFilesScanner(enabled=True, scan_mode=scan_mode)
            if backup_files.is_available():
                self.scanners.append(backup_files)
                logger.info("Backup Files Scanner enabled")
        except Exception as e:
            logger.warning(f"Failed to initialize Backup Files Scanner: {e}")
        
        # API Security Analyzer (defensive)
        try:
            api_security = APISecurityAnalyzer(enabled=True, scan_mode=scan_mode)
            if api_security.is_available():
                self.scanners.append(api_security)
                logger.info("API Security Analyzer enabled")
        except Exception as e:
            logger.warning(f"Failed to initialize API Security Analyzer: {e}")
        
        # Content Security Analyzer (defensive)
        try:
            content_security = ContentSecurityAnalyzer(enabled=True, scan_mode=scan_mode)
            if content_security.is_available():
                self.scanners.append(content_security)
                logger.info("Content Security Analyzer enabled")
        except Exception as e:
            logger.warning(f"Failed to initialize Content Security Analyzer: {e}")
        
        # Offensive scanners (only in offensive mode)
        if scan_mode == ScanMode.OFFENSIVE or scan_mode == ScanMode.COMPREHENSIVE:
            if enable_sqlmap:
                try:
                    sqlmap = SQLMapAdapter(enabled=True, scan_mode=scan_mode)
                    if sqlmap.is_available():
                        self.scanners.append(sqlmap)
                        logger.info("SQLMap scanner enabled (OFFENSIVE)")
                    else:
                        logger.warning("SQLMap not available, skipping")
                except Exception as e:
                    logger.warning(f"Failed to initialize SQLMap: {e}")
            
            # WordPress offensive testing (login brute force, REST API testing)
            try:
                wp_offensive = WordPressOffensive(enabled=True, scan_mode=scan_mode)
                if wp_offensive.is_available():
                    self.scanners.append(wp_offensive)
                    logger.info("WordPress Offensive scanner enabled (OFFENSIVE)")
            except Exception as e:
                logger.warning(f"Failed to initialize WordPress Offensive: {e}")
            
            # XSS testing
            try:
                xss_tester = XSSTester(enabled=True, scan_mode=scan_mode)
                if xss_tester.is_available():
                    self.scanners.append(xss_tester)
                    logger.info("XSS Tester enabled (OFFENSIVE)")
            except Exception as e:
                logger.warning(f"Failed to initialize XSS Tester: {e}")
            
            # Directory brute forcing
            try:
                dir_bruteforcer = DirectoryBruteforcer(enabled=True, scan_mode=scan_mode)
                if dir_bruteforcer.is_available():
                    self.scanners.append(dir_bruteforcer)
                    logger.info("Directory Bruteforcer enabled (OFFENSIVE)")
                else:
                    logger.info("Directory Bruteforcer not available (ffuf/gobuster not found), skipping")
            except Exception as e:
                logger.warning(f"Failed to initialize Directory Bruteforcer: {e}")
            
            # Parameter discovery
            try:
                param_discovery = ParameterDiscovery(enabled=True, scan_mode=scan_mode)
                if param_discovery.is_available():
                    self.scanners.append(param_discovery)
                    logger.info("Parameter Discovery enabled (OFFENSIVE)")
                else:
                    logger.info("Parameter Discovery not available (Arjun not found), skipping")
            except Exception as e:
                logger.warning(f"Failed to initialize Parameter Discovery: {e}")
            
            # JWT Security Testing
            try:
                jwt_security = JWTSecurityScanner(enabled=True, scan_mode=scan_mode)
                if jwt_security.is_available():
                    self.scanners.append(jwt_security)
                    logger.info("JWT Security Scanner enabled (OFFENSIVE)")
            except Exception as e:
                logger.warning(f"Failed to initialize JWT Security Scanner: {e}")
            
            # GraphQL Security Testing
            try:
                graphql_security = GraphQLSecurityScanner(enabled=True, scan_mode=scan_mode)
                if graphql_security.is_available():
                    self.scanners.append(graphql_security)
                    logger.info("GraphQL Security Scanner enabled (OFFENSIVE)")
            except Exception as e:
                logger.warning(f"Failed to initialize GraphQL Security Scanner: {e}")
            
            # Deserialization Testing
            try:
                deserialization = DeserializationScanner(enabled=True, scan_mode=scan_mode)
                if deserialization.is_available():
                    self.scanners.append(deserialization)
                    logger.info("Deserialization Scanner enabled (OFFENSIVE)")
            except Exception as e:
                logger.warning(f"Failed to initialize Deserialization Scanner: {e}")
            
            # WebSocket Security Testing
            try:
                websocket_security = WebSocketSecurityScanner(enabled=True, scan_mode=scan_mode)
                if websocket_security.is_available():
                    self.scanners.append(websocket_security)
                    logger.info("WebSocket Security Scanner enabled (OFFENSIVE)")
            except Exception as e:
                logger.warning(f"Failed to initialize WebSocket Security Scanner: {e}")
            
            # Authentication Bypass Testing
            try:
                auth_bypass = AuthenticationBypassScanner(enabled=True, scan_mode=scan_mode)
                if auth_bypass.is_available():
                    self.scanners.append(auth_bypass)
                    logger.info("Authentication Bypass Scanner enabled (OFFENSIVE)")
            except Exception as e:
                logger.warning(f"Failed to initialize Authentication Bypass Scanner: {e}")
            
            # Exploit intelligence
            try:
                exploit_intel = ExploitIntel(enabled=True, scan_mode=scan_mode)
                if exploit_intel.is_available():
                    self.scanners.append(exploit_intel)
                    logger.info("Exploit Intelligence enabled (OFFENSIVE)")
                else:
                    logger.info("Exploit Intelligence not available (SearchSploit not found), skipping")
            except Exception as e:
                logger.warning(f"Failed to initialize Exploit Intelligence: {e}")
            
            # Command Injection / RCE Scanner
            try:
                cmd_injection = CommandInjectionScanner(enabled=True, scan_mode=scan_mode)
                if cmd_injection.is_available():
                    self.scanners.append(cmd_injection)
                    logger.info("Command Injection Scanner enabled (OFFENSIVE)")
            except Exception as e:
                logger.warning(f"Failed to initialize Command Injection Scanner: {e}")
            
            # File Upload Vulnerability Scanner
            try:
                file_upload = FileUploadScanner(enabled=True, scan_mode=scan_mode)
                if file_upload.is_available():
                    self.scanners.append(file_upload)
                    logger.info("File Upload Scanner enabled (OFFENSIVE)")
            except Exception as e:
                logger.warning(f"Failed to initialize File Upload Scanner: {e}")
            
            # Path Traversal / File Inclusion Scanner
            try:
                path_traversal = PathTraversalScanner(enabled=True, scan_mode=scan_mode, exhaustive=exhaustive)
                if path_traversal.is_available():
                    self.scanners.append(path_traversal)
                    mode_str = "EXHAUSTIVE" if exhaustive else "standard"
                    logger.info(f"Path Traversal Scanner enabled (OFFENSIVE, {mode_str} mode)")
            except Exception as e:
                logger.warning(f"Failed to initialize Path Traversal Scanner: {e}")
            
            # WordPress-Specific Vulnerabilities Scanner
            try:
                wp_vulns = WordPressVulnerabilities(enabled=True, scan_mode=scan_mode)
                if wp_vulns.is_available():
                    self.scanners.append(wp_vulns)
                    logger.info("WordPress Vulnerabilities Scanner enabled (OFFENSIVE)")
            except Exception as e:
                logger.warning(f"Failed to initialize WordPress Vulnerabilities Scanner: {e}")
            
            # SSRF Scanner (for all sites)
            try:
                ssrf_scanner = SSRFScanner(enabled=True, scan_mode=scan_mode)
                if ssrf_scanner.is_available():
                    self.scanners.append(ssrf_scanner)
                    logger.info("SSRF Scanner enabled (OFFENSIVE)")
            except Exception as e:
                logger.warning(f"Failed to initialize SSRF Scanner: {e}")
            
            # XXE Scanner (for all sites)
            try:
                xxe_scanner = XXEScanner(enabled=True, scan_mode=scan_mode)
                if xxe_scanner.is_available():
                    self.scanners.append(xxe_scanner)
                    logger.info("XXE Scanner enabled (OFFENSIVE)")
            except Exception as e:
                logger.warning(f"Failed to initialize XXE Scanner: {e}")
            
            # IDOR Scanner (for all sites)
            try:
                idor_scanner = IDORScanner(enabled=True, scan_mode=scan_mode)
                if idor_scanner.is_available():
                    self.scanners.append(idor_scanner)
                    logger.info("IDOR Scanner enabled (OFFENSIVE)")
            except Exception as e:
                logger.warning(f"Failed to initialize IDOR Scanner: {e}")
            
            # CSRF Scanner (for all sites)
            try:
                csrf_scanner = CSRFScanner(enabled=True, scan_mode=scan_mode)
                if csrf_scanner.is_available():
                    self.scanners.append(csrf_scanner)
                    logger.info("CSRF Scanner enabled (OFFENSIVE)")
            except Exception as e:
                logger.warning(f"Failed to initialize CSRF Scanner: {e}")
            
            # Template Injection Scanner (for all sites)
            try:
                template_injection = TemplateInjectionScanner(enabled=True, scan_mode=scan_mode)
                if template_injection.is_available():
                    self.scanners.append(template_injection)
                    logger.info("Template Injection Scanner enabled (OFFENSIVE)")
            except Exception as e:
                logger.warning(f"Failed to initialize Template Injection Scanner: {e}")

        if preset:
            from .utils.scan_presets import get_allowed_scanners_for_preset
            allowed = get_allowed_scanners_for_preset(preset)
            if allowed is not None:
                before = len(self.scanners)
                self.scanners = [s for s in self.scanners if s.name in allowed]
                logger.info(f"Preset '{preset}': using {len(self.scanners)}/{before} scanners")
        
        if not self.scanners:
            raise RuntimeError("No scanners available. Please install at least one scanner (WPScan, Nuclei, or Nmap).")
    
    def scan(self, target_url: str) -> ScanResult:
        """
        Run all enabled scanners on target.
        
        Args:
            target_url: Target URL or domain to scan
            
        Returns:
            ScanResult with aggregated findings
        """
        target = ScanTarget(url=target_url)
        result = ScanResult(target=target, scan_mode=self.scan_mode)
        
        mode_str = "OFFENSIVE" if self.scan_mode == ScanMode.OFFENSIVE else "DEFENSIVE"
        logger.info(f"Starting {mode_str} security scan of {target.url}")
        
        # Step 1: Run subdomain enumeration first
        subdomain_findings = []
        subdomain_urls = []
        subdomain_scanner = None
        
        for scanner in self.scanners:
            if scanner.name == "subdomain_enum" and scanner.enabled:
                subdomain_scanner = scanner
                break
        
        if subdomain_scanner:
            logger.info("Running subdomain enumeration...")
            try:
                subdomain_findings = subdomain_scanner.scan(target)
                for finding in subdomain_findings:
                    result.add_finding(finding)
                
                # Extract subdomain URLs for scanning
                if subdomain_findings:
                    metadata = subdomain_findings[0].metadata or {}
                    subdomains = metadata.get('subdomains', [])
                    protocol = target.protocol or "https"
                    for subdomain in subdomains[:10]:  # Limit to 10 subdomains to scan
                        subdomain_urls.append(f"{protocol}://{subdomain}")
                    logger.info(f"Discovered {len(subdomains)} subdomain(s), will scan top {len(subdomain_urls)}")
            except Exception as e:
                logger.warning(f"Subdomain enumeration failed: {e}")
        
        # Run each scanner
        # WordPress Analyzer should run after WPScan if WPScan is enabled
        # (so we know it's WordPress), but it can also run independently
        wp_analyzer = None
        scanners_to_run = []
        
        for scanner in self.scanners:
            if not scanner.enabled:
                continue
            
            # Separate WordPress Analyzer to run after WPScan
            if scanner.name == "wordpress_analyzer":
                wp_analyzer = scanner
            else:
                scanners_to_run.append(scanner)
        
        # Run all scanners except WordPress Analyzer and ExploitIntel
        # ExploitIntel should run last to use findings from other scanners
        # Parameter discovery should run early so its results can be used by SQLMap and other scanners
        exploit_intel_scanner = None
        parameter_discovery_scanner = None
        sqlmap_scanner = None
        scanners_to_run_filtered = []
        
        for scanner in scanners_to_run:
            if scanner.name == "exploit_intel":
                exploit_intel_scanner = scanner
            elif scanner.name == "parameter_discovery":
                parameter_discovery_scanner = scanner
            elif scanner.name == "sqlmap":
                sqlmap_scanner = scanner
            else:
                scanners_to_run_filtered.append(scanner)
        
        # Track discovered parameters for use by SQLMap and other scanners
        discovered_parameters = {}  # Format: {url: [param1, param2, ...]}
        
        # Run parameter discovery first if available (so results can be used by other scanners)
        if parameter_discovery_scanner and parameter_discovery_scanner.enabled:
            logger.info(f"Running {parameter_discovery_scanner.name} scanner (early for parameter discovery)...")
            result.scanners_run.append(parameter_discovery_scanner.name)
            
            if self.progress_callback:
                self.progress_callback({
                    'current_scanner': f'Running {parameter_discovery_scanner.name}...',
                    'scanners_completed': 0,
                    'scanners_total': len(scanners_to_run_filtered) + (1 if wp_analyzer else 0) + (1 if exploit_intel_scanner else 0) + (1 if sqlmap_scanner else 0),
                })
            
            try:
                param_findings = parameter_discovery_scanner.scan(target)
                logger.info(f"{parameter_discovery_scanner.name} found {len(param_findings)} finding(s)")
                
                for finding in param_findings:
                    result.add_finding(finding)
                    # Extract discovered parameters from metadata
                    if finding.metadata and 'parameters' in finding.metadata:
                        url = finding.url or target.url
                        params = finding.metadata.get('parameters', [])
                        if url not in discovered_parameters:
                            discovered_parameters[url] = []
                        discovered_parameters[url].extend(params)
                        # Remove duplicates
                        discovered_parameters[url] = list(set(discovered_parameters[url]))
                
                if discovered_parameters:
                    logger.info(f"Discovered {sum(len(p) for p in discovered_parameters.values())} parameters for use in subsequent scans")
            except Exception as e:
                logger.warning(f"{parameter_discovery_scanner.name} failed: {e}")
        
        total_scanners = len(scanners_to_run_filtered) + (1 if wp_analyzer else 0) + (1 if exploit_intel_scanner else 0) + (1 if sqlmap_scanner else 0)
        completed = 1 if (parameter_discovery_scanner and parameter_discovery_scanner.enabled) else 0
        
        for scanner in scanners_to_run_filtered:
            logger.info(f"Running {scanner.name} scanner...")
            
            # Track scanner start time for per-scanner estimates
            scanner_start_time = datetime.now()
            
            # Scanner time estimates (in seconds) - used for initial estimate
            scanner_estimates = {
                'wpscan': 60,
                'nuclei': 30,
                'nmap': 40,
                'sqlmap': 120,
                'directory_bruteforcer': 60,
                'parameter_discovery': 120,
                'exploit_intel': 60,  # Increased time for multiple source lookups
                'wordpress_analyzer': 5,
                'wordpress_offensive': 90,
                'xss_tester': 45,
                'subdomain_enum': 30,
            }
            estimated_scanner_time = scanner_estimates.get(scanner.name.lower(), 30)
            
            # Update progress
            if self.progress_callback:
                self.progress_callback({
                    'current_scanner': f'Running {scanner.name}...',
                    'scanners_completed': completed,
                    'scanners_total': total_scanners,
                    'current_scanner_estimate': estimated_scanner_time,  # Per-scanner estimate
                })
            
            result.scanners_run.append(scanner.name)
            
            try:
                findings = scanner.scan(target)
                logger.info(f"{scanner.name} found {len(findings)} finding(s)")
                
                for finding in findings:
                    result.add_finding(finding)
                    # Track successful exploitations
                    if finding.exploited:
                        result.exploitations_successful += 1
                
                completed += 1
                if self.progress_callback:
                    self.progress_callback({
                        'current_scanner': f'Completed {scanner.name}',
                        'scanners_completed': completed,
                        'scanners_total': total_scanners,
                    })
            
            except TimeoutError as e:
                error_msg = f"Scanner timed out: {str(e)}"
                logger.warning(f"{scanner.name} timed out (this is OK for slow/unreachable targets)")
                result.scanner_errors[scanner.name] = error_msg
            except FileNotFoundError as e:
                error_msg = f"Scanner not found: {str(e)}"
                logger.error(f"{scanner.name} not found: {error_msg}")
                result.scanner_errors[scanner.name] = error_msg
            except ValueError as e:
                error_msg = f"Invalid input: {str(e)}"
                logger.error(f"{scanner.name} input error: {error_msg}")
                result.scanner_errors[scanner.name] = error_msg
            except Exception as e:
                error_msg = str(e)
                logger.error(f"{scanner.name} failed: {error_msg}", exc_info=logger.level == logging.DEBUG)
                result.scanner_errors[scanner.name] = error_msg
        
        # Run SQLMap with discovered parameters if available
        if sqlmap_scanner and sqlmap_scanner.enabled:
            logger.info(f"Running {sqlmap_scanner.name} scanner (with discovered parameters if available)...")
            
            if self.progress_callback:
                self.progress_callback({
                    'current_scanner': f'Running {sqlmap_scanner.name}...',
                    'scanners_completed': completed,
                    'scanners_total': total_scanners,
                })
            
            result.scanners_run.append(sqlmap_scanner.name)
            
            try:
                # Pass discovered parameters to SQLMap
                findings = sqlmap_scanner.scan(target, discovered_parameters=discovered_parameters if discovered_parameters else None)
                logger.info(f"{sqlmap_scanner.name} found {len(findings)} finding(s)")
                
                for finding in findings:
                    result.add_finding(finding)
                    if finding.exploited:
                        result.exploitations_successful += 1
                
                completed += 1
                if self.progress_callback:
                    self.progress_callback({
                        'current_scanner': f'Completed {sqlmap_scanner.name}',
                        'scanners_completed': completed,
                        'scanners_total': total_scanners,
                    })
            except Exception as e:
                error_msg = str(e)
                logger.error(f"{sqlmap_scanner.name} failed: {error_msg}", exc_info=logger.level == logging.DEBUG)
                result.scanner_errors[sqlmap_scanner.name] = error_msg
        
        # Run ExploitIntel last, with all findings from other scanners
        if exploit_intel_scanner and exploit_intel_scanner.enabled:
            logger.info(f"Running {exploit_intel_scanner.name} scanner with existing findings...")
            
            if self.progress_callback:
                self.progress_callback({
                    'current_scanner': f'Running {exploit_intel_scanner.name}...',
                    'scanners_completed': completed,
                    'scanners_total': total_scanners,
                    'current_scanner_estimate': 60,
                })
            
            result.scanners_run.append(exploit_intel_scanner.name)
            
            try:
                # Pass existing findings to exploit intelligence scanner
                findings = exploit_intel_scanner.scan(target, existing_findings=result.findings)
                logger.info(f"{exploit_intel_scanner.name} found {len(findings)} finding(s)")
                
                for finding in findings:
                    result.add_finding(finding)
                
                completed += 1
                if self.progress_callback:
                    self.progress_callback({
                        'current_scanner': f'Completed {exploit_intel_scanner.name}',
                        'scanners_completed': completed,
                        'scanners_total': total_scanners,
                    })
            except Exception as e:
                error_msg = f"Exploit intelligence error: {str(e)}"
                logger.warning(f"{exploit_intel_scanner.name} failed: {error_msg}")
                result.scanner_errors[exploit_intel_scanner.name] = error_msg
        
        # Step 2: Scan discovered subdomains (limited to prevent resource exhaustion)
        if subdomain_urls and len(subdomain_urls) <= 5:  # Only scan if 5 or fewer subdomains
            logger.info(f"Scanning {len(subdomain_urls)} discovered subdomain(s)...")
            for subdomain_url in subdomain_urls:
                try:
                    subdomain_target = ScanTarget(url=subdomain_url)
                    logger.info(f"Scanning subdomain: {subdomain_url}")
                    
                    # Run quick scans on subdomains (limited scanners)
                    for scanner in scanners_to_run_filtered:
                        if scanner.name in ['nuclei', 'wordpress_analyzer']:  # Only run lightweight scanners
                            try:
                                findings = scanner.scan(subdomain_target)
                                for finding in findings:
                                    # Mark as subdomain finding
                                    finding.metadata = finding.metadata or {}
                                    finding.metadata['subdomain'] = subdomain_url
                                    finding.title = f"[{subdomain_url}] {finding.title}"
                                    result.add_finding(finding)
                            except Exception as e:
                                logger.debug(f"Subdomain scan failed for {scanner.name} on {subdomain_url}: {e}")
                except Exception as e:
                    logger.warning(f"Failed to scan subdomain {subdomain_url}: {e}")
        elif subdomain_urls:
            logger.info(f"Discovered {len(subdomain_urls)} subdomains, skipping subdomain scans (too many to scan efficiently)")
        
        # Run WordPress Analyzer after other scanners (it will detect WordPress itself if needed)
        if wp_analyzer:
            logger.info(f"Running {wp_analyzer.name} scanner...")
            
            if self.progress_callback:
                self.progress_callback({
                    'current_scanner': f'Running {wp_analyzer.name}...',
                    'scanners_completed': completed,
                    'scanners_total': total_scanners,
                })
            
            result.scanners_run.append(wp_analyzer.name)
            
            try:
                findings = wp_analyzer.scan(target)
                logger.info(f"{wp_analyzer.name} found {len(findings)} finding(s)")
                
                for finding in findings:
                    result.add_finding(finding)
                    # Track successful exploitations
                    if finding.exploited:
                        result.exploitations_successful += 1
                
                completed += 1
                if self.progress_callback:
                    self.progress_callback({
                        'current_scanner': f'Completed {wp_analyzer.name}',
                        'scanners_completed': completed,
                        'scanners_total': total_scanners,
                    })
            
            except TimeoutError as e:
                error_msg = f"Scanner timed out: {str(e)}"
                logger.warning(f"{wp_analyzer.name} timed out (this is OK for slow/unreachable targets)")
                result.scanner_errors[wp_analyzer.name] = error_msg
            except FileNotFoundError as e:
                error_msg = f"Scanner not found: {str(e)}"
                logger.error(f"{wp_analyzer.name} not found: {error_msg}")
                result.scanner_errors[wp_analyzer.name] = error_msg
            except ValueError as e:
                error_msg = f"Invalid input: {str(e)}"
                logger.error(f"{wp_analyzer.name} input error: {error_msg}")
                result.scanner_errors[wp_analyzer.name] = error_msg
            except Exception as e:
                error_msg = str(e)
                logger.error(f"{wp_analyzer.name} failed: {error_msg}", exc_info=logger.level == logging.DEBUG)
                result.scanner_errors[wp_analyzer.name] = error_msg
        
        # Step 2: Scan discovered subdomains (limited to prevent resource exhaustion)
        if subdomain_urls and len(subdomain_urls) <= 5:  # Only scan if 5 or fewer subdomains
            logger.info(f"Scanning {len(subdomain_urls)} discovered subdomain(s)...")
            for subdomain_url in subdomain_urls:
                try:
                    subdomain_target = ScanTarget(url=subdomain_url)
                    logger.info(f"Scanning subdomain: {subdomain_url}")
                    
                    # Run quick scans on subdomains (limited scanners)
                    for scanner in scanners_to_run_filtered:
                        if scanner.name in ['nuclei', 'wordpress_analyzer']:  # Only run lightweight scanners
                            try:
                                findings = scanner.scan(subdomain_target)
                                for finding in findings:
                                    # Mark as subdomain finding
                                    finding.metadata = finding.metadata or {}
                                    finding.metadata['subdomain'] = subdomain_url
                                    finding.title = f"[{subdomain_url}] {finding.title}"
                                    result.add_finding(finding)
                            except Exception as e:
                                logger.debug(f"Subdomain scan failed for {scanner.name} on {subdomain_url}: {e}")
                except Exception as e:
                    logger.warning(f"Failed to scan subdomain {subdomain_url}: {e}")
        elif subdomain_urls:
            logger.info(f"Discovered {len(subdomain_urls)} subdomains, skipping subdomain scans (too many to scan efficiently)")
        
        # Calculate risk score
        from .scoring.engine import RiskScoringEngine
        result.findings = RiskScoringEngine.enhance_findings_with_remediation(result.findings)
        result.risk_score = RiskScoringEngine.calculate_risk(result)
        
        # Generate AI analysis (non-blocking - if it fails, scan still succeeds)
        try:
            from .utils.ai_analyzer import generate_analysis
            logger.info("Generating AI analysis...")
            result.ai_analysis = generate_analysis(result)
            if result.ai_analysis:
                logger.info("AI analysis generated successfully")
            else:
                logger.debug("AI analysis not available (no API key or generation failed)")
        except Exception as e:
            logger.warning(f"Failed to generate AI analysis: {e}")
            result.ai_analysis = None  # Ensure it's None if generation fails
        
        result.scan_completed_at = datetime.utcnow()
        
        logger.info(f"Scan completed. Total findings: {len(result.findings)}")
        logger.info(f"Risk score: {result.risk_score.overall_score}/100 ({result.risk_score.risk_level.value})")
        
        if self.scan_mode == ScanMode.OFFENSIVE and result.exploitations_successful > 0:
            logger.warning(f"⚠️  {result.exploitations_successful} successful exploitation(s) detected!")
        
        return result

