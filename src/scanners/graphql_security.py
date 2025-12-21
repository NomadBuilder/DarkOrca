"""GraphQL Security Testing Scanner."""

import re
import requests
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


class GraphQLSecurityScanner(BaseScanner):
    """Scanner for GraphQL security vulnerabilities."""
    
    def __init__(self, enabled: bool = True, scan_mode: ScanMode = ScanMode.DEFENSIVE):
        """
        Initialize GraphQL security scanner.
        
        Args:
            enabled: Whether scanner is enabled
            scan_mode: Scan mode (defensive or offensive)
        """
        super().__init__(
            name="graphql_security",
            command=None,  # Python-based
            enabled=enabled,
            scan_mode=scan_mode
        )
        # Use OPSEC-enabled session helper
        from ..utils.scanner_session import create_scanner_session
        self.session = create_scanner_session()
        # Set content type (needed for GraphQL requests)
        self.session.headers['Content-Type'] = 'application/json'
    
    def is_available(self) -> bool:
        """GraphQL security scanner is always available."""
        return True
    
    def scan(self, target: ScanTarget) -> List[Finding]:
        """Run GraphQL security tests."""
        if self.scan_mode == ScanMode.DEFENSIVE:
            return []  # Only run in offensive mode
        
        findings = []
        
        try:
            # Step 1: Detect GraphQL endpoint
            graphql_endpoints = self._discover_graphql_endpoints(target.url)
            
            if not graphql_endpoints:
                return findings  # No GraphQL found
            
            for endpoint in graphql_endpoints:
                findings.extend(self._test_graphql_endpoint(target.url, endpoint))
        
        except Exception as e:
            logger.debug(f"GraphQL security scan error: {e}")
        
        return findings
    
    def _discover_graphql_endpoints(self, url: str) -> List[str]:
        """Discover GraphQL endpoints."""
        endpoints = []
        common_paths = [
            '/graphql',
            '/graphql/',
            '/api/graphql',
            '/api/graphql/',
            '/v1/graphql',
            '/v2/graphql',
            '/query',
            '/gql',
            '/graph',
        ]
        
        # Try each common path
        for path in common_paths:
            try:
                test_url = urljoin(url, path)
                # Try introspection query
                response = self.session.post(
                    test_url,
                    json={'query': '{ __schema { types { name } } }'},
                    timeout=5
                )
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        # Check if response looks like GraphQL
                        if isinstance(data, dict) and ('data' in data or 'errors' in data):
                            endpoints.append(test_url)
                            logger.debug(f"Found GraphQL endpoint: {test_url}")
                    except:
                        pass
            except:
                continue
        
        # Also check if GraphQL is mentioned in page source
        try:
            response = self.session.get(url, timeout=10)
            if 'graphql' in response.text.lower() or 'graphiql' in response.text.lower():
                # Try to extract GraphQL endpoint from page
                pattern = r'["\']([^"\']*graphql[^"\']*)["\']'
                matches = re.findall(pattern, response.text, re.IGNORECASE)
                for match in matches:
                    endpoint = urljoin(url, match)
                    if endpoint not in endpoints:
                        endpoints.append(endpoint)
        except:
            pass
        
        return endpoints
    
    def _test_graphql_endpoint(self, base_url: str, endpoint: str) -> List[Finding]:
        """Test GraphQL endpoint for security vulnerabilities."""
        findings = []
        
        # Test 1: Introspection enabled
        introspection_enabled = self._test_introspection(endpoint)
        if introspection_enabled:
                    # Collect evidence
                    try:
                        test_response = self.session.post(endpoint, json={'query': '{ __schema { queryType { name } } }'}, timeout=5)
                        evidence_data = EvidenceCollector.collect_request_response(test_response, request_url=endpoint, request_method="POST")
                        evidence_str = EvidenceCollector.format_evidence_string(evidence_data)
                    except:
                        evidence_str = "Introspection query returned schema information"
                    
                    findings.append(Finding(
                        title="GraphQL Introspection Enabled",
                        description=f"GraphQL introspection is enabled at {endpoint}. This exposes the entire schema, including types, queries, mutations, and fields.",
                        severity=FindingSeverity.MEDIUM,
                        category=FindingCategory.INFORMATION_DISCLOSURE,
                        source_scanner=self.name,
                        url=endpoint,
                        evidence=evidence_str,
                remediation="Disable introspection in production. Use schema introspection only in development environments. Implement access controls if introspection is required.",
                references=["https://blog.doyensec.com/2018/05/17/graphql-security-overview.html"],
                metadata={'endpoint': endpoint, 'introspection_enabled': True}
            ))
        
        # Test 2: Depth limiting bypass (DoS via deeply nested queries)
        depth_bypass = self._test_depth_limiting(endpoint)
        if depth_bypass:
            findings.append(Finding(
                title="GraphQL Depth Limiting Missing or Bypassed",
                description=f"GraphQL endpoint at {endpoint} does not enforce query depth limits or limits can be bypassed. This enables DoS attacks via deeply nested queries.",
                severity=FindingSeverity.HIGH,
                category=FindingCategory.WEAK_SECURITY,
                source_scanner=self.name,
                url=endpoint,
                evidence=f"Deeply nested query (depth {depth_bypass}) was accepted",
                remediation="Implement query depth limiting (recommended: max depth 6-10). Use libraries like graphql-depth-limit. Also implement query cost analysis and rate limiting.",
                references=["https://www.apollographql.com/blog/graphql/security/securing-your-graphql-api-from-malicious-queries/"],
                metadata={'max_depth_accepted': depth_bypass}
            ))
        
        # Test 3: Query complexity/DoS
        complexity_issue = self._test_query_complexity(endpoint)
        if complexity_issue:
            findings.append(Finding(
                title="GraphQL Query Complexity Not Limited",
                description=f"GraphQL endpoint may be vulnerable to resource exhaustion attacks via complex queries that request large amounts of data.",
                severity=FindingSeverity.MEDIUM,
                category=FindingCategory.WEAK_SECURITY,
                source_scanner=self.name,
                url=endpoint,
                remediation="Implement query complexity analysis. Set maximum query cost/points. Use pagination for list fields. Implement rate limiting per query complexity.",
                metadata={'complexity_test': complexity_issue}
            ))
        
        # Test 4: GraphQL injection (if we can identify queries)
        injection_findings = self._test_graphql_injection(endpoint)
        findings.extend(injection_findings)
        
        # Test 5: Batch query attacks
        batch_finding = self._test_batch_queries(endpoint)
        if batch_finding:
            findings.append(batch_finding)
        
        return findings
    
    def _test_introspection(self, endpoint: str) -> bool:
        """Test if GraphQL introspection is enabled."""
        try:
            introspection_query = {
                'query': '{ __schema { queryType { name } mutationType { name } types { name kind description } } }'
            }
            response = self.session.post(endpoint, json=introspection_query, timeout=5)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    if 'data' in data and '__schema' in data['data']:
                        return True
                except:
                    pass
        except:
            pass
        return False
    
    def _test_depth_limiting(self, endpoint: str) -> Optional[int]:
        """Test query depth limits by sending progressively deeper queries."""
        # Start with a simple query structure
        for depth in [10, 15, 20, 30, 50]:
            try:
                # Create a nested query
                query = '{ __typename ' + ' { __typename ' * depth + ' }' * (depth + 1)
                payload = {'query': query}
                
                response = self.session.post(endpoint, json=payload, timeout=10)
                if response.status_code == 200:
                    try:
                        data = response.json()
                        # If no error about depth, it might be accepted
                        if 'data' in data or ('errors' not in data or 'depth' not in str(data.get('errors', [])).lower()):
                            # Try a bit deeper to confirm
                            if depth >= 15:
                                return depth
                    except:
                        pass
            except:
                continue
        return None
    
    def _test_query_complexity(self, endpoint: str) -> Optional[Dict]:
        """Test if query complexity is limited."""
        try:
            # Create a query that requests many fields
            query = '{ __typename ' + ' id name description ' * 50 + ' }'
            payload = {'query': query}
            
            response = self.session.post(endpoint, json=payload, timeout=10)
            if response.status_code == 200:
                try:
                    data = response.json()
                    # If no complexity limit error, might be vulnerable
                    if 'errors' not in data or 'complexity' not in str(data.get('errors', [])).lower():
                        return {'status': 'complexity_not_limited'}
                except:
                    pass
        except:
            pass
        return None
    
    def _test_graphql_injection(self, endpoint: str) -> List[Finding]:
        """Test for GraphQL injection vulnerabilities."""
        findings = []
        
        # GraphQL injection payloads
        injection_payloads = [
            # SQL injection in arguments
            {'query': 'query { user(id: "1 OR 1=1") { name } }'},
            {'query': 'query { user(id: "1; DROP TABLE users--") { name } }'},
            # NoSQL injection
            {'query': 'query { user(id: "1 || 1==1") { name } }'},
            # Command injection
            {'query': 'query { user(id: "1; whoami") { name } }'},
            # XSS in string arguments
            {'query': 'query { user(id: "1") { name(comment: "<script>alert(1)</script>") } }'},
        ]
        
        for payload in injection_payloads:
            try:
                response = self.session.post(endpoint, json=payload, timeout=5)
                if response.status_code == 200:
                    # Check for SQL errors or unusual responses
                    response_text = response.text.lower()
                    sql_errors = ['sql', 'database', 'mysql', 'postgresql', 'syntax error', 'unexpected token']
                    if any(error in response_text for error in sql_errors):
                        findings.append(Finding(
                            title="Potential GraphQL Injection Vulnerability",
                            description=f"GraphQL endpoint may be vulnerable to injection attacks. SQL/database errors detected in response to malicious query.",
                            severity=FindingSeverity.HIGH,
                            category=FindingCategory.VULNERABILITY,
                            source_scanner=self.name,
                            url=endpoint,
                            evidence=f"Injection payload triggered database errors",
                            remediation="Sanitize and validate all GraphQL arguments. Use parameterized queries for database operations. Implement input validation at the GraphQL resolver level.",
                            metadata={'payload': payload}
                        ))
                        break  # Found one, don't spam
            except:
                continue
        
        return findings
    
    def _test_batch_queries(self, endpoint: str) -> Optional[Finding]:
        """Test for batch query vulnerabilities (rate limiting bypass)."""
        try:
            # Send multiple queries in one request
            batch_query = [
                {'query': '{ __typename }'},
                {'query': '{ __typename }'},
                {'query': '{ __typename }'},
            ] * 10  # 30 queries in batch
            
            response = self.session.post(endpoint, json=batch_query, timeout=10)
            if response.status_code == 200:
                try:
                    data = response.json()
                    # If batch was processed, might bypass rate limits
                    if isinstance(data, list) and len(data) > 1:
                        return Finding(
                            title="GraphQL Batch Query Support",
                            description=f"GraphQL endpoint supports batch queries (array of queries). This may bypass rate limiting if not properly handled.",
                            severity=FindingSeverity.LOW,
                            category=FindingCategory.INFORMATION_DISCLOSURE,
                            source_scanner=self.name,
                            url=endpoint,
                            remediation="Ensure rate limiting applies to batch queries, not just individual queries. Consider limiting batch size and total query complexity per batch.",
                            metadata={'batch_size': len(batch_query)}
                        )
                except:
                    pass
        except:
            pass
        return None
