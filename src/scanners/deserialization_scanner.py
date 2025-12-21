"""Deserialization Attack Scanner - Tests for insecure deserialization vulnerabilities."""

import re
import requests
import base64
import json
from typing import List, Optional, Dict, Any
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

from .base import BaseScanner
from ..models.scan import ScanTarget
from ..models.finding import Finding, FindingSeverity, FindingCategory
from ..models.scan_mode import ScanMode
from ..utils.evidence_collector import EvidenceCollector

import logging
logger = logging.getLogger(__name__)


class DeserializationScanner(BaseScanner):
    """Scanner for insecure deserialization vulnerabilities (Java, PHP, Python, .NET)."""
    
    def __init__(self, enabled: bool = True, scan_mode: ScanMode = ScanMode.DEFENSIVE):
        """
        Initialize deserialization scanner.
        
        Args:
            enabled: Whether scanner is enabled
            scan_mode: Scan mode (defensive or offensive)
        """
        super().__init__(
            name="deserialization",
            command=None,  # Python-based
            enabled=enabled,
            scan_mode=scan_mode
        )
        # Use OPSEC-enabled session helper
        from ..utils.scanner_session import create_scanner_session
        self.session = create_scanner_session()
        # Set content type (needed for deserialization testing)
        self.session.headers['Content-Type'] = 'application/json'
    
    def is_available(self) -> bool:
        """Deserialization scanner is always available."""
        return True
    
    def scan(self, target: ScanTarget) -> List[Finding]:
        """Run deserialization tests."""
        if self.scan_mode == ScanMode.DEFENSIVE:
            return []  # Only run in offensive mode
        
        findings = []
        
        try:
            # Test different deserialization types
            findings.extend(self._test_java_deserialization(target.url))
            findings.extend(self._test_php_deserialization(target.url))
            findings.extend(self._test_python_deserialization(target.url))
            findings.extend(self._test_dotnet_deserialization(target.url))
            findings.extend(self._test_yaml_deserialization(target.url))
        
        except Exception as e:
            logger.debug(f"Deserialization scan error: {e}")
        
        return findings
    
    def _test_java_deserialization(self, url: str) -> List[Finding]:
        """Test for Java deserialization vulnerabilities."""
        findings = []
        
        # Java serialized objects start with magic bytes: AC ED 00 05 (hex) or rO0 (base64)
        # Common Java deserialization payloads (base64 encoded Ysoserial-like payloads)
        java_payloads = [
            # Base64 encoded Java serialized objects (simplified detection payloads)
            # Note: Full Ysoserial payloads are large - using simplified detection
            ('rO0ABXNy', 'base64_java_serialized'),  # Common Java serialization header
            ('ACED0005', 'hex_java_serialized'),  # Hex representation
        ]
        
        # Test in various locations
        test_locations = self._get_test_locations(url)
        
        for location, method, data_key in test_locations:
            for payload, payload_type in java_payloads:
                try:
                    if method == 'GET':
                        response = self.session.get(location, params={data_key: payload}, timeout=5)
                    elif method == 'POST':
                        if 'json' in self.session.headers.get('Content-Type', ''):
                            response = self.session.post(location, json={data_key: payload}, timeout=5)
                        else:
                            response = self.session.post(location, data={data_key: payload}, timeout=5)
                    else:
                        continue
                    
                    # Check for Java deserialization error indicators
                    error_indicators = [
                        'java.io',
                        'readObject',
                        'InvalidClassException',
                        'ClassNotFoundException',
                        'SerializationException',
                        'NotSerializableException',
                    ]
                    
                    response_text = response.text.lower()
                    if any(indicator.lower() in response_text for indicator in error_indicators):
                        findings.append(Finding(
                            title="Potential Java Deserialization Vulnerability",
                            description=f"Java deserialization error detected when sending serialized object to {location}. This may indicate insecure deserialization.",
                            severity=FindingSeverity.HIGH,
                            category=FindingCategory.VULNERABILITY,
                            source_scanner=self.name,
                            url=location,
                            evidence=f"Java serialization error in response. Payload type: {payload_type}",
                            remediation="Never deserialize untrusted data. Use whitelisting for allowed classes. Consider using safer alternatives like JSON. Validate all input before deserialization.",
                            references=["https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data"],
                            metadata={'type': 'java', 'payload_type': payload_type, 'parameter': data_key}
                        ))
                        break  # Found issue, move to next location
                
                except Exception as e:
                    logger.debug(f"Java deserialization test error: {e}")
                    continue
        
        return findings
    
    def _test_php_deserialization(self, url: str) -> List[Finding]:
        """Test for PHP deserialization vulnerabilities."""
        findings = []
        
        # PHP serialized format: O:8:"stdClass":1:{s:4:"test";s:4:"data";}
        # PHP POP (Property Oriented Programming) chain payloads
        php_payloads = [
            # Basic PHP serialized object
            ('O:8:"stdClass":1:{s:4:"test";s:4:"data";}', 'php_serialized'),
            # PHP POP chain attempt
            ('O:1:"A":1:{s:4:"prop";s:10:"test_value";}', 'php_pop'),
            # Unserialize with dangerous class
            ('O:7:"SplFile":1:{s:4:"path";s:10:"/etc/passwd";}', 'php_splfile'),
        ]
        
        test_locations = self._get_test_locations(url)
        
        for location, method, data_key in test_locations:
            for payload, payload_type in php_payloads:
                try:
                    if method == 'GET':
                        response = self.session.get(location, params={data_key: payload}, timeout=5)
                    elif method == 'POST':
                        response = self.session.post(location, data={data_key: payload}, timeout=5)
                    else:
                        continue
                    
                    # Check for PHP unserialize error indicators
                    error_indicators = [
                        'unserialize()',
                        'unserialize',
                        'php_unserialize',
                        'syntax error',
                        'unexpected',
                    ]
                    
                    # Also check for file disclosure (if POP chain worked)
                    file_indicators = [
                        'root:x:',
                        '[extensions]',
                    ]
                    
                    response_text = response.text.lower()
                    if any(indicator.lower() in response_text for indicator in error_indicators):
                        # Check if it's a syntax error (normal) vs actual deserialization attempt
                        if 'syntax error' not in response_text or 'unserialize' in response_text:
                            findings.append(Finding(
                                title="Potential PHP Deserialization Vulnerability",
                                description=f"PHP deserialization detected at {location}. Application processes serialized data which may be exploitable.",
                                severity=FindingSeverity.HIGH,
                                category=FindingCategory.VULNERABILITY,
                                source_scanner=self.name,
                                url=location,
                                evidence=f"PHP unserialize() error or processing detected. Payload type: {payload_type}",
                                remediation="Avoid unserialize() with user input. Use json_decode() or other safe alternatives. Whitelist allowed classes if deserialization is necessary.",
                                references=["https://owasp.org/www-community/vulnerabilities/PHP_Object_Injection"],
                                metadata={'type': 'php', 'payload_type': payload_type, 'parameter': data_key}
                            ))
                            break
                    
                    # Check for file content (successful POP chain)
                    if any(indicator in response.text for indicator in file_indicators):
                        findings.append(Finding(
                            title="PHP Deserialization Exploitation Successful",
                            description=f"PHP deserialization POP chain successfully executed at {location}. File content was retrieved, indicating code execution capability.",
                            severity=FindingSeverity.CRITICAL,
                            category=FindingCategory.EXPLOITATION,
                            source_scanner=self.name,
                            url=location,
                            evidence=f"File content retrieved via PHP deserialization. Payload type: {payload_type}",
                            exploitation_details=f"PHP POP chain executed successfully, allowing file read/command execution.",
                            remediation="Immediately disable unserialize() on untrusted input. Migrate to JSON-based data formats.",
                            references=["https://owasp.org/www-community/vulnerabilities/PHP_Object_Injection"],
                            metadata={'type': 'php_pop_success', 'payload_type': payload_type}
                        ))
                        break
                
                except Exception as e:
                    logger.debug(f"PHP deserialization test error: {e}")
                    continue
        
        return findings
    
    def _test_python_deserialization(self, url: str) -> List[Finding]:
        """Test for Python pickle deserialization vulnerabilities."""
        findings = []
        
        # Python pickle format detection
        # Pickle magic bytes: \x80\x03 (protocol 3) or \x80\x02 (protocol 2)
        # Base64 encoded pickle: gASV... or YnBvcA==
        python_payloads = [
            # Base64 encoded pickle (simplified)
            ('gASV', 'pickle_base64'),  # Common pickle base64 start
            # Pickle with RCE attempt (base64 encoded)
            # This is a simplified payload - real payloads would execute commands
            ('Y3BvcApxAQou', 'pickle_rce_attempt'),
        ]
        
        test_locations = self._get_test_locations(url)
        
        for location, method, data_key in test_locations:
            for payload, payload_type in python_payloads:
                try:
                    if method == 'GET':
                        response = self.session.get(location, params={data_key: payload}, timeout=5)
                    elif method == 'POST':
                        response = self.session.post(location, data={data_key: payload}, timeout=5)
                    else:
                        continue
                    
                    # Check for pickle error indicators
                    error_indicators = [
                        'pickle',
                        'pickling',
                        'unpickle',
                        'pickle.loads',
                        'pickle.load',
                        'PicklingError',
                        'UnpicklingError',
                    ]
                    
                    response_text = response.text.lower()
                    if any(indicator.lower() in response_text for indicator in error_indicators):
                        findings.append(Finding(
                            title="Potential Python Pickle Deserialization Vulnerability",
                            description=f"Python pickle deserialization detected at {location}. Pickle should never be used with untrusted data.",
                            severity=FindingSeverity.HIGH,
                            category=FindingCategory.VULNERABILITY,
                            source_scanner=self.name,
                            url=location,
                            evidence=f"Pickle processing detected. Payload type: {payload_type}",
                            remediation="Never use pickle.loads() or pickle.load() with user input. Use json.loads() or other safe serialization formats. Pickle is inherently insecure with untrusted data.",
                            references=["https://docs.python.org/3/library/pickle.html#warning"],
                            metadata={'type': 'python_pickle', 'payload_type': payload_type, 'parameter': data_key}
                        ))
                        break
                
                except Exception as e:
                    logger.debug(f"Python deserialization test error: {e}")
                    continue
        
        return findings
    
    def _test_dotnet_deserialization(self, url: str) -> List[Finding]:
        """Test for .NET deserialization vulnerabilities."""
        findings = []
        
        # .NET BinaryFormatter serialized objects
        # Base64 encoded: AAEAAAD... (common prefix)
        dotnet_payloads = [
            ('AAEAAAD', 'dotnet_binaryformatter'),  # Common .NET BinaryFormatter prefix
            ('AQAAAD', 'dotnet_soap'),
        ]
        
        test_locations = self._get_test_locations(url)
        
        for location, method, data_key in test_locations:
            for payload, payload_type in dotnet_payloads:
                try:
                    if method == 'GET':
                        response = self.session.get(location, params={data_key: payload}, timeout=5)
                    elif method == 'POST':
                        response = self.session.post(location, data={data_key: payload}, timeout=5)
                    else:
                        continue
                    
                    # Check for .NET deserialization error indicators
                    error_indicators = [
                        'System.Runtime.Serialization',
                        'BinaryFormatter',
                        'Deserialize',
                        'SerializationException',
                        'InvalidOperationException',
                        'ObjectDisposedException',
                    ]
                    
                    response_text = response.text.lower()
                    if any(indicator.lower() in response_text for indicator in error_indicators):
                        findings.append(Finding(
                            title="Potential .NET Deserialization Vulnerability",
                            description=f".NET deserialization detected at {location}. BinaryFormatter deserialization with untrusted data is dangerous.",
                            severity=FindingSeverity.HIGH,
                            category=FindingCategory.VULNERABILITY,
                            source_scanner=self.name,
                            url=location,
                            evidence=f".NET deserialization error detected. Payload type: {payload_type}",
                            remediation="Avoid BinaryFormatter.Deserialize() with untrusted input. Use safer alternatives like DataContractSerializer or JSON. Microsoft recommends avoiding BinaryFormatter entirely.",
                            references=["https://docs.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide"],
                            metadata={'type': 'dotnet', 'payload_type': payload_type, 'parameter': data_key}
                        ))
                        break
                
                except Exception as e:
                    logger.debug(f".NET deserialization test error: {e}")
                    continue
        
        return findings
    
    def _test_yaml_deserialization(self, url: str) -> List[Finding]:
        """Test for YAML deserialization vulnerabilities (PyYAML, etc.)."""
        findings = []
        
        # YAML with dangerous Python code execution
        # PyYAML's yaml.load() is unsafe, yaml.safe_load() is safe
        yaml_payloads = [
            # Dangerous YAML payload (PyYAML yaml.load)
            ('!!python/object/apply:os.system ["id"]', 'yaml_python_rce'),
            ('!!python/object/apply:subprocess.check_output [["ls"]]', 'yaml_python_rce2'),
            ('!!python/object/new:os.system ["whoami"]', 'yaml_python_rce3'),
        ]
        
        test_locations = self._get_test_locations(url)
        
        for location, method, data_key in test_locations:
            for payload, payload_type in yaml_payloads:
                try:
                    if method == 'GET':
                        response = self.session.get(location, params={data_key: payload}, timeout=5)
                    elif method == 'POST':
                        # YAML might be in request body
                        self.session.headers['Content-Type'] = 'application/x-yaml'
                        response = self.session.post(location, data=payload, timeout=5)
                        self.session.headers['Content-Type'] = 'application/json'
                    else:
                        continue
                    
                    # Check for command execution output
                    command_output_indicators = ['uid=', 'gid=', 'groups=', 'root']
                    
                    # Check for YAML parsing errors
                    yaml_errors = ['yaml', 'YAML', 'ScannerError', 'ParserError']
                    
                    response_text = response.text
                    if any(indicator in response_text for indicator in command_output_indicators):
                        findings.append(Finding(
                            title="YAML Deserialization Code Execution",
                            description=f"YAML deserialization code execution confirmed at {location}. Dangerous yaml.load() is being used with untrusted input.",
                            severity=FindingSeverity.CRITICAL,
                            category=FindingCategory.EXPLOITATION,
                            source_scanner=self.name,
                            url=location,
                            evidence=f"Command execution output detected. Payload type: {payload_type}",
                            exploitation_details=f"YAML deserialization allows arbitrary code execution. Command was executed successfully.",
                            remediation="Replace yaml.load() with yaml.safe_load(). Never use yaml.load() with user input. Consider using JSON instead of YAML.",
                            references=["https://pyyaml.org/wiki/PyYAMLDocumentation#LoadingYAML"],
                            metadata={'type': 'yaml', 'payload_type': payload_type, 'parameter': data_key}
                        ))
                        break
                    elif any(indicator.lower() in response_text.lower() for indicator in yaml_errors):
                        findings.append(Finding(
                            title="Potential YAML Deserialization Vulnerability",
                            description=f"YAML processing detected at {location}. If using yaml.load() instead of yaml.safe_load(), this is dangerous.",
                            severity=FindingSeverity.HIGH,
                            category=FindingCategory.VULNERABILITY,
                            source_scanner=self.name,
                            url=location,
                            evidence=f"YAML parsing detected. Payload type: {payload_type}",
                            remediation="Ensure yaml.safe_load() is used instead of yaml.load(). yaml.load() allows arbitrary code execution.",
                            metadata={'type': 'yaml_unsafe', 'payload_type': payload_type}
                        ))
                        break
                
                except Exception as e:
                    logger.debug(f"YAML deserialization test error: {e}")
                    continue
        
        return findings
    
    def _get_test_locations(self, url: str) -> List[tuple]:
        """Get locations to test (URLs with parameters)."""
        locations = []
        
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            # Test GET parameters
            if params:
                base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                for param_name in list(params.keys())[:3]:  # Limit to 3 params
                    locations.append((base_url, 'GET', param_name))
            
            # Test POST endpoints (common API endpoints)
            api_endpoints = ['/api', '/api/data', '/api/serialize', '/api/process']
            for endpoint in api_endpoints:
                test_url = urljoin(url, endpoint)
                locations.append((test_url, 'POST', 'data'))
                locations.append((test_url, 'POST', 'input'))
                locations.append((test_url, 'POST', 'payload'))
        
        except Exception as e:
            logger.debug(f"Error getting test locations: {e}")
        
        return locations[:10]  # Limit total locations
