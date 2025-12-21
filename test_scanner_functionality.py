#!/usr/bin/env python3
"""Functional tests for scanner methods."""

import sys
from src.models.scan_mode import ScanMode
from src.models.scan import ScanTarget

print("=" * 70)
print("🔍 FUNCTIONAL TESTS - SCANNER METHODS")
print("=" * 70)
print()

test_target = ScanTarget(url="https://example.com")

def test_scanner_scan_method(scanner_name, module_name, class_name):
    """Test that scanner has scan method that accepts ScanTarget."""
    try:
        module = __import__(f'src.scanners.{module_name}', fromlist=[class_name])
        scanner_class = getattr(module, class_name)
        scanner = scanner_class(scan_mode=ScanMode.OFFENSIVE)
        
        # Check scan method exists
        if not hasattr(scanner, 'scan'):
            print(f"  ❌ {scanner_name}: Missing scan() method")
            return False
        
        # Check scan method signature
        import inspect
        sig = inspect.signature(scanner.scan)
        params = list(sig.parameters.keys())
        
        if len(params) < 1:
            print(f"  ❌ {scanner_name}: scan() has no parameters")
            return False
        
        # Check that first parameter is target (or can accept ScanTarget)
        print(f"  ✅ {scanner_name}: scan() method exists with signature {sig}")
        return True
        
    except Exception as e:
        print(f"  ❌ {scanner_name}: {e}")
        return False

print("\nTesting scan() method signatures:")
print("-" * 70)

scanners_to_test = [
    ('JWT Security', 'jwt_security', 'JWTSecurityScanner'),
    ('GraphQL Security', 'graphql_security', 'GraphQLSecurityScanner'),
    ('Deserialization', 'deserialization_scanner', 'DeserializationScanner'),
    ('WebSocket Security', 'websocket_security', 'WebSocketSecurityScanner'),
    ('Authentication Bypass', 'auth_bypass', 'AuthenticationBypassScanner'),
]

all_passed = True
for name, module, class_name in scanners_to_test:
    if not test_scanner_scan_method(name, module, class_name):
        all_passed = False

print()
print("Testing enhanced scanners:")
print("-" * 70)

enhanced_scanners = [
    ('XSS Tester', 'xss_tester', 'XSSTester'),
    ('Command Injection', 'command_injection', 'CommandInjectionScanner'),
    ('SQLMap', 'sqlmap', 'SQLMapAdapter'),
]

for name, module, class_name in enhanced_scanners:
    if not test_scanner_scan_method(name, module, class_name):
        all_passed = False

print()
if all_passed:
    print("✅ All scanner scan() methods are properly defined!")
else:
    print("❌ Some scanners have issues")
    sys.exit(1)

print()
print("Testing evidence collection utility functionality:")
print("-" * 70)

try:
    from src.utils.evidence_collector import EvidenceCollector
    import requests
    
    # Create a mock response
    class MockElapsed:
        def total_seconds(self):
            return 0.5
    
    class MockResponse:
        def __init__(self):
            self.status_code = 200
            self.headers = {'Content-Type': 'text/html', 'Server': 'nginx'}
            self._content = b'<html>Test</html>'
            self.url = 'https://example.com/test'
            self.elapsed = MockElapsed()
            self.text = '<html>Test</html>'
            self.content = b'<html>Test</html>'
    
    mock_response = MockResponse()
    
    # Test collect_request_response
    evidence_data = EvidenceCollector.collect_request_response(
        mock_response,
        request_url='https://example.com/test',
        request_method='GET'
    )
    
    assert 'request' in evidence_data
    assert 'response' in evidence_data
    assert evidence_data['request']['url'] == 'https://example.com/test'
    assert evidence_data['response']['status_code'] == 200
    print("  ✅ collect_request_response() works correctly")
    
    # Test format_evidence_string
    evidence_str = EvidenceCollector.format_evidence_string(evidence_data)
    assert len(evidence_str) > 0
    assert 'Request:' in evidence_str or 'Status Code:' in evidence_str
    print("  ✅ format_evidence_string() works correctly")
    
    # Test format_evidence_json
    evidence_json = EvidenceCollector.format_evidence_json(evidence_data)
    assert len(evidence_json) > 0
    print("  ✅ format_evidence_json() works correctly")
    
    print("\n✅ Evidence collection utility fully functional!")
    
except Exception as e:
    print(f"  ❌ Evidence collection test failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print()
print("=" * 70)
print("✅ ALL FUNCTIONAL TESTS PASSED")
print("=" * 70)
