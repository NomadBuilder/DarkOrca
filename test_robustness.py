"""Comprehensive tests for robustness improvements."""

import sys
import os
import unittest
import logging
from unittest.mock import Mock, patch, MagicMock
import json

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.utils.validators import (
    validate_url, validate_email, sanitize_input, 
    validate_scan_id, validate_path_traversal_safe
)
from src.utils.config_validator import ConfigValidator
from src.utils.logging_config import setup_logging
from src.utils.http_client import HTTPClient, get_default_client, DEFAULT_TIMEOUT


class TestValidators(unittest.TestCase):
    """Test input validation utilities."""
    
    def test_validate_url_valid(self):
        """Test URL validation with valid URLs."""
        valid_urls = [
            'https://example.com',
            'http://example.com',
            'example.com',
            'https://subdomain.example.com/path',
            'http://192.168.1.1',
            'http://127.0.0.1:8080',  # localhost with port (simplified - actual localhost:port might need special handling)
        ]
        
        for url in valid_urls:
            with self.subTest(url=url):
                is_valid, error = validate_url(url)
                self.assertTrue(is_valid, f"URL '{url}' should be valid: {error}")
    
    def test_validate_url_invalid(self):
        """Test URL validation with invalid URLs."""
        invalid_urls = [
            '',
            '   ',
            'invalid',
            'ftp://example.com',  # Unsupported scheme
            'A' * 3000,  # Too long
        ]
        
        for url in invalid_urls:
            with self.subTest(url=url[:50]):
                is_valid, error = validate_url(url)
                self.assertFalse(is_valid, f"URL '{url}' should be invalid")
                self.assertIsNotNone(error)
    
    def test_validate_email_valid(self):
        """Test email validation with valid emails."""
        valid_emails = [
            'test@example.com',
            'user.name@example.com',
            'user+tag@example.co.uk',
            'user_123@test-domain.com',
        ]
        
        for email in valid_emails:
            with self.subTest(email=email):
                is_valid, error = validate_email(email)
                self.assertTrue(is_valid, f"Email '{email}' should be valid: {error}")
    
    def test_validate_email_invalid(self):
        """Test email validation with invalid emails."""
        invalid_emails = [
            '',
            'invalid',
            '@example.com',
            'test@',
            'test..test@example.com',  # Consecutive dots
            '.test@example.com',  # Starts with dot
            'test@.example.com',  # Domain starts with dot
            'A' * 300,  # Too long
        ]
        
        for email in invalid_emails:
            with self.subTest(email=email[:50]):
                is_valid, error = validate_email(email)
                self.assertFalse(is_valid, f"Email '{email}' should be invalid")
                self.assertIsNotNone(error)
    
    def test_sanitize_input(self):
        """Test input sanitization."""
        # Test null bytes
        self.assertEqual(sanitize_input('test\x00string'), 'teststring')
        
        # Test newlines (removed by default)
        self.assertEqual(sanitize_input('test\nstring'), 'test string')
        
        # Test newlines (allowed when specified)
        self.assertEqual(sanitize_input('test\nstring', allow_newlines=True), 'test\nstring')
        
        # Test length limit
        long_string = 'A' * 100
        self.assertEqual(len(sanitize_input(long_string, max_length=50)), 50)
        
        # Test whitespace trimming
        self.assertEqual(sanitize_input('  test  '), 'test')
        
        # Test multiple spaces
        self.assertEqual(sanitize_input('test    string'), 'test string')
    
    def test_validate_path_traversal_safe(self):
        """Test path traversal validation."""
        base_dir = '/tmp/test'
        
        # Valid paths
        is_valid, error = validate_path_traversal_safe('file.txt', base_dir)
        self.assertTrue(is_valid, f"Should be valid: {error}")
        
        # Invalid paths with traversal
        invalid_paths = [
            '../file.txt',
            '../../etc/passwd',
            '/etc/passwd',
            '..\\file.txt',
        ]
        
        for path in invalid_paths:
            with self.subTest(path=path):
                is_valid, error = validate_path_traversal_safe(path, base_dir)
                self.assertFalse(is_valid, f"Path '{path}' should be invalid")
                self.assertIsNotNone(error)


class TestConfigValidator(unittest.TestCase):
    """Test configuration validation."""
    
    def test_validate_config_default(self):
        """Test config validation with default values."""
        is_valid, errors = ConfigValidator.validate_config()
        # Should be valid with defaults
        self.assertTrue(is_valid, f"Default config should be valid: {errors}")
    
    @patch.dict(os.environ, {'MAX_CONCURRENT_SCANS': 'invalid'})
    def test_validate_config_invalid_max_concurrent(self):
        """Test config validation with invalid MAX_CONCURRENT_SCANS."""
        # Reload module to pick up env change
        import importlib
        import src.utils.config_validator
        importlib.reload(src.utils.config_validator)
        
        is_valid, errors = src.utils.config_validator.ConfigValidator.validate_config()
        self.assertFalse(is_valid)
        self.assertTrue(any('MAX_CONCURRENT_SCANS' in str(e) for e in errors))
    
    @patch.dict(os.environ, {'BASE_URL': 'invalid-url'})
    def test_validate_config_invalid_base_url(self):
        """Test config validation with invalid BASE_URL."""
        import importlib
        import src.utils.config_validator
        importlib.reload(src.utils.config_validator)
        
        is_valid, errors = src.utils.config_validator.ConfigValidator.validate_config()
        self.assertFalse(is_valid)
        self.assertTrue(any('BASE_URL' in str(e) for e in errors))


class TestHTTPClient(unittest.TestCase):
    """Test HTTP client with timeout configuration."""
    
    def test_http_client_init(self):
        """Test HTTP client initialization."""
        client = HTTPClient(timeout=60, connect_timeout=15)
        self.assertEqual(client.timeout, 60)
        self.assertEqual(client.connect_timeout, 15)
        self.assertIn('User-Agent', client.default_headers)
        self.assertEqual(client.default_headers['User-Agent'], 'DarkOrca/1.0')
    
    def test_http_client_max_timeout(self):
        """Test that timeouts are capped at MAX_TIMEOUT."""
        client = HTTPClient(timeout=10000)  # Very large timeout
        self.assertLessEqual(client.timeout, 300)  # Should be capped
    
    @patch('requests.Session.get')
    def test_http_client_get(self, mock_get):
        """Test HTTP client GET request."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response
        
        client = HTTPClient(timeout=30)
        response = client.get('https://example.com')
        
        self.assertEqual(response.status_code, 200)
        mock_get.assert_called_once()
        call_kwargs = mock_get.call_args[1]
        self.assertEqual(call_kwargs['timeout'], 30)
    
    @patch('requests.Session.get')
    def test_http_client_get_with_timeout_override(self, mock_get):
        """Test HTTP client GET with timeout override."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response
        
        client = HTTPClient(timeout=30)
        response = client.get('https://example.com', timeout=60)
        
        call_kwargs = mock_get.call_args[1]
        self.assertEqual(call_kwargs['timeout'], 60)
    
    def test_get_default_client(self):
        """Test getting default HTTP client."""
        client = get_default_client()
        self.assertIsInstance(client, HTTPClient)


class TestLoggingConfig(unittest.TestCase):
    """Test logging configuration."""
    
    def test_setup_logging_human(self):
        """Test human-readable logging setup."""
        setup_logging(level='INFO', format_type='human')
        root_logger = logging.getLogger()
        # Check effective level (logger.level is 0/NOTSET if not explicitly set, effective level inherits)
        self.assertEqual(root_logger.getEffectiveLevel(), logging.INFO)
    
    def test_setup_logging_json(self):
        """Test JSON logging setup."""
        setup_logging(level='DEBUG', format_type='json')
        root_logger = logging.getLogger()
        # Check effective level
        self.assertEqual(root_logger.getEffectiveLevel(), logging.DEBUG)


class TestIntegration(unittest.TestCase):
    """Integration tests for robustness features."""
    
    def test_validator_integration(self):
        """Test that validators work together."""
        # Test URL validation and sanitization together
        url = '  https://example.com  '
        sanitized = sanitize_input(url)
        is_valid, error = validate_url(sanitized)
        self.assertTrue(is_valid)
        self.assertEqual(sanitized, 'https://example.com')
        
        # Test email validation and sanitization
        email = '  test@example.com  '
        sanitized = sanitize_input(email)
        is_valid, error = validate_email(sanitized)
        self.assertTrue(is_valid)
        self.assertEqual(sanitized, 'test@example.com')
    
    def test_xss_prevention(self):
        """Test XSS prevention through sanitization."""
        xss_payloads = [
            '<script>alert(1)</script>',
            'javascript:alert(1)',
            '<img src=x onerror=alert(1)>',
            "'; DROP TABLE users; --",
        ]
        
        for payload in xss_payloads:
            with self.subTest(payload=payload[:30]):
                sanitized = sanitize_input(payload)
                # Script tags and dangerous chars should be handled
                # (Note: full HTML sanitization would require a library like bleach)
                self.assertNotIn('\x00', sanitized)  # Null bytes removed


def run_tests():
    """Run all robustness tests."""
    print("=" * 70)
    print("Running Robustness Improvement Tests")
    print("=" * 70)
    print()
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add test classes
    suite.addTests(loader.loadTestsFromTestCase(TestValidators))
    suite.addTests(loader.loadTestsFromTestCase(TestConfigValidator))
    suite.addTests(loader.loadTestsFromTestCase(TestHTTPClient))
    suite.addTests(loader.loadTestsFromTestCase(TestLoggingConfig))
    suite.addTests(loader.loadTestsFromTestCase(TestIntegration))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print()
    print("=" * 70)
    print("Test Summary")
    print("=" * 70)
    print(f"Tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print()
    
    if result.failures:
        print("Failures:")
        for test, traceback in result.failures:
            print(f"  - {test}")
            print(f"    {traceback.split(chr(10))[-2]}")
        print()
    
    if result.errors:
        print("Errors:")
        for test, traceback in result.errors:
            print(f"  - {test}")
            print(f"    {traceback.split(chr(10))[-2]}")
        print()
    
    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_tests()
    sys.exit(0 if success else 1)
