"""Test suite for robustness improvements."""

import unittest
import os
import sys
from unittest.mock import patch, MagicMock

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.utils.validators import (
    validate_url, validate_email, sanitize_input, 
    validate_scan_id, validate_path_traversal_safe
)
from src.utils.config_validator import ConfigValidator
from src.utils.config import Config
from src.utils.logging_config import setup_logging


class TestValidators(unittest.TestCase):
    """Test input validation utilities."""
    
    def test_validate_url_valid(self):
        """Test URL validation with valid URLs."""
        test_cases = [
            ("https://example.com", True),
            ("http://test.com", True),
            ("example.com", True),  # Should add https://
            ("https://subdomain.example.com", True),
            ("http://192.168.1.1", True),
            ("https://localhost", True),
            ("https://127.0.0.1:8080", True),
        ]
        
        for url, should_pass in test_cases:
            with self.subTest(url=url):
                is_valid, error_msg = validate_url(url)
                self.assertTrue(is_valid, f"URL '{url}' should be valid but got error: {error_msg}")
    
    def test_validate_url_invalid(self):
        """Test URL validation with invalid URLs."""
        test_cases = [
            ("", False),
            ("invalid", False),
            ("ftp://example.com", False),  # Unsupported scheme
            ("javascript:alert(1)", False),
            ("A" * 3000, False),  # Too long
            ("  ", False),  # Whitespace only
        ]
        
        for url, should_pass in test_cases:
            with self.subTest(url=url[:50]):
                is_valid, error_msg = validate_url(url)
                self.assertFalse(is_valid, f"URL '{url[:50]}' should be invalid but passed validation")
                self.assertIsNotNone(error_msg, "Error message should be provided")
    
    def test_validate_email_valid(self):
        """Test email validation with valid emails."""
        test_cases = [
            ("test@example.com", True),
            ("user.name@example.com", True),
            ("user+tag@example.co.uk", True),
            ("test123@test-domain.com", True),
        ]
        
        for email, should_pass in test_cases:
            with self.subTest(email=email):
                is_valid, error_msg = validate_email(email)
                self.assertTrue(is_valid, f"Email '{email}' should be valid but got error: {error_msg}")
    
    def test_validate_email_invalid(self):
        """Test email validation with invalid emails."""
        test_cases = [
            ("", False),
            ("invalid", False),
            ("@example.com", False),
            ("test@", False),
            ("test..test@example.com", False),  # Consecutive dots
            (".test@example.com", False),  # Leading dot
            ("test@.example.com", False),  # Leading dot in domain
            ("A" * 300, False),  # Too long
        ]
        
        for email, should_pass in test_cases:
            with self.subTest(email=email[:50]):
                is_valid, error_msg = validate_email(email)
                self.assertFalse(is_valid, f"Email '{email[:50]}' should be invalid but passed validation")
                self.assertIsNotNone(error_msg, "Error message should be provided")
    
    def test_sanitize_input(self):
        """Test input sanitization."""
        test_cases = [
            ("  test  ", "test"),
            ("test\nvalue", "test value"),
            ("test\x00null", "testnull"),
            ("test\tvalue", "test value"),
            ("test   value", "test value"),  # Multiple spaces
        ]
        
        for input_str, expected in test_cases:
            with self.subTest(input=input_str):
                result = sanitize_input(input_str)
                self.assertEqual(result, expected)
        
        # Test max_length
        long_input = "A" * 100
        result = sanitize_input(long_input, max_length=50)
        self.assertEqual(len(result), 50)
    
    def test_validate_path_traversal_safe(self):
        """Test path traversal validation."""
        base_dir = "/tmp/test"
        
        # Valid paths
        is_valid, _ = validate_path_traversal_safe("file.txt", base_dir)
        self.assertTrue(is_valid)
        
        # Invalid paths
        is_valid, _ = validate_path_traversal_safe("../etc/passwd", base_dir)
        self.assertFalse(is_valid)
        
        is_valid, _ = validate_path_traversal_safe("../../etc/passwd", base_dir)
        self.assertFalse(is_valid)
        
        is_valid, _ = validate_path_traversal_safe("/etc/passwd", base_dir)
        self.assertFalse(is_valid)


class TestConfigValidator(unittest.TestCase):
    """Test configuration validation."""
    
    def test_validate_config_default(self):
        """Test configuration validation with defaults."""
        is_valid, errors = ConfigValidator.validate_config()
        # Should be valid with default values
        self.assertTrue(is_valid, f"Default config should be valid, but got errors: {errors}")
    
    @patch.dict(os.environ, {'MAX_CONCURRENT_SCANS': '0'})
    def test_validate_config_invalid_max_scans(self):
        """Test validation catches invalid MAX_CONCURRENT_SCANS."""
        # Reload config to pick up new env var
        import importlib
        import src.utils.config_validator
        importlib.reload(src.utils.config_validator)
        
        is_valid, errors = ConfigValidator.validate_config()
        # Should find error
        self.assertFalse(is_valid)
        self.assertTrue(any('MAX_CONCURRENT_SCANS' in error for error in errors))


class TestConfig(unittest.TestCase):
    """Test Config class."""
    
    def test_get_request_timeout(self):
        """Test request timeout getter."""
        timeout = Config.get_request_timeout()
        self.assertIsInstance(timeout, tuple)
        self.assertEqual(len(timeout), 2)
        self.assertGreater(timeout[0], 0)  # connect timeout
        self.assertGreater(timeout[1], 0)  # read timeout
    
    def test_validate_config_default(self):
        """Test Config validation with defaults."""
        is_valid, errors = Config.validate_config()
        self.assertTrue(is_valid, f"Default Config should be valid, but got errors: {errors}")


class TestLoggingConfig(unittest.TestCase):
    """Test logging configuration."""
    
    def test_setup_logging_human(self):
        """Test human-readable logging setup."""
        setup_logging(level='INFO', format_type='human')
        import logging
        logger = logging.getLogger(__name__)
        logger.info("Test message")
        # Should not raise exception
    
    def test_setup_logging_json(self):
        """Test JSON logging setup."""
        setup_logging(level='INFO', format_type='json')
        import logging
        logger = logging.getLogger(__name__)
        logger.info("Test message")
        # Should not raise exception


if __name__ == '__main__':
    # Setup logging for tests
    setup_logging(level='INFO', format_type='human')
    
    # Run tests
    unittest.main(verbosity=2)
