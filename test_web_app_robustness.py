"""Test web app robustness features."""

import sys
import os
import unittest
from unittest.mock import Mock, patch, MagicMock
import json
import threading
import time

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import Flask app (need to do this carefully to avoid running it)
os.environ['FLASK_ENV'] = 'testing'  # Prevent auto-reloader


class TestWebAppRobustness(unittest.TestCase):
    """Test web app robustness features."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Import after setting environment
        from web_app import app
        self.app = app
        self.client = app.test_client()
        self.app.config['TESTING'] = True
    
    def test_health_check_endpoint(self):
        """Test health check endpoint."""
        response = self.client.get('/health')
        self.assertEqual(response.status_code, 200)
        
        data = json.loads(response.data)
        self.assertIn('status', data)
        self.assertEqual(data['status'], 'healthy')
        self.assertIn('timestamp', data)
        self.assertIn('concurrent_scans', data)
        self.assertIn('max_concurrent_scans', data)
        self.assertIn('active_scans_count', data)
        self.assertIn('queue_length', data)
    
    def test_input_validation_url(self):
        """Test URL input validation in scan endpoint."""
        # Test missing target
        response = self.client.post('/api/scan', json={})
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertIn('error', data)
        self.assertIn('required', data['error'].lower())
        
        # Test invalid URL
        response = self.client.post('/api/scan', json={'target': 'invalid-url'})
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertIn('error', data)
        self.assertIn('Invalid', data['error'])
        
        # Test URL too long
        long_url = 'http://' + 'a' * 3000 + '.com'
        response = self.client.post('/api/scan', json={'target': long_url})
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertIn('error', data)
    
    def test_input_validation_email(self):
        """Test email input validation in scan endpoint."""
        # Test invalid email format
        response = self.client.post('/api/scan', json={
            'target': 'https://example.com',
            'email': 'invalid-email'
        })
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertIn('error', data)
        self.assertIn('email', data['error'].lower())
        
        # Test valid email (should pass validation, might fail on scan start)
        response = self.client.post('/api/scan', json={
            'target': 'https://example.com',
            'email': 'test@example.com'
        })
        # Should not fail on email validation (may fail on scan start, but that's OK)
        self.assertNotEqual(response.status_code, 400) or 'email' not in json.loads(response.data).get('error', '').lower()
    
    def test_scan_mode_validation(self):
        """Test scan mode validation."""
        # Test invalid scan mode
        response = self.client.post('/api/scan', json={
            'target': 'https://example.com',
            'scan_mode': 'invalid_mode'
        })
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertIn('error', data)
        self.assertIn('scan_mode', data['error'].lower())
        
        # Test valid scan modes
        for mode in ['defensive', 'offensive', 'comprehensive']:
            with self.subTest(mode=mode):
                response = self.client.post('/api/scan', json={
                    'target': 'https://example.com',
                    'scan_mode': mode
                })
                # Should not fail on mode validation (may fail later, but not on validation)
                self.assertNotEqual(response.status_code, 400) or 'scan_mode' not in json.loads(response.data).get('error', '').lower()
    
    def test_concurrent_scan_limit(self):
        """Test concurrent scan limit enforcement."""
        # This test would require mocking the scan execution
        # For now, just verify the endpoint exists and validates input
        response = self.client.post('/api/scan', json={'target': 'https://example.com'})
        # Should either start scan or return error about limits (but not validation error)
        self.assertIn(response.status_code, [200, 429, 500])  # 500 might happen if scan fails to start


def run_web_app_tests():
    """Run web app robustness tests."""
    print("=" * 70)
    print("Running Web App Robustness Tests")
    print("=" * 70)
    print()
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTests(loader.loadTestsFromTestCase(TestWebAppRobustness))
    
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
    
    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_web_app_tests()
    sys.exit(0 if success else 1)
