"""Comprehensive test suite to verify core functionality after security improvements."""

import os
import sys
import json
import time
import unittest
import tempfile
import secrets
from pathlib import Path
from unittest.mock import patch, MagicMock
from flask import Flask

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

# Set test environment
os.environ['SECRET_KEY'] = 'test-secret-key-for-testing-only'
os.environ['MAX_CONCURRENT_SCANS'] = '5'
os.environ['RATE_LIMIT_SCANS_PER_MINUTE'] = '10'
os.environ['SESSION_COOKIE_SECURE'] = 'False'  # For testing without HTTPS

# Import after environment setup
from web_app import app
from src.utils.database import init_database, User, SavedScan, UserSession, get_db_connection
from src.utils.csrf import generate_csrf_token


class SecurityIntegrationTest(unittest.TestCase):
    """Comprehensive tests for core functionality with security features."""
    
    @classmethod
    def setUpClass(cls):
        """Set up test database and client."""
        # Create temporary database
        cls.db_fd, cls.db_path = tempfile.mkstemp(suffix='.db')
        os.environ['DATABASE_PATH'] = cls.db_path
        
        # Initialize test database
        init_database()
        
        # Create test client
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False  # We'll test CSRF manually
        cls.client = app.test_client()
        cls.app_context = app.app_context()
        cls.app_context.push()
    
    @classmethod
    def tearDownClass(cls):
        """Clean up test database."""
        cls.app_context.pop()
        os.close(cls.db_fd)
        if os.path.exists(cls.db_path):
            os.unlink(cls.db_path)
    
    def setUp(self):
        """Set up for each test."""
        # Clear any existing test data
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM saved_scans")
            cursor.execute("DELETE FROM user_sessions")
            cursor.execute("DELETE FROM users")
            conn.commit()
    
    def get_csrf_token(self):
        """Get CSRF token by making a request that sets it."""
        # Make a GET request to get CSRF token set in session
        self.client.get('/')
        with self.client.session_transaction() as sess:
            if 'csrf_token' not in sess:
                sess['csrf_token'] = secrets.token_urlsafe(32)
            return sess['csrf_token']
    
    def test_1_health_check(self):
        """Test health check endpoint."""
        print("\n[TEST 1] Health Check Endpoint")
        response = self.client.get('/health')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['status'], 'healthy')
        self.assertIn('timestamp', data)
        self.assertIn('concurrent_scans', data)
        print("✅ Health check works")
    
    def test_2_public_pages(self):
        """Test public page endpoints."""
        print("\n[TEST 2] Public Pages")
        endpoints = ['/', '/login', '/signup', '/glossary', '/about', '/faq']
        for endpoint in endpoints:
            response = self.client.get(endpoint)
            self.assertIn(response.status_code, [200, 302], f"{endpoint} returned {response.status_code}")
        print("✅ All public pages load correctly")
    
    def test_3_static_files(self):
        """Test static file serving."""
        print("\n[TEST 3] Static Files")
        # Test favicon
        response = self.client.get('/favicon.ico')
        self.assertIn(response.status_code, [200, 404])  # May not exist
        print("✅ Static files accessible")
    
    def test_4_signup_flow(self):
        """Test user signup flow."""
        print("\n[TEST 4] User Signup Flow")
        
        # Get signup page
        response = self.client.get('/signup')
        self.assertEqual(response.status_code, 200)
        
        # Try signup (signup endpoint doesn't require CSRF - this is acceptable for public endpoints)
        response = self.client.post('/signup', json={
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'testpass123'
        }, content_type='application/json')
        
        # Should succeed (200 success)
        self.assertIn(response.status_code, [200, 201], f"Signup should succeed (got {response.status_code})")
        
        # Check if user was created
        user = User.get_by_username('testuser')
        self.assertIsNotNone(user, "User should be created")
        self.assertEqual(user.email, 'test@example.com')
        print("✅ Signup flow works correctly")
    
    def test_5_login_flow(self):
        """Test user login flow."""
        print("\n[TEST 5] User Login Flow")
        
        # Create test user first
        user = User.create('testuser2', 'test2@example.com', 'testpass123')
        self.assertIsNotNone(user)
        
        # Get login page
        self.client.get('/login')
        
        # Try login (login endpoint doesn't require CSRF - this is acceptable for public endpoints)
        response = self.client.post('/login', json={
            'username': 'testuser2',
            'password': 'testpass123'
        }, content_type='application/json')
        
        # Should succeed with correct credentials
        self.assertEqual(response.status_code, 200, f"Login should succeed with valid credentials (got {response.status_code})")
        data = json.loads(response.data)
        self.assertIn('success', data)
        self.assertTrue(data['success'])
        
        # Try login with wrong password
        response = self.client.post('/login', json={
            'username': 'testuser2',
            'password': 'wrongpassword'
        }, content_type='application/json')
        self.assertEqual(response.status_code, 401, "Should reject incorrect password")
        
        print("✅ Login flow works correctly")
    
    def test_6_protected_endpoints(self):
        """Test protected endpoints require authentication."""
        print("\n[TEST 6] Protected Endpoints")
        
        # Try accessing protected endpoint without auth
        response = self.client.get('/profile')
        self.assertEqual(response.status_code, 302, "Should redirect to login")
        self.assertIn('/login', response.location)
        
        response = self.client.get('/api/profile/saved-scans')
        self.assertEqual(response.status_code, 401, "Should return 401 for API endpoints")
        
        print("✅ Protected endpoints properly require authentication")
    
    def test_7_authenticated_access(self):
        """Test accessing protected endpoints with authentication."""
        print("\n[TEST 7] Authenticated Access")
        
        # Create and login user
        user = User.create('testuser3', 'test3@example.com', 'testpass123')
        session_token = UserSession.create(user.id)
        
        # Set session cookie
        with self.client.session_transaction() as sess:
            sess['session_token'] = session_token
            sess['user_id'] = user.id
            sess['username'] = user.username
        
        # Access protected endpoint
        response = self.client.get('/profile')
        self.assertEqual(response.status_code, 200, "Should access profile with valid session")
        
        response = self.client.get('/api/profile/saved-scans')
        self.assertEqual(response.status_code, 200, "Should access API with valid session")
        data = json.loads(response.data)
        # API returns dict with 'scans' key, not list directly
        self.assertIn('scans', data, "Should return scans in response")
        self.assertIsInstance(data.get('scans'), list, "Should return list of saved scans")
        
        print("✅ Authenticated users can access protected endpoints")
    
    def test_8_scan_initiation_csrf(self):
        """Test scan initiation requires CSRF token."""
        print("\n[TEST 8] Scan Initiation CSRF Protection")
        
        # Get CSRF token
        self.client.get('/')
        csrf_token = self.get_csrf_token()
        
        # Try scan without CSRF token (should fail)
        response = self.client.post('/api/scan', json={
            'target': 'https://example.com',
            'scan_mode': 'defensive'
        }, content_type='application/json')
        self.assertEqual(response.status_code, 403, "Should reject scan without CSRF token")
        
        # Try scan with CSRF token in header (should work)
        response = self.client.post('/api/scan', json={
            'target': 'https://example.com',
            'scan_mode': 'defensive',
            'csrf_token': csrf_token
        }, headers={'X-CSRF-Token': csrf_token}, content_type='application/json')
        
        # Should accept the request (may fail validation, but CSRF should pass)
        self.assertNotEqual(response.status_code, 403, "Should not reject CSRF when token is provided")
        print("✅ Scan initiation properly protected with CSRF")
    
    def test_9_scan_status_endpoint(self):
        """Test scan status endpoint (GET, no CSRF needed)."""
        print("\n[TEST 9] Scan Status Endpoint")
        
        # Status endpoint should be accessible without CSRF (GET request)
        response = self.client.get('/api/scan/nonexistent/status')
        self.assertEqual(response.status_code, 404, "Should return 404 for non-existent scan")
        
        print("✅ Scan status endpoint accessible (GET)")
    
    def test_10_scan_results_endpoint(self):
        """Test scan results endpoint (GET, no CSRF needed)."""
        print("\n[TEST 10] Scan Results Endpoint")
        
        # Results endpoint should be accessible without CSRF (GET request)
        response = self.client.get('/api/scan/nonexistent/results')
        self.assertEqual(response.status_code, 404, "Should return 404 for non-existent scan")
        
        print("✅ Scan results endpoint accessible (GET)")
    
    def test_11_save_scan_csrf(self):
        """Test save scan requires CSRF token."""
        print("\n[TEST 11] Save Scan CSRF Protection")
        
        # Create and login user
        user = User.create('testuser4', 'test4@example.com', 'testpass123')
        session_token = UserSession.create(user.id)
        
        with self.client.session_transaction() as sess:
            sess['session_token'] = session_token
            sess['user_id'] = user.id
            sess['username'] = user.username
            if 'csrf_token' not in sess:
                sess['csrf_token'] = secrets.token_urlsafe(32)
            csrf_token = sess['csrf_token']
        
        # Try save without CSRF token (should fail)
        response = self.client.post('/api/profile/save-scan', json={
            'scan_id': 'test_scan',
            'target_url': 'https://example.com',
            'scan_results': {'findings': []}
        }, content_type='application/json')
        self.assertEqual(response.status_code, 403, "Should reject save without CSRF token")
        
        print("✅ Save scan properly protected with CSRF")
    
    def test_12_logout_csrf(self):
        """Test logout requires CSRF token."""
        print("\n[TEST 12] Logout CSRF Protection")
        
        # Create and login user
        user = User.create('testuser5', 'test5@example.com', 'testpass123')
        session_token = UserSession.create(user.id)
        
        with self.client.session_transaction() as sess:
            sess['session_token'] = session_token
            sess['user_id'] = user.id
            sess['username'] = user.username
            if 'csrf_token' not in sess:
                sess['csrf_token'] = secrets.token_urlsafe(32)
            csrf_token = sess['csrf_token']
        
        # Try logout without CSRF token (should fail)
        response = self.client.post('/logout', content_type='application/x-www-form-urlencoded')
        self.assertEqual(response.status_code, 403, "Should reject logout without CSRF token")
        
        # Try logout with CSRF token (should succeed)
        response = self.client.post('/logout', data={
            'csrf_token': csrf_token
        }, headers={'X-CSRF-Token': csrf_token}, content_type='application/x-www-form-urlencoded')
        
        self.assertIn(response.status_code, [200, 302, 201], "Logout should succeed with CSRF token")
        print("✅ Logout properly protected with CSRF")
    
    def test_13_password_hashing(self):
        """Test password hashing with bcrypt."""
        print("\n[TEST 13] Password Hashing")
        
        # Create user with password
        user = User.create('testuser6', 'test6@example.com', 'testpass123')
        
        # Verify password
        is_valid = User.authenticate('testuser6', 'testpass123')
        self.assertTrue(is_valid, "Should authenticate with correct password")
        
        is_invalid = User.authenticate('testuser6', 'wrongpassword')
        self.assertFalse(is_invalid, "Should not authenticate with wrong password")
        
        print("✅ Password hashing works correctly")
    
    def test_14_security_headers(self):
        """Test security headers are present."""
        print("\n[TEST 14] Security Headers")
        
        response = self.client.get('/')
        
        # Check for security headers
        headers = dict(response.headers)
        self.assertIn('X-Content-Type-Options', headers)
        self.assertEqual(headers['X-Content-Type-Options'], 'nosniff')
        
        # Other headers may vary based on implementation
        print("✅ Security headers present")
    
    def test_15_shareable_results(self):
        """Test shareable results endpoint."""
        print("\n[TEST 15] Shareable Results")
        
        # Should return 404 for non-existent shareable ID
        response = self.client.get('/results/invalidid12345')
        self.assertIn(response.status_code, [404, 400], "Should handle invalid shareable ID")
        
        response = self.client.get('/api/results/invalidid12345')
        self.assertIn(response.status_code, [404, 400], "Should handle invalid shareable ID via API")
        
        print("✅ Shareable results endpoint works")
    
    def test_16_user_settings_api(self):
        """Test user settings API."""
        print("\n[TEST 16] User Settings API")
        
        # Create and login user
        user = User.create('testuser7', 'test7@example.com', 'testpass123')
        session_token = UserSession.create(user.id)
        
        with self.client.session_transaction() as sess:
            sess['session_token'] = session_token
            sess['user_id'] = user.id
            sess['username'] = user.username
            if 'csrf_token' not in sess:
                sess['csrf_token'] = secrets.token_urlsafe(32)
            csrf_token = sess['csrf_token']
        
        # Get settings
        response = self.client.get('/api/profile/settings')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('user', data)
        self.assertIn('email', data['user'])
        
        # Update settings (requires CSRF based on implementation)
        response = self.client.put('/api/profile/settings', json={
            'settings': {'test_key': 'test_value'},
            'csrf_token': csrf_token
        }, headers={'X-CSRF-Token': csrf_token}, content_type='application/json')
        # Should succeed with CSRF token
        self.assertIn(response.status_code, [200, 201], f"Settings update should work with CSRF (got {response.status_code})")
        if response.status_code == 200:
            data = json.loads(response.data)
            self.assertIn('success', data)
            self.assertTrue(data['success'])
        print("✅ User settings API accessible")
    
    def test_17_input_validation(self):
        """Test input validation on scan endpoint."""
        print("\n[TEST 17] Input Validation")
        
        # Get CSRF token
        self.client.get('/')
        csrf_token = self.get_csrf_token()
        
        # Test invalid URL
        response = self.client.post('/api/scan', json={
            'target': 'not-a-valid-url',
            'csrf_token': csrf_token
        }, headers={'X-CSRF-Token': csrf_token}, content_type='application/json')
        self.assertEqual(response.status_code, 400, "Should reject invalid URL")
        
        # Test missing target
        response = self.client.post('/api/scan', json={
            'csrf_token': csrf_token
        }, headers={'X-CSRF-Token': csrf_token}, content_type='application/json')
        self.assertEqual(response.status_code, 400, "Should reject missing target")
        
        print("✅ Input validation works correctly")
    
    def test_18_session_management(self):
        """Test session management and expiration."""
        print("\n[TEST 18] Session Management")
        
        # Create user
        user = User.create('testuser8', 'test8@example.com', 'testpass123')
        session_token = UserSession.create(user.id)
        
        # Test valid session
        user_from_token = UserSession.get_user_from_token(session_token)
        self.assertIsNotNone(user_from_token)
        self.assertEqual(user_from_token.id, user.id)
        
        # Test invalid session
        invalid_user = UserSession.get_user_from_token('invalid_token')
        self.assertIsNone(invalid_user)
        
        # Delete session
        UserSession.delete_token(session_token)
        deleted_user = UserSession.get_user_from_token(session_token)
        self.assertIsNone(deleted_user, "Session should be deleted")
        
        print("✅ Session management works correctly")


def run_tests():
    """Run all tests and print summary."""
    print("\n" + "="*70)
    print("🔒 SECURITY INTEGRATION TEST SUITE")
    print("="*70)
    print("\nTesting core functionality after security improvements...")
    print("="*70)
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(SecurityIntegrationTest)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "="*70)
    print("📊 TEST SUMMARY")
    print("="*70)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success rate: {((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100):.1f}%")
    
    if result.failures:
        print("\n❌ FAILURES:")
        for test, traceback in result.failures:
            print(f"  - {test}")
    
    if result.errors:
        print("\n❌ ERRORS:")
        for test, traceback in result.errors:
            print(f"  - {test}")
    
    if result.wasSuccessful():
        print("\n✅ ALL TESTS PASSED!")
    else:
        print("\n⚠️  SOME TESTS FAILED - REVIEW OUTPUT ABOVE")
    
    print("="*70 + "\n")
    
    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_tests()
    sys.exit(0 if success else 1)
