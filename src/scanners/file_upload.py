"""File Upload vulnerability scanner."""

import re
import requests
import os
import hashlib
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse

from .base import BaseScanner
from ..models.scan import ScanTarget
from ..models.finding import Finding, FindingSeverity, FindingCategory
from ..models.scan_mode import ScanMode

import logging
logger = logging.getLogger(__name__)


class FileUploadScanner(BaseScanner):
    """Scanner for File Upload vulnerabilities."""
    
    def __init__(self, enabled: bool = True, scan_mode: ScanMode = ScanMode.DEFENSIVE):
        """
        Initialize File Upload scanner.
        
        Args:
            enabled: Whether scanner is enabled
            scan_mode: Scan mode (defensive or offensive)
        """
        super().__init__(
            name="file_upload",
            command=None,  # No external command needed
            enabled=enabled,
            scan_mode=scan_mode
        )
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.session.timeout = 15
        
        # Generate unique test marker
        self.test_marker = hashlib.md5(f"file_upload_test_{os.urandom(16).hex()}".encode()).hexdigest()[:8]
    
    def is_available(self) -> bool:
        """File upload scanner is always available."""
        return True
    
    def scan(self, target: ScanTarget) -> List[Finding]:
        """Run file upload vulnerability tests."""
        if self.scan_mode == ScanMode.DEFENSIVE:
            return []  # Only run in offensive mode
        
        findings = []
        
        # Discover file upload endpoints
        upload_endpoints = self._discover_upload_endpoints(target.url)
        
        # Test each endpoint
        for endpoint in upload_endpoints:
            findings.extend(self._test_upload_endpoint(endpoint, target.url))
        
        return findings
    
    def _discover_upload_endpoints(self, url: str) -> List[str]:
        """Discover file upload endpoints."""
        endpoints = []
        
        # Common upload endpoints
        common_paths = [
            '/upload',
            '/upload.php',
            '/upload.html',
            '/file-upload',
            '/upload-file',
            '/uploader',
            '/uploader.php',
            '/admin/upload',
            '/wp-admin/upload.php',
            '/wp-admin/media-new.php',
            '/wp-content/uploads/',
            '/api/upload',
            '/upload/image',
            '/upload/file',
            '/upload/avatar',
            '/profile/upload',
            '/settings/upload',
        ]
        
        # Check for forms with file inputs
        try:
            response = self.session.get(url, timeout=10)
            if response.status_code == 200:
                # Look for file input fields
                file_inputs = re.findall(r'<input[^>]*type=["\']file["\'][^>]*>', response.text, re.IGNORECASE)
                if file_inputs:
                    # Try to find the form action
                    form_actions = re.findall(r'<form[^>]*action=["\']([^"\']+)["\']', response.text, re.IGNORECASE)
                    for action in form_actions:
                        if action.startswith('http'):
                            endpoints.append(action)
                        else:
                            endpoints.append(urljoin(url, action))
                
                # Also check for common upload endpoints
                for path in common_paths:
                    test_url = urljoin(url, path)
                    try:
                        test_response = self.session.get(test_url, timeout=5)
                        if test_response.status_code in [200, 405]:  # 405 = Method Not Allowed but endpoint exists
                            endpoints.append(test_url)
                    except:
                        continue
        except Exception as e:
            logger.debug(f"Error discovering upload endpoints: {e}")
        
        # Remove duplicates
        return list(set(endpoints))
    
    def _test_upload_endpoint(self, endpoint: str, base_url: str) -> List[Finding]:
        """Test a file upload endpoint for vulnerabilities."""
        findings = []
        
        # Test different file upload bypass techniques
        test_cases = [
            # PHP web shell
            {
                'filename': 'test.php',
                'content': f'<?php echo "{self.test_marker}"; ?>',
                'content_type': 'application/x-php',
                'description': 'PHP web shell upload',
            },
            {
                'filename': 'test.php.jpg',
                'content': f'<?php echo "{self.test_marker}"; ?>',
                'content_type': 'image/jpeg',
                'description': 'Double extension bypass (PHP)',
            },
            {
                'filename': 'test.php%00.jpg',
                'content': f'<?php echo "{self.test_marker}"; ?>',
                'content_type': 'image/jpeg',
                'description': 'Null byte injection bypass',
            },
            {
                'filename': 'test.phtml',
                'content': f'<?php echo "{self.test_marker}"; ?>',
                'content_type': 'text/html',
                'description': 'Alternative PHP extension (phtml)',
            },
            {
                'filename': 'test.php5',
                'content': f'<?php echo "{self.test_marker}"; ?>',
                'content_type': 'application/x-php',
                'description': 'PHP5 extension',
            },
            
            # JSP web shell
            {
                'filename': 'test.jsp',
                'content': f'<% out.println("{self.test_marker}"); %>',
                'content_type': 'application/x-jsp',
                'description': 'JSP web shell upload',
            },
            
            # ASP web shell
            {
                'filename': 'test.asp',
                'content': f'<% Response.Write("{self.test_marker}") %>',
                'content_type': 'application/x-asp',
                'description': 'ASP web shell upload',
            },
            
            # Python web shell
            {
                'filename': 'test.py',
                'content': f'print("{self.test_marker}")',
                'content_type': 'text/x-python',
                'description': 'Python script upload',
            },
            
            # Path traversal in filename
            {
                'filename': '../../../test.php',
                'content': f'<?php echo "{self.test_marker}"; ?>',
                'content_type': 'application/x-php',
                'description': 'Path traversal in filename',
            },
            {
                'filename': '..\\..\\..\\test.php',
                'content': f'<?php echo "{self.test_marker}"; ?>',
                'content_type': 'application/x-php',
                'description': 'Windows path traversal',
            },
            
            # MIME type bypass
            {
                'filename': 'test.php',
                'content': f'<?php echo "{self.test_marker}"; ?>',
                'content_type': 'image/jpeg',
                'description': 'MIME type spoofing',
            },
            {
                'filename': 'test.php',
                'content': f'<?php echo "{self.test_marker}"; ?>',
                'content_type': 'image/png',
                'description': 'MIME type spoofing (PNG)',
            },
        ]
        
        for test_case in test_cases:
            try:
                # Try to upload the file
                files = {
                    'file': (test_case['filename'], test_case['content'], test_case['content_type']),
                    'upload': (test_case['filename'], test_case['content'], test_case['content_type']),
                    'image': (test_case['filename'], test_case['content'], test_case['content_type']),
                }
                
                # Try different parameter names
                for file_param in ['file', 'upload', 'image', 'avatar', 'photo', 'attachment']:
                    try:
                        files_dict = {file_param: (test_case['filename'], test_case['content'], test_case['content_type'])}
                        response = self.session.post(endpoint, files=files_dict, timeout=15)
                        
                        # Check if upload was successful
                        if response.status_code in [200, 201, 302]:
                            # Try to access the uploaded file
                            uploaded_file_url = self._find_uploaded_file_url(response, test_case['filename'], base_url)
                            
                            if uploaded_file_url:
                                # Verify the file was uploaded and is executable
                                verify_response = self.session.get(uploaded_file_url, timeout=10)
                                if verify_response.status_code == 200:
                                    if self.test_marker in verify_response.text:
                                        # Web shell successfully uploaded and executed!
                                        findings.append(Finding(
                                            title=f"File Upload Vulnerability - Web Shell Upload Successful",
                                            description=f"Successfully uploaded and executed a web shell via file upload endpoint '{endpoint}'. "
                                                      f"The uploaded file '{test_case['filename']}' was accessible and executed server-side code. "
                                                      f"Bypass technique: {test_case['description']}. "
                                                      f"This indicates a critical file upload vulnerability allowing remote code execution.",
                                            severity=FindingSeverity.CRITICAL,
                                            category=FindingCategory.EXPLOITATION,
                                            source_scanner="file_upload",
                                            source_id=f"file_upload_{endpoint.replace('/', '_')}",
                                            url=uploaded_file_url,
                                            remediation=f"Implement strict file upload validation: "
                                                       f"1. Whitelist allowed file extensions "
                                                       f"2. Validate file content (not just extension/MIME type) "
                                                       f"3. Store uploaded files outside web root or with restricted permissions "
                                                       f"4. Scan uploaded files for malicious content "
                                                       f"5. Use secure file names (no user-controlled paths) "
                                                       f"6. Implement file type verification using magic bytes",
                                            metadata={
                                                "endpoint": endpoint,
                                                "uploaded_file": test_case['filename'],
                                                "uploaded_url": uploaded_file_url,
                                                "bypass_technique": test_case['description'],
                                                "content_type": test_case['content_type'],
                                                "exploitation_details": {
                                                    "web_shell_uploaded": True,
                                                    "file_executable": True,
                                                    "test_marker_found": True,
                                                },
                                            },
                                            references=[
                                                "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
                                                "https://portswigger.net/web-security/file-upload",
                                            ],
                                        ))
                                        break  # Found vulnerability, no need to test more
                    except:
                        continue
                
            except Exception as e:
                logger.debug(f"Error testing upload case {test_case['description']}: {e}")
                continue
        
        return findings
    
    def _find_uploaded_file_url(self, response: requests.Response, filename: str, base_url: str) -> Optional[str]:
        """Try to find the URL of the uploaded file from the response."""
        # Check response text for file URLs
        response_text = response.text
        
        # Common patterns for uploaded file URLs
        patterns = [
            rf'<img[^>]*src=["\']([^"\']*{re.escape(filename)})["\']',
            rf'<a[^>]*href=["\']([^"\']*{re.escape(filename)})["\']',
            rf'["\']([^"\']*uploads[^"\']*{re.escape(filename)})["\']',
            rf'["\']([^"\']*files[^"\']*{re.escape(filename)})["\']',
            rf'["\']([^"\']*{re.escape(filename)})["\']',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            for match in matches:
                if match.startswith('http'):
                    return match
                else:
                    return urljoin(base_url, match)
        
        # Also check Location header (redirects)
        if 'Location' in response.headers:
            location = response.headers['Location']
            if filename in location:
                if location.startswith('http'):
                    return location
                else:
                    return urljoin(base_url, location)
        
        # Try common upload directories
        common_dirs = [
            '/uploads/',
            '/upload/',
            '/files/',
            '/file/',
            '/media/',
            '/images/',
            '/wp-content/uploads/',
        ]
        
        for dir_path in common_dirs:
            test_url = urljoin(base_url, dir_path + filename)
            try:
                test_response = self.session.get(test_url, timeout=5)
                if test_response.status_code == 200 and self.test_marker in test_response.text:
                    return test_url
            except:
                continue
        
        return None

