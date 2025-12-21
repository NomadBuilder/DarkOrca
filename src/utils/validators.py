"""Input validation utilities for DarkOrca."""

import re
import logging
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Constants
MAX_URL_LENGTH = 2048  # Standard maximum URL length
MAX_EMAIL_LENGTH = 254  # RFC 5321 maximum email length
MAX_SCAN_ID_LENGTH = 100


def validate_url(url: str, require_scheme: bool = False) -> tuple[bool, Optional[str]]:
    """
    Validate URL format and length.
    
    Args:
        url: URL string to validate
        require_scheme: Whether URL must include http:// or https://
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not url:
        return False, "URL cannot be empty"
    
    if not isinstance(url, str):
        return False, "URL must be a string"
    
    # Trim whitespace
    url = url.strip()
    
    if not url:
        return False, "URL cannot be empty or whitespace only"
    
    # Length check
    if len(url) > MAX_URL_LENGTH:
        return False, f"URL exceeds maximum length of {MAX_URL_LENGTH} characters"
    
    # Basic format check - must contain a dot (domain) or start with http
    if not ("." in url or url.startswith("http://") or url.startswith("https://")):
        return False, "URL must be a valid domain or URL"
    
    # Try to parse as URL
    try:
        parsed = urlparse(url)
        
        # If no scheme, add https:// for validation
        if not parsed.scheme:
            if require_scheme:
                return False, "URL must include http:// or https://"
            # Add scheme for validation
            test_url = f"https://{url}"
            parsed = urlparse(test_url)
        
        # Validate scheme
        if parsed.scheme and parsed.scheme not in ["http", "https"]:
            return False, f"Unsupported URL scheme: {parsed.scheme}. Only http and https are supported."
        
        # Validate netloc (domain)
        if not parsed.netloc and not parsed.path:
            return False, "Invalid URL format: missing domain"
        
        # Basic domain validation
        domain = parsed.netloc or parsed.path.split("/")[0]
        if domain:
            # Check for invalid characters
            if any(char in domain for char in [' ', '\n', '\r', '\t']):
                return False, "URL contains invalid whitespace characters"
            
            # Remove port for domain validation
            domain_without_port = domain.split(':')[0] if ':' in domain else domain
            
            # Domain should have at least one dot (unless localhost or IP)
            if '.' not in domain_without_port and domain_without_port not in ['localhost', '127.0.0.1', '::1']:
                # Check if it's an IP address (IPv4 or IPv6)
                ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
                ipv6_pattern = r'^[0-9a-fA-F:]+$'
                if not (re.match(ipv4_pattern, domain_without_port) or re.match(ipv6_pattern, domain_without_port)):
                    return False, "URL must include a valid domain name or IP address"
        
        return True, None
        
    except Exception as e:
        logger.warning(f"URL validation error: {e}")
        return False, f"Invalid URL format: {str(e)}"


def validate_email(email: str) -> tuple[bool, Optional[str]]:
    """
    Validate email address format and length.
    
    Args:
        email: Email string to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not email:
        return False, "Email cannot be empty"
    
    if not isinstance(email, str):
        return False, "Email must be a string"
    
    # Trim whitespace
    email = email.strip()
    
    if not email:
        return False, "Email cannot be empty or whitespace only"
    
    # Length check
    if len(email) > MAX_EMAIL_LENGTH:
        return False, f"Email exceeds maximum length of {MAX_EMAIL_LENGTH} characters"
    
    # Basic email format validation (RFC 5322 simplified)
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    
    if not re.match(email_pattern, email):
        return False, "Invalid email format"
    
    # Additional checks
    if email.count('@') != 1:
        return False, "Email must contain exactly one @ symbol"
    
    local_part, domain = email.split('@')
    
    if not local_part or len(local_part) > 64:  # RFC 5321 local part max length
        return False, "Invalid email local part"
    
    if not domain or len(domain) > 253:  # RFC 5321 domain max length
        return False, "Invalid email domain"
    
    # Check for consecutive dots
    if '..' in email:
        return False, "Email cannot contain consecutive dots"
    
    # Check for leading/trailing dots
    if local_part.startswith('.') or local_part.endswith('.'):
        return False, "Email local part cannot start or end with a dot"
    
    if domain.startswith('.') or domain.endswith('.'):
        return False, "Email domain cannot start or end with a dot"
    
    return True, None


def sanitize_input(input_str: str, max_length: Optional[int] = None, allow_newlines: bool = False) -> str:
    """
    Sanitize user input to prevent XSS and other injection attacks.
    
    Args:
        input_str: Input string to sanitize
        max_length: Maximum length (None for no limit)
        allow_newlines: Whether to allow newline characters
        
    Returns:
        Sanitized string
    """
    if not input_str or not isinstance(input_str, str):
        return ""
    
    # Trim whitespace
    sanitized = input_str.strip()
    
    # Remove null bytes
    sanitized = sanitized.replace('\x00', '')
    
    # Remove newlines if not allowed
    if not allow_newlines:
        sanitized = sanitized.replace('\n', ' ').replace('\r', ' ')
    
    # Remove tabs
    sanitized = sanitized.replace('\t', ' ')
    
    # Collapse multiple spaces
    sanitized = re.sub(r' +', ' ', sanitized)
    
    # Apply length limit
    if max_length and len(sanitized) > max_length:
        sanitized = sanitized[:max_length]
    
    return sanitized


def validate_scan_id(scan_id: str) -> tuple[bool, Optional[str]]:
    """
    Validate scan ID format.
    
    Args:
        scan_id: Scan ID string to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not scan_id:
        return False, "Scan ID cannot be empty"
    
    if not isinstance(scan_id, str):
        return False, "Scan ID must be a string"
    
    if len(scan_id) > MAX_SCAN_ID_LENGTH:
        return False, f"Scan ID exceeds maximum length of {MAX_SCAN_ID_LENGTH} characters"
    
    # Scan IDs should be alphanumeric with underscores and hyphens
    if not re.match(r'^[a-zA-Z0-9_-]+$', scan_id):
        return False, "Scan ID contains invalid characters (only letters, numbers, underscores, and hyphens allowed)"
    
    return True, None


def validate_path_traversal_safe(path: str, base_directory: str) -> tuple[bool, Optional[str]]:
    """
    Validate that a file path doesn't contain path traversal sequences.
    
    Args:
        path: File path to validate
        base_directory: Base directory that path should be within
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not path:
        return False, "Path cannot be empty"
    
    # Check for path traversal sequences
    if '..' in path or path.startswith('/') or '\\' in path:
        return False, "Path contains invalid traversal characters"
    
    # Resolve path relative to base directory
    import os
    try:
        resolved_path = os.path.abspath(os.path.join(base_directory, path))
        base_path = os.path.abspath(base_directory)
        
        # Ensure resolved path is within base directory
        if not resolved_path.startswith(base_path):
            return False, "Path is outside allowed directory"
        
        return True, None
    except Exception as e:
        logger.warning(f"Path validation error: {e}")
        return False, f"Invalid path: {str(e)}"
