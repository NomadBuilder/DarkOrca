"""Configuration constants and utilities."""

import os
from typing import Optional


class Config:
    """Application configuration constants."""
    
    # HTTP Request Configuration
    DEFAULT_REQUEST_TIMEOUT = int(os.getenv('REQUEST_TIMEOUT', '30'))  # seconds
    DEFAULT_CONNECT_TIMEOUT = int(os.getenv('CONNECT_TIMEOUT', '10'))  # seconds
    DEFAULT_READ_TIMEOUT = int(os.getenv('READ_TIMEOUT', '30'))  # seconds
    
    # Scan Configuration
    MAX_CONCURRENT_SCANS = int(os.getenv('MAX_CONCURRENT_SCANS', '5'))
    MAX_SCAN_DURATION = int(os.getenv('MAX_SCAN_DURATION', '7200'))  # 2 hours in seconds
    SCAN_RESULT_EXPIRY_DAYS = int(os.getenv('RESULTS_EXPIRY_DAYS', '30'))
    
    # Rate Limiting
    RATE_LIMIT_SCANS_PER_MINUTE = int(os.getenv('RATE_LIMIT_SCANS_PER_MINUTE', '5'))
    RATE_LIMIT_REQUESTS_PER_HOUR = int(os.getenv('RATE_LIMIT_REQUESTS_PER_HOUR', '200'))
    RATE_LIMIT_REQUESTS_PER_MINUTE = int(os.getenv('RATE_LIMIT_REQUESTS_PER_MINUTE', '50'))
    
    # Input Validation
    MAX_URL_LENGTH = 2048
    MAX_EMAIL_LENGTH = 254
    MAX_SCAN_ID_LENGTH = 100
    
    # File Upload
    MAX_FILE_SIZE = int(os.getenv('MAX_FILE_SIZE', str(10 * 1024 * 1024)))  # 10MB
    
    @staticmethod
    def get_request_timeout() -> tuple[int, int]:
        """
        Get request timeout as (connect_timeout, read_timeout).
        
        Returns:
            Tuple of (connect_timeout, read_timeout) in seconds
        """
        return (Config.DEFAULT_CONNECT_TIMEOUT, Config.DEFAULT_READ_TIMEOUT)
    
    @staticmethod
    def validate_config() -> tuple[bool, list[str]]:
        """
        Validate configuration values.
        
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []
        
        # Validate timeouts
        if Config.DEFAULT_REQUEST_TIMEOUT < 1 or Config.DEFAULT_REQUEST_TIMEOUT > 300:
            errors.append(f"REQUEST_TIMEOUT must be between 1 and 300 seconds, got {Config.DEFAULT_REQUEST_TIMEOUT}")
        
        if Config.DEFAULT_CONNECT_TIMEOUT < 1 or Config.DEFAULT_CONNECT_TIMEOUT > 60:
            errors.append(f"CONNECT_TIMEOUT must be between 1 and 60 seconds, got {Config.DEFAULT_CONNECT_TIMEOUT}")
        
        if Config.DEFAULT_READ_TIMEOUT < 1 or Config.DEFAULT_READ_TIMEOUT > 600:
            errors.append(f"READ_TIMEOUT must be between 1 and 600 seconds, got {Config.DEFAULT_READ_TIMEOUT}")
        
        # Validate scan configuration
        if Config.MAX_CONCURRENT_SCANS < 1 or Config.MAX_CONCURRENT_SCANS > 100:
            errors.append(f"MAX_CONCURRENT_SCANS must be between 1 and 100, got {Config.MAX_CONCURRENT_SCANS}")
        
        if Config.MAX_SCAN_DURATION < 60 or Config.MAX_SCAN_DURATION > 86400:
            errors.append(f"MAX_SCAN_DURATION must be between 60 and 86400 seconds, got {Config.MAX_SCAN_DURATION}")
        
        # Validate rate limits
        if Config.RATE_LIMIT_SCANS_PER_MINUTE < 1:
            errors.append(f"RATE_LIMIT_SCANS_PER_MINUTE must be at least 1, got {Config.RATE_LIMIT_SCANS_PER_MINUTE}")
        
        return len(errors) == 0, errors
