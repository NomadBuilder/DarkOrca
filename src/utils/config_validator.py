"""Configuration validation utilities."""

import os
import logging
from typing import Dict, List, Tuple, Optional

# Import Config class if available (optional dependency)
try:
    from .config import Config
    CONFIG_AVAILABLE = True
except ImportError:
    CONFIG_AVAILABLE = False

logger = logging.getLogger(__name__)


class ConfigValidator:
    """Validate application configuration on startup."""
    
    @staticmethod
    def validate_config() -> Tuple[bool, List[str]]:
        """
        Validate all configuration values.
        
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []
        
        # Validate MAX_CONCURRENT_SCANS
        max_concurrent = os.getenv('MAX_CONCURRENT_SCANS', '5')
        try:
            max_concurrent_int = int(max_concurrent)
            if max_concurrent_int < 1 or max_concurrent_int > 100:
                errors.append(f"MAX_CONCURRENT_SCANS must be between 1 and 100, got {max_concurrent_int}")
        except ValueError:
            errors.append(f"MAX_CONCURRENT_SCANS must be an integer, got '{max_concurrent}'")
        
        # Validate email configuration (if provided)
        resend_key = os.getenv('RESEND_API_KEY', '')
        smtp_server = os.getenv('SMTP_SERVER', '')
        smtp_username = os.getenv('SMTP_USERNAME', '')
        smtp_password = os.getenv('SMTP_PASSWORD', '')
        
        if resend_key:
            # Resend API key should be non-empty if provided
            if len(resend_key.strip()) == 0:
                errors.append("RESEND_API_KEY is set but empty")
        elif smtp_server:
            # If using SMTP, server and credentials should be provided
            if not smtp_username or not smtp_password:
                errors.append("SMTP_SERVER is set but SMTP_USERNAME and/or SMTP_PASSWORD are missing")
            try:
                smtp_port = int(os.getenv('SMTP_PORT', '587'))
                if smtp_port < 1 or smtp_port > 65535:
                    errors.append(f"SMTP_PORT must be between 1 and 65535, got {smtp_port}")
            except ValueError:
                errors.append(f"SMTP_PORT must be an integer, got '{os.getenv('SMTP_PORT', '587')}'")
        
        # Validate BASE_URL if provided
        base_url = os.getenv('BASE_URL', '')
        if base_url:
            if not (base_url.startswith('http://') or base_url.startswith('https://')):
                errors.append(f"BASE_URL must start with http:// or https://, got '{base_url}'")
        
        # Validate FROM_EMAIL if provided
        from_email = os.getenv('FROM_EMAIL', '')
        if from_email:
            # Basic email format check
            if '@' not in from_email or '.' not in from_email.split('@')[1] if '@' in from_email else False:
                errors.append(f"FROM_EMAIL appears to be invalid: '{from_email}'")
        
        # Validate RESULTS_EXPIRY_DAYS if set as env var (optional)
        expiry_days = os.getenv('RESULTS_EXPIRY_DAYS', '')
        if expiry_days:
            try:
                expiry_int = int(expiry_days)
                if expiry_int < 1 or expiry_int > 365:
                    errors.append(f"RESULTS_EXPIRY_DAYS must be between 1 and 365, got {expiry_int}")
            except ValueError:
                errors.append(f"RESULTS_EXPIRY_DAYS must be an integer, got '{expiry_days}'")
        
        # Validate PORT if provided
        port = os.getenv('PORT', '')
        if port:
            try:
                port_int = int(port)
                if port_int < 1 or port_int > 65535:
                    errors.append(f"PORT must be between 1 and 65535, got {port_int}")
            except ValueError:
                errors.append(f"PORT must be an integer, got '{port}'")
        
        return len(errors) == 0, errors
    
    @staticmethod
    def log_config_summary():
        """Log a summary of current configuration (without sensitive values)."""
        # Import Config if available for consistent values
        if CONFIG_AVAILABLE:
            from .config import Config
            max_scans = Config.MAX_CONCURRENT_SCANS
            expiry_days = Config.SCAN_RESULT_EXPIRY_DAYS
        else:
            max_scans = os.getenv('MAX_CONCURRENT_SCANS', '5')
            expiry_days = os.getenv('RESULTS_EXPIRY_DAYS', '30')
        
        logger.info("=" * 60)
        logger.info("Configuration Summary:")
        logger.info("=" * 60)
        logger.info(f"  MAX_CONCURRENT_SCANS: {max_scans}")
        logger.info(f"  BASE_URL: {os.getenv('BASE_URL', 'http://localhost:5001')}")
        logger.info(f"  FROM_EMAIL: {os.getenv('FROM_EMAIL', 'onboarding@resend.dev')}")
        logger.info(f"  FROM_NAME: {os.getenv('FROM_NAME', 'DarkOrca')}")
        logger.info(f"  RESULTS_EXPIRY_DAYS: {expiry_days}")
        
        # Email configuration
        if os.getenv('RESEND_API_KEY'):
            logger.info(f"  Email: Resend (API key present)")
        elif os.getenv('SMTP_SERVER'):
            logger.info(f"  Email: SMTP ({os.getenv('SMTP_SERVER', 'unknown')})")
        else:
            logger.info(f"  Email: Disabled")
        
        # AI configuration
        if os.getenv('OPENAI_API_KEY') or os.getenv('AI_API_KEY'):
            logger.info(f"  AI Analysis: Enabled")
        else:
            logger.info(f"  AI Analysis: Disabled")
        
        logger.info("=" * 60)
