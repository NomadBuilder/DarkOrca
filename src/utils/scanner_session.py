"""Helper for creating scanner sessions with OPSEC features."""

import os
import requests
from typing import Optional, Dict

# Check if OPSEC is enabled
_OPSEC_ENABLED = os.getenv('OPSEC_ENABLED', 'false').lower() == 'true'
_OPSEC_ROTATE_UA = os.getenv('OPSEC_ROTATE_USER_AGENT', 'true').lower() == 'true'
_OPSEC_USE_PROXY = os.getenv('OPSEC_USE_PROXY', 'true').lower() == 'true'

def create_scanner_session(use_opsec: Optional[bool] = None) -> requests.Session:
    """
    Create a requests session for scanners with optional OPSEC features.
    
    This is a convenience function that scanners should use instead of
    creating sessions directly. It automatically applies OPSEC if enabled.
    
    Args:
        use_opsec: If True, enable OPSEC. If None, uses OPSEC_ENABLED env var.
        
    Returns:
        Configured requests.Session
    """
    session = requests.Session()
    session.verify = False  # Allow self-signed certs (common in security testing)
    
    # Apply OPSEC if enabled
    use_stealth = use_opsec if use_opsec is not None else _OPSEC_ENABLED
    
    if use_stealth:
        try:
            from .opsec import create_stealth_session, UserAgentRotator, HeaderNormalizer, ProxyManager
            
            # Create stealth session (handles user agent, headers, proxy)
            stealth_session = create_stealth_session(
                rotate_user_agent=_OPSEC_ROTATE_UA,
                use_proxy=_OPSEC_USE_PROXY,
                add_delays=False
            )
            
            # Copy configuration to our session
            session.headers.update(stealth_session.headers)
            if stealth_session.proxies:
                session.proxies.update(stealth_session.proxies)
            
        except ImportError:
            # OPSEC module not available, use minimal stealth
            from .opsec import UserAgentRotator
            session.headers['User-Agent'] = UserAgentRotator.get_default()
    else:
        # Still use realistic user agent even without full OPSEC
        # (but don't use tool signatures)
        session.headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    
    # Set timeout
    session.timeout = 10
    
    return session
