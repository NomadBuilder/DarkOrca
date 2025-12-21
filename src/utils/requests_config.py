"""HTTP requests configuration with consistent timeouts and OPSEC features."""

import os
import requests
from typing import Optional, Dict, Any
from .config import Config

# OPSEC features (can be enabled via environment variables)
_OPSEC_ENABLED = os.getenv('OPSEC_ENABLED', 'false').lower() == 'true'
_OPSEC_ROTATE_UA = os.getenv('OPSEC_ROTATE_USER_AGENT', 'true').lower() == 'true'
_OPSEC_USE_PROXY = os.getenv('OPSEC_USE_PROXY', 'true').lower() == 'true'

# Import OPSEC utilities if needed
if _OPSEC_ENABLED:
    try:
        from .opsec import (
            create_stealth_session,
            UserAgentRotator,
            HeaderNormalizer,
            ProxyManager,
            RequestTiming
        )
    except ImportError:
        _OPSEC_ENABLED = False


def make_request(
    method: str,
    url: str,
    timeout: Optional[tuple[int, int]] = None,
    use_opsec: Optional[bool] = None,
    **kwargs
) -> requests.Response:
    """
    Make HTTP request with consistent timeout configuration and optional OPSEC features.
    
    Args:
        method: HTTP method (GET, POST, etc.)
        url: Request URL
        timeout: Optional (connect_timeout, read_timeout) tuple. If None, uses Config defaults.
        use_opsec: If True, use OPSEC features (stealth mode). If None, uses OPSEC_ENABLED env var.
        **kwargs: Additional arguments to pass to requests.request()
        
    Returns:
        Response object
    """
    if timeout is None:
        timeout = Config.get_request_timeout()
    
    # Ensure timeout is set
    if 'timeout' not in kwargs:
        kwargs['timeout'] = timeout
    
    # Apply OPSEC if enabled
    use_stealth = use_opsec if use_opsec is not None else _OPSEC_ENABLED
    
    if use_stealth and _OPSEC_ENABLED:
        # Create stealth session
        session = create_stealth_session(
            rotate_user_agent=_OPSEC_ROTATE_UA,
            use_proxy=_OPSEC_USE_PROXY,
            add_delays=False,  # Delays should be added manually between requests
            custom_headers=kwargs.get('headers')
        )
        
        # Remove headers from kwargs (already set in session)
        if 'headers' in kwargs:
            # Merge any additional headers
            session.headers.update(kwargs.pop('headers'))
        
        # Add proxy if not already in kwargs
        if 'proxies' not in kwargs and _OPSEC_USE_PROXY:
            proxies = ProxyManager.get_proxy_config()
            if proxies:
                kwargs['proxies'] = proxies
        
        # Use session for request
        return session.request(method, url, **kwargs)
    else:
        # Standard request (but still remove tool signatures from headers if present)
        if _OPSEC_ENABLED:
            try:
                headers = kwargs.get('headers', {})
                if headers:
                    # Ensure no tool signatures
                    clean_headers = HeaderNormalizer.get_clean_headers(headers)
                    kwargs['headers'] = clean_headers
                else:
                    # Add at least a clean user agent
                    kwargs['headers'] = {'User-Agent': UserAgentRotator.get_default()}
            except NameError:
                # OPSEC not imported, skip
                pass
        
        return requests.request(method, url, **kwargs)


def get(url: str, timeout: Optional[tuple[int, int]] = None, use_opsec: Optional[bool] = None, **kwargs) -> requests.Response:
    """GET request with consistent timeout and optional OPSEC features."""
    if timeout is None:
        timeout = Config.get_request_timeout()
    if 'timeout' not in kwargs:
        kwargs['timeout'] = timeout
    return make_request('GET', url, timeout=timeout, use_opsec=use_opsec, **kwargs)


def post(url: str, timeout: Optional[tuple[int, int]] = None, use_opsec: Optional[bool] = None, **kwargs) -> requests.Response:
    """POST request with consistent timeout and optional OPSEC features."""
    if timeout is None:
        timeout = Config.get_request_timeout()
    if 'timeout' not in kwargs:
        kwargs['timeout'] = timeout
    return make_request('POST', url, timeout=timeout, use_opsec=use_opsec, **kwargs)


def put(url: str, timeout: Optional[tuple[int, int]] = None, **kwargs) -> requests.Response:
    """PUT request with consistent timeout."""
    if timeout is None:
        timeout = Config.get_request_timeout()
    if 'timeout' not in kwargs:
        kwargs['timeout'] = timeout
    return requests.put(url, **kwargs)


def patch(url: str, timeout: Optional[tuple[int, int]] = None, **kwargs) -> requests.Response:
    """PATCH request with consistent timeout."""
    if timeout is None:
        timeout = Config.get_request_timeout()
    if 'timeout' not in kwargs:
        kwargs['timeout'] = timeout
    return requests.patch(url, **kwargs)


def delete(url: str, timeout: Optional[tuple[int, int]] = None, **kwargs) -> requests.Response:
    """DELETE request with consistent timeout."""
    if timeout is None:
        timeout = Config.get_request_timeout()
    if 'timeout' not in kwargs:
        kwargs['timeout'] = timeout
    return requests.delete(url, **kwargs)
