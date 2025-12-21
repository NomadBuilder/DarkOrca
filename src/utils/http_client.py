"""Centralized HTTP client with timeout configuration."""

import os
import requests
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

# Default timeout configuration (in seconds)
DEFAULT_TIMEOUT = int(os.getenv('HTTP_TIMEOUT', '30'))  # 30 seconds default
DEFAULT_CONNECT_TIMEOUT = int(os.getenv('HTTP_CONNECT_TIMEOUT', '10'))  # 10 seconds for connection
DEFAULT_READ_TIMEOUT = int(os.getenv('HTTP_READ_TIMEOUT', '30'))  # 30 seconds for reading

# Maximum timeout to prevent excessive waits
MAX_TIMEOUT = 300  # 5 minutes maximum


class HTTPClient:
    """Centralized HTTP client with configurable timeouts."""
    
    def __init__(
        self,
        timeout: Optional[float] = None,
        connect_timeout: Optional[float] = None,
        read_timeout: Optional[float] = None,
        default_headers: Optional[Dict[str, str]] = None
    ):
        """
        Initialize HTTP client.
        
        Args:
            timeout: Total timeout (connect + read). If None, uses DEFAULT_TIMEOUT.
            connect_timeout: Connection timeout. If None, uses DEFAULT_CONNECT_TIMEOUT.
            read_timeout: Read timeout. If None, uses DEFAULT_READ_TIMEOUT.
            default_headers: Default headers to include in all requests.
        """
        self.timeout = timeout if timeout is not None else DEFAULT_TIMEOUT
        self.connect_timeout = connect_timeout if connect_timeout is not None else DEFAULT_CONNECT_TIMEOUT
        self.read_timeout = read_timeout if read_timeout is not None else DEFAULT_READ_TIMEOUT
        
        # Ensure timeouts are within reasonable limits
        self.timeout = min(self.timeout, MAX_TIMEOUT)
        self.connect_timeout = min(self.connect_timeout, MAX_TIMEOUT)
        self.read_timeout = min(self.read_timeout, MAX_TIMEOUT)
        
        # Default headers
        self.default_headers = default_headers or {}
        if 'User-Agent' not in self.default_headers:
            self.default_headers['User-Agent'] = 'DarkOrca/1.0'
        
        # Create session for connection pooling
        self.session = requests.Session()
        self.session.headers.update(self.default_headers)
    
    def get(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
        **kwargs
    ) -> requests.Response:
        """
        Make a GET request with configured timeouts.
        
        Args:
            url: URL to request
            params: Query parameters
            headers: Additional headers (merged with default headers)
            timeout: Override default timeout for this request
            **kwargs: Additional arguments passed to requests.get
            
        Returns:
            requests.Response object
        """
        request_headers = {**self.default_headers}
        if headers:
            request_headers.update(headers)
        
        request_timeout = timeout if timeout is not None else self.timeout
        request_timeout = min(request_timeout, MAX_TIMEOUT)
        
        try:
            response = self.session.get(
                url,
                params=params,
                headers=request_headers,
                timeout=request_timeout,
                **kwargs
            )
            return response
        except requests.exceptions.Timeout as e:
            logger.warning(f"Request timeout for {url}: {e}")
            raise
        except requests.exceptions.RequestException as e:
            logger.error(f"Request error for {url}: {e}")
            raise
    
    def post(
        self,
        url: str,
        data: Optional[Any] = None,
        json: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
        **kwargs
    ) -> requests.Response:
        """
        Make a POST request with configured timeouts.
        
        Args:
            url: URL to request
            data: Form data
            json: JSON data
            headers: Additional headers (merged with default headers)
            timeout: Override default timeout for this request
            **kwargs: Additional arguments passed to requests.post
            
        Returns:
            requests.Response object
        """
        request_headers = {**self.default_headers}
        if headers:
            request_headers.update(headers)
        
        request_timeout = timeout if timeout is not None else self.timeout
        request_timeout = min(request_timeout, MAX_TIMEOUT)
        
        try:
            response = self.session.post(
                url,
                data=data,
                json=json,
                headers=request_headers,
                timeout=request_timeout,
                **kwargs
            )
            return response
        except requests.exceptions.Timeout as e:
            logger.warning(f"Request timeout for {url}: {e}")
            raise
        except requests.exceptions.RequestException as e:
            logger.error(f"Request error for {url}: {e}")
            raise
    
    def request(
        self,
        method: str,
        url: str,
        timeout: Optional[float] = None,
        **kwargs
    ) -> requests.Response:
        """
        Make a request with configured timeouts.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            url: URL to request
            timeout: Override default timeout for this request
            **kwargs: Additional arguments passed to requests.request
            
        Returns:
            requests.Response object
        """
        request_timeout = timeout if timeout is not None else self.timeout
        request_timeout = min(request_timeout, MAX_TIMEOUT)
        
        try:
            response = self.session.request(
                method,
                url,
                timeout=request_timeout,
                **kwargs
            )
            return response
        except requests.exceptions.Timeout as e:
            logger.warning(f"Request timeout for {method} {url}: {e}")
            raise
        except requests.exceptions.RequestException as e:
            logger.error(f"Request error for {method} {url}: {e}")
            raise


# Global HTTP client instance
_default_client = HTTPClient()


def get_default_client() -> HTTPClient:
    """Get the default HTTP client instance."""
    return _default_client
