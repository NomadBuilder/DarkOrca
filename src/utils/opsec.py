"""Operational Security (OPSEC) utilities for anonymizing scans and preventing attribution."""

import os
import random
import time
import requests
from typing import Dict, Optional, List
from urllib.parse import urlparse


class UserAgentRotator:
    """Rotates user agents to prevent fingerprinting."""
    
    # Realistic browser user agents (updated 2024)
    USER_AGENTS = [
        # Chrome on Windows
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
        
        # Chrome on macOS
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
        
        # Firefox on Windows
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
        
        # Firefox on macOS
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0',
        
        # Safari on macOS
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
        
        # Edge on Windows
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
        
        # Chrome on Linux
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    ]
    
    @classmethod
    def get_random(cls) -> str:
        """Get a random user agent."""
        return random.choice(cls.USER_AGENTS)
    
    @classmethod
    def get_default(cls) -> str:
        """Get a common, unremarkable user agent."""
        return cls.USER_AGENTS[0]  # Most common Chrome on Windows


class HeaderNormalizer:
    """Normalizes and removes identifying headers."""
    
    # Headers that should be removed or normalized to prevent fingerprinting
    IDENTIFYING_HEADERS = [
        'X-Powered-By',
        'X-AspNet-Version',
        'Server',
        'X-Tool',
        'X-Scanner',
        'User-Agent',  # Will be replaced with normalized version
    ]
    
    @classmethod
    def get_clean_headers(cls, custom_headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """
        Get clean headers with tool signatures removed.
        
        Args:
            custom_headers: Additional headers to include
            
        Returns:
            Dict of normalized headers
        """
        headers = {}
        
        # Add realistic browser headers
        headers['Accept'] = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8'
        headers['Accept-Language'] = 'en-US,en;q=0.9'
        headers['Accept-Encoding'] = 'gzip, deflate, br'
        headers['Connection'] = 'keep-alive'
        headers['Upgrade-Insecure-Requests'] = '1'
        headers['Sec-Fetch-Dest'] = 'document'
        headers['Sec-Fetch-Mode'] = 'navigate'
        headers['Sec-Fetch-Site'] = 'none'
        headers['Sec-Fetch-User'] = '?1'
        headers['Cache-Control'] = 'max-age=0'
        
        # User-Agent (will be set by session)
        headers['User-Agent'] = UserAgentRotator.get_default()
        
        # Add custom headers (override defaults if needed)
        if custom_headers:
            headers.update(custom_headers)
        
        # Remove any identifying headers that might have been added
        for header in cls.IDENTIFYING_HEADERS:
            if header.lower() in [h.lower() for h in headers.keys() if header != 'User-Agent']:
                del headers[header]
        
        return headers


class RequestTiming:
    """Adds random delays to requests to prevent timing-based fingerprinting."""
    
    @staticmethod
    def random_delay(min_seconds: float = 0.1, max_seconds: float = 2.0):
        """
        Add random delay between requests.
        
        Args:
            min_seconds: Minimum delay
            max_seconds: Maximum delay
        """
        delay = random.uniform(min_seconds, max_seconds)
        time.sleep(delay)
    
    @staticmethod
    def human_like_delay():
        """Add human-like delay (typically 0.5-3 seconds)."""
        RequestTiming.random_delay(0.5, 3.0)


class ProxyManager:
    """Manages proxy configuration for anonymizing source IP."""
    
    @staticmethod
    def get_proxy_config() -> Optional[Dict[str, str]]:
        """
        Get proxy configuration from environment variables.
        
        Supports:
        - HTTP_PROXY / http_proxy
        - HTTPS_PROXY / https_proxy
        - SOCKS proxies via SOCKS_PROXY
        
        Format: http://user:pass@host:port or http://host:port
        
        Returns:
            Dict with 'http' and 'https' keys, or None if no proxy configured
        """
        proxies = {}
        
        # Check for HTTP proxy
        http_proxy = os.getenv('HTTP_PROXY') or os.getenv('http_proxy')
        if http_proxy:
            proxies['http'] = http_proxy
        
        # Check for HTTPS proxy
        https_proxy = os.getenv('HTTPS_PROXY') or os.getenv('https_proxy')
        if https_proxy:
            proxies['https'] = https_proxy
        elif http_proxy:
            # If only HTTP_PROXY is set, use it for HTTPS too
            proxies['https'] = http_proxy
        
        # Check for SOCKS proxy
        socks_proxy = os.getenv('SOCKS_PROXY') or os.getenv('socks_proxy')
        if socks_proxy:
            # SOCKS proxies require requests[socks] package
            if not socks_proxy.startswith('socks5://') and not socks_proxy.startswith('socks4://'):
                socks_proxy = f'socks5://{socks_proxy}'
            proxies['http'] = socks_proxy
            proxies['https'] = socks_proxy
        
        return proxies if proxies else None
    
    @staticmethod
    def validate_proxy(proxy_url: str) -> bool:
        """
        Validate that a proxy URL is accessible.
        
        Args:
            proxy_url: Proxy URL to validate
            
        Returns:
            True if proxy is accessible, False otherwise
        """
        try:
            test_url = 'http://httpbin.org/ip'
            proxies = {'http': proxy_url, 'https': proxy_url}
            response = requests.get(test_url, proxies=proxies, timeout=10)
            return response.status_code == 200
        except:
            return False


def create_stealth_session(
    rotate_user_agent: bool = True,
    use_proxy: bool = True,
    add_delays: bool = False,
    custom_headers: Optional[Dict[str, str]] = None
) -> requests.Session:
    """
    Create a requests session configured for stealth scanning.
    
    Args:
        rotate_user_agent: If True, randomize user agent
        use_proxy: If True, use proxy from environment if available
        add_delays: If True, add random delays between requests
        custom_headers: Custom headers to add
        
    Returns:
        Configured requests.Session
    """
    session = requests.Session()
    
    # Set user agent
    if rotate_user_agent:
        session.headers['User-Agent'] = UserAgentRotator.get_random()
    else:
        session.headers['User-Agent'] = UserAgentRotator.get_default()
    
    # Get clean headers
    clean_headers = HeaderNormalizer.get_clean_headers(custom_headers)
    session.headers.update(clean_headers)
    
    # Configure proxy
    if use_proxy:
        proxies = ProxyManager.get_proxy_config()
        if proxies:
            session.proxies.update(proxies)
    
    # Disable SSL verification warnings (but still allow self-signed certs)
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    session.verify = False
    
    # Store delay config for later use
    session._opsec_add_delays = add_delays
    
    return session


def sanitize_logs(log_message: str, target_url: Optional[str] = None) -> str:
    """
    Sanitize log messages to remove identifying information.
    
    Args:
        log_message: Original log message
        target_url: Target URL (will be sanitized)
        
    Returns:
        Sanitized log message
    """
    if target_url:
        # Replace target URL with sanitized version
        parsed = urlparse(target_url)
        sanitized_url = f"{parsed.scheme}://{parsed.netloc}/***"
        log_message = log_message.replace(target_url, sanitized_url)
    
    # Remove tool signatures
    log_message = log_message.replace('DarkOrca', '[TOOL]')
    log_message = log_message.replace('DarkAI', '[ORG]')
    
    return log_message


def get_opsec_recommendations() -> List[str]:
    """Get OPSEC recommendations for secure scanning."""
    return [
        "1. Use VPN or Proxy: Set HTTP_PROXY or HTTPS_PROXY environment variable",
        "2. Rotate User-Agents: Enable user agent rotation in scanner configuration",
        "3. Add Request Delays: Enable random delays to mimic human behavior",
        "4. Scan from VPS: Use a VPS or cloud instance, not your home IP",
        "5. Use Tor: For maximum anonymity, route through Tor (socks5://127.0.0.1:9050)",
        "6. Limit Logging: Disable verbose logging or sanitize logs before storage",
        "7. Secure Storage: Encrypt scan results if storing sensitive target data",
        "8. Authorization: Always ensure you have permission to scan targets",
        "9. Rate Limiting: Respect target's rate limits to avoid detection",
        "10. Clean Up: Don't leave tool signatures in request logs on target servers",
    ]
