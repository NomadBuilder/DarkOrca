"""Security headers middleware for DarkOrca."""

from flask import Response
from functools import wraps
from typing import Callable


def add_security_headers(response: Response) -> Response:
    """
    Add security headers to all responses.
    
    Args:
        response: Flask response object
        
    Returns:
        Response with security headers added
    """
    # Content Security Policy
    # Allow self, inline scripts from tailwindcss CDN, and Font Awesome CDN
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com "
        "https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com "
        "https://cdnjs.cloudflare.com; "
        "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
        "img-src 'self' data: https:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self';"
    )
    
    # Prevent clickjacking
    response.headers['X-Frame-Options'] = 'DENY'
    
    # Prevent MIME type sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # XSS Protection (legacy, but still useful)
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Referrer Policy
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # Permissions Policy (formerly Feature-Policy)
    response.headers['Permissions-Policy'] = (
        'geolocation=(), microphone=(), camera=(), payment=()'
    )
    
    # Strict Transport Security (HSTS) - only if HTTPS
    # Note: In production with HTTPS, set this appropriately
    # For development (HTTP), we don't set this to avoid issues
    
    return response


def security_headers_decorator(f: Callable) -> Callable:
    """Decorator to add security headers to a route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        response = f(*args, **kwargs)
        if isinstance(response, Response):
            return add_security_headers(response)
        return response
    return decorated_function
