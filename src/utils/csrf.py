"""CSRF protection for DarkOrca."""

import secrets
import hmac
import hashlib
from flask import session, request, abort, jsonify
from functools import wraps
from typing import Callable, Optional


def generate_csrf_token() -> str:
    """Generate a CSRF token and store it in the session."""
    session.permanent = True  # Ensure session persists across requests
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_urlsafe(32)
    return session['csrf_token']


def validate_csrf_token(token: Optional[str] = None) -> bool:
    """
    Validate a CSRF token.
    
    Args:
        token: CSRF token to validate. If None, reads from request.
        
    Returns:
        True if token is valid, False otherwise
    """
    if token is None:
        # Try to get token from header first (most reliable for API requests)
        token = request.headers.get('X-CSRF-Token')
        # Then try JSON body
        if not token and request.is_json:
            try:
                json_data = request.get_json(silent=True) or {}
                token = json_data.get('csrf_token')
            except Exception:
                pass
        # Finally try form data
        if not token:
            token = request.form.get('csrf_token')
    
    if not token:
        return False
    
    session_token = session.get('csrf_token')
    if not session_token:
        return False
    
    # Use hmac.compare_digest to prevent timing attacks
    return hmac.compare_digest(token, session_token)


def require_csrf(f: Callable) -> Callable:
    """
    Decorator to require CSRF token for POST/PUT/DELETE requests.
    
    Usage:
        @app.route('/api/something', methods=['POST'])
        @require_csrf
        def my_handler():
            ...
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method in ('POST', 'PUT', 'DELETE', 'PATCH'):
            if not validate_csrf_token():
                # For API endpoints, return JSON error instead of HTML
                if request.path.startswith('/api/'):
                    return jsonify({'error': 'CSRF token missing or invalid'}), 403
                abort(403, description='CSRF token missing or invalid')
        return f(*args, **kwargs)
    return decorated_function


def csrf_exempt(f: Callable) -> Callable:
    """
    Decorator to exempt a route from CSRF protection.
    Use with caution - only for routes that are safe from CSRF (e.g., read-only APIs).
    """
    f._csrf_exempt = True
    return f
