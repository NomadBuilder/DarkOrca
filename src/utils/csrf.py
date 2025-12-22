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
        import logging
        logger = logging.getLogger(__name__)
        logger.debug(f"Generated new CSRF token: {session['csrf_token'][:10]}...")
    return session['csrf_token']


def validate_csrf_token(token: Optional[str] = None) -> bool:
    """
    Validate a CSRF token.
    
    Args:
        token: CSRF token to validate. If None, reads from request.
        
    Returns:
        True if token is valid, False otherwise
    """
    import logging
    logger = logging.getLogger(__name__)
    
    if token is None:
        # Try to get token from header first (most reliable for API requests)
        token = request.headers.get('X-CSRF-Token')
        logger.debug(f"CSRF token from header: {'found' if token else 'not found'}")
        # Then try JSON body
        if not token and request.is_json:
            try:
                json_data = request.get_json(silent=True) or {}
                token = json_data.get('csrf_token')
                logger.debug(f"CSRF token from JSON body: {'found' if token else 'not found'}")
            except Exception as e:
                logger.debug(f"Error reading JSON body for CSRF token: {e}")
                pass
        # Finally try form data
        if not token:
            token = request.form.get('csrf_token')
            logger.debug(f"CSRF token from form data: {'found' if token else 'not found'}")
    
    if not token:
        logger.warning("CSRF token not found in request (header, JSON body, or form data)")
        return False
    
    session_token = session.get('csrf_token')
    if not session_token:
        logger.warning(f"CSRF token not found in session. Session keys: {list(session.keys())}")
        # Try to generate a new token if session exists but token is missing
        if session:
            logger.debug("Session exists but CSRF token missing, generating new one")
            session_token = generate_csrf_token()
        else:
            return False
    
    # Use hmac.compare_digest to prevent timing attacks
    is_valid = hmac.compare_digest(token, session_token)
    if not is_valid:
        logger.warning(f"CSRF token mismatch. Provided: {token[:10]}..., Session: {session_token[:10]}...")
    return is_valid


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
