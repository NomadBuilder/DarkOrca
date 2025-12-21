"""Authentication utilities for web app."""

import logging
from typing import Optional
from flask import session, request

from .database import User, UserSession

logger = logging.getLogger(__name__)


def get_current_user() -> Optional[User]:
    """Get the current authenticated user from session."""
    session_token = session.get('session_token')
    if not session_token:
        return None
    
    user = UserSession.get_user_from_token(session_token)
    if not user:
        # Session expired or invalid, clear it
        session.pop('session_token', None)
        return None
    
    return user


def require_auth(func):
    """Decorator to require authentication for a route."""
    from functools import wraps
    from flask import jsonify, redirect, url_for
    
    @wraps(func)
    def wrapper(*args, **kwargs):
        user = get_current_user()
        if not user:
            # Check if this is an API request
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Authentication required'}), 401
            else:
                # Redirect to login for web requests
                return redirect('/login?next=' + request.path)
        return func(*args, **kwargs)
    return wrapper


def login_user(user: User) -> str:
    """Log in a user and return session token."""
    session_token = UserSession.create(user.id)
    session['session_token'] = session_token
    session['user_id'] = user.id
    session['username'] = user.username
    logger.info(f"User {user.username} logged in")
    return session_token


def logout_user():
    """Log out the current user."""
    session_token = session.get('session_token')
    if session_token:
        UserSession.delete_token(session_token)
    session.clear()
    logger.info("User logged out")
