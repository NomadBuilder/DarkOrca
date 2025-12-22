"""Modern web UI for DarkOrca."""

import os
import json
import logging
import threading
import hashlib
import uuid
import re
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
from flask import Flask, render_template, request, jsonify, send_from_directory, abort, Response, redirect, url_for
from flask_cors import CORS
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    FLASK_LIMITER_AVAILABLE = True
except ImportError:
    FLASK_LIMITER_AVAILABLE = False
    # Create dummy limiter decorator if not available
    class Limiter:
        def __init__(self, *args, **kwargs):
            pass
        def limit(self, *args, **kwargs):
            def decorator(f):
                return f
            return decorator
    def get_remote_address():
        return '127.0.0.1'

# Load environment variables from .env file (same as DarkAI-consolidated)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv is optional

from src.orchestrator import ScanOrchestrator
from src.models.scan_mode import ScanMode
from src.utils.glossary import Glossary
from src.utils.validators import validate_url, validate_email, sanitize_input, validate_scan_id
from src.utils.config_validator import ConfigValidator
from src.utils.config import Config
from src.utils.database import init_database, User, SavedScan, UserSession
from src.utils.auth import get_current_user, require_auth, login_user, logout_user
from src.utils.csrf import generate_csrf_token, require_csrf

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', secrets.token_urlsafe(32))  # Required for sessions

# Secure session configuration
app.config['SESSION_COOKIE_SECURE'] = os.getenv('SESSION_COOKIE_SECURE', 'False').lower() == 'true'  # True in production (HTTPS)
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection
# Session timeout: 24 hours (reduced from 30 days for better security)
SESSION_TIMEOUT_HOURS = int(os.getenv('SESSION_TIMEOUT_HOURS', '24'))
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=SESSION_TIMEOUT_HOURS)

CORS(app)

# Add security headers to all responses
from src.utils.security_headers import add_security_headers
app.after_request(add_security_headers)

# Rate limiting
if FLASK_LIMITER_AVAILABLE:
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["200 per hour", "50 per minute"],
        storage_uri="memory://"  # In-memory storage (use Redis for production)
    )
else:
    # Dummy limiter class if flask-limiter not installed
    class DummyLimiter:
        def limit(self, *args, **kwargs):
            def decorator(f):
                return f
            return decorator
    limiter = DummyLimiter()

# Configure structured logging
from src.utils.logging_config import setup_logging
log_format = os.getenv('LOG_FORMAT', 'human')  # 'human' or 'json'
log_level = os.getenv('LOG_LEVEL', 'INFO')
log_file = os.getenv('LOG_FILE', None)  # Optional log file path
setup_logging(level=log_level, format_type=log_format, include_location=False, log_file=log_file)
logger = logging.getLogger(__name__)

# Store active scans and results
# Note: Scans remain in active_scans even after completion for status checks
active_scans = {}
scan_results = {}
# Keep completed scans for at least 1 hour for status checks
MAX_SCAN_AGE_HOURS = 1

# Concurrent scan limits
MAX_CONCURRENT_SCANS = int(os.getenv('MAX_CONCURRENT_SCANS', '5'))
current_concurrent_scans = 0
scan_queue = []
scan_lock = threading.Lock()  # Lock for thread-safe access to concurrent scan counter
results_lock = threading.Lock()  # Lock for thread-safe access to scan_results
active_scans_lock = threading.Lock()  # Lock for thread-safe access to active_scans


# Thread-safe helper functions for accessing global state
def get_scan_result(scan_id: str):
    """Thread-safe getter for scan_results."""
    with results_lock:
        return scan_results.get(scan_id)


def set_scan_result(scan_id: str, value):
    """Thread-safe setter for scan_results."""
    with results_lock:
        scan_results[scan_id] = value


def get_active_scan(scan_id: str):
    """Thread-safe getter for active_scans."""
    with active_scans_lock:
        return active_scans.get(scan_id)


def set_active_scan(scan_id: str, value):
    """Thread-safe setter for active_scans."""
    with active_scans_lock:
        active_scans[scan_id] = value


def update_active_scan(scan_id: str, updates: dict):
    """Thread-safe updater for active_scans (partial update)."""
    with active_scans_lock:
        if scan_id in active_scans:
            active_scans[scan_id].update(updates)
        else:
            active_scans[scan_id] = updates


def has_active_scan(scan_id: str) -> bool:
    """Thread-safe check for scan_id in active_scans."""
    with active_scans_lock:
        return scan_id in active_scans


def has_scan_result(scan_id: str) -> bool:
    """Thread-safe check for scan_id in scan_results."""
    with results_lock:
        return scan_id in scan_results


def delete_scan_result(scan_id: str):
    """Thread-safe deleter for scan_results."""
    with results_lock:
        scan_results.pop(scan_id, None)

# Persistent storage for shareable results
RESULTS_DIR = Path('scan_results')
RESULTS_DIR.mkdir(exist_ok=True)
RESULTS_EXPIRY_DAYS = 30  # Results expire after 30 days


# Determine if we're in production/development mode
IS_PRODUCTION = os.getenv('FLASK_ENV', 'development').lower() == 'production'

@app.before_request
def ensure_session():
    """Ensure session is permanent for all requests."""
    from flask import session
    session.permanent = True  # Make session persist across requests


@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors with generic message."""
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Resource not found'}), 404
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors - sanitize error messages in production."""
    logger.error(f"Internal server error: {error}", exc_info=True)
    if request.path.startswith('/api/'):
        # In production, return generic error. In development, include more detail.
        error_msg = 'An internal error occurred' if IS_PRODUCTION else str(error)
        return jsonify({'error': error_msg}), 500
    # For HTML pages, return generic error page
    return render_template('500.html'), 500


@app.errorhandler(Exception)
def handle_exception(error):
    """Global exception handler - sanitize all exceptions."""
    logger.error(f"Unhandled exception: {error}", exc_info=True)
    # Check if this is an API request
    if request.path.startswith('/api/'):
        # Return generic error message in production
        error_msg = 'An error occurred processing your request' if IS_PRODUCTION else str(error)
        status_code = getattr(error, 'code', 500)
        return jsonify({'error': error_msg}), status_code
    # For HTML pages, re-raise or return generic error
    if IS_PRODUCTION:
        return render_template('500.html'), 500
    raise  # In development, show actual error


@app.route('/')
def index():
    """Main dashboard."""
    user = get_current_user()
    csrf_token = generate_csrf_token()  # Generate CSRF token for forms
    return render_template('index.html', user=user, csrf_token=csrf_token)


# Authentication routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page and handler."""
    if request.method == 'GET':
        csrf_token = generate_csrf_token()
        return render_template('login.html', csrf_token=csrf_token)
    
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        if not username or not password:
            return jsonify({'error': 'Username and password are required'}), 400
        
        # Check if account is locked before attempting authentication
        user_obj = User.get_by_username(username)
        if user_obj and User.check_account_locked(user_obj.id):
            # Account is locked - return generic error (don't reveal lock status to prevent enumeration)
            return jsonify({'error': 'Authentication failed'}), 401
        
        user = User.authenticate(username, password)
        if user:
            login_user(user)
            return jsonify({
                'success': True,
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email
                }
            })
        else:
            # Generic error message to prevent username enumeration
            # Same message regardless of whether username exists, password is wrong, or account is locked
            return jsonify({'error': 'Authentication failed'}), 401
    
    # GET request - show login page
    return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Signup page and handler."""
    if request.method == 'GET':
        csrf_token = generate_csrf_token()
        return render_template('signup.html', csrf_token=csrf_token)
    
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username', '').strip()
        email = data.get('email', '').strip()
        password = data.get('password', '')
        
        # Validate input
        if not username or not email or not password:
            return jsonify({'error': 'Username, email, and password are required'}), 400
        
        if len(username) < 3:
            return jsonify({'error': 'Username must be at least 3 characters'}), 400
        
        # Enhanced password strength requirements
        password_errors = []
        if len(password) < 8:
            password_errors.append('at least 8 characters')
        if not re.search(r'[A-Z]', password):
            password_errors.append('one uppercase letter')
        if not re.search(r'[a-z]', password):
            password_errors.append('one lowercase letter')
        if not re.search(r'\d', password):
            password_errors.append('one number')
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            password_errors.append('one special character')
        
        if password_errors:
            return jsonify({
                'error': f'Password must contain: {", ".join(password_errors)}'
            }), 400
        
        # Validate email
        is_valid, error_msg = validate_email(email)
        if not is_valid:
            return jsonify({'error': f'Invalid email: {error_msg}'}), 400
        
        try:
            user = User.create(username, email, password)
            login_user(user)
            
            # Send welcome email (non-blocking - don't fail registration if email fails)
            try:
                from src.utils.email_sender import get_email_sender
                email_sender = get_email_sender()
                if email_sender.is_enabled():
                    email_sender.send_welcome_email(email, username)
            except Exception as e:
                logger.warning(f"Failed to send welcome email to {email}: {e}", exc_info=True)
                # Don't fail registration if email fails
            
            return jsonify({
                'success': True,
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email
                }
            })
        except ValueError as e:
            return jsonify({'error': str(e)}), 400


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    """Logout handler."""
    logout_user()
    if request.method == 'POST':
        return jsonify({'success': True})
    # For GET requests, redirect to home
    return redirect(url_for('index'))


@app.route('/profile')
@require_auth
def profile():
    """User profile/settings page."""
    user = get_current_user()
    csrf_token = generate_csrf_token()
    return render_template('profile.html', user=user, csrf_token=csrf_token)


# Saved scans API routes
@app.route('/api/profile/saved-scans', methods=['GET'])
@require_auth
def get_saved_scans():
    """Get user's saved scans."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    
    limit = request.args.get('limit', 50, type=int)
    offset = request.args.get('offset', 0, type=int)
    
    saved_scans = SavedScan.get_user_scans(user.id, limit=limit, offset=offset)
    
    return jsonify({
        'scans': [scan.to_dict() for scan in saved_scans],
        'count': len(saved_scans)
    })


@app.route('/api/profile/saved-scans/<int:saved_scan_id>', methods=['GET'])
@require_auth
def get_saved_scan(saved_scan_id):
    """Get a specific saved scan."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    
    saved_scan = SavedScan.get_by_id(saved_scan_id, user.id)
    if not saved_scan:
        return jsonify({'error': 'Saved scan not found'}), 404
    
    return jsonify(saved_scan.to_dict())


@app.route('/api/profile/saved-scans/<int:saved_scan_id>', methods=['DELETE'])
@require_auth
@require_csrf
def delete_saved_scan(saved_scan_id):
    """Delete a saved scan."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    
    success = SavedScan.delete(saved_scan_id, user.id)
    if success:
        return jsonify({'success': True})
    else:
        return jsonify({'error': 'Saved scan not found'}), 404


@app.route('/api/profile/save-scan', methods=['POST'])
@require_auth
@require_csrf
def save_scan():
    """Save a scan result to user's profile."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.get_json()
    scan_id = data.get('scan_id')
    if not scan_id:
        return jsonify({'error': 'scan_id is required'}), 400
    
    # Get scan result from scan_results or shareable results
    result_dict = None
    target = None
    scan_mode = None
    target_url = None
    shareable_id = None
    
    if has_scan_result(scan_id):
        result_dict = get_scan_result(scan_id)
        target = result_dict.get('target', '')
        scan_mode = result_dict.get('scan_mode', 'DEFENSIVE')
        target_url = result_dict.get('target_url', target)
        shareable_id = result_dict.get('shareable_id')
    else:
        # Try to load from shareable results
        shareable_id = data.get('shareable_id')
        if shareable_id:
            result_data = _load_shareable_result(shareable_id)
            if result_data:
                result_dict = result_data.get('results')
                target = result_data.get('target', '')
                scan_mode = result_data.get('scan_mode', 'DEFENSIVE')
                target_url = target
    
    if not result_dict:
        return jsonify({'error': 'Scan results not found'}), 404
    
    # Extract target URL from result_dict if available
    if not target_url and 'target' in result_dict:
        target_obj = result_dict['target']
        if isinstance(target_obj, dict):
            target_url = target_obj.get('url', target)
        else:
            target_url = str(target_obj)
    
    try:
        saved_scan = SavedScan.save(
            user_id=user.id,
            scan_id=scan_id,
            shareable_id=shareable_id,
            target=target,
            scan_mode=scan_mode,
            target_url=target_url,
            result_data=result_dict
        )
        return jsonify({
            'success': True,
            'saved_scan': saved_scan.to_dict()
        })
    except Exception as e:
        logger.error(f"Error saving scan: {e}", exc_info=True)
        return jsonify({'error': f'Failed to save scan: {str(e)}'}), 500


@app.route('/api/profile/settings', methods=['GET', 'PUT'])
@require_auth
@require_csrf  # CSRF protection for PUT requests
def user_settings():
    """Get or update user settings."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    
    if request.method == 'GET':
        return jsonify({
            'settings': user.settings,
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'created_at': user.created_at
            }
        })
    
    # PUT request - update settings
    if request.method == 'PUT':
        # CSRF protection for PUT requests
        from src.utils.csrf import validate_csrf_token
        if not validate_csrf_token():
            return jsonify({'error': 'CSRF token missing or invalid'}), 403
    
    data = request.get_json()
    new_settings = data.get('settings', {})
    
    if not isinstance(new_settings, dict):
        return jsonify({'error': 'Settings must be an object'}), 400
    
    user.update_settings(new_settings)
    return jsonify({
        'success': True,
        'settings': user.settings
    })


@app.route('/static/<path:filename>')
def static_files(filename):
    """Serve static files with path traversal protection."""
    from src.utils.validators import validate_path_traversal_safe
    
    # Validate filename doesn't contain path traversal
    is_valid, error_msg = validate_path_traversal_safe(filename, 'static')
    if not is_valid:
        abort(400, description=f"Invalid file path: {error_msg}")
    
    return send_from_directory('static', filename)


@app.route('/favicon.ico')
def favicon():
    """Serve favicon."""
    return send_from_directory('static', 'DarkOrca.png', mimetype='image/png')


@app.route('/glossary')
def glossary():
    """Serve glossary page."""
    category = request.args.get('category', '')
    search = request.args.get('search', '')
    
    terms = Glossary.search_terms(search, category if category else None)
    categories = Glossary.get_categories()
    user = get_current_user()
    csrf_token = generate_csrf_token()
    
    return render_template('glossary.html', terms=terms, categories=categories,
                         current_category=category, search_query=search, user=user, csrf_token=csrf_token)


@app.route('/about')
def about():
    """Serve about page."""
    return render_template('about.html')


@app.route('/faq')
def faq():
    """Serve FAQ page."""
    user = get_current_user()
    csrf_token = generate_csrf_token()
    return render_template('faq.html', user=user, csrf_token=csrf_token)


@app.route('/health')
def health_check():
    """Health check endpoint for monitoring."""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '1.0.0',
        'concurrent_scans': current_concurrent_scans,
        'max_concurrent_scans': MAX_CONCURRENT_SCANS,
        'active_scans_count': len(active_scans),
        'queue_length': len(scan_queue),
    }), 200


@app.errorhandler(429)
def ratelimit_handler(e):
    """Handle rate limit errors."""
    return jsonify({
        'error': 'Rate limit exceeded. Please try again later.',
        'message': str(e.description)
    }), 429


@app.route('/api/scan', methods=['POST'])
@limiter.limit(f"{Config.RATE_LIMIT_SCANS_PER_MINUTE} per minute")  # Rate limit: configurable scans per minute per IP
@require_csrf  # CSRF protection for scan initiation
def start_scan():
    """Start a new scan."""
    global current_concurrent_scans
    
    # Check concurrent scan limit
    if current_concurrent_scans >= MAX_CONCURRENT_SCANS:
        return jsonify({
            'error': f'Maximum concurrent scans ({MAX_CONCURRENT_SCANS}) reached. Please try again later.',
            'queue_position': len(scan_queue) + 1
        }), 429  # Too Many Requests
    
    data = request.json
    if not data:
        return jsonify({'error': 'Request body is required'}), 400
    
    target = data.get('target')
    scan_mode = data.get('scan_mode', 'defensive')
    email = data.get('email', '').strip()  # Optional email for notifications
    enable_sqlmap = data.get('enable_sqlmap', False)
    enable_wpscan = data.get('enable_wpscan', True)
    enable_nuclei = data.get('enable_nuclei', True)
    enable_nmap = data.get('enable_nmap', True)
    exhaustive = data.get('exhaustive', False)  # Exhaustive mode (slower but more thorough)
    
    # Validate target URL
    if not target:
        return jsonify({'error': 'Target URL is required'}), 400
    
    # Sanitize and validate target
    target = sanitize_input(str(target), max_length=2048)
    is_valid, error_msg = validate_url(target, require_scheme=False)
    if not is_valid:
        return jsonify({'error': f'Invalid target URL: {error_msg}'}), 400
    
    # Validate email if provided
    if email:
        email = sanitize_input(email, max_length=254)
        is_valid, error_msg = validate_email(email)
        if not is_valid:
            return jsonify({'error': f'Invalid email address: {error_msg}'}), 400
    
    # Validate scan_mode
    if scan_mode not in ['defensive', 'offensive', 'comprehensive']:
        return jsonify({'error': 'Invalid scan_mode. Must be defensive, offensive, or comprehensive'}), 400
    
    # Generate scan ID
    scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    # Initialize scan status BEFORE starting thread to avoid race condition
    start_time = datetime.now()
    
    # Pre-calculate scanner estimates for single mode
    if scan_mode != 'comprehensive':
        mode = ScanMode.OFFENSIVE if scan_mode == 'offensive' else ScanMode.DEFENSIVE
        temp_orchestrator = ScanOrchestrator(
            enable_wpscan=enable_wpscan,
            enable_nuclei=enable_nuclei,
            enable_nmap=enable_nmap,
            enable_sqlmap=enable_sqlmap,
            scan_mode=mode,
            exhaustive=exhaustive,
        )
        total_scanners = len(temp_orchestrator.scanners)
        scanner_time_estimates = {
            'wpscan': 60,
            'nuclei': 30,
            'nmap': 40,
            'sqlmap': 120,
            'directory_bruteforcer': 60,
            'parameter_discovery': 120,
            'exploit_intel': 30,
            'wordpress_analyzer': 5,
        }
        estimated_total = sum(scanner_time_estimates.get(scanner.name.lower(), 30) for scanner in temp_orchestrator.scanners)
    else:
        total_scanners = 0
        estimated_total = 0
    
    # Initialize scan status immediately (thread-safe)
    set_active_scan(scan_id, {
        'status': 'running',
        'progress': 0,
        'current_scanner': 'Initializing...',
        'started_at': start_time.isoformat(),
        'estimated_remaining_seconds': estimated_total,
        'scanners_total': total_scanners,
        'scanners_completed': 0,
        'elapsed_seconds': 0,
        'email': email,  # Store email for notification
    })
    with active_scans_lock:
        total_scans = len(active_scans)
    logger.info(f"Scan {scan_id} initialized and added to active_scans. Total active scans: {total_scans}")
    
    # Start scan in background thread
    def run_scan():
        """Run scan in background thread with comprehensive error handling."""
        global current_concurrent_scans
        
        # Increment concurrent scan counter
        with scan_lock:
            current_concurrent_scans += 1
            logger.info(f"Scan {scan_id} started. Concurrent scans: {current_concurrent_scans}/{MAX_CONCURRENT_SCANS}")
        
        try:
            logger.info(f"Scan thread started for {scan_id}, target: {target}, mode: {scan_mode}")
            if scan_mode == 'comprehensive':
                # Comprehensive mode: Run both defensive and offensive
                start_time = datetime.now()
                # Count unique scanners (WPScan, Nuclei, Nmap run in both phases but count once)
                base_scanners = len([s for s in [enable_wpscan, enable_nuclei, enable_nmap] if s])
                # Offensive-only scanners: SQLMap + WordPress Offensive + XSS Tester + Directory Bruteforcer + Parameter Discovery + Exploit Intelligence
                offensive_only_count = 0
                if enable_sqlmap:
                    offensive_only_count += 1  # SQLMap
                offensive_only_count += 1  # WordPress Offensive (always available)
                offensive_only_count += 1  # XSS Tester (always available)
                offensive_only_count += 1  # Directory Bruteforcer (if available)
                offensive_only_count += 1  # Parameter Discovery (if available)
                offensive_only_count += 1  # Exploit Intelligence (if available)
                # Total unique scanners = base scanners (count once) + offensive-only + WordPress Analyzer
                total_scanners = base_scanners + offensive_only_count + 1  # +1 for WordPress Analyzer
                defensive_scanners = base_scanners + 1  # Defensive phase runs base scanners + WordPress Analyzer
                offensive_scanners = base_scanners + offensive_only_count  # Offensive phase runs base + all offensive scanners
                
                # For progress tracking: we need to track scanners as they complete
                # Defensive: 0 to base_scanners
                # Offensive: base_scanners to base_scanners + offensive_scanners (but base scanners already counted)
                # So total unique scanners completed = base_scanners (from defensive) + offensive_only (from offensive)
                
                set_active_scan(scan_id, {
                    'status': 'running',
                    'progress': 0,
                    'current_scanner': None,
                    'started_at': start_time.isoformat(),
                    'phase': 'defensive',
                    'scanners_total': total_scanners,
                    'scanners_completed': 0,
                    'elapsed_seconds': 0,
                    'estimated_remaining_seconds': None,
                })
                
                # First run defensive scan
                def update_defensive_progress(progress_data):
                    defensive_completed = progress_data.get('scanners_completed', 0)
                    update_active_scan(scan_id, {
                        'current_scanner': f'Defensive: {progress_data.get("current_scanner", "Running...")}',
                        'scanners_completed': min(defensive_completed, defensive_scanners),
                        'progress': int((defensive_completed / max(defensive_scanners, 1)) * 50)
                    })
                    # Track per-scanner estimate
                    if 'current_scanner_estimate' in progress_data:
                        active_scans[scan_id]['current_scanner_estimate'] = progress_data.get('current_scanner_estimate')
                        scanner_name = progress_data.get('current_scanner', '').replace('Running ', '').replace('...', '')
                        active_scans[scan_id]['current_scanner_name'] = scanner_name
                        active_scans[scan_id]['current_scanner_start'] = datetime.now().isoformat()
                
                defensive_orchestrator = ScanOrchestrator(
                    enable_wpscan=enable_wpscan,
                    enable_nuclei=enable_nuclei,
                    enable_nmap=enable_nmap,
                    enable_sqlmap=False,  # No SQLMap in defensive phase
                    scan_mode=ScanMode.DEFENSIVE,
                    exhaustive=exhaustive,
                    progress_callback=update_defensive_progress,
                )
                
                active_scans[scan_id]['current_scanner'] = f'Defensive Phase: Starting...'
                defensive_start = datetime.now()
                defensive_result = defensive_orchestrator.scan(target)
                defensive_elapsed = (datetime.now() - defensive_start).total_seconds()
                
                # Defensive phase complete
                active_scans[scan_id]['scanners_completed'] = defensive_scanners
                active_scans[scan_id]['progress'] = 50
                
                # Then run offensive scan
                active_scans[scan_id]['phase'] = 'offensive'
                offensive_start = datetime.now()
                
                # Estimate offensive phase time based on defensive phase
                avg_time_per_scanner = defensive_elapsed / max(defensive_scanners, 1)
                estimated_offensive = avg_time_per_scanner * offensive_scanners
                active_scans[scan_id]['estimated_remaining_seconds'] = int(estimated_offensive)
                
                def update_offensive_progress(progress_data):
                    base_progress = 50
                    offensive_completed = progress_data.get('scanners_completed', 0)
                    offensive_progress = int((offensive_completed / max(offensive_scanners, 1)) * 50)
                    active_scans[scan_id]['current_scanner'] = f'Offensive: {progress_data.get("current_scanner", "Running...")}'
                    # Track per-scanner estimate
                    if 'current_scanner_estimate' in progress_data:
                        active_scans[scan_id]['current_scanner_estimate'] = progress_data.get('current_scanner_estimate')
                        scanner_name = progress_data.get('current_scanner', '').replace('Running ', '').replace('...', '')
                        active_scans[scan_id]['current_scanner_name'] = scanner_name
                        active_scans[scan_id]['current_scanner_start'] = datetime.now().isoformat()
                    # Track per-scanner estimate
                    if 'current_scanner_estimate' in progress_data:
                        active_scans[scan_id]['current_scanner_estimate'] = progress_data.get('current_scanner_estimate')
                        active_scans[scan_id]['current_scanner_name'] = progress_data.get('current_scanner', '').replace('Running ', '').replace('...', '')
                        active_scans[scan_id]['current_scanner_start'] = datetime.now().isoformat()
                    # For progress: defensive already completed base_scanners
                    # Offensive phase runs base_scanners again + offensive_only
                    # But we only count unique scanners, so:
                    # - Base scanners already counted from defensive (base_scanners)
                    # - Only count new scanners from offensive phase (offensive_completed - base_scanners, but only if > base_scanners)
                    # Actually simpler: defensive gave us base_scanners, offensive gives us offensive_only new ones
                    # So total = base_scanners + min(offensive_completed - base_scanners, offensive_only)
                    # But offensive_completed counts from 0, so when it reaches base_scanners, we've re-run base
                    # When it exceeds base_scanners, we've run new scanners
                    new_offensive_scanners = max(0, offensive_completed - base_scanners)
                    total_completed = base_scanners + min(new_offensive_scanners, offensive_only_count)
                    # Add 1 for WordPress Analyzer if we're near the end
                    if offensive_completed >= offensive_scanners:
                        total_completed = total_scanners  # All done
                    active_scans[scan_id]['scanners_completed'] = min(total_completed, total_scanners)
                    active_scans[scan_id]['progress'] = base_progress + offensive_progress
                
                offensive_orchestrator = ScanOrchestrator(
                    enable_wpscan=enable_wpscan,
                    enable_nuclei=enable_nuclei,
                    enable_nmap=enable_nmap,
                    enable_sqlmap=enable_sqlmap,
                    scan_mode=ScanMode.OFFENSIVE,
                    exhaustive=exhaustive,
                    progress_callback=update_offensive_progress,
                )
                
                active_scans[scan_id]['current_scanner'] = f'Offensive Phase: Starting...'
                offensive_result = offensive_orchestrator.scan(target)
                
                # Merge results
                from src.models.scan import ScanResult
                from src.models.risk import RiskScore
                
                # Combine findings with deduplication
                # Use add_finding to automatically deduplicate
                combined_result = ScanResult(
                    target=defensive_result.target,
                    scan_mode=ScanMode.COMPREHENSIVE,
                )
                # Add defensive findings first
                for finding in defensive_result.findings:
                    combined_result.add_finding(finding)
                # Add offensive findings (will be deduplicated automatically)
                for finding in offensive_result.findings:
                    combined_result.add_finding(finding)
                combined_result.scanners_run = list(set(defensive_result.scanners_run + offensive_result.scanners_run))
                combined_result.scanner_errors = {**defensive_result.scanner_errors, **offensive_result.scanner_errors}
                combined_result.exploitations_successful = offensive_result.exploitations_successful
                combined_result.scan_started_at = defensive_result.scan_started_at
                
                # Recalculate risk score
                from src.scoring.engine import RiskScoringEngine
                combined_result.findings = RiskScoringEngine.enhance_findings_with_remediation(combined_result.findings)
                combined_result.risk_score = RiskScoringEngine.calculate_risk(combined_result)
                
                # Generate AI analysis for combined result (non-blocking)
                try:
                    from src.utils.ai_analyzer import generate_analysis
                    logger.info("Generating AI analysis for combined scan result...")
                    combined_result.ai_analysis = generate_analysis(combined_result)
                    if combined_result.ai_analysis:
                        logger.info("AI analysis generated successfully for combined result")
                    else:
                        logger.debug("AI analysis not available for combined result")
                except Exception as e:
                    logger.warning(f"Failed to generate AI analysis for combined result: {e}")
                    combined_result.ai_analysis = None
                
                combined_result.scan_completed_at = datetime.utcnow()
                
                result = combined_result
            else:
                # Single mode scan
                mode = ScanMode.OFFENSIVE if scan_mode == 'offensive' else ScanMode.DEFENSIVE
                def update_single_progress(progress_data):
                    active_scans[scan_id]['current_scanner'] = progress_data.get('current_scanner', 'Running...')
                    active_scans[scan_id]['scanners_completed'] = progress_data.get('scanners_completed', 0)
                    active_scans[scan_id]['scanners_total'] = progress_data.get('scanners_total', len(orchestrator.scanners))
                    active_scans[scan_id]['progress'] = int((progress_data.get('scanners_completed', 0) / max(progress_data.get('scanners_total', 1), 1)) * 100)
                    # Track per-scanner estimate
                    if 'current_scanner_estimate' in progress_data:
                        active_scans[scan_id]['current_scanner_estimate'] = progress_data.get('current_scanner_estimate')
                        active_scans[scan_id]['current_scanner_name'] = progress_data.get('current_scanner', '').replace('Running ', '').replace('...', '')
                
                orchestrator = ScanOrchestrator(
                    enable_wpscan=enable_wpscan,
                    enable_nuclei=enable_nuclei,
                    enable_nmap=enable_nmap,
                    enable_sqlmap=enable_sqlmap,
                    scan_mode=mode,
                    exhaustive=exhaustive,
                    progress_callback=update_single_progress,
                )
                
                # Update scan status with actual scanner count - thread-safe
                scanner_total = len(orchestrator.scanners)
                update_active_scan(scan_id, {
                    'scanners_total': scanner_total,
                    'current_scanner': 'Starting scan...'
                })
                
                result = orchestrator.scan(target)
                
                # Update final progress - thread-safe
                update_active_scan(scan_id, {
                    'progress': 100,
                    'scanners_completed': scanner_total,
                    'estimated_remaining_seconds': 0,
                    'current_scanner': 'Complete'
                })
            
            # Validate result has required fields
            if not hasattr(result, 'risk_score') or result.risk_score is None:
                logger.error(f"Scan {scan_id} completed but risk_score is missing!")
                # Create a default risk score
                from src.models.risk import RiskScore, RiskLevel
                result.risk_score = RiskScore.calculate(result.findings)
                logger.info(f"Generated default risk score: {result.risk_score.overall_score}")
            
            if not hasattr(result, 'target') or result.target is None:
                logger.error(f"Scan {scan_id} completed but target is missing!")
                raise ValueError("Scan result missing target")
            
            # Convert result to dict
            try:
                result_dict = {
                    'target': {
                        'url': result.target.url,
                        'domain': result.target.domain,
                        'protocol': result.target.protocol,
                    },
                    'scan_mode': result.scan_mode.value if hasattr(result.scan_mode, 'value') else str(result.scan_mode),
                    'findings': [],  # Will be populated below
                    'risk_score': result.risk_score.to_dict() if hasattr(result.risk_score, 'to_dict') else {},
                    'scanners_run': getattr(result, 'scanners_run', []),
                    'scanner_errors': getattr(result, 'scanner_errors', {}),
                    'exploitations_successful': getattr(result, 'exploitations_successful', 0),
                    'scan_completed_at': result.scan_completed_at.isoformat() if result.scan_completed_at else None,
                    'scan_started_at': result.scan_started_at.isoformat() if result.scan_started_at else None,
                    'ai_analysis': getattr(result, 'ai_analysis', None),  # Include AI analysis if available
                }
            except Exception as e:
                logger.error(f"Error creating result_dict: {e}", exc_info=True)
                raise
            
            # Convert Finding objects to dicts properly
            findings_list = []
            try:
                for finding in getattr(result, 'findings', []):
                    try:
                        finding_dict = {
                            'title': getattr(finding, 'title', 'Unknown'),
                            'description': getattr(finding, 'description', ''),
                            'severity': finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
                            'category': finding.category.value if hasattr(finding.category, 'value') else str(finding.category),
                            'source_scanner': getattr(finding, 'source_scanner', 'Unknown'),
                            'source_id': getattr(finding, 'source_id', ''),
                            'url': getattr(finding, 'url', ''),
                            'evidence': getattr(finding, 'evidence', ''),
                            'cve': getattr(finding, 'cve', None),
                            'remediation': getattr(finding, 'remediation', ''),
                            'references': getattr(finding, 'references', []),
                            'metadata': getattr(finding, 'metadata', {}),
                            'discovered_at': finding.discovered_at.isoformat() if hasattr(finding, 'discovered_at') and finding.discovered_at else None,
                            'exploited': getattr(finding, 'exploited', False),
                            'exploitation_details': getattr(finding, 'exploitation_details', None),
                        }
                        findings_list.append(finding_dict)
                    except Exception as e:
                        logger.warning(f"Error converting finding to dict: {e}")
                        continue  # Skip this finding but continue with others
                
                result_dict['findings'] = findings_list
                logger.info(f"Converted {len(findings_list)} findings to dict")
            except Exception as e:
                logger.error(f"Error converting findings: {e}", exc_info=True)
                result_dict['findings'] = []  # Empty list if conversion fails
            
            # Save results BEFORE marking as completed (critical for frontend to load results) - thread-safe
            set_scan_result(scan_id, result_dict)
            logger.info(f"Results saved for scan {scan_id}, total findings: {len(findings_list)}")
            
            # Generate shareable ID and save to persistent storage
            shareable_id = _generate_shareable_id(scan_id, target)
            _save_shareable_result(shareable_id, result_dict, target, scan_mode)
            logger.info(f"Results saved with shareable ID: {shareable_id}")
            
            # Add shareable_id and other metadata to result_dict for frontend
            result_dict['shareable_id'] = shareable_id
            result_dict['shareable_url'] = f"/results/{shareable_id}"
            result_dict['scan_id'] = scan_id  # Add scan_id for saving to profile
            result_dict['target_url'] = target  # Add target_url for saving
            result_dict['scan_id'] = scan_id  # Add scan_id for saving to profile
            result_dict['target_url'] = target  # Add target_url for saving
            
            # Send email notification if email provided
            scan_info = get_active_scan(scan_id)
            email = scan_info.get('email', '') if scan_info else ''
            if email:
                try:
                    from src.utils.email_sender import get_email_sender
                    email_sender = get_email_sender()
                    logger.info(f"Email notification requested for {email}. Email sender enabled: {email_sender.is_enabled()}")
                    if email_sender.is_enabled():
                        risk_score = result.risk_score.overall_score if result.risk_score else 0
                        risk_level = result.risk_score.risk_level.value if result.risk_score else 'low'
                        findings_count = len(result.findings)
                        logger.info(f"Sending email to {email} for scan {scan_id} (risk: {risk_level}, score: {risk_score})")
                        success = email_sender.send_scan_complete_notification(
                            to_email=email,
                            target_url=target,
                            scan_mode=scan_mode,
                            risk_score=risk_score,
                            risk_level=risk_level,
                            findings_count=findings_count,
                            shareable_id=shareable_id,
                            scan_id=scan_id
                        )
                        if success:
                            logger.info(f"Email successfully sent to {email}")
                        else:
                            logger.warning(f"Email send returned False for {email}")
                    else:
                        logger.warning(f"Email notifications are disabled. Check RESEND_API_KEY or SMTP credentials in .env file")
                except Exception as e:
                    logger.error(f"Failed to send email notification to {email}: {e}", exc_info=True)
            
            # Update active_scans to mark as completed (preserve existing data)
            # Keep scan in active_scans even after completion so status checks work
            if scan_id in active_scans:
                active_scans[scan_id].update({
                    'status': 'completed',
                    'progress': 100,
                    'scanners_completed': get_active_scan(scan_id).get('scanners_total', 0) if get_active_scan(scan_id) else 0,
                    'completed_at': datetime.now().isoformat(),
                    'estimated_remaining_seconds': 0,
                    'current_scanner': 'Complete',
                })
            else:
                # If somehow not in active_scans, add it so status endpoint works - thread-safe
                set_active_scan(scan_id, {
                    'status': 'completed',
                    'progress': 100,
                    'scanners_completed': len(result.scanners_run) if hasattr(result, 'scanners_run') else 0,
                    'scanners_total': len(result.scanners_run) if hasattr(result, 'scanners_run') else 0,
                    'completed_at': datetime.now().isoformat(),
                    'estimated_remaining_seconds': 0,
                    'current_scanner': 'Complete',
                })
            
        except Exception as e:
            logger.error(f"Scan failed: {e}", exc_info=True)
            import traceback
            error_trace = traceback.format_exc()
            logger.error(f"Full traceback: {error_trace}")
            
            # Try to save partial results if we have any
            try:
                if 'result' in locals() and result is not None:
                    logger.info("Attempting to save partial results...")
                    # Create minimal result dict
                    partial_result = {
                        'target': {
                            'url': getattr(result.target, 'url', target) if hasattr(result, 'target') else target,
                            'domain': getattr(result.target, 'domain', '') if hasattr(result, 'target') else '',
                            'protocol': getattr(result.target, 'protocol', 'https') if hasattr(result, 'target') else 'https',
                        },
                        'scan_mode': getattr(result, 'scan_mode', ScanMode.DEFENSIVE).value if hasattr(result, 'scan_mode') else 'defensive',
                        'findings': [],
                        'risk_score': {
                            'overall_score': 0.0,
                            'risk_level': 'error',
                            'summary': f'Scan failed: {str(e)}'
                        },
                        'scanners_run': getattr(result, 'scanners_run', []),
                        'scanner_errors': {**getattr(result, 'scanner_errors', {}), 'scan_failure': str(e)},
                        'exploitations_successful': 0,
                    }
                    set_scan_result(scan_id, partial_result)
                    logger.info("Partial results saved")
            except Exception as save_error:
                logger.error(f"Failed to save partial results: {save_error}")
            
            if has_active_scan(scan_id):
                update_active_scan(scan_id, {
                    'status': 'error',
                    'error': 'An error occurred during scan' if IS_PRODUCTION else str(e),  # Sanitize error in production
                    'completed_at': datetime.now().isoformat(),
                })
            else:
                set_active_scan(scan_id, {
                    'status': 'error',
                    'error': 'An error occurred during scan' if IS_PRODUCTION else str(e),  # Sanitize error in production
                    'completed_at': datetime.now().isoformat(),
                })
        finally:
            # Always decrement concurrent scan counter when scan completes or fails
            with scan_lock:
                current_concurrent_scans = max(0, current_concurrent_scans - 1)
                logger.info(f"Scan {scan_id} finished. Concurrent scans: {current_concurrent_scans}/{MAX_CONCURRENT_SCANS}")
    
    thread = threading.Thread(target=run_scan, name=f"scan-{scan_id}")
    thread.daemon = True
    thread.start()
    logger.info(f"Started scan thread for {scan_id}, thread name: {thread.name}, thread alive: {thread.is_alive()}")
    
    # Verify scan is in active_scans before returning - thread-safe
    if not has_active_scan(scan_id):
        logger.error(f"CRITICAL: Scan {scan_id} not found in active_scans after initialization!")
    else:
        logger.info(f"Scan {scan_id} confirmed in active_scans before returning response")
    
    return jsonify({
        'scan_id': scan_id,
        'status': 'started',
        'message': 'Scan started successfully'
    })


@app.route('/api/scan/<scan_id>/status', methods=['GET'])
def get_scan_status(scan_id):
    """Get scan status."""
    with active_scans_lock:
        active_keys = list(active_scans.keys())[-5:]
        total_active = len(active_scans)
    logger.info(f"Status check for scan_id: '{scan_id}' (type: {type(scan_id)}, len: {len(scan_id)}), active_scans keys: {active_keys}")
    logger.info(f"Scan ID in active_scans: {has_active_scan(scan_id)}, Total active scans: {total_active}")
    
    # Check active_scans first (includes completed scans) - thread-safe
    if has_active_scan(scan_id):
        scan_data = get_active_scan(scan_id).copy() if get_active_scan(scan_id) else None
        if not scan_data:
            return jsonify({'error': 'Scan not found'}), 404
        
        # If completed, ensure we have the right status
        if scan_data.get('status') == 'completed':
            scan_data['progress'] = 100
            scan_data['estimated_remaining_seconds'] = 0
            return jsonify(scan_data)
        
        # Calculate elapsed time for running scans
        if 'started_at' in scan_data:
            started = datetime.fromisoformat(scan_data['started_at'])
            elapsed = (datetime.now() - started).total_seconds()
            scan_data['elapsed_seconds'] = int(elapsed)
            
            # Calculate per-scanner remaining time estimate
            # Use current scanner estimate if available, otherwise calculate from overall progress
            if scan_data.get('current_scanner_estimate') is not None and scan_data.get('current_scanner_start'):
                # Estimate for current scanner only
                try:
                    scanner_start = datetime.fromisoformat(scan_data.get('current_scanner_start'))
                    scanner_elapsed = (datetime.now() - scanner_start).total_seconds()
                    scanner_estimate = scan_data.get('current_scanner_estimate', 30)
                    scanner_remaining = scanner_estimate - scanner_elapsed
                    # If scanner is taking longer than estimate, show 0 (will display "Finishing..." in UI)
                    # But add a small buffer (5 seconds) to avoid showing 0 too early
                    if scanner_remaining < 5:
                        scan_data['estimated_remaining_seconds'] = 0
                    else:
                        scan_data['estimated_remaining_seconds'] = int(scanner_remaining)
                    scan_data['is_per_scanner_estimate'] = True
                    scan_data['current_scanner_elapsed_seconds'] = int(scanner_elapsed)
                except:
                    # Fallback if date parsing fails
                    scan_data['is_per_scanner_estimate'] = False
            elif scan_data.get('estimated_remaining_seconds') is not None and scan_data.get('progress', 0) > 0:
                # Fallback to overall progress-based estimate
                if scan_data['progress'] < 100:
                    remaining = elapsed * (100 - scan_data['progress']) / max(scan_data['progress'], 1)
                    scan_data['estimated_remaining_seconds'] = int(remaining)
                else:
                    scan_data['estimated_remaining_seconds'] = 0
                scan_data['is_per_scanner_estimate'] = False
        
        # Update progress based on scanners completed
        if 'scanners_total' in scan_data and scan_data['scanners_total'] > 0:
            if 'scanners_completed' in scan_data:
                progress = int((scan_data['scanners_completed'] / scan_data['scanners_total']) * 100)
                scan_data['progress'] = min(progress, 99)  # Cap at 99% until complete
        
        return jsonify(scan_data)
    elif has_scan_result(scan_id):
        # Scan completed but not in active_scans - restore it - thread-safe
        result_data = get_scan_result(scan_id)
        scan_data = {
            'status': 'completed',
            'progress': 100,
            'estimated_remaining_seconds': 0,
            'scanners_completed': len(result_data.get('scanners_run', [])),
            'scanners_total': len(result_data.get('scanners_run', [])),
            'current_scanner': 'Complete',
            'completed_at': result_data.get('scan_completed_at'),
        }
        # Restore to active_scans so future status checks work - thread-safe
        set_active_scan(scan_id, scan_data)
        logger.info(f"Restored completed scan {scan_id} to active_scans")
        return jsonify(scan_data)
    else:
        # Check if scan_id has encoding issues (spaces vs underscores)
        normalized_scan_id = scan_id.replace(' ', '_')
        if normalized_scan_id != scan_id and has_active_scan(normalized_scan_id):
            logger.warning(f"Scan ID {scan_id} not found, but normalized version {normalized_scan_id} exists in active_scans")
            scan_id = normalized_scan_id
            scan_data = get_active_scan(scan_id).copy() if get_active_scan(scan_id) else None
            if not scan_data:
                return jsonify({'error': 'Scan not found'}), 404
            if 'started_at' in scan_data:
                started = datetime.fromisoformat(scan_data['started_at'])
                elapsed = (datetime.now() - started).total_seconds()
                scan_data['elapsed_seconds'] = int(elapsed)
            return jsonify(scan_data)
        
        with active_scans_lock:
            active_keys = list(active_scans.keys())[-10:]
        logger.warning(f"Scan ID {scan_id} not found in active_scans or scan_results. Active scan IDs: {active_keys}")
        # Return 404 with helpful message
        return jsonify({
            'error': 'Scan not found',
            'scan_id': scan_id,
            'message': 'Scan session may have expired or server was restarted. Please start a new scan.',
            'available_scans': active_keys[-5:] if active_keys else []
        }), 404


@app.route('/api/scan/<scan_id>/cancel', methods=['POST'])
@require_auth
@require_csrf
def cancel_scan(scan_id):
    """Cancel a running scan."""
    if has_active_scan(scan_id):
        existing = get_active_scan(scan_id)
        set_active_scan(scan_id, {
            'status': 'cancelled',
            'progress': existing.get('progress', 0) if existing else 0,
            'cancelled_at': datetime.now().isoformat(),
        })
        logger.info(f"Scan {scan_id} cancelled by user")
        return jsonify({'status': 'cancelled', 'message': 'Scan cancelled successfully'})
    else:
        return jsonify({'error': 'Scan not found'}), 404


@app.route('/api/scan/<scan_id>/results', methods=['GET'])
def get_scan_results(scan_id):
    """Get scan results."""
    if has_scan_result(scan_id):
        try:
            result_data = get_scan_result(scan_id)
            
            # Ensure all data is JSON serializable
            def make_serializable(obj):
                """Recursively convert non-serializable objects to strings."""
                if isinstance(obj, datetime):
                    return obj.isoformat()
                elif isinstance(obj, dict):
                    return {k: make_serializable(v) for k, v in obj.items()}
                elif isinstance(obj, list):
                    return [make_serializable(item) for item in obj]
                elif hasattr(obj, '__dict__'):
                    return make_serializable(obj.__dict__)
                else:
                    try:
                        json.dumps(obj)  # Test if serializable
                        return obj
                    except (TypeError, ValueError):
                        return str(obj)
            
            serializable_result = make_serializable(result_data)
            return jsonify(serializable_result)
        except Exception as e:
            logger.error(f"Error serializing results for {scan_id}: {e}", exc_info=True)
            error_msg = 'Failed to serialize results' if IS_PRODUCTION else f'Failed to serialize results: {str(e)}'
            return jsonify({'error': error_msg}), 500
    else:
        return jsonify({'error': 'Results not found'}), 404


@app.route('/api/scans', methods=['GET'])
def list_scans():
    """List all scans."""
    scans = []
    with results_lock:
        scan_results_copy = dict(scan_results)  # Make a copy while holding lock
    for scan_id, result in scan_results_copy.items():
        scans.append({
            'scan_id': scan_id,
            'target': result['target']['url'],
            'scan_mode': result['scan_mode'],
            'findings_count': len(result['findings']),
            'risk_score': result['risk_score']['overall_score'],
            'completed_at': result.get('scan_completed_at'),
        })
    return jsonify({'scans': scans})


def _generate_shareable_id(scan_id: str, target: str) -> str:
    """Generate a unique shareable ID for scan results."""
    # Create a hash from scan_id + target + timestamp for uniqueness
    unique_string = f"{scan_id}_{target}_{datetime.now().isoformat()}"
    hash_obj = hashlib.sha256(unique_string.encode())
    # Use first 16 characters of hash for shorter URL
    return hash_obj.hexdigest()[:16]


def _save_shareable_result(shareable_id: str, result_dict: dict, target: str, scan_mode: str):
    """Save scan results to persistent storage with shareable ID."""
    try:
        result_file = RESULTS_DIR / f"{shareable_id}.json"
        
        # Add metadata
        result_data = {
            'shareable_id': shareable_id,
            'target': target,
            'scan_mode': scan_mode,
            'created_at': datetime.now().isoformat(),
            'expires_at': (datetime.now() + timedelta(days=RESULTS_EXPIRY_DAYS)).isoformat(),
            'results': result_dict,
        }
        
        with open(result_file, 'w') as f:
            json.dump(result_data, f, indent=2, default=str)
        
        logger.info(f"Saved shareable result to {result_file}")
    except Exception as e:
        logger.error(f"Failed to save shareable result: {e}")


def _load_shareable_result(shareable_id: str) -> Optional[dict]:
    """Load scan results from persistent storage."""
    try:
        result_file = RESULTS_DIR / f"{shareable_id}.json"
        
        if not result_file.exists():
            return None
        
        with open(result_file, 'r') as f:
            result_data = json.load(f)
        
        # Check if expired
        expires_at = datetime.fromisoformat(result_data.get('expires_at', ''))
        if datetime.now() > expires_at:
            logger.info(f"Shareable result {shareable_id} has expired")
            result_file.unlink()  # Delete expired result
            return None
        
        return result_data
    except Exception as e:
        logger.error(f"Failed to load shareable result: {e}")
        return None


@app.route('/results/<shareable_id>')
def view_shareable_results(shareable_id):
    """View shareable scan results."""
    # Validate shareable_id format (16 hex characters)
    if not re.match(r'^[a-f0-9]{16}$', shareable_id):
        abort(404)
    
    # Load results from persistent storage
    result_data = _load_shareable_result(shareable_id)
    
    if not result_data:
        # Return a simple error page
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Results Not Found - DarkOrca</title>
            <style>
                body {{ font-family: system-ui; background: #05060b; color: #f2f3f5; text-align: center; padding: 50px; }}
                h1 {{ color: #ff6b6b; }}
            </style>
        </head>
        <body>
            <h1>Results Not Found</h1>
            <p>The scan results you are looking for do not exist or have expired.</p>
            <p><a href="/" style="color: #ff6b6b;">Return to DarkOrca</a></p>
        </body>
        </html>
        """, 404
    
    # Render the same index page but with pre-loaded results
    return render_template('index.html', shareable_id=shareable_id)


@app.route('/api/results/<shareable_id>', methods=['GET'])
def get_shareable_results(shareable_id):
    """Get shareable scan results via API."""
    result_data = _load_shareable_result(shareable_id)
    
    if not result_data:
        return jsonify({'error': 'Results not found or expired'}), 404
    
    # Return the results in the same format as regular scan results
    return jsonify(result_data['results'])


@app.route('/api/scan/<scan_id>/download/pdf', methods=['GET'])
def download_scan_pdf(scan_id):
    """Download scan results as PDF."""
    if scan_id not in scan_results:
        return jsonify({'error': 'Results not found'}), 404
    
    try:
        from src.reports.pdf_reporter import PDFReporter
        from src.models.scan import ScanResult, ScanTarget
        from src.models.risk import RiskScore, RiskLevel
        from src.models.scan_mode import ScanMode
        
        if not PDFReporter.is_available():
            return jsonify({'error': 'PDF generation not available. Install reportlab: pip install reportlab'}), 500
        
        # Reconstruct ScanResult from dict
        result_dict = scan_results[scan_id]
        target = ScanTarget(url=result_dict['target']['url'])
        
        # Reconstruct findings - include ALL fields to ensure nothing is missing in PDF
        from src.models.finding import Finding, FindingSeverity, FindingCategory
        findings = []
        for f_dict in result_dict.get('findings', []):
            # Parse discovered_at if available
            discovered_at = None
            if f_dict.get('discovered_at'):
                try:
                    discovered_at = datetime.fromisoformat(f_dict['discovered_at'].replace('Z', '+00:00'))
                except:
                    pass
            
            finding = Finding(
                title=f_dict.get('title', ''),
                description=f_dict.get('description', ''),
                severity=FindingSeverity[f_dict.get('severity', 'INFO').upper()],
                category=FindingCategory[f_dict.get('category', 'OTHER').upper()],
                source_scanner=f_dict.get('source_scanner', ''),
                source_id=f_dict.get('source_id', ''),
                url=f_dict.get('url', ''),
                evidence=f_dict.get('evidence'),
                remediation=f_dict.get('remediation', ''),
                references=f_dict.get('references', []),
                cve=f_dict.get('cve'),
                metadata=f_dict.get('metadata', {}),
                discovered_at=discovered_at or datetime.utcnow(),
                exploited=f_dict.get('exploited', False),
                exploitation_details=f_dict.get('exploitation_details'),
            )
            findings.append(finding)
        
        # Reconstruct risk score
        risk_dict = result_dict.get('risk_score', {})
        risk_level_str = risk_dict.get('risk_level', 'LOW').upper()
        try:
            risk_level = RiskLevel[risk_level_str]
        except KeyError:
            risk_level = RiskLevel.LOW
        
        # Reconstruct full risk score with all counts
        risk_score = RiskScore(
            overall_score=risk_dict.get('overall_score', 0),
            risk_level=risk_level,
            summary=risk_dict.get('summary', ''),
            critical_count=risk_dict.get('critical_count', 0),
            high_count=risk_dict.get('high_count', 0),
            medium_count=risk_dict.get('medium_count', 0),
            low_count=risk_dict.get('low_count', 0),
            info_count=risk_dict.get('info_count', 0),
        )
        
        # Reconstruct ScanResult
        result = ScanResult(
            target=target,
            findings=findings,
            risk_score=risk_score,
            scanners_run=result_dict.get('scanners_run', []),
            scanner_errors=result_dict.get('scanner_errors', {}),
            scan_mode=ScanMode[result_dict.get('scan_mode', 'defensive').upper()],
        )
        
        # Set timestamps
        if result_dict.get('scan_started_at'):
            result.scan_started_at = datetime.fromisoformat(result_dict['scan_started_at'])
        if result_dict.get('scan_completed_at'):
            result.scan_completed_at = datetime.fromisoformat(result_dict['scan_completed_at'])
        
        # Generate PDF
        pdf_buffer = PDFReporter.generate(result)
        
        # Generate filename
        target_url = target.url.replace('https://', '').replace('http://', '').replace('/', '_')
        filename = f"darkorca_{target_url}_{scan_id}.pdf"
        
        return Response(
            pdf_buffer.read(),
            mimetype='application/pdf',
            headers={
                'Content-Disposition': f'attachment; filename="{filename}"',
                'Content-Type': 'application/pdf',
            }
        )
    except Exception as e:
        logger.error(f"Error generating PDF: {e}", exc_info=True)
        return jsonify({'error': f'Failed to generate PDF: {str(e)}'}), 500


@app.route('/api/results/<shareable_id>/download/pdf', methods=['GET'])
def download_shareable_pdf(shareable_id):
    """Download shareable scan results as PDF."""
    result_data = _load_shareable_result(shareable_id)
    
    if not result_data:
        return jsonify({'error': 'Results not found or expired'}), 404
    
    try:
        from src.reports.pdf_reporter import PDFReporter
        from src.models.scan import ScanResult, ScanTarget
        from src.models.risk import RiskScore, RiskLevel
        from src.models.scan_mode import ScanMode
        
        if not PDFReporter.is_available():
            return jsonify({'error': 'PDF generation not available. Install reportlab: pip install reportlab'}), 500
        
        # Reconstruct ScanResult from dict
        result_dict = result_data['results']
        target = ScanTarget(url=result_dict['target']['url'])
        
        # Reconstruct findings - include ALL fields to ensure nothing is missing in PDF
        from src.models.finding import Finding, FindingSeverity, FindingCategory
        findings = []
        for f_dict in result_dict.get('findings', []):
            # Parse discovered_at if available
            discovered_at = None
            if f_dict.get('discovered_at'):
                try:
                    discovered_at = datetime.fromisoformat(f_dict['discovered_at'].replace('Z', '+00:00'))
                except:
                    pass
            
            finding = Finding(
                title=f_dict.get('title', ''),
                description=f_dict.get('description', ''),
                severity=FindingSeverity[f_dict.get('severity', 'INFO').upper()],
                category=FindingCategory[f_dict.get('category', 'OTHER').upper()],
                source_scanner=f_dict.get('source_scanner', ''),
                source_id=f_dict.get('source_id', ''),
                url=f_dict.get('url', ''),
                evidence=f_dict.get('evidence'),
                remediation=f_dict.get('remediation', ''),
                references=f_dict.get('references', []),
                cve=f_dict.get('cve'),
                metadata=f_dict.get('metadata', {}),
                discovered_at=discovered_at or datetime.utcnow(),
                exploited=f_dict.get('exploited', False),
                exploitation_details=f_dict.get('exploitation_details'),
            )
            findings.append(finding)
        
        # Reconstruct risk score
        risk_dict = result_dict.get('risk_score', {})
        risk_level_str = risk_dict.get('risk_level', 'LOW').upper()
        try:
            risk_level = RiskLevel[risk_level_str]
        except KeyError:
            risk_level = RiskLevel.LOW
        
        # Reconstruct full risk score with all counts
        risk_score = RiskScore(
            overall_score=risk_dict.get('overall_score', 0),
            risk_level=risk_level,
            summary=risk_dict.get('summary', ''),
            critical_count=risk_dict.get('critical_count', 0),
            high_count=risk_dict.get('high_count', 0),
            medium_count=risk_dict.get('medium_count', 0),
            low_count=risk_dict.get('low_count', 0),
            info_count=risk_dict.get('info_count', 0),
        )
        
        # Reconstruct ScanResult
        result = ScanResult(
            target=target,
            findings=findings,
            risk_score=risk_score,
            scanners_run=result_dict.get('scanners_run', []),
            scanner_errors=result_dict.get('scanner_errors', {}),
            scan_mode=ScanMode[result_dict.get('scan_mode', 'defensive').upper()],
        )
        
        # Set timestamps
        if result_dict.get('scan_started_at'):
            result.scan_started_at = datetime.fromisoformat(result_dict['scan_started_at'])
        if result_dict.get('scan_completed_at'):
            result.scan_completed_at = datetime.fromisoformat(result_dict['scan_completed_at'])
        
        # Generate PDF
        pdf_buffer = PDFReporter.generate(result)
        
        # Generate filename
        target_url = target.url.replace('https://', '').replace('http://', '').replace('/', '_')
        filename = f"darkorca_{target_url}_{shareable_id}.pdf"
        
        return Response(
            pdf_buffer.read(),
            mimetype='application/pdf',
            headers={
                'Content-Disposition': f'attachment; filename="{filename}"',
                'Content-Type': 'application/pdf',
            }
        )
    except Exception as e:
        logger.error(f"Error generating PDF: {e}", exc_info=True)
        return jsonify({'error': f'Failed to generate PDF: {str(e)}'}), 500


# Initialize database on startup
init_database()
logger.info("Database initialized")

if __name__ == '__main__':
    # Initialize database
    init_database()
    
    # Validate configuration on startup
    is_valid, errors = ConfigValidator.validate_config()
    if not is_valid:
        logger.error("Configuration validation failed:")
        for error in errors:
            logger.error(f"  - {error}")
        logger.error("Please fix configuration errors before starting the application.")
        exit(1)
    
    # Validate Config class values
    config_valid, config_errors = Config.validate_config()
    if not config_valid:
        logger.error("Config class validation failed:")
        for error in config_errors:
            logger.error(f"  - {error}")
        logger.error("Please fix configuration errors before starting the application.")
        exit(1)
    
    # Log configuration summary
    ConfigValidator.log_config_summary()
    logger.info(f"Request timeout: {Config.DEFAULT_REQUEST_TIMEOUT}s (connect: {Config.DEFAULT_CONNECT_TIMEOUT}s, read: {Config.DEFAULT_READ_TIMEOUT}s)")
    logger.info(f"Max scan duration: {Config.MAX_SCAN_DURATION}s")
    
    port = int(os.getenv('PORT', 5001))
    print(f"\n{'='*60}")
    print(f"🚀 DarkOrca Web UI Starting...")
    print(f"{'='*60}")
    print(f"📍 Web interface: http://localhost:{port}")
    print(f"🌐 Network access: http://0.0.0.0:{port}")
    print(f"💚 Health check: http://localhost:{port}/health")
    print(f"{'='*60}\n")
    app.run(debug=True, host='0.0.0.0', port=port)

