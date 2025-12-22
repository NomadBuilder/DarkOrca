"""Database models and utilities for user accounts and saved scans."""

import sqlite3
import hashlib
import secrets
import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, List, Dict, Any
from contextlib import contextmanager

logger = logging.getLogger(__name__)

# Database file path
DB_PATH = Path('darkorca.db')


def get_db_path() -> Path:
    """Get the database file path."""
    return DB_PATH


@contextmanager
def get_db_connection():
    """Context manager for database connections."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row  # Return rows as dictionaries
    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        logger.error(f"Database error: {e}")
        raise
    finally:
        conn.close()


def init_database():
    """Initialize the database with required tables."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                settings TEXT DEFAULT '{}',
                failed_login_attempts INTEGER DEFAULT 0,
                locked_until TEXT
            )
        ''')
        
        # Add new columns if they don't exist (for existing databases)
        try:
            cursor.execute('ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER DEFAULT 0')
        except sqlite3.OperationalError:
            pass  # Column already exists
        
        try:
            cursor.execute('ALTER TABLE users ADD COLUMN locked_until TEXT')
        except sqlite3.OperationalError:
            pass  # Column already exists
        
        # Saved scans table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS saved_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                scan_id TEXT NOT NULL,
                shareable_id TEXT,
                target TEXT NOT NULL,
                scan_mode TEXT NOT NULL,
                target_url TEXT NOT NULL,
                created_at TEXT NOT NULL,
                saved_at TEXT NOT NULL,
                result_data TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                UNIQUE(user_id, scan_id)
            )
        ''')
        
        # Sessions table (for session management)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                session_token TEXT UNIQUE NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        ''')
        
        # Create indices for performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_user_sessions_token ON user_sessions(session_token)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions(user_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_saved_scans_user_id ON saved_scans(user_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_saved_scans_created_at ON saved_scans(created_at DESC)')
        
        logger.info("Database initialized successfully")


def hash_password(password: str) -> str:
    """
    Hash a password using bcrypt (secure, slow, adaptive).
    
    Note: For existing SHA-256 hashes, we support migration during login.
    New passwords are always hashed with bcrypt.
    """
    try:
        import bcrypt
        # Generate salt and hash password
        salt = bcrypt.gensalt(rounds=12)  # 12 rounds is secure and reasonable performance
        password_hash = bcrypt.hashpw(password.encode('utf-8'), salt)
        return password_hash.decode('utf-8')
    except ImportError:
        # Fallback to SHA-256 if bcrypt not available (should not happen in production)
        import logging
        logger = logging.getLogger(__name__)
        logger.warning("bcrypt not available, using SHA-256 (INSECURE - install bcrypt)")
        salt = secrets.token_hex(16)
        password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
        return f"sha256:{salt}:{password_hash}"  # Mark as SHA-256 for migration


def verify_password(password: str, password_hash: str) -> bool:
    """
    Verify a password against a hash.
    Supports both bcrypt (new) and SHA-256 (legacy) for migration.
    """
    try:
        import bcrypt
        # Try bcrypt first (most secure, current standard)
        try:
            return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
        except (ValueError, TypeError):
            # Not a bcrypt hash, try legacy SHA-256
            pass
    except ImportError:
        pass  # bcrypt not available, use SHA-256
    
    # Legacy SHA-256 support (for migration)
    try:
        if password_hash.startswith('sha256:'):
            # New format: sha256:salt:hash
            _, salt, stored_hash = password_hash.split(':', 2)
        else:
            # Old format: salt:hash
            salt, stored_hash = password_hash.split(':', 1)
        computed_hash = hashlib.sha256((password + salt).encode()).hexdigest()
        return computed_hash == stored_hash
    except (ValueError, AttributeError):
        return False


class User:
    """User model."""
    
    def __init__(self, id: int, username: str, email: str, created_at: str, updated_at: str, settings: str = '{}',
                 failed_login_attempts: int = 0, locked_until: Optional[str] = None):
        self.id = id
        self.username = username
        self.email = email
        self.created_at = created_at
        self.updated_at = updated_at
        self.settings = json.loads(settings) if isinstance(settings, str) else settings
        self.failed_login_attempts = failed_login_attempts
        self.locked_until = locked_until
    
    @staticmethod
    def check_account_locked(user_id: int) -> bool:
        """Check if account is locked due to failed login attempts."""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT locked_until FROM users WHERE id = ?', (user_id,))
            row = cursor.fetchone()
            if row and row['locked_until']:
                try:
                    locked_until = datetime.fromisoformat(row['locked_until'])
                    if datetime.now() < locked_until:
                        return True  # Still locked
                    else:
                        # Lock expired, clear it
                        cursor.execute('''
                            UPDATE users SET locked_until = NULL, failed_login_attempts = 0 WHERE id = ?
                        ''', (user_id,))
                        conn.commit()
                        return False
                except (ValueError, TypeError):
                    return False
            return False
    
    @staticmethod
    def increment_failed_login(user_id: int):
        """Increment failed login attempts and lock account if threshold reached."""
        MAX_FAILED_ATTEMPTS = 5
        LOCKOUT_DURATION_MINUTES = 15
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT failed_login_attempts FROM users WHERE id = ?', (user_id,))
            row = cursor.fetchone()
            if row and row['failed_login_attempts'] is not None:
                current_attempts = row['failed_login_attempts'] + 1
            else:
                current_attempts = 1
            
            if current_attempts >= MAX_FAILED_ATTEMPTS:
                # Lock account
                locked_until = (datetime.now() + timedelta(minutes=LOCKOUT_DURATION_MINUTES)).isoformat()
                cursor.execute('''
                    UPDATE users SET failed_login_attempts = ?, locked_until = ? WHERE id = ?
                ''', (current_attempts, locked_until, user_id))
                logger.warning(f"Account locked for user_id {user_id} due to {current_attempts} failed login attempts")
            else:
                cursor.execute('''
                    UPDATE users SET failed_login_attempts = ? WHERE id = ?
                ''', (current_attempts, user_id))
            conn.commit()
    
    @staticmethod
    def reset_failed_login(user_id: int):
        """Reset failed login attempts on successful login."""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?
            ''', (user_id,))
            conn.commit()
    
    @staticmethod
    def authenticate_and_upgrade(username: str, password: str) -> Optional['User']:
        """
        Authenticate user and upgrade password hash if using legacy SHA-256.
        Returns user if authentication succeeds, None otherwise.
        
        Security: Always performs password verification to prevent timing attacks
        that could reveal whether a username exists or not.
        """
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            row = cursor.fetchone()
            
            # Always perform password verification to prevent timing attacks
            # Use a dummy hash if user doesn't exist to maintain constant-time comparison
            if row:
                stored_hash = row['password_hash']
            else:
                # Use a dummy hash for non-existent users to maintain timing
                # This prevents attackers from determining if a username exists via timing
                dummy_password = secrets.token_urlsafe(32)  # Random dummy password
                try:
                    import bcrypt
                    stored_hash = bcrypt.hashpw(dummy_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                except ImportError:
                    # If bcrypt not available, use a dummy SHA-256 hash
                    dummy_salt = secrets.token_hex(16)
                    dummy_hash = hashlib.sha256((dummy_password + dummy_salt).encode()).hexdigest()
                    stored_hash = f"sha256:{dummy_salt}:{dummy_hash}"
            
            # Check if account is locked (only if user exists)
            if row:
                user_id = row['id']
                if User.check_account_locked(user_id):
                    logger.warning(f"Login attempt for locked account: {username}")
                    # Still increment to maintain timing, but don't reveal lock status
                    User.increment_failed_login(user_id)
                    return None
            
            # Always verify password (constant-time operation)
            if verify_password(password, stored_hash) and row:
                # Only proceed if password matches AND user exists
                user_id = row['id']
                
                # Reset failed login attempts on successful login
                User.reset_failed_login(user_id)
                
                # Handle optional fields (for backward compatibility with old databases)
                failed_login_attempts = 0
                locked_until = None
                try:
                    failed_login_attempts = row['failed_login_attempts'] or 0
                except (KeyError, IndexError):
                    pass
                try:
                    locked_until = row['locked_until']
                except (KeyError, IndexError):
                    pass
                
                user = User(
                    id=row['id'],
                    username=row['username'],
                    email=row['email'],
                    created_at=row['created_at'],
                    updated_at=row['updated_at'],
                    settings=row['settings'],
                    failed_login_attempts=failed_login_attempts,
                    locked_until=locked_until
                )
                # Upgrade to bcrypt if using legacy SHA-256
                if row['password_hash'].startswith('sha256:'):
                    try:
                        import bcrypt
                        new_hash = hash_password(password)
                        now = datetime.now().isoformat()
                        cursor.execute(
                            'UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?',
                            (new_hash, now, user.id)
                        )
                        conn.commit()
                        logger.info(f"Upgraded password hash for user {username} to bcrypt")
                    except ImportError:
                        pass  # bcrypt not available, keep SHA-256
                return user
            else:
                # Password verification failed - increment failed attempts if user exists
                if row:
                    User.increment_failed_login(row['id'])
        return None
    
    @staticmethod
    def create(username: str, email: str, password: str) -> 'User':
        """Create a new user."""
        now = datetime.now().isoformat()
        password_hash = hash_password(password)
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute('''
                    INSERT INTO users (username, email, password_hash, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?)
                ''', (username, email, password_hash, now, now))
                user_id = cursor.lastrowid
                conn.commit()  # Explicitly commit before fetching
                logger.info(f"Created user: {username} (ID: {user_id})")
                # Fetch the newly created user
                cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
                row = cursor.fetchone()
                if row:
                    # Handle optional fields (for backward compatibility with old databases)
                    failed_login_attempts = 0
                    locked_until = None
                    try:
                        failed_login_attempts = row['failed_login_attempts'] or 0
                    except (KeyError, IndexError):
                        pass
                    try:
                        locked_until = row['locked_until']
                    except (KeyError, IndexError):
                        pass
                    
                    return User(
                        id=row['id'],
                        username=row['username'],
                        email=row['email'],
                        created_at=row['created_at'],
                        updated_at=row['updated_at'],
                        settings=row['settings'],
                        failed_login_attempts=failed_login_attempts,
                        locked_until=locked_until
                    )
                # Fallback to get_by_id
                return User.get_by_id(user_id)
            except sqlite3.IntegrityError as e:
                if 'username' in str(e).lower():
                    raise ValueError("Username already exists")
                elif 'email' in str(e).lower():
                    raise ValueError("Email already exists")
                raise
    
    @staticmethod
    def get_by_id(user_id: int) -> Optional['User']:
        """Get user by ID."""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
            row = cursor.fetchone()
            if row:
                # Handle optional fields (for backward compatibility with old databases)
                failed_login_attempts = 0
                locked_until = None
                try:
                    failed_login_attempts = row['failed_login_attempts'] or 0
                except (KeyError, IndexError):
                    pass
                try:
                    locked_until = row['locked_until']
                except (KeyError, IndexError):
                    pass
                
                return User(
                    id=row['id'],
                    username=row['username'],
                    email=row['email'],
                    created_at=row['created_at'],
                    updated_at=row['updated_at'],
                    settings=row['settings'],
                    failed_login_attempts=failed_login_attempts,
                    locked_until=locked_until
                )
            return None
    
    @staticmethod
    def get_by_username(username: str) -> Optional['User']:
        """Get user by username."""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            row = cursor.fetchone()
            if row:
                # Handle optional fields (for backward compatibility with old databases)
                failed_login_attempts = 0
                locked_until = None
                try:
                    failed_login_attempts = row['failed_login_attempts'] or 0
                except (KeyError, IndexError):
                    pass
                try:
                    locked_until = row['locked_until']
                except (KeyError, IndexError):
                    pass
                
                return User(
                    id=row['id'],
                    username=row['username'],
                    email=row['email'],
                    created_at=row['created_at'],
                    updated_at=row['updated_at'],
                    settings=row['settings'],
                    failed_login_attempts=failed_login_attempts,
                    locked_until=locked_until
                )
            return None
    
    @staticmethod
    def authenticate(username: str, password: str) -> Optional['User']:
        """
        Authenticate a user with username and password.
        Automatically upgrades legacy SHA-256 hashes to bcrypt.
        """
        return User.authenticate_and_upgrade(username, password)
    
    def update_settings(self, settings: Dict[str, Any]):
        """Update user settings."""
        self.settings = {**self.settings, **settings}
        now = datetime.now().isoformat()
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE users SET settings = ?, updated_at = ? WHERE id = ?
            ''', (json.dumps(self.settings), now, self.id))
        logger.info(f"Updated settings for user {self.username}")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert user to dictionary."""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
            'settings': self.settings
        }


class SavedScan:
    """Saved scan model."""
    
    def __init__(self, id: int, user_id: int, scan_id: str, shareable_id: Optional[str],
                 target: str, scan_mode: str, target_url: str, created_at: str,
                 saved_at: str, result_data: str):
        self.id = id
        self.user_id = user_id
        self.scan_id = scan_id
        self.shareable_id = shareable_id
        self.target = target
        self.scan_mode = scan_mode
        self.target_url = target_url
        self.created_at = created_at
        self.saved_at = saved_at
        self.result_data = json.loads(result_data) if isinstance(result_data, str) else result_data
    
    @staticmethod
    def save(user_id: int, scan_id: str, shareable_id: Optional[str], target: str,
             scan_mode: str, target_url: str, result_data: Dict[str, Any]) -> 'SavedScan':
        """Save a scan result to user's profile."""
        now = datetime.now().isoformat()
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            # Use INSERT OR REPLACE to handle duplicates
            cursor.execute('''
                INSERT OR REPLACE INTO saved_scans 
                (user_id, scan_id, shareable_id, target, scan_mode, target_url, created_at, saved_at, result_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                user_id, scan_id, shareable_id, target, scan_mode, target_url,
                result_data.get('scan_started_at', now), now, json.dumps(result_data)
            ))
            saved_scan_id = cursor.lastrowid
            logger.info(f"Saved scan {scan_id} for user {user_id}")
            
            # Fetch the saved scan
            cursor.execute('SELECT * FROM saved_scans WHERE id = ?', (saved_scan_id,))
            row = cursor.fetchone()
            if row:
                return SavedScan(
                    id=row['id'],
                    user_id=row['user_id'],
                    scan_id=row['scan_id'],
                    shareable_id=row['shareable_id'],
                    target=row['target'],
                    scan_mode=row['scan_mode'],
                    target_url=row['target_url'],
                    created_at=row['created_at'],
                    saved_at=row['saved_at'],
                    result_data=row['result_data']
                )
            raise RuntimeError("Failed to retrieve saved scan")
    
    @staticmethod
    def get_user_scans(user_id: int, limit: int = 50, offset: int = 0) -> List['SavedScan']:
        """Get saved scans for a user."""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM saved_scans 
                WHERE user_id = ? 
                ORDER BY saved_at DESC 
                LIMIT ? OFFSET ?
            ''', (user_id, limit, offset))
            rows = cursor.fetchall()
            return [
                SavedScan(
                    id=row['id'],
                    user_id=row['user_id'],
                    scan_id=row['scan_id'],
                    shareable_id=row['shareable_id'],
                    target=row['target'],
                    scan_mode=row['scan_mode'],
                    target_url=row['target_url'],
                    created_at=row['created_at'],
                    saved_at=row['saved_at'],
                    result_data=row['result_data']
                )
                for row in rows
            ]
    
    @staticmethod
    def get_by_id(saved_scan_id: int, user_id: int) -> Optional['SavedScan']:
        """Get a saved scan by ID (ensure it belongs to user)."""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM saved_scans WHERE id = ? AND user_id = ?
            ''', (saved_scan_id, user_id))
            row = cursor.fetchone()
            if row:
                return SavedScan(
                    id=row['id'],
                    user_id=row['user_id'],
                    scan_id=row['scan_id'],
                    shareable_id=row['shareable_id'],
                    target=row['target'],
                    scan_mode=row['scan_mode'],
                    target_url=row['target_url'],
                    created_at=row['created_at'],
                    saved_at=row['saved_at'],
                    result_data=row['result_data']
                )
            return None
    
    @staticmethod
    def delete(saved_scan_id: int, user_id: int) -> bool:
        """Delete a saved scan."""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM saved_scans WHERE id = ? AND user_id = ?', (saved_scan_id, user_id))
            deleted = cursor.rowcount > 0
            if deleted:
                logger.info(f"Deleted saved scan {saved_scan_id} for user {user_id}")
            return deleted
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert saved scan to dictionary."""
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'shareable_id': self.shareable_id,
            'target': self.target,
            'scan_mode': self.scan_mode,
            'target_url': self.target_url,
            'created_at': self.created_at,
            'saved_at': self.saved_at,
            'result_data': self.result_data
        }


class UserSession:
    """User session model."""
    
    SESSION_DURATION_DAYS = 30  # Sessions last 30 days
    
    @staticmethod
    def create(user_id: int) -> str:
        """Create a new session and return session token."""
        session_token = secrets.token_urlsafe(32)
        now = datetime.now()
        expires_at = now + timedelta(days=UserSession.SESSION_DURATION_DAYS)
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO user_sessions (user_id, session_token, created_at, expires_at)
                VALUES (?, ?, ?, ?)
            ''', (user_id, session_token, now.isoformat(), expires_at.isoformat()))
            logger.info(f"Created session for user {user_id}")
            return session_token
    
    @staticmethod
    def get_user_from_token(session_token: str) -> Optional[User]:
        """Get user from session token."""
        now = datetime.now()
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT u.* FROM users u
                JOIN user_sessions s ON u.id = s.user_id
                WHERE s.session_token = ? AND s.expires_at > ?
            ''', (session_token, now.isoformat()))
            row = cursor.fetchone()
            if row:
                # Handle optional fields (for backward compatibility with old databases)
                failed_login_attempts = 0
                locked_until = None
                try:
                    failed_login_attempts = row['failed_login_attempts'] or 0
                except (KeyError, IndexError):
                    pass
                try:
                    locked_until = row['locked_until']
                except (KeyError, IndexError):
                    pass
                
                return User(
                    id=row['id'],
                    username=row['username'],
                    email=row['email'],
                    created_at=row['created_at'],
                    updated_at=row['updated_at'],
                    settings=row['settings'],
                    failed_login_attempts=failed_login_attempts,
                    locked_until=locked_until
                )
            return None
    
    @staticmethod
    def delete_token(session_token: str):
        """Delete a session token."""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM user_sessions WHERE session_token = ?', (session_token,))
            logger.info(f"Deleted session token")
    
    @staticmethod
    def cleanup_expired():
        """Clean up expired sessions."""
        now = datetime.now()
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM user_sessions WHERE expires_at <= ?', (now.isoformat(),))
            deleted = cursor.rowcount
            if deleted > 0:
                logger.info(f"Cleaned up {deleted} expired sessions")
