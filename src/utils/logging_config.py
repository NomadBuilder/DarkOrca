"""Structured logging configuration for DarkOrca."""

import os
import logging
import json
import sys
from datetime import datetime, timezone
from typing import Optional


class JSONFormatter(logging.Formatter):
    """JSON formatter for structured logging."""
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_data = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
        }
        
        # Add exception info if present
        if record.exc_info:
            log_data['exception'] = self.formatException(record.exc_info)
        
        # Add extra fields if present
        if hasattr(record, 'extra'):
            log_data.update(record.extra)
        
        return json.dumps(log_data)


class HumanFormatter(logging.Formatter):
    """Human-readable formatter with colors."""
    
    # ANSI color codes
    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[35m',   # Magenta
        'RESET': '\033[0m',       # Reset
    }
    
    def __init__(self, include_location: bool = False):
        """Initialize human formatter."""
        if include_location:
            fmt = '%(asctime)s - %(name)s - %(levelname)s - %(module)s:%(lineno)d - %(message)s'
        else:
            fmt = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        super().__init__(fmt=fmt, datefmt='%Y-%m-%d %H:%M:%S')
        self.include_location = include_location
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record with colors."""
        # Add color to levelname
        levelname = record.levelname
        color = self.COLORS.get(levelname, '')
        reset = self.COLORS['RESET']
        
        # Temporarily modify levelname for formatting
        original_levelname = record.levelname
        record.levelname = f"{color}{levelname}{reset}"
        
        try:
            formatted = super().format(record)
        finally:
            # Restore original levelname
            record.levelname = original_levelname
        
        return formatted


def setup_logging(
    level: str = 'INFO',
    format_type: str = 'human',
    include_location: bool = False,
    log_file: Optional[str] = None
) -> None:
    """
    Setup logging configuration.
    
    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        format_type: 'human' or 'json'
        include_location: Whether to include module:line in human format
        log_file: Optional path to log file (if None, logs to stderr)
    """
    # Convert level string to logging level
    log_level = getattr(logging, level.upper(), logging.INFO)
    
    # Determine formatter
    if format_type.lower() == 'json':
        formatter = JSONFormatter()
    else:
        formatter = HumanFormatter(include_location=include_location)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    # Remove existing handlers
    root_logger.handlers.clear()
    
    # Create handler
    if log_file:
        # File handler
        from logging.handlers import RotatingFileHandler
        handler = RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5
        )
    else:
        # Stream handler (stdout/stderr)
        handler = logging.StreamHandler(sys.stderr)
    
    handler.setLevel(log_level)
    handler.setFormatter(formatter)
    
    # Add handler to root logger
    root_logger.addHandler(handler)
    
    # Suppress noisy loggers
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('requests').setLevel(logging.WARNING)
    logging.getLogger('werkzeug').setLevel(logging.WARNING)  # Flask's WSGI server
    
    # Log the configuration (after handler is set up)
    logger = logging.getLogger(__name__)
    logger.info(f"Logging configured: level={level}, format={format_type}, file={log_file or 'stderr'}")
