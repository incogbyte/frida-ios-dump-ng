"""Logging configuration for frida-ios-dump-ng.

Provides structured logging with configurable levels and formatters.
"""

import logging
import sys
from typing import Optional

# Package logger
logger = logging.getLogger("frida_ios_dump_ng")

# Log format constants
VERBOSE_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
NORMAL_FORMAT = "%(message)s"
DEBUG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s (%(filename)s:%(lineno)d): %(message)s"


class ColorFormatter(logging.Formatter):
    """Formatter that adds colors to log levels for terminal output."""
    
    COLORS = {
        logging.DEBUG: "\033[36m",     # Cyan
        logging.INFO: "\033[32m",      # Green
        logging.WARNING: "\033[33m",   # Yellow
        logging.ERROR: "\033[31m",     # Red
        logging.CRITICAL: "\033[1;31m", # Bold Red
    }
    RESET = "\033[0m"
    
    def __init__(self, fmt: str, use_colors: bool = True):
        super().__init__(fmt, datefmt="%H:%M:%S")
        self.use_colors = use_colors and sys.stdout.isatty()
    
    def format(self, record: logging.LogRecord) -> str:
        message = super().format(record)
        if self.use_colors and record.levelno in self.COLORS:
            color = self.COLORS[record.levelno]
            # Only colorize the level name part for verbose format
            if "[" in message:
                return message.replace(
                    f"[{record.levelname}]",
                    f"{color}[{record.levelname}]{self.RESET}"
                )
        return message


def setup_logging(
    verbosity: int = 0,
    quiet: bool = False,
    log_file: Optional[str] = None,
) -> None:
    """Configure logging for the application.
    
    Args:
        verbosity: Verbosity level (0=normal, 1=verbose, 2+=debug)
        quiet: If True, suppress all output except errors
        log_file: Optional path to write logs to file
    """
    # Determine log level
    if quiet:
        level = logging.ERROR
    elif verbosity >= 2:
        level = logging.DEBUG
    elif verbosity == 1:
        level = logging.INFO
    else:
        level = logging.INFO
    
    # Determine format
    if verbosity >= 2:
        fmt = DEBUG_FORMAT
    elif verbosity >= 1:
        fmt = VERBOSE_FORMAT
    else:
        fmt = NORMAL_FORMAT
    
    # Configure root logger for package
    logger.setLevel(logging.DEBUG)  # Capture all, filter at handler level
    logger.handlers.clear()
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(ColorFormatter(fmt))
    logger.addHandler(console_handler)
    
    # File handler if specified
    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter(DEBUG_FORMAT))
        logger.addHandler(file_handler)
    
    # Suppress noisy third-party loggers
    logging.getLogger("paramiko").setLevel(logging.WARNING)
    logging.getLogger("frida").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Get a child logger for a module.
    
    Args:
        name: Module name (typically __name__)
        
    Returns:
        Logger instance for the module
    """
    if name.startswith("frida_ios_dump_ng."):
        return logging.getLogger(name)
    return logging.getLogger(f"frida_ios_dump_ng.{name}")
