"""Utility functions for frida-ipa-extract."""

import re
import sys
from typing import List, TypeVar

T = TypeVar('T')


def sanitize_filename(name: str, fallback: str = "app") -> str:
    """Sanitize a string for use as a filename.
    
    Replaces unsafe characters with underscores.
    
    Args:
        name: The string to sanitize
        fallback: Value to return if name is empty or all unsafe
        
    Returns:
        Safe filename string
    """
    if not name:
        return fallback
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", name.strip())
    return safe or fallback


def prompt_choice(options: List[T], prompt: str) -> T:
    """Prompt user to select from a numbered list.
    
    Args:
        options: List of options to choose from
        prompt: Prompt message to display
        
    Returns:
        The selected option
        
    Raises:
        RuntimeError: If stdin is not a TTY
    """
    if not sys.stdin.isatty():
        raise RuntimeError("Interactive selection requires a TTY.")
    
    while True:
        choice = input(prompt).strip()
        if choice.isdigit():
            idx = int(choice)
            if 1 <= idx <= len(options):
                return options[idx - 1]
        print("Invalid selection. Try again.")
