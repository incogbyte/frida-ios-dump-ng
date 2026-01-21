"""Progress bar module for file transfer operations.

Provides thread-safe progress tracking with ETA calculation.
"""

import sys
import threading
import time
from typing import Optional


def format_bytes(value: int) -> str:
    """Format byte count as human-readable string."""
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(value)
    for unit in units:
        if size < 1024.0 or unit == units[-1]:
            if unit == "B":
                return f"{int(size)}{unit}"
            return f"{size:.1f}{unit}"
        size /= 1024.0
    return f"{size:.1f}TB"


def format_time(seconds: float) -> str:
    """Format seconds as human-readable time string."""
    if seconds < 60:
        return f"{int(seconds)}s"
    elif seconds < 3600:
        mins = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{mins}m{secs:02d}s"
    else:
        hours = int(seconds // 3600)
        mins = int((seconds % 3600) // 60)
        return f"{hours}h{mins:02d}m"


class ProgressBar:
    """Thread-safe progress bar with ETA calculation."""
    
    def __init__(self, total: Optional[int], label: str = ""):
        self.total = total
        self.label = label
        self.current = 0
        self._last_render = 0.0
        self._last_len = 0
        self._enabled = sys.stdout.isatty()
        self._start_time = time.time()
        self._lock = threading.Lock()

    def set_total(self, total: int) -> None:
        """Update the total byte count."""
        with self._lock:
            self.total = total

    def update(self, delta: int) -> None:
        """Add delta bytes to current progress."""
        if delta <= 0:
            return
        with self._lock:
            self.current += delta
            self._render_unlocked()

    def _render_unlocked(self, force: bool = False) -> None:
        """Render progress bar (must hold lock)."""
        if not self._enabled:
            return

        now = time.time()
        if not force and (now - self._last_render) < 0.1:
            return
        self._last_render = now

        if self.total:
            ratio = min(self.current / self.total, 1.0)
            width = 30
            filled = int(width * ratio)
            bar = "=" * filled + " " * (width - filled)
            percent = ratio * 100.0
            
            # Calculate ETA
            elapsed = now - self._start_time
            eta_str = ""
            if ratio > 0.01 and ratio < 1.0:
                total_time = elapsed / ratio
                remaining = total_time - elapsed
                eta_str = f" ETA {format_time(remaining)}"
            
            line = (
                f"{self.label} [{bar}] {percent:5.1f}% "
                f"{format_bytes(self.current)}/{format_bytes(self.total)}{eta_str}"
            )
        else:
            line = f"{self.label} {format_bytes(self.current)}"

        padding = " " * max(0, self._last_len - len(line))
        sys.stdout.write("\r" + line + padding)
        sys.stdout.flush()
        self._last_len = len(line)

    def render(self, force: bool = False) -> None:
        """Render the progress bar to stdout."""
        with self._lock:
            self._render_unlocked(force)

    def finish(self) -> None:
        """Complete the progress bar and print newline."""
        if not self._enabled:
            return
        with self._lock:
            self._render_unlocked(force=True)
        sys.stdout.write("\n")
        sys.stdout.flush()
