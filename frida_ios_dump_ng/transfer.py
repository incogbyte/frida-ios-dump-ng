"""Transfer module for downloading files via Frida RPC.

Provides parallel file transfer capabilities with configurable concurrency
and batch stat operations for improved performance.
"""

import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from threading import Lock
from typing import Callable, Dict, List, Optional, Tuple

from .log import get_logger

log = get_logger(__name__)


@dataclass
class TransferConfig:
    """Configuration for file transfer operations."""
    chunk_size: int = 256 * 1024
    max_workers: int = 4
    batch_stat_size: int = 50


@dataclass
class TransferStats:
    """Statistics for tracking transfer progress."""
    total_files: int = 0
    transferred_files: int = 0
    total_bytes: int = 0
    transferred_bytes: int = 0
    _lock: Lock = field(default_factory=Lock, repr=False)

    def add_transferred(self, file_count: int = 1, byte_count: int = 0) -> None:
        with self._lock:
            self.transferred_files += file_count
            self.transferred_bytes += byte_count


def enumerate_bundle_files(
    dumper,
    bundle_path: str,
    config: Optional[TransferConfig] = None,
) -> Tuple[List[str], List[str], Dict[str, int], int]:
    """Enumerate files in a bundle directory with their sizes.
    
    Uses batch stat operations when available for better performance.
    
    Args:
        dumper: FridaDumper instance with active session
        bundle_path: Remote path to the bundle directory
        config: Optional transfer configuration
        
    Returns:
        Tuple of (dirs, files, sizes_dict, total_bytes)
    """
    if config is None:
        config = TransferConfig()

    listing = dumper.list_files(bundle_path)
    dirs: List[str] = listing.get("dirs", [])
    files: List[str] = listing.get("files", [])
    sizes: Dict[str, int] = {}
    total = 0

    log.debug(f"Enumerating bundle: {len(files)} files, {len(dirs)} dirs")

    # Try batch stat if available
    if hasattr(dumper, 'stat_paths') and files:
        # Process in batches
        for i in range(0, len(files), config.batch_stat_size):
            batch = files[i:i + config.batch_stat_size]
            paths = [f"{bundle_path}/{rel}" for rel in batch]
            
            try:
                stats = dumper.stat_paths(paths)
                for rel in batch:
                    remote_path = f"{bundle_path}/{rel}"
                    stat = stats.get(remote_path, {})
                    if stat.get("exists") and not stat.get("isDir"):
                        size = int(stat.get("size", 0))
                        sizes[rel] = size
                        total += size
            except Exception as e:
                log.debug(f"Batch stat failed, falling back: {e}")
                # Fallback to individual stat
                for rel in batch:
                    remote_path = f"{bundle_path}/{rel}"
                    stat = dumper.stat_path(remote_path)
                    if stat.get("exists") and not stat.get("isDir"):
                        size = int(stat.get("size", 0))
                        sizes[rel] = size
                        total += size
    else:
        # Individual stat calls (original behavior)
        for rel in files:
            remote_path = f"{bundle_path}/{rel}"
            stat = dumper.stat_path(remote_path)
            if not stat.get("exists") or stat.get("isDir"):
                continue
            size = int(stat.get("size", 0))
            sizes[rel] = size
            total += size

    log.debug(f"Bundle enumeration complete: {len(sizes)} files, {total} bytes total")
    return dirs, files, sizes, total


def pull_bundle_via_frida(
    dumper,
    bundle_path: str,
    local_dir: str,
    config: Optional[TransferConfig] = None,
    *,
    files: Optional[List[str]] = None,
    dirs: Optional[List[str]] = None,
    sizes: Optional[Dict[str, int]] = None,
    progress: Optional[object] = None,
) -> None:
    """Download a bundle directory via Frida RPC.
    
    Uses parallel downloads when max_workers > 1 in config.
    
    Args:
        dumper: FridaDumper instance with active session
        bundle_path: Remote path to the bundle directory
        local_dir: Local destination directory
        config: Optional transfer configuration
        files: Pre-enumerated list of relative file paths
        dirs: Pre-enumerated list of relative directory paths
        sizes: Pre-computed size dictionary (rel_path -> size)
        progress: Optional progress bar instance
    """
    if config is None:
        config = TransferConfig()

    if files is None or dirs is None or sizes is None:
        dirs, files, sizes, _ = enumerate_bundle_files(dumper, bundle_path, config)

    # Create directories
    os.makedirs(local_dir, exist_ok=True)
    for rel in sorted(dirs, key=len):
        os.makedirs(os.path.join(local_dir, rel), exist_ok=True)

    # Filter files that have sizes (exist and are not directories)
    valid_files = [rel for rel in files if rel in sizes]
    log.debug(f"Downloading {len(valid_files)} files with {config.max_workers} workers")

    if config.max_workers > 1 and len(valid_files) > 1:
        # Parallel download
        _pull_files_parallel(
            dumper,
            bundle_path,
            local_dir,
            valid_files,
            sizes,
            config,
            progress,
        )
    else:
        # Sequential download
        for rel in valid_files:
            remote_path = f"{bundle_path}/{rel}"
            local_path = os.path.join(local_dir, rel)
            pull_file_via_frida(
                dumper,
                remote_path,
                local_path,
                chunk_size=config.chunk_size,
                size=sizes.get(rel),
                progress=progress,
            )


def _pull_files_parallel(
    dumper,
    bundle_path: str,
    local_dir: str,
    files: List[str],
    sizes: Dict[str, int],
    config: TransferConfig,
    progress: Optional[object],
) -> None:
    """Download multiple files in parallel using ThreadPoolExecutor."""
    
    def download_file(rel: str) -> Tuple[str, bool, Optional[Exception]]:
        remote_path = f"{bundle_path}/{rel}"
        local_path = os.path.join(local_dir, rel)
        try:
            pull_file_via_frida(
                dumper,
                remote_path,
                local_path,
                chunk_size=config.chunk_size,
                size=sizes.get(rel),
                progress=progress,
            )
            return rel, True, None
        except Exception as e:
            return rel, False, e

    with ThreadPoolExecutor(max_workers=config.max_workers) as executor:
        futures = {executor.submit(download_file, rel): rel for rel in files}
        
        for future in as_completed(futures):
            rel, success, error = future.result()
            if not success and error:
                log.warning(f"Failed to download {rel}: {error}")


def pull_file_via_frida(
    dumper,
    remote_path: str,
    local_path: str,
    chunk_size: int = 256 * 1024,
    *,
    size: Optional[int] = None,
    progress: Optional[object] = None,
) -> None:
    """Download a single file via Frida RPC.
    
    Args:
        dumper: FridaDumper instance with active session
        remote_path: Full remote path to the file
        local_path: Local destination path
        chunk_size: Size of each read chunk
        size: Optional pre-computed file size
        progress: Optional progress bar instance
    """
    if size is None:
        stat = dumper.stat_path(remote_path)
        if not stat.get("exists"):
            raise RuntimeError(f"Remote path not found: {remote_path}")
        if stat.get("isDir"):
            raise RuntimeError(f"Remote path is a directory: {remote_path}")
        size = int(stat.get("size", 0))

    local_dir = os.path.dirname(local_path)
    if local_dir:
        os.makedirs(local_dir, exist_ok=True)

    with open(local_path, "wb") as handle:
        offset = 0
        while offset < size:
            read_size = min(chunk_size, size - offset)
            chunk = dumper.read_file(remote_path, offset, read_size)
            if not chunk:
                break
            handle.write(chunk)
            offset += len(chunk)
            if progress is not None:
                progress.update(len(chunk))
