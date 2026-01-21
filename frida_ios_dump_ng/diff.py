"""IPA diff module.

Compares two IPA files and shows differences in structure,
metadata, and binary content.
"""

import hashlib
import os
import plistlib
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from .log import get_logger
from .metadata import extract_info_plist, extract_entitlements

log = get_logger(__name__)


@dataclass
class DiffResult:
    """Result of comparing two IPA files."""
    ipa1_path: str
    ipa2_path: str
    
    # Files
    added_files: List[str] = field(default_factory=list)
    removed_files: List[str] = field(default_factory=list)
    modified_files: List[str] = field(default_factory=list)
    unchanged_files: int = 0
    
    # Sizes
    ipa1_size: int = 0
    ipa2_size: int = 0
    
    # Metadata changes
    version_change: Optional[Tuple[str, str]] = None
    build_change: Optional[Tuple[str, str]] = None
    min_ios_change: Optional[Tuple[str, str]] = None
    
    # Entitlements
    added_entitlements: List[str] = field(default_factory=list)
    removed_entitlements: List[str] = field(default_factory=list)
    
    # Permissions
    added_permissions: List[str] = field(default_factory=list)
    removed_permissions: List[str] = field(default_factory=list)


def hash_file(zf: zipfile.ZipFile, name: str) -> str:
    """Calculate MD5 hash of a file inside a zip."""
    with zf.open(name) as f:
        return hashlib.md5(f.read()).hexdigest()


def list_ipa_files(ipa_path: str) -> Dict[str, int]:
    """List all files in an IPA with their sizes.
    
    Returns:
        Dictionary mapping file path to size
    """
    files = {}
    with zipfile.ZipFile(ipa_path, 'r') as zf:
        for info in zf.infolist():
            if not info.is_dir():
                # Normalize path (remove Payload prefix)
                path = info.filename
                if path.startswith("Payload/"):
                    path = path[8:]  # Remove "Payload/"
                files[path] = info.file_size
    return files


def compare_ipas(ipa1_path: str, ipa2_path: str) -> DiffResult:
    """Compare two IPA files.
    
    Args:
        ipa1_path: Path to first (older) IPA
        ipa2_path: Path to second (newer) IPA
        
    Returns:
        DiffResult with comparison details
    """
    result = DiffResult(ipa1_path=ipa1_path, ipa2_path=ipa2_path)
    
    # File sizes
    result.ipa1_size = os.path.getsize(ipa1_path)
    result.ipa2_size = os.path.getsize(ipa2_path)
    
    # List files
    files1 = list_ipa_files(ipa1_path)
    files2 = list_ipa_files(ipa2_path)
    
    set1 = set(files1.keys())
    set2 = set(files2.keys())
    
    result.added_files = sorted(set2 - set1)
    result.removed_files = sorted(set1 - set2)
    
    # Check modified files
    common_files = set1 & set2
    log.debug(f"Checking {len(common_files)} common files for modifications...")
    
    with zipfile.ZipFile(ipa1_path, 'r') as zf1, zipfile.ZipFile(ipa2_path, 'r') as zf2:
        for path in common_files:
            # First check size
            if files1[path] != files2[path]:
                result.modified_files.append(path)
            else:
                # Same size, check hash for important files
                if any(path.endswith(ext) for ext in ['.plist', '.entitlements', '.strings', '']):
                    # Only hash-check executables and plists
                    name1 = f"Payload/{path}"
                    name2 = f"Payload/{path}"
                    try:
                        if hash_file(zf1, name1) != hash_file(zf2, name2):
                            result.modified_files.append(path)
                        else:
                            result.unchanged_files += 1
                    except:
                        result.unchanged_files += 1
                else:
                    result.unchanged_files += 1
    
    result.modified_files.sort()
    
    # Compare metadata
    info1 = extract_info_plist(ipa1_path)
    info2 = extract_info_plist(ipa2_path)
    
    if info1 and info2:
        v1 = info1.get("CFBundleShortVersionString", "")
        v2 = info2.get("CFBundleShortVersionString", "")
        if v1 != v2:
            result.version_change = (v1, v2)
        
        b1 = info1.get("CFBundleVersion", "")
        b2 = info2.get("CFBundleVersion", "")
        if b1 != b2:
            result.build_change = (b1, b2)
        
        ios1 = info1.get("MinimumOSVersion", "")
        ios2 = info2.get("MinimumOSVersion", "")
        if ios1 != ios2:
            result.min_ios_change = (ios1, ios2)
        
        # Compare permissions
        perms1 = {k for k in info1.keys() if k.startswith("NS") and k.endswith("UsageDescription")}
        perms2 = {k for k in info2.keys() if k.startswith("NS") and k.endswith("UsageDescription")}
        result.added_permissions = sorted(perms2 - perms1)
        result.removed_permissions = sorted(perms1 - perms2)
    
    # Compare entitlements
    ent1 = extract_entitlements(ipa1_path) or {}
    ent2 = extract_entitlements(ipa2_path) or {}
    
    ent1_keys = set(ent1.keys())
    ent2_keys = set(ent2.keys())
    result.added_entitlements = sorted(ent2_keys - ent1_keys)
    result.removed_entitlements = sorted(ent1_keys - ent2_keys)
    
    return result


def format_size(size: int) -> str:
    """Format byte size as human-readable."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f"{size:.1f}{unit}" if unit != 'B' else f"{size}{unit}"
        size /= 1024
    return f"{size:.1f}TB"


def format_diff(result: DiffResult) -> str:
    """Format diff result as human-readable text.
    
    Args:
        result: DiffResult from compare_ipas
        
    Returns:
        Formatted diff string
    """
    lines = []
    
    # Header
    lines.append("=" * 70)
    lines.append("IPA DIFF REPORT")
    lines.append("=" * 70)
    lines.append(f"  Old: {os.path.basename(result.ipa1_path)} ({format_size(result.ipa1_size)})")
    lines.append(f"  New: {os.path.basename(result.ipa2_path)} ({format_size(result.ipa2_size)})")
    
    size_diff = result.ipa2_size - result.ipa1_size
    if size_diff > 0:
        lines.append(f"  Size change: +{format_size(size_diff)}")
    elif size_diff < 0:
        lines.append(f"  Size change: -{format_size(-size_diff)}")
    
    # Version changes
    if result.version_change or result.build_change or result.min_ios_change:
        lines.append("")
        lines.append("-" * 70)
        lines.append("VERSION CHANGES")
        lines.append("-" * 70)
        
        if result.version_change:
            lines.append(f"  Version: {result.version_change[0]} → {result.version_change[1]}")
        if result.build_change:
            lines.append(f"  Build: {result.build_change[0]} → {result.build_change[1]}")
        if result.min_ios_change:
            lines.append(f"  Min iOS: {result.min_ios_change[0]} → {result.min_ios_change[1]}")
    
    # Permission changes
    if result.added_permissions or result.removed_permissions:
        lines.append("")
        lines.append("-" * 70)
        lines.append("PERMISSION CHANGES")
        lines.append("-" * 70)
        
        for perm in result.added_permissions:
            short = perm.replace("NS", "").replace("UsageDescription", "")
            lines.append(f"  + {short}")
        for perm in result.removed_permissions:
            short = perm.replace("NS", "").replace("UsageDescription", "")
            lines.append(f"  - {short}")
    
    # Entitlement changes
    if result.added_entitlements or result.removed_entitlements:
        lines.append("")
        lines.append("-" * 70)
        lines.append("ENTITLEMENT CHANGES")
        lines.append("-" * 70)
        
        for ent in result.added_entitlements:
            short = ent.replace("com.apple.developer.", "").replace("com.apple.security.", "")
            lines.append(f"  + {short}")
        for ent in result.removed_entitlements:
            short = ent.replace("com.apple.developer.", "").replace("com.apple.security.", "")
            lines.append(f"  - {short}")
    
    # File changes summary
    lines.append("")
    lines.append("-" * 70)
    lines.append("FILE CHANGES")
    lines.append("-" * 70)
    lines.append(f"  Added: {len(result.added_files)} files")
    lines.append(f"  Removed: {len(result.removed_files)} files")
    lines.append(f"  Modified: {len(result.modified_files)} files")
    lines.append(f"  Unchanged: {result.unchanged_files} files")
    
    # Show some added files
    if result.added_files:
        lines.append("")
        lines.append("  Added files:")
        for f in result.added_files[:10]:
            lines.append(f"    + {f}")
        if len(result.added_files) > 10:
            lines.append(f"    ... and {len(result.added_files) - 10} more")
    
    # Show some removed files
    if result.removed_files:
        lines.append("")
        lines.append("  Removed files:")
        for f in result.removed_files[:10]:
            lines.append(f"    - {f}")
        if len(result.removed_files) > 10:
            lines.append(f"    ... and {len(result.removed_files) - 10} more")
    
    # Show some modified files
    if result.modified_files:
        lines.append("")
        lines.append("  Modified files:")
        for f in result.modified_files[:10]:
            lines.append(f"    ~ {f}")
        if len(result.modified_files) > 10:
            lines.append(f"    ... and {len(result.modified_files) - 10} more")
    
    lines.append("")
    lines.append("=" * 70)
    
    return "\n".join(lines)


def print_diff(ipa1_path: str, ipa2_path: str) -> None:
    """Compare two IPAs and print the diff.
    
    Args:
        ipa1_path: Path to first (older) IPA
        ipa2_path: Path to second (newer) IPA
    """
    log.info(f"Comparing IPAs...")
    log.debug(f"  IPA 1: {ipa1_path}")
    log.debug(f"  IPA 2: {ipa2_path}")
    
    if not os.path.exists(ipa1_path):
        raise SystemExit(f"File not found: {ipa1_path}")
    if not os.path.exists(ipa2_path):
        raise SystemExit(f"File not found: {ipa2_path}")
    
    result = compare_ipas(ipa1_path, ipa2_path)
    print(format_diff(result))
