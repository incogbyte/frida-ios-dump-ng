"""Metadata extraction module.

Extracts and displays app metadata including Info.plist, entitlements,
and provisioning profile information.
"""

import plistlib
import subprocess
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from .log import get_logger

log = get_logger(__name__)


def extract_info_plist(ipa_path: str) -> Optional[Dict[str, Any]]:
    """Extract and parse Info.plist from an IPA file.
    
    Args:
        ipa_path: Path to the IPA file
        
    Returns:
        Parsed Info.plist as dictionary, or None if not found
    """
    try:
        with zipfile.ZipFile(ipa_path, 'r') as zf:
            for name in zf.namelist():
                if name.endswith('.app/Info.plist'):
                    with zf.open(name) as f:
                        return plistlib.load(f)
    except Exception as e:
        log.warning(f"Failed to extract Info.plist: {e}")
    return None


def extract_entitlements(ipa_path: str) -> Optional[Dict[str, Any]]:
    """Extract entitlements from the main executable in an IPA.
    
    Uses codesign to extract embedded entitlements.
    
    Args:
        ipa_path: Path to the IPA file
        
    Returns:
        Entitlements dictionary, or None if extraction fails
    """
    try:
        with zipfile.ZipFile(ipa_path, 'r') as zf:
            # Find the main executable
            app_name = None
            for name in zf.namelist():
                if name.endswith('.app/Info.plist'):
                    with zf.open(name) as f:
                        info = plistlib.load(f)
                        app_name = info.get('CFBundleExecutable')
                    app_dir = name.rsplit('/', 1)[0]
                    break
            
            if not app_name:
                log.warning("Could not find main executable name")
                return None
            
            executable_path = f"{app_dir}/{app_name}"
            
            with tempfile.TemporaryDirectory() as tmpdir:
                # Extract the executable
                zf.extract(executable_path, tmpdir)
                local_exe = Path(tmpdir) / executable_path
                
                # Use codesign to extract entitlements
                result = subprocess.run(
                    ['codesign', '-d', '--entitlements', ':-', str(local_exe)],
                    capture_output=True,
                    text=False,
                )
                
                if result.returncode == 0 and result.stdout:
                    # Parse the plist output
                    return plistlib.loads(result.stdout)
                    
    except Exception as e:
        log.debug(f"Failed to extract entitlements: {e}")
    
    return None


def extract_provisioning_profile(ipa_path: str) -> Optional[Dict[str, Any]]:
    """Extract provisioning profile from an IPA.
    
    Args:
        ipa_path: Path to the IPA file
        
    Returns:
        Provisioning profile dictionary, or None if not found
    """
    try:
        with zipfile.ZipFile(ipa_path, 'r') as zf:
            for name in zf.namelist():
                if name.endswith('.app/embedded.mobileprovision'):
                    with zf.open(name) as f:
                        data = f.read()
                        # mobileprovision is a signed plist, extract the plist part
                        start = data.find(b'<?xml')
                        end = data.find(b'</plist>') + 8
                        if start >= 0 and end > start:
                            plist_data = data[start:end]
                            return plistlib.loads(plist_data)
    except Exception as e:
        log.debug(f"Failed to extract provisioning profile: {e}")
    return None


def format_metadata(info: Optional[Dict], entitlements: Optional[Dict], profile: Optional[Dict]) -> str:
    """Format metadata as human-readable text.
    
    Args:
        info: Info.plist dictionary
        entitlements: Entitlements dictionary
        profile: Provisioning profile dictionary
        
    Returns:
        Formatted string
    """
    lines = []
    
    if info:
        lines.append("=" * 60)
        lines.append("APP INFO (Info.plist)")
        lines.append("=" * 60)
        
        fields = [
            ("Bundle ID", "CFBundleIdentifier"),
            ("Name", "CFBundleDisplayName"),
            ("Version", "CFBundleShortVersionString"),
            ("Build", "CFBundleVersion"),
            ("Min iOS", "MinimumOSVersion"),
            ("Executable", "CFBundleExecutable"),
        ]
        
        for label, key in fields:
            if key in info:
                lines.append(f"  {label}: {info[key]}")
        
        # URL Schemes
        url_types = info.get("CFBundleURLTypes", [])
        if url_types:
            schemes = []
            for ut in url_types:
                schemes.extend(ut.get("CFBundleURLSchemes", []))
            if schemes:
                lines.append(f"  URL Schemes: {', '.join(schemes)}")
        
        # Permissions
        permission_keys = [k for k in info.keys() if k.startswith("NS") and k.endswith("UsageDescription")]
        if permission_keys:
            lines.append("  Permissions:")
            for key in sorted(permission_keys):
                perm_name = key.replace("NS", "").replace("UsageDescription", "")
                lines.append(f"    - {perm_name}")
    
    if entitlements:
        lines.append("")
        lines.append("=" * 60)
        lines.append("ENTITLEMENTS")
        lines.append("=" * 60)
        
        for key, value in sorted(entitlements.items()):
            if isinstance(value, bool):
                value_str = "YES" if value else "NO"
            elif isinstance(value, list):
                value_str = ", ".join(str(v) for v in value[:3])
                if len(value) > 3:
                    value_str += f" (+{len(value) - 3} more)"
            else:
                value_str = str(value)
            
            # Shorten common prefixes
            short_key = key.replace("com.apple.developer.", "")
            short_key = short_key.replace("com.apple.security.", "")
            lines.append(f"  {short_key}: {value_str}")
    
    if profile:
        lines.append("")
        lines.append("=" * 60)
        lines.append("PROVISIONING PROFILE")
        lines.append("=" * 60)
        
        lines.append(f"  Name: {profile.get('Name', 'unknown')}")
        lines.append(f"  Team: {profile.get('TeamName', 'unknown')}")
        lines.append(f"  Expiration: {profile.get('ExpirationDate', 'unknown')}")
        
        # Profile type
        provisions_all = profile.get("ProvisionsAllDevices", False)
        if provisions_all:
            lines.append("  Type: Enterprise/In-House")
        elif profile.get("ProvisionedDevices"):
            device_count = len(profile.get("ProvisionedDevices", []))
            lines.append(f"  Type: Development ({device_count} devices)")
        else:
            lines.append("  Type: App Store")
    
    return "\n".join(lines)


def print_metadata(ipa_path: str) -> None:
    """Extract and print metadata from an IPA file.
    
    Args:
        ipa_path: Path to the IPA file
    """
    log.info(f"Extracting metadata from: {ipa_path}")
    
    info = extract_info_plist(ipa_path)
    entitlements = extract_entitlements(ipa_path)
    profile = extract_provisioning_profile(ipa_path)
    
    if not any([info, entitlements, profile]):
        log.warning("No metadata found in IPA")
        return
    
    print(format_metadata(info, entitlements, profile))
