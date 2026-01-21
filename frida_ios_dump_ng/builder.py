"""IPA builder module.

Creates IPA archives from app bundle directories with optimized compression.
"""

import os
import zipfile
from typing import Set

# Extensions that are already compressed or don't benefit from compression
UNCOMPRESSED_EXTENSIONS: Set[str] = {
    '.png', '.jpg', '.jpeg', '.gif', '.webp',  # Images
    '.m4a', '.mp3', '.aac', '.wav',            # Audio
    '.mp4', '.m4v', '.mov',                    # Video
    '.zip', '.gz', '.bz2', '.xz',              # Archives
    '.car',                                     # Asset catalogs (compiled)
}


def get_compression(filename: str) -> int:
    """Determine compression method based on file extension.
    
    Pre-compressed files are stored without additional compression
    to avoid wasting CPU and potentially increasing file size.
    """
    ext = os.path.splitext(filename)[1].lower()
    if ext in UNCOMPRESSED_EXTENSIONS:
        return zipfile.ZIP_STORED
    return zipfile.ZIP_DEFLATED


def build_ipa(
    bundle_dir: str,
    output_path: str,
    compression_level: int = 6,
) -> None:
    """Build an IPA archive from a bundle directory.
    
    Args:
        bundle_dir: Path to the .app bundle directory
        output_path: Path for the output .ipa file
        compression_level: Deflate compression level (0-9, default 6)
    """
    app_dir_name = os.path.basename(bundle_dir)
    
    with zipfile.ZipFile(
        output_path,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=compression_level,
    ) as zipf:
        for root, _, files in os.walk(bundle_dir):
            for name in files:
                full_path = os.path.join(root, name)
                rel_path = os.path.relpath(full_path, bundle_dir)
                arcname = os.path.join("Payload", app_dir_name, rel_path)
                
                # Use smart compression based on file type
                compression = get_compression(name)
                zipf.write(full_path, arcname, compress_type=compression)
