"""
Project Ingestion & Safe ZIP Extraction Module for SupplyGuard AI.
Handles local directory discovery and secure ZIP unpacking with strict resource limits.
Uses only Python standard library.
"""

import io
import os
import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import Union, BinaryIO, Optional, List, Set

from core.models import ProjectContext

# Safety and Resource Limits
MAX_ZIP_SIZE = 50 * 1024 * 1024          # 50 MB
MAX_FILE_SIZE = 5 * 1024 * 1024         # 5 MB
MAX_TOTAL_EXTRACTED_SIZE = 200 * 1024 * 1024  # 200 MB
MAX_EXTRACTED_FILES = 10_000

# Directories ignored during traversal (path-component match)
IGNORED_DIRS: Set[str] = {
    ".git",
    "node_modules",
    "dist",
    "build",
    "__pycache__",
    ".venv",
    "venv",
    ".idea",
    ".vscode",
}

# Relevant files and extensions for Node.js supply-chain analysis
RELEVANT_FILENAMES: Set[str] = {
    "package.json",
    "package-lock.json",
    ".env",
    ".env.example",
    ".env.local",
    ".env.production",
    ".env.development",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
}

RELEVANT_EXTENSIONS: Set[str] = {
    ".js",
    ".ts",
    ".mjs",
    ".cjs",
    ".json",
    ".yaml",
    ".yml",
    ".pem",
    ".key",
    ".env",
}

# Common binary file extensions to skip from text analysis
KNOWN_BINARY_EXTENSIONS: Set[str] = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf",
    ".zip", ".tar", ".gz", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".node", ".bin",
    ".woff", ".woff2", ".ttf", ".eot",
    ".mp3", ".mp4", ".wav", ".avi",
    ".pyc", ".class", ".o", ".obj",
}


class IngestionError(Exception):
    """Base error for project ingestion failures."""
    pass


class ZipSecurityError(IngestionError):
    """Raised when an uploaded ZIP exhibits unsafe behavior (e.g., path traversal)."""
    pass


class ResourceLimitError(IngestionError):
    """Raised when file or extraction size limits are exceeded."""
    pass


def is_binary_file(file_path: Path) -> bool:
    """
    Detects whether a file is binary using extension heuristic and null-byte sniffing.
    Reads at most 1024 bytes without loading the whole file into memory.
    """
    suffix = file_path.suffix.lower()
    if suffix in KNOWN_BINARY_EXTENSIONS:
        return True

    try:
        with open(file_path, "rb") as f:
            chunk = f.read(1024)
            if b"\x00" in chunk:
                return True
    except (OSError, PermissionError):
        return True

    return False


def is_ignored_path(relative_path: Path) -> bool:
    """Checks if any component in the path matches an ignored directory."""
    return any(part in IGNORED_DIRS for part in relative_path.parts)


def is_relevant_file(relative_path: Path, full_path: Path) -> bool:
    """
    Determines if a file is relevant for supply-chain analysis.
    Matches specific filenames (package.json, .env) or code extensions (.js, .ts, etc.),
    while ensuring the file is not binary.
    """
    filename_lower = relative_path.name.lower()
    suffix_lower = relative_path.suffix.lower()

    matches_name = (
        filename_lower in {f.lower() for f in RELEVANT_FILENAMES}
        or filename_lower.startswith(".env")
    )
    matches_ext = suffix_lower in RELEVANT_EXTENSIONS

    if not (matches_name or matches_ext):
        return False

    return not is_binary_file(full_path)


def discover_directory(root_dir: Path, project_name: Optional[str] = None) -> ProjectContext:
    """
    Recursively discovers files in a directory while pruning ignored directories
    and filtering relevant files.
    """
    root_path = root_dir.resolve()
    if not root_path.exists() or not root_path.is_dir():
        raise IngestionError(f"Target path does not exist or is not a directory: {root_dir}")

    all_files: List[Path] = []
    relevant_files: List[Path] = []
    detected_ecosystems: List[str] = []

    for root, dirs, files in os.walk(root_path):
        # Prune ignored directories in-place to avoid unnecessary traversal
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]

        current_dir = Path(root)
        for fname in files:
            full_path = current_dir / fname
            try:
                rel_path = full_path.relative_to(root_path)
            except ValueError:
                continue

            if is_ignored_path(rel_path):
                continue

            all_files.append(rel_path)

            if is_relevant_file(rel_path, full_path):
                relevant_files.append(rel_path)
                if rel_path.name.lower() == "package.json":
                    if "Node.js" not in detected_ecosystems:
                        detected_ecosystems.append("Node.js")

    proj_name = project_name or root_path.name

    return ProjectContext(
        project_name=proj_name,
        root_path=root_path,
        detected_ecosystems=detected_ecosystems,
        all_discovered_files=all_files,
        relevant_files=relevant_files,
        total_file_count=len(all_files),
        relevant_file_count=len(relevant_files),
        temp_dir_obj=None,
    )


def extract_zip_safely(
    zip_source: Union[str, Path, BinaryIO, io.BytesIO],
    destination_dir: Path,
) -> None:
    """
    Safely unpacks a ZIP archive into destination_dir with strict path traversal
    and resource limit validations.
    """
    dest_resolved = destination_dir.resolve()

    # If zip_source is a file path, check its size on disk
    if isinstance(zip_source, (str, Path)):
        p = Path(zip_source)
        if not p.exists():
            raise IngestionError(f"ZIP file not found: {zip_source}")
        if p.stat().st_size > MAX_ZIP_SIZE:
            raise ResourceLimitError(
                f"ZIP file size ({p.stat().st_size} bytes) exceeds maximum limit of {MAX_ZIP_SIZE} bytes"
            )

    try:
        zf = zipfile.ZipFile(zip_source, mode="r")
    except (zipfile.BadZipFile, zipfile.LargeZipFile) as e:
        raise IngestionError(f"Invalid or corrupted ZIP archive: {e}")

    with zf:
        infolist = zf.infolist()

        if len(infolist) > MAX_EXTRACTED_FILES:
            raise ResourceLimitError(
                f"ZIP contains {len(infolist)} entries, exceeding maximum limit of {MAX_EXTRACTED_FILES}"
            )

        total_extracted_size = 0

        # Validate all members before extracting any files
        for member in infolist:
            filename = member.filename

            # 1. Reject absolute paths or Windows drive letters
            if filename.startswith(("/", "\\")) or (len(filename) > 1 and filename[1] == ":"):
                raise ZipSecurityError(
                    f"ZIP member contains dangerous absolute path or drive letter: '{filename}'"
                )

            # 2. Check path traversal relative to extraction root
            target_path = (dest_resolved / filename).resolve()
            try:
                if not target_path.is_relative_to(dest_resolved):
                    raise ZipSecurityError(
                        f"ZIP member attempts path traversal outside destination: '{filename}'"
                    )
            except AttributeError:
                # Python < 3.9 fallback if needed (though we run 3.14)
                if not str(target_path).startswith(str(dest_resolved)):
                    raise ZipSecurityError(
                        f"ZIP member attempts path traversal outside destination: '{filename}'"
                    )

            if target_path == dest_resolved and not member.is_dir():
                raise ZipSecurityError(f"ZIP member points to extraction root directory: '{filename}'")

            # 3. Check individual file size limit
            if member.file_size > MAX_FILE_SIZE:
                raise ResourceLimitError(
                    f"File '{filename}' uncompressed size ({member.file_size} bytes) exceeds limit of {MAX_FILE_SIZE} bytes"
                )

            total_extracted_size += member.file_size
            if total_extracted_size > MAX_TOTAL_EXTRACTED_SIZE:
                raise ResourceLimitError(
                    f"Total uncompressed archive size exceeds limit of {MAX_TOTAL_EXTRACTED_SIZE} bytes"
                )

        # Extraction phase (safe chunked writing)
        for member in infolist:
            target_path = (dest_resolved / member.filename).resolve()

            if member.is_dir():
                target_path.mkdir(parents=True, exist_ok=True)
                continue

            target_path.parent.mkdir(parents=True, exist_ok=True)

            extracted_bytes = 0
            with zf.open(member) as src, open(target_path, "wb") as dst:
                while True:
                    chunk = src.read(64 * 1024)
                    if not chunk:
                        break
                    extracted_bytes += len(chunk)
                    if extracted_bytes > MAX_FILE_SIZE:
                        raise ResourceLimitError(
                            f"Decompressed file '{member.filename}' exceeds limit of {MAX_FILE_SIZE} bytes"
                        )
                    dst.write(chunk)


def ingest_project(
    source: Union[str, Path, BinaryIO, io.BytesIO],
    project_name: Optional[str] = None,
) -> ProjectContext:
    """
    Main ingestion entry point for SupplyGuard AI.
    Accepts either a directory path or a ZIP archive (path, bytes, or file-like object).
    Returns a ProjectContext with discovered files and metadata.
    """
    # 1. Directory Path
    if isinstance(source, (str, Path)):
        p = Path(source)
        if p.is_dir():
            return discover_directory(p, project_name=project_name)

        # Check if it's a ZIP file on disk
        if p.is_file() and (p.suffix.lower() == ".zip" or zipfile.is_zipfile(p)):
            temp_dir = tempfile.TemporaryDirectory(prefix="supplyguard_")
            try:
                extract_zip_safely(p, Path(temp_dir.name))
                ctx = discover_directory(Path(temp_dir.name), project_name=project_name or p.stem)
                ctx.temp_dir_obj = temp_dir
                return ctx
            except Exception:
                temp_dir.cleanup()
                raise

        raise IngestionError(f"Specified source path is not a directory or valid ZIP: {source}")

    # 2. File-like / Binary stream (e.g. Streamlit UploadedFile)
    temp_dir = tempfile.TemporaryDirectory(prefix="supplyguard_")
    try:
        extract_zip_safely(source, Path(temp_dir.name))
        name = project_name or getattr(source, "name", "uploaded_project")
        if isinstance(name, str) and name.lower().endswith(".zip"):
            name = Path(name).stem
        ctx = discover_directory(Path(temp_dir.name), project_name=name)
        ctx.temp_dir_obj = temp_dir
        return ctx
    except Exception:
        temp_dir.cleanup()
        raise
