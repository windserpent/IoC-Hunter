"""
Utility Helper Functions for IoC-Hunter Linux

Common utility functions used throughout the project.
Python 3.9+ compatible.
"""

import hashlib
import os
import re
import subprocess
import logging
from datetime import datetime
from pathlib import Path
from typing import Union, Optional, List, Dict, Any


def format_timestamp(dt: datetime, format_str: Optional[str] = None) -> str:
    """
    Format datetime as string using specified format.
    
    Args:
        dt: Datetime to format
        format_str: Format string (defaults to ISO format)
        
    Returns:
        Formatted timestamp string
    """
    if format_str is None:
        format_str = "%Y-%m-%d %H:%M:%S"
    
    return dt.strftime(format_str)


def sanitize_path(path: Union[str, Path], base_path: Optional[Path] = None) -> Path:
    """
    Sanitize and validate file path for security.
    
    Args:
        path: Path to sanitize
        base_path: Optional base path to restrict access to
        
    Returns:
        Sanitized Path object
        
    Raises:
        ValueError: If path is invalid or outside base_path
    """
    path_obj = Path(path).resolve()
    
    # Basic security checks
    if '..' in str(path_obj):
        raise ValueError(f"Path contains parent directory references: {path}")
    
    # Check if path is within base_path if specified
    if base_path is not None:
        base_path_resolved = Path(base_path).resolve()
        try:
            path_obj.relative_to(base_path_resolved)
        except ValueError:
            raise ValueError(f"Path {path} is outside allowed base path {base_path}")
    
    return path_obj


def calculate_file_hash(file_path: Union[str, Path], algorithm: str = "sha256") -> str:
    """
    Calculate hash of file for integrity checking.
    
    Args:
        file_path: Path to file
        algorithm: Hash algorithm (sha256, md5, sha1)
        
    Returns:
        Hex digest of file hash
        
    Raises:
        FileNotFoundError: If file doesn't exist
        ValueError: If unsupported algorithm
    """
    supported_algorithms = ["md5", "sha1", "sha256", "sha512"]
    if algorithm not in supported_algorithms:
        raise ValueError(f"Unsupported algorithm: {algorithm}. Supported: {supported_algorithms}")
    
    file_path = Path(file_path)
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    
    hash_obj = hashlib.new(algorithm)
    
    with open(file_path, 'rb') as f:
        # Read file in chunks to handle large files
        for chunk in iter(lambda: f.read(4096), b""):
            hash_obj.update(chunk)
    
    return hash_obj.hexdigest()


def run_system_command(command: List[str], timeout: int = 30, 
                      capture_output: bool = True) -> subprocess.CompletedProcess:
    """
    Run system command safely with timeout.
    
    Args:
        command: Command to run as list of strings
        timeout: Timeout in seconds
        capture_output: Whether to capture stdout/stderr
        
    Returns:
        CompletedProcess object
        
    Raises:
        subprocess.TimeoutExpired: If command times out
        subprocess.CalledProcessError: If command fails
    """
    logger = logging.getLogger(__name__)
    
    logger.debug(f"Running command: {' '.join(command)}")
    
    try:
        result = subprocess.run(
            command,
            timeout=timeout,
            capture_output=capture_output,
            text=True,
            check=False  # Don't automatically raise on non-zero exit
        )
        
        if result.returncode != 0:
            logger.warning(f"Command failed with exit code {result.returncode}: {' '.join(command)}")
            if result.stderr:
                logger.warning(f"Command stderr: {result.stderr}")
        
        return result
        
    except subprocess.TimeoutExpired as e:
        logger.error(f"Command timed out after {timeout}s: {' '.join(command)}")
        raise
    except Exception as e:
        logger.error(f"Error running command: {e}")
        raise


def parse_log_line_timestamp(line: str, timestamp_patterns: Optional[List[str]] = None) -> Optional[datetime]:
    """
    Extract timestamp from log line using common patterns.
    
    Args:
        line: Log line to parse
        timestamp_patterns: Optional custom timestamp patterns
        
    Returns:
        Parsed datetime or None if not found
    """
    if timestamp_patterns is None:
        # Common log timestamp patterns
        timestamp_patterns = [
            r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})',  # 2025-10-24 10:30:15
            r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})',  # 2025-10-24T10:30:15
            r'(\w{3} \d{2} \d{2}:\d{2}:\d{2})',        # Oct 24 10:30:15
            r'(\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2})',  # 10/24/2025 10:30:15
        ]
    
    for pattern in timestamp_patterns:
        match = re.search(pattern, line)
        if match:
            timestamp_str = match.group(1)
            
            # Try common datetime formats
            formats = [
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S",
                "%b %d %H:%M:%S",
                "%m/%d/%Y %H:%M:%S"
            ]
            
            for fmt in formats:
                try:
                    # For formats without year, add current year
                    if "%Y" not in fmt:
                        current_year = datetime.now().year
                        timestamp_str = f"{current_year} {timestamp_str}"
                        fmt = f"%Y {fmt}"
                    
                    return datetime.strptime(timestamp_str, fmt)
                except ValueError:
                    continue
    
    return None


def validate_file_permissions(file_path: Union[str, Path], required_permissions: str = "r") -> bool:
    """
    Validate file permissions.
    
    Args:
        file_path: Path to file
        required_permissions: Required permissions string ("r", "w", "rw")
        
    Returns:
        True if permissions are satisfied
    """
    file_path = Path(file_path)
    
    if not file_path.exists():
        return False
    
    permissions_ok = True
    
    if "r" in required_permissions:
        permissions_ok = permissions_ok and os.access(file_path, os.R_OK)
    
    if "w" in required_permissions:
        permissions_ok = permissions_ok and os.access(file_path, os.W_OK)
    
    if "x" in required_permissions:
        permissions_ok = permissions_ok and os.access(file_path, os.X_OK)
    
    return permissions_ok


def get_file_info(file_path: Union[str, Path]) -> Dict[str, Any]:
    """
    Get comprehensive file information.
    
    Args:
        file_path: Path to file
        
    Returns:
        Dictionary with file information
        
    Raises:
        FileNotFoundError: If file doesn't exist
    """
    file_path = Path(file_path)
    
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    
    stat_info = file_path.stat()
    
    return {
        "path": str(file_path.absolute()),
        "name": file_path.name,
        "size_bytes": stat_info.st_size,
        "size_human": format_file_size(stat_info.st_size),
        "created": datetime.fromtimestamp(stat_info.st_ctime),
        "modified": datetime.fromtimestamp(stat_info.st_mtime),
        "accessed": datetime.fromtimestamp(stat_info.st_atime),
        "permissions": oct(stat_info.st_mode)[-3:],
        "owner_uid": stat_info.st_uid,
        "group_gid": stat_info.st_gid,
        "is_file": file_path.is_file(),
        "is_dir": file_path.is_dir(),
        "is_symlink": file_path.is_symlink()
    }


def format_file_size(size_bytes: int) -> str:
    """
    Format file size in human-readable format.
    
    Args:
        size_bytes: Size in bytes
        
    Returns:
        Human-readable size string
    """
    if size_bytes == 0:
        return "0 B"
    
    units = ["B", "KB", "MB", "GB", "TB"]
    unit_index = 0
    size = float(size_bytes)
    
    while size >= 1024 and unit_index < len(units) - 1:
        size /= 1024
        unit_index += 1
    
    if unit_index == 0:
        return f"{int(size)} {units[unit_index]}"
    else:
        return f"{size:.1f} {units[unit_index]}"


def check_command_availability(command: str) -> bool:
    """
    Check if a command is available in the system PATH.
    
    Args:
        command: Command name to check
        
    Returns:
        True if command is available
    """
    try:
        subprocess.run(["which", command], 
                      capture_output=True, 
                      check=True, 
                      timeout=5)
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False


def extract_ip_addresses(text: str) -> List[str]:
    """
    Extract IP addresses from text using regex.
    
    Args:
        text: Text to search for IP addresses
        
    Returns:
        List of found IP addresses
    """
    # IPv4 pattern
    ipv4_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    ipv4_addresses = re.findall(ipv4_pattern, text)
    
    # Filter out invalid IPv4 addresses
    valid_ipv4 = []
    for ip in ipv4_addresses:
        parts = ip.split('.')
        if all(0 <= int(part) <= 255 for part in parts):
            valid_ipv4.append(ip)
    
    # IPv6 pattern (basic)
    ipv6_pattern = r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
    ipv6_addresses = re.findall(ipv6_pattern, text)
    
    return valid_ipv4 + ipv6_addresses


def setup_logging(log_level: str = "INFO", log_file: Optional[str] = None) -> logging.Logger:
    """
    Setup logging configuration for IoC-Hunter.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR)
        log_file: Optional log file path
        
    Returns:
        Configured logger
    """
    # Convert string level to logging constant
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Setup root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)
    
    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)
    
    # File handler if specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
    
    return root_logger
