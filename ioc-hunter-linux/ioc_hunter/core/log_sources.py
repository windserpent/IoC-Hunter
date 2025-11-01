"""
Log Sources Manager for IoC-Hunter Linux

Provides unified interface to various Linux log sources including:
- systemd/journald (primary)
- Traditional syslog files
- Authentication logs
- Application-specific logs

Python 3.9+ compatible.
"""

import logging
import gzip
import bz2
import subprocess
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Union, Iterator, Generator
from ..utils.helpers import run_system_command, parse_log_line_timestamp

# Try to import systemd for native journald support
try:
    import systemd.journal  # type: ignore
    SYSTEMD_AVAILABLE = True
except ImportError:
    systemd = None  # type: ignore
    SYSTEMD_AVAILABLE = False
    logging.warning("systemd-python not available - using journalctl via subprocess")


class LogEntry:
    """
    Represents a single log entry from any log source.
    
    Provides a unified format for log entries regardless of source.
    """
    
    def __init__(self, 
                 timestamp: datetime,
                 source: str,
                 message: str,
                 metadata: Optional[Dict[str, Any]] = None,
                 raw_line: Optional[str] = None):
        """
        Initialize log entry.
        
        Args:
            timestamp: When the log entry occurred
            source: Log source name (e.g., "journald", "auth.log")
            message: Log message content
            metadata: Additional structured metadata
            raw_line: Original raw log line
        """
        self.timestamp = timestamp
        self.source = source
        self.message = message
        self.metadata = metadata or {}
        self.raw_line = raw_line or message
        
        # Extract common fields from metadata
        self.unit = self.metadata.get("_SYSTEMD_UNIT", self.metadata.get("unit", ""))
        self.hostname = self.metadata.get("_HOSTNAME", self.metadata.get("hostname", ""))
        self.pid = self.metadata.get("_PID", self.metadata.get("pid", ""))
        self.service = self.metadata.get("SYSLOG_IDENTIFIER", self.metadata.get("service", ""))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert log entry to dictionary format."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "message": self.message,
            "unit": self.unit,
            "hostname": self.hostname,
            "pid": self.pid,
            "service": self.service,
            "metadata": self.metadata,
            "raw_line": self.raw_line
        }
    
    def __str__(self) -> str:
        """String representation of log entry."""
        return f"[{self.timestamp}] {self.source}: {self.message}"


class BaseLogSource(ABC):
    """
    Abstract base class for log sources.
    
    All log source implementations must inherit from this class.
    """
    
    name: Optional[str] = None              # Source name (e.g., "journald")
    display_name: Optional[str] = None      # Human-readable name
    description: Optional[str] = None       # Source description
    priority: int = 999           # Source priority (lower = higher priority)
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize log source.
        
        Args:
            config: Source-specific configuration
        """
        if not self.name:
            raise ValueError(f"Log source {self.__class__.__name__} must define 'name' class attribute")
        
        self.config = config or {}
        self.logger = logging.getLogger(f"{__name__}.{self.name}")
        self.is_available = self._check_availability()
    
    def _get_source_name(self) -> str:
        """Get the source name, ensuring it's never None for type safety."""
        return self.name or "unknown_source"
    
    @abstractmethod
    def get_entries(self, begin_time: datetime, end_time: datetime, 
                   filters: Optional[Dict[str, Any]] = None) -> Generator[LogEntry, None, None]:
        """
        Get log entries within time range.
        
        Args:
            begin_time: Start of time range
            end_time: End of time range
            filters: Optional filters to apply
            
        Yields:
            LogEntry objects
        """
        pass
    
    @abstractmethod
    def _check_availability(self) -> bool:
        """
        Check if this log source is available on the system.
        
        Returns:
            True if source is available
        """
        pass
    
    def is_accessible(self) -> bool:
        """
        Check if log source is accessible (available + readable).
        
        Returns:
            True if source is accessible
        """
        return self.is_available and self._check_permissions()
    
    def _check_permissions(self) -> bool:
        """
        Check if current user has permission to read this log source.
        
        Override this method for source-specific permission checks.
        
        Returns:
            True if readable
        """
        return True  # Default to accessible


class JournaldLogSource(BaseLogSource):
    """
    systemd/journald log source.
    
    Supports both native systemd-python and journalctl subprocess fallback.
    """
    
    name = "journald"
    display_name = "systemd Journal"
    description = "systemd journald logs (modern Linux systems)"
    priority = 1
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.use_native = SYSTEMD_AVAILABLE and self.config.get("prefer_native", True)
        
        if self.use_native:
            self.logger.info("Using native systemd-python for journald access")
        else:
            self.logger.info("Using journalctl subprocess for journald access")
    
    def get_entries(self, begin_time: datetime, end_time: datetime, 
                   filters: Optional[Dict[str, Any]] = None) -> Generator[LogEntry, None, None]:
        """Get journald entries within time range."""
        if not self.is_available:
            self.logger.error("journald is not available")
            return
        
        if self.use_native:
            yield from self._get_entries_native(begin_time, end_time, filters)
        else:
            yield from self._get_entries_subprocess(begin_time, end_time, filters)
    
    def _get_entries_native(self, begin_time: datetime, end_time: datetime, 
                           filters: Optional[Dict[str, Any]]) -> Generator[LogEntry, None, None]:
        """Get entries using native systemd-python."""
        if not SYSTEMD_AVAILABLE or systemd is None:
            raise ImportError("systemd-python is required for native journald access")
        try:
            journal = systemd.journal.Reader()
            
            # Set time range
            journal.seek_realtime(begin_time)
            
            # Apply filters
            if filters:
                for key, value in filters.items():
                    if key.startswith("_"):  # systemd field
                        journal.add_match(f"{key}={value}")
                    elif key == "unit":
                        journal.add_match(f"_SYSTEMD_UNIT={value}")
                    elif key == "service":
                        journal.add_match(f"SYSLOG_IDENTIFIER={value}")
            
            # Read entries
            for entry in journal:
                entry_time = entry.get('__REALTIME_TIMESTAMP')
                if entry_time:
                    entry_datetime = datetime.fromtimestamp(entry_time.timestamp())
                    
                    # Check if within time range
                    if entry_datetime > end_time:
                        break
                    if entry_datetime < begin_time:
                        continue
                    
                    # Create LogEntry
                    message = entry.get('MESSAGE', '')
                    metadata = dict(entry)
                    
                    yield LogEntry(
                        timestamp=entry_datetime,
                        source=self._get_source_name(),
                        message=message,
                        metadata=metadata,
                        raw_line=f"{entry_datetime} {message}"
                    )
                    
        except Exception as e:
            self.logger.error(f"Error reading journald entries: {e}")
    
    def _get_entries_subprocess(self, begin_time: datetime, end_time: datetime, 
                               filters: Optional[Dict[str, Any]]) -> Generator[LogEntry, None, None]:
        """Get entries using journalctl subprocess."""
        try:
            # Build journalctl command
            cmd = [
                "journalctl",
                "--output=json",
                "--no-pager",
                f"--since={begin_time.strftime('%Y-%m-%d %H:%M:%S')}",
                f"--until={end_time.strftime('%Y-%m-%d %H:%M:%S')}"
            ]
            
            # Add filters
            if filters:
                for key, value in filters.items():
                    if key == "unit":
                        cmd.extend(["-u", value])
                    elif key == "service":
                        cmd.extend([f"SYSLOG_IDENTIFIER={value}"])
                    elif key.startswith("_"):
                        cmd.extend([f"{key}={value}"])
            
            # Run command
            result = run_system_command(cmd, timeout=60)
            
            if result.returncode != 0:
                self.logger.error(f"journalctl failed: {result.stderr}")
                return
            
            # Parse JSON output
            import json
            for line in result.stdout.splitlines():
                if not line.strip():
                    continue
                
                try:
                    entry_data = json.loads(line)
                    
                    # Extract timestamp
                    timestamp_str = entry_data.get('__REALTIME_TIMESTAMP')
                    if timestamp_str:
                        # Convert from microseconds since epoch
                        timestamp_us = int(timestamp_str)
                        entry_datetime = datetime.fromtimestamp(timestamp_us / 1000000)
                    else:
                        continue
                    
                    message = entry_data.get('MESSAGE', '')
                    
                    yield LogEntry(
                        timestamp=entry_datetime,
                        source=self._get_source_name(),
                        message=message,
                        metadata=entry_data,
                        raw_line=f"{entry_datetime} {message}"
                    )
                    
                except json.JSONDecodeError as e:
                    self.logger.debug(f"Failed to parse journal entry JSON: {e}")
                    continue
                    
        except Exception as e:
            self.logger.error(f"Error running journalctl: {e}")
    
    def _check_availability(self) -> bool:
        """Check if journald is available."""
        try:
            # Try to run journalctl to check availability
            result = subprocess.run(
                ["journalctl", "--version"],
                capture_output=True,
                timeout=5,
                check=False
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def _check_permissions(self) -> bool:
        """Check if we can read journald."""
        try:
            # Try to read one entry
            result = subprocess.run(
                ["journalctl", "-n", "1", "--quiet"],
                capture_output=True,
                timeout=5,
                check=False
            )
            return result.returncode == 0
        except Exception:
            return False


class SyslogFileSource(BaseLogSource):
    """
    Traditional syslog file source.
    
    Supports plain text, gzip, and bzip2 compressed files.
    """
    
    name = "syslog_file"
    display_name = "Syslog Files"
    description = "Traditional syslog files (/var/log/syslog, /var/log/messages)"
    priority = 3
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        # Set up configuration first
        temp_config = config or {}
        self.log_paths = temp_config.get("paths", ["/var/log/syslog", "/var/log/messages"])
        self.available_paths = self._find_available_paths()
        
        # Now call parent init which will call _check_availability()
        super().__init__(config)
    
    def get_entries(self, begin_time: datetime, end_time: datetime, 
                   filters: Optional[Dict[str, Any]] = None) -> Generator[LogEntry, None, None]:
        """Get syslog entries within time range."""
        for log_path in self.available_paths:
            yield from self._read_log_file(log_path, begin_time, end_time, filters)
    
    def _read_log_file(self, log_path: Path, begin_time: datetime, end_time: datetime, 
                      filters: Optional[Dict[str, Any]]) -> Generator[LogEntry, None, None]:
        """Read entries from a single log file."""
        try:
            # Determine file type and open appropriately
            if log_path.suffix == '.gz':
                file_obj = gzip.open(log_path, 'rt', encoding='utf-8', errors='ignore')
            elif log_path.suffix == '.bz2':
                file_obj = bz2.open(log_path, 'rt', encoding='utf-8', errors='ignore')
            else:
                file_obj = open(log_path, 'r', encoding='utf-8', errors='ignore')
            
            with file_obj as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Parse timestamp from line
                    timestamp = parse_log_line_timestamp(line)
                    if not timestamp:
                        continue
                    
                    # Check time range
                    if timestamp < begin_time or timestamp > end_time:
                        continue
                    
                    # Apply filters
                    if filters and not self._matches_filters(line, filters):
                        continue
                    
                    # Extract metadata
                    metadata = {
                        "file_path": str(log_path),
                        "line_number": line_num
                    }
                    
                    # Try to extract service/hostname from syslog format
                    # Format: timestamp hostname service[pid]: message
                    import re
                    syslog_match = re.match(r'.*?\s+(\w+)\s+([^:\[\s]+)(?:\[(\d+)\])?\s*:\s*(.*)', line)
                    if syslog_match:
                        hostname, service, pid, message = syslog_match.groups()
                        metadata.update({
                            "hostname": hostname,
                            "service": service,
                            "pid": pid,
                            "extracted_message": message
                        })
                        display_message = message
                    else:
                        display_message = line
                    
                    yield LogEntry(
                        timestamp=timestamp,
                        source=f"{self.name}:{log_path.name}",
                        message=display_message,
                        metadata=metadata,
                        raw_line=line
                    )
                    
        except Exception as e:
            self.logger.error(f"Error reading log file {log_path}: {e}")
    
    def _matches_filters(self, line: str, filters: Dict[str, Any]) -> bool:
        """Check if log line matches filters."""
        for key, value in filters.items():
            if key == "service" and value.lower() not in line.lower():
                return False
            elif key == "message" and value.lower() not in line.lower():
                return False
        return True
    
    def _find_available_paths(self) -> List[Path]:
        """Find available log file paths."""
        available = []
        
        for path_str in self.log_paths:
            path = Path(path_str)
            
            # Check for exact file
            if path.exists() and path.is_file():
                available.append(path)
                continue
            
            # Check for compressed versions
            for suffix in ['.gz', '.bz2']:
                compressed_path = path.with_suffix(path.suffix + suffix)
                if compressed_path.exists() and compressed_path.is_file():
                    available.append(compressed_path)
            
            # Check for rotated versions (syslog.1, syslog.2, etc.)
            if path.parent.exists():
                for rotated_file in path.parent.glob(f"{path.name}.*"):
                    if rotated_file.is_file() and rotated_file not in available:
                        available.append(rotated_file)
        
        return available
    
    def _check_availability(self) -> bool:
        """Check if any syslog files are available."""
        return len(self.available_paths) > 0
    
    def _check_permissions(self) -> bool:
        """Check if we can read available syslog files."""
        for path in self.available_paths:
            try:
                with open(path, 'r') as f:
                    f.read(1)  # Try to read one character
                return True  # If any file is readable, consider accessible
            except PermissionError:
                continue
            except Exception:
                continue
        return False


class AuthLogSource(SyslogFileSource):
    """
    Authentication log source.
    
    Specialized syslog source for authentication logs.
    """
    
    name = "auth_log"
    display_name = "Authentication Logs"
    description = "Authentication and authorization logs"
    priority = 2
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        # Override default paths for auth logs
        if config is None:
            config = {}
        config.setdefault("paths", ["/var/log/auth.log", "/var/log/secure"])
        super().__init__(config)


class LogSourceManager:
    """
    Manager for all log sources.
    
    Provides unified interface to access logs from multiple sources.
    """
    
    def __init__(self, config_manager=None):
        """
        Initialize log source manager.
        
        Args:
            config_manager: Configuration manager instance
        """
        self.config_manager = config_manager
        self.logger = logging.getLogger(__name__)
        
        # Initialize log sources
        self.sources: Dict[str, BaseLogSource] = {}
        self._init_sources()
    
    def _init_sources(self):
        """Initialize all log sources."""
        # Get log sources configuration
        if self.config_manager:
            sources_config = self.config_manager.load_config("log_sources")
        else:
            sources_config = {}
        
        # Initialize standard sources
        source_classes = [
            JournaldLogSource,
            AuthLogSource,
            SyslogFileSource
        ]
        
        for source_class in source_classes:
            try:
                source_config = sources_config.get(source_class.name, {})
                
                # Skip if explicitly disabled
                if not source_config.get("enabled", True):
                    self.logger.info(f"Log source {source_class.name} disabled in configuration")
                    continue
                
                source = source_class(source_config)
                
                if source.is_accessible():
                    self.sources[source.name] = source
                    self.logger.info(f"Initialized log source: {source.display_name}")
                else:
                    self.logger.warning(f"Log source not accessible: {source.display_name}")
                    
            except Exception as e:
                self.logger.error(f"Failed to initialize log source {source_class.name}: {e}")
    
    def get_available_sources(self) -> List[str]:
        """Get list of available log source names."""
        return list(self.sources.keys())
    
    def get_source(self, name: str) -> Optional[BaseLogSource]:
        """
        Get log source by name.
        
        Args:
            name: Source name
            
        Returns:
            Log source or None if not found
        """
        return self.sources.get(name)
    
    def get_entries(self, begin_time: datetime, end_time: datetime,
                   sources: Optional[List[str]] = None,
                   filters: Optional[Dict[str, Any]] = None) -> Generator[LogEntry, None, None]:
        """
        Get log entries from multiple sources.
        
        Args:
            begin_time: Start of time range
            end_time: End of time range
            sources: List of source names to query (None = all available)
            filters: Optional filters to apply
            
        Yields:
            LogEntry objects sorted by timestamp
        """
        if sources is None:
            sources = self.get_available_sources()
        
        # Collect entries from all sources
        all_entries = []
        
        for source_name in sources:
            source = self.get_source(source_name)
            if source is None:
                self.logger.warning(f"Requested source not available: {source_name}")
                continue
            
            try:
                source_entries = list(source.get_entries(begin_time, end_time, filters))
                all_entries.extend(source_entries)
                self.logger.debug(f"Got {len(source_entries)} entries from {source_name}")
                
            except Exception as e:
                self.logger.error(f"Error getting entries from {source_name}: {e}")
        
        # Sort by timestamp and yield
        all_entries.sort(key=lambda e: e.timestamp)
        for entry in all_entries:
            yield entry
    
    def get_source_info(self) -> List[Dict[str, Any]]:
        """
        Get information about all sources.
        
        Returns:
            List of source information dictionaries
        """
        info = []
        
        for name, source in self.sources.items():
            info.append({
                "name": source.name,
                "display_name": source.display_name,
                "description": source.description,
                "priority": source.priority,
                "available": source.is_available,
                "accessible": source.is_accessible()
            })
        
        return sorted(info, key=lambda x: x["priority"])
    
    def test_sources(self) -> Dict[str, bool]:
        """
        Test all sources for accessibility.
        
        Returns:
            Dictionary mapping source names to accessibility status
        """
        results = {}
        
        for name, source in self.sources.items():
            try:
                results[name] = source.is_accessible()
            except Exception as e:
                self.logger.error(f"Error testing source {name}: {e}")
                results[name] = False
        
        return results
