"""
Privilege Escalation IoC Category for IoC-Hunter Linux

Detects privilege escalation attempts including sudo abuse, setuid/setgid
modifications, capability changes, and rapid escalation patterns.

This category implements advanced sudo log discovery and correlation analysis
to identify multi-stage privilege escalation attacks.

Python 3.9+ compatible.
"""

import re
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Set
from collections import defaultdict
from pathlib import Path

from ..core.base_category import BaseIoCCategory, IoCEvent
from ..utils.helpers import extract_ip_addresses


class PrivilegeEscalation(BaseIoCCategory):
    """
    Privilege Escalation Detection Category.
    
    Detects:
    - Dangerous sudo usage (sudo su, sudo -i, sudo /bin/bash)
    - Setuid/setgid binary modifications and usage  
    - Password changes, especially root password modifications
    - Sudoers file access and modifications (visudo)
    - SUID/SGID binary monitoring via file permission changes
    - Linux capabilities system changes
    - Rapid privilege escalation correlation patterns
    """
    
    # Required class attributes for auto-discovery
    name = "privilege_escalation"
    display_name = "Privilege Escalation Activity"
    description = "Detects sudo abuse, setuid modifications, capability changes and privilege escalation patterns"
    version = "1.0.0"
    tier = 1  # Tier 1 = Critical (included in quick scans)
    
    def __init__(self, config_manager: Optional[Any] = None, log_sources: Optional[Any] = None) -> None:
        super().__init__(config_manager, log_sources)
        
        # Load privilege escalation patterns and thresholds
        self.patterns = self.get_patterns()
        self.thresholds = self.patterns.get("thresholds", {
            "rapid_escalation_window_minutes": 10,
            "sudo_abuse_threshold": 3,
            "setuid_changes_threshold": 2
        })
        
        # Debug pattern loading
        if self.patterns:
            pattern_types = self.patterns.get("patterns", {})
            self.logger.info(f"Loaded {len(pattern_types)} pattern types: {list(pattern_types.keys())}")
        else:
            self.logger.warning("No patterns loaded from configuration")
        
        # Tracking for correlation analysis
        self.sudo_events = defaultdict(list)  # user -> list of (timestamp, command)
        self.setuid_changes = defaultdict(list)  # user -> list of (timestamp, file, operation)
        self.password_changes = defaultdict(list)  # user -> list of timestamps
        self.capability_changes = defaultdict(list)  # user -> list of (timestamp, operation)
        self.privilege_timeline = []  # All privilege events for correlation
        
        # Custom sudo log paths discovered from /etc/sudoers
        self.custom_sudo_logs = []
        self._discover_sudo_log_paths()
        
        self.logger.info(f"Initialized Privilege Escalation scanner")
        if self.custom_sudo_logs:
            self.logger.info(f"Discovered custom sudo log paths: {self.custom_sudo_logs}")

    def _get_category_name(self) -> str:
        """Get the category name, ensuring it's never None for type safety."""
        return self.name or "privilege_escalation"
    
    def get_required_log_sources(self) -> List[str]:
        """Privilege escalation requires auth logs, journald, and syslog."""
        return ["auth_log", "journald"]
    
    def get_supported_log_sources(self) -> List[str]:
        """Privilege escalation can use multiple log sources."""
        return ["auth_log", "journald", "syslog_file", "kernel_logs"]
    
    def _discover_sudo_log_paths(self) -> None:
        """
        Parse /etc/sudoers to discover custom log file configurations.
        
        Looks for lines like:
        - Defaults logfile=/var/log/sudo.log
        - Defaults log_output
        - Defaults iolog_dir=/var/log/sudo-io
        """
        sudoers_paths = ["/etc/sudoers", "/etc/sudoers.d/*"]
        
        for sudoers_pattern in sudoers_paths:
            try:
                if "*" in sudoers_pattern:
                    # Handle sudoers.d directory
                    sudoers_dir = Path(sudoers_pattern.replace("/*", ""))
                    if sudoers_dir.exists():
                        for sudoers_file in sudoers_dir.glob("*"):
                            if sudoers_file.is_file():
                                self._parse_sudoers_file(sudoers_file)
                else:
                    # Handle main sudoers file
                    sudoers_file = Path(sudoers_pattern)
                    if sudoers_file.exists():
                        self._parse_sudoers_file(sudoers_file)
                        
            except (OSError, PermissionError) as e:
                self.logger.warning(f"Cannot access sudoers file {sudoers_pattern}: {e}")
    
    def _parse_sudoers_file(self, sudoers_file: Path) -> None:
        """Parse a single sudoers file for log configuration."""
        try:
            with open(sudoers_file, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    
                    # Skip comments and empty lines
                    if not line or line.startswith('#'):
                        continue
                    
                    # Look for log file configuration
                    if 'Defaults' in line and 'logfile=' in line:
                        match = re.search(r'logfile=([^\s,]+)', line)
                        if match:
                            log_path = match.group(1)
                            if log_path not in self.custom_sudo_logs:
                                self.custom_sudo_logs.append(log_path)
                    
                    # Look for I/O logging directory
                    if 'Defaults' in line and 'iolog_dir=' in line:
                        match = re.search(r'iolog_dir=([^\s,]+)', line)
                        if match:
                            iolog_dir = match.group(1)
                            if iolog_dir not in self.custom_sudo_logs:
                                self.custom_sudo_logs.append(f"{iolog_dir}/*")
                                
        except (OSError, PermissionError) as e:
            self.logger.warning(f"Cannot read sudoers file {sudoers_file}: {e}")
    
    def scan(self, begin_time: datetime, end_time: datetime) -> List[IoCEvent]:
        """
        Scan for privilege escalation activity within time range.
        
        Args:
            begin_time: Start of scan window
            end_time: End of scan window
            
        Returns:
            List of privilege escalation IoC events
        """
        scan_start = datetime.now()
        events = []
        processed_count = 0
        
        self.logger.info(f"Scanning privilege escalation activity from {begin_time} to {end_time}")
        
        # Define filters for privilege escalation logs
        privesc_filters = {
            "keywords": ["sudo", "passwd", "su", "setuid", "chmod", "visudo", "capability"],
            "exclude_noise": True
        }
        
        try:
            # Ensure log sources are available
            if not self.log_sources:
                self.logger.error("Log sources not initialized")
                return []
            
            # Get entries from primary log sources
            log_entries = self.log_sources.get_entries(
                begin_time=begin_time,
                end_time=end_time,
                sources=self.get_required_log_sources(),
                filters=privesc_filters
            )
            
            # Also check custom sudo logs if discovered
            if self.custom_sudo_logs:
                for custom_log in self.custom_sudo_logs:
                    try:
                        custom_entries = self._read_custom_sudo_log(custom_log, begin_time, end_time)
                        log_entries.extend(custom_entries)
                    except Exception as e:
                        self.logger.warning(f"Failed to read custom sudo log {custom_log}: {e}")
            
            # Process each log entry
            for entry in log_entries:
                processed_count += 1
                
                # Extract basic info from LogEntry object
                timestamp = entry.timestamp
                message = entry.message
                source = entry.source
                raw_log = entry.raw_line
                
                # Skip empty messages
                if not message.strip():
                    continue
                
                # Detect different types of privilege escalation
                detected_events = []
                
                # 1. Sudo abuse detection
                sudo_events = self._detect_sudo_abuse(timestamp, message, source, entry)
                detected_events.extend(sudo_events)
                
                # 2. Setuid/setgid modifications
                setuid_events = self._detect_setuid_modifications(timestamp, message, source, entry)
                detected_events.extend(setuid_events)
                
                # 3. Password changes
                passwd_events = self._detect_password_changes(timestamp, message, source, entry)
                detected_events.extend(passwd_events)
                
                # 4. Sudoers file access
                visudo_events = self._detect_visudo_access(timestamp, message, source, entry)
                detected_events.extend(visudo_events)
                
                # 5. Capability changes (enhanced feature)
                capability_events = self._detect_capability_changes(timestamp, message, source, entry)
                detected_events.extend(capability_events)
                
                # 6. SUID/SGID binary monitoring (enhanced feature)
                suid_binary_events = self._detect_suid_binary_usage(timestamp, message, source, entry)
                detected_events.extend(suid_binary_events)
                
                # Add all detected events and track for correlation
                for event in detected_events:
                    events.append(event)
                    self._track_for_correlation(event)
            
            # Perform correlation analysis to detect rapid escalation patterns
            correlation_events = self._perform_correlation_analysis(begin_time, end_time)
            events.extend(correlation_events)
            
            scan_duration = (datetime.now() - scan_start).total_seconds()
            self.logger.info(f"Privilege escalation scan completed: {len(events)} events found, "
                           f"{processed_count} entries processed in {scan_duration:.2f}s")
            
            return events
            
        except Exception as e:
            self.logger.error(f"Error during privilege escalation scan: {e}")
            return events
    
    def _read_custom_sudo_log(self, log_path: str, begin_time: datetime, end_time: datetime) -> List[Dict]:
        """Read entries from custom sudo log files."""
        entries = []
        
        try:
            if "*" in log_path:
                # Handle wildcard paths (like iolog directories)
                base_path = Path(log_path.replace("/*", ""))
                if base_path.exists():
                    for log_file in base_path.glob("*"):
                        if log_file.is_file():
                            file_entries = self._parse_log_file(log_file, begin_time, end_time)
                            entries.extend(file_entries)
            else:
                # Handle specific log files
                log_file = Path(log_path)
                if log_file.exists():
                    entries = self._parse_log_file(log_file, begin_time, end_time)
                    
        except Exception as e:
            self.logger.warning(f"Error reading custom sudo log {log_path}: {e}")
        
        return entries
    
    def _parse_log_file(self, log_file: Path, begin_time: datetime, end_time: datetime) -> List[Dict]:
        """Parse a log file and return entries within time range."""
        entries = []
        
        try:
            with open(log_file, 'r', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Try to parse timestamp (basic parsing for now)
                    timestamp = self._extract_timestamp_from_line(line)
                    if timestamp and begin_time <= timestamp <= end_time:
                        entries.append({
                            'timestamp': timestamp,
                            'message': line,
                            'source': f'custom_sudo_log:{log_file.name}',
                            'raw_log': line
                        })
                        
        except Exception as e:
            self.logger.warning(f"Error parsing log file {log_file}: {e}")
        
        return entries
    
    def _extract_timestamp_from_line(self, line: str) -> Optional[datetime]:
        """Extract timestamp from log line using common patterns."""
        # Common sudo log timestamp patterns
        patterns = [
            r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})',  # Aug 15 10:30:25
            r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})',  # 2024-08-15 10:30:25
            r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})'  # 2024-08-15T10:30:25
        ]
        
        for pattern in patterns:
            match = re.search(pattern, line)
            if match:
                try:
                    timestamp_str = match.group(1)
                    # Try different parsing approaches
                    if 'T' in timestamp_str:
                        return datetime.fromisoformat(timestamp_str)
                    elif '-' in timestamp_str:
                        return datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                    else:
                        # Handle syslog format (need current year)
                        current_year = datetime.now().year
                        return datetime.strptime(f"{current_year} {timestamp_str}", '%Y %b %d %H:%M:%S')
                except ValueError:
                    continue
        
        return None
    
    def _detect_sudo_abuse(self, timestamp: datetime, message: str, source: str, entry) -> List[IoCEvent]:
        """Detect dangerous sudo usage patterns."""
        events = []
        
        # Get sudo abuse patterns
        sudo_patterns = self.patterns.get("patterns", {}).get("sudo_abuse", [])
        dangerous_patterns = self.patterns.get("patterns", {}).get("dangerous_sudo", [])
        
        user = self._extract_user_from_message(message)
        command = self._extract_command_from_message(message)
        
        # Check for dangerous sudo usage
        for pattern in sudo_patterns:
            if pattern.lower() in message.lower():
                severity = "HIGH"
                event_type = "sudo_to_root"
                
                if "sudo su" in message.lower():
                    details = f"User {user} executed 'sudo su' - direct root shell access"
                elif "sudo -i" in message.lower():
                    details = f"User {user} executed 'sudo -i' - interactive root shell"
                elif "sudo /bin/bash" in message.lower() or "sudo /bin/sh" in message.lower():
                    details = f"User {user} executed shell via sudo - potential privilege abuse"
                elif "sudo passwd" in message.lower():
                    event_type = "passwd_change"
                    details = f"User {user} executed 'sudo passwd' - password modification attempt"
                elif "sudo visudo" in message.lower():
                    event_type = "visudo_access"
                    details = f"User {user} accessed sudoers file via visudo"
                else:
                    details = f"User {user} executed dangerous sudo command: {command}"
                
                event = IoCEvent(
                    timestamp=timestamp,
                    category=self._get_category_name(),
                    severity=severity,
                    source=source,
                    event_type=event_type,
                    details=details,
                    raw_log=entry.raw_line,
                    metadata={
                        'user': user,
                        'command': command,
                        'pattern_matched': pattern,
                        'source_ip': self._extract_ip_from_message(message)
                    }
                )
                
                events.append(event)
                
                # Track for correlation
                self.sudo_events[user].append((timestamp, command))
                
                break  # Only match first pattern to avoid duplicates
        
        # Check for other dangerous sudo usage
        for pattern in dangerous_patterns:
            if pattern.lower() in message.lower() and not any(p.lower() in message.lower() for p in sudo_patterns):
                severity = "MEDIUM"
                event_type = "dangerous_sudo"
                details = f"User {user} executed potentially dangerous sudo command: {command}"
                
                event = IoCEvent(
                    timestamp=timestamp,
                    category=self._get_category_name(),
                    severity=severity,
                    source=source,
                    event_type=event_type,
                    details=details,
                    raw_log=entry.raw_line,
                    metadata={
                        'user': user,
                        'command': command,
                        'pattern_matched': pattern,
                        'source_ip': self._extract_ip_from_message(message)
                    }
                )
                
                events.append(event)
                break
        
        return events
    
    def _detect_setuid_modifications(self, timestamp: datetime, message: str, source: str, entry) -> List[IoCEvent]:
        """Enhanced setuid/setgid modification detection with context awareness and filtering."""
        events = []
        
        # Get patterns for filtering and context
        patterns_dict = self.patterns.get("patterns", {})
        setuid_patterns = patterns_dict.get("setuid_usage", [])
        ignore_patterns = patterns_dict.get("ignore_patterns", [])
        legitimate_contexts = patterns_dict.get("legitimate_contexts", [])
        high_risk_operations = patterns_dict.get("high_risk_operations", [])
        medium_risk_operations = patterns_dict.get("medium_risk_operations", [])
        low_risk_operations = patterns_dict.get("low_risk_operations", [])
        
        # FIRST: Check if this should be ignored (system events, legitimate operations)
        if self._should_ignore_message(message, ignore_patterns):
            return events
        
        user = self._extract_user_from_message(message)
        command = self._extract_command_from_message(message)
        
        # Skip if we couldn't extract meaningful user/command info
        if user == 'unknown' and command == 'unknown':
            return events
        
        for pattern in setuid_patterns:
            if pattern.lower() in message.lower():
                # Check if this is a legitimate operation
                is_legitimate = (
                    self._has_legitimate_context(message, legitimate_contexts) or
                    self._is_legitimate_privilege_operation(message, command)
                )
                
                # Determine risk level for the operation
                operation_risk = self._determine_operation_risk(command, high_risk_operations, medium_risk_operations, low_risk_operations)
                
                if is_legitimate:
                    severity = "MEDIUM" if operation_risk == "HIGH" else "LOW"
                    event_type = "legitimate_setuid_modification"
                else:
                    severity = operation_risk
                    event_type = f"{operation_risk.lower()}_risk_privilege_escalation"
                
                # Extract file being modified
                file_match = re.search(r'chmod.*?([/\w\-\.]+)', message)
                target_file = file_match.group(1) if file_match else "unknown"
                
                details = f"User {user} modified setuid/setgid permissions on {target_file}"
                if is_legitimate:
                    details += " (legitimate system operation)"
                
                event = IoCEvent(
                    timestamp=timestamp,
                    category=self._get_category_name(),
                    severity=severity,
                    source=source,
                    event_type=event_type,
                    details=details,
                    raw_log=entry.raw_line,
                    metadata={
                        'user': user,
                        'target_file': target_file,
                        'command': command,
                        'pattern_matched': pattern,
                        'operation': 'setuid_modification',
                        'is_legitimate': is_legitimate,  # New field
                        'context_verified': True,  # New field
                        'risk_level': operation_risk.lower()
                    }
                )
                
                events.append(event)
                
                # Track for correlation
                self.setuid_changes[user].append((timestamp, target_file, 'modification'))
                
                break
        
        return events
    
    def _detect_password_changes(self, timestamp: datetime, message: str, source: str, entry) -> List[IoCEvent]:
        """Detect password change events, especially for root."""
        events = []
        
        user = self._extract_user_from_message(message)
        
        # Look for password change indicators
        passwd_indicators = [
            "password changed", "passwd:", "password updated",
            "password set", "password modified"
        ]
        
        for indicator in passwd_indicators:
            if indicator.lower() in message.lower():
                # Determine if this is a root password change
                is_root_change = ("root" in message.lower() or 
                                "uid=0" in message.lower() or
                                user == "root")
                
                severity = "HIGH" if is_root_change else "MEDIUM"
                event_type = "root_password_change" if is_root_change else "password_change"
                
                target_user = "root" if is_root_change else self._extract_target_user_from_message(message, user)
                
                details = f"Password changed for user {target_user} by {user}"
                if is_root_change:
                    details += " - ROOT PASSWORD MODIFIED"
                
                event = IoCEvent(
                    timestamp=timestamp,
                    category=self._get_category_name(),
                    severity=severity,
                    source=source,
                    event_type=event_type,
                    details=details,
                    raw_log=entry.raw_line,
                    metadata={
                        'user': user,
                        'target_user': target_user,
                        'is_root_change': is_root_change,
                        'indicator_matched': indicator
                    }
                )
                
                events.append(event)
                
                # Track for correlation
                self.password_changes[user].append(timestamp)
                
                break
        
        return events
    
    def _detect_visudo_access(self, timestamp: datetime, message: str, source: str, entry) -> List[IoCEvent]:
        """Detect access to sudoers file via visudo or direct editing."""
        events = []
        
        user = self._extract_user_from_message(message)
        
        # Look for visudo usage or direct sudoers file access
        visudo_indicators = [
            "visudo", "/etc/sudoers", "sudoers file", "sudoers modified"
        ]
        
        for indicator in visudo_indicators:
            if indicator.lower() in message.lower():
                severity = "HIGH"
                event_type = "visudo_access"
                
                if "visudo" in message.lower():
                    details = f"User {user} accessed sudoers file via visudo command"
                else:
                    details = f"User {user} accessed/modified sudoers file directly: {indicator}"
                
                event = IoCEvent(
                    timestamp=timestamp,
                    category=self._get_category_name(),
                    severity=severity,
                    source=source,
                    event_type=event_type,
                    details=details,
                    raw_log=entry.raw_line,
                    metadata={
                        'user': user,
                        'indicator_matched': indicator,
                        'access_type': 'visudo' if 'visudo' in indicator else 'direct'
                    }
                )
                
                events.append(event)
                break
        
        return events
    
    def _detect_capability_changes(self, timestamp: datetime, message: str, source: str, entry) -> List[IoCEvent]:
        """Detect Linux capability changes (enhanced feature)."""
        events = []
        
        user = self._extract_user_from_message(message)
        
        # Look for capability-related commands and changes
        capability_indicators = [
            "setcap", "getcap", "capability", "cap_", "CAP_",
            "capsh", "pscap", "filecap", "libcap"
        ]
        
        for indicator in capability_indicators:
            if indicator in message:  # Case sensitive for capability names
                severity = "MEDIUM"
                event_type = "capability_change"
                
                # Extract capability name if present
                cap_match = re.search(r'(CAP_\w+|cap_\w+)', message)
                capability = cap_match.group(1) if cap_match else "unknown"
                
                # Extract target file for setcap operations
                file_match = re.search(r'setcap.*?([/\w\-\.]+)', message)
                target_file = file_match.group(1) if file_match else "unknown"
                
                if "setcap" in message.lower():
                    details = f"User {user} set capability {capability} on file {target_file}"
                    severity = "HIGH"  # Setting capabilities is more suspicious
                elif "getcap" in message.lower():
                    details = f"User {user} queried capabilities on system"
                else:
                    details = f"User {user} performed capability-related operation: {indicator}"
                
                event = IoCEvent(
                    timestamp=timestamp,
                    category=self._get_category_name(),
                    severity=severity,
                    source=source,
                    event_type=event_type,
                    details=details,
                    raw_log=entry.raw_line,
                    metadata={
                        'user': user,
                        'capability': capability,
                        'target_file': target_file,
                        'indicator_matched': indicator,
                        'operation': 'set' if 'setcap' in message.lower() else 'query'
                    }
                )
                
                events.append(event)
                
                # Track for correlation
                operation = 'set' if 'setcap' in message.lower() else 'query'
                self.capability_changes[user].append((timestamp, operation))
                
                break
        
        return events
    
    def _detect_suid_binary_usage(self, timestamp: datetime, message: str, source: str, entry) -> List[IoCEvent]:
        """Enhanced SUID/SGID binary usage detection with context awareness and filtering."""
        events = []
        
        # Get patterns for filtering and context
        patterns_dict = self.patterns.get("patterns", {})
        ignore_patterns = patterns_dict.get("ignore_patterns", [])
        legitimate_contexts = patterns_dict.get("legitimate_contexts", [])
        high_risk_operations = patterns_dict.get("high_risk_operations", [])
        medium_risk_operations = patterns_dict.get("medium_risk_operations", [])
        low_risk_operations = patterns_dict.get("low_risk_operations", [])
        
        # FIRST: Check if this should be ignored (system events, legitimate operations)
        if self._should_ignore_message(message, ignore_patterns):
            return events
        
        user = self._extract_user_from_message(message)
        
        # Common SUID binaries that might be abused
        suid_binaries = [
            "find", "vim", "nano", "less", "more", "nmap", "awk", "gawk",
            "perl", "python", "ruby", "node", "php", "docker", "systemctl",
            "mount", "umount", "su", "sudo", "doas"
        ]
        
        # Look for execution of potentially dangerous SUID binaries
        for binary in suid_binaries:
            if f" {binary} " in message or f"/{binary} " in message or message.endswith(binary):
                # Check if this appears to be executed with elevated privileges
                if any(indicator in message.lower() for indicator in ["root", "uid=0", "euid=0"]):
                    
                    # Check if this is a legitimate operation
                    is_legitimate = (
                        self._has_legitimate_context(message, legitimate_contexts) or
                        self._is_legitimate_privilege_operation(message, message) or
                        self._is_legitimate_suid_usage(message, binary)
                    )
                    
                    # Determine base severity based on binary risk
                    if binary in ["vim", "nano", "find", "nmap", "docker"]:
                        base_severity = "HIGH"
                        escalation_potential = True
                    else:
                        base_severity = "MEDIUM"
                        escalation_potential = False
                    
                    # Adjust severity based on legitimacy
                    if is_legitimate:
                        if base_severity == "HIGH":
                            severity = "MEDIUM"  # Reduce HIGH to MEDIUM for legitimate
                        else:
                            severity = "LOW"     # Reduce MEDIUM to LOW for legitimate
                        event_type = "legitimate_suid_binary_usage"
                    else:
                        severity = base_severity
                        event_type = "suid_binary_usage"
                    
                    details = f"User {user} executed SUID binary {binary} with elevated privileges"
                    
                    # Add context information
                    if is_legitimate:
                        details += " (legitimate system operation)"
                    elif escalation_potential and not is_legitimate:
                        details += f" - {binary} can be used for privilege escalation"
                    
                    event = IoCEvent(
                        timestamp=timestamp,
                        category=self._get_category_name(),
                        severity=severity,
                        source=source,
                        event_type=event_type,
                        details=details,
                        raw_log=entry.raw_line,
                        metadata={
                            'user': user,
                            'binary': binary,
                            'escalation_potential': escalation_potential,
                            'is_legitimate': is_legitimate,  # New field
                            'context_verified': True,  # New field
                            'base_severity': base_severity,  # New field
                            'risk_level': base_severity.lower()
                        }
                    )
                    
                    events.append(event)
                    break
        
        return events
    
    def _track_for_correlation(self, event: IoCEvent) -> None:
        """Track events for correlation analysis."""
        self.privilege_timeline.append({
            'timestamp': event.timestamp,
            'user': event.metadata.get('user', 'unknown'),
            'event_type': event.event_type,
            'severity': event.severity,
            'details': event.details
        })
    
    def _perform_correlation_analysis(self, begin_time: datetime, end_time: datetime) -> List[IoCEvent]:
        """Analyze tracked events for rapid privilege escalation patterns."""
        events = []
        
        # Sort timeline by timestamp
        self.privilege_timeline.sort(key=lambda x: x['timestamp'])
        
        # Look for rapid privilege escalation patterns
        window_minutes = self.thresholds.get("rapid_escalation_window_minutes", 10)
        window_delta = timedelta(minutes=window_minutes)
        
        # Group events by user within time windows
        user_windows = defaultdict(list)
        
        for event_data in self.privilege_timeline:
            if begin_time <= event_data['timestamp'] <= end_time:
                user = event_data['user']
                user_windows[user].append(event_data)
        
        # Analyze each user's activity for escalation patterns
        for user, user_events in user_windows.items():
            if len(user_events) < 2:
                continue
            
            # Check for rapid escalation within time window
            for i, start_event in enumerate(user_events[:-1]):
                escalation_events = [start_event]
                start_time = start_event['timestamp']
                end_window = start_time + window_delta
                
                # Collect events within window
                for next_event in user_events[i+1:]:
                    if next_event['timestamp'] <= end_window:
                        escalation_events.append(next_event)
                    else:
                        break
                
                # Check if this represents a privilege escalation chain
                if self._is_escalation_pattern(escalation_events):
                    severity = "HIGH"
                    event_type = "rapid_privilege_escalation"
                    
                    event_types = [e['event_type'] for e in escalation_events]
                    details = (f"Rapid privilege escalation detected for user {user}: "
                             f"{len(escalation_events)} privilege events in {window_minutes} minutes "
                             f"({', '.join(event_types)})")
                    
                    event = IoCEvent(
                        timestamp=start_time,
                        category=self._get_category_name(),
                        severity=severity,
                        source="correlation_analysis",
                        event_type=event_type,
                        details=details,
                        raw_log=None,
                        metadata={
                            'user': user,
                            'escalation_events': len(escalation_events),
                            'time_window_minutes': window_minutes,
                            'event_types': event_types,
                            'pattern': 'rapid_escalation'
                        }
                    )
                    
                    events.append(event)
                    
                    # Don't create overlapping correlation events
                    break
        
        return events
    
    def _is_escalation_pattern(self, events: List[Dict]) -> bool:
        """Determine if a sequence of events represents privilege escalation."""
        if len(events) < 2:
            return False
        
        # Define escalation patterns
        escalation_sequences = [
            # Classic escalation pattern
            ["sudo_to_root", "password_change"],
            ["sudo_to_root", "visudo_access"],
            ["setuid_modification", "sudo_to_root"],
            ["capability_change", "sudo_to_root"],
            
            # Multiple sudo abuse events
            ["sudo_to_root", "sudo_to_root"],
            ["dangerous_sudo", "sudo_to_root"],
            
            # SUID escalation pattern
            ["suid_binary_usage", "setuid_modification"],
            ["suid_binary_usage", "sudo_to_root"]
        ]
        
        event_types = [e['event_type'] for e in events]
        
        # Check if event sequence matches any escalation pattern
        for pattern in escalation_sequences:
            if self._sequence_contains_pattern(event_types, pattern):
                return True
        
        # Also flag if there are multiple HIGH severity privilege events
        high_severity_count = sum(1 for e in events if e['severity'] == 'HIGH')
        if high_severity_count >= 2:
            return True
        
        return False
    
    def _sequence_contains_pattern(self, sequence: List[str], pattern: List[str]) -> bool:
        """Check if sequence contains the given pattern (not necessarily consecutive)."""
        pattern_index = 0
        
        for event_type in sequence:
            if pattern_index < len(pattern) and event_type == pattern[pattern_index]:
                pattern_index += 1
                if pattern_index == len(pattern):
                    return True
        
        return False
    
    def _extract_user_from_message(self, message: str) -> str:
        """Enhanced user extraction with better context awareness."""
        # FIRST: Try specific structured patterns
        structured_patterns = [
            r'user=([^\s,]+)',
            r'USER=([^\s,]+)',
            r'for user ([^\s,]+)',
            r'by user ([^\s,]+)',
            r'([^\s]+)@',  # user@hostname
            r'uid=\d+\(([^)]+)\)',
            r'sudo:\s+([^\s]+)\s+:',  # sudo logs
        ]
        
        for pattern in structured_patterns:
            match = re.search(pattern, message)
            if match:
                user = match.group(1)
                # VALIDATE: Don't return system event types as users
                if not self._is_system_event_type(user):
                    # Filter out common non-user strings but allow root
                    if user not in ['sudo', 'passwd', 'su', 'for', 'by', 'user'] or user == 'root':
                        return user
        
        # AVOID: The overly broad fallback pattern unless we have high confidence
        if 'user ' in message.lower() or 'sudo' in message.lower():
            # Try the broader pattern but validate result
            broad_pattern = r'\s([a-z_][a-z0-9_]{0,30})\s'
            match = re.search(broad_pattern, message)
            if match:
                user = match.group(1)
                if not self._is_system_event_type(user):
                    if user not in ['sudo', 'passwd', 'su', 'for', 'by', 'user'] or user == 'root':
                        return user
        
        return 'unknown'
    
    def _extract_target_user_from_message(self, message: str, acting_user: str) -> str:
        """Extract target user from password change messages."""
        # Look for "passwd username" or similar patterns
        patterns = [
            r'passwd\s+([^\s]+)',
            r'password.*for\s+([^\s]+)',
            r'changing.*password.*for\s+([^\s]+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, message)
            if match:
                target = match.group(1)
                if target != acting_user:
                    return target
        
        return acting_user
    
    def _extract_command_from_message(self, message: str) -> str:
        """Extract command from log message."""
        # Look for command patterns
        patterns = [
            r'COMMAND=([^\n\r]+)',
            r'command=([^\n\r]+)',
            r'executed:\s*([^\n\r]+)',
            r'running:\s*([^\n\r]+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, message)
            if match:
                return match.group(1).strip()
        
        # Fallback: try to extract after sudo
        sudo_match = re.search(r'sudo\s+(.+)', message)
        if sudo_match:
            return sudo_match.group(1).strip()
        
        return 'unknown'
    
    def _extract_ip_from_message(self, message: str) -> Optional[str]:
        """Extract IP address from log message."""
        ips = extract_ip_addresses(message)
        return ips[0] if ips else None

    def _should_ignore_message(self, message: str, ignore_patterns: List[str]) -> bool:
        """Check if message should be ignored (system events, legitimate operations, etc.)."""
        if not ignore_patterns:
            return False
        
        message_lower = message.lower()
        for pattern in ignore_patterns:
            if pattern.lower() in message_lower:
                return True
        return False
    
    def _has_legitimate_context(self, message: str, legitimate_contexts: List[str]) -> bool:
        """Check if the message indicates legitimate system operation."""
        if not legitimate_contexts:
            return False
        
        message_lower = message.lower()
        for context in legitimate_contexts:
            if context.lower() in message_lower:
                return True
        return False
    
    def _is_system_event_type(self, word: str) -> bool:
        """Check if a word is a system event type, not a username."""
        if not word or len(word) < 2:
            return True
        
        system_event_types = {
            'setuid', 'setgid', 'chmod', 'chown', 'mount', 'umount',
            'kernel', 'systemd', 'audit', 'passwd', 'group', 'shadow',
            'sudo', 'su', 'login', 'logout', 'session', 'pam'
        }
        return word.lower() in system_event_types
    
    def _determine_operation_risk(self, operation: str, high_risk: List[str], 
                                 medium_risk: List[str], low_risk: List[str]) -> str:
        """Determine risk level based on privilege operation classification."""
        operation_lower = operation.lower()
        
        # Check high risk operations
        for high_op in high_risk:
            if high_op.lower() in operation_lower:
                return "HIGH"
        
        # Check medium risk operations  
        for medium_op in medium_risk:
            if medium_op.lower() in operation_lower:
                return "MEDIUM"
                
        # Check low risk operations
        for low_op in low_risk:
            if low_op.lower() in operation_lower:
                return "LOW"
        
        # Default to medium for unclassified operations
        return "MEDIUM"
    
    def _is_legitimate_privilege_operation(self, message: str, command: str) -> bool:
        """Check if privilege operation appears legitimate."""
        # Check for common legitimate patterns
        legitimate_indicators = [
            'package installation', 'system update', 'maintenance',
            'backup', 'scheduled', 'systemd', 'cron', 'logrotate',
            'apt install', 'apt-get', 'dpkg', 'yum install', 'dnf install'
        ]
        
        combined_text = f"{message} {command}".lower()
        return any(indicator in combined_text for indicator in legitimate_indicators)

    def _is_legitimate_suid_usage(self, message: str, binary: str) -> bool:
        """Check if SUID binary usage appears legitimate based on context."""
        message_lower = message.lower()
        
        # Package management contexts (most common legitimate usage)
        package_contexts = [
            'apt install', 'apt-get install', 'dpkg', 'yum install', 
            'dnf install', 'pip install', 'npm install', 'gem install',
            'cargo install', 'package installation', 'software installation'
        ]
        
        # System operation contexts
        system_contexts = [
            'systemd', 'cron', 'logrotate', 'backup', 'maintenance',
            'system update', 'scheduled task', 'system service',
            'startup script', 'init script', 'service script'
        ]
        
        # Check for package management (very high confidence of legitimacy)
        for context in package_contexts:
            if context in message_lower:
                return True
        
        # Check for system operations
        for context in system_contexts:
            if context in message_lower:
                return True
        
        # Specific binary legitimacy checks
        if binary == 'gawk':
            # gawk is commonly used in package scripts and system operations
            if any(indicator in message_lower for indicator in [
                'sed', 'grep', 'awk', 'package', 'install', 'script', 'configure'
            ]):
                return True
        
        if binary in ['mount', 'umount']:
            # Mount/umount in system contexts
            if any(indicator in message_lower for indicator in [
                'filesystem', 'boot', 'system', 'fstab', 'systemd'
            ]):
                return True
        
        if binary == 'systemctl':
            # systemctl in service management contexts
            if any(indicator in message_lower for indicator in [
                'service', 'daemon', 'enable', 'disable', 'start', 'stop'
            ]):
                return True
        
        return False
