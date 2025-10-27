"""
SSH Activity IoC Category for IoC-Hunter Linux

Detects suspicious SSH activity including failed logins, brute force attempts,
port forwarding, and unusual authentication patterns.

This is the first concrete IoC category implementation, demonstrating the
extensible architecture. Priority #1 for blue team exercises.

Python 3.9+ compatible.
"""

import re
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from collections import defaultdict, Counter

from ..core.base_category import BaseIoCCategory, IoCEvent
from ..utils.helpers import extract_ip_addresses


class SSHActivity(BaseIoCCategory):
    """.
    
    Detects:
    - Failed login attempts and brute force attacks
    - Successful logins after multiple failures  
    - SSH port forwarding and tunneling
    - Invalid user attempts
    - Unusual authentication patterns
    - Suspicious SSH client behavior
    """
    
    # Required class attributes for auto-discovery
    name = "ssh_activity"
    display_name = "SSH Suspicious Activity" 
    description = "Detects SSH brute force, port forwarding, and suspicious authentication activity"
    version = "1.0.0"
    tier = 1  # Tier 1 = Critical (included in quick scans)
    
    def __init__(self, config_manager=None, log_sources=None):
        super().__init__(config_manager, log_sources)
        
        # Load SSH-specific patterns and thresholds
        self.patterns = self.get_patterns()
        self.thresholds = self.patterns.get("thresholds", {})
        
        # Tracking for correlation analysis
        self.failed_attempts = defaultdict(list)  # IP -> list of timestamps
        self.successful_logins = defaultdict(list)  # IP -> list of timestamps
        self.user_attempts = defaultdict(Counter)  # IP -> Counter of usernames
        
        self.logger.info(f"Initialized SSH Activity scanner with {len(self.patterns)} pattern categories")
    
    def get_required_log_sources(self) -> List[str]:
        """SSH activity requires authentication logs and journald."""
        return ["auth_log", "journald"]
    
    def get_supported_log_sources(self) -> List[str]:
        """SSH can use multiple log sources."""
        return ["auth_log", "journald", "syslog_file"]
    
    def scan(self, begin_time: datetime, end_time: datetime) -> List[IoCEvent]:
        """
        Scan for SSH suspicious activity within time range.
        
        Args:
            begin_time: Start of scan window
            end_time: End of scan window
            
        Returns:
            List of SSH-related IoC events
        """
        scan_start = datetime.now()
        events = []
        processed_count = 0
        
        self.logger.info(f"Scanning SSH activity from {begin_time} to {end_time}")
        
        # Get SSH-related log entries
        ssh_filters = {
            "service": "ssh",
            "unit": "ssh.service"
        }
        
        try:
            # Ensure log sources are available
            if not self.log_sources:
                self.logger.error("Log sources not initialized")
                return []
            
            # Get entries from log sources
            log_entries = self.log_sources.get_entries(
                begin_time=begin_time,
                end_time=end_time,
                sources=self.get_required_log_sources(),
                filters=ssh_filters
            )
            
            # Process each log entry
            for entry in log_entries:
                processed_count += 1
                
                # Analyze the log entry for SSH indicators
                ssh_events = self._analyze_ssh_entry(entry)
                events.extend(ssh_events)
                
                # Update correlation tracking
                self._update_tracking(entry, ssh_events)
            
            # Perform correlation analysis
            correlation_events = self._perform_correlation_analysis(begin_time, end_time)
            events.extend(correlation_events)
            
        except Exception as e:
            self.logger.error(f"Error scanning SSH activity: {e}")
            raise
        
        # Update metrics
        scan_duration = (datetime.now() - scan_start).total_seconds()
        self.update_metrics(processed_count, len(events), scan_duration)
        
        self.logger.info(f"SSH scan complete: {len(events)} events found, {processed_count} entries processed")
        
        return events
    
    def _analyze_ssh_entry(self, log_entry) -> List[IoCEvent]:
        """
        Analyze a single log entry for SSH indicators.
        
        Args:
            log_entry: LogEntry object to analyze
            
        Returns:
            List of IoC events found in this entry
        """
        events = []
        message = log_entry.message.lower()
        raw_message = log_entry.raw_line
        
        # Extract metadata
        source_ip = self._extract_source_ip(raw_message)
        username = self._extract_username(raw_message)
        
        # Check for failed login attempts
        if self._is_failed_login(message):
            event_type = "failed_login"
            
            # Determine severity based on context
            if self._is_invalid_user(message):
                event_type = "invalid_user_attempt"
                severity = "MEDIUM" 
            elif self._is_repeated_failure(source_ip):
                event_type = "repeated_failed_login"
                severity = "HIGH"
            else:
                severity = "MEDIUM"
            
            details = f"SSH failed login attempt"
            if username:
                details += f" for user '{username}'"
            if source_ip:
                details += f" from {source_ip}"
            
            event = self.create_event(
                timestamp=log_entry.timestamp,
                event_type=event_type,
                details=details,
                source=log_entry.source,
                raw_log=raw_message,
                severity=severity,
                metadata={
                    "source_ip": source_ip,
                    "username": username,
                    "ssh_event_type": "authentication_failure"
                }
            )
            events.append(event)
        
        # Check for successful logins
        elif self._is_successful_login(message):
            event_type = "successful_login"
            severity = "LOW"  # Default to low
            
            # Check if this follows recent failures (suspicious)
            if source_ip and self._has_recent_failures(source_ip):
                event_type = "successful_login_after_failures"
                severity = "HIGH"
            
            details = f"SSH successful login"
            if username:
                details += f" for user '{username}'"
            if source_ip:
                details += f" from {source_ip}"
            
            event = self.create_event(
                timestamp=log_entry.timestamp,
                event_type=event_type,
                details=details,
                source=log_entry.source,
                raw_log=raw_message,
                severity=severity,
                metadata={
                    "source_ip": source_ip,
                    "username": username,
                    "ssh_event_type": "authentication_success"
                }
            )
            events.append(event)
        
        # Check for port forwarding / tunneling
        elif self._is_port_forwarding(message):
            details = f"SSH port forwarding detected"
            if source_ip:
                details += f" from {source_ip}"
            
            event = self.create_event(
                timestamp=log_entry.timestamp,
                event_type="port_forwarding",
                details=details,
                source=log_entry.source,
                raw_log=raw_message,
                severity="HIGH",
                metadata={
                    "source_ip": source_ip,
                    "username": username,
                    "ssh_event_type": "port_forwarding"
                }
            )
            events.append(event)
        
        # Check for connection anomalies
        elif self._is_connection_anomaly(message):
            event_type = "connection_anomaly"
            
            if "did not receive identification" in message:
                event_type = "no_identification_string"
                severity = "MEDIUM"
            elif "connection closed" in message and "authenticating" in message:
                event_type = "authentication_timeout"
                severity = "MEDIUM"
            else:
                severity = "LOW"
            
            details = f"SSH connection anomaly: {self._extract_anomaly_details(message)}"
            if source_ip:
                details += f" from {source_ip}"
            
            event = self.create_event(
                timestamp=log_entry.timestamp,
                event_type=event_type,
                details=details,
                source=log_entry.source,
                raw_log=raw_message,
                severity=severity,
                metadata={
                    "source_ip": source_ip,
                    "ssh_event_type": "connection_anomaly"
                }
            )
            events.append(event)
        
        return events
    
    def _perform_correlation_analysis(self, begin_time: datetime, end_time: datetime) -> List[IoCEvent]:
        """
        Perform correlation analysis to detect attack patterns.
        
        Args:
            begin_time: Start of analysis window
            end_time: End of analysis window
            
        Returns:
            List of correlation-based IoC events
        """
        events = []
        
        # Analyze brute force patterns
        brute_force_events = self._detect_brute_force_attacks(begin_time, end_time)
        events.extend(brute_force_events)
        
        # Analyze user enumeration
        enumeration_events = self._detect_user_enumeration(begin_time, end_time)
        events.extend(enumeration_events)
        
        return events
    
    def _detect_brute_force_attacks(self, begin_time: datetime, end_time: datetime) -> List[IoCEvent]:
        """Detect brute force attack patterns."""
        events = []
        threshold = self.thresholds.get("brute_force_threshold", 10)
        window_minutes = self.thresholds.get("brute_force_window_minutes", 10)
        
        for source_ip, timestamps in self.failed_attempts.items():
            # Count failures in the window
            window_start = end_time - timedelta(minutes=window_minutes)
            recent_failures = [ts for ts in timestamps if window_start <= ts <= end_time]
            
            if len(recent_failures) >= threshold:
                event = self.create_event(
                    timestamp=max(recent_failures),
                    event_type="brute_force_attack",
                    details=f"SSH brute force attack detected: {len(recent_failures)} failed attempts from {source_ip} in {window_minutes} minutes",
                    source="correlation_analysis",
                    severity="HIGH",
                    metadata={
                        "source_ip": source_ip,
                        "failure_count": len(recent_failures),
                        "time_window_minutes": window_minutes,
                        "attack_pattern": "brute_force"
                    }
                )
                events.append(event)
        
        return events
    
    def _detect_user_enumeration(self, begin_time: datetime, end_time: datetime) -> List[IoCEvent]:
        """Detect user enumeration attempts."""
        events = []
        
        for source_ip, user_counter in self.user_attempts.items():
            # Check for attempts against many different users
            if len(user_counter) >= 5:  # 5+ different usernames
                total_attempts = sum(user_counter.values())
                
                event = self.create_event(
                    timestamp=end_time,
                    event_type="user_enumeration",
                    details=f"SSH user enumeration detected: {total_attempts} attempts against {len(user_counter)} users from {source_ip}",
                    source="correlation_analysis",
                    severity="HIGH",
                    metadata={
                        "source_ip": source_ip,
                        "unique_users": len(user_counter),
                        "total_attempts": total_attempts,
                        "attempted_users": list(user_counter.keys()),
                        "attack_pattern": "user_enumeration"
                    }
                )
                events.append(event)
        
        return events
    
    def _update_tracking(self, log_entry, events: List[IoCEvent]):
        """Update correlation tracking data."""
        for event in events:
            source_ip = event.metadata.get("source_ip")
            username = event.metadata.get("username")
            
            if source_ip:
                if event.event_type in ["failed_login", "invalid_user_attempt", "repeated_failed_login"]:
                    self.failed_attempts[source_ip].append(event.timestamp)
                    if username:
                        self.user_attempts[source_ip][username] += 1
                elif event.event_type in ["successful_login", "successful_login_after_failures"]:
                    self.successful_logins[source_ip].append(event.timestamp)
    
    def _extract_source_ip(self, message: str) -> Optional[str]:
        """Extract source IP address from SSH log message."""
        ips = extract_ip_addresses(message)
        return ips[0] if ips else None
    
    def _extract_username(self, message: str) -> Optional[str]:
        """Extract username from SSH log message."""
        # Common SSH log patterns for usernames
        patterns = [
            r'user (\w+)',
            r'for (\w+) from',
            r'invalid user (\w+)',
            r'Failed password for (\w+)',
            r'Accepted \w+ for (\w+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, message, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def _is_failed_login(self, message: str) -> bool:
        """Check if message indicates a failed login."""
        failed_patterns = self.patterns.get("patterns", {}).get("failed_login", [])
        return any(pattern.lower() in message for pattern in failed_patterns)
    
    def _is_successful_login(self, message: str) -> bool:
        """Check if message indicates a successful login."""
        success_patterns = self.patterns.get("patterns", {}).get("successful_login", [])
        return any(pattern.lower() in message for pattern in success_patterns)
    
    def _is_port_forwarding(self, message: str) -> bool:
        """Check if message indicates port forwarding."""
        forwarding_patterns = self.patterns.get("patterns", {}).get("suspicious_commands", [])
        return any(pattern.lower() in message for pattern in forwarding_patterns)
    
    def _is_connection_anomaly(self, message: str) -> bool:
        """Check if message indicates connection anomaly."""
        anomaly_indicators = [
            "did not receive identification",
            "connection closed by authenticating user",
            "connection reset",
            "protocol error",
            "bad protocol version"
        ]
        return any(indicator in message for indicator in anomaly_indicators)
    
    def _is_invalid_user(self, message: str) -> bool:
        """Check if message indicates invalid user attempt."""
        return "invalid user" in message
    
    def _is_repeated_failure(self, source_ip: Optional[str]) -> bool:
        """Check if this IP has recent repeated failures."""
        if not source_ip or source_ip not in self.failed_attempts:
            return False
        
        recent_threshold = datetime.now() - timedelta(minutes=5)
        recent_failures = [ts for ts in self.failed_attempts[source_ip] if ts >= recent_threshold]
        return len(recent_failures) >= 3
    
    def _has_recent_failures(self, source_ip: str) -> bool:
        """Check if source IP has recent failed attempts."""
        if source_ip not in self.failed_attempts:
            return False
        
        recent_threshold = datetime.now() - timedelta(minutes=10)
        recent_failures = [ts for ts in self.failed_attempts[source_ip] if ts >= recent_threshold]
        return len(recent_failures) >= 2
    
    def _extract_anomaly_details(self, message: str) -> str:
        """Extract specific details about connection anomaly."""
        if "did not receive identification" in message:
            return "No SSH identification string received"
        elif "connection closed" in message:
            return "Connection closed during authentication"
        elif "protocol error" in message:
            return "SSH protocol error"
        else:
            return "Unknown connection anomaly"
    
    def validate_configuration(self) -> bool:
        """Validate SSH category configuration."""
        required_pattern_keys = ["failed_login", "successful_login", "suspicious_commands"]
        
        for key in required_pattern_keys:
            if key not in self.patterns:
                self.logger.error(f"Missing required pattern category: {key}")
                return False
        
        required_threshold_keys = ["failed_login_count", "brute_force_threshold"]
        thresholds = self.patterns.get("thresholds", {})
        
        for key in required_threshold_keys:
            if key not in thresholds:
                self.logger.warning(f"Missing threshold configuration: {key}, using defaults")
        
        return True


# Category is automatically discovered and registered by the scanner
# Category is automatically registered by the scanner's auto-discovery system
