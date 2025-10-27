"""
Account Management IoC Category for IoC-Hunter Linux

Detects suspicious account management activities including user lifecycle events,
group modifications, authentication failures, and system account abuse.

This category implements correlation analysis to identify account-based attack patterns
and persistence mechanisms through account manipulation.

Python 3.9+ compatible.
"""

import re
import logging
import os
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Set
from collections import defaultdict, Counter
from pathlib import Path

from ..core.base_category import BaseIoCCategory, IoCEvent
from ..utils.helpers import extract_ip_addresses, run_system_command, check_command_availability


class AccountManagement(BaseIoCCategory):
    """
    Account Management Detection Category.
    
    Detects:
    - User lifecycle events (creation, modification, deletion)
    - Group management and membership changes
    - Authentication failures and brute force attacks
    - Password policy violations and suspicious changes
    - System account abuse and privilege escalation
    - Shadow file modifications
    - Login shell changes for persistence
    - Unusual home directory creation patterns
    """
    
    # Required class attributes for auto-discovery
    name = "account_management"
    display_name = "Account Management Activity"
    description = "Detects user lifecycle, group changes, authentication failures and account-based attack patterns"
    version = "1.0.0"
    tier = 1  # Tier 1 = Critical (included in quick scans)
    
    def __init__(self, config_manager=None, log_sources=None):
        super().__init__(config_manager, log_sources)
        
        # Load account management patterns and thresholds
        self.patterns = self.get_patterns()
        self.thresholds = self.patterns.get("thresholds", {
            "brute_force_threshold": 5,
            "brute_force_window_minutes": 10,
            "rapid_account_creation_threshold": 3,
            "rapid_account_window_minutes": 5,
            "auth_failure_threshold": 10
        })
        
        # Debug pattern loading
        if self.patterns:
            pattern_types = self.patterns.get("patterns", {})
            self.logger.info(f"Loaded {len(pattern_types)} pattern types: {list(pattern_types.keys())}")
        else:
            self.logger.warning("No patterns loaded from configuration")
        
        # Tracking for correlation analysis
        self.user_events = defaultdict(list)  # user -> list of (timestamp, event_type, details)
        self.auth_failures = defaultdict(list)  # source_ip -> list of (timestamp, user, details)
        self.group_changes = defaultdict(list)  # user -> list of (timestamp, group, operation)
        self.password_events = defaultdict(list)  # user -> list of timestamps
        self.shell_changes = defaultdict(list)  # user -> list of (timestamp, old_shell, new_shell)
        self.account_timeline = []  # All account events for correlation
        
        # Track suspicious activity patterns
        self.failed_users_per_ip = defaultdict(set)  # ip -> set of usernames attempted
        self.privileged_groups = {'root', 'sudo', 'wheel', 'admin', 'adm', 'staff'}
        
        self.logger.info(f"Initialized Account Management scanner")
    
    def get_required_log_sources(self) -> List[str]:
        """Account management requires auth logs and journald."""
        return ["auth_log", "journald"]
    
    def get_supported_log_sources(self) -> List[str]:
        """Account management can use multiple log sources."""
        return ["auth_log", "journald", "syslog_file"]
    
    def scan(self, begin_time: datetime, end_time: datetime) -> List[IoCEvent]:
        """
        Scan for account management activity within time range.
        
        Args:
            begin_time: Start of scan window
            end_time: End of scan window
            
        Returns:
            List of account management IoC events
        """
        scan_start = datetime.now()
        events = []
        processed_count = 0
        
        self.logger.info(f"Scanning account management activity from {begin_time} to {end_time}")
        
        # Define filters for account management logs
        account_filters = {
            "keywords": ["user", "group", "passwd", "login", "auth", "shadow", "useradd", "usermod", "userdel"],
            "exclude_noise": True
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
                filters=account_filters
            )
            
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
                
                # Detect different types of account management events
                detected_events = []
                
                # 1. User lifecycle events
                user_events = self._detect_user_lifecycle(timestamp, message, source, entry)
                detected_events.extend(user_events)
                
                # 2. Group management events
                group_events = self._detect_group_changes(timestamp, message, source, entry)
                detected_events.extend(group_events)
                
                # 3. Authentication failures and brute force
                auth_events = self._detect_authentication_failures(timestamp, message, source, entry)
                detected_events.extend(auth_events)
                
                # 4. Password policy violations
                password_events = self._detect_password_events(timestamp, message, source, entry)
                detected_events.extend(password_events)
                
                # 5. Shadow file monitoring (enhanced feature)
                shadow_events = self._detect_shadow_file_changes(timestamp, message, source, entry)
                detected_events.extend(shadow_events)
                
                # 6. Login shell changes (enhanced feature)
                shell_events = self._detect_shell_changes(timestamp, message, source, entry)
                detected_events.extend(shell_events)
                
                # 7. Home directory creation patterns (enhanced feature)
                home_dir_events = self._detect_home_directory_events(timestamp, message, source, entry)
                detected_events.extend(home_dir_events)
                
                # Add all detected events and track for correlation
                for event in detected_events:
                    events.append(event)
                    self._track_for_correlation(event)
            
            # Perform correlation analysis
            correlation_events = self._perform_correlation_analysis(begin_time, end_time)
            events.extend(correlation_events)
            
            scan_duration = (datetime.now() - scan_start).total_seconds()
            self.logger.info(f"Account management scan completed: {len(events)} events found, "
                           f"{processed_count} entries processed in {scan_duration:.2f}s")
            
            return events
            
        except Exception as e:
            self.logger.error(f"Error during account management scan: {e}")
            return events
    
    def _detect_user_lifecycle(self, timestamp: datetime, message: str, source: str, entry) -> List[IoCEvent]:
        """Detect user creation, modification, and deletion events."""
        events = []
        
        # Get user lifecycle patterns
        creation_patterns = self.patterns.get("patterns", {}).get("user_creation", [])
        modification_patterns = self.patterns.get("patterns", {}).get("user_modification", [])
        
        user = self._extract_user_from_message(message)
        target_user = self._extract_target_user_from_message(message)
        
        # Check for user creation
        for pattern in creation_patterns:
            if pattern.lower() in message.lower():
                severity = "HIGH"
                event_type = "user_creation"
                
                # Check if system account is being created
                if target_user in self.patterns.get("patterns", {}).get("suspicious_users", []):
                    severity = "HIGH"
                    details = f"Suspicious system account '{target_user}' created by {user}"
                else:
                    details = f"New user account '{target_user}' created by {user}"
                
                # Extract additional details
                uid_match = re.search(r'uid[=:](\d+)', message)
                gid_match = re.search(r'gid[=:](\d+)', message)
                home_match = re.search(r'home[=:]([^\s,]+)', message)
                
                event = IoCEvent(
                    timestamp=timestamp,
                    category=self.name,
                    severity=severity,
                    source=source,
                    event_type=event_type,
                    details=details,
                    raw_log=entry.raw_line,
                    metadata={
                        'acting_user': user,
                        'target_user': target_user,
                        'uid': uid_match.group(1) if uid_match else None,
                        'gid': gid_match.group(1) if gid_match else None,
                        'home_directory': home_match.group(1) if home_match else None,
                        'pattern_matched': pattern,
                        'is_system_account': target_user in self.patterns.get("patterns", {}).get("suspicious_users", [])
                    }
                )
                
                events.append(event)
                
                # Track for correlation
                self.user_events[target_user].append((timestamp, 'creation', details))
                
                break
        
        # Check for user modification
        for pattern in modification_patterns:
            if pattern.lower() in message.lower():
                severity = "MEDIUM"
                event_type = "user_modification"
                
                details = f"User account '{target_user}' modified by {user}"
                
                # Check for privilege escalation via usermod
                if "usermod" in message.lower() and any(group in message.lower() for group in self.privileged_groups):
                    severity = "HIGH"
                    event_type = "privilege_escalation_usermod"
                    details += " - privileged group assignment detected"
                
                event = IoCEvent(
                    timestamp=timestamp,
                    category=self.name,
                    severity=severity,
                    source=source,
                    event_type=event_type,
                    details=details,
                    raw_log=entry.raw_line,
                    metadata={
                        'acting_user': user,
                        'target_user': target_user,
                        'pattern_matched': pattern,
                        'modification_type': self._extract_modification_type(message)
                    }
                )
                
                events.append(event)
                
                # Track for correlation
                self.user_events[target_user].append((timestamp, 'modification', details))
                
                break
        
        # Check for user deletion
        if any(pattern in message.lower() for pattern in ["userdel", "user deleted", "account removed"]):
            severity = "MEDIUM"
            event_type = "user_deletion"
            
            details = f"User account '{target_user}' deleted by {user}"
            
            event = IoCEvent(
                timestamp=timestamp,
                category=self.name,
                severity=severity,
                source=source,
                event_type=event_type,
                details=details,
                raw_log=entry.raw_line,
                metadata={
                    'acting_user': user,
                    'target_user': target_user,
                    'deletion_type': 'userdel' if 'userdel' in message.lower() else 'other'
                }
            )
            
            events.append(event)
            
            # Track for correlation
            self.user_events[target_user].append((timestamp, 'deletion', details))
        
        return events
    
    def _detect_group_changes(self, timestamp: datetime, message: str, source: str, entry) -> List[IoCEvent]:
        """Detect group creation, modification, and membership changes."""
        events = []
        
        # Get group change patterns
        group_patterns = self.patterns.get("patterns", {}).get("group_changes", [])
        
        user = self._extract_user_from_message(message)
        target_user = self._extract_target_user_from_message(message)
        
        for pattern in group_patterns:
            if pattern.lower() in message.lower():
                severity = "MEDIUM"
                event_type = "group_modification"
                
                # Extract group name
                group_name = self._extract_group_from_message(message)
                
                # Check if privileged group
                if group_name in self.privileged_groups:
                    severity = "HIGH"
                    event_type = "privileged_group_modification"
                
                if "added to group" in message.lower():
                    details = f"User '{target_user}' added to group '{group_name}' by {user}"
                    operation = "add"
                elif "removed from group" in message.lower():
                    details = f"User '{target_user}' removed from group '{group_name}' by {user}"
                    operation = "remove"
                elif "groupadd" in message.lower():
                    details = f"New group '{group_name}' created by {user}"
                    operation = "create"
                else:
                    details = f"Group '{group_name}' modified by {user}"
                    operation = "modify"
                
                event = IoCEvent(
                    timestamp=timestamp,
                    category=self.name,
                    severity=severity,
                    source=source,
                    event_type=event_type,
                    details=details,
                    raw_log=entry.raw_line,
                    metadata={
                        'acting_user': user,
                        'target_user': target_user,
                        'group_name': group_name,
                        'operation': operation,
                        'is_privileged_group': group_name in self.privileged_groups,
                        'pattern_matched': pattern
                    }
                )
                
                events.append(event)
                
                # Track for correlation
                self.group_changes[target_user].append((timestamp, group_name, operation))
                
                break
        
        return events
    
    def _detect_authentication_failures(self, timestamp: datetime, message: str, source: str, entry) -> List[IoCEvent]:
        """Detect authentication failures and potential brute force attacks."""
        events = []
        
        # Look for authentication failure indicators
        failure_indicators = [
            "authentication failure", "failed login", "invalid user", "login incorrect",
            "failed password", "authentication failed", "login failed", "bad password"
        ]
        
        for indicator in failure_indicators:
            if indicator.lower() in message.lower():
                severity = "MEDIUM"
                event_type = "authentication_failure"
                
                user = self._extract_user_from_message(message)
                source_ip = self._extract_ip_from_message(message)
                
                details = f"Authentication failure for user '{user}'"
                if source_ip:
                    details += f" from {source_ip}"
                
                # Track failed attempts for brute force detection
                if source_ip:
                    self.auth_failures[source_ip].append((timestamp, user, details))
                    self.failed_users_per_ip[source_ip].add(user)
                    
                    # Check for immediate brute force patterns
                    recent_failures = [
                        (ts, u, d) for ts, u, d in self.auth_failures[source_ip]
                        if (timestamp - ts).total_seconds() <= self.thresholds["brute_force_window_minutes"] * 60
                    ]
                    
                    if len(recent_failures) >= self.thresholds["brute_force_threshold"]:
                        severity = "HIGH"
                        event_type = "brute_force_attack"
                        details = f"Brute force attack detected from {source_ip}: {len(recent_failures)} failures in {self.thresholds['brute_force_window_minutes']} minutes"
                
                event = IoCEvent(
                    timestamp=timestamp,
                    category=self.name,
                    severity=severity,
                    source=source,
                    event_type=event_type,
                    details=details,
                    raw_log=entry.raw_line,
                    metadata={
                        'user': user,
                        'source_ip': source_ip,
                        'indicator_matched': indicator,
                        'recent_failure_count': len(recent_failures) if source_ip else 0
                    }
                )
                
                events.append(event)
                break
        
        return events
    
    def _detect_password_events(self, timestamp: datetime, message: str, source: str, entry) -> List[IoCEvent]:
        """Detect password changes and policy violations."""
        events = []
        
        user = self._extract_user_from_message(message)
        target_user = self._extract_target_user_from_message(message)
        
        # Look for password change events
        password_indicators = [
            "password changed", "password updated", "password set", "passwd:",
            "password expired", "password policy", "weak password"
        ]
        
        for indicator in password_indicators:
            if indicator.lower() in message.lower():
                severity = "MEDIUM"
                event_type = "password_change"
                
                # Check for root password changes
                if target_user == "root" or "root" in message.lower():
                    severity = "HIGH"
                    event_type = "root_password_change"
                    details = f"Root password changed by {user}"
                else:
                    details = f"Password changed for user '{target_user}' by {user}"
                
                # Check for policy violations
                if "weak password" in message.lower() or "password policy" in message.lower():
                    severity = "HIGH"
                    event_type = "password_policy_violation"
                    details = f"Password policy violation for user '{target_user}'"
                
                event = IoCEvent(
                    timestamp=timestamp,
                    category=self.name,
                    severity=severity,
                    source=source,
                    event_type=event_type,
                    details=details,
                    raw_log=entry.raw_line,
                    metadata={
                        'acting_user': user,
                        'target_user': target_user,
                        'indicator_matched': indicator,
                        'is_root_change': target_user == "root"
                    }
                )
                
                events.append(event)
                
                # Track for correlation
                self.password_events[target_user].append(timestamp)
                
                break
        
        return events
    
    def _detect_shadow_file_changes(self, timestamp: datetime, message: str, source: str, entry) -> List[IoCEvent]:
        """Detect direct shadow file modifications (enhanced feature)."""
        events = []
        
        # Look for shadow file access patterns
        shadow_indicators = [
            "/etc/shadow", "shadow file", "shadow modified", "vipw", "pwconv", "pwunconv"
        ]
        
        user = self._extract_user_from_message(message)
        
        for indicator in shadow_indicators:
            if indicator.lower() in message.lower():
                severity = "HIGH"
                event_type = "shadow_file_modification"
                
                if "vipw" in message.lower():
                    details = f"Shadow file accessed via vipw by {user}"
                    access_method = "vipw"
                elif "/etc/shadow" in message.lower():
                    details = f"Direct shadow file access by {user}"
                    access_method = "direct"
                else:
                    details = f"Shadow file modification detected: {indicator}"
                    access_method = "other"
                
                event = IoCEvent(
                    timestamp=timestamp,
                    category=self.name,
                    severity=severity,
                    source=source,
                    event_type=event_type,
                    details=details,
                    raw_log=entry.raw_line,
                    metadata={
                        'user': user,
                        'indicator_matched': indicator,
                        'access_method': access_method
                    }
                )
                
                events.append(event)
                break
        
        return events
    
    def _detect_shell_changes(self, timestamp: datetime, message: str, source: str, entry) -> List[IoCEvent]:
        """Detect login shell changes for persistence (enhanced feature)."""
        events = []
        
        user = self._extract_user_from_message(message)
        target_user = self._extract_target_user_from_message(message)
        
        # Look for shell change patterns
        if "usermod" in message.lower() and ("-s" in message or "--shell" in message):
            severity = "MEDIUM"
            event_type = "login_shell_change"
            
            # Extract old and new shell
            shell_match = re.search(r'-s\s+([^\s]+)', message)
            new_shell = shell_match.group(1) if shell_match else "unknown"
            
            details = f"Login shell changed for user '{target_user}' to '{new_shell}' by {user}"
            
            # Flag suspicious shell changes
            suspicious_shells = ["/bin/false", "/usr/sbin/nologin", "/bin/true"]
            if new_shell in suspicious_shells:
                severity = "HIGH"
                details += " - potentially disabling account"
            elif new_shell in ["/bin/bash", "/bin/sh", "/bin/zsh"]:
                # Check if this is re-enabling a previously disabled account
                recent_changes = [
                    (ts, old, new) for ts, old, new in self.shell_changes[target_user]
                    if (timestamp - ts).total_seconds() <= 3600  # Within last hour
                ]
                if any(old in suspicious_shells for ts, old, new in recent_changes):
                    severity = "HIGH"
                    details += " - potentially re-enabling disabled account"
            
            event = IoCEvent(
                timestamp=timestamp,
                category=self.name,
                severity=severity,
                source=source,
                event_type=event_type,
                details=details,
                raw_log=entry.raw_line,
                metadata={
                    'acting_user': user,
                    'target_user': target_user,
                    'new_shell': new_shell,
                    'is_suspicious_shell': new_shell in suspicious_shells
                }
            )
            
            events.append(event)
            
            # Track for correlation
            self.shell_changes[target_user].append((timestamp, "unknown", new_shell))
        
        return events
    
    def _detect_home_directory_events(self, timestamp: datetime, message: str, source: str, entry) -> List[IoCEvent]:
        """Detect unusual home directory creation patterns (enhanced feature)."""
        events = []
        
        user = self._extract_user_from_message(message)
        
        # Look for home directory creation in unusual locations
        home_patterns = [
            r'/tmp/[^/]+',     # Home in /tmp
            r'/var/tmp/[^/]+', # Home in /var/tmp
            r'/dev/shm/[^/]+', # Home in shared memory
            r'/usr/[^/]+',     # Home in /usr
            r'/opt/[^/]+',     # Home in /opt
            r'/var/www/[^/]+'  # Home in web directory
        ]
        
        for pattern in home_patterns:
            if re.search(pattern, message):
                severity = "HIGH"
                event_type = "suspicious_home_directory"
                
                home_match = re.search(pattern, message)
                suspicious_home = home_match.group(0) if home_match else "unknown"
                
                details = f"User home directory created in suspicious location: {suspicious_home} by {user}"
                
                event = IoCEvent(
                    timestamp=timestamp,
                    category=self.name,
                    severity=severity,
                    source=source,
                    event_type=event_type,
                    details=details,
                    raw_log=entry.raw_line,
                    metadata={
                        'user': user,
                        'suspicious_home': suspicious_home,
                        'pattern_matched': pattern
                    }
                )
                
                events.append(event)
                break
        
        return events
    
    def _track_for_correlation(self, event: IoCEvent) -> None:
        """Track events for correlation analysis."""
        self.account_timeline.append({
            'timestamp': event.timestamp,
            'user': event.metadata.get('target_user', event.metadata.get('user', 'unknown')),
            'event_type': event.event_type,
            'severity': event.severity,
            'details': event.details,
            'source_ip': event.metadata.get('source_ip')
        })
    
    def _perform_correlation_analysis(self, begin_time: datetime, end_time: datetime) -> List[IoCEvent]:
        """Analyze tracked events for account-based attack patterns."""
        events = []
        
        # Sort timeline by timestamp
        self.account_timeline.sort(key=lambda x: x['timestamp'])
        
        # 1. Detect rapid account creation
        events.extend(self._detect_rapid_account_creation(begin_time, end_time))
        
        # 2. Detect user enumeration attacks
        events.extend(self._detect_user_enumeration(begin_time, end_time))
        
        # 3. Detect privilege escalation through group membership
        events.extend(self._detect_group_privilege_escalation(begin_time, end_time))
        
        return events
    
    def _detect_rapid_account_creation(self, begin_time: datetime, end_time: datetime) -> List[IoCEvent]:
        """Detect rapid account creation patterns."""
        events = []
        
        # Find account creation events within time window
        creation_events = [
            event for event in self.account_timeline
            if event['event_type'] == 'user_creation' and begin_time <= event['timestamp'] <= end_time
        ]
        
        if len(creation_events) >= self.thresholds["rapid_account_creation_threshold"]:
            # Group by time windows
            window_minutes = self.thresholds["rapid_account_window_minutes"]
            window_delta = timedelta(minutes=window_minutes)
            
            for i, start_event in enumerate(creation_events[:-1]):
                window_events = [start_event]
                start_time = start_event['timestamp']
                end_window = start_time + window_delta
                
                # Collect events within window
                for next_event in creation_events[i+1:]:
                    if next_event['timestamp'] <= end_window:
                        window_events.append(next_event)
                    else:
                        break
                
                if len(window_events) >= self.thresholds["rapid_account_creation_threshold"]:
                    severity = "HIGH"
                    event_type = "rapid_account_creation"
                    
                    usernames = [e['user'] for e in window_events]
                    details = (f"Rapid account creation detected: {len(window_events)} accounts created "
                             f"in {window_minutes} minutes ({', '.join(usernames)})")
                    
                    event = IoCEvent(
                        timestamp=start_time,
                        category=self.name,
                        severity=severity,
                        source="correlation_analysis",
                        event_type=event_type,
                        details=details,
                        raw_log=None,
                        metadata={
                            'account_count': len(window_events),
                            'time_window_minutes': window_minutes,
                            'usernames': usernames,
                            'pattern': 'rapid_creation'
                        }
                    )
                    
                    events.append(event)
                    break  # Avoid overlapping correlations
        
        return events
    
    def _detect_user_enumeration(self, begin_time: datetime, end_time: datetime) -> List[IoCEvent]:
        """Detect user enumeration through failed authentication attempts."""
        events = []
        
        # Analyze failed attempts per IP
        for source_ip, users_attempted in self.failed_users_per_ip.items():
            if len(users_attempted) >= 5:  # Threshold for enumeration
                severity = "HIGH"
                event_type = "user_enumeration"
                
                details = (f"User enumeration detected from {source_ip}: "
                         f"{len(users_attempted)} different usernames attempted "
                         f"({', '.join(list(users_attempted)[:5])}{'...' if len(users_attempted) > 5 else ''})")
                
                # Find the first failure event from this IP in the time window
                first_event_time = None
                for timestamp, user, _ in self.auth_failures[source_ip]:
                    if begin_time <= timestamp <= end_time:
                        first_event_time = timestamp
                        break
                
                if first_event_time:
                    event = IoCEvent(
                        timestamp=first_event_time,
                        category=self.name,
                        severity=severity,
                        source="correlation_analysis",
                        event_type=event_type,
                        details=details,
                        raw_log=None,
                        metadata={
                            'source_ip': source_ip,
                            'users_attempted': list(users_attempted),
                            'enumeration_count': len(users_attempted),
                            'pattern': 'user_enumeration'
                        }
                    )
                    
                    events.append(event)
        
        return events
    
    def _detect_group_privilege_escalation(self, begin_time: datetime, end_time: datetime) -> List[IoCEvent]:
        """Detect privilege escalation through group membership changes."""
        events = []
        
        # Look for users added to privileged groups
        for user, group_changes in self.group_changes.items():
            privileged_additions = [
                (ts, group, op) for ts, group, op in group_changes
                if op == 'add' and group in self.privileged_groups and begin_time <= ts <= end_time
            ]
            
            if privileged_additions:
                for timestamp, group, operation in privileged_additions:
                    severity = "HIGH"
                    event_type = "group_privilege_escalation"
                    
                    details = f"Privilege escalation detected: user '{user}' added to privileged group '{group}'"
                    
                    event = IoCEvent(
                        timestamp=timestamp,
                        category=self.name,
                        severity=severity,
                        source="correlation_analysis",
                        event_type=event_type,
                        details=details,
                        raw_log=None,
                        metadata={
                            'user': user,
                            'group': group,
                            'operation': operation,
                            'is_privileged_group': True,
                            'pattern': 'group_privilege_escalation'
                        }
                    )
                    
                    events.append(event)
        
        return events
    
    def _extract_user_from_message(self, message: str) -> str:
        """Extract username from log message."""
        patterns = [
            r'user=([^\s,]+)',
            r'USER=([^\s,]+)',
            r'for user ([^\s,]+)',
            r'by user ([^\s,]+)',
            r'([^\s]+)@',
            r'uid=\d+\(([^)]+)\)',
            r'\s([a-z_][a-z0-9_]{0,30})\s'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, message)
            if match:
                user = match.group(1)
                if user not in ['root', 'user', 'for', 'by'] or user == 'root':
                    return user
        
        return 'unknown'
    
    def _extract_target_user_from_message(self, message: str) -> str:
        """Extract target username from user management messages."""
        patterns = [
            r'useradd\s+([^\s]+)',
            r'userdel\s+([^\s]+)',
            r'usermod.*?([a-z_][a-z0-9_]{0,30})',
            r'for\s+([a-z_][a-z0-9_]{0,30})',
            r'user\s+([a-z_][a-z0-9_]{0,30})',
            r'account\s+([a-z_][a-z0-9_]{0,30})'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, message)
            if match:
                return match.group(1)
        
        return self._extract_user_from_message(message)
    
    def _extract_group_from_message(self, message: str) -> str:
        """Extract group name from group management messages."""
        patterns = [
            r'groupadd\s+([^\s]+)',
            r'group\s+([a-z_][a-z0-9_]{0,30})',
            r'added to group\s+([^\s]+)',
            r'removed from group\s+([^\s]+)',
            r'-G\s+([^\s]+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, message)
            if match:
                return match.group(1)
        
        return 'unknown'
    
    def _extract_modification_type(self, message: str) -> str:
        """Extract the type of user modification."""
        if "-s" in message or "--shell" in message:
            return "shell_change"
        elif "-G" in message or "--groups" in message:
            return "group_membership"
        elif "-d" in message or "--home" in message:
            return "home_directory"
        elif "-u" in message or "--uid" in message:
            return "uid_change"
        else:
            return "unknown"
    
    def _extract_ip_from_message(self, message: str) -> Optional[str]:
        """Extract IP address from log message."""
        ips = extract_ip_addresses(message)
        return ips[0] if ips else None
