"""
Service Manipulation IoC Category for IoC-Hunter Linux

Detects suspicious service manipulation activities including systemd service creation,
modification, masking, and timer abuse for persistence and privilege escalation.

This category focuses on modern systemd-based systems and implements detection
for advanced persistence techniques through service manipulation.

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


class ServiceManipulation(BaseIoCCategory):
    """
    Service Manipulation Detection Category.
    
    Detects:
    - New systemd service creation and registration
    - Service modification and configuration changes
    - Critical security service stops and disables
    - Service masking for advanced persistence
    - Systemd timer manipulation and abuse
    - Suspicious service startup patterns
    - Service privilege escalation attempts
    """
    
    # Required class attributes for auto-discovery
    name = "service_manipulation"
    display_name = "Service Manipulation Activity"
    description = "Detects systemd service creation, modification, masking and timer manipulation for persistence"
    version = "1.0.0"
    tier = 1  # Tier 1 = Critical (included in quick scans)
    
    def __init__(self, config_manager=None, log_sources=None):
        super().__init__(config_manager, log_sources)
        
        # Load service manipulation patterns and thresholds
        self.patterns = self.get_patterns()
        self.thresholds = self.patterns.get("thresholds", {
            "rapid_service_changes_threshold": 3,
            "rapid_service_window_minutes": 5,
            "critical_service_threshold": 2
        })
        
        # Debug pattern loading
        if self.patterns:
            pattern_types = self.patterns.get("patterns", {})
            self.logger.info(f"Loaded {len(pattern_types)} pattern types: {list(pattern_types.keys())}")
        else:
            self.logger.warning("No patterns loaded from configuration")
        
        # Tracking for correlation analysis
        self.service_events = defaultdict(list)  # service_name -> list of (timestamp, action, details)
        self.timer_events = defaultdict(list)  # timer_name -> list of (timestamp, action, details)
        self.critical_service_events = []  # List of critical service events
        self.user_service_actions = defaultdict(list)  # user -> list of (timestamp, action, service)
        self.service_timeline = []  # All service events for correlation
        
        # Critical services to monitor
        self.critical_services = set(self.patterns.get("patterns", {}).get("critical_services", [
            "sshd", "systemd-logind", "networking", "firewalld", "iptables", "fail2ban",
            "rsyslog", "systemd-journald", "auditd", "clamav", "apparmor", "selinux"
        ]))
        
        # Suspicious services to flag
        self.suspicious_services = set(self.patterns.get("patterns", {}).get("suspicious_services", [
            "nc", "netcat", "telnet", "rsh", "rlogin", "xinetd"
        ]))
        
        self.logger.info(f"Initialized Service Manipulation scanner")
        self.logger.info(f"Monitoring {len(self.critical_services)} critical services")
    
    def _get_category_name(self) -> str:
        """Get the category name, ensuring it's never None for type safety."""
        return self.name or "service_manipulation"
    
    def get_required_log_sources(self) -> List[str]:
        """Service manipulation requires journald primarily."""
        return ["journald"]
    
    def get_supported_log_sources(self) -> List[str]:
        """Service manipulation can use multiple log sources."""
        return ["journald", "syslog_file", "auth_log"]
    
    def scan(self, begin_time: datetime, end_time: datetime) -> List[IoCEvent]:
        """
        Scan for service manipulation activity within time range.
        
        Args:
            begin_time: Start of scan window
            end_time: End of scan window
            
        Returns:
            List of service manipulation IoC events
        """
        scan_start = datetime.now()
        events = []
        processed_count = 0
        
        self.logger.info(f"Scanning service manipulation activity from {begin_time} to {end_time}")
        
        # Define filters for service manipulation logs
        service_filters = {
            "keywords": ["systemctl", "systemd", "service", "timer", "enable", "disable", "start", "stop", "mask"],
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
                filters=service_filters
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
                
                # Detect different types of service manipulation
                detected_events = []
                
                # 1. Service creation and registration
                creation_events = self._detect_service_creation(timestamp, message, source, entry)
                detected_events.extend(creation_events)
                
                # 2. Service modification and configuration changes
                modification_events = self._detect_service_modification(timestamp, message, source, entry)
                detected_events.extend(modification_events)
                
                # 3. Critical service protection monitoring
                critical_events = self._detect_critical_service_changes(timestamp, message, source, entry)
                detected_events.extend(critical_events)
                
                # 4. Service masking detection
                masking_events = self._detect_service_masking(timestamp, message, source, entry)
                detected_events.extend(masking_events)
                
                # 5. Timer manipulation detection
                timer_events = self._detect_timer_manipulation(timestamp, message, source, entry)
                detected_events.extend(timer_events)
                
                # 6. Suspicious service startup patterns
                startup_events = self._detect_suspicious_service_startup(timestamp, message, source, entry)
                detected_events.extend(startup_events)
                
                # Add all detected events and track for correlation
                for event in detected_events:
                    events.append(event)
                    self._track_for_correlation(event)
            
            # Perform correlation analysis
            correlation_events = self._perform_correlation_analysis(begin_time, end_time)
            events.extend(correlation_events)
            
            scan_duration = (datetime.now() - scan_start).total_seconds()
            self.logger.info(f"Service manipulation scan completed: {len(events)} events found, "
                           f"{processed_count} entries processed in {scan_duration:.2f}s")
            
            return events
            
        except Exception as e:
            self.logger.error(f"Error during service manipulation scan: {e}")
            return events
    
    def _detect_service_creation(self, timestamp: datetime, message: str, source: str, entry) -> List[IoCEvent]:
        """Enhanced service creation detection with context awareness and filtering."""
        events = []
        
        # Get patterns for filtering and context
        patterns_dict = self.patterns.get("patterns", {})
        creation_patterns = patterns_dict.get("service_creation", [])
        ignore_patterns = patterns_dict.get("ignore_patterns", [])
        legitimate_contexts = patterns_dict.get("legitimate_contexts", [])
        high_risk_services = patterns_dict.get("high_risk_services", [])
        medium_risk_services = patterns_dict.get("medium_risk_services", [])
        low_risk_services = patterns_dict.get("low_risk_services", [])
        
        # FIRST: Check if this should be ignored (legitimate system services)
        if self._should_ignore_message(message, ignore_patterns):
            return events
        
        user = self._extract_user_from_message(message)
        service_name = self._extract_service_name_from_message(message)
        
        # Skip if we couldn't extract meaningful service info
        if not service_name or service_name == 'unknown':
            return events
        
        for pattern in creation_patterns:
            if pattern.lower() in message.lower():
                # Check if this is a legitimate service operation
                is_legitimate = (
                    self._has_legitimate_context(message, legitimate_contexts) or
                    self._is_legitimate_service(service_name, message)
                )
                
                # Check if service name matches suspicious patterns (with enhanced matching)
                is_suspicious_service = any(
                    re.search(sus_svc.lower(), service_name.lower()) 
                    for sus_svc in self.suspicious_services
                )
                
                if is_legitimate:
                    severity = "LOW"
                    event_type = "legitimate_service_creation"
                elif is_suspicious_service:
                    # Determine risk level for suspicious services
                    risk_level = self._determine_service_risk(service_name, high_risk_services, medium_risk_services, low_risk_services)
                    severity = risk_level
                    event_type = f"{risk_level.lower()}_risk_suspicious_service"
                else:
                    severity = "MEDIUM"
                    event_type = "service_creation"
                
                if "systemctl enable" in message.lower():
                    details = f"Service '{service_name}' enabled by {user}"
                    action = "enable"
                elif "systemctl start" in message.lower():
                    details = f"Service '{service_name}' started by {user}"
                    action = "start"
                elif "unit file created" in message.lower():
                    details = f"New service unit file created for '{service_name}'"
                    action = "unit_created"
                else:
                    details = f"Service '{service_name}' created/registered by {user}"
                    action = "created"
                
                # Add context information to details
                if is_legitimate:
                    details += " (legitimate system service)"
                
                # Extract service file path if available
                file_path = self._extract_service_file_path(message)
                
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
                        'service_name': service_name,
                        'action': action,
                        'service_file_path': file_path,
                        'is_suspicious_service': is_suspicious_service,
                        'is_legitimate': is_legitimate,  # New field
                        'context_verified': True,  # New field
                        'pattern_matched': pattern,
                        'risk_level': self._determine_service_risk(service_name, high_risk_services, medium_risk_services, low_risk_services).lower() if is_suspicious_service else 'low'
                    }
                )
                
                events.append(event)
                
                # Track for correlation
                self.service_events[service_name].append((timestamp, action, details))
                self.user_service_actions[user].append((timestamp, action, service_name))
                
                break
        
        return events
    
    def _detect_service_modification(self, timestamp: datetime, message: str, source: str, entry) -> List[IoCEvent]:
        """Detect service modification and configuration changes."""
        events = []
        
        # Get service modification patterns
        modification_patterns = self.patterns.get("patterns", {}).get("service_modification", [])
        
        user = self._extract_user_from_message(message)
        service_name = self._extract_service_name_from_message(message)
        
        for pattern in modification_patterns:
            if pattern.lower() in message.lower():
                severity = "MEDIUM"
                event_type = "service_modification"
                
                if "systemctl stop" in message.lower():
                    details = f"Service '{service_name}' stopped by {user}"
                    action = "stop"
                    # Check if critical service
                    if service_name in self.critical_services:
                        severity = "HIGH"
                        event_type = "critical_service_stop"
                        details += " - CRITICAL SERVICE STOPPED"
                elif "systemctl disable" in message.lower():
                    details = f"Service '{service_name}' disabled by {user}"
                    action = "disable"
                    # Check if critical service
                    if service_name in self.critical_services:
                        severity = "HIGH"
                        event_type = "critical_service_disable"
                        details += " - CRITICAL SERVICE DISABLED"
                elif "systemctl reload" in message.lower():
                    details = f"Service '{service_name}' configuration reloaded by {user}"
                    action = "reload"
                elif "systemctl restart" in message.lower():
                    details = f"Service '{service_name}' restarted by {user}"
                    action = "restart"
                else:
                    details = f"Service '{service_name}' modified by {user}"
                    action = "modified"
                
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
                        'service_name': service_name,
                        'action': action,
                        'is_critical_service': service_name in self.critical_services,
                        'pattern_matched': pattern
                    }
                )
                
                events.append(event)
                
                # Track for correlation
                self.service_events[service_name].append((timestamp, action, details))
                self.user_service_actions[user].append((timestamp, action, service_name))
                
                # Track critical service events separately
                if service_name in self.critical_services:
                    self.critical_service_events.append({
                        'timestamp': timestamp,
                        'service': service_name,
                        'action': action,
                        'user': user
                    })
                
                break
        
        return events
    
    def _detect_critical_service_changes(self, timestamp: datetime, message: str, source: str, entry) -> List[IoCEvent]:
        """Detect changes to critical security services."""
        events = []
        
        user = self._extract_user_from_message(message)
        service_name = self._extract_service_name_from_message(message)
        
        # Only process if this is a critical service
        if service_name in self.critical_services:
            critical_actions = ["stop", "disable", "mask", "kill"]
            
            for action in critical_actions:
                if action in message.lower():
                    severity = "HIGH"
                    event_type = "critical_service_compromise"
                    
                    details = f"Critical security service '{service_name}' {action}ped by {user} - SECURITY COMPROMISE RISK"
                    
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
                            'service_name': service_name,
                            'action': action,
                            'is_critical_service': True,
                            'compromise_risk': 'high'
                        }
                    )
                    
                    events.append(event)
                    
                    # Track critical service events
                    self.critical_service_events.append({
                        'timestamp': timestamp,
                        'service': service_name,
                        'action': action,
                        'user': user
                    })
                    
                    break
        
        return events
    
    def _detect_service_masking(self, timestamp: datetime, message: str, source: str, entry) -> List[IoCEvent]:
        """Detect service masking for advanced persistence."""
        events = []
        
        user = self._extract_user_from_message(message)
        service_name = self._extract_service_name_from_message(message)
        
        # Look for masking operations
        if "systemctl mask" in message.lower():
            severity = "HIGH"
            event_type = "service_masking"
            
            details = f"Service '{service_name}' masked by {user} - advanced persistence technique"
            
            # Extra severity for critical services
            if service_name in self.critical_services:
                severity = "HIGH"
                details += " - CRITICAL SERVICE MASKED"
            
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
                    'service_name': service_name,
                    'action': 'mask',
                    'persistence_technique': 'service_masking',
                    'is_critical_service': service_name in self.critical_services
                }
            )
            
            events.append(event)
            
            # Track for correlation
            self.service_events[service_name].append((timestamp, 'mask', details))
            self.user_service_actions[user].append((timestamp, 'mask', service_name))
        
        # Look for unmasking operations (could indicate cleanup or re-enabling)
        elif "systemctl unmask" in message.lower():
            severity = "MEDIUM"
            event_type = "service_unmasking"
            
            details = f"Service '{service_name}' unmasked by {user}"
            
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
                    'service_name': service_name,
                    'action': 'unmask',
                    'is_critical_service': service_name in self.critical_services
                }
            )
            
            events.append(event)
            
            # Track for correlation
            self.service_events[service_name].append((timestamp, 'unmask', details))
            self.user_service_actions[user].append((timestamp, 'unmask', service_name))
        
        return events
    
    def _detect_timer_manipulation(self, timestamp: datetime, message: str, source: str, entry) -> List[IoCEvent]:
        """Detect systemd timer manipulation for persistence."""
        events = []
        
        user = self._extract_user_from_message(message)
        timer_name = self._extract_timer_name_from_message(message)
        
        # Look for timer-related operations
        timer_operations = [
            ("timer created", "creation"),
            ("timer enabled", "enable"),
            ("timer started", "start"),
            ("timer stopped", "stop"),
            ("timer disabled", "disable")
        ]
        
        for operation_text, action in timer_operations:
            if operation_text in message.lower() or (action in message.lower() and ".timer" in message.lower()):
                severity = "MEDIUM"
                event_type = "timer_manipulation"
                
                if action in ["creation", "enable", "start"]:
                    severity = "HIGH"
                    event_type = "suspicious_timer_creation"
                    details = f"Systemd timer '{timer_name}' {action} by {user} - potential persistence mechanism"
                else:
                    details = f"Systemd timer '{timer_name}' {action} by {user}"
                
                # Extract timer service association
                associated_service = self._extract_associated_service(message, timer_name)
                
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
                        'timer_name': timer_name,
                        'action': action,
                        'associated_service': associated_service,
                        'persistence_technique': 'systemd_timer'
                    }
                )
                
                events.append(event)
                
                # Track for correlation
                self.timer_events[timer_name].append((timestamp, action, details))
                self.user_service_actions[user].append((timestamp, f"timer_{action}", timer_name))
                
                break
        
        return events
    
    def _detect_suspicious_service_startup(self, timestamp: datetime, message: str, source: str, entry) -> List[IoCEvent]:
        """Enhanced suspicious service startup detection with context awareness and filtering."""
        events = []
        
        # Get patterns for filtering and context
        patterns_dict = self.patterns.get("patterns", {})
        ignore_patterns = patterns_dict.get("ignore_patterns", [])
        legitimate_contexts = patterns_dict.get("legitimate_contexts", [])
        high_risk_services = patterns_dict.get("high_risk_services", [])
        medium_risk_services = patterns_dict.get("medium_risk_services", [])
        low_risk_services = patterns_dict.get("low_risk_services", [])
        
        # FIRST: Check if this should be ignored (legitimate system services)
        if self._should_ignore_message(message, ignore_patterns):
            return events
        
        user = self._extract_user_from_message(message)
        service_name = self._extract_service_name_from_message(message)
        
        # Skip if we couldn't extract meaningful service info
        if not service_name or service_name == 'unknown':
            return events
        
        # Check for services with suspicious names or characteristics
        # FIXED: More specific patterns that won't match legitimate services
        suspicious_indicators = [
            # Network services - more specific patterns
            (r'\bnc\b\.service', 'netcat_service'),
            (r'\bnetcat\b\.service', 'netcat_service'), 
            (r'.*backdoor.*\.service', 'backdoor_service'),
            (r'.*reverse.*\.service', 'reverse_shell_service'),
            (r'.*shell.*\.service', 'shell_service'),
            
            # Services in unusual locations
            (r'/tmp/.*\.service', 'temp_service'),
            (r'/var/tmp/.*\.service', 'temp_service'),
            (r'/dev/shm/.*\.service', 'shared_memory_service'),
            
            # Services with suspicious execution contexts
            (r'.*root.*\.service', 'root_context_service'),
            (r'.*sudo.*\.service', 'sudo_context_service')
        ]
        
        for pattern, indicator_type in suspicious_indicators:
            if re.search(pattern, message.lower()):
                # Check if this is a legitimate service
                is_legitimate = (
                    self._has_legitimate_context(message, legitimate_contexts) or
                    self._is_legitimate_service(service_name, message)
                )
                
                # Always determine risk level for consistent metadata
                risk_level = self._determine_service_risk(service_name, high_risk_services, medium_risk_services, low_risk_services)
                
                if is_legitimate:
                    severity = "LOW"
                    event_type = "legitimate_service_operation"
                else:
                    # Use determined risk level for suspicious services
                    severity = risk_level
                    event_type = f"{risk_level.lower()}_risk_suspicious_service"
                
                details = f"Suspicious service '{service_name}' startup detected - {indicator_type} pattern"
                if is_legitimate:
                    details += " (legitimate system service)"
                
                # Extract additional context
                exec_start = self._extract_exec_start(message)
                working_directory = self._extract_working_directory(message)
                
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
                        'service_name': service_name,
                        'indicator_type': indicator_type,
                        'exec_start': exec_start,
                        'working_directory': working_directory,
                        'pattern_matched': pattern,
                        'is_legitimate': is_legitimate,  # New field
                        'context_verified': True,  # New field
                        'risk_level': risk_level.lower()
                    }
                )
                
                events.append(event)
                break
        
        return events
    
    def _track_for_correlation(self, event: IoCEvent) -> None:
        """Track events for correlation analysis."""
        self.service_timeline.append({
            'timestamp': event.timestamp,
            'user': event.metadata.get('user', 'unknown'),
            'service_name': event.metadata.get('service_name', event.metadata.get('timer_name', 'unknown')),
            'action': event.metadata.get('action', 'unknown'),
            'event_type': event.event_type,
            'severity': event.severity,
            'details': event.details
        })
    
    def _perform_correlation_analysis(self, begin_time: datetime, end_time: datetime) -> List[IoCEvent]:
        """Analyze tracked events for service-based attack patterns."""
        events = []
        
        # Sort timeline by timestamp
        self.service_timeline.sort(key=lambda x: x['timestamp'])
        
        # 1. Detect rapid service manipulation
        events.extend(self._detect_rapid_service_manipulation(begin_time, end_time))
        
        # 2. Detect critical service compromise patterns
        events.extend(self._detect_critical_service_compromise_pattern(begin_time, end_time))
        
        # 3. Detect persistence establishment patterns
        events.extend(self._detect_persistence_patterns(begin_time, end_time))
        
        return events
    
    def _detect_rapid_service_manipulation(self, begin_time: datetime, end_time: datetime) -> List[IoCEvent]:
        """Detect rapid service manipulation patterns."""
        events = []
        
        # Group events by user within time windows
        window_minutes = self.thresholds.get("rapid_service_window_minutes", 5)
        window_delta = timedelta(minutes=window_minutes)
        
        user_windows = defaultdict(list)
        
        for event_data in self.service_timeline:
            if begin_time <= event_data['timestamp'] <= end_time:
                user = event_data['user']
                user_windows[user].append(event_data)
        
        # Analyze each user's activity
        for user, user_events in user_windows.items():
            if len(user_events) < self.thresholds.get("rapid_service_changes_threshold", 3):
                continue
            
            # Check for rapid manipulation within time window
            for i, start_event in enumerate(user_events[:-2]):
                window_events = [start_event]
                start_time = start_event['timestamp']
                end_window = start_time + window_delta
                
                # Collect events within window
                for next_event in user_events[i+1:]:
                    if next_event['timestamp'] <= end_window:
                        window_events.append(next_event)
                    else:
                        break
                
                if len(window_events) >= self.thresholds.get("rapid_service_changes_threshold", 3):
                    severity = "HIGH"
                    event_type = "rapid_service_manipulation"
                    
                    services = list(set([e['service_name'] for e in window_events]))
                    actions = [e['action'] for e in window_events]
                    
                    details = (f"Rapid service manipulation detected for user {user}: "
                             f"{len(window_events)} service operations in {window_minutes} minutes "
                             f"(services: {', '.join(services[:3])}{'...' if len(services) > 3 else ''})")
                    
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
                            'operation_count': len(window_events),
                            'time_window_minutes': window_minutes,
                            'services_affected': services,
                            'actions': actions,
                            'pattern': 'rapid_manipulation'
                        }
                    )
                    
                    events.append(event)
                    break  # Avoid overlapping correlations
        
        return events
    
    def _detect_critical_service_compromise_pattern(self, begin_time: datetime, end_time: datetime) -> List[IoCEvent]:
        """Detect patterns indicating systematic compromise of critical services."""
        events = []
        
        # Filter critical service events within time window
        critical_events = [
            event for event in self.critical_service_events
            if begin_time <= event['timestamp'] <= end_time
        ]
        
        if len(critical_events) >= self.thresholds.get("critical_service_threshold", 2):
            # Group by user
            user_critical_events = defaultdict(list)
            for event in critical_events:
                user_critical_events[event['user']].append(event)
            
            for user, events_list in user_critical_events.items():
                if len(events_list) >= 2:
                    severity = "HIGH"
                    event_type = "critical_service_compromise_pattern"
                    
                    services = [e['service'] for e in events_list]
                    actions = [e['action'] for e in events_list]
                    
                    details = (f"Critical service compromise pattern detected for user {user}: "
                             f"{len(events_list)} critical services affected "
                             f"({', '.join(services)})")
                    
                    first_event_time = min(e['timestamp'] for e in events_list)
                    
                    event = IoCEvent(
                        timestamp=first_event_time,
                        category=self._get_category_name(),
                        severity=severity,
                        source="correlation_analysis",
                        event_type=event_type,
                        details=details,
                        raw_log=None,
                        metadata={
                            'user': user,
                            'critical_services_affected': services,
                            'actions': actions,
                            'compromise_count': len(events_list),
                            'pattern': 'critical_service_compromise'
                        }
                    )
                    
                    events.append(event)
        
        return events
    
    def _detect_persistence_patterns(self, begin_time: datetime, end_time: datetime) -> List[IoCEvent]:
        """Detect persistence establishment through service and timer manipulation."""
        events = []
        
        # Look for combinations of service creation + timer creation
        service_creations = [
            event for event in self.service_timeline
            if event['event_type'] in ['service_creation', 'suspicious_service_creation']
            and begin_time <= event['timestamp'] <= end_time
        ]
        
        timer_creations = [
            event for event in self.service_timeline
            if event['event_type'] in ['timer_manipulation', 'suspicious_timer_creation']
            and begin_time <= event['timestamp'] <= end_time
        ]
        
        # Check for users creating both services and timers
        service_users = set(event['user'] for event in service_creations)
        timer_users = set(event['user'] for event in timer_creations)
        persistence_users = service_users.intersection(timer_users)
        
        for user in persistence_users:
            severity = "HIGH"
            event_type = "persistence_establishment_pattern"
            
            user_services = [e['service_name'] for e in service_creations if e['user'] == user]
            user_timers = [e['service_name'] for e in timer_creations if e['user'] == user]
            
            details = (f"Persistence establishment pattern detected for user {user}: "
                     f"created {len(user_services)} services and {len(user_timers)} timers")
            
            # Use timestamp of first event
            first_service_time = min((e['timestamp'] for e in service_creations if e['user'] == user), default=datetime.now())
            first_timer_time = min((e['timestamp'] for e in timer_creations if e['user'] == user), default=datetime.now())
            first_event_time = min(first_service_time, first_timer_time)
            
            event = IoCEvent(
                timestamp=first_event_time,
                category=self._get_category_name(),
                severity=severity,
                source="correlation_analysis",
                event_type=event_type,
                details=details,
                raw_log=None,
                metadata={
                    'user': user,
                    'services_created': user_services,
                    'timers_created': user_timers,
                    'persistence_methods': ['service_creation', 'timer_manipulation'],
                    'pattern': 'persistence_establishment'
                }
            )
            
            events.append(event)
        
        return events
    
    def _extract_user_from_message(self, message: str) -> str:
        """Extract username from log message."""
        patterns = [
            r'user=([^\s,]+)',
            r'USER=([^\s,]+)',
            r'uid=\d+\(([^)]+)\)',
            r'\s([a-z_][a-z0-9_]{0,30})\s'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, message)
            if match:
                user = match.group(1)
                if user not in ['systemctl', 'systemd', 'service'] or user == 'root':
                    return user
        
        return 'unknown'
    
    def _extract_service_name_from_message(self, message: str) -> str:
        """Extract service name from systemctl/systemd messages."""
        patterns = [
            r'systemctl\s+\w+\s+([^\s]+\.service)',
            r'service\s+([^\s]+\.service)',
            r'([^\s]+\.service)',
            r'systemctl\s+\w+\s+([^\s]+)',
            r'Started\s+([^.]+)\.',
            r'Stopped\s+([^.]+)\.',
            r'unit\s+([^\s]+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, message)
            if match:
                service = match.group(1)
                # Clean up service name
                if service.endswith('.service'):
                    service = service[:-8]  # Remove .service suffix for consistency
                return service
        
        return 'unknown'
    
    def _extract_timer_name_from_message(self, message: str) -> str:
        """Extract timer name from systemd timer messages."""
        patterns = [
            r'([^\s]+\.timer)',
            r'timer\s+([^\s]+)',
            r'systemctl\s+\w+\s+([^\s]+\.timer)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, message)
            if match:
                timer = match.group(1)
                if timer.endswith('.timer'):
                    timer = timer[:-6]  # Remove .timer suffix for consistency
                return timer
        
        return 'unknown'
    
    def _extract_service_file_path(self, message: str) -> Optional[str]:
        """Extract service file path from unit creation messages."""
        patterns = [
            r'(/[^\s]+\.service)',
            r'created\s+([^\s]+\.service)',
            r'unit file\s+([^\s]+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, message)
            if match:
                return match.group(1)
        
        return None
    
    def _extract_associated_service(self, message: str, timer_name: str) -> Optional[str]:
        """Extract the service associated with a timer."""
        # Timer usually has same name as service
        if timer_name and timer_name != 'unknown':
            return timer_name  # Service typically has same base name
        
        return None
    
    def _extract_exec_start(self, message: str) -> Optional[str]:
        """Extract ExecStart command from service messages."""
        patterns = [
            r'ExecStart=([^\n\r]+)',
            r'command=([^\n\r]+)',
            r'executing:\s*([^\n\r]+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, message)
            if match:
                return match.group(1).strip()
        
        return None
    
    def _extract_working_directory(self, message: str) -> Optional[str]:
        """Extract WorkingDirectory from service messages."""
        patterns = [
            r'WorkingDirectory=([^\s]+)',
            r'working directory:\s*([^\s]+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, message)
            if match:
                return match.group(1)
        
        return None

    def _should_ignore_message(self, message: str, ignore_patterns: List[str]) -> bool:
        """Check if message should be ignored (legitimate system services, etc.)."""
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
    
    def _determine_service_risk(self, service_name: str, high_risk: List[str], 
                               medium_risk: List[str], low_risk: List[str]) -> str:
        """Determine risk level based on service classification."""
        service_lower = service_name.lower()
        
        # Check high risk services
        for high_service in high_risk:
            if re.search(high_service.lower(), service_lower):
                return "HIGH"
        
        # Check medium risk services  
        for medium_service in medium_risk:
            if re.search(medium_service.lower(), service_lower):
                return "MEDIUM"
                
        # Check low risk services
        for low_service in low_risk:
            if re.search(low_service.lower(), service_lower):
                return "LOW"
        
        # Default to medium for unclassified services with suspicious patterns
        return "MEDIUM"
    
    def _is_legitimate_service(self, service_name: str, message: str) -> bool:
        """Check if service appears to be legitimate system service."""
        # Common legitimate service patterns
        legitimate_indicators = [
            'systemd', 'cron', 'logrotate', 'session', 'cleanup',
            'tmp', 'backup', 'update', 'maintenance', 'php',
            'apache', 'nginx', 'mysql', 'postgresql', 'redis'
        ]
        
        service_lower = service_name.lower()
        message_lower = message.lower()
        
        # Check service name for legitimate patterns
        for indicator in legitimate_indicators:
            if indicator in service_lower:
                return True
        
        # Check message context for legitimate operations
        legitimate_contexts = [
            'started by systemd', 'system service', 'scheduled',
            'package installation', 'system update'
        ]
        
        for context in legitimate_contexts:
            if context in message_lower:
                return True
        
        return False
