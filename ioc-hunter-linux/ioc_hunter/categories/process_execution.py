"""
Process Execution IoC Category for IoC-Hunter Linux

Detects suspicious process execution activities including network reconnaissance,
reverse shells, file transfers, persistence mechanisms, and command injection attacks.

This category implements correlation analysis to identify process-based attack patterns
and multi-stage attack sequences through process execution monitoring.

Python 3.9+ compatible.
"""

import re
import logging
import os
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Set
from collections import defaultdict, Counter
from pathlib import Path

try:
    # Try relative imports first (when in package)
    from ..core.base_category import BaseIoCCategory, IoCEvent
    from ..utils.helpers import extract_ip_addresses, run_system_command, check_command_availability
except ImportError:
    # Fall back to absolute imports (when testing standalone)
    from ioc_hunter.core.base_category import BaseIoCCategory, IoCEvent
    from ioc_hunter.utils.helpers import extract_ip_addresses, run_system_command, check_command_availability


class ProcessExecution(BaseIoCCategory):
    """
    Process Execution Detection Category.
    
    Detects:
    - Suspicious process execution patterns (interactive shells, command injection)
    - Network reconnaissance tools (nmap, masscan, tcpdump)
    - File download and transfer activities (wget, curl, scp)
    - Reverse shell establishment attempts
    - Persistence mechanism creation through process execution
    - Command obfuscation and evasion techniques
    - Cross-platform attack tool usage
    """
    
    # Required class attributes for auto-discovery
    name = "process_execution"
    display_name = "Process Execution Activity"
    description = "Detects suspicious process execution, network tools, reverse shells and persistence mechanisms"
    version = "1.0.0"
    tier = 1  # Tier 1 = Critical (included in quick scans)
    
    def __init__(self, config_manager=None, log_sources=None):
        super().__init__(config_manager, log_sources)
        
        # Load process execution patterns and thresholds
        self.patterns = self.get_patterns()
        self.thresholds = self.patterns.get("thresholds", {
            "rapid_execution_threshold": 5,
            "rapid_execution_window_minutes": 2,
            "network_tool_threshold": 3,
            "download_threshold": 5
        })
        
        # Debug pattern loading
        if self.patterns:
            pattern_types = self.patterns.get("patterns", {})
            self.logger.info(f"Loaded {len(pattern_types)} pattern types: {list(pattern_types.keys())}")
        else:
            self.logger.warning("No patterns loaded from configuration")
        
        # Tracking for correlation analysis
        self.process_events = defaultdict(list)  # process_name -> list of (timestamp, user, command, details)
        self.network_tool_usage = defaultdict(list)  # user -> list of (timestamp, tool, target)
        self.download_activity = defaultdict(list)  # user -> list of (timestamp, tool, url/file)
        self.shell_activity = defaultdict(list)  # user -> list of (timestamp, shell_type, details)
        self.user_process_timeline = defaultdict(list)  # user -> chronological process list
        self.process_timeline = []  # All process events for correlation
        
        # High-risk process patterns (compiled for performance)
        self.reverse_shell_patterns = [
            re.compile(pattern, re.IGNORECASE) 
            for pattern in self.patterns.get("patterns", {}).get("reverse_shells", [])
        ]
        
        # Network tool patterns
        self.network_tools = set(self.patterns.get("patterns", {}).get("network_tools", [
            "nmap", "masscan", "zmap", "hping", "tcpdump", "wireshark", "tshark"
        ]))
        
        # Download tool patterns
        self.download_tools = set(self.patterns.get("patterns", {}).get("download_tools", [
            "wget", "curl", "fetch", "lynx", "links"
        ]))
        
        self.logger.info(f"Initialized Process Execution scanner")
        self.logger.info(f"Monitoring {len(self.network_tools)} network tools, {len(self.download_tools)} download tools")
    
    def _get_category_name(self) -> str:
        """Get the category name, ensuring it's never None for type safety."""
        return self.name or "process_execution"
    
    def get_required_log_sources(self) -> List[str]:
        """Process execution requires multiple log sources for comprehensive monitoring."""
        return ["journald", "auth_log"]
    
    def get_supported_log_sources(self) -> List[str]:
        """Process execution can use multiple log sources."""
        return ["journald", "syslog_file", "auth_log", "kern_log"]
    
    def scan(self, begin_time: datetime, end_time: datetime) -> List[IoCEvent]:
        """
        Scan for process execution activity within time range.
        
        Args:
            begin_time: Start of scan window
            end_time: End of scan window
            
        Returns:
            List of process execution IoC events
        """
        scan_start = datetime.now()
        events = []
        processed_count = 0
        
        self.logger.info(f"Scanning process execution activity from {begin_time} to {end_time}")
        
        # Define filters for process execution logs
        process_filters = {
            "keywords": ["exec", "command", "process", "bash", "sh", "python", "perl", "ruby", "wget", "curl", "nc", "nmap"],
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
                filters=process_filters
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
                
                # Detect different types of process execution events
                detected_events = []
                
                # 1. Suspicious process patterns
                suspicious_events = self._detect_suspicious_processes(timestamp, message, source, entry)
                detected_events.extend(suspicious_events)
                
                # 2. Network reconnaissance tools
                network_events = self._detect_network_tools(timestamp, message, source, entry)
                detected_events.extend(network_events)
                
                # 3. File download activities
                download_events = self._detect_download_activities(timestamp, message, source, entry)
                detected_events.extend(download_events)
                
                # 4. Reverse shell attempts
                shell_events = self._detect_reverse_shells(timestamp, message, source, entry)
                detected_events.extend(shell_events)
                
                # 5. File transfer operations
                transfer_events = self._detect_file_transfers(timestamp, message, source, entry)
                detected_events.extend(transfer_events)
                
                # 6. Persistence mechanism creation
                persistence_events = self._detect_persistence_attempts(timestamp, message, source, entry)
                detected_events.extend(persistence_events)
                
                # Add all detected events and track for correlation
                for event in detected_events:
                    events.append(event)
                    self._track_for_correlation(event)
            
            # Perform correlation analysis
            correlation_events = self._perform_correlation_analysis(begin_time, end_time)
            events.extend(correlation_events)
            
            scan_duration = (datetime.now() - scan_start).total_seconds()
            self.logger.info(f"Process execution scan completed: {len(events)} events found, "
                           f"{processed_count} entries processed in {scan_duration:.2f}s")
            
            return events
            
        except Exception as e:
            self.logger.error(f"Error during process execution scan: {e}")
            return events
    
    def _detect_suspicious_processes(self, timestamp: datetime, message: str, source: str, entry) -> List[IoCEvent]:
        """Detect suspicious process execution patterns."""
        events = []
        
        # Get suspicious process patterns
        suspicious_patterns = self.patterns.get("patterns", {}).get("suspicious_processes", [])
        
        user = self._extract_user_from_message(message)
        command = self._extract_command_from_message(message)
        
        for pattern in suspicious_patterns:
            if pattern.lower() in message.lower():
                severity = "HIGH"
                event_type = "suspicious_process_execution"
                
                # Determine specific threat type
                if "bash -i" in message.lower() or "sh -i" in message.lower():
                    event_type = "interactive_shell_execution"
                    details = f"Interactive shell executed by {user}: {command}"
                elif "/dev/tcp/" in message.lower() or "/dev/udp/" in message.lower():
                    event_type = "network_file_descriptor_usage"
                    details = f"Network file descriptor usage detected by {user}: {command}"
                elif any(lang in message.lower() for lang in ["python -c", "perl -e", "ruby -e", "php -r"]):
                    event_type = "inline_script_execution"
                    details = f"Inline script execution by {user}: {command}"
                else:
                    details = f"Suspicious process execution by {user}: {command}"
                
                # Extract additional context
                pid = self._extract_pid_from_message(message)
                parent_process = self._extract_parent_process(message)
                
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
                        'pid': pid,
                        'parent_process': parent_process,
                        'pattern_matched': pattern,
                        'threat_type': 'process_execution'
                    }
                )
                
                events.append(event)
                
                # Track for correlation
                self.process_events[command[:50]].append((timestamp, user, command, details))
                self.user_process_timeline[user].append((timestamp, event_type, command))
                
                break
        
        return events
    
    def _detect_network_tools(self, timestamp: datetime, message: str, source: str, entry) -> List[IoCEvent]:
        """Detect network reconnaissance tool usage."""
        events = []
        
        user = self._extract_user_from_message(message)
        command = self._extract_command_from_message(message)
        
        # Check for network tool usage
        for tool in self.network_tools:
            if tool.lower() in message.lower():
                severity = "HIGH"
                event_type = "network_reconnaissance"
                
                # Extract target information
                target = self._extract_target_from_command(command, tool)
                scan_type = self._extract_scan_type(command, tool)
                
                if tool in ["nmap", "masscan", "zmap"]:
                    event_type = "network_scanning"
                    details = f"Network scanning tool '{tool}' used by {user} targeting {target}"
                elif tool in ["tcpdump", "wireshark", "tshark"]:
                    event_type = "network_monitoring"
                    details = f"Network monitoring tool '{tool}' used by {user}"
                    severity = "MEDIUM"  # Monitoring tools are less critical than active scanning
                else:
                    details = f"Network tool '{tool}' executed by {user}: {command}"
                
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
                        'tool': tool,
                        'command': command,
                        'target': target,
                        'scan_type': scan_type,
                        'threat_type': 'network_reconnaissance'
                    }
                )
                
                events.append(event)
                
                # Track for correlation
                self.network_tool_usage[user].append((timestamp, tool, target))
                self.user_process_timeline[user].append((timestamp, event_type, tool))
                
                break
        
        return events
    
    def _detect_download_activities(self, timestamp: datetime, message: str, source: str, entry) -> List[IoCEvent]:
        """Detect suspicious file download activities."""
        events = []
        
        user = self._extract_user_from_message(message)
        command = self._extract_command_from_message(message)
        
        # Check for download tool usage
        for tool in self.download_tools:
            if tool.lower() in message.lower():
                severity = "MEDIUM"
                event_type = "file_download"
                
                # Extract URL and destination
                url = self._extract_url_from_command(command)
                destination = self._extract_download_destination(command)
                
                # Increase severity for suspicious patterns
                if any(suspicious in command.lower() for suspicious in ["/tmp/", "/var/tmp/", "/dev/shm/", "127.0.0.1", "localhost"]):
                    severity = "HIGH"
                    event_type = "suspicious_download"
                
                if any(suspicious in url.lower() for suspicious in ["pastebin", "bit.ly", "tinyurl", ".onion"]):
                    severity = "HIGH"
                    event_type = "suspicious_url_download"
                
                details = f"File download using '{tool}' by {user} from {url} to {destination}"
                
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
                        'tool': tool,
                        'command': command,
                        'url': url,
                        'destination': destination,
                        'threat_type': 'file_download'
                    }
                )
                
                events.append(event)
                
                # Track for correlation
                self.download_activity[user].append((timestamp, tool, url))
                self.user_process_timeline[user].append((timestamp, event_type, tool))
                
                break
        
        return events
    
    def _detect_reverse_shells(self, timestamp: datetime, message: str, source: str, entry) -> List[IoCEvent]:
        """Detect reverse shell establishment attempts."""
        events = []
        
        user = self._extract_user_from_message(message)
        command = self._extract_command_from_message(message)
        
        # Check against compiled reverse shell patterns
        for pattern in self.reverse_shell_patterns:
            if pattern.search(message):
                severity = "HIGH"
                event_type = "reverse_shell_attempt"
                
                # Extract target IP and port
                target_ip = self._extract_target_ip_from_shell(command)
                target_port = self._extract_target_port_from_shell(command)
                shell_type = self._determine_shell_type(command)
                
                details = f"Reverse shell attempt by {user} to {target_ip}:{target_port} using {shell_type}"
                
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
                        'target_ip': target_ip,
                        'target_port': target_port,
                        'shell_type': shell_type,
                        'pattern_matched': pattern.pattern,
                        'threat_type': 'reverse_shell'
                    }
                )
                
                events.append(event)
                
                # Track for correlation
                self.shell_activity[user].append((timestamp, shell_type, target_ip))
                self.user_process_timeline[user].append((timestamp, event_type, shell_type))
                
                break
        
        return events
    
    def _detect_file_transfers(self, timestamp: datetime, message: str, source: str, entry) -> List[IoCEvent]:
        """Detect file transfer operations."""
        events = []
        
        # Get file transfer patterns
        transfer_patterns = self.patterns.get("patterns", {}).get("file_transfer", [])
        
        user = self._extract_user_from_message(message)
        command = self._extract_command_from_message(message)
        
        for pattern in transfer_patterns:
            if pattern.lower() in message.lower():
                severity = "MEDIUM"
                event_type = "file_transfer"
                
                # Extract transfer details
                source_file = self._extract_source_file(command, pattern)
                destination = self._extract_transfer_destination(command, pattern)
                transfer_method = pattern
                
                # Increase severity for suspicious patterns
                if any(suspicious in command.lower() for suspicious in ["/etc/passwd", "/etc/shadow", "id_rsa", ".ssh/"]):
                    severity = "HIGH"
                    event_type = "sensitive_file_transfer"
                
                details = f"File transfer using '{transfer_method}' by {user}: {source_file} -> {destination}"
                
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
                        'transfer_method': transfer_method,
                        'source_file': source_file,
                        'destination': destination,
                        'threat_type': 'file_transfer'
                    }
                )
                
                events.append(event)
                
                # Track for correlation
                self.user_process_timeline[user].append((timestamp, event_type, transfer_method))
                
                break
        
        return events
    
    def _detect_persistence_attempts(self, timestamp: datetime, message: str, source: str, entry) -> List[IoCEvent]:
        """Detect persistence mechanism creation through process execution."""
        events = []
        
        # Get persistence patterns
        persistence_patterns = self.patterns.get("patterns", {}).get("persistence_commands", [])
        
        user = self._extract_user_from_message(message)
        command = self._extract_command_from_message(message)
        
        for pattern in persistence_patterns:
            if pattern.lower() in message.lower():
                severity = "HIGH"
                event_type = "persistence_attempt"
                
                # Determine persistence method
                if "crontab" in pattern.lower():
                    persistence_method = "cron_job"
                    details = f"Cron-based persistence attempt by {user}: {command}"
                elif "systemctl --user" in pattern.lower():
                    persistence_method = "systemd_user_service"
                    details = f"Systemd user service persistence attempt by {user}: {command}"
                elif any(profile in pattern.lower() for profile in ["bashrc", "profile"]):
                    persistence_method = "shell_profile"
                    details = f"Shell profile modification for persistence by {user}: {command}"
                elif "rc.local" in pattern.lower():
                    persistence_method = "init_script"
                    details = f"Init script persistence attempt by {user}: {command}"
                else:
                    persistence_method = "unknown"
                    details = f"Persistence mechanism attempt by {user}: {command}"
                
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
                        'persistence_method': persistence_method,
                        'pattern_matched': pattern,
                        'threat_type': 'persistence'
                    }
                )
                
                events.append(event)
                
                # Track for correlation
                self.user_process_timeline[user].append((timestamp, event_type, persistence_method))
                
                break
        
        return events
    
    def _track_for_correlation(self, event: IoCEvent) -> None:
        """Track events for correlation analysis."""
        self.process_timeline.append({
            'timestamp': event.timestamp,
            'user': event.metadata.get('user', 'unknown'),
            'event_type': event.event_type,
            'threat_type': event.metadata.get('threat_type', 'unknown'),
            'severity': event.severity,
            'details': event.details,
            'command': event.metadata.get('command', ''),
            'tool': event.metadata.get('tool', event.metadata.get('transfer_method', 'unknown'))
        })
    
    def _perform_correlation_analysis(self, begin_time: datetime, end_time: datetime) -> List[IoCEvent]:
        """Analyze tracked events for process-based attack patterns."""
        events = []
        
        # Sort timeline by timestamp
        self.process_timeline.sort(key=lambda x: x['timestamp'])
        
        # 1. Detect rapid process execution patterns
        events.extend(self._detect_rapid_execution_patterns(begin_time, end_time))
        
        # 2. Detect multi-stage attack sequences
        events.extend(self._detect_attack_sequences(begin_time, end_time))
        
        # 3. Detect network tool usage patterns
        events.extend(self._detect_network_tool_patterns(begin_time, end_time))
        
        # 4. Detect download and execution patterns
        events.extend(self._detect_download_execution_patterns(begin_time, end_time))
        
        return events
    
    def _detect_rapid_execution_patterns(self, begin_time: datetime, end_time: datetime) -> List[IoCEvent]:
        """Detect rapid process execution patterns indicating automated attacks."""
        events = []
        
        # Group events by user within time windows
        window_minutes = self.thresholds.get("rapid_execution_window_minutes", 2)
        window_delta = timedelta(minutes=window_minutes)
        
        user_windows = defaultdict(list)
        
        for event_data in self.process_timeline:
            if begin_time <= event_data['timestamp'] <= end_time:
                user = event_data['user']
                user_windows[user].append(event_data)
        
        # Analyze each user's activity
        for user, user_events in user_windows.items():
            if len(user_events) < self.thresholds.get("rapid_execution_threshold", 5):
                continue
            
            # Check for rapid execution within time window
            for i, start_event in enumerate(user_events[:-4]):
                window_events = [start_event]
                start_time = start_event['timestamp']
                end_window = start_time + window_delta
                
                # Collect events within window
                for next_event in user_events[i+1:]:
                    if next_event['timestamp'] <= end_window:
                        window_events.append(next_event)
                    else:
                        break
                
                if len(window_events) >= self.thresholds.get("rapid_execution_threshold", 5):
                    severity = "HIGH"
                    event_type = "rapid_process_execution"
                    
                    tools = list(set([e['tool'] for e in window_events]))
                    threat_types = list(set([e['threat_type'] for e in window_events]))
                    
                    details = (f"Rapid process execution detected for user {user}: "
                             f"{len(window_events)} processes in {window_minutes} minutes "
                             f"(types: {', '.join(threat_types[:3])}{'...' if len(threat_types) > 3 else ''})")
                    
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
                            'execution_count': len(window_events),
                            'time_window_minutes': window_minutes,
                            'tools_used': tools,
                            'threat_types': threat_types,
                            'pattern': 'rapid_execution'
                        }
                    )
                    
                    events.append(event)
                    break  # Don't create duplicate events for same user
        
        return events
    
    def _detect_attack_sequences(self, begin_time: datetime, end_time: datetime) -> List[IoCEvent]:
        """Detect multi-stage attack sequences."""
        events = []
        
        # Look for common attack sequences per user
        for user, user_events in self.user_process_timeline.items():
            if len(user_events) < 3:  # Need at least 3 events for sequence
                continue
            
            user_events.sort(key=lambda x: x[0])  # Sort by timestamp
            
            # Check for reconnaissance -> download -> execution sequence
            sequence_events = [e for e in user_events if begin_time <= e[0] <= end_time]
            
            if len(sequence_events) >= 3:
                event_types = [e[1] for e in sequence_events]
                
                # Check for common attack patterns
                if self._is_attack_sequence(event_types):
                    severity = "HIGH"
                    event_type = "multi_stage_attack_sequence"
                    
                    first_event_time = sequence_events[0][0]
                    last_event_time = sequence_events[-1][0]
                    duration = (last_event_time - first_event_time).total_seconds() / 60
                    
                    details = (f"Multi-stage attack sequence detected for user {user}: "
                             f"{len(sequence_events)} stages over {duration:.1f} minutes "
                             f"({' -> '.join(event_types[:5])})")
                    
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
                            'sequence_length': len(sequence_events),
                            'duration_minutes': duration,
                            'event_sequence': event_types,
                            'pattern': 'attack_sequence'
                        }
                    )
                    
                    events.append(event)
        
        return events
    
    def _detect_network_tool_patterns(self, begin_time: datetime, end_time: datetime) -> List[IoCEvent]:
        """Detect suspicious network tool usage patterns."""
        events = []
        
        for user, tool_usage in self.network_tool_usage.items():
            relevant_usage = [usage for usage in tool_usage if begin_time <= usage[0] <= end_time]
            
            if len(relevant_usage) >= self.thresholds.get("network_tool_threshold", 3):
                severity = "HIGH"
                event_type = "extensive_network_reconnaissance"
                
                tools = list(set([usage[1] for usage in relevant_usage]))
                targets = list(set([usage[2] for usage in relevant_usage if usage[2] != 'unknown']))
                
                first_usage_time = min(usage[0] for usage in relevant_usage)
                
                details = (f"Extensive network reconnaissance by user {user}: "
                         f"{len(relevant_usage)} tool executions using {', '.join(tools)}")
                
                if targets:
                    details += f" targeting {', '.join(targets[:3])}{'...' if len(targets) > 3 else ''}"
                
                event = IoCEvent(
                    timestamp=first_usage_time,
                    category=self._get_category_name(),
                    severity=severity,
                    source="correlation_analysis",
                    event_type=event_type,
                    details=details,
                    raw_log=None,
                    metadata={
                        'user': user,
                        'tool_executions': len(relevant_usage),
                        'tools_used': tools,
                        'targets': targets,
                        'pattern': 'network_reconnaissance'
                    }
                )
                
                events.append(event)
        
        return events
    
    def _detect_download_execution_patterns(self, begin_time: datetime, end_time: datetime) -> List[IoCEvent]:
        """Detect download followed by execution patterns."""
        events = []
        
        for user, download_events in self.download_activity.items():
            relevant_downloads = [dl for dl in download_events if begin_time <= dl[0] <= end_time]
            
            if len(relevant_downloads) >= self.thresholds.get("download_threshold", 5):
                severity = "HIGH"
                event_type = "excessive_download_activity"
                
                tools = list(set([dl[1] for dl in relevant_downloads]))
                urls = [dl[2] for dl in relevant_downloads if dl[2] != 'unknown']
                
                first_download_time = min(dl[0] for dl in relevant_downloads)
                
                details = (f"Excessive download activity by user {user}: "
                         f"{len(relevant_downloads)} downloads using {', '.join(tools)}")
                
                event = IoCEvent(
                    timestamp=first_download_time,
                    category=self._get_category_name(),
                    severity=severity,
                    source="correlation_analysis",
                    event_type=event_type,
                    details=details,
                    raw_log=None,
                    metadata={
                        'user': user,
                        'download_count': len(relevant_downloads),
                        'tools_used': tools,
                        'urls': urls[:10],  # Limit to first 10 URLs
                        'pattern': 'excessive_downloads'
                    }
                )
                
                events.append(event)
        
        return events
    
    def _is_attack_sequence(self, event_types: List[str]) -> bool:
        """Check if event sequence matches known attack patterns."""
        sequence_str = ' -> '.join(event_types)
        
        # Common attack sequences
        attack_patterns = [
            ["network_reconnaissance", "file_download", "reverse_shell_attempt"],
            ["network_scanning", "suspicious_download", "persistence_attempt"],
            ["network_monitoring", "file_transfer", "suspicious_process_execution"],
            ["file_download", "interactive_shell_execution", "persistence_attempt"]
        ]
        
        for pattern in attack_patterns:
            if all(stage in event_types for stage in pattern):
                return True
        
        return False
    
    # Helper methods for extraction
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
                return match.group(1)
        
        return 'unknown'
    
    def _extract_command_from_message(self, message: str) -> str:
        """Extract command from log message."""
        patterns = [
            r'COMMAND=([^\n\r]+)',
            r'command=([^\n\r]+)',
            r'executed:\s*([^\n\r]+)',
            r'exec.*:\s*([^\n\r]+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, message)
            if match:
                return match.group(1).strip()
        
        # Fallback: return the message itself if no specific command pattern found
        return message[:200]  # Limit length
    
    def _extract_pid_from_message(self, message: str) -> Optional[str]:
        """Extract PID from log message."""
        patterns = [
            r'pid=(\d+)',
            r'PID=(\d+)',
            r'\[(\d+)\]'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, message)
            if match:
                return match.group(1)
        
        return None
    
    def _extract_parent_process(self, message: str) -> Optional[str]:
        """Extract parent process from log message."""
        patterns = [
            r'ppid=(\d+)',
            r'parent=([^\s,]+)',
            r'from\s+([^\s]+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, message)
            if match:
                return match.group(1)
        
        return None
    
    def _extract_target_from_command(self, command: str, tool: str) -> str:
        """Extract target from network tool command."""
        # Look for IP addresses or hostnames
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        hostname_pattern = r'\b[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
        
        # Try IP first
        ip_match = re.search(ip_pattern, command)
        if ip_match:
            return ip_match.group(0)
        
        # Then hostname
        hostname_match = re.search(hostname_pattern, command)
        if hostname_match:
            return hostname_match.group(0)
        
        return 'unknown'
    
    def _extract_scan_type(self, command: str, tool: str) -> str:
        """Extract scan type from network tool command."""
        if tool == "nmap":
            if "-sS" in command:
                return "syn_scan"
            elif "-sU" in command:
                return "udp_scan"
            elif "-sT" in command:
                return "tcp_scan"
            elif "-A" in command:
                return "aggressive_scan"
        
        return 'unknown'
    
    def _extract_url_from_command(self, command: str) -> str:
        """Extract URL from download command."""
        url_pattern = r'https?://[^\s]+'
        match = re.search(url_pattern, command)
        return match.group(0) if match else 'unknown'
    
    def _extract_download_destination(self, command: str) -> str:
        """Extract download destination from command."""
        # Look for -O, -o, or output redirection
        patterns = [
            r'-[Oo]\s+([^\s]+)',
            r'>\s*([^\s]+)',
            r'--output-document=([^\s]+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, command)
            if match:
                return match.group(1)
        
        return '/tmp/'  # Default assumption for downloads
    
    def _extract_target_ip_from_shell(self, command: str) -> str:
        """Extract target IP from reverse shell command."""
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        match = re.search(ip_pattern, command)
        return match.group(0) if match else 'unknown'
    
    def _extract_target_port_from_shell(self, command: str) -> str:
        """Extract target port from reverse shell command."""
        # Look for port numbers in common contexts
        patterns = [
            r':(\d{1,5})\b',
            r'\s(\d{1,5})\s*$',
            r'/(\d{1,5})\b'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, command)
            if match:
                port = int(match.group(1))
                if 1 <= port <= 65535:
                    return str(port)
        
        return 'unknown'
    
    def _determine_shell_type(self, command: str) -> str:
        """Determine the type of shell being used."""
        if "bash" in command.lower():
            return "bash"
        elif "sh" in command.lower():
            return "sh"
        elif "python" in command.lower():
            return "python"
        elif "perl" in command.lower():
            return "perl"
        elif "ruby" in command.lower():
            return "ruby"
        elif "nc" in command.lower() or "netcat" in command.lower():
            return "netcat"
        else:
            return "unknown"
    
    def _extract_source_file(self, command: str, pattern: str) -> str:
        """Extract source file from transfer command."""
        if pattern == "scp":
            # scp source dest
            parts = command.split()
            if len(parts) >= 3:
                return parts[-2]  # Second to last argument
        elif pattern == "rsync":
            # rsync options source dest
            parts = command.split()
            if len(parts) >= 3:
                return parts[-2]
        
        return 'unknown'
    
    def _extract_transfer_destination(self, command: str, pattern: str) -> str:
        """Extract transfer destination from command."""
        if pattern in ["scp", "rsync", "sftp"]:
            parts = command.split()
            if len(parts) >= 2:
                return parts[-1]  # Last argument
        
        return 'unknown'
