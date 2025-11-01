"""
Timeline Exporter for IoC-Hunter Linux

Exports IoC scan results in timeline format for temporal analysis.
Optimized for incident response and forensic timeline construction.

Python 3.9+ compatible.
"""

import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any, Union, IO, cast

from ..core.base_exporter import BaseExporter, ExportMetadata
from ..core.base_category import IoCEvent


class TimelineExporter(BaseExporter):
    """
    Timeline format exporter for IoC scan results.
    
    Exports events in temporal sequence suitable for:
    - Incident response analysis
    - Forensic timeline construction
    - Attack progression visualization
    - Temporal correlation analysis
    """
    
    # Required class attributes for auto-discovery
    name = "timeline"
    display_name = "Timeline Export"
    description = "Temporal sequence format for incident analysis"
    file_extension = ".json"
    supports_streaming = False  # Requires sorting by timestamp
    version = "1.0.0"
    
    def __init__(self, config_manager=None):
        super().__init__(config_manager)
        
        # Load timeline-specific configuration
        self.timeline_config = self.config.get("timeline", {})
        
        # Timeline formatting options
        self.time_grouping = self.timeline_config.get("time_grouping", "minute")  # second, minute, hour
        self.include_gaps = self.timeline_config.get("include_gaps", True)
        self.gap_threshold_minutes = self.timeline_config.get("gap_threshold_minutes", 5)
        self.include_statistics = self.timeline_config.get("include_statistics", True)
        self.sort_within_groups = self.timeline_config.get("sort_within_groups", "severity")  # severity, category, source
        
        # Output format options
        self.format_style = self.timeline_config.get("format_style", "detailed")  # detailed, compact, forensic
        self.timestamp_precision = self.timeline_config.get("timestamp_precision", "second")  # second, minute
        
    def export(self, events: List[IoCEvent], metadata: ExportMetadata, 
               output: Union[str, Path, IO], **kwargs) -> bool:
        """
        Export IoC events to timeline format.
        
        Args:
            events: List of IoC events to export
            metadata: Export metadata
            output: Path to write timeline file
            **kwargs: Additional export options
            
        Returns:
            True if export successful, False otherwise
        """
        try:
            self.logger.info(f"Starting timeline export to {output}")
            self.logger.debug(f"Exporting {len(events)} events in timeline format")
            
            # Prepare output - handle both path and IO objects
            if hasattr(output, 'write'):
                # output is an IO object, use it directly
                io_output = cast(IO, output)
                timeline_document = self._build_timeline_document(events, metadata)
                json.dump(
                    timeline_document,
                    io_output,
                    indent=2,
                    ensure_ascii=False,
                    sort_keys=False,  # Preserve chronological order
                    default=self._json_serializer
                )
                self.logger.info(f"Timeline export completed to IO stream")
            else:
                # output is a path-like object, convert to Path and handle file creation
                path_output = cast(Union[str, Path], output)
                output_path = Path(path_output)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                
                # Build timeline document
                timeline_document = self._build_timeline_document(events, metadata)
                
                # Write timeline file
                with open(output_path, 'w', encoding='utf-8') as timelinefile:
                    json.dump(
                        timeline_document,
                        timelinefile,
                        indent=2,
                        ensure_ascii=False,
                        sort_keys=False,  # Preserve chronological order
                        default=self._json_serializer
                    )
                self.logger.info(f"Timeline export completed: {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Timeline export failed: {e}")
            return False
    
    def _build_timeline_document(self, events: List[IoCEvent], metadata: ExportMetadata) -> Dict[str, Any]:
        """
        Build complete timeline document structure.
        
        Args:
            events: List of IoC events
            metadata: Export metadata
            
        Returns:
            Complete timeline document as dictionary
        """
        # Sort events chronologically
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        
        document = {
            "timeline_metadata": self._format_metadata(metadata),
            "timeline_configuration": {
                "time_grouping": self.time_grouping,
                "format_style": self.format_style,
                "sort_within_groups": self.sort_within_groups,
                "timestamp_precision": self.timestamp_precision
            }
        }
        
        if self.include_statistics:
            document["timeline_statistics"] = self._build_timeline_statistics(sorted_events)
        
        # Build time-grouped events
        document["timeline"] = self._build_timeline_sequence(sorted_events)  # type: ignore
        
        return document
    
    def _format_metadata(self, metadata: ExportMetadata) -> Dict[str, Any]:
        """
        Format export metadata for timeline output.
        
        Args:
            metadata: Export metadata
            
        Returns:
            Formatted metadata dictionary
        """
        return {
            "scanner_version": metadata.scanner_version,
            "export_time": metadata.export_time.isoformat(),
            "scan_begin": metadata.scan_begin.isoformat(),
            "scan_end": metadata.scan_end.isoformat(),
            "categories_scanned": metadata.categories_scanned,
            "total_events": metadata.total_events,
            "scan_duration_seconds": (
                getattr(metadata.scan_duration, 'total_seconds', lambda: metadata.scan_duration)()
                if metadata.scan_duration else None
            ),
            "export_format": "timeline",
            "export_version": self.version
        }
    
    def _build_timeline_statistics(self, events: List[IoCEvent]) -> Dict[str, Any]:
        """
        Build timeline statistics.
        
        Args:
            events: Sorted list of IoC events
            
        Returns:
            Timeline statistics dictionary
        """
        if not events:
            return {
                "total_events": 0,
                "time_span": None,
                "events_per_minute": 0,
                "peak_activity_period": None
            }
        
        # Calculate time span
        time_span_seconds = (events[-1].timestamp - events[0].timestamp).total_seconds()
        time_span_minutes = time_span_seconds / 60
        
        # Calculate events per minute
        events_per_minute = len(events) / max(time_span_minutes, 1)
        
        # Find peak activity period (5-minute windows)
        peak_period = self._find_peak_activity_period(events)
        
        # Count by severity over time
        severity_timeline = self._build_severity_timeline(events)
        
        return {
            "total_events": len(events),
            "time_span": {
                "seconds": time_span_seconds,
                "minutes": time_span_minutes,
                "formatted": self._format_duration(time_span_seconds)
            },
            "events_per_minute": round(events_per_minute, 2),
            "peak_activity_period": peak_period,
            "severity_timeline": severity_timeline
        }
    
    def _find_peak_activity_period(self, events: List[IoCEvent]) -> Dict[str, Any]:
        """
        Find 5-minute period with highest activity.
        
        Args:
            events: Sorted list of events
            
        Returns:
            Peak activity period information
        """
        if len(events) < 2:
            return {}
        
        window_minutes = 5
        window_delta = timedelta(minutes=window_minutes)
        
        max_count = 0
        peak_start = None
        peak_end = None
        
        # Slide window through timeline
        for i, event in enumerate(events):
            window_start = event.timestamp
            window_end = window_start + window_delta
            
            # Count events in window
            count = sum(1 for e in events[i:] 
                       if window_start <= e.timestamp < window_end)
            
            if count > max_count:
                max_count = count
                peak_start = window_start
                peak_end = window_end
        
        return {
            "start_time": peak_start.isoformat() if peak_start else None,
            "end_time": peak_end.isoformat() if peak_end else None,
            "event_count": max_count,
            "events_per_minute": round(max_count / window_minutes, 2)
        }
    
    def _build_severity_timeline(self, events: List[IoCEvent]) -> Dict[str, Any]:
        """
        Build timeline of severity levels.
        
        Args:
            events: List of events
            
        Returns:
            Severity timeline data
        """
        severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        severity_first_seen = {}
        severity_last_seen = {}
        
        for event in events:
            severity = event.severity
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            if severity not in severity_first_seen:
                severity_first_seen[severity] = event.timestamp
            severity_last_seen[severity] = event.timestamp
        
        return {
            "severity_counts": severity_counts,
            "first_seen": {k: v.isoformat() for k, v in severity_first_seen.items()},
            "last_seen": {k: v.isoformat() for k, v in severity_last_seen.items()}
        }
    
    def _build_timeline_sequence(self, events: List[IoCEvent]) -> List[Dict[str, Any]]:
        """
        Build chronological timeline sequence.
        
        Args:
            events: Sorted list of events
            
        Returns:
            List of timeline entries
        """
        if not events:
            return []
        
        timeline = []
        
        if self.time_grouping == "none":
            # Individual events
            for i, event in enumerate(events):
                timeline.append(self._format_timeline_event(event, i + 1))
        else:
            # Group by time periods
            grouped_events = self._group_events_by_time(events)
            
            for group_time, group_events in grouped_events:
                timeline_entry = self._format_timeline_group(group_time, group_events)
                timeline.append(timeline_entry)
                
                if self.include_gaps and len(timeline) > 1:
                    # Check for gaps between groups
                    gap_info = self._check_for_gap(timeline[-2], timeline[-1])
                    if gap_info:
                        timeline.insert(-1, gap_info)
        
        return timeline
    
    def _group_events_by_time(self, events: List[IoCEvent]) -> List[tuple]:
        """
        Group events by time period.
        
        Args:
            events: List of events
            
        Returns:
            List of (group_time, group_events) tuples
        """
        groups = {}
        
        for event in events:
            if self.time_grouping == "minute":
                group_key = event.timestamp.replace(second=0, microsecond=0)
            elif self.time_grouping == "hour":
                group_key = event.timestamp.replace(minute=0, second=0, microsecond=0)
            elif self.time_grouping == "second":
                group_key = event.timestamp.replace(microsecond=0)
            else:
                group_key = event.timestamp
            
            if group_key not in groups:
                groups[group_key] = []
            groups[group_key].append(event)
        
        # Sort groups by time and events within groups
        sorted_groups = []
        for group_time in sorted(groups.keys()):
            group_events = groups[group_time]
            
            # Sort within group
            if self.sort_within_groups == "severity":
                group_events.sort(key=lambda e: ("HIGH", "MEDIUM", "LOW").index(e.severity))
            elif self.sort_within_groups == "category":
                group_events.sort(key=lambda e: e.category)
            elif self.sort_within_groups == "source":
                group_events.sort(key=lambda e: e.source)
            
            sorted_groups.append((group_time, group_events))
        
        return sorted_groups
    
    def _format_timeline_event(self, event: IoCEvent, sequence_number: int) -> Dict[str, Any]:
        """
        Format single timeline event.
        
        Args:
            event: IoC event
            sequence_number: Sequence number in timeline
            
        Returns:
            Formatted timeline event
        """
        return {
            "sequence": sequence_number,
            "timestamp": event.timestamp.isoformat(),
            "event_type": "ioc_detection",
            "category": event.category,
            "severity": event.severity,
            "source": event.source,
            "details": event.details,
            "metadata": dict(event.metadata) if event.metadata else {}
        }
    
    def _format_timeline_group(self, group_time: datetime, events: List[IoCEvent]) -> Dict[str, Any]:
        """
        Format timeline group.
        
        Args:
            group_time: Time of the group
            events: Events in the group
            
        Returns:
            Formatted timeline group
        """
        return {
            "timestamp": group_time.isoformat(),
            "event_type": "time_group",
            "group_duration": self.time_grouping,
            "event_count": len(events),
            "severity_summary": self._summarize_group_severity(events),
            "category_summary": self._summarize_group_categories(events),
            "events": [self._format_grouped_event(event) for event in events]
        }
    
    def _format_grouped_event(self, event: IoCEvent) -> Dict[str, Any]:
        """
        Format event within a group.
        
        Args:
            event: IoC event
            
        Returns:
            Formatted grouped event
        """
        if self.format_style == "compact":
            return {
                "time": event.timestamp.strftime("%H:%M:%S"),
                "severity": event.severity,
                "category": event.category,
                "details": event.details[:50] + "..." if len(event.details) > 50 else event.details
            }
        else:
            return {
                "timestamp": event.timestamp.isoformat(),
                "category": event.category,
                "severity": event.severity,
                "source": event.source,
                "details": event.details,
                "metadata": dict(event.metadata) if event.metadata else {}
            }
    
    def _summarize_group_severity(self, events: List[IoCEvent]) -> Dict[str, int]:
        """Summarize severity levels in a group."""
        counts = {}
        for event in events:
            counts[event.severity] = counts.get(event.severity, 0) + 1
        return counts
    
    def _summarize_group_categories(self, events: List[IoCEvent]) -> Dict[str, int]:
        """Summarize categories in a group."""
        counts = {}
        for event in events:
            counts[event.category] = counts.get(event.category, 0) + 1
        return counts
    
    def _check_for_gap(self, prev_entry: Dict[str, Any], current_entry: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check for significant time gap between entries.
        
        Args:
            prev_entry: Previous timeline entry
            current_entry: Current timeline entry
            
        Returns:
            Gap information if gap is significant, None otherwise
        """
        if not self.include_gaps:
            return {}
        
        prev_time = datetime.fromisoformat(prev_entry["timestamp"])
        current_time = datetime.fromisoformat(current_entry["timestamp"])
        
        gap_duration = (current_time - prev_time).total_seconds() / 60  # Minutes
        
        if gap_duration > self.gap_threshold_minutes:
            return {
                "timestamp": prev_time.isoformat(),
                "event_type": "time_gap",
                "gap_duration_minutes": round(gap_duration, 1),
                "gap_description": f"No activity for {self._format_duration(gap_duration * 60)}"
            }
        
        return {}
    
    def _format_duration(self, seconds: float) -> str:
        """
        Format duration in human-readable format.
        
        Args:
            seconds: Duration in seconds
            
        Returns:
            Formatted duration string
        """
        if seconds < 60:
            return f"{int(seconds)} seconds"
        elif seconds < 3600:
            minutes = int(seconds / 60)
            return f"{minutes} minutes"
        else:
            hours = int(seconds / 3600)
            minutes = int((seconds % 3600) / 60)
            return f"{hours}h {minutes}m"
    
    def _json_serializer(self, obj: Any) -> Any:
        """Custom JSON serializer for non-serializable objects."""
        if isinstance(obj, datetime):
            return obj.isoformat()
        elif hasattr(obj, '__dict__'):
            return obj.__dict__
        else:
            return str(obj)
    
    def get_required_config_keys(self) -> List[str]:
        """Get required configuration keys for timeline export."""
        return []  # No required config, all have defaults
    
    def validate_configuration(self) -> bool:
        """Validate timeline exporter configuration."""
        # Validate time_grouping
        valid_groupings = ["none", "second", "minute", "hour"]
        if self.time_grouping not in valid_groupings:
            self.logger.error(f"Timeline time_grouping must be one of {valid_groupings}, got: '{self.time_grouping}'")
            return False
        
        # Validate sort_within_groups
        valid_sorts = ["severity", "category", "source", "timestamp"]
        if self.sort_within_groups not in valid_sorts:
            self.logger.error(f"Timeline sort_within_groups must be one of {valid_sorts}, got: '{self.sort_within_groups}'")
            return False
        
        # Validate format_style
        valid_styles = ["detailed", "compact", "forensic"]
        if self.format_style not in valid_styles:
            self.logger.error(f"Timeline format_style must be one of {valid_styles}, got: '{self.format_style}'")
            return False
        
        # Validate gap_threshold_minutes
        if not isinstance(self.gap_threshold_minutes, (int, float)) or self.gap_threshold_minutes < 0:
            self.logger.error(f"Timeline gap_threshold_minutes must be non-negative number, got: {self.gap_threshold_minutes}")
            return False
        
        return True
    
    def get_capabilities(self) -> Dict[str, Any]:
        """Get timeline exporter capabilities."""
        return {
            "streaming": self.supports_streaming,
            "batch_size": None,  # Processes all events at once for chronological sorting
            "memory_efficient": False,  # Requires all events in memory for sorting
            "supports_metadata": True,
            "supports_filtering": False,  # Filtering done before export
            "time_grouping_options": ["none", "second", "minute", "hour"],
            "format_styles": ["detailed", "compact", "forensic"],
            "supports_gaps": True,
            "supports_statistics": True
        }
