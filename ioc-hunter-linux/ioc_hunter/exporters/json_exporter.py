"""
JSON Exporter for IoC-Hunter Linux

Exports IoC scan results to JSON format for programmatic analysis and integration.
Compatible with REST APIs, data analysis tools, and other JSON consumers.

Python 3.9+ compatible.
"""

import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any, Union, IO

from ..core.base_exporter import BaseExporter, ExportMetadata
from ..core.base_category import IoCEvent


class JSONExporter(BaseExporter):
    """
    JSON format exporter for IoC scan results.
    
    Exports events in JavaScript Object Notation format suitable for:
    - REST API integration
    - Data analysis tools (Python, JavaScript)
    - SIEM ingestion
    - Web applications
    - Report generation tools
    """
    
    # Required class attributes for auto-discovery
    name = "json"
    display_name = "JSON Export"
    description = "JavaScript Object Notation format for programmatic analysis"
    file_extension = ".json"
    supports_streaming = False  # JSON requires complete document structure
    version = "1.0.0"
    
    def __init__(self, config_manager=None):
        super().__init__(config_manager)
        
        # Load JSON-specific configuration
        self.json_config = self.config.get("json", {})
        
        # JSON formatting options
        self.indent = self.json_config.get("indent", 2)
        self.ensure_ascii = self.json_config.get("ensure_ascii", False)
        self.sort_keys = self.json_config.get("sort_keys", True)
        self.include_metadata = self.json_config.get("include_metadata", True)
        self.timestamp_format = self.json_config.get("timestamp_format", "iso")  # iso, epoch, or custom
        self.custom_timestamp_format = self.json_config.get("custom_timestamp_format", "%Y-%m-%d %H:%M:%S")
        
    def export(self, events: List[IoCEvent], metadata: ExportMetadata, 
               output: Union[str, Path, IO], **kwargs) -> bool:
        """
        Export IoC events to JSON format.
        
        Args:
            events: List of IoC events to export
            metadata: Export metadata
            output: Path to write JSON file or IO object to write to
            **kwargs: Additional export options
            
        Returns:
            True if export successful, False otherwise
        """
        try:
            self.logger.info(f"Starting JSON export to {output}")
            self.logger.debug(f"Exporting {len(events)} events")
            
            # Build JSON document structure
            json_document = self._build_json_document(events, metadata)

            # Handle different output types
            if hasattr(output, 'write'):
                # It's an IO object, write directly
                from typing import cast, TextIO
                output_io = cast(TextIO, output)
                json.dump(
                    json_document,
                    output_io,
                    indent=self.indent,
                    ensure_ascii=self.ensure_ascii,
                    sort_keys=self.sort_keys,
                    default=self._json_serializer
                )
                self.logger.info(f"JSON export completed to IO stream")
            else:
                # It's a path, prepare output path
                from typing import cast, Union
                output_path_str = cast(Union[str, Path], output)
                output_path = Path(output_path_str)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                
                # Write JSON file
                with open(output_path, 'w', encoding='utf-8') as jsonfile:
                    json.dump(
                        json_document,
                        jsonfile,
                        indent=self.indent,
                        ensure_ascii=self.ensure_ascii,
                        sort_keys=self.sort_keys,
                        default=self._json_serializer
                    )
                
                self.logger.info(f"JSON export completed: {output_path}")

            return True
            
        except Exception as e:
            self.logger.error(f"JSON export failed: {e}")
            return False
    
    def _build_json_document(self, events: List[IoCEvent], metadata: ExportMetadata) -> Dict[str, Any]:
        """
        Build complete JSON document structure.
        
        Args:
            events: List of IoC events
            metadata: Export metadata
            
        Returns:
            Complete JSON document as dictionary
        """
        document = {}
        
        # Add metadata if enabled
        if self.include_metadata:
            document["export_metadata"] = self._format_metadata(metadata)
        
        # Add summary statistics
        document["summary"] = self._build_summary(events)
        
        # Add events
        document["events"] = [self._format_event(event) for event in events]
        
        return document
    
    def _format_metadata(self, metadata: ExportMetadata) -> Dict[str, Any]:
        """
        Format export metadata for JSON output.
        
        Args:
            metadata: Export metadata
            
        Returns:
            Formatted metadata dictionary
        """
        return {
            "scanner_version": metadata.scanner_version,
            "export_time": self._format_timestamp(metadata.export_time),
            "scan_begin": self._format_timestamp(metadata.scan_begin),
            "scan_end": self._format_timestamp(metadata.scan_end),
            "categories_scanned": metadata.categories_scanned,
            "total_events": metadata.total_events,
            "scan_duration_seconds": metadata.scan_duration.total_seconds() if isinstance(metadata.scan_duration, timedelta) else (float(metadata.scan_duration) if metadata.scan_duration else None),
            "export_format": "json",
            "export_version": self.version
        }
    
    def _build_summary(self, events: List[IoCEvent]) -> Dict[str, Any]:
        """
        Build summary statistics from events.
        
        Args:
            events: List of IoC events
            
        Returns:
            Summary statistics dictionary
        """
        if not events:
            return {
                "total_events": 0,
                "severity_counts": {},
                "category_counts": {},
                "time_range": None
            }
        
        # Count by severity
        severity_counts = {}
        for event in events:
            severity = event.severity
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Count by category
        category_counts = {}
        for event in events:
            category = event.category
            category_counts[category] = category_counts.get(category, 0) + 1
        
        # Determine time range
        timestamps = [event.timestamp for event in events]
        time_range = {
            "earliest": self._format_timestamp(min(timestamps)),
            "latest": self._format_timestamp(max(timestamps))
        } if timestamps else None
        
        return {
            "total_events": len(events),
            "severity_counts": severity_counts,
            "category_counts": category_counts,
            "time_range": time_range
        }
    
    def _format_event(self, event: IoCEvent) -> Dict[str, Any]:
        """
        Format single IoC event for JSON output.
        
        Args:
            event: IoC event to format
            
        Returns:
            Formatted event dictionary
        """
        return {
            "timestamp": self._format_timestamp(event.timestamp),
            "category": event.category,
            "severity": event.severity,
            "source": event.source,
            "details": event.details,
            "metadata": dict(event.metadata) if event.metadata else {}
        }
    
    def _format_timestamp(self, timestamp: datetime) -> Union[str, int, float]:
        """
        Format timestamp according to configuration.
        
        Args:
            timestamp: Datetime to format
            
        Returns:
            Formatted timestamp
        """
        if self.timestamp_format == "iso":
            return timestamp.isoformat()
        elif self.timestamp_format == "epoch":
            return timestamp.timestamp()
        elif self.timestamp_format == "custom":
            return timestamp.strftime(self.custom_timestamp_format)
        else:
            # Default to ISO format
            return timestamp.isoformat()
    
    def _json_serializer(self, obj: Any) -> Any:
        """
        Custom JSON serializer for non-serializable objects.
        
        Args:
            obj: Object to serialize
            
        Returns:
            Serializable representation
        """
        if isinstance(obj, datetime):
            return self._format_timestamp(obj)
        elif hasattr(obj, '__dict__'):
            return obj.__dict__
        else:
            return str(obj)
    
    def get_required_config_keys(self) -> List[str]:
        """Get required configuration keys for JSON export."""
        return []  # No required config, all have defaults
    
    def validate_configuration(self) -> bool:
        """Validate JSON exporter configuration."""
        # Validate indent
        if not isinstance(self.indent, (int, type(None))):
            self.logger.error(f"JSON indent must be integer or None, got: {type(self.indent)}")
            return False
        
        if isinstance(self.indent, int) and self.indent < 0:
            self.logger.error(f"JSON indent must be non-negative, got: {self.indent}")
            return False
        
        # Validate timestamp format
        valid_formats = ["iso", "epoch", "custom"]
        if self.timestamp_format not in valid_formats:
            self.logger.error(f"JSON timestamp_format must be one of {valid_formats}, got: '{self.timestamp_format}'")
            return False
        
        # Validate custom timestamp format if used
        if self.timestamp_format == "custom":
            try:
                datetime.now().strftime(self.custom_timestamp_format)
            except ValueError as e:
                self.logger.error(f"Invalid custom timestamp format '{self.custom_timestamp_format}': {e}")
                return False
        
        return True
    
    def get_capabilities(self) -> Dict[str, Any]:
        """Get JSON exporter capabilities."""
        return {
            "streaming": self.supports_streaming,
            "batch_size": None,  # No batch processing for JSON
            "memory_efficient": False,  # Builds complete document in memory
            "supports_metadata": True,
            "supports_filtering": False,  # Filtering done before export
            "timestamp_formats": ["iso", "epoch", "custom"],
            "max_file_size": None  # No inherent limit
        }