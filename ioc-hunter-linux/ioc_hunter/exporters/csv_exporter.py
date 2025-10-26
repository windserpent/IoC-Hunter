"""
CSV Exporter for IoC-Hunter Linux

Exports IoC scan results to CSV format for spreadsheet analysis.
Compatible with Excel, LibreOffice Calc, and other spreadsheet applications.

Python 3.9+ compatible.
"""

import csv
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Union, IO

from ..core.base_exporter import BaseExporter, ExportMetadata
from ..core.base_category import IoCEvent


class CSVExporter(BaseExporter):
    """
    CSV format exporter for IoC scan results.
    
    Exports events in comma-separated values format suitable for:
    - Spreadsheet analysis (Excel, LibreOffice Calc)
    - Data analysis tools (Python pandas, R)
    - Database imports
    - Report generation
    """
    
    # Required class attributes for auto-discovery
    name = "csv"
    display_name = "CSV Export"
    description = "Comma-separated values format for spreadsheet analysis"
    file_extension = ".csv"
    supports_streaming = True
    version = "1.0.0"
    
    def __init__(self, config_manager=None):
        super().__init__(config_manager)
        
        # Load CSV-specific configuration
        self.csv_config = self.config.get("csv", {})
        
        # CSV formatting options
        self.delimiter = self.csv_config.get("delimiter", ",")
        self.include_headers = self.csv_config.get("include_headers", True)
        self.quote_character = self.csv_config.get("quote_character", '"')
        self.escape_character = self.csv_config.get("escape_character", "\\")
        self.date_format = self.csv_config.get("date_format", "%Y-%m-%d %H:%M:%S")
        
        # Field configuration
        self.fields = self.csv_config.get("fields", [
            "timestamp",
            "severity", 
            "category",
            "event_type",
            "source",
            "details",
            "source_ip",
            "username"
        ])
        
        self.logger.info(f"Initialized CSV exporter with {len(self.fields)} fields")
    
    def export(self, events: List[IoCEvent], metadata: ExportMetadata, 
              output: Union[str, Path, IO]) -> bool:
        """
        Export IoC events to CSV format.
        
        Args:
            events: List of IoC events to export
            metadata: Export metadata
            output: Output destination (file path or file-like object)
            
        Returns:
            True if export was successful
        """
        try:
            # Determine if we're writing to file or file-like object
            if isinstance(output, (str, Path)):
                with open(output, 'w', newline='', encoding='utf-8') as csvfile:
                    return self._write_csv(events, metadata, csvfile)
            else:
                return self._write_csv(events, metadata, output)
                
        except Exception as e:
            self.logger.error(f"CSV export failed: {e}")
            return False
    
    def _write_csv(self, events: List[IoCEvent], metadata: ExportMetadata, csvfile: IO) -> bool:
        """
        Write CSV data to file-like object.
        
        Args:
            events: Events to write
            metadata: Export metadata
            csvfile: File-like object to write to
            
        Returns:
            True if successful
        """
        try:
            # Create CSV writer
            writer = csv.writer(
                csvfile,
                delimiter=self.delimiter,
                quotechar=self.quote_character,
                quoting=csv.QUOTE_MINIMAL,
                escapechar=self.escape_character if self.escape_character != '"' else None
            )
            
            # Write headers if enabled
            if self.include_headers:
                headers = self._get_csv_headers()
                writer.writerow(headers)
                
                # Write metadata comment if this is the first line
                if self.csv_config.get("include_metadata_comment", True):
                    self._write_metadata_comment(csvfile, metadata)
            
            # Write events
            for event in events:
                row = self._event_to_csv_row(event)
                writer.writerow(row)
            
            self.logger.info(f"Successfully exported {len(events)} events to CSV")
            return True
            
        except Exception as e:
            self.logger.error(f"Error writing CSV data: {e}")
            return False
    
    def _get_csv_headers(self) -> List[str]:
        """
        Get CSV column headers.
        
        Returns:
            List of header strings
        """
        # Map internal field names to display names
        header_mapping = {
            "timestamp": "Timestamp",
            "severity": "Severity",
            "category": "Category", 
            "event_type": "Event Type",
            "source": "Log Source",
            "details": "Details",
            "source_ip": "Source IP",
            "username": "Username",
            "raw_log": "Raw Log Entry",
            "hostname": "Hostname",
            "pid": "Process ID",
            "service": "Service"
        }
        
        return [header_mapping.get(field, field.title()) for field in self.fields]
    
    def _event_to_csv_row(self, event: IoCEvent) -> List[str]:
        """
        Convert IoC event to CSV row.
        
        Args:
            event: IoC event to convert
            
        Returns:
            List of field values for CSV row
        """
        row = []
        
        for field in self.fields:
            value = self._get_field_value(event, field)
            
            # Convert to string and handle None values
            if value is None:
                row.append("")
            elif isinstance(value, datetime):
                row.append(value.strftime(self.date_format))
            else:
                row.append(str(value))
        
        return row
    
    def _get_field_value(self, event: IoCEvent, field: str) -> Any:
        """
        Get field value from IoC event.
        
        Args:
            event: IoC event
            field: Field name
            
        Returns:
            Field value or None if not found
        """
        # Direct event attributes
        if hasattr(event, field):
            return getattr(event, field)
        
        # Metadata fields
        if field in event.metadata:
            return event.metadata[field]
        
        # Special computed fields
        if field == "source_ip":
            return event.metadata.get("source_ip", "")
        elif field == "username":
            return event.metadata.get("username", "")
        elif field == "hostname":
            return event.metadata.get("hostname", event.metadata.get("_HOSTNAME", ""))
        elif field == "pid":
            return event.metadata.get("pid", event.metadata.get("_PID", ""))
        elif field == "service":
            return event.metadata.get("service", event.metadata.get("SYSLOG_IDENTIFIER", ""))
        
        return None
    
    def _write_metadata_comment(self, csvfile: IO, metadata: ExportMetadata):
        """
        Write export metadata as CSV comment.
        
        Args:
            csvfile: File to write to
            metadata: Export metadata
        """
        try:
            csvfile.write(f"# IoC-Hunter Linux Export\n")
            csvfile.write(f"# Export Time: {metadata.export_time.strftime(self.date_format)}\n")
            csvfile.write(f"# Scan Range: {metadata.scan_begin.strftime(self.date_format)} to {metadata.scan_end.strftime(self.date_format)}\n")
            csvfile.write(f"# Categories: {', '.join(metadata.categories_scanned)}\n")
            csvfile.write(f"# Total Events: {metadata.total_events}\n")
            csvfile.write(f"# Scanner Version: {metadata.scanner_version}\n")
            csvfile.write("#\n")
        except Exception as e:
            self.logger.warning(f"Could not write metadata comment: {e}")
    
    def get_required_config_keys(self) -> List[str]:
        """Get required configuration keys for CSV export."""
        return []  # No required config, all have defaults
    
    def validate_configuration(self) -> bool:
        """Validate CSV exporter configuration."""
        # Validate delimiter
        if len(self.delimiter) != 1:
            self.logger.error(f"CSV delimiter must be single character, got: '{self.delimiter}'")
            return False
        
        # Validate quote character  
        if len(self.quote_character) != 1:
            self.logger.error(f"CSV quote character must be single character, got: '{self.quote_character}'")
            return False
        
        # Validate fields
        if not self.fields:
            self.logger.error("CSV fields list cannot be empty")
            return False
        
        # Validate date format
        try:
            test_date = datetime.now()
            test_date.strftime(self.date_format)
        except ValueError as e:
            self.logger.error(f"Invalid CSV date format '{self.date_format}': {e}")
            return False
        
        self.logger.debug("CSV configuration validation passed")
        return True
    
    def get_sample_output(self, events: List[IoCEvent]) -> str:
        """
        Generate sample CSV output for preview.
        
        Args:
            events: Sample events (first 5 will be used)
            
        Returns:
            Sample CSV output as string
        """
        if not events:
            return "# No events to export\n"
        
        # Create sample metadata
        sample_metadata = ExportMetadata(
            scan_begin=events[0].timestamp,
            scan_end=events[-1].timestamp,
            categories_scanned=list(set(event.category for event in events)),
            total_events=len(events),
            export_format="csv"
        )
        
        # Export sample (first 5 events max)
        sample_events = events[:5]
        
        try:
            return self.export_to_string(sample_events, sample_metadata) or "Export failed"
        except Exception as e:
            return f"# Error generating sample: {e}\n"


# Register the exporter for auto-discovery
from ..core.base_exporter import exporter_registry
exporter_registry.register_exporter(CSVExporter)