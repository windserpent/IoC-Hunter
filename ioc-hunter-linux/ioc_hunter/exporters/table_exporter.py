"""
Table Exporter for IoC-Hunter Linux

Exports IoC scan results to formatted table for command-line display.
Optimized for terminal output with color coding and column formatting.

Python 3.9+ compatible.
"""

import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Union, IO, Optional, cast

from ..core.base_exporter import BaseExporter, ExportMetadata
from ..core.base_category import IoCEvent


class TableExporter(BaseExporter):
    """
    Table format exporter for IoC scan results.
    
    Exports events in formatted table suitable for:
    - Command-line display
    - Terminal output
    - Quick visual analysis
    - Console-based workflows
    """
    
    # Required class attributes for auto-discovery
    name = "table"
    display_name = "Table Display"
    description = "Formatted table for command-line display"
    file_extension = ".txt"
    supports_streaming = True
    version = "1.0.0"
    
    def __init__(self, config_manager=None):
        super().__init__(config_manager)
        
        # Load table-specific configuration
        self.table_config = self.config.get("table", {})
        
        # Table formatting options
        self.use_colors = self.table_config.get("use_colors", True)
        self.max_width = self.table_config.get("max_width", 120)
        self.timestamp_format = self.table_config.get("timestamp_format", "%Y-%m-%d %H:%M:%S")
        self.show_metadata = self.table_config.get("show_metadata", True)
        self.severity_colors = self.table_config.get("severity_colors", {
            "HIGH": "\033[91m",    # Red
            "MEDIUM": "\033[93m",  # Yellow  
            "LOW": "\033[0m"       # Normal
        })
        self.reset_color = "\033[0m"
        
        # Column configuration
        self.columns = self.table_config.get("columns", [
            {"name": "timestamp", "width": 19, "title": "Time"},
            {"name": "severity", "width": 8, "title": "Severity"},
            {"name": "category", "width": 20, "title": "Category"},
            {"name": "details", "width": 50, "title": "Details"}
        ])
        
        # Disable colors if not in terminal or disabled
        if not self.use_colors or not sys.stdout.isatty():
            self.use_colors = False
            self.severity_colors = {k: "" for k in self.severity_colors}
            self.reset_color = ""
    
    def export(self, events: List[IoCEvent], metadata: ExportMetadata, 
               output: Optional[Union[str, Path, IO]] = None, **kwargs) -> bool:
        """
        Export IoC events to table format.
        
        Args:
            events: List of IoC events to export
            metadata: Export metadata
            output: Path to write table file (None = stdout)
            **kwargs: Additional export options
            
        Returns:
            True if export successful, False otherwise
        """
        try:
            self.logger.debug(f"Starting table export for {len(events)} events")
            
            # Determine output destination and handle different types
            close_file = False
            if output is None:
                # Default to stdout
                output_file = sys.stdout
                use_colors = self.use_colors
                severity_colors = self.severity_colors
                reset_color = self.reset_color
            elif hasattr(output, 'write'):
                # output is an IO object, use it directly
                output_file = cast(IO, output)
                # Disable colors for IO stream output
                use_colors = False
                severity_colors = {k: "" for k in self.severity_colors}
                reset_color = ""
            else:
                # output is a path-like object, convert to Path and handle file creation
                path_output = cast(Union[str, Path], output)
                output_path = Path(path_output)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_file = open(output_path, 'w', encoding='utf-8')
                close_file = True
                # Disable colors for file output
                use_colors = False
                severity_colors = {k: "" for k in self.severity_colors}
                reset_color = ""
            
            try:
                # Write header information
                if self.show_metadata:
                    self._write_header(output_file, metadata, use_colors, reset_color)
                
                # Write table
                self._write_table(output_file, events, use_colors, severity_colors, reset_color)
                
                # Write summary
                if self.show_metadata:
                    self._write_summary(output_file, events, use_colors, reset_color)
                
            finally:
                if close_file:
                    output_file.close()
            
            if output is None:
                self.logger.info("Table export completed to stdout")
            elif hasattr(output, 'write'):
                self.logger.info("Table export completed to IO stream")
            else:
                self.logger.info(f"Table export completed: {output}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Table export failed: {e}")
            return False
    
    def _write_header(self, output_file: IO, metadata: ExportMetadata, 
                     use_colors: bool, reset_color: str):
        """
        Write table header with metadata.
        
        Args:
            output_file: File to write to
            metadata: Export metadata
            use_colors: Whether to use color formatting
            reset_color: Reset color sequence
        """
        header_color = "\033[96m" if use_colors else ""  # Cyan
        
        output_file.write(f"{header_color}{'='*60}{reset_color}\n")
        output_file.write(f"{header_color}IoC-Hunter Linux Scan Results{reset_color}\n")
        output_file.write(f"{header_color}{'='*60}{reset_color}\n")
        output_file.write(f"Export Time: {metadata.export_time.strftime(self.timestamp_format)}\n")
        output_file.write(f"Scan Range: {metadata.scan_begin.strftime(self.timestamp_format)} to {metadata.scan_end.strftime(self.timestamp_format)}\n")
        output_file.write(f"Categories: {', '.join(metadata.categories_scanned)}\n")
        output_file.write(f"Total Events: {metadata.total_events}\n")
        output_file.write(f"Scanner Version: {metadata.scanner_version}\n")
        output_file.write(f"{header_color}{'='*60}{reset_color}\n\n")
    
    def _write_table(self, output_file: IO, events: List[IoCEvent],
                    use_colors: bool, severity_colors: Dict[str, str], reset_color: str):
        """
        Write formatted table of events.
        
        Args:
            output_file: File to write to
            events: List of events to display
            use_colors: Whether to use color formatting
            severity_colors: Color codes for severity levels
            reset_color: Reset color sequence
        """
        if not events:
            output_file.write("No IoC events found.\n")
            return
        
        # Calculate column widths
        col_widths = [col["width"] for col in self.columns]
        
        # Write table header
        header_line = " | ".join(
            col["title"].ljust(width) 
            for col, width in zip(self.columns, col_widths)
        )
        output_file.write(f"{header_line}\n")
        output_file.write("-" * len(header_line) + "\n")
        
        # Write events
        for event in events:
            self._write_event_row(output_file, event, col_widths, 
                                use_colors, severity_colors, reset_color)
    
    def _write_event_row(self, output_file: IO, event: IoCEvent, col_widths: List[int],
                        use_colors: bool, severity_colors: Dict[str, str], reset_color: str):
        """
        Write single event row.
        
        Args:
            output_file: File to write to
            event: Event to write
            col_widths: Column widths
            use_colors: Whether to use color formatting
            severity_colors: Color codes for severity levels
            reset_color: Reset color sequence
        """
        # Format values for each column
        values = []
        for col in self.columns:
            value = self._get_column_value(event, col["name"])
            
            # Truncate if too long
            if len(value) > col["width"]:
                value = value[:col["width"]-3] + "..."
            
            values.append(value.ljust(col["width"]))
        
        # Create row with color coding
        row_line = " | ".join(values)
        
        if use_colors and event.severity in severity_colors:
            color = severity_colors[event.severity]
            row_line = f"{color}{row_line}{reset_color}"
        
        output_file.write(f"{row_line}\n")
    
    def _get_column_value(self, event: IoCEvent, column_name: str) -> str:
        """
        Get formatted value for a column.
        
        Args:
            event: IoC event
            column_name: Name of column
            
        Returns:
            Formatted string value
        """
        if column_name == "timestamp":
            return event.timestamp.strftime(self.timestamp_format)
        elif column_name == "severity":
            return event.severity
        elif column_name == "category":
            return event.category
        elif column_name == "source":
            return event.source
        elif column_name == "details":
            return event.details
        elif column_name in event.metadata:
            return str(event.metadata[column_name])
        else:
            return ""
    
    def _write_summary(self, output_file: IO, events: List[IoCEvent],
                      use_colors: bool, reset_color: str):
        """
        Write summary statistics.
        
        Args:
            output_file: File to write to
            events: List of events
            use_colors: Whether to use color formatting
            reset_color: Reset color sequence
        """
        if not events:
            return
        
        header_color = "\033[96m" if use_colors else ""  # Cyan
        
        output_file.write(f"\n{header_color}Summary:{reset_color}\n")
        
        # Count by severity
        severity_counts = {}
        for event in events:
            severity = event.severity
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        for severity, count in sorted(severity_counts.items()):
            color = self.severity_colors.get(severity, "") if use_colors else ""
            output_file.write(f"  {color}{severity}: {count}{reset_color}\n")
        
        # Count by category
        category_counts = {}
        for event in events:
            category = event.category
            category_counts[category] = category_counts.get(category, 0) + 1
        
        if len(category_counts) > 1:
            output_file.write(f"\nCategories:\n")
            for category, count in sorted(category_counts.items()):
                output_file.write(f"  {category}: {count}\n")
    
    def get_required_config_keys(self) -> List[str]:
        """Get required configuration keys for table export."""
        return []  # No required config, all have defaults
    
    def validate_configuration(self) -> bool:
        """Validate table exporter configuration."""
        # Validate max_width
        if not isinstance(self.max_width, int) or self.max_width < 40:
            self.logger.error(f"Table max_width must be integer >= 40, got: {self.max_width}")
            return False
        
        # Validate columns configuration
        if not isinstance(self.columns, list) or not self.columns:
            self.logger.error("Table columns must be non-empty list")
            return False
        
        for col in self.columns:
            if not isinstance(col, dict):
                self.logger.error(f"Table column must be dictionary, got: {type(col)}")
                return False
            
            required_keys = ["name", "width", "title"]
            for key in required_keys:
                if key not in col:
                    self.logger.error(f"Table column missing required key: {key}")
                    return False
            
            if not isinstance(col["width"], int) or col["width"] < 1:
                self.logger.error(f"Table column width must be positive integer, got: {col['width']}")
                return False
        
        # Validate timestamp format
        try:
            datetime.now().strftime(self.timestamp_format)
        except ValueError as e:
            self.logger.error(f"Invalid timestamp format '{self.timestamp_format}': {e}")
            return False
        
        return True
    
    def get_capabilities(self) -> Dict[str, Any]:
        """Get table exporter capabilities."""
        return {
            "streaming": self.supports_streaming,
            "batch_size": 100,  # Process in batches for large datasets
            "memory_efficient": True,
            "supports_metadata": True,
            "supports_filtering": False,  # Filtering done before export
            "supports_colors": True,
            "terminal_output": True,
            "file_output": True
        }
