"""
Base Exporter Class for IoC-Hunter Linux

Abstract base class for all export format implementations.
This class defines the interface that all exporters must implement,
ensuring consistency and extensibility.

Python 3.9+ compatible.
"""

import logging
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Union, IO
from .base_category import IoCEvent


class ExportMetadata:
    """
    Metadata for exported IoC data.
    
    Contains information about the scan and export process.
    """
    
    def __init__(self, 
                 scan_begin: datetime,
                 scan_end: datetime,
                 categories_scanned: List[str],
                 total_events: int,
                 export_format: str,
                 export_time: Optional[datetime] = None,
                 scanner_version: str = "1.0.0",
                 additional_info: Optional[Dict[str, Any]] = None):
        """
        Initialize export metadata.
        
        Args:
            scan_begin: Scan start time
            scan_end: Scan end time
            categories_scanned: List of categories that were scanned
            total_events: Total number of events found
            export_format: Export format name
            export_time: When export was performed (defaults to now)
            scanner_version: IoC-Hunter version
            additional_info: Additional metadata
        """
        self.scan_begin = scan_begin
        self.scan_end = scan_end
        self.categories_scanned = categories_scanned
        self.total_events = total_events
        self.export_format = export_format
        self.export_time = export_time or datetime.now()
        self.scanner_version = scanner_version
        self.additional_info = additional_info or {}
        
        # Calculate scan duration
        self.scan_duration = (scan_end - scan_begin).total_seconds()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metadata to dictionary format."""
        return {
            "scan_begin": self.scan_begin.isoformat(),
            "scan_end": self.scan_end.isoformat(),
            "scan_duration_seconds": self.scan_duration,
            "categories_scanned": self.categories_scanned,
            "total_events": self.total_events,
            "export_format": self.export_format,
            "export_time": self.export_time.isoformat(),
            "scanner_version": self.scanner_version,
            "additional_info": self.additional_info
        }


class BaseExporter(ABC):
    """
    Abstract base class for all IoC export formats.
    
    All exporters must inherit from this class and implement
    the required abstract methods. This ensures consistency across
    all export formats and enables auto-discovery.
    """
    
    # Exporter metadata - must be defined by subclasses
    name: str = None              # Exporter name (e.g., "csv")
    display_name: str = None      # Human-readable name (e.g., "CSV Export")
    description: str = None       # Exporter description
    file_extension: str = None    # Default file extension (e.g., ".csv")
    supports_streaming: bool = False  # Whether exporter supports streaming output
    version: str = "1.0.0"       # Exporter version
    
    def __init__(self, config_manager=None):
        """
        Initialize exporter.
        
        Args:
            config_manager: Configuration manager instance
        """
        # Validate required class attributes
        if not self.name:
            raise ValueError(f"Exporter {self.__class__.__name__} must define 'name' class attribute")
        if not self.display_name:
            raise ValueError(f"Exporter {self.__class__.__name__} must define 'display_name' class attribute")
        if not self.description:
            raise ValueError(f"Exporter {self.__class__.__name__} must define 'description' class attribute")
        if not self.file_extension:
            raise ValueError(f"Exporter {self.__class__.__name__} must define 'file_extension' class attribute")
        
        self.config_manager = config_manager
        self.logger = logging.getLogger(f"{__name__}.{self.name}")
        
        # Load exporter-specific configuration
        self.config = self._load_config()
    
    @abstractmethod
    def export(self, events: List[IoCEvent], metadata: ExportMetadata, 
              output: Union[str, Path, IO]) -> bool:
        """
        Export IoC events to specified output.
        
        This is the main method that performs the actual export.
        Must be implemented by all subclasses.
        
        Args:
            events: List of IoC events to export
            metadata: Export metadata
            output: Output destination (file path or file-like object)
            
        Returns:
            True if export was successful
        """
        pass
    
    def validate_output(self, output: Union[str, Path, IO]) -> bool:
        """
        Validate output destination.
        
        Override this method to perform exporter-specific validation.
        
        Args:
            output: Output destination
            
        Returns:
            True if output is valid
        """
        if isinstance(output, (str, Path)):
            output_path = Path(output)
            
            # Check if parent directory exists or can be created
            try:
                output_path.parent.mkdir(parents=True, exist_ok=True)
                return True
            except Exception as e:
                self.logger.error(f"Cannot create output directory: {e}")
                return False
        
        # For file-like objects, assume they're valid
        return hasattr(output, 'write')
    
    def get_default_filename(self, metadata: ExportMetadata) -> str:
        """
        Generate default filename for export.
        
        Args:
            metadata: Export metadata
            
        Returns:
            Default filename
        """
        timestamp = metadata.export_time.strftime("%Y%m%d_%H%M%S")
        categories = "_".join(metadata.categories_scanned[:3])  # Limit to first 3
        if len(metadata.categories_scanned) > 3:
            categories += "_plus"
        
        filename = f"ioc_hunter_{categories}_{timestamp}{self.file_extension}"
        return filename
    
    def export_to_file(self, events: List[IoCEvent], metadata: ExportMetadata, 
                      file_path: Union[str, Path], overwrite: bool = False) -> bool:
        """
        Export IoC events to file.
        
        Args:
            events: List of IoC events to export
            metadata: Export metadata
            file_path: Output file path
            overwrite: Whether to overwrite existing files
            
        Returns:
            True if export was successful
        """
        file_path = Path(file_path)
        
        # Check if file exists and overwrite flag
        if file_path.exists() and not overwrite:
            self.logger.error(f"Output file exists and overwrite=False: {file_path}")
            return False
        
        # Validate output
        if not self.validate_output(file_path):
            return False
        
        try:
            return self.export(events, metadata, file_path)
        except Exception as e:
            self.logger.error(f"Export failed: {e}")
            return False
    
    def export_to_string(self, events: List[IoCEvent], metadata: ExportMetadata) -> Optional[str]:
        """
        Export IoC events to string.
        
        Args:
            events: List of IoC events to export
            metadata: Export metadata
            
        Returns:
            Exported data as string, or None if failed
        """
        try:
            from io import StringIO
            string_buffer = StringIO()
            
            if self.export(events, metadata, string_buffer):
                return string_buffer.getvalue()
            else:
                return None
                
        except Exception as e:
            self.logger.error(f"String export failed: {e}")
            return None
    
    def get_config(self) -> Dict[str, Any]:
        """Get exporter configuration."""
        return self.config
    
    def get_required_config_keys(self) -> List[str]:
        """
        Get list of required configuration keys.
        
        Override this method to specify required configuration.
        
        Returns:
            List of required configuration keys
        """
        return []
    
    def validate_configuration(self) -> bool:
        """
        Validate exporter configuration.
        
        Override this method to perform exporter-specific validation.
        
        Returns:
            True if configuration is valid
        """
        required_keys = self.get_required_config_keys()
        
        for key in required_keys:
            if key not in self.config:
                self.logger.error(f"Required configuration key missing: {key}")
                return False
        
        return True
    
    def filter_events(self, events: List[IoCEvent], 
                     severity_filter: Optional[List[str]] = None,
                     category_filter: Optional[List[str]] = None,
                     time_filter: Optional[tuple[datetime, datetime]] = None) -> List[IoCEvent]:
        """
        Filter events before export.
        
        Args:
            events: List of events to filter
            severity_filter: List of severities to include
            category_filter: List of categories to include
            time_filter: Tuple of (begin_time, end_time) to filter by
            
        Returns:
            Filtered list of events
        """
        filtered_events = events
        
        # Filter by severity
        if severity_filter:
            severity_set = set(s.upper() for s in severity_filter)
            filtered_events = [e for e in filtered_events if e.severity in severity_set]
        
        # Filter by category
        if category_filter:
            category_set = set(category_filter)
            filtered_events = [e for e in filtered_events if e.category in category_set]
        
        # Filter by time
        if time_filter:
            begin_time, end_time = time_filter
            filtered_events = [e for e in filtered_events 
                             if begin_time <= e.timestamp <= end_time]
        
        return filtered_events
    
    def sort_events(self, events: List[IoCEvent], 
                   sort_by: str = "timestamp", reverse: bool = False) -> List[IoCEvent]:
        """
        Sort events before export.
        
        Args:
            events: List of events to sort
            sort_by: Field to sort by ("timestamp", "severity", "category")
            reverse: Whether to sort in reverse order
            
        Returns:
            Sorted list of events
        """
        if sort_by == "timestamp":
            return sorted(events, key=lambda e: e.timestamp, reverse=reverse)
        elif sort_by == "severity":
            # Define severity order
            severity_order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
            return sorted(events, 
                         key=lambda e: (severity_order.get(e.severity, 0), e.timestamp), 
                         reverse=reverse)
        elif sort_by == "category":
            return sorted(events, key=lambda e: (e.category, e.timestamp), reverse=reverse)
        else:
            self.logger.warning(f"Unknown sort field: {sort_by}, using timestamp")
            return sorted(events, key=lambda e: e.timestamp, reverse=reverse)
    
    def _load_config(self) -> Dict[str, Any]:
        """Load exporter-specific configuration."""
        if self.config_manager:
            return self.config_manager.get_export_config(self.name)
        return {}
    
    def __str__(self) -> str:
        """String representation of exporter."""
        return f"{self.display_name}"
    
    def __repr__(self) -> str:
        """Debug representation of exporter."""
        return f"BaseExporter(name='{self.name}', format='{self.file_extension}')"


class ExporterRegistry:
    """
    Registry for managing exporters.
    
    Provides auto-discovery and management of export formats.
    """
    
    def __init__(self):
        self._exporters: Dict[str, BaseExporter] = {}
        self.logger = logging.getLogger(__name__)
    
    def register_exporter(self, exporter_class: type) -> None:
        """
        Register an exporter.
        
        Args:
            exporter_class: Exporter class to register
        """
        if not issubclass(exporter_class, BaseExporter):
            raise ValueError(f"Exporter must inherit from BaseExporter: {exporter_class}")
        
        # Create instance to get metadata
        try:
            instance = exporter_class()
            exporter_name = instance.name
            
            if exporter_name in self._exporters:
                self.logger.warning(f"Exporter '{exporter_name}' already registered, overwriting")
            
            self._exporters[exporter_name] = exporter_class
            self.logger.info(f"Registered exporter: {exporter_name}")
            
        except Exception as e:
            self.logger.error(f"Failed to register exporter {exporter_class}: {e}")
            raise
    
    def get_exporter(self, name: str) -> Optional[type]:
        """
        Get exporter class by name.
        
        Args:
            name: Exporter name
            
        Returns:
            Exporter class or None if not found
        """
        return self._exporters.get(name)
    
    def get_all_exporters(self) -> Dict[str, type]:
        """Get all registered exporters."""
        return self._exporters.copy()
    
    def list_exporters(self) -> List[Dict[str, Any]]:
        """
        List all exporters with metadata.
        
        Returns:
            List of exporter information dictionaries
        """
        exporters = []
        
        for name, exporter_class in self._exporters.items():
            try:
                instance = exporter_class()
                exporters.append({
                    "name": instance.name,
                    "display_name": instance.display_name,
                    "description": instance.description,
                    "file_extension": instance.file_extension,
                    "supports_streaming": instance.supports_streaming,
                    "version": instance.version
                })
            except Exception as e:
                self.logger.error(f"Error getting info for exporter {name}: {e}")
        
        return sorted(exporters, key=lambda x: x["name"])
    
    def get_supported_formats(self) -> List[str]:
        """Get list of supported export format names."""
        return list(self._exporters.keys())


# Global exporter registry
exporter_registry = ExporterRegistry()
