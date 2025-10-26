"""
Main IoC Scanner Engine for IoC-Hunter Linux

Orchestrates IoC detection across multiple categories and log sources.
This is the core component that ties everything together.

Python 3.9+ compatible.
"""

import logging
import time
import glob
import importlib
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Union
from concurrent.futures import ThreadPoolExecutor, as_completed

from .config_manager import ConfigManager
from .log_sources import LogSourceManager
from .base_category import BaseIoCCategory, IoCEvent, category_registry
from .base_exporter import BaseExporter, ExportMetadata, exporter_registry
from ..utils.time_parser import TimeParser


class ScanResults:
    """
    Container for scan results and metadata.
    """
    
    def __init__(self, 
                 begin_time: datetime,
                 end_time: datetime,
                 categories_scanned: List[str],
                 scan_mode: str = "targeted"):
        """
        Initialize scan results.
        
        Args:
            begin_time: Scan start time
            end_time: Scan end time
            categories_scanned: List of categories that were scanned
            scan_mode: Scan mode ("quick", "full", "targeted")
        """
        self.begin_time = begin_time
        self.end_time = end_time
        self.categories_scanned = categories_scanned
        self.scan_mode = scan_mode
        self.scan_started = datetime.now()
        self.scan_completed = None
        
        # Results storage
        self.events: List[IoCEvent] = []
        self.category_metrics: Dict[str, Dict[str, Any]] = {}
        self.errors: List[str] = []
        
        # Performance metrics
        self.total_log_entries_processed = 0
        self.total_scan_duration = 0.0
    
    def add_events(self, events: List[IoCEvent], category_name: str, metrics: Dict[str, Any]):
        """
        Add events from a category scan.
        
        Args:
            events: List of IoC events found
            category_name: Name of the category
            metrics: Performance metrics from the category
        """
        self.events.extend(events)
        self.category_metrics[category_name] = metrics
        
        # Update totals
        self.total_log_entries_processed += metrics.get("events_processed", 0)
    
    def add_error(self, error_message: str):
        """Add an error message to the results."""
        self.errors.append(error_message)
    
    def complete_scan(self):
        """Mark scan as completed and calculate final metrics."""
        self.scan_completed = datetime.now()
        self.total_scan_duration = (self.scan_completed - self.scan_started).total_seconds()
    
    def get_events_by_severity(self, severity: str) -> List[IoCEvent]:
        """Get events filtered by severity level."""
        return [event for event in self.events if event.severity == severity.upper()]
    
    def get_events_by_category(self, category: str) -> List[IoCEvent]:
        """Get events filtered by category."""
        return [event for event in self.events if event.category == category]
    
    def get_summary(self) -> Dict[str, Any]:
        """Get scan summary statistics."""
        severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        category_counts = {}
        
        for event in self.events:
            severity_counts[event.severity] = severity_counts.get(event.severity, 0) + 1
            category_counts[event.category] = category_counts.get(event.category, 0) + 1
        
        return {
            "scan_mode": self.scan_mode,
            "time_range": {
                "begin": self.begin_time.isoformat(),
                "end": self.end_time.isoformat(),
                "duration_minutes": (self.end_time - self.begin_time).total_seconds() / 60
            },
            "scan_performance": {
                "started": self.scan_started.isoformat(),
                "completed": self.scan_completed.isoformat() if self.scan_completed else None,
                "duration_seconds": self.total_scan_duration,
                "log_entries_processed": self.total_log_entries_processed
            },
            "categories_scanned": self.categories_scanned,
            "total_events": len(self.events),
            "severity_breakdown": severity_counts,
            "category_breakdown": category_counts,
            "errors": len(self.errors)
        }
    
    def to_export_metadata(self) -> ExportMetadata:
        """Convert to ExportMetadata for exporters."""
        return ExportMetadata(
            scan_begin=self.begin_time,
            scan_end=self.end_time,
            categories_scanned=self.categories_scanned,
            total_events=len(self.events),
            export_format="scan_results",
            scanner_version="1.0.0",
            additional_info=self.get_summary()
        )


class IoCScanner:
    """
    Main IoC Scanner Engine.
    
    Orchestrates IoC detection across multiple categories and log sources.
    """
    
    def __init__(self, config_dir: Optional[str] = None):
        """
        Initialize IoC Scanner.
        
        Args:
            config_dir: Optional custom configuration directory
        """
        self.logger = logging.getLogger(__name__)
        
        # Initialize core components
        self.config_manager = ConfigManager(config_dir)
        self.log_sources = LogSourceManager(self.config_manager)
        self.time_parser = TimeParser()
        
        # Create default configurations if they don't exist
        self.config_manager.create_default_configs()
        
        # Load scanner configuration
        self.config = self.config_manager.load_config("scanner")
        
        # Auto-discover categories and exporters
        self._discover_categories()
        self._discover_exporters()
        
        # Validate system requirements
        self._validate_system()
        
        self.logger.info("IoC Scanner initialized successfully")
    
    def _discover_categories(self):
        """Auto-discover IoC categories from the categories package."""
        try:
            categories_path = Path(__file__).parent.parent / "categories"
            
            if not categories_path.exists():
                self.logger.warning("Categories directory not found")
                return
            
            # Import all Python files in the categories directory
            for category_file in categories_path.glob("*.py"):
                if category_file.name.startswith("__"):
                    continue
                
                try:
                    module_name = f"ioc_hunter.categories.{category_file.stem}"
                    
                    # Import the module
                    if module_name not in sys.modules:
                        spec = importlib.util.spec_from_file_location(module_name, category_file)
                        module = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(module)
                        sys.modules[module_name] = module
                    else:
                        module = sys.modules[module_name]
                    
                    # Find classes that inherit from BaseIoCCategory
                    for attr_name in dir(module):
                        attr = getattr(module, attr_name)
                        if (isinstance(attr, type) and 
                            issubclass(attr, BaseIoCCategory) and 
                            attr != BaseIoCCategory):
                            
                            category_registry.register_category(attr)
                            
                except Exception as e:
                    self.logger.error(f"Error importing category {category_file}: {e}")
        
        except Exception as e:
            self.logger.error(f"Error discovering categories: {e}")
    
    def _discover_exporters(self):
        """Auto-discover exporters from the exporters package."""
        try:
            exporters_path = Path(__file__).parent.parent / "exporters"
            
            if not exporters_path.exists():
                self.logger.warning("Exporters directory not found")
                return
            
            # Import all Python files in the exporters directory
            for exporter_file in exporters_path.glob("*.py"):
                if exporter_file.name.startswith("__"):
                    continue
                
                try:
                    module_name = f"ioc_hunter.exporters.{exporter_file.stem}"
                    
                    # Import the module
                    if module_name not in sys.modules:
                        spec = importlib.util.spec_from_file_location(module_name, exporter_file)
                        module = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(module)
                        sys.modules[module_name] = module
                    else:
                        module = sys.modules[module_name]
                    
                    # Find classes that inherit from BaseExporter
                    for attr_name in dir(module):
                        attr = getattr(module, attr_name)
                        if (isinstance(attr, type) and 
                            issubclass(attr, BaseExporter) and 
                            attr != BaseExporter):
                            
                            exporter_registry.register_exporter(attr)
                            
                except Exception as e:
                    self.logger.error(f"Error importing exporter {exporter_file}: {e}")
        
        except Exception as e:
            self.logger.error(f"Error discovering exporters: {e}")
    
    def _validate_system(self):
        """Validate system requirements and accessibility."""
        # Check log source accessibility
        source_results = self.log_sources.test_sources()
        accessible_sources = [name for name, accessible in source_results.items() if accessible]
        
        if not accessible_sources:
            self.logger.error("No log sources are accessible")
        else:
            self.logger.info(f"Accessible log sources: {', '.join(accessible_sources)}")
        
        # Check if running with sufficient privileges
        import os
        if os.geteuid() != 0:
            self.logger.warning("Not running as root - some log sources may not be accessible")
    
    def scan(self, 
             categories: Optional[List[str]] = None,
             begin_time: Optional[Union[str, datetime]] = None,
             end_time: Optional[Union[str, datetime]] = None,
             scan_mode: str = "targeted") -> ScanResults:
        """
        Perform IoC scan.
        
        Args:
            categories: List of category names to scan (None = all available)
            begin_time: Scan start time (defaults to 20 minutes ago)
            end_time: Scan end time (defaults to now)
            scan_mode: Scan mode ("quick", "full", "targeted")
            
        Returns:
            ScanResults object containing all findings
        """
        # Parse time range
        if begin_time is None:
            begin_dt, end_dt = self.time_parser.get_default_scan_window()
        else:
            begin_dt = self.time_parser.parse(begin_time)
            if end_time is None:
                end_dt = datetime.now()
            else:
                end_dt = self.time_parser.parse(end_time)
        
        # Validate time range
        if begin_dt >= end_dt:
            raise ValueError(f"Begin time ({begin_dt}) must be before end time ({end_dt})")
        
        # Determine categories to scan
        if categories is None:
            available_categories = list(category_registry.get_all_categories().keys())
            if not available_categories:
                raise RuntimeError("No IoC categories available")
            categories = available_categories
        
        # Create results container
        results = ScanResults(begin_dt, end_dt, categories, scan_mode)
        
        self.logger.info(f"Starting {scan_mode} scan: {len(categories)} categories, "
                        f"{self.time_parser.format_duration(begin_dt, end_dt)} time window")
        
        # Perform scan
        try:
            self._perform_scan(categories, begin_dt, end_dt, results)
        except Exception as e:
            self.logger.error(f"Scan failed: {e}")
            results.add_error(f"Scan failed: {e}")
        finally:
            results.complete_scan()
        
        # Log scan summary
        summary = results.get_summary()
        self.logger.info(f"Scan completed: {summary['total_events']} events found, "
                        f"{summary['scan_performance']['duration_seconds']:.1f}s elapsed")
        
        return results
    
    def quick_scan(self, 
                  begin_time: Optional[Union[str, datetime]] = None,
                  end_time: Optional[Union[str, datetime]] = None) -> ScanResults:
        """
        Perform quick scan (Tier 1 categories only).
        
        Args:
            begin_time: Scan start time (defaults to 20 minutes ago)
            end_time: Scan end time (defaults to now)
            
        Returns:
            ScanResults object
        """
        # Get Tier 1 (critical) categories
        tier1_categories = list(category_registry.get_tier_categories(1).keys())
        
        return self.scan(
            categories=tier1_categories,
            begin_time=begin_time,
            end_time=end_time,
            scan_mode="quick"
        )
    
    def full_scan(self, 
                 begin_time: Optional[Union[str, datetime]] = None,
                 end_time: Optional[Union[str, datetime]] = None) -> ScanResults:
        """
        Perform full scan (all available categories).
        
        Args:
            begin_time: Scan start time (defaults to 20 minutes ago)
            end_time: Scan end time (defaults to now)
            
        Returns:
            ScanResults object
        """
        return self.scan(
            categories=None,  # All categories
            begin_time=begin_time,
            end_time=end_time,
            scan_mode="full"
        )
    
    def _perform_scan(self, categories: List[str], begin_time: datetime, 
                     end_time: datetime, results: ScanResults):
        """
        Perform the actual scanning across categories.
        
        Args:
            categories: List of category names to scan
            begin_time: Scan start time
            end_time: Scan end time
            results: Results container to populate
        """
        max_workers = min(self.config.get("max_parallel_categories", 4), len(categories))
        
        if max_workers > 1:
            self._perform_parallel_scan(categories, begin_time, end_time, results, max_workers)
        else:
            self._perform_sequential_scan(categories, begin_time, end_time, results)
    
    def _perform_sequential_scan(self, categories: List[str], begin_time: datetime,
                               end_time: datetime, results: ScanResults):
        """Perform sequential scan (one category at a time)."""
        for i, category_name in enumerate(categories, 1):
            self.logger.info(f"Scanning category {i}/{len(categories)}: {category_name}")
            
            try:
                events, metrics = self._scan_category(category_name, begin_time, end_time)
                results.add_events(events, category_name, metrics)
                
            except Exception as e:
                error_msg = f"Error scanning category {category_name}: {e}"
                self.logger.error(error_msg)
                results.add_error(error_msg)
    
    def _perform_parallel_scan(self, categories: List[str], begin_time: datetime,
                             end_time: datetime, results: ScanResults, max_workers: int):
        """Perform parallel scan (multiple categories concurrently)."""
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all category scans
            future_to_category = {
                executor.submit(self._scan_category, category_name, begin_time, end_time): category_name
                for category_name in categories
            }
            
            # Process completed scans
            completed = 0
            for future in as_completed(future_to_category):
                category_name = future_to_category[future]
                completed += 1
                
                self.logger.info(f"Completed category {completed}/{len(categories)}: {category_name}")
                
                try:
                    events, metrics = future.result()
                    results.add_events(events, category_name, metrics)
                    
                except Exception as e:
                    error_msg = f"Error scanning category {category_name}: {e}"
                    self.logger.error(error_msg)
                    results.add_error(error_msg)
    
    def _scan_category(self, category_name: str, begin_time: datetime, 
                      end_time: datetime) -> tuple[List[IoCEvent], Dict[str, Any]]:
        """
        Scan a single category.
        
        Args:
            category_name: Name of category to scan
            begin_time: Scan start time
            end_time: Scan end time
            
        Returns:
            Tuple of (events_found, performance_metrics)
        """
        # Get category class
        category_class = category_registry.get_category(category_name)
        if category_class is None:
            raise ValueError(f"Category not found: {category_name}")
        
        # Create category instance
        category_instance = category_class(
            config_manager=self.config_manager,
            log_sources=self.log_sources
        )
        
        # Perform scan
        scan_start = time.time()
        events = category_instance.scan(begin_time, end_time)
        scan_duration = time.time() - scan_start
        
        # Get metrics
        metrics = category_instance.get_metrics()
        metrics["scan_duration"] = scan_duration
        
        self.logger.debug(f"Category {category_name}: {len(events)} events, {scan_duration:.2f}s")
        
        return events, metrics
    
    def export_results(self, results: ScanResults, format_name: str, 
                      output_path: Optional[Union[str, Path]] = None, **kwargs) -> bool:
        """
        Export scan results using specified format.
        
        Args:
            results: Scan results to export
            format_name: Export format name
            output_path: Output file path (optional for some formats)
            **kwargs: Additional arguments for exporter
            
        Returns:
            True if export was successful
        """
        # Get exporter class
        exporter_class = exporter_registry.get_exporter(format_name)
        if exporter_class is None:
            self.logger.error(f"Export format not found: {format_name}")
            return False
        
        # Create exporter instance
        exporter = exporter_class(config_manager=self.config_manager)
        
        # Generate metadata
        metadata = results.to_export_metadata()
        metadata.export_format = format_name
        
        # Determine output
        if output_path is None:
            output_path = exporter.get_default_filename(metadata)
        
        # Perform export
        try:
            success = exporter.export_to_file(results.events, metadata, output_path, **kwargs)
            
            if success:
                self.logger.info(f"Exported {len(results.events)} events to {output_path}")
            else:
                self.logger.error(f"Export failed to {output_path}")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Export error: {e}")
            return False
    
    def get_available_categories(self) -> List[Dict[str, Any]]:
        """Get list of available IoC categories."""
        return category_registry.list_categories()
    
    def get_available_exporters(self) -> List[Dict[str, Any]]:
        """Get list of available export formats."""
        return exporter_registry.list_exporters()
    
    def get_system_info(self) -> Dict[str, Any]:
        """Get system information and status."""
        return {
            "scanner_version": "1.0.0",
            "python_version": sys.version,
            "log_sources": self.log_sources.get_source_info(),
            "available_categories": len(category_registry.get_all_categories()),
            "available_exporters": len(exporter_registry.get_all_exporters()),
            "configuration": {
                "config_dir": str(self.config_manager.config_dir),
                "max_parallel_categories": self.config.get("max_parallel_categories", 4),
                "default_scan_window_minutes": self.config.get("default_scan_window_minutes", 20)
            }
        }
