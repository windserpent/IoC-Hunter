"""
Base IoC Category Class for IoC-Hunter Linux

Abstract base class for all IoC detection categories.
This class defines the interface that all categories must implement,
ensuring consistency and extensibility.

Python 3.9+ compatible.
"""

import logging
from abc import ABC, abstractmethod
from datetime import datetime
from typing import List, Dict, Any, Optional, Union
from pathlib import Path


class IoCEvent:
    """
    Represents a single IoC event/finding.
    
    This is the standard data structure returned by all IoC categories.
    """
    
    def __init__(self, 
                 timestamp: datetime,
                 category: str,
                 severity: str,
                 source: str,
                 event_type: str,
                 details: str,
                 raw_log: Optional[str] = None,
                 metadata: Optional[Dict[str, Any]] = None):
        """
        Initialize IoC event.
        
        Args:
            timestamp: When the event occurred
            category: IoC category name (e.g., "ssh_activity")
            severity: Severity level ("HIGH", "MEDIUM", "LOW")
            source: Log source (e.g., "journald", "auth.log")
            event_type: Specific event type within category
            details: Human-readable event description
            raw_log: Original log line (optional)
            metadata: Additional structured data (optional)
        """
        self.timestamp = timestamp
        self.category = category
        self.severity = severity.upper()
        self.source = source
        self.event_type = event_type
        self.details = details
        self.raw_log = raw_log
        self.metadata = metadata or {}
        
        # Add creation timestamp for forensic tracking
        self.created_at = datetime.now()
        
        # Validate severity
        if self.severity not in ["HIGH", "MEDIUM", "LOW"]:
            logging.warning(f"Invalid severity '{severity}', defaulting to 'MEDIUM'")
            self.severity = "MEDIUM"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert IoC event to dictionary format."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "category": self.category,
            "severity": self.severity,
            "source": self.source,
            "event_type": self.event_type,
            "details": self.details,
            "raw_log": self.raw_log,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat()
        }
    
    def __str__(self) -> str:
        """String representation of IoC event."""
        return f"[{self.severity}] {self.category}: {self.details} ({self.timestamp})"
    
    def __repr__(self) -> str:
        """Debug representation of IoC event."""
        return f"IoCEvent(category='{self.category}', severity='{self.severity}', timestamp='{self.timestamp}')"


class BaseIoCCategory(ABC):
    """
    Abstract base class for all IoC detection categories.
    
    All IoC categories must inherit from this class and implement
    the required abstract methods. This ensures consistency across
    all detection categories and enables auto-discovery.
    """
    
    # Category metadata - must be defined by subclasses
    name: Optional[str] = None              # Category name (e.g., "ssh_activity")
    display_name: Optional[str] = None      # Human-readable name (e.g., "SSH Suspicious Activity")
    description: Optional[str] = None       # Category description
    version: str = "1.0.0"       # Category version
    tier: int = 1                # Category tier (1=critical, 2=important, 3=optional)
    
    def __init__(self, config_manager=None, log_sources=None):
        """
        Initialize IoC category.
        
        Args:
            config_manager: Configuration manager instance
            log_sources: Log source manager instance
        """
        # Validate required class attributes
        if not self.name:
            raise ValueError(f"Category {self.__class__.__name__} must define 'name' class attribute")
        if not self.display_name:
            raise ValueError(f"Category {self.__class__.__name__} must define 'display_name' class attribute")
        if not self.description:
            raise ValueError(f"Category {self.__class__.__name__} must define 'description' class attribute")
        
        self.config_manager = config_manager
        self.log_sources = log_sources
        self.logger = logging.getLogger(f"{__name__}.{self.name}")
        
        # Load category-specific configuration
        self.config = self._load_config()
        
        # Track performance metrics
        self.metrics = {
            "events_processed": 0,
            "events_found": 0,
            "scan_duration": 0,
            "last_scan": None
        }
    
    @abstractmethod
    def scan(self, begin_time: datetime, end_time: datetime) -> List[IoCEvent]:
        """
        Scan for IoCs within the specified time range.
        
        This is the main method that performs the actual IoC detection.
        Must be implemented by all subclasses.
        
        Args:
            begin_time: Start of scan window
            end_time: End of scan window
            
        Returns:
            List of IoC events found
        """
        pass
    
    def get_required_log_sources(self) -> List[str]:
        """
        Get list of required log sources for this category.
        
        Override this method to specify which log sources are needed.
        
        Returns:
            List of log source names
        """
        return ["journald"]  # Default to journald
    
    def get_supported_log_sources(self) -> List[str]:
        """
        Get list of all supported log sources for this category.
        
        Override this method to specify all supported log sources.
        
        Returns:
            List of log source names
        """
        return ["journald", "syslog", "auth_log"]  # Default sources
    
    def validate_configuration(self) -> bool:
        """
        Validate category configuration.
        
        Override this method to perform category-specific validation.
        
        Returns:
            True if configuration is valid
        """
        return True
    
    def get_patterns(self) -> Dict[str, Any]:
        """
        Get detection patterns for this category.
        
        Returns:
            Dictionary of detection patterns
        """
        if self.config_manager:
            return self.config_manager.get_category_config(self.name)
        return {}
    
    def get_severity_mapping(self) -> Dict[str, str]:
        """
        Get severity mapping for different event types.
        
        Returns:
            Dictionary mapping event types to severity levels
        """
        if self.config_manager:
            return self.config_manager.get_category_config(self.name).get("severity_mapping", {})
        return {}
    
    def determine_severity(self, event_type: str, context: Optional[Dict[str, Any]] = None) -> str:
        """
        Determine severity for an event type.
        
        Args:
            event_type: Type of event
            context: Optional context for severity determination
            
        Returns:
            Severity level ("HIGH", "MEDIUM", "LOW")
        """
        severity_mapping = self.get_severity_mapping()
        
        # Check direct mapping first
        if event_type in severity_mapping:
            return severity_mapping[event_type].upper()
        
        # Check context-based rules if available
        if context and self.config_manager:
            severity_rules = self.config_manager.load_config("severity_rules")
            
            # Apply context-based severity rules
            for severity, rules in severity_rules.items():
                if self._matches_severity_rules(event_type, context, rules):
                    return severity.upper()
        
        # Default to MEDIUM
        return "MEDIUM"
    
    def _matches_severity_rules(self, event_type: str, context: Dict[str, Any], rules: Dict[str, Any]) -> bool:
        """Check if event matches severity rules."""
        # Pattern-based matching
        patterns = rules.get("patterns", [])
        for pattern in patterns:
            if pattern.lower() in event_type.lower():
                return True
        
        # Event count thresholds
        if "event_counts" in rules and "count" in context:
            threshold = rules["event_counts"].get("threshold", 0)
            if context["count"] >= threshold:
                return True
        
        return False
    
    def create_event(self, timestamp: datetime, event_type: str, details: str,
                    source: str = "unknown", raw_log: Optional[str] = None,
                    metadata: Optional[Dict[str, Any]] = None,
                    severity: Optional[str] = None) -> IoCEvent:
        """
        Create an IoC event with automatic severity determination.
        
        Args:
            timestamp: Event timestamp
            event_type: Type of event
            details: Event details
            source: Log source
            raw_log: Original log line
            metadata: Additional metadata
            severity: Override severity (optional)
            
        Returns:
            IoCEvent instance
        """
        if severity is None:
            severity = self.determine_severity(event_type, metadata)
        
        return IoCEvent(
            timestamp=timestamp,
            category=self.name,
            severity=severity,
            source=source,
            event_type=event_type,
            details=details,
            raw_log=raw_log,
            metadata=metadata
        )
    
    def update_metrics(self, events_processed: int, events_found: int, scan_duration: float):
        """
        Update performance metrics.
        
        Args:
            events_processed: Number of log events processed
            events_found: Number of IoCs found
            scan_duration: Scan duration in seconds
        """
        self.metrics["events_processed"] += events_processed
        self.metrics["events_found"] += events_found
        self.metrics["scan_duration"] += scan_duration
        self.metrics["last_scan"] = datetime.now()
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get performance metrics for this category."""
        return self.metrics.copy()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load category-specific configuration."""
        if self.config_manager:
            return self.config_manager.get_category_config(self.name)
        return {}
    
    def __str__(self) -> str:
        """String representation of category."""
        return f"{self.display_name} (Tier {self.tier})"
    
    def __repr__(self) -> str:
        """Debug representation of category."""
        return f"BaseIoCCategory(name='{self.name}', tier={self.tier})"


class CategoryRegistry:
    """
    Registry for managing IoC categories.
    
    Provides auto-discovery and management of IoC categories.
    """
    
    def __init__(self):
        self._categories: Dict[str, BaseIoCCategory] = {}
        self.logger = logging.getLogger(__name__)
    
    def register_category(self, category_class: type) -> None:
        """
        Register an IoC category.
        
        Args:
            category_class: Category class to register
        """
        if not issubclass(category_class, BaseIoCCategory):
            raise ValueError(f"Category must inherit from BaseIoCCategory: {category_class}")
        
        # Create instance to get metadata
        try:
            instance = category_class()
            category_name = instance.name
            
            if category_name in self._categories:
                self.logger.debug(f"Category '{category_name}' already registered, overwriting")
            
            self._categories[category_name] = category_class
            self.logger.info(f"Registered IoC category: {category_name}")
            
        except Exception as e:
            self.logger.error(f"Failed to register category {category_class}: {e}")
            raise
    
    def get_category(self, name: str) -> Optional[type]:
        """
        Get category class by name.
        
        Args:
            name: Category name
            
        Returns:
            Category class or None if not found
        """
        return self._categories.get(name)
    
    def get_all_categories(self) -> Dict[str, type]:
        """Get all registered categories."""
        return self._categories.copy()
    
    def get_tier_categories(self, tier: int) -> Dict[str, type]:
        """
        Get categories by tier.
        
        Args:
            tier: Tier number
            
        Returns:
            Dictionary of categories in the specified tier
        """
        tier_categories = {}
        
        for name, category_class in self._categories.items():
            try:
                instance = category_class()
                if instance.tier == tier:
                    tier_categories[name] = category_class
            except Exception as e:
                self.logger.error(f"Error checking tier for category {name}: {e}")
        
        return tier_categories
    
    def list_categories(self) -> List[Dict[str, Any]]:
        """
        List all categories with metadata.
        
        Returns:
            List of category information dictionaries
        """
        categories = []
        
        for name, category_class in self._categories.items():
            try:
                instance = category_class()
                categories.append({
                    "name": instance.name,
                    "display_name": instance.display_name,
                    "description": instance.description,
                    "tier": instance.tier,
                    "version": instance.version,
                    "required_sources": instance.get_required_log_sources(),
                    "supported_sources": instance.get_supported_log_sources()
                })
            except Exception as e:
                self.logger.error(f"Error getting info for category {name}: {e}")
        
        return sorted(categories, key=lambda x: (x["tier"], x["name"]))


# Global category registry
category_registry = CategoryRegistry()
