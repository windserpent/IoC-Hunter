"""
Configuration Manager for IoC-Hunter Linux

Handles all configuration loading, validation, and management.
This module is designed to never require modification - all new
configuration needs are handled through config files.

Python 3.9+ compatible.
"""

import json
import os
import logging
from pathlib import Path
from typing import Dict, Any, Optional, Union, List

try:
    import yaml  # type: ignore
    YAML_AVAILABLE = True
except ImportError:
    yaml = None  # type: ignore
    YAML_AVAILABLE = False
    logging.warning("PyYAML not available - YAML config files will not be supported")


class ConfigManager:
    """
    Centralized configuration management for IoC-Hunter.
    
    Supports JSON and YAML configuration files with automatic discovery,
    environment variable overrides, and validation.
    """
    
    def __init__(self, config_dir: Optional[str] = None):
        """
        Initialize configuration manager.
        
        Args:
            config_dir: Optional custom config directory path
        """
        # Determine config directory
        if config_dir:
            self.config_dir = Path(config_dir)
        else:
            # Default to config/ directory relative to package
            package_root = Path(__file__).parent.parent.parent
            self.config_dir = package_root / "config"
        
        self.config_dir.mkdir(exist_ok=True)
        
        # Configuration cache
        self._config_cache: Dict[str, Any] = {}
        
        # Default configuration
        self._defaults = self._load_default_config()
        
        self.logger = logging.getLogger(__name__)
        
    def _load_default_config(self) -> Dict[str, Any]:
        """Load default configuration values."""
        return {
            "scanner": {
                "default_scan_window_minutes": 20,
                "max_memory_mb": 512,
                "max_parallel_categories": 4,
                "enable_compressed_logs": True,
                "enable_streaming": True,
                "progress_updates": True
            },
            "log_sources": {
                "journald": {
                    "enabled": True,
                    "priority": 1,
                    "fallback_to_files": True
                },
                "auth_log": {
                    "enabled": True,
                    "priority": 2,
                    "paths": ["/var/log/auth.log", "/var/log/secure"]
                },
                "syslog": {
                    "enabled": True,
                    "priority": 3,
                    "paths": ["/var/log/syslog", "/var/log/messages"]
                }
            },
            "output": {
                "default_format": "table",
                "timestamp_format": "%Y-%m-%d %H:%M:%S",
                "severity_colors": {
                    "HIGH": "red",
                    "MEDIUM": "yellow", 
                    "LOW": "white"
                }
            },
            "security": {
                "require_root_warning": True,
                "max_file_size_mb": 1024,
                "trusted_paths_only": True
            }
        }
    
    def load_config(self, config_name: str, required: bool = False) -> Dict[str, Any]:
        """
        Load configuration from file with caching.
        
        Args:
            config_name: Configuration file name (without extension)
            required: Whether this config file is required
            
        Returns:
            Configuration dictionary
            
        Raises:
            FileNotFoundError: If required config file not found
        """
        if config_name in self._config_cache:
            return self._config_cache[config_name]
        
        config_data = {}
        
        # Try to load from various formats
        for extension in ['.json', '.yaml', '.yml']:
            config_path = self.config_dir / f"{config_name}{extension}"
            
            if config_path.exists():
                try:
                    if extension == '.json':
                        config_data = self._load_json(config_path)
                    elif extension in ['.yaml', '.yml']:
                        if YAML_AVAILABLE:
                            config_data = self._load_yaml(config_path)
                        else:
                            self.logger.warning(f"YAML file {config_path} found but PyYAML not available")
                            continue
                    
                    self.logger.info(f"Loaded configuration from {config_path}")
                    break
                    
                except Exception as e:
                    self.logger.error(f"Error loading config from {config_path}: {e}")
                    continue
        
        # Handle required config not found
        if not config_data and required:
            raise FileNotFoundError(f"Required configuration '{config_name}' not found in {self.config_dir}")
        
        # Merge with defaults if available
        if config_name in self._defaults:
            merged_config = self._deep_merge(self._defaults[config_name], config_data)
            config_data = merged_config
        
        # Apply environment variable overrides
        config_data = self._apply_env_overrides(config_name, config_data)
        
        # Cache the result
        self._config_cache[config_name] = config_data
        
        return config_data
    
    def _load_json(self, path: Path) -> Dict[str, Any]:
        """Load JSON configuration file."""
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def _load_yaml(self, path: Path) -> Dict[str, Any]:
        """Load YAML configuration file."""
        if not YAML_AVAILABLE or yaml is None:
            raise ImportError("PyYAML is required to load YAML configuration files")
        with open(path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f) or {}
    
    def _deep_merge(self, default: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        """Deep merge two dictionaries, with override taking precedence."""
        result = default.copy()
        
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value
        
        return result
    
    def _apply_env_overrides(self, config_name: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Apply environment variable overrides to configuration."""
        # Look for environment variables in format: IOC_HUNTER_<CONFIG>_<KEY>
        prefix = f"IOC_HUNTER_{config_name.upper()}_"
        
        for env_var, value in os.environ.items():
            if env_var.startswith(prefix):
                # Extract the key path
                key_path = env_var[len(prefix):].lower().split('_')
                
                # Apply the override
                current = config
                for key in key_path[:-1]:
                    if key not in current:
                        current[key] = {}
                    current = current[key]
                
                # Convert value to appropriate type
                final_key = key_path[-1]
                current[final_key] = self._convert_env_value(value)
        
        return config
    
    def _convert_env_value(self, value: str) -> Union[str, int, bool, float]:
        """Convert environment variable string to appropriate type."""
        # Boolean values
        if value.lower() in ['true', 'yes', '1']:
            return True
        elif value.lower() in ['false', 'no', '0']:
            return False
        
        # Numeric values
        try:
            if '.' in value:
                return float(value)
            else:
                return int(value)
        except ValueError:
            pass
        
        # String value
        return value
    
    def get(self, config_name: str, key: Optional[str] = None, default: Any = None) -> Any:
        """
        Get configuration value with optional key path.
        
        Args:
            config_name: Configuration file name
            key: Optional dot-separated key path (e.g., "scanner.max_memory_mb")
            default: Default value if key not found
            
        Returns:
            Configuration value
        """
        config = self.load_config(config_name)
        
        if key is None:
            return config
        
        # Navigate key path
        current = config
        for key_part in key.split('.'):
            if isinstance(current, dict) and key_part in current:
                current = current[key_part]
            else:
                return default
        
        return current
    
    def get_log_sources(self) -> List[Dict[str, Any]]:
        """Get configured log sources in priority order."""
        log_config = self.load_config("log_sources")
        
        # Convert to list and sort by priority
        sources = []
        for source_name, source_config in log_config.items():
            if source_config.get("enabled", True):
                source_info = source_config.copy()
                source_info["name"] = source_name
                sources.append(source_info)
        
        # Sort by priority (lower number = higher priority)
        sources.sort(key=lambda x: x.get("priority", 999))
        
        return sources
    
    def get_category_config(self, category_name: str) -> Dict[str, Any]:
        """Get configuration for a specific IoC category."""
        # Try category-specific config first
        try:
            category_config = self.load_config(f"category_{category_name}")
            if category_config:  # Only return if not empty
                return category_config
        except FileNotFoundError:
            pass
        
        # Fall back to general patterns config
        patterns_config = self.load_config("default_patterns")
        return patterns_config.get(category_name, {})
    
    def get_export_config(self, export_format: str) -> Dict[str, Any]:
        """Get configuration for a specific export format."""
        export_config = self.load_config("export_formats")
        return export_config.get(export_format, {})
    
    def save_config(self, config_name: str, config_data: Dict[str, Any], format: str = "json") -> None:
        """
        Save configuration to file.
        
        Args:
            config_name: Configuration file name
            config_data: Configuration data to save
            format: File format ('json' or 'yaml')
        """
        if format == "yaml" and not YAML_AVAILABLE:
            self.logger.warning("YAML not available, saving as JSON instead")
            format = "json"
        
        extension = ".yaml" if format == "yaml" else ".json"
        config_path = self.config_dir / f"{config_name}{extension}"
        
        try:
            with open(config_path, 'w', encoding='utf-8') as f:
                if format == "yaml" and YAML_AVAILABLE and yaml is not None:
                    yaml.dump(config_data, f, default_flow_style=False, indent=2)
                else:
                    json.dump(config_data, f, indent=2, ensure_ascii=False)
            
            # Update cache
            self._config_cache[config_name] = config_data
            self.logger.info(f"Saved configuration to {config_path}")
            
        except Exception as e:
            self.logger.error(f"Error saving config to {config_path}: {e}")
            raise
    
    def create_default_configs(self) -> None:
        """Create default configuration files if they don't exist."""
        default_configs = {
            "default_patterns": self._get_default_patterns(),
            "log_sources": self._defaults["log_sources"],
            "export_formats": self._get_default_export_formats(),
            "severity_rules": self._get_default_severity_rules()
        }
        
        for config_name, config_data in default_configs.items():
            config_path = self.config_dir / f"{config_name}.json"
            if not config_path.exists():
                self.save_config(config_name, config_data)
                self.logger.info(f"Created default config: {config_path}")
    
    def _get_default_patterns(self) -> Dict[str, Any]:
        """Get default IoC detection patterns."""
        return {
            "ssh_activity": {
                "patterns": {
                    "failed_login": ["Failed password", "Invalid user", "authentication failure"],
                    "successful_login": ["Accepted password", "Accepted publickey"],
                    "suspicious_commands": ["ssh -L", "ssh -R", "ssh -D"],
                    "brute_force_threshold": 5
                },
                "severity_mapping": {
                    "failed_login": "MEDIUM",
                    "brute_force": "HIGH",
                    "port_forwarding": "HIGH"
                }
            },
            "privilege_escalation": {
                "patterns": {
                    "sudo_abuse": ["sudo su", "sudo -i", "sudo /bin/bash"],
                    "setuid_usage": ["chmod +s", "chmod 4755"],
                    "suspicious_sudo": ["sudo rm", "sudo mv", "sudo chmod"]
                },
                "severity_mapping": {
                    "sudo_to_root": "HIGH",
                    "setuid_modification": "HIGH",
                    "dangerous_sudo": "MEDIUM"
                }
            }
        }
    
    def _get_default_export_formats(self) -> Dict[str, Any]:
        """Get default export format configurations."""
        return {
            "csv": {
                "enabled": True,
                "fields": ["timestamp", "category", "severity", "source", "details"],
                "delimiter": ",",
                "include_headers": True
            },
            "json": {
                "enabled": True,
                "pretty_print": True,
                "include_metadata": True
            },
            "splunk": {
                "enabled": True,
                "default_index": "ioc_hunter",
                "default_sourcetype": "linux_ioc",
                "include_raw_log": True
            }
        }
    
    def _get_default_severity_rules(self) -> Dict[str, Any]:
        """Get default severity classification rules."""
        return {
            "HIGH": {
                "patterns": ["root access", "privilege escalation", "brute force"],
                "event_counts": {"threshold": 10, "window_minutes": 5}
            },
            "MEDIUM": {
                "patterns": ["failed login", "suspicious command", "file modification"],
                "event_counts": {"threshold": 20, "window_minutes": 10}
            },
            "LOW": {
                "patterns": ["normal login", "routine operation"],
                "default": True
            }
        }
