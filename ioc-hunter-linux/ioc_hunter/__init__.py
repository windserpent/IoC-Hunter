"""
IoC-Hunter Linux - Comprehensive Indicator of Compromise Detection for Linux Systems

A Python-based security scanning tool designed for blue team exercises and incident response.
Supports Ubuntu 24.04.3, Fedora 42, Oracle Linux 9.2, and compatible distributions.

Author: IoC-Hunter Project
Version: 1.0.0  
Python: 3.9+ compatibility
License: Open Source
"""

__version__ = "1.0.0"
__author__ = "IoC-Hunter Project"
__license__ = "Open Source"
__python_requires__ = ">=3.9"

# Core imports for package users
from .core.scanner import IoCScanner
from .core.config_manager import ConfigManager
from .utils.time_parser import TimeParser

# Version info
VERSION_INFO = {
    "version": __version__,
    "python_minimum": "3.9",
    "target_systems": ["Ubuntu 24.04.3", "Fedora 42", "Oracle Linux 9.2"],
    "description": "Linux IoC detection for blue team exercises"
}

__all__ = [
    "IoCScanner",
    "ConfigManager", 
    "TimeParser",
    "VERSION_INFO"
]
