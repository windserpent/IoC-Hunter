"""
Time Parser for IoC-Hunter Linux

Handles natural language time parsing for blue team exercises.
Supports formats like "20 minutes ago", "1 hour ago", "2025-10-24 10:30", etc.

Python 3.9+ compatible.
"""

import re
import logging
from datetime import datetime, timedelta
from typing import Union, Optional

try:
    from dateutil.parser import parse as dateutil_parse
    from dateutil.relativedelta import relativedelta
    DATEUTIL_AVAILABLE = True
except ImportError:
    DATEUTIL_AVAILABLE = False
    logging.warning("dateutil not available - falling back to basic time parsing")


class TimeParser:
    """
    Natural language time parsing for IoC-Hunter.
    
    Supports various time formats including natural language expressions
    perfect for blue team exercises under pressure.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Basic time patterns for fallback parsing
        self._basic_patterns = [
            # Relative time patterns
            (r'(\d+)\s*minutes?\s*ago', self._parse_minutes_ago),
            (r'(\d+)\s*hours?\s*ago', self._parse_hours_ago),
            (r'(\d+)\s*days?\s*ago', self._parse_days_ago),
            (r'(\d+)\s*weeks?\s*ago', self._parse_weeks_ago),
            
            # Shorthand patterns
            (r'(\d+)m\s*ago', self._parse_minutes_ago),
            (r'(\d+)h\s*ago', self._parse_hours_ago),
            (r'(\d+)d\s*ago', self._parse_days_ago),
            
            # Special keywords
            (r'now', lambda m: datetime.now()),
            (r'today', lambda m: datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)),
            (r'yesterday', lambda m: datetime.now().replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=1)),
        ]
    
    def parse(self, time_input: Union[str, datetime], reference_time: Optional[datetime] = None) -> datetime:
        """
        Parse time input into datetime object.
        
        Args:
            time_input: Time string or datetime object
            reference_time: Reference time for relative parsing (defaults to now)
            
        Returns:
            Parsed datetime object
            
        Raises:
            ValueError: If time input cannot be parsed
        """
        if isinstance(time_input, datetime):
            return time_input
        
        if not isinstance(time_input, str):
            raise ValueError(f"Time input must be string or datetime, got {type(time_input)}")
        
        time_str = time_input.strip().lower()
        
        if not time_str:
            raise ValueError("Empty time input")
        
        # Set reference time
        if reference_time is None:
            reference_time = datetime.now()
        
        # Try dateutil first if available
        if DATEUTIL_AVAILABLE:
            try:
                return self._parse_with_dateutil(time_str, reference_time)
            except Exception as e:
                self.logger.debug(f"dateutil parsing failed: {e}, falling back to basic parsing")
        
        # Fall back to basic parsing
        return self._parse_basic(time_str, reference_time)
    
    def _parse_with_dateutil(self, time_str: str, reference_time: datetime) -> datetime:
        """Parse using dateutil library."""
        # Handle relative expressions that dateutil might not understand
        relative_result = self._try_relative_parsing(time_str, reference_time)
        if relative_result:
            return relative_result
        
        # Use dateutil for absolute time parsing
        try:
            # dateutil can handle most standard formats
            parsed_time = dateutil_parse(time_str, default=reference_time)
            
            # If the parsed time is in the future and looks like a relative expression,
            # it might have been misinterpreted
            if parsed_time > reference_time and any(word in time_str for word in ['ago', 'last', 'yesterday']):
                # Fall back to basic parsing
                return self._parse_basic(time_str, reference_time)
            
            return parsed_time
            
        except Exception as e:
            raise ValueError(f"Could not parse time '{time_str}': {e}")
    
    def _parse_basic(self, time_str: str, reference_time: datetime) -> datetime:
        """Parse using basic pattern matching."""
        # Try relative patterns first
        relative_result = self._try_relative_parsing(time_str, reference_time)
        if relative_result:
            return relative_result
        
        # Try to parse as ISO format or other common formats
        for fmt in [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M",
            "%Y-%m-%d",
            "%m/%d/%Y %H:%M:%S",
            "%m/%d/%Y %H:%M",
            "%m/%d/%Y",
            "%d-%m-%Y %H:%M:%S",
            "%d-%m-%Y %H:%M",
            "%d-%m-%Y"
        ]:
            try:
                return datetime.strptime(time_str, fmt)
            except ValueError:
                continue
        
        raise ValueError(f"Could not parse time '{time_str}' with basic parser")
    
    def _try_relative_parsing(self, time_str: str, reference_time: datetime) -> Optional[datetime]:
        """Try to parse relative time expressions."""
        for pattern, parser_func in self._basic_patterns:
            match = re.search(pattern, time_str, re.IGNORECASE)
            if match:
                try:
                    if callable(parser_func):
                        return parser_func(match)
                    else:
                        # Pattern matched but no parser function
                        continue
                except Exception as e:
                    self.logger.debug(f"Error in relative parsing: {e}")
                    continue
        
        return None
    
    def _parse_minutes_ago(self, match) -> datetime:
        """Parse 'X minutes ago' pattern."""
        minutes = int(match.group(1))
        return datetime.now() - timedelta(minutes=minutes)
    
    def _parse_hours_ago(self, match) -> datetime:
        """Parse 'X hours ago' pattern."""
        hours = int(match.group(1))
        return datetime.now() - timedelta(hours=hours)
    
    def _parse_days_ago(self, match) -> datetime:
        """Parse 'X days ago' pattern."""
        days = int(match.group(1))
        return datetime.now() - timedelta(days=days)
    
    def _parse_weeks_ago(self, match) -> datetime:
        """Parse 'X weeks ago' pattern."""
        weeks = int(match.group(1))
        return datetime.now() - timedelta(weeks=weeks)
    
    def parse_time_range(self, begin_time: Union[str, datetime], 
                        end_time: Union[str, datetime, None] = None) -> tuple[datetime, datetime]:
        """
        Parse a time range for scanning.
        
        Args:
            begin_time: Start time
            end_time: End time (defaults to now)
            
        Returns:
            Tuple of (begin_datetime, end_datetime)
            
        Raises:
            ValueError: If time range is invalid
        """
        begin_dt = self.parse(begin_time)
        
        if end_time is None:
            end_dt = datetime.now()
        else:
            end_dt = self.parse(end_time)
        
        # Validate time range
        if begin_dt > end_dt:
            raise ValueError(f"Begin time ({begin_dt}) cannot be after end time ({end_dt})")
        
        # Warn about very large time ranges (more than 30 days)
        time_span = end_dt - begin_dt
        if time_span.days > 30:
            self.logger.warning(f"Large time range detected: {time_span.days} days. This may impact performance.")
        
        return begin_dt, end_dt
    
    def format_duration(self, start_time: datetime, end_time: datetime) -> str:
        """
        Format duration between two times in human-readable format.
        
        Args:
            start_time: Start datetime
            end_time: End datetime
            
        Returns:
            Human-readable duration string
        """
        duration = end_time - start_time
        
        if duration.total_seconds() < 60:
            return f"{int(duration.total_seconds())} seconds"
        elif duration.total_seconds() < 3600:
            return f"{int(duration.total_seconds() / 60)} minutes"
        elif duration.total_seconds() < 86400:
            hours = int(duration.total_seconds() / 3600)
            minutes = int((duration.total_seconds() % 3600) / 60)
            if minutes > 0:
                return f"{hours}h {minutes}m"
            else:
                return f"{hours} hours"
        else:
            days = duration.days
            hours = int(duration.seconds / 3600)
            if hours > 0:
                return f"{days}d {hours}h"
            else:
                return f"{days} days"
    
    def get_default_scan_window(self, window_minutes: int = 20) -> tuple[datetime, datetime]:
        """
        Get default scan window (typically last 20 minutes).
        
        Args:
            window_minutes: Window size in minutes
            
        Returns:
            Tuple of (begin_time, end_time)
        """
        end_time = datetime.now()
        begin_time = end_time - timedelta(minutes=window_minutes)
        return begin_time, end_time
    
    @staticmethod
    def is_dateutil_available() -> bool:
        """Check if dateutil is available."""
        return DATEUTIL_AVAILABLE


# Convenience functions for common use cases
def parse_time(time_input: Union[str, datetime]) -> datetime:
    """
    Convenience function to parse time input.
    
    Args:
        time_input: Time string or datetime object
        
    Returns:
        Parsed datetime object
    """
    parser = TimeParser()
    return parser.parse(time_input)


def parse_scan_window(begin_time: Union[str, datetime], 
                     end_time: Union[str, datetime, None] = None) -> tuple[datetime, datetime]:
    """
    Convenience function to parse scan window.
    
    Args:
        begin_time: Start time
        end_time: End time (defaults to now)
        
    Returns:
        Tuple of (begin_datetime, end_datetime)
    """
    parser = TimeParser()
    return parser.parse_time_range(begin_time, end_time)


def get_default_window(minutes: int = 20) -> tuple[datetime, datetime]:
    """
    Get default scan window.
    
    Args:
        minutes: Window size in minutes
        
    Returns:
        Tuple of (begin_time, end_time)
    """
    parser = TimeParser()
    return parser.get_default_scan_window(minutes)
