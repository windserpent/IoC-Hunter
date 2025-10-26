# IoC-Hunter Linux

**Comprehensive Indicator of Compromise Detection for Linux Systems**

A Python-based security scanning tool designed for blue team exercises and incident response on Linux systems. Supports Ubuntu 24.04.3, Fedora 42, Oracle Linux 9.2, and compatible distributions.

## Quick Start

```bash
# Clone and setup (30-60 seconds)
git clone <repository-url>
cd ioc-hunter-linux
chmod +x setup.sh
./setup.sh

# Quick security scan (requires root for full log access)
sudo ./scripts/ioc-hunter --quick

# Full comprehensive scan
sudo ./scripts/ioc-hunter --full --begin "1 hour ago"

# Targeted scan with export
sudo ./scripts/ioc-hunter --ssh --privilege-escalation --export json --output incident.json
```

## Key Features

- **11 Comprehensive IoC Categories**: SSH activity, privilege escalation, account management, service manipulation, process execution, network connections, filesystem changes, log tampering, cron manipulation, kernel modules, command history analysis
- **Natural Language Time Parsing**: Use intuitive expressions like "20 minutes ago", "1 hour ago", "yesterday at 3pm"
- **Multiple Log Sources**: systemd/journald (primary), syslog, authentication logs, application-specific logs
- **Flexible Export Formats**: CSV, JSON, Splunk-ready, Timeline, Syslog, Markdown
- **Auto-Discovery Architecture**: Categories and exporters are automatically discovered
- **Performance Optimized**: Parallel processing, streaming analysis, memory-efficient
- **Blue Team Focused**: Designed for rapid threat detection during security exercises

## System Requirements

- **Python**: 3.9+ (compatible with all target distributions)
- **Privileges**: Root access required for comprehensive log access
- **Systems**: Ubuntu 24.04.3, Fedora 42, Oracle Linux 9.2, and compatible
- **Resources**: 2+ cores, 4+ GB RAM recommended
- **Network**: Internet access for setup (package installation)

## IoC Categories

### Tier 1 - Critical Categories (Quick Scan)
1. **SSH Suspicious Activity** - Failed logins, brute force, port forwarding
2. **Privilege Escalation** - sudo abuse, setuid usage, dangerous commands  
3. **Account Management** - User creation, group modifications, password changes
4. **Service Manipulation** - Systemctl abuse, suspicious service activity
5. **Process Execution** - Suspicious processes, reverse shells, network tools
6. **Network Connections** - Unexpected outbound connections, port scanning
7. **File System Changes** - Critical file modifications, suspicious locations
8. **Log Tampering** - Log clearing, history manipulation, journal corruption
9. **Cron/Timer Manipulation** - Suspicious scheduled tasks, persistence
10. **Kernel Module Loading** - Unsigned modules, potential rootkits
11. **Command History Analysis** - Suspicious bash history, attack commands

## Installation

### Automatic Setup (Recommended)
```bash
# Download and run setup script
./setup.sh
```

The setup script automatically:
- Detects your Linux distribution
- Installs required system packages
- Installs Python dependencies
- Validates log source access
- Creates system-wide symlink (optional)

### Manual Installation
```bash
# Install system packages
# Ubuntu/Debian:
sudo apt install python3-pip python3-systemd jq

# Fedora:
sudo dnf install python3-pip python3-systemd jq

# RHEL/Oracle Linux:
sudo yum install python3-pip jq

# Install Python packages
pip3 install --user -r requirements.txt

# Make CLI executable
chmod +x scripts/ioc-hunter
```

## Usage Examples

### Basic Scanning
```bash
# Quick scan (last 20 minutes, critical categories)
sudo ./scripts/ioc-hunter --quick

# Full scan (last 20 minutes, all categories)  
sudo ./scripts/ioc-hunter --full

# Custom time window
sudo ./scripts/ioc-hunter --quick --begin "1 hour ago" --end "30 minutes ago"
```

### Targeted Scanning
```bash
# SSH and privilege escalation only
sudo ./scripts/ioc-hunter --ssh-activity --privilege-escalation

# Multiple categories with custom time
sudo ./scripts/ioc-hunter --ssh-activity --account-management --process-execution --begin "2 hours ago"
```

### Natural Language Time Examples
```bash
# Relative time expressions
--begin "20 minutes ago"
--begin "1 hour ago" 
--begin "2 days ago"

# Absolute time formats
--begin "2025-10-24 10:30:00"
--begin "Oct 24 2025 10:30AM"

# Special keywords
--begin "yesterday"
--begin "today"
--end "now"
```

### Export and Analysis
```bash
# Export to JSON
sudo ./scripts/ioc-hunter --quick --export json --output results.json

# Export to CSV for spreadsheet analysis
sudo ./scripts/ioc-hunter --full --export csv --output analysis.csv

# Export to Splunk (requires Splunk configuration)
sudo ./scripts/ioc-hunter --quick --export splunk

# Create incident timeline
sudo ./scripts/ioc-hunter --full --export timeline --output incident_timeline.json
```

### Blue Team Workflow
```bash
# 1. Quick assessment
sudo ./scripts/ioc-hunter --quick

# 2. If threats found, detailed investigation
sudo ./scripts/ioc-hunter --full --begin "4 hours ago" --export json --output investigation.json

# 3. Focus on specific threat categories
sudo ./scripts/ioc-hunter --ssh-activity --privilege-escalation --command-history --begin "1 hour ago"

# 4. Export for team analysis
sudo ./scripts/ioc-hunter --full --export markdown --output team_report.md
```

## Configuration

IoC-Hunter uses JSON configuration files in the `config/` directory:

- `default_patterns.json` - IoC detection patterns and rules
- `log_sources.json` - Log source configurations and paths
- `export_formats.json` - Export format settings
- `severity_rules.json` - Severity classification rules

Configuration can be customized for specific environments or extended with new patterns.

## System Information

```bash
# Show available categories
./scripts/ioc-hunter --list-categories

# Show available export formats  
./scripts/ioc-hunter --list-exporters

# Test log source accessibility
sudo ./scripts/ioc-hunter --test-sources

# Show system information
./scripts/ioc-hunter --system-info
```

## Architecture

IoC-Hunter uses a modular, extensible architecture:

```
ioc_hunter/
├── core/           # Main framework components
├── categories/     # IoC detection categories (auto-discovered)
├── exporters/      # Export format implementations (auto-discovered)
├── filters/        # Search and filtering functionality
└── utils/          # Utility functions and helpers
```

### Extensibility

New IoC categories and export formats are automatically discovered:

1. **Add new category**: Drop a Python file in `ioc_hunter/categories/`
2. **Add new exporter**: Drop a Python file in `ioc_hunter/exporters/`
3. **No code changes required**: CLI automatically recognizes new components

## Performance

### Typical Scan Times
- **15-minute window**: 10-30 seconds
- **1-hour window**: 30-60 seconds  
- **24-hour window**: 1-3 minutes
- **1-week window**: 5-15 minutes

### Memory Usage
- **Baseline**: 50-100 MB
- **Large datasets**: 200-400 MB
- **Enterprise environments**: Up to 500 MB during processing

## Security Considerations

- **Root privileges required**: Necessary for comprehensive log access
- **Local execution only**: No network communication except for exports
- **Audit trail**: All scans can be logged and exported
- **Data sensitivity**: Results may contain sensitive system information
- **Log source validation**: Built-in validation for log source integrity

## Blue Team Integration

### SIEM Integration
```bash
# Direct Splunk integration
sudo ./scripts/ioc-hunter --quick --export splunk --splunk-server splunk.local:8089

# Syslog format for other SIEMs
sudo ./scripts/ioc-hunter --full --export syslog --output /var/log/ioc_results.log
```

### Automation
```bash
# Scheduled scanning (add to crontab)
*/20 * * * * /usr/local/bin/ioc-hunter --quick --export json --output /var/log/ioc_scan_$(date +\%Y\%m\%d_\%H\%M).json

# Alert on high-severity findings
sudo ./scripts/ioc-hunter --quick --severity HIGH && echo "HIGH severity IoCs detected!" | mail -s "Security Alert" admin@company.com
```

## Troubleshooting

### Common Issues

**"Permission denied" errors**
- Solution: Run with `sudo` for comprehensive log access

**"No log sources accessible"**
- Check log file permissions: `ls -la /var/log/`
- Verify systemd/journald status: `systemctl status systemd-journald`

**"Module import errors"**
- Reinstall dependencies: `pip3 install --user -r requirements.txt`
- Check Python version: `python3 --version` (3.9+ required)

**Poor performance**
- Reduce time window: Use shorter scan periods
- Use quick mode: `--quick` instead of `--full`
- Check available memory: `free -h`

### Log Sources

IoC-Hunter automatically detects and uses available log sources:
- **journald**: Modern systemd systems (primary)
- **auth.log**: Authentication logs (`/var/log/auth.log`, `/var/log/secure`)
- **syslog**: Traditional system logs (`/var/log/syslog`, `/var/log/messages`)
- **Application logs**: Web servers, mail servers, Splunk (detected automatically)

## Contributing

IoC-Hunter is designed for easy extension:

1. **New IoC Categories**: Inherit from `BaseIoCCategory`
2. **New Export Formats**: Inherit from `BaseExporter`  
3. **New Log Sources**: Inherit from `BaseLogSource`
4. **Configuration**: Extend JSON configuration files

See `docs/` for development documentation.

## Support

- **Documentation**: See `docs/USAGE_GUIDE.md` for comprehensive usage
- **Blue Team Guide**: See `docs/BLUE_TEAM_GUIDE.md` for exercise-specific guidance
- **Configuration**: See `config/` directory for customization options

## Version Information

- **Version**: 1.0.0
- **Python Compatibility**: 3.9+
- **Target Systems**: Ubuntu 24.04.3, Fedora 42, Oracle Linux 9.2
- **License**: Open Source

---

**Ready to start hunting for IoCs?**

```bash
sudo ./scripts/ioc-hunter --quick
```

*For blue team exercises, incident response, and continuous security monitoring.*
