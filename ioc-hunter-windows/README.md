# IoC-Hunter

**A comprehensive PowerShell module for detecting Indicators of Compromise (IoCs) on Windows systems through systematic Windows Event Log analysis.**

IoC-Hunter provides security professionals with a powerful, production-ready tool for rapid threat detection and forensic analysis. The module analyzes 26 different categories of suspicious activities, from failed authentication attempts to advanced persistent threat indicators.

## Key Features

- **26 IoC Categories**: Comprehensive coverage from basic failed logins to sophisticated process injection techniques
- **Dual Scan Modes**: Quick scans (18 critical categories, 2-4 minutes) and Full scans (all 26 categories, 5-15 minutes)
- **Multiple Export Formats**: CSV, JSON, Timeline, and SIEM-ready outputs
- **Production Ready**: Comprehensive test suite with 100% pass rate
- **Memory Optimized**: Efficient processing with built-in performance monitoring
- **Forensic Workflow**: Complete save/load capability for incident response
- **Advanced Filtering**: Time-based analysis with flexible search capabilities

## IoC Categories Detected

### Quick Scan Categories (18 Critical)
- Failed Login Attempts
- Lateral Movement / Suspicious Logons  
- Credential Dumping Activity
- Suspicious Service Activity
- Suspicious Scheduled Task Activity
- Registry Modifications (Quick)
- Windows Defender Events
- RDP/Terminal Services Activity
- WMI Activity
- Suspicious PowerShell Activity
- Account Management Activity
- Event Log Clearing
- Privilege Escalation
- Suspicious Process Creation
- Share Access (Quick)
- Firewall Rule Changes
- Suspicious DNS Activity
- Process Injection (Quick)

### Additional Full Scan Categories (8 Additional)
- Suspicious Registry Modifications (Full)
- Suspicious Share Access (Full)
- Process Injection (Full)
- File Creation in Suspicious Locations
- Certificate Installation
- Network Connection Events
- Application Crashes
- Boot/Startup Events
- Print Spooler Events
- Suspicious Driver Loading
- Software Installation

## Prerequisites

- **PowerShell 5.1 or later**
- **Administrator privileges** (required for Windows Event Log access)
- **Windows Event Logs** must be accessible
- **Recommended**: At least 4GB RAM for large dataset analysis

## Installation

1. **Download or clone** the IoC-Hunter module to your desired location
2. **Verify directory structure**:
   ```
   IoC-Hunter/
   ├── IoC-Hunter.psd1
   ├── IoC-Hunter.psm1
   ├── Functions/
   │   ├── Public/
   │   └── Private/
   └── Tests/
   ```
3. **Import the module**:
   ```powershell
   Import-Module .\IoC-Hunter
   ```

## Quick Start

### Basic Usage

```powershell
# Import the module
Import-Module .\IoC-Hunter

# Quick scan (18 critical categories, ~2-4 minutes)
$results = Get-IoCs -Quick -BeginTime (Get-Date).AddHours(-1)

# Full comprehensive scan (all 26 categories, ~5-15 minutes)  
$results = Get-IoCs -Full -BeginTime (Get-Date).AddHours(-24)

# Targeted scan (specific categories only)
$results = Get-IoCs -PowerShellSuspicious -FailedLogins -BeginTime (Get-Date).AddMinutes(-30)
```

### Analyzing Results

```powershell
# View summary
$results | Format-Table EventID, Category, Severity, TimeGenerated

# Filter high-severity events
$critical = Search-IoCs -InputObject $results -Severity "High"

# Search for specific indicators
$powershell_events = Search-IoCs -InputObject $results -Category "PowerShell"
```

### Saving and Loading Results

```powershell
# Save scan results for incident response
Save-IoCs -Results $results -Path "incident_$(Get-Date -f 'yyyyMMdd_HHmm').json" -Description "Compromise assessment"

# Load saved results for analysis
$saved_results = Import-IoCs -Path "incident_20251024_1430.json"
```

### Export for External Systems

```powershell
# Export to CSV for spreadsheet analysis
Export-IoCs -InputObject $results -Format CSV -Path "security_events.csv"

# Export to SIEM-ready format
Export-IoCs -InputObject $results -Format SIEM -Path "siem_events.json"

# Create timeline for forensic analysis
Export-IoCs -InputObject $results -Format Timeline -Path "incident_timeline.json"
```

## Advanced Examples

### Incident Response Workflow

```powershell
# 1. Initial quick assessment
$quick_scan = Get-IoCs -Quick -BeginTime (Get-Date).AddHours(-4)
Write-Host "Quick scan found $($quick_scan.Count) potential IoCs"

# 2. If threats detected, run comprehensive scan
if ($quick_scan.Count -gt 0) {
    $full_scan = Get-IoCs -Full -BeginTime (Get-Date).AddDays(-1)
    Save-IoCs -Results $full_scan -Path "full_incident_scan.json" -Description "Complete incident analysis"
}

# 3. Generate report for stakeholders
$high_priority = Search-IoCs -InputObject $full_scan -Severity "High"
Export-IoCs -InputObject $high_priority -Format CSV -Path "executive_summary.csv"
```

### Threat Hunting

```powershell
# Hunt for lateral movement over past week
$lateral_movement = Get-IoCs -LateralMovement -CredentialDumping -BeginTime (Get-Date).AddDays(-7)

# Look for PowerShell-based attacks
$powershell_threats = Get-IoCs -PowerShellSuspicious -BeginTime (Get-Date).AddDays(-3)

# Comprehensive persistence mechanism check
$persistence = Get-IoCs -ServiceSuspicious -ScheduledTaskSuspicious -RegistryModifications -BeginTime (Get-Date).AddDays(-1)
```

### Performance Optimization

```powershell
# For frequent monitoring, use shorter time windows
$recent_threats = Get-IoCs -Quick -BeginTime (Get-Date).AddMinutes(-15)

# For deep forensic analysis, extend time window but expect longer runtime
$forensic_scan = Get-IoCs -Full -BeginTime (Get-Date).AddDays(-30)
# Note: 30-day full scan may take 30+ minutes depending on system activity
```

## Available Functions

- **Get-IoCs**: Main detection function with 43 parameters for comprehensive IoC detection
- **Save-IoCs**: Persist scan results with metadata for incident response workflows  
- **Import-IoCs**: Load previously saved scan results for continued analysis
- **Search-IoCs**: Filter and query IoC results by various criteria
- **Export-IoCs**: Export results in multiple formats (CSV, JSON, Timeline, SIEM)

## Testing and Validation

IoC-Hunter includes a comprehensive test suite to ensure reliability:

```powershell
# Navigate to Tests directory
cd .\Tests\

# Run complete test suite
.\Run-AllTests.ps1

# Quick validation test
.\Run-AllTests.ps1 -QuickTest
```

**Current Test Status**: All 5 test suites passing (100% success rate)

## Performance Characteristics

### Typical Scan Times
- **15-minute window**: 1-5 seconds
- **1-hour window**: 5-15 seconds  
- **24-hour window**: 30-60 seconds
- **1-week window**: 2-5 minutes
- **1-month window**: 10-30 minutes

### Memory Usage
- **Baseline**: 50-100 MB
- **Large datasets (1000+ events)**: 100-200 MB
- **Enterprise environments**: Up to 300 MB during processing

## Troubleshooting

### Common Issues

**"Access Denied" Errors**
- Solution: Run PowerShell as Administrator

**"Module not found" Errors**  
- Solution: Verify module path and ensure all files are present

**Performance Issues**
- Consider smaller time windows for frequent scans
- Use Quick mode for routine monitoring
- Reserve Full mode for thorough investigations

**"Event log unavailable" Warnings**
- Normal on systems with limited logging
- Module will adapt and scan available logs

## Integration Examples

### SIEM Integration

```powershell
# Automated SIEM feeding (run via scheduled task)
$threats = Get-IoCs -Quick -BeginTime (Get-Date).AddMinutes(-15)
if ($threats.Count -gt 0) {
    Export-IoCs -InputObject $threats -Format SIEM -Path "\\siem-server\incoming\ioc_$(Get-Date -f 'yyyyMMdd_HHmmss').json"
}
```

### Incident Response Automation

```powershell
# Automated threat detection and alerting
$critical_threats = Get-IoCs -Quick -BeginTime (Get-Date).AddMinutes(-5)
$high_severity = Search-IoCs -InputObject $critical_threats -Severity "High"

if ($high_severity.Count -gt 0) {
    Save-IoCs -Results $high_severity -Path "ALERT_$(Get-Date -f 'yyyyMMdd_HHmmss').json" -Description "Automated threat detection alert"
    # Trigger additional response actions here
}
```

## Security Considerations

- **Requires Administrator privileges**: Necessary for comprehensive event log access
- **Local execution only**: Module reads local Windows Event Logs
- **No network communication**: All analysis performed locally
- **Audit trail**: All scans can be saved with timestamps and descriptions
- **Data sensitivity**: Results may contain sensitive system information

## Support and Documentation

- **Complete Usage Guide**: See `USAGE-GUIDE.md` for comprehensive documentation
- **Test Documentation**: See `Tests/TEST-USAGE-GUIDE.md` for testing information
- **Module Structure**: See `MODULE-STRUCTURE` for technical details

## Version Information

- **Module Version**: 1.0.0
- **PowerShell Compatibility**: 5.1+
- **Test Suite Status**: 5/5 tests passing
- **Production Ready**: Yes

## License and Disclaimer

This tool is designed for legitimate security analysis and incident response activities. Users are responsible for ensuring compliance with applicable laws and organizational policies when analyzing system logs and security events.

---

**Ready to start hunting for IoCs?**

```powershell
Import-Module .\IoC-Hunter
Get-IoCs -Quick -BeginTime (Get-Date).AddHours(-1)
```

For comprehensive documentation and advanced usage patterns, see `USAGE-GUIDE.md`.
