# IoC-Hunter Usage Guide

**Comprehensive documentation for the IoC-Hunter PowerShell module - your complete guide to Windows threat detection and incident response.**

## Table of Contents

1. [Overview](#overview)
2. [Function Reference](#function-reference)
3. [IoC Categories Explained](#ioc-categories-explained)
4. [Scan Modes](#scan-modes)
5. [Time Window Management](#time-window-management)
6. [Advanced Usage Patterns](#advanced-usage-patterns)
7. [Performance Optimization](#performance-optimization)
8. [Integration Scenarios](#integration-scenarios)
9. [Workflow Examples](#workflow-examples)
10. [Troubleshooting](#troubleshooting)
11. [Best Practices](#best-practices)
12. [FAQ](#faq)

## Overview

IoC-Hunter is a production-ready PowerShell module designed for security professionals who need to rapidly detect and analyze threats on Windows systems. By systematically analyzing Windows Event Logs across 26 different security categories, IoC-Hunter provides comprehensive coverage of modern attack vectors and persistence mechanisms.

### Core Capabilities

- **26 IoC Categories**: From basic failed logins to advanced process injection techniques
- **Dual Scan Modes**: Quick (18 categories, 2-4 min) and Full (26 categories, 5-15 min)
- **Flexible Time Windows**: From minutes to months of historical analysis
- **Multiple Export Formats**: CSV, JSON, Timeline, SIEM-ready outputs
- **Complete Workflow**: Save, load, search, and analyze scan results
- **Production Ready**: 100% test pass rate with comprehensive error handling
- **Memory Optimized**: Efficient processing with built-in performance monitoring

### System Requirements

- **PowerShell**: Version 5.1 or later
- **Privileges**: Administrator access (required for event log reading)
- **Memory**: Minimum 4GB recommended for large dataset analysis
- **Event Logs**: Windows Event Logs must be accessible and enabled
- **Storage**: Varies by scan size (typically 1-50MB for saved results)

## Function Reference

### Get-IoCs

**Primary detection function with 43 parameters for comprehensive threat hunting.**

#### Syntax
```powershell
Get-IoCs [-Quick] [-BeginTime <DateTime>] [-EndTime <DateTime>] [-Table] [-Help]

Get-IoCs [-Full] [-BeginTime <DateTime>] [-EndTime <DateTime>] [-Table] [-Help]

Get-IoCs [-FailedLogins] [-PowerShellSuspicious] [-ProcessCreation] [additional category parameters...] 
         [-BeginTime <DateTime>] [-EndTime <DateTime>] [-Table] [-Help]
```

#### Core Parameters

**-Quick**
- Enables Quick scan mode (18 critical categories)
- Estimated time: 2-4 minutes
- Cannot be combined with -Full
- Optimized for rapid threat detection

**-Full**
- Enables Full scan mode (all 26 categories)
- Estimated time: 5-15 minutes  
- Cannot be combined with -Quick
- Comprehensive threat coverage

**-BeginTime <DateTime>**
- Start time for event log analysis
- Default: 20 minutes ago
- Must be earlier than EndTime
- Examples: `(Get-Date).AddHours(-24)`, `"2025-10-23 09:00:00"`

**-EndTime <DateTime>**
- End time for event log analysis
- Default: Current time
- Must be later than BeginTime
- Examples: `(Get-Date)`, `"2025-10-23 17:00:00"`

**-Table**
- Returns results formatted as a table
- Useful for quick visual analysis
- When omitted, returns full objects with all properties

**-Help**
- Displays comprehensive help information
- Includes parameter descriptions and examples

#### Category Parameters

All 26 IoC categories can be used as individual switch parameters:

- **-FailedLogins**: Failed authentication attempts
- **-PowerShellSuspicious**: Suspicious PowerShell activity  
- **-ProcessCreation**: Suspicious process creation events
- **-NetworkConnections**: Network connection events
- **-PrivilegeEscalation**: Privilege escalation attempts
- **-ServiceSuspicious**: Suspicious service activity
- **-ScheduledTaskSuspicious**: Suspicious scheduled tasks
- **-AccountManagement**: Account management activity
- **-EventLogClearing**: Event log clearing attempts
- **-RegistryModifications**: Registry modifications
- **-WindowsDefender**: Windows Defender events
- **-LateralMovement**: Lateral movement indicators
- **-WMIActivity**: WMI activity events
- **-DriverLoading**: Suspicious driver loading
- **-FileCreation**: File creation in suspicious locations
- **-RDPActivity**: RDP/Terminal Services activity
- **-CredentialDumping**: Credential dumping activity
- **-FirewallChanges**: Firewall rule changes
- **-ShareAccess**: File share access events
- **-ProcessInjection**: Process injection techniques
- **-CertificateInstallation**: Certificate installation events
- **-DNSEvents**: Suspicious DNS activity
- **-ApplicationCrashes**: Application crashes
- **-BootStartupEvents**: Boot/startup events
- **-PrintSpoolerEvents**: Print spooler events
- **-SoftwareInstallation**: Software installation events

#### Output Properties

Get-IoCs returns objects with the following properties:

- **TimeCreated**: When the event occurred
- **EventID**: Windows Event ID
- **Category**: IoC category name
- **Severity**: High, Medium, or Low
- **User**: Associated user account
- **Source**: Event source
- **Target**: Target of the activity
- **Details**: Detailed description
- **Computer**: Machine name
- **LogName**: Source event log
- **RecordId**: Event record ID
- **EventXML**: Full event XML
- **ForensicData**: Additional forensic information

### Save-IoCs

**Saves IoC scan results to structured JSON files for persistence and sharing.**

#### Syntax
```powershell
Save-IoCs -Results <Object[]> -Path <String> [-Description <String>] [-Compress]
```

#### Parameters

**-Results <Object[]>**
- IoC scan results from Get-IoCs (mandatory)
- Accepts pipeline input
- Can handle arrays of IoC objects

**-Path <String>**
- File path for saved results (mandatory)
- Must include .json extension
- Directory created automatically if needed

**-Description <String>**
- Optional description for documentation
- Helps identify scan purpose and context
- Stored in saved file metadata

**-Compress**
- Compresses JSON output to reduce file size
- Recommended for large scans or storage optimization

#### Saved File Structure

The saved JSON includes:
- All original IoC data and properties
- Scan metadata (timestamp, user, computer, description)
- Summary statistics (event counts, severity distribution)
- Version information for compatibility tracking

### Import-IoCs

**Loads previously saved IoC scan results for analysis.**

#### Syntax
```powershell
Import-IoCs -Path <String>
```

#### Parameters

**-Path <String>**
- Path to saved IoC JSON file (mandatory)
- Must be a file created by Save-IoCs
- Validates file format and version compatibility

#### Usage Notes

- Restores complete IoC objects with all properties
- Maintains original timestamp and metadata information  
- Compatible with all Search-IoCs and Export-IoCs operations
- Validates file integrity during import

### Search-IoCs

**Filters and queries IoC results by various criteria.**

#### Syntax
```powershell
Search-IoCs -InputObject <Object[]> [-Category <String>] [-Severity <String>] [-User <String>] 
            [-BeginTime <DateTime>] [-EndTime <DateTime>] [-EventID <Int32>] [-Source <String>]
```

#### Parameters

**-InputObject <Object[]>**
- IoC results to search (mandatory)
- Accepts pipeline input from Get-IoCs or Import-IoCs

**-Category <String>**
- Filter by IoC category name
- Examples: "PowerShell", "FailedLogins", "ProcessCreation"

**-Severity <String>**
- Filter by severity level
- Values: "High", "Medium", "Low"

**-User <String>**
- Filter by associated user account
- Supports partial matches

**-BeginTime / -EndTime <DateTime>**
- Filter by time range within loaded results
- Useful for narrowing focus to specific time periods

**-EventID <Int32>**
- Filter by specific Windows Event ID
- Examples: 4625 (failed logins), 4688 (process creation)

**-Source <String>**
- Filter by event source
- Examples: "Microsoft-Windows-Security-Auditing"

### Export-IoCs

**Exports IoC results to various formats for external systems.**

#### Syntax
```powershell
Export-IoCs -InputObject <Object[]> -Path <String> [-Format <String>]
```

#### Parameters

**-InputObject <Object[]>**
- IoC results to export (mandatory)
- Accepts pipeline input

**-Path <String>**
- Export file path (mandatory)
- Extension should match format

**-Format <String>**
- Export format (optional, default: CSV)
- Values: "CSV", "JSON", "Timeline", "SIEM"

#### Export Formats

**CSV Format**
- Spreadsheet-compatible tabular data
- Includes all key IoC properties
- Best for: Manual analysis, reporting, Excel integration

**JSON Format**  
- Structured data with full property preservation
- Maintains nested objects and arrays
- Best for: Programmatic analysis, API integration

**Timeline Format**
- Chronologically ordered events with time focus
- Optimized for temporal analysis
- Best for: Incident timeline reconstruction, forensic analysis

**SIEM Format**
- Standardized format for SIEM integration
- Normalized field names and structures
- Best for: Security tool integration, automated processing

## IoC Categories Explained

### Quick Scan Categories (18 Critical)

These categories are included in Quick scan mode for rapid threat detection:

#### 1. FailedLogins
**Event IDs**: 4625
**Description**: Failed authentication attempts indicating potential brute force attacks
**Severity**: High (multiple failures), Medium (isolated failures)
**Common Indicators**: Rapid repeated failures, failures from unusual locations, service account failures

#### 2. LateralMovement  
**Event IDs**: 4624, 4648, 4672
**Description**: Successful logons and authentication events suggesting lateral movement
**Severity**: High (unusual patterns), Medium (suspicious timing)
**Common Indicators**: Logons to multiple systems, unusual service accounts, off-hours access

#### 3. CredentialDumping
**Event IDs**: 4656, 4663 (LSASS access)
**Description**: Suspicious access to credential stores like LSASS process
**Severity**: High (direct LSASS access), Medium (suspicious process access)
**Common Indicators**: Non-system processes accessing LSASS, credential extraction tools

#### 4. ServiceSuspicious
**Event IDs**: 7034, 7035, 7036, 7040, 7045
**Description**: Suspicious Windows service creation, modification, and execution
**Severity**: High (unknown services), Medium (service modifications)
**Common Indicators**: Services with suspicious names, temporary services, unsigned binaries

#### 5. ScheduledTaskSuspicious
**Event IDs**: 4698, 4699, 4700, 4701, 4702
**Description**: Suspicious scheduled task creation and execution  
**Severity**: High (persistence mechanisms), Medium (unusual scheduling)
**Common Indicators**: Tasks with system privileges, unusual schedules, suspicious executables

#### 6. RegistryModifications (Quick)
**Event IDs**: 4657 (high-confidence keys only)
**Description**: Registry changes in critical areas for persistence and configuration
**Severity**: High (persistence keys), Medium (configuration changes)
**Common Indicators**: Run keys, service modifications, policy changes

#### 7. WindowsDefender
**Event IDs**: 1116, 1117, 5001, 5007, 5012
**Description**: Windows Defender events including detections and configuration changes
**Severity**: High (threat detections), Medium (configuration changes)
**Common Indicators**: Real-time protection disabled, exclusions added, threats detected

#### 8. RDPActivity
**Event IDs**: 1149, 21, 24, 25 (TerminalServices-*)
**Description**: Remote Desktop Protocol connections and authentication
**Severity**: High (unauthorized access), Medium (unusual patterns)
**Common Indicators**: Off-hours connections, failed RDP authentications, unusual source IPs

#### 9. WMIActivity
**Event IDs**: 5857, 5858, 5859, 5860, 5861
**Description**: Windows Management Instrumentation activity for persistence and lateral movement
**Severity**: High (WMI persistence), Medium (suspicious queries)
**Common Indicators**: WMI event subscriptions, remote WMI access, PowerShell WMI usage

#### 10. PowerShellSuspicious
**Event IDs**: 4103, 4104, 600, 800
**Description**: Suspicious PowerShell activity including script blocks and engine state
**Severity**: High (obfuscation detected), Medium (suspicious patterns)
**Common Indicators**: Base64 encoding, obfuscation, download cradles, invoke expressions

#### 11. AccountManagement
**Event IDs**: 4720, 4722, 4724, 4725, 4726, 4728, 4732, 4738
**Description**: User account and group membership changes
**Severity**: High (privileged account changes), Medium (account modifications)
**Common Indicators**: Admin account creation, group membership changes, account enablement

#### 12. EventLogClearing
**Event IDs**: 1102, 104
**Description**: Event log clearing attempts used to cover tracks
**Severity**: High (security log clearing), Medium (other log clearing)
**Common Indicators**: Manual log clearing, automated clearing scripts, selective log deletion

#### 13. PrivilegeEscalation
**Event IDs**: 4672, 4673, 4674, 4688 (with privilege changes)
**Description**: Privilege escalation attempts and successful elevations
**Severity**: High (unexpected elevations), Medium (service escalations)
**Common Indicators**: Process elevation, UAC bypasses, service account privilege use

#### 14. ProcessCreation
**Event IDs**: 4688, 1 (Sysmon)
**Description**: Suspicious process creation and execution patterns
**Severity**: High (known malicious processes), Medium (suspicious patterns)
**Common Indicators**: Unsigned binaries, unusual parent-child relationships, suspicious locations

#### 15. ShareAccess (Quick)
**Event IDs**: 5140, 5142, 5143, 5144 (high-confidence patterns)
**Description**: File share access events indicating potential data access or lateral movement
**Severity**: High (admin share access), Medium (unusual patterns)
**Common Indicators**: Administrative share access, off-hours access, large data transfers

#### 16. FirewallChanges
**Event IDs**: 2004, 2005, 2006, 2033
**Description**: Windows Firewall rule modifications
**Severity**: High (security rule changes), Medium (rule additions)
**Common Indicators**: Firewall disabling, new inbound rules, port opening

#### 17. DNSEvents
**Event IDs**: 3008, 3020 (DNS Client), 259, 260 (DNS Server)
**Description**: Suspicious DNS activity and domain resolution patterns
**Severity**: High (known malicious domains), Medium (suspicious patterns)
**Common Indicators**: DNS tunneling, DGA domains, unusual query patterns

#### 18. ProcessInjection (Quick)
**Event IDs**: 8, 10 (Sysmon), 4688 (with injection indicators)
**Description**: Process injection techniques including DLL injection and process hollowing
**Severity**: High (confirmed injection), Medium (suspicious process relationships)
**Common Indicators**: Cross-process memory access, DLL injection, process hollowing

### Additional Full Scan Categories (8 Additional)

These categories are only included in Full scan mode for comprehensive analysis:

#### 19. RegistryModifications (Full)
**Enhanced registry monitoring** with broader key coverage including application settings, user preferences, and extended persistence mechanisms. Includes all Quick scan registry keys plus comprehensive monitoring.

#### 20. ShareAccess (Full)
**Comprehensive file share analysis** including all share types, access patterns, and data transfer monitoring. Extends Quick scan with detailed access logging and pattern analysis.

#### 21. ProcessInjection (Full)
**Advanced injection technique detection** including advanced persistence methods, memory manipulation, and steganographic techniques. Comprehensive coverage beyond Quick scan basics.

#### 22. FileCreation
**Event IDs**: 11 (Sysmon), 4656, 4658, 4663
**Description**: File creation in suspicious locations including system directories and startup folders
**Severity**: High (system directory creation), Medium (unusual locations)
**Common Indicators**: Executable creation in system folders, startup directory modifications, web shell creation

#### 23. CertificateInstallation
**Event IDs**: 1007, 1008 (CAPI2), 90, 91 (CertificateServicesClient)
**Description**: Certificate installation events indicating potential man-in-the-middle attacks
**Severity**: High (root certificate installation), Medium (user certificate changes)
**Common Indicators**: Self-signed certificates, unusual certificate authorities, SSL interception

#### 24. NetworkConnections
**Event IDs**: 3 (Sysmon), 5156 (Windows Filtering Platform)
**Description**: Network connection events for command & control communication detection
**Severity**: High (known malicious IPs), Medium (suspicious patterns)
**Common Indicators**: Unusual outbound connections, non-standard ports, foreign IP communication

#### 25. ApplicationCrashes
**Event IDs**: 1000, 1001 (Application Error), 1026 (Application Hang)
**Description**: Application crashes potentially indicating exploitation attempts
**Severity**: High (security software crashes), Medium (repeated crashes)
**Common Indicators**: Security tool crashes, browser exploitation, targeted application failures

#### 26. BootStartupEvents
**Event IDs**: 12, 13, 14 (Sysmon), 6005, 6006, 6008 (EventLog)
**Description**: System boot and startup events for persistence mechanism detection
**Severity**: High (startup modifications), Medium (boot anomalies)
**Common Indicators**: Startup program changes, boot sector modifications, system startup delays

#### 27. PrintSpoolerEvents
**Event IDs**: 307, 315, 316 (PrintService)
**Description**: Print spooler activity including PrintNightmare exploitation detection
**Severity**: High (privilege escalation via spooler), Medium (unusual print activity)
**Common Indicators**: Non-standard print drivers, privilege escalation attempts, remote print exploitation

#### 28. DriverLoading
**Event IDs**: 6 (Sysmon), 219 (Kernel-PnP), 7034 (Service Control Manager)
**Description**: Driver loading from suspicious locations and unsigned driver usage
**Severity**: High (unsigned drivers), Medium (unusual driver sources)
**Common Indicators**: Unsigned drivers, drivers from temp directories, rootkit installation

#### 29. SoftwareInstallation
**Event IDs**: 1033, 1034 (MsiInstaller), 11707, 11708, 11724
**Description**: Software installation events for unauthorized application detection
**Severity**: High (unauthorized system software), Medium (unusual installations)
**Common Indicators**: Silent installations, unsigned software, privilege escalation via installation

## Scan Modes

### Quick Scan Mode

**Purpose**: Rapid threat detection for routine monitoring and incident response
**Categories**: 18 critical security categories
**Estimated Time**: 2-4 minutes
**Memory Usage**: 50-150 MB
**Use Cases**: 
- Routine security monitoring
- Initial incident response assessment  
- Automated scheduled scans
- Rapid threat triage

**Command**: `Get-IoCs -Quick`

**Included Categories**:
The Quick scan focuses on high-confidence indicators and common attack vectors:
- Authentication failures and brute force attempts
- Lateral movement and credential abuse
- PowerShell-based attacks and suspicious scripting
- Service and scheduled task abuse for persistence
- Registry modifications for persistence and configuration changes
- Windows Defender events and security tool interference
- Network-based attacks and suspicious connections
- Process creation and injection techniques

### Full Scan Mode

**Purpose**: Comprehensive threat hunting and forensic analysis
**Categories**: All 26 security categories
**Estimated Time**: 5-15 minutes
**Memory Usage**: 100-300 MB
**Use Cases**:
- Thorough security assessments
- Incident investigation and forensics
- Compliance auditing
- Deep threat hunting exercises

**Command**: `Get-IoCs -Full`

**Additional Categories**:
Full scan adds 8 additional categories for complete coverage:
- Enhanced registry and file share monitoring
- Advanced process injection techniques
- File creation and software installation tracking
- Certificate management and SSL interception
- Network connection analysis
- Application stability and exploitation indicators
- System boot and driver loading events
- Print spooler exploitation detection

### Targeted Scan Mode

**Purpose**: Focus on specific threat categories based on intelligence or investigation needs
**Categories**: User-selected individual categories
**Estimated Time**: Seconds to minutes (depends on categories)
**Memory Usage**: 25-100 MB
**Use Cases**:
- Threat hunting based on intelligence
- Investigation of specific attack vectors
- Performance-optimized monitoring
- Category-specific analysis

**Command**: `Get-IoCs -PowerShellSuspicious -FailedLogins -ProcessCreation`

## Time Window Management

### Understanding Time Windows

IoC-Hunter's flexibility in time window selection is crucial for effective threat hunting and incident response:

#### Default Behavior
- **BeginTime**: 20 minutes ago
- **EndTime**: Current time
- **Rationale**: Provides recent activity snapshot without overwhelming results

#### Common Time Windows

**Real-time Monitoring (5-15 minutes)**
```powershell
Get-IoCs -Quick -BeginTime (Get-Date).AddMinutes(-15)
```
- Use case: Continuous monitoring, automated alerting
- Performance: 1-5 seconds
- Memory: 25-75 MB

**Incident Response (1-6 hours)**
```powershell
Get-IoCs -Quick -BeginTime (Get-Date).AddHours(-6)
```
- Use case: Initial incident assessment, threat triage
- Performance: 5-30 seconds
- Memory: 50-150 MB

**Daily Analysis (24 hours)**
```powershell
Get-IoCs -Full -BeginTime (Get-Date).AddDays(-1)
```
- Use case: Daily security reviews, comprehensive monitoring
- Performance: 30-120 seconds
- Memory: 100-250 MB

**Weekly Investigation (7 days)**
```powershell
Get-IoCs -Full -BeginTime (Get-Date).AddDays(-7)
```
- Use case: Weekly security assessments, trend analysis
- Performance: 2-10 minutes
- Memory: 150-300 MB

**Forensic Analysis (30+ days)**
```powershell
Get-IoCs -Full -BeginTime (Get-Date).AddDays(-30)
```
- Use case: Comprehensive forensics, compliance auditing
- Performance: 10-60 minutes
- Memory: 200-500 MB

#### Time Window Optimization

**Performance Considerations**:
- **Shorter windows**: Faster execution, lower memory usage
- **Longer windows**: More comprehensive but slower execution
- **Category count**: More categories = longer execution time
- **System activity**: Busy systems generate more events to analyze

**Best Practices**:
1. **Start small**: Begin with shorter windows for initial assessment
2. **Expand gradually**: Increase window size based on findings
3. **Use Quick mode**: For routine monitoring and rapid assessment
4. **Reserve Full mode**: For thorough investigations and forensics
5. **Monitor performance**: Track execution time and memory usage

#### Custom Time Ranges

**Business Hours Analysis**
```powershell
$start = Get-Date "2025-10-24 09:00:00"
$end = Get-Date "2025-10-24 17:00:00"
Get-IoCs -Full -BeginTime $start -EndTime $end
```

**Weekend Activity Review**
```powershell
$friday = Get-Date "2025-10-25 17:00:00"  
$monday = Get-Date "2025-10-28 09:00:00"
Get-IoCs -Quick -BeginTime $friday -EndTime $monday
```

**Incident Time Frame**
```powershell
# Focus on specific incident window
$incident_start = Get-Date "2025-10-24 14:30:00"
$incident_end = Get-Date "2025-10-24 16:15:00"
Get-IoCs -Full -BeginTime $incident_start -EndTime $incident_end
```

## Advanced Usage Patterns

### Pattern 1: Layered Analysis

**Concept**: Start with broad, fast scans and progressively narrow focus based on findings.

```powershell
# Layer 1: Quick assessment
$quick_results = Get-IoCs -Quick -BeginTime (Get-Date).AddHours(-4)
Write-Host "Quick scan found $($quick_results.Count) potential IoCs"

# Layer 2: If threats found, expand scope
if ($quick_results.Count -gt 0) {
    $full_results = Get-IoCs -Full -BeginTime (Get-Date).AddDays(-1)
    $high_severity = Search-IoCs -InputObject $full_results -Severity "High"
    
    # Layer 3: Deep dive on specific categories
    $categories = $high_severity | Group-Object Category | Sort-Object Count -Descending
    foreach ($category in $categories) {
        Write-Host "Investigating $($category.Name): $($category.Count) events"
    }
}
```

### Pattern 2: Continuous Monitoring

**Concept**: Automated monitoring with intelligent alerting and escalation.

```powershell
# Continuous monitoring script (run via scheduled task)
function Start-ContinuousMonitoring {
    $baseline_path = "C:\Security\baseline.json"
    $alert_threshold = 5
    
    while ($true) {
        # Quick scan every 5 minutes
        $current_scan = Get-IoCs -Quick -BeginTime (Get-Date).AddMinutes(-5)
        
        if ($current_scan.Count -gt $alert_threshold) {
            # Save results for investigation
            $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
            Save-IoCs -Results $current_scan -Path "C:\Security\alerts\alert_$timestamp.json" -Description "Automated alert - $($current_scan.Count) IoCs detected"
            
            # Escalate if high-severity events found
            $critical = Search-IoCs -InputObject $current_scan -Severity "High"
            if ($critical.Count -gt 0) {
                # Trigger immediate full scan
                $full_scan = Get-IoCs -Full -BeginTime (Get-Date).AddHours(-1)
                Save-IoCs -Results $full_scan -Path "C:\Security\alerts\critical_$timestamp.json" -Description "Critical threat escalation"
                
                # Send alert (implement your notification method)
                Send-SecurityAlert -Events $critical -Severity "Critical"
            }
        }
        
        Start-Sleep -Seconds 300  # Wait 5 minutes
    }
}
```

### Pattern 3: Threat Hunting Methodology

**Concept**: Systematic threat hunting using hypothesis-driven analysis.

```powershell
# Threat hunting workflow
function Start-ThreatHunt {
    param(
        [string]$Hypothesis,
        [datetime]$StartTime,
        [datetime]$EndTime
    )
    
    Write-Host "=== Threat Hunt: $Hypothesis ===" -ForegroundColor Cyan
    
    # Phase 1: Broad collection
    $all_data = Get-IoCs -Full -BeginTime $StartTime -EndTime $EndTime
    Save-IoCs -Results $all_data -Path "hunt_raw_$((Get-Date -f 'yyyyMMdd')).json" -Description "Raw data for hunt: $Hypothesis"
    
    # Phase 2: Hypothesis testing
    switch -Wildcard ($Hypothesis) {
        "*PowerShell*" {
            $evidence = Search-IoCs -InputObject $all_data -Category "PowerShell"
            $suspicious_ps = $evidence | Where-Object { $_.Details -match "Invoke-|Download|Base64|Encoded" }
        }
        "*Lateral*" {
            $evidence = Search-IoCs -InputObject $all_data -Category "LateralMovement"
            $unusual_logons = $evidence | Group-Object User | Where-Object Count -gt 10
        }
        "*Persistence*" {
            $service_events = Search-IoCs -InputObject $all_data -Category "ServiceSuspicious"
            $task_events = Search-IoCs -InputObject $all_data -Category "ScheduledTaskSuspicious"
            $registry_events = Search-IoCs -InputObject $all_data -Category "RegistryModifications"
            $evidence = @($service_events) + @($task_events) + @($registry_events)
        }
    }
    
    # Phase 3: Analysis and reporting
    if ($evidence.Count -gt 0) {
        Write-Host "[FINDINGS] Hunt hypothesis supported: $($evidence.Count) supporting events" -ForegroundColor Red
        Export-IoCs -InputObject $evidence -Format Timeline -Path "hunt_evidence_$((Get-Date -f 'yyyyMMdd')).json"
        return $evidence
    } else {
        Write-Host "[NO FINDINGS] Hunt hypothesis not supported" -ForegroundColor Green
        return $null
    }
}

# Example usage
$evidence = Start-ThreatHunt -Hypothesis "PowerShell-based attacks in last 24h" -StartTime (Get-Date).AddDays(-1) -EndTime (Get-Date)
```

### Pattern 4: Comparative Analysis

**Concept**: Compare current state against baselines or previous scans.

```powershell
# Comparative analysis workflow
function Compare-SecurityState {
    param(
        [string]$BaselinePath,
        [datetime]$ComparisonPeriod = (Get-Date).AddDays(-1)
    )
    
    # Load baseline
    $baseline = Import-IoCs -Path $BaselinePath
    Write-Host "Baseline: $($baseline.Count) events from $(($baseline[0].TimeCreated).ToShortDateString())"
    
    # Current scan
    $current = Get-IoCs -Full -BeginTime $ComparisonPeriod
    Write-Host "Current: $($current.Count) events from $($ComparisonPeriod.ToShortDateString())"
    
    # Category comparison
    $baseline_categories = $baseline | Group-Object Category | Select-Object Name, Count
    $current_categories = $current | Group-Object Category | Select-Object Name, Count
    
    Write-Host "`n=== Category Comparison ===" -ForegroundColor Yellow
    foreach ($category in $current_categories) {
        $baseline_count = ($baseline_categories | Where-Object Name -eq $category.Name).Count
        if (-not $baseline_count) { $baseline_count = 0 }
        
        $change = $category.Count - $baseline_count
        $status = if ($change -gt 0) { "INCREASE (+$change)" } elseif ($change -lt 0) { "DECREASE ($change)" } else { "NO CHANGE" }
        
        Write-Host "$($category.Name): Baseline=$baseline_count, Current=$($category.Count) [$status]"
    }
    
    # New event types
    $new_events = $current | Where-Object { $_.EventID -notin $baseline.EventID }
    if ($new_events.Count -gt 0) {
        Write-Host "`n[ALERT] $($new_events.Count) new event types detected:" -ForegroundColor Red
        $new_events | Group-Object EventID | Select-Object Name, Count | Format-Table
    }
}
```

### Pattern 5: Multi-System Analysis

**Concept**: Coordinate analysis across multiple systems for enterprise-wide threat hunting.

```powershell
# Multi-system analysis (run from central system)
function Start-EnterpriseHunt {
    param(
        [string[]]$ComputerNames,
        [datetime]$StartTime,
        [string]$OutputPath = "C:\EnterpriseHunt"
    )
    
    $all_results = @()
    
    foreach ($computer in $ComputerNames) {
        Write-Host "Scanning $computer..." -ForegroundColor Green
        
        try {
            # Remote scan using PowerShell remoting
            $session = New-PSSession -ComputerName $computer
            $results = Invoke-Command -Session $session -ScriptBlock {
                Import-Module C:\Tools\IoC-Hunter
                Get-IoCs -Quick -BeginTime $using:StartTime
            }
            
            # Add computer name to results
            $results | ForEach-Object { $_.Computer = $computer }
            $all_results += $results
            
            # Save individual results
            if ($results.Count -gt 0) {
                Save-IoCs -Results $results -Path "$OutputPath\$computer_$(Get-Date -f 'yyyyMMdd').json" -Description "Enterprise hunt - $computer"
            }
            
            Remove-PSSession $session
            Write-Host "$computer: $($results.Count) events found" -ForegroundColor White
            
        } catch {
            Write-Host "$computer: ERROR - $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    
    # Enterprise summary
    Write-Host "`n=== Enterprise Summary ===" -ForegroundColor Cyan
    Write-Host "Total systems scanned: $($ComputerNames.Count)"
    Write-Host "Total events found: $($all_results.Count)"
    
    $by_computer = $all_results | Group-Object Computer | Sort-Object Count -Descending
    $by_category = $all_results | Group-Object Category | Sort-Object Count -Descending
    
    Write-Host "`nTop affected systems:"
    $by_computer | Select-Object -First 5 | Format-Table Name, Count
    
    Write-Host "Top threat categories:"
    $by_category | Select-Object -First 5 | Format-Table Name, Count
    
    # Save consolidated results
    if ($all_results.Count -gt 0) {
        Save-IoCs -Results $all_results -Path "$OutputPath\enterprise_consolidated_$(Get-Date -f 'yyyyMMdd').json" -Description "Enterprise-wide threat hunt"
        Export-IoCs -InputObject $all_results -Format CSV -Path "$OutputPath\enterprise_summary_$(Get-Date -f 'yyyyMMdd').csv"
    }
    
    return $all_results
}

# Example usage
$servers = @("SERVER01", "SERVER02", "WORKSTATION01", "WORKSTATION02")
$enterprise_threats = Start-EnterpriseHunt -ComputerNames $servers -StartTime (Get-Date).AddDays(-7)
```

## Performance Optimization

### Memory Management

**Understanding Memory Usage**:
- **Baseline**: 50-100 MB (module loading and basic operation)
- **Quick Scan**: +50-100 MB (processing 18 categories)
- **Full Scan**: +100-200 MB (processing 26 categories)
- **Large Datasets**: +100-300 MB (processing 1000+ events)

**Memory Optimization Strategies**:

```powershell
# Strategy 1: Process in chunks for large time windows
function Get-IoCs-Chunked {
    param(
        [datetime]$StartTime,
        [datetime]$EndTime,
        [int]$ChunkHours = 6
    )
    
    $all_results = @()
    $current_time = $StartTime
    
    while ($current_time -lt $EndTime) {
        $chunk_end = $current_time.AddHours($ChunkHours)
        if ($chunk_end -gt $EndTime) { $chunk_end = $EndTime }
        
        Write-Host "Processing chunk: $($current_time.ToString()) to $($chunk_end.ToString())"
        
        $chunk_results = Get-IoCs -Quick -BeginTime $current_time -EndTime $chunk_end
        $all_results += $chunk_results
        
        # Force garbage collection
        [System.GC]::Collect()
        
        $current_time = $chunk_end
    }
    
    return $all_results
}

# Strategy 2: Category-based processing for targeted analysis
function Get-IoCs-ByCategory {
    param(
        [string[]]$Categories,
        [datetime]$StartTime,
        [datetime]$EndTime
    )
    
    $all_results = @()
    
    foreach ($category in $Categories) {
        Write-Host "Processing category: $category"
        
        $category_results = Get-IoCs -BeginTime $StartTime -EndTime $EndTime -$category
        $all_results += $category_results
        
        # Memory cleanup between categories
        [System.GC]::Collect()
    }
    
    return $all_results
}
```

### Performance Monitoring

**Built-in Performance Tracking**:

```powershell
# Performance measurement wrapper
function Measure-IoCScan {
    param(
        [scriptblock]$ScanBlock,
        [string]$Description = "IoC Scan"
    )
    
    $start_time = Get-Date
    $start_memory = [System.GC]::GetTotalMemory($false) / 1MB
    
    Write-Host "Starting $Description..." -ForegroundColor Green
    Write-Host "Start time: $start_time"
    Write-Host "Start memory: $([math]::Round($start_memory, 2)) MB"
    
    # Execute the scan
    $results = & $ScanBlock
    
    $end_time = Get-Date
    $end_memory = [System.GC]::GetTotalMemory($false) / 1MB
    $duration = $end_time - $start_time
    $memory_delta = $end_memory - $start_memory
    
    Write-Host "`n=== Performance Results ===" -ForegroundColor Cyan
    Write-Host "Duration: $($duration.TotalSeconds) seconds"
    Write-Host "Memory change: $([math]::Round($memory_delta, 2)) MB"
    Write-Host "Events found: $($results.Count)"
    Write-Host "Events/second: $([math]::Round($results.Count / $duration.TotalSeconds, 2))"
    
    return $results
}

# Example usage
$results = Measure-IoCScan -Description "Quick Scan Test" -ScanBlock {
    Get-IoCs -Quick -BeginTime (Get-Date).AddHours(-24)
}
```

### Query Optimization

**Optimizing Time Windows**:
- **Small windows (< 1 hour)**: Use for real-time monitoring
- **Medium windows (1-24 hours)**: Standard for daily operations
- **Large windows (> 24 hours)**: Use chunked processing

**Category Selection Optimization**:
- **High-frequency categories**: PowerShell, ProcessCreation, NetworkConnections
- **Medium-frequency categories**: FailedLogins, RegistryModifications, ServiceSuspicious
- **Low-frequency categories**: CertificateInstallation, PrintSpoolerEvents

**System Resource Considerations**:
```powershell
# Check system resources before large scans
function Test-SystemReadiness {
    $memory = Get-WmiObject -Class Win32_OperatingSystem
    $available_mb = [math]::Round($memory.FreePhysicalMemory / 1024, 2)
    $cpu = Get-WmiObject Win32_Processor | Measure-Object -Property LoadPercentage -Average
    
    Write-Host "Available Memory: $available_mb MB"
    Write-Host "CPU Load: $([math]::Round($cpu.Average, 2))%"
    
    if ($available_mb -lt 1000) {
        Write-Warning "Low memory detected. Consider using chunked processing."
        return $false
    }
    
    if ($cpu.Average -gt 80) {
        Write-Warning "High CPU load detected. Consider scheduling scan for later."
        return $false
    }
    
    return $true
}

# Usage
if (Test-SystemReadiness) {
    $results = Get-IoCs -Full -BeginTime (Get-Date).AddDays(-7)
} else {
    Write-Host "Using optimized scan parameters due to resource constraints"
    $results = Get-IoCs -Quick -BeginTime (Get-Date).AddHours(-6)
}
```

## Integration Scenarios

### SIEM Integration

**Automated SIEM Feeding**:

```powershell
# SIEM integration script (run as scheduled task)
param(
    [string]$SIEMPath = "\\siem-server\ingestion",
    [int]$IntervalMinutes = 15,
    [string]$LogPath = "C:\IoC-Hunter\Logs"
)

function Send-ToSIEM {
    param(
        [string]$DestinationPath,
        [object[]]$IoCs,
        [string]$LogFile
    )
    
    try {
        if ($IoCs.Count -gt 0) {
            $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
            $filename = "ioc_hunter_$timestamp.json"
            
            # Export in SIEM format
            Export-IoCs -InputObject $IoCs -Format SIEM -Path "$DestinationPath\$filename"
            
            # Log successful transfer
            Add-Content -Path $LogFile -Value "$(Get-Date): Successfully sent $($IoCs.Count) events to SIEM ($filename)"
            
            return $true
        } else {
            Add-Content -Path $LogFile -Value "$(Get-Date): No new IoCs to send to SIEM"
            return $true
        }
    } catch {
        Add-Content -Path $LogFile -Value "$(Get-Date): ERROR sending to SIEM: $($_.Exception.Message)"
        return $false
    }
}

# Main SIEM integration loop
$log_file = "$LogPath\siem_integration.log"
$last_run_file = "$LogPath\last_run.txt"

# Determine scan window
if (Test-Path $last_run_file) {
    $last_run = Get-Content $last_run_file | Get-Date
    $scan_start = $last_run
} else {
    $scan_start = (Get-Date).AddMinutes(-$IntervalMinutes)
}

$scan_end = Get-Date

# Perform scan
$new_iocs = Get-IoCs -Quick -BeginTime $scan_start -EndTime $scan_end

# Send to SIEM if events found
if (Send-ToSIEM -DestinationPath $SIEMPath -IoCs $new_iocs -LogFile $log_file) {
    # Update last run timestamp
    $scan_end.ToString() | Out-File $last_run_file
}
```

**SIEM Query Integration**:

```powershell
# Query SIEM and correlate with IoC-Hunter data
function Correlate-WithSIEM {
    param(
        [object[]]$IoCResults,
        [string]$SIEMQueryAPI = "https://siem.company.com/api/query"
    )
    
    $correlated_events = @()
    
    foreach ($ioc in $IoCResults) {
        # Build SIEM query based on IoC properties
        $siem_query = @{
            'start_time' = $ioc.TimeCreated.AddMinutes(-30).ToString('yyyy-MM-ddTHH:mm:ss')
            'end_time' = $ioc.TimeCreated.AddMinutes(30).ToString('yyyy-MM-ddTHH:mm:ss')
            'user' = $ioc.User
            'computer' = $ioc.Computer
            'event_id' = $ioc.EventID
        }
        
        # Execute SIEM query (implement based on your SIEM API)
        $siem_results = Invoke-SIEMQuery -Query $siem_query -API $SIEMQueryAPI
        
        if ($siem_results.Count -gt 0) {
            $correlated_events += [PSCustomObject]@{
                'IoCEvent' = $ioc
                'SIEMEvents' = $siem_results
                'CorrelationCount' = $siem_results.Count
                'CorrelationType' = 'TimeUserComputer'
            }
        }
    }
    
    return $correlated_events
}
```

### Incident Response Platform Integration

**ServiceNow Integration**:

```powershell
# ServiceNow incident creation from IoC findings
function New-ServiceNowIncident {
    param(
        [object[]]$HighSeverityIoCs,
        [string]$ServiceNowURL,
        [pscredential]$Credential
    )
    
    if ($HighSeverityIoCs.Count -eq 0) { return }
    
    # Group IoCs by category for better incident organization
    $grouped_iocs = $HighSeverityIoCs | Group-Object Category
    
    foreach ($group in $grouped_iocs) {
        $incident_description = @"
IoC-Hunter has detected $($group.Count) high-severity events in category: $($group.Name)

Event Details:
$($group.Group | ForEach-Object { "- $($_.TimeCreated): $($_.Details)" } | Out-String)

Recommended Actions:
1. Isolate affected systems: $($group.Group.Computer | Sort-Object -Unique)
2. Review user accounts: $($group.Group.User | Sort-Object -Unique)
3. Escalate to security team for analysis
4. Preserve logs and evidence

Generated by IoC-Hunter at $(Get-Date)
"@

        $incident_data = @{
            'short_description' = "Security Alert: $($group.Name) - $($group.Count) events detected"
            'description' = $incident_description
            'category' = 'Security'
            'subcategory' = 'Intrusion'
            'priority' = '1'
            'impact' = '1'
            'urgency' = '1'
            'assignment_group' = 'Security Operations'
            'caller_id' = 'IoC-Hunter Automation'
        }
        
        # Create ServiceNow incident (implement based on your ServiceNow API)
        $response = Invoke-ServiceNowAPI -Action 'CreateIncident' -Data $incident_data -URL $ServiceNowURL -Credential $Credential
        
        Write-Host "Created ServiceNow incident $($response.IncidentNumber) for $($group.Name)"
    }
}
```

### Email Alerting

**Automated Email Alerts**:

```powershell
# Email alerting system
function Send-IoCAlertsEmail {
    param(
        [object[]]$AlertEvents,
        [string]$SMTPServer = "smtp.company.com",
        [string]$From = "ioc-hunter@company.com",
        [string[]]$To = @("security-team@company.com"),
        [pscredential]$Credential
    )
    
    if ($AlertEvents.Count -eq 0) { return }
    
    # Create summary statistics
    $stats = @{
        'Total' = $AlertEvents.Count
        'High' = ($AlertEvents | Where-Object Severity -eq 'High').Count
        'Medium' = ($AlertEvents | Where-Object Severity -eq 'Medium').Count
        'Low' = ($AlertEvents | Where-Object Severity -eq 'Low').Count
        'Categories' = ($AlertEvents | Group-Object Category).Count
        'Systems' = ($AlertEvents | Select-Object Computer -Unique).Count
        'TimeRange' = "$($AlertEvents.TimeCreated | Measure-Object -Minimum | Select-Object -ExpandProperty Minimum) to $($AlertEvents.TimeCreated | Measure-Object -Maximum | Select-Object -ExpandProperty Maximum)"
    }
    
    # Generate HTML email body
    $html_body = @"
<html>
<head><title>IoC-Hunter Security Alert</title></head>
<body>
<h2 style="color: red;">Security Alert - IoC Detection</h2>
<p><strong>Alert Time:</strong> $(Get-Date)</p>
<p><strong>Severity:</strong> $($stats.High) High, $($stats.Medium) Medium, $($stats.Low) Low</p>

<h3>Summary</h3>
<ul>
<li><strong>Total Events:</strong> $($stats.Total)</li>
<li><strong>Affected Systems:</strong> $($stats.Systems)</li>
<li><strong>Categories:</strong> $($stats.Categories)</li>
<li><strong>Time Range:</strong> $($stats.TimeRange)</li>
</ul>

<h3>Top Categories</h3>
<table border="1" style="border-collapse: collapse;">
<tr><th>Category</th><th>Count</th><th>Severity</th></tr>
$($AlertEvents | Group-Object Category | Sort-Object Count -Descending | Select-Object -First 10 | ForEach-Object {
    $severity = ($_.Group | Group-Object Severity | Sort-Object Count -Descending | Select-Object -First 1).Name
    "<tr><td>$($_.Name)</td><td>$($_.Count)</td><td>$severity</td></tr>"
})
</table>

<h3>Recent High-Severity Events</h3>
<table border="1" style="border-collapse: collapse;">
<tr><th>Time</th><th>Category</th><th>Computer</th><th>User</th><th>Details</th></tr>
$($AlertEvents | Where-Object Severity -eq 'High' | Sort-Object TimeCreated -Descending | Select-Object -First 5 | ForEach-Object {
    "<tr><td>$($_.TimeCreated)</td><td>$($_.Category)</td><td>$($_.Computer)</td><td>$($_.User)</td><td>$($_.Details)</td></tr>"
})
</table>

<p><strong>Action Required:</strong> Please review these events immediately and follow incident response procedures.</p>
<p><em>Generated by IoC-Hunter Security Monitoring</em></p>
</body>
</html>
"@

    # Send email
    try {
        Send-MailMessage -To $To -From $From -Subject "SECURITY ALERT: $($stats.Total) IoCs Detected ($($stats.High) High Severity)" -Body $html_body -BodyAsHtml -SmtpServer $SMTPServer -Credential $Credential
        Write-Host "Security alert email sent successfully to $($To -join ', ')"
    } catch {
        Write-Error "Failed to send security alert email: $($_.Exception.Message)"
    }
}
```

## Workflow Examples

### Daily Security Operations

**Standard Daily Workflow**:

```powershell
# Daily security operations script
param(
    [string]$OutputPath = "C:\Security\Daily",
    [string]$EmailRecipients = "security-team@company.com"
)

$today = Get-Date
$yesterday = $today.AddDays(-1)

Write-Host "=== Daily Security Assessment - $($today.ToShortDateString()) ===" -ForegroundColor Cyan

# 1. Quick overnight scan
Write-Host "Performing overnight quick scan..." -ForegroundColor Green
$overnight_scan = Get-IoCs -Quick -BeginTime $yesterday.AddHours(18) -EndTime $today.AddHours(8)

# 2. Save results
$daily_file = "$OutputPath\daily_scan_$($today.ToString('yyyyMMdd')).json"
Save-IoCs -Results $overnight_scan -Path $daily_file -Description "Daily overnight security scan"

# 3. Analyze results
$high_priority = Search-IoCs -InputObject $overnight_scan -Severity "High"
$categories = $overnight_scan | Group-Object Category | Sort-Object Count -Descending

Write-Host "`n=== Daily Summary ===" -ForegroundColor Yellow
Write-Host "Total events: $($overnight_scan.Count)"
Write-Host "High severity: $($high_priority.Count)"
Write-Host "Top categories: $($categories[0].Name) ($($categories[0].Count)), $($categories[1].Name) ($($categories[1].Count))"

# 4. Generate reports
if ($overnight_scan.Count -gt 0) {
    Export-IoCs -InputObject $overnight_scan -Format CSV -Path "$OutputPath\daily_report_$($today.ToString('yyyyMMdd')).csv"
    
    if ($high_priority.Count -gt 0) {
        Export-IoCs -InputObject $high_priority -Format Timeline -Path "$OutputPath\daily_high_priority_$($today.ToString('yyyyMMdd')).json"
        # Send alert email for high priority events
        Send-IoCAlertsEmail -AlertEvents $high_priority -To $EmailRecipients
    }
}

# 5. Weekly trending (if Sunday)
if ($today.DayOfWeek -eq 'Sunday') {
    Write-Host "`nPerforming weekly analysis..." -ForegroundColor Green
    $week_start = $today.AddDays(-7)
    $weekly_scan = Get-IoCs -Full -BeginTime $week_start -EndTime $today
    Save-IoCs -Results $weekly_scan -Path "$OutputPath\weekly_scan_$($today.ToString('yyyyMMdd')).json" -Description "Weekly comprehensive security scan"
    Export-IoCs -InputObject $weekly_scan -Format CSV -Path "$OutputPath\weekly_report_$($today.ToString('yyyyMMdd')).csv"
}

Write-Host "Daily security assessment complete." -ForegroundColor Green
```

### Incident Response Workflow

**Comprehensive Incident Response**:

```powershell
# Incident response workflow
param(
    [datetime]$IncidentTime,
    [string]$AffectedSystem,
    [string]$IncidentID,
    [string]$OutputPath = "C:\Incidents\$IncidentID"
)

if (-not (Test-Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force
}

Write-Host "=== Incident Response: $IncidentID ===" -ForegroundColor Red
Write-Host "Incident Time: $IncidentTime"
Write-Host "Affected System: $AffectedSystem"
Write-Host "Output Path: $OutputPath"

# Phase 1: Immediate assessment (± 2 hours from incident)
Write-Host "`nPhase 1: Immediate Assessment" -ForegroundColor Yellow
$immediate_window_start = $IncidentTime.AddHours(-2)
$immediate_window_end = $IncidentTime.AddHours(2)

$immediate_scan = Get-IoCs -Quick -BeginTime $immediate_window_start -EndTime $immediate_window_end
Save-IoCs -Results $immediate_scan -Path "$OutputPath\immediate_assessment.json" -Description "Immediate incident assessment - 4 hour window"

$immediate_high = Search-IoCs -InputObject $immediate_scan -Severity "High"
Write-Host "Immediate scan: $($immediate_scan.Count) events, $($immediate_high.Count) high severity"

# Phase 2: Extended analysis (± 24 hours from incident)
Write-Host "`nPhase 2: Extended Analysis" -ForegroundColor Yellow
$extended_window_start = $IncidentTime.AddDays(-1)
$extended_window_end = $IncidentTime.AddDays(1)

$extended_scan = Get-IoCs -Full -BeginTime $extended_window_start -EndTime $extended_window_end
Save-IoCs -Results $extended_scan -Path "$OutputPath\extended_analysis.json" -Description "Extended incident analysis - 48 hour window"

# Phase 3: Timeline reconstruction
Write-Host "`nPhase 3: Timeline Reconstruction" -ForegroundColor Yellow
$all_events = $extended_scan | Sort-Object TimeCreated
Export-IoCs -InputObject $all_events -Format Timeline -Path "$OutputPath\incident_timeline.json"

# Focus on affected system if specified
if ($AffectedSystem) {
    $system_events = Search-IoCs -InputObject $extended_scan -Computer $AffectedSystem
    if ($system_events.Count -gt 0) {
        Save-IoCs -Results $system_events -Path "$OutputPath\affected_system_$AffectedSystem.json" -Description "Events specific to affected system"
        Export-IoCs -InputObject $system_events -Format CSV -Path "$OutputPath\affected_system_$AffectedSystem.csv"
    }
}

# Phase 4: Category analysis
Write-Host "`nPhase 4: Category Analysis" -ForegroundColor Yellow
$categories = $extended_scan | Group-Object Category | Sort-Object Count -Descending

foreach ($category in $categories | Select-Object -First 5) {
    $category_events = Search-IoCs -InputObject $extended_scan -Category $category.Name
    Export-IoCs -InputObject $category_events -Format CSV -Path "$OutputPath\category_$($category.Name).csv"
    Write-Host "$($category.Name): $($category.Count) events"
}

# Phase 5: Generate executive summary
Write-Host "`nPhase 5: Executive Summary" -ForegroundColor Yellow
$summary = @{
    'IncidentID' = $IncidentID
    'IncidentTime' = $IncidentTime
    'AffectedSystem' = $AffectedSystem
    'AnalysisTime' = Get-Date
    'TotalEvents' = $extended_scan.Count
    'HighSeverityEvents' = ($extended_scan | Where-Object Severity -eq 'High').Count
    'CategoriesAffected' = $categories.Count
    'TimelineStart' = ($all_events | Select-Object -First 1).TimeCreated
    'TimelineEnd' = ($all_events | Select-Object -Last 1).TimeCreated
    'TopCategories' = $categories | Select-Object -First 5 | ForEach-Object { "$($_.Name) ($($_.Count))" }
}

$summary | ConvertTo-Json -Depth 3 | Out-File "$OutputPath\executive_summary.json"

Write-Host "`n=== Incident Analysis Complete ===" -ForegroundColor Green
Write-Host "Files generated in: $OutputPath"
Write-Host "Total events analyzed: $($extended_scan.Count)"
Write-Host "High severity events: $($summary.HighSeverityEvents)"
Write-Host "Categories affected: $($summary.CategoriesAffected)"
```

### Compliance Auditing Workflow

**Monthly Compliance Report**:

```powershell
# Monthly compliance auditing
param(
    [int]$Month = (Get-Date).Month,
    [int]$Year = (Get-Date).Year,
    [string]$OutputPath = "C:\Compliance\Reports",
    [string]$ComplianceFramework = "NIST"
)

$month_start = Get-Date -Year $Year -Month $Month -Day 1 -Hour 0 -Minute 0 -Second 0
$month_end = $month_start.AddMonths(1).AddSeconds(-1)

Write-Host "=== Monthly Compliance Report ===" -ForegroundColor Cyan
Write-Host "Period: $($month_start.ToString('MMMM yyyy'))"
Write-Host "Framework: $ComplianceFramework"

# Full month scan
Write-Host "`nPerforming comprehensive monthly scan..." -ForegroundColor Green
$monthly_scan = Get-IoCs -Full -BeginTime $month_start -EndTime $month_end

# Save raw data
$monthly_file = "$OutputPath\monthly_raw_$($Year)_$($Month.ToString('00')).json"
Save-IoCs -Results $monthly_scan -Path $monthly_file -Description "Monthly compliance scan - $($month_start.ToString('MMMM yyyy'))"

# Compliance analysis based on framework
switch ($ComplianceFramework) {
    "NIST" {
        $compliance_categories = @{
            'Identify' = @('AssetManagement', 'DataSecurity')
            'Protect' = @('AccessControl', 'DataSecurity', 'InfoProtection', 'Maintenance', 'ProtectiveTech')
            'Detect' = @('AnomaliesEvents', 'SecurityMonitoring', 'DetectionProcesses')
            'Respond' = @('ResponsePlanning', 'Communications', 'Analysis', 'Mitigation', 'Improvements')
            'Recover' = @('RecoveryPlanning', 'Improvements', 'Communications')
        }
        
        # Map IoC categories to NIST functions
        $nist_mapping = @{
            'FailedLogins' = 'Detect'
            'PowerShellSuspicious' = 'Detect'
            'ProcessCreation' = 'Detect'
            'LateralMovement' = 'Detect'
            'PrivilegeEscalation' = 'Detect'
            'AccountManagement' = 'Protect'
            'EventLogClearing' = 'Detect'
            'ServiceSuspicious' = 'Detect'
            'RegistryModifications' = 'Detect'
        }
        
        # Generate NIST compliance report
        foreach ($function in $compliance_categories.Keys) {
            $function_events = $monthly_scan | Where-Object { $nist_mapping[$_.Category] -eq $function }
            if ($function_events.Count -gt 0) {
                Export-IoCs -InputObject $function_events -Format CSV -Path "$OutputPath\NIST_$function`_$($Year)_$($Month.ToString('00')).csv"
            }
        }
    }
    
    "SOX" {
        # SOX-specific analysis focusing on access controls and data integrity
        $sox_categories = @('AccountManagement', 'PrivilegeEscalation', 'FileCreation', 'ShareAccess')
        foreach ($category in $sox_categories) {
            $sox_events = Search-IoCs -InputObject $monthly_scan -Category $category
            if ($sox_events.Count -gt 0) {
                Export-IoCs -InputObject $sox_events -Format CSV -Path "$OutputPath\SOX_$category`_$($Year)_$($Month.ToString('00')).csv"
            }
        }
    }
    
    "PCI-DSS" {
        # PCI-DSS specific analysis focusing on cardholder data environment
        $pci_categories = @('NetworkConnections', 'FirewallChanges', 'AccountManagement', 'FileCreation')
        foreach ($category in $pci_categories) {
            $pci_events = Search-IoCs -InputObject $monthly_scan -Category $category
            if ($pci_events.Count -gt 0) {
                Export-IoCs -InputObject $pci_events -Format CSV -Path "$OutputPath\PCI_$category`_$($Year)_$($Month.ToString('00')).csv"
            }
        }
    }
}

# Generate summary statistics
$stats = @{
    'Period' = $month_start.ToString('MMMM yyyy')
    'Framework' = $ComplianceFramework
    'TotalEvents' = $monthly_scan.Count
    'HighSeverity' = ($monthly_scan | Where-Object Severity -eq 'High').Count
    'MediumSeverity' = ($monthly_scan | Where-Object Severity -eq 'Medium').Count
    'LowSeverity' = ($monthly_scan | Where-Object Severity -eq 'Low').Count
    'TopCategories' = ($monthly_scan | Group-Object Category | Sort-Object Count -Descending | Select-Object -First 5)
    'DailyCounts' = (1..31 | ForEach-Object {
        $day_start = $month_start.AddDays($_ - 1)
        $day_end = $day_start.AddDays(1).AddSeconds(-1)
        $day_events = $monthly_scan | Where-Object { $_.TimeCreated -ge $day_start -and $_.TimeCreated -le $day_end }
        [PSCustomObject]@{ Day = $_; Events = $day_events.Count }
    })
}

$stats | ConvertTo-Json -Depth 3 | Out-File "$OutputPath\compliance_summary_$($Year)_$($Month.ToString('00')).json"

Write-Host "`nCompliance report generated successfully" -ForegroundColor Green
Write-Host "Total events: $($stats.TotalEvents)"
Write-Host "High severity: $($stats.HighSeverity)"
Write-Host "Files saved to: $OutputPath"
```

## Troubleshooting

### Common Issues and Solutions

#### Issue: "Access Denied" Errors

**Symptoms**:
- Error messages about insufficient privileges
- Cannot access Windows Event Logs
- Functions fail with security-related errors

**Solutions**:
1. **Run as Administrator**: Most common solution
   ```powershell
   # Right-click PowerShell and "Run as Administrator"
   # Then import and use IoC-Hunter normally
   ```

2. **Check User Rights**:
   ```powershell
   # Verify current user has "Log on as a service" and "Generate security audits" rights
   whoami /priv
   ```

3. **Enable Event Log Access**:
   ```powershell
   # Ensure event logs are accessible
   Get-EventLog -List
   ```

#### Issue: "Module not found" Errors

**Symptoms**:
- Cannot import IoC-Hunter module
- Functions not recognized
- Module path errors

**Solutions**:
1. **Verify Module Path**:
   ```powershell
   # Check current directory and module location
   Get-Location
   Get-ChildItem -Path . -Name "IoC-Hunter*"
   ```

2. **Use Full Path Import**:
   ```powershell
   # Import using full path
   Import-Module "C:\Full\Path\To\IoC-Hunter\IoC-Hunter.psm1"
   ```

3. **Check Module Structure**:
   ```powershell
   # Verify all required files exist
   Get-ChildItem -Path ".\IoC-Hunter" -Recurse
   ```

#### Issue: Performance Problems

**Symptoms**:
- Scans taking excessive time
- High memory usage
- System becomes unresponsive

**Solutions**:
1. **Reduce Time Window**:
   ```powershell
   # Instead of large windows, use smaller chunks
   Get-IoCs -Quick -BeginTime (Get-Date).AddHours(-6)  # Better than -AddDays(-30)
   ```

2. **Use Quick Mode**:
   ```powershell
   # Use Quick instead of Full for routine monitoring
   Get-IoCs -Quick  # Instead of Get-IoCs -Full
   ```

3. **Category Selection**:
   ```powershell
   # Target specific categories instead of full scans
   Get-IoCs -PowerShellSuspicious -FailedLogins -BeginTime (Get-Date).AddHours(-24)
   ```

4. **Memory Management**:
   ```powershell
   # Force garbage collection for large datasets
   [System.GC]::Collect()
   ```

#### Issue: "Event log unavailable" Warnings

**Symptoms**:
- Warnings about missing event logs
- Categories returning 0 results unexpectedly
- Incomplete scan results

**Solutions**:
1. **Check Event Log Services**:
   ```powershell
   Get-Service -Name "EventLog"
   Get-Service -Name "Windows Event Log"
   ```

2. **Verify Log Existence**:
   ```powershell
   Get-WinEvent -ListLog * | Where-Object RecordCount -gt 0
   ```

3. **Enable Required Logs**:
   ```powershell
   # Enable security auditing if disabled
   auditpol /get /category:*
   ```

#### Issue: PowerShell Execution Policy

**Symptoms**:
- Cannot run scripts
- "Execution policy" error messages
- Scripts blocked from running

**Solutions**:
1. **Check Current Policy**:
   ```powershell
   Get-ExecutionPolicy
   ```

2. **Set Execution Policy**:
   ```powershell
   # For current user (recommended)
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   
   # For local machine (requires admin)
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine
   ```

3. **Bypass Policy Temporarily**:
   ```powershell
   PowerShell -ExecutionPolicy Bypass -File ".\IoC-Hunter\Tests\Run-AllTests.ps1"
   ```

### Diagnostic Commands

**System Health Check**:
```powershell
# Comprehensive system check for IoC-Hunter readiness
function Test-IoCHunterReadiness {
    Write-Host "=== IoC-Hunter Readiness Check ===" -ForegroundColor Cyan
    
    # Check PowerShell version
    $ps_version = $PSVersionTable.PSVersion
    if ($ps_version.Major -ge 5) {
        Write-Host "[PASS] PowerShell version: $ps_version" -ForegroundColor Green
    } else {
        Write-Host "[FAIL] PowerShell version: $ps_version (5.1+ required)" -ForegroundColor Red
    }
    
    # Check admin privileges
    $is_admin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    if ($is_admin) {
        Write-Host "[PASS] Running as Administrator" -ForegroundColor Green
    } else {
        Write-Host "[WARN] Not running as Administrator - some features may be limited" -ForegroundColor Yellow
    }
    
    # Check execution policy
    $exec_policy = Get-ExecutionPolicy
    if ($exec_policy -in @('RemoteSigned', 'Unrestricted', 'Bypass')) {
        Write-Host "[PASS] Execution Policy: $exec_policy" -ForegroundColor Green
    } else {
        Write-Host "[WARN] Execution Policy: $exec_policy - may prevent script execution" -ForegroundColor Yellow
    }
    
    # Check available memory
    $memory = Get-WmiObject -Class Win32_OperatingSystem
    $available_gb = [math]::Round($memory.FreePhysicalMemory / 1024 / 1024, 2)
    if ($available_gb -ge 2) {
        Write-Host "[PASS] Available Memory: $available_gb GB" -ForegroundColor Green
    } else {
        Write-Host "[WARN] Available Memory: $available_gb GB - consider freeing memory for large scans" -ForegroundColor Yellow
    }
    
    # Check event log accessibility
    try {
        $security_log = Get-WinEvent -ListLog Security -ErrorAction Stop
        Write-Host "[PASS] Security Event Log accessible ($($security_log.RecordCount) records)" -ForegroundColor Green
    } catch {
        Write-Host "[FAIL] Cannot access Security Event Log: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    # Check module files
    if (Test-Path ".\IoC-Hunter\IoC-Hunter.psm1") {
        Write-Host "[PASS] IoC-Hunter module files found" -ForegroundColor Green
    } else {
        Write-Host "[FAIL] IoC-Hunter module files not found in current directory" -ForegroundColor Red
    }
    
    Write-Host "`nReadiness check complete." -ForegroundColor Cyan
}

# Run the readiness check
Test-IoCHunterReadiness
```

**Performance Diagnostics**:
```powershell
# Performance diagnostic function
function Test-IoCPerformance {
    param(
        [int]$TestMinutes = 5
    )
    
    Write-Host "=== IoC-Hunter Performance Test ===" -ForegroundColor Cyan
    Write-Host "Test window: $TestMinutes minutes"
    
    # Baseline measurement
    $start_memory = [System.GC]::GetTotalMemory($false) / 1MB
    $start_time = Get-Date
    
    # Quick scan test
    Write-Host "`nTesting Quick Scan..." -ForegroundColor Yellow
    $quick_start = Get-Date
    $quick_results = Get-IoCs -Quick -BeginTime (Get-Date).AddMinutes(-$TestMinutes)
    $quick_duration = (Get-Date) - $quick_start
    $quick_memory = [System.GC]::GetTotalMemory($false) / 1MB
    
    Write-Host "Quick Scan: $($quick_results.Count) events in $([math]::Round($quick_duration.TotalSeconds, 2)) seconds"
    Write-Host "Memory usage: $([math]::Round($quick_memory - $start_memory, 2)) MB"
    
    # Performance cleanup
    [System.GC]::Collect()
    Start-Sleep -Seconds 2
    
    # Category performance test
    Write-Host "`nTesting Individual Categories..." -ForegroundColor Yellow
    $categories = @('FailedLogins', 'PowerShellSuspicious', 'ProcessCreation')
    
    foreach ($category in $categories) {
        $cat_start = Get-Date
        $cat_results = Get-IoCs -BeginTime (Get-Date).AddMinutes(-$TestMinutes) -$category
        $cat_duration = (Get-Date) - $cat_start
        
        Write-Host "$category`: $($cat_results.Count) events in $([math]::Round($cat_duration.TotalSeconds, 2)) seconds"
    }
    
    Write-Host "`nPerformance test complete." -ForegroundColor Cyan
}

# Run performance test
Test-IoCPerformance -TestMinutes 10
```

### Error Message Reference

**Common Error Messages and Solutions**:

| Error Message | Cause | Solution |
|---------------|-------|----------|
| "Access to the path is denied" | Insufficient file system permissions | Run as Administrator, check file/folder permissions |
| "Cannot access the Security event log" | Insufficient event log permissions | Run as Administrator, verify event log service |
| "The term 'Get-IoCs' is not recognized" | Module not imported correctly | Verify module path, re-import module |
| "Cannot convert null array to type" | Invalid input parameters | Check parameter values, ensure valid time ranges |
| "Out of memory exception" | Insufficient system memory | Reduce time window, use Quick mode, restart PowerShell |
| "The operation has timed out" | Event log query timeout | Reduce time window, check system performance |
| "Invalid JSON primitive" | File format corruption | Use valid saved files, re-scan if necessary |
| "Path does not exist" | Invalid file path | Check file/directory existence, use full paths |

## Best Practices

### Security Best Practices

1. **Privilege Management**:
   - Always run IoC-Hunter with minimum required privileges
   - Use dedicated service accounts for automated scanning
   - Regularly review and audit access permissions
   - Implement proper credential storage for automation

2. **Data Protection**:
   - Encrypt saved IoC result files containing sensitive data
   - Implement secure file transfer for SIEM integration
   - Use appropriate retention policies for saved scans
   - Sanitize data before sharing with external parties

3. **Monitoring and Alerting**:
   - Implement automated monitoring for critical security events
   - Set up escalation procedures for high-severity findings
   - Monitor IoC-Hunter itself for proper operation
   - Maintain audit logs of all scanning activities

### Operational Best Practices

1. **Scanning Strategy**:
   ```powershell
   # Recommended scanning schedule
   # Real-time monitoring: Every 5-15 minutes (Quick mode)
   # Daily operations: Once daily (Quick mode, 24-hour window)
   # Weekly analysis: Once weekly (Full mode, 7-day window)
   # Monthly compliance: Once monthly (Full mode, 30-day window)
   ```

2. **Performance Optimization**:
   - Start with smaller time windows and expand as needed
   - Use Quick mode for routine monitoring
   - Reserve Full mode for investigations and compliance
   - Monitor system resources during large scans
   - Implement chunked processing for very large datasets

3. **Result Management**:
   ```powershell
   # Implement consistent naming conventions
   $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
   $filename = "ioc_scan_${env:COMPUTERNAME}_$timestamp.json"
   
   # Use descriptive metadata
   Save-IoCs -Results $results -Path $filename -Description "Daily security scan - $env:COMPUTERNAME"
   ```

4. **Integration Planning**:
   - Design SIEM integration for automated feeding
   - Implement proper error handling and retry logic
   - Plan for scalability across multiple systems
   - Document integration procedures and dependencies

### Development and Testing Best Practices

1. **Test Environment**:
   - Maintain separate testing environment for IoC-Hunter development
   - Test all changes against known dataset before production
   - Validate performance impact of configuration changes
   - Document all customizations and modifications

2. **Change Management**:
   - Version control all custom scripts and configurations
   - Test module updates in non-production environment first
   - Maintain rollback procedures for failed updates
   - Document all changes and their business justification

3. **Quality Assurance**:
   ```powershell
   # Regular validation testing
   .\Tests\Run-AllTests.ps1  # Run before production deployment
   
   # Performance baseline maintenance
   Measure-IoCScan { Get-IoCs -Quick -BeginTime (Get-Date).AddHours(-1) }
   ```

## FAQ

### General Questions

**Q: What is the difference between Quick and Full scan modes?**
A: Quick mode scans 18 critical security categories optimized for speed (2-4 minutes), while Full mode scans all 26 categories for comprehensive coverage (5-15 minutes). Quick mode is ideal for routine monitoring, Full mode for thorough investigations.

**Q: How much system resources does IoC-Hunter require?**
A: Memory usage ranges from 50-100 MB baseline to 200-500 MB for large scans. CPU usage is typically low except during active scanning. Administrator privileges are required for event log access.

**Q: Can IoC-Hunter be used on domain controllers?**
A: Yes, but exercise caution on production domain controllers. Test thoroughly in development first and consider performance impact during business hours.

**Q: Does IoC-Hunter work with Windows Event Forwarding (WEF)?**
A: Yes, IoC-Hunter analyzes local Windows Event Logs, so it works with WEF if events are forwarded to the local system. For centralized analysis, deploy on WEF collector servers.

### Technical Questions

**Q: How do I analyze events from remote systems?**
A: Use PowerShell remoting to execute IoC-Hunter on remote systems:
```powershell
$session = New-PSSession -ComputerName "RemoteServer"
$results = Invoke-Command -Session $session -ScriptBlock {
    Import-Module C:\Tools\IoC-Hunter
    Get-IoCs -Quick -BeginTime (Get-Date).AddHours(-24)
}
```

**Q: Can I add custom IoC categories?**
A: Currently, IoC-Hunter includes 26 predefined categories based on common attack vectors. Custom categories require module modification. Consider using targeted scans with existing categories that match your specific needs.

**Q: How do I optimize performance for large time windows?**
A: Use chunked processing for windows larger than 7 days:
```powershell
# Process in 6-hour chunks for month-long analysis
$results = Get-IoCs-Chunked -StartTime (Get-Date).AddDays(-30) -EndTime (Get-Date) -ChunkHours 6
```

**Q: What event logs does IoC-Hunter require?**
A: IoC-Hunter primarily uses Security, System, Application, and Windows PowerShell logs. Additional logs (Sysmon, WMI, etc.) enhance detection but aren't required. The module adapts based on available logs.

### Integration Questions

**Q: How do I integrate IoC-Hunter with my SIEM?**
A: Use the SIEM export format and automated feeding:
```powershell
# Export in SIEM format
Export-IoCs -InputObject $results -Format SIEM -Path "siem_feed.json"

# Automated SIEM integration (scheduled task)
Get-IoCs -Quick -BeginTime (Get-Date).AddMinutes(-15) | 
Export-IoCs -Format SIEM -Path "\\siem-server\ingestion\ioc_$(Get-Date -f 'yyyyMMdd_HHmmss').json"
```

**Q: Can IoC-Hunter replace my existing security tools?**
A: IoC-Hunter complements existing security tools by providing Windows-specific event log analysis. It's designed to work alongside EDR, SIEM, and other security solutions, not replace them.

**Q: How do I handle false positives?**
A: Use Search-IoCs to filter results, implement severity-based filtering, and develop custom analysis scripts:
```powershell
# Filter out known false positives
$filtered_results = Search-IoCs -InputObject $results -Severity "High" | 
    Where-Object { $_.User -notmatch "ServiceAccount|BackupUser" }
```

### Troubleshooting Questions

**Q: Why am I getting "Access Denied" errors?**
A: Most commonly, this indicates insufficient privileges. Run PowerShell as Administrator. Also verify that Windows Event Log service is running and accessible.

**Q: IoC-Hunter runs slowly on my system. How can I improve performance?**
A: Try these optimizations:
1. Use Quick mode instead of Full mode
2. Reduce time window size
3. Ensure adequate system memory (4GB+ recommended)
4. Run during off-peak hours for large scans
5. Use category-specific scans instead of comprehensive scans

**Q: Some categories always return 0 results. Is this normal?**
A: Yes, this is normal on systems with limited activity or disabled logging. For example, Print Spooler events are rare on most systems. The module adapts to available data.

**Q: How do I know if IoC-Hunter is working correctly?**
A: Run the test suite to validate functionality:
```powershell
cd .\Tests\
.\Run-AllTests.ps1
```
All tests should pass. PowerShell categories typically show results due to IoC-Hunter's own execution.

### Best Practices Questions

**Q: How often should I run IoC-Hunter scans?**
A: Recommended schedule:
- **Real-time monitoring**: Every 5-15 minutes (Quick mode)
- **Daily operations**: Once daily (Quick mode, 24-hour window)  
- **Weekly analysis**: Once weekly (Full mode, 7-day window)
- **Incident response**: As needed (Full mode, targeted time windows)

**Q: What should I do with high-severity findings?**
A: Follow your incident response procedures:
1. Isolate affected systems if necessary
2. Preserve evidence (save IoC results)
3. Escalate to security team
4. Perform detailed analysis with Full mode
5. Document findings and remediation actions

**Q: How long should I retain IoC-Hunter results?**
A: Retention depends on compliance requirements and organizational policies. Common approaches:
- **Operational data**: 30-90 days for trending and analysis
- **Incident data**: 1-7 years for compliance and legal requirements
- **Compliance scans**: Per regulatory requirements (often 3-7 years)

---

This comprehensive usage guide provides everything needed to effectively deploy and operate IoC-Hunter in production environments. For additional support or advanced use cases, refer to the test documentation and module source code for detailed implementation examples.
