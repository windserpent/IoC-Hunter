<#
.SYNOPSIS
    Scans Windows Event Logs for Indicators of Compromise (IoCs) and potential security threats.

.DESCRIPTION
    Get-IoCs is a comprehensive security scanning tool that analyzes Windows Event Logs to identify potential
    indicators of compromise and suspicious activities. It supports both targeted category scanning and 
    predefined scan modes (Quick and Full) for efficient threat detection.
    
    The function examines 26 different security categories including failed logins, suspicious PowerShell 
    activity, process injection, lateral movement, and many other attack vectors. Results include detailed
    forensic data and can be exported for further analysis.

.PARAMETER FailedLogins
    Scans for failed authentication attempts (Event ID 4625). Identifies potential brute force attacks
    and unauthorized access attempts.

.PARAMETER PowerShellSuspicious
    Detects suspicious PowerShell activity including script block logging and engine state changes.
    Identifies potential malicious PowerShell usage and obfuscated scripts.

.PARAMETER ProcessCreation
    Monitors process creation events (Event ID 4688) for suspicious executables, command lines,
    and process spawning patterns.

.PARAMETER NetworkConnections
    Analyzes network connection events to identify suspicious outbound connections and potential
    command & control communication.

.PARAMETER PrivilegeEscalation
    Detects privilege escalation attempts and successful elevation of privileges that could indicate
    compromised accounts or exploitation.

.PARAMETER ServiceEvents
    Monitors Windows service creation, modification, and execution for signs of persistence mechanisms
    and malicious service installation.

.PARAMETER ScheduledTasks
    Scans for suspicious scheduled task creation and execution, a common persistence technique
    used by attackers.

.PARAMETER AccountManagement
    Tracks user account creation, modification, and group membership changes that could indicate
    unauthorized administrative access.

.PARAMETER EventLogClearing
    Detects attempts to clear event logs (Event ID 1102), often used by attackers to cover their tracks.

.PARAMETER RegistryModifications
    Monitors registry changes in critical areas that could indicate persistence mechanisms, 
    configuration tampering, or malware installation.

.PARAMETER WindowsDefender
    Analyzes Windows Defender events including threat detections, exclusion changes, and 
    real-time protection modifications.

.PARAMETER LateralMovement
    Identifies successful logons and authentication events that could indicate lateral movement
    through the network.

.PARAMETER WMIActivity
    Detects suspicious Windows Management Instrumentation (WMI) activity often used for
    persistence and lateral movement.

.PARAMETER DriverLoading
    Monitors driver loading events from suspicious locations, potential rootkit installation,
    and unsigned driver usage.

.PARAMETER FileCreation
    Scans for file creation in suspicious locations including system directories, startup folders,
    and web server directories.

.PARAMETER RDPActivity
    Tracks Remote Desktop Protocol connections and authentication events for unauthorized
    remote access attempts.

.PARAMETER CredentialDumping
    Detects potential credential dumping activities and suspicious access to credential stores
    like LSASS process.

.PARAMETER FirewallChanges
    Monitors Windows Firewall rule modifications that could indicate attempts to open
    unauthorized network access.

.PARAMETER ShareAccess
    Analyzes file share access patterns for suspicious activity and potential data exfiltration
    or lateral movement via network shares.

.PARAMETER ProcessInjection
    Detects process injection techniques including DLL injection, process hollowing, and other
    code injection methods used by malware.

.PARAMETER CertificateInstallation
    Monitors certificate installation events that could indicate man-in-the-middle attacks
    or SSL/TLS interception.

.PARAMETER DNSEvents
    Analyzes DNS query patterns for suspicious domains, DNS tunneling, and command & control
    communication attempts.

.PARAMETER ApplicationCrashes
    Tracks application crashes that could indicate exploitation attempts or system instability
    caused by malicious activity.

.PARAMETER BootStartupEvents
    Monitors system boot and startup events for persistence mechanisms and startup modifications.

.PARAMETER PrintSpoolerEvents
    Detects suspicious print spooler activity including potential PrintNightmare exploitation
    and related vulnerabilities.

.PARAMETER SoftwareInstallation
    Tracks software installation events for unauthorized application installation and
    potential malware deployment.

.PARAMETER Quick
    Enables Quick scan mode covering 18 critical security categories optimized for speed.
    Estimated execution time: 2-4 minutes. Includes high-confidence indicators and common attack vectors.
    Cannot be combined with -Full parameter.

.PARAMETER Full
    Enables Full scan mode covering all 26 security categories for comprehensive threat detection.
    Estimated execution time: 5-15 minutes. Provides complete coverage of all available IoC categories.
    Cannot be combined with -Quick parameter.

.PARAMETER BeginTime
    Start time for the event log scan. Defaults to 20 minutes ago.
    Must be earlier than EndTime.

.PARAMETER EndTime
    End time for the event log scan. Defaults to current time.
    Must be later than BeginTime.

.PARAMETER Table
    Returns results formatted as a table for easy viewing. When not specified,
    returns full objects with all properties.

.PARAMETER Help
    Displays this help information.

.EXAMPLE
    Get-IoCs -Quick
    
    Performs a quick scan of the last 20 minutes using 18 critical security categories.
    Optimized for rapid threat detection with 2-4 minute execution time.

.EXAMPLE
    Get-IoCs -Full -BeginTime (Get-Date).AddHours(-24) -EndTime (Get-Date)
    
    Performs a comprehensive scan of the last 24 hours covering all 26 security categories.
    Provides complete threat coverage with 5-15 minute execution time.

.EXAMPLE
    Get-IoCs -FailedLogins -PowerShellSuspicious -BeginTime (Get-Date).AddHours(-6)
    
    Scans for failed login attempts and suspicious PowerShell activity in the last 6 hours.
    Targeted scan focusing on specific threat categories.

.EXAMPLE
    $results = Get-IoCs -Quick
    $results | Where-Object Severity -eq "High" | Format-Table
    
    Performs a quick scan and filters results to show only high-severity threats in table format.

.EXAMPLE
    Get-IoCs -Full -BeginTime "2025-10-23 09:00:00" -EndTime "2025-10-23 17:00:00" -Table
    
    Scans business hours (9 AM to 5 PM) on October 23rd, 2025, using full scan mode
    and displays results in table format.

.EXAMPLE
    $iocs = Get-IoCs -ProcessCreation -RegistryModifications -NetworkConnections
    $iocs | Save-IoCs -Path "security_scan.json" -Description "Targeted security scan"
    
    Performs targeted scanning for specific categories and saves results for later analysis.

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    System.Object[]
    Returns an array of custom objects containing IoC details including:
    - TimeCreated: When the event occurred
    - EventID: Windows Event ID
    - Category: IoC category name  
    - Severity: High, Medium, or Low
    - User: Associated user account
    - Source: Event source
    - Target: Target of the activity
    - Details: Detailed description
    - Computer: Machine name
    - LogName: Source event log
    - RecordId: Event record ID
    - EventXML: Full event XML
    - ForensicData: Additional forensic information

.NOTES
    Author: IoC-Hunter Module
    Version: 1.0.0
    
    Requirements:
    - Windows PowerShell 5.1 or PowerShell Core 6.0+
    - Administrative privileges recommended for full event log access
    - Some categories require specific logs to be enabled (e.g., DNS Client Events)
    
    Performance Notes:
    - Quick scan: ~30-70% faster than Full scan, covers most common threats
    - Full scan: Comprehensive coverage, longer execution time
    - Memory usage scales with time window size and result count
    - Consider smaller time windows for better performance
    
    Security Categories:
    Quick Scan (18 categories): FailedLogins, PowerShellSuspicious, ProcessCreation, 
    LateralMovement, CredentialDumping, PrivilegeEscalation, EventLogClearing, 
    AccountManagement, ProcessInjection, RDPActivity, RegistryModifications (Quick), 
    ShareAccess (Quick), ServiceEvents, WMIActivity, WindowsDefender, ScheduledTasks, 
    DNSEvents, FirewallChanges
    
    Full Scan (26 categories): All Quick scan categories plus NetworkConnections, 
    DriverLoading, FileCreation, CertificateInstallation, ApplicationCrashes, 
    BootStartupEvents, PrintSpoolerEvents, SoftwareInstallation, and full versions 
    of RegistryModifications and ShareAccess

.LINK
    Save-IoCs
.LINK
    Import-IoCs
.LINK
    Export-IoCs
.LINK
    Search-IoCs
#>

function Get-IoCs {
    [CmdletBinding()]
    param(
        # Individual category switches
        [switch]$FailedLogins,
        [switch]$PowerShellSuspicious,
        [switch]$ProcessCreation,
        [switch]$NetworkConnections,
        [switch]$PrivilegeEscalation,
        [switch]$ServiceEvents,
        [switch]$ScheduledTasks,
        [switch]$AccountManagement,
        [switch]$EventLogClearing,
        [switch]$RegistryModifications,
        [switch]$WindowsDefender,
        [switch]$LateralMovement,
        [switch]$WMIActivity,
        [switch]$DriverLoading,
        [switch]$FileCreation,
        [switch]$RDPActivity,
        [switch]$CredentialDumping,
        [switch]$FirewallChanges,
        [switch]$ShareAccess,
        [switch]$ProcessInjection,
        [switch]$CertificateInstallation,
        [switch]$DNSEvents,
        [switch]$ApplicationCrashes,
        [switch]$BootStartupEvents,
        [switch]$PrintSpoolerEvents,
        [switch]$SoftwareInstallation,
        
        # Enhanced scan modes
        [switch]$Quick,    # 18 critical categories optimized for speed
        [switch]$Full,     # All 26 categories comprehensive scan
        
        [DateTime]$BeginTime = (Get-Date).AddMinutes(-20),
        [DateTime]$EndTime = (Get-Date),
        [switch]$Table,
        [switch]$Help
    )
    
    if ($Help) {
        Get-Help Get-IoCs -Full
        return
    }
    
    # Time range validation
    if ($BeginTime -gt $EndTime) {
        Write-Error "Scan Begin Time cannot be greater than the End Time."
        return
    }

    # Parameter validation
    if ($Quick -and $Full) {
        Write-Error "Cannot specify both -Quick and -Full parameters. Choose one scan mode."
        return
    }
    
    # Handle Quick scan mode - enable 18 critical categories
    if ($Quick) {
        # Tier 1: Active Attack Detection (4 categories)
        $PowerShellSuspicious = $FailedLogins = $ProcessCreation = $LateralMovement = $true
        
        # Tier 2: High-Impact Indicators (8 categories)
        $CredentialDumping = $PrivilegeEscalation = $EventLogClearing = $AccountManagement = $true
        $ProcessInjection = $RDPActivity = $RegistryModifications = $ShareAccess = $true
        
        # Tier 3: Communication/Persistence (6 categories)  
        $ServiceEvents = $WMIActivity = $WindowsDefender = $ScheduledTasks = $true
        $DNSEvents = $FirewallChanges = $true
        
        Write-Host "=== IoC-Hunter QUICK SCAN ===" -ForegroundColor Cyan
        Write-Host "Scanning 18 critical categories for rapid threat detection" -ForegroundColor Gray
        Write-Host "Estimated time: 2-4 minutes" -ForegroundColor Gray
    }
    
    # Handle Full scan mode - enable all 26 categories
    if ($Full) {
        $FailedLogins = $PowerShellSuspicious = $ProcessCreation = $NetworkConnections = $true
        $PrivilegeEscalation = $ServiceEvents = $ScheduledTasks = $AccountManagement = $true
        $EventLogClearing = $RegistryModifications = $WindowsDefender = $LateralMovement = $true
        $WMIActivity = $DriverLoading = $FileCreation = $RDPActivity = $true
        $CredentialDumping = $FirewallChanges = $ShareAccess = $ProcessInjection = $true
        $CertificateInstallation = $DNSEvents = $ApplicationCrashes = $BootStartupEvents = $true
        $PrintSpoolerEvents = $SoftwareInstallation = $true
        
        Write-Host "=== IoC-Hunter FULL SCAN ===" -ForegroundColor Cyan
        Write-Host "Comprehensive scan of all 26 categories" -ForegroundColor Gray
        Write-Host "Estimated time: 5-15 minutes" -ForegroundColor Gray
    }
    
    # If no scan mode specified, individual categories only
    if (-not $Quick -and -not $Full) {
        Write-Host "=== IoC-Hunter TARGETED SCAN ===" -ForegroundColor Cyan
        Write-Host "Scanning selected categories only" -ForegroundColor Gray
    }
    
    # Calculate time range
    $TimeSpan = $EndTime - $BeginTime
    $TotalMinutes = [math]::Round($TimeSpan.TotalMinutes, 1)
    
    $Results = @()
    $ScanStartTime = Get-Date
    $CategoryCount = 0
    $TotalCategories = 0
    
    # Count enabled categories for progress tracking
    $EnabledCategories = @()
    if ($FailedLogins) { $EnabledCategories += "FailedLogins" }
    if ($PowerShellSuspicious) { $EnabledCategories += "PowerShellSuspicious" }
    if ($ProcessCreation) { $EnabledCategories += "ProcessCreation" }
    if ($LateralMovement) { $EnabledCategories += "LateralMovement" }
    if ($CredentialDumping) { $EnabledCategories += "CredentialDumping" }
    if ($ServiceEvents) { $EnabledCategories += "ServiceEvents" }
    if ($ScheduledTasks) { $EnabledCategories += "ScheduledTasks" }
    if ($RegistryModifications) { $EnabledCategories += "RegistryModifications" }
    if ($WindowsDefender) { $EnabledCategories += "WindowsDefender" }
    if ($RDPActivity) { $EnabledCategories += "RDPActivity" }
    if ($FileCreation) { $EnabledCategories += "FileCreation" }
    if ($WMIActivity) { $EnabledCategories += "WMIActivity" }
    if ($AccountManagement) { $EnabledCategories += "AccountManagement" }
    if ($EventLogClearing) { $EnabledCategories += "EventLogClearing" }
    if ($PrivilegeEscalation) { $EnabledCategories += "PrivilegeEscalation" }
    if ($ShareAccess) { $EnabledCategories += "ShareAccess" }
    if ($FirewallChanges) { $EnabledCategories += "FirewallChanges" }
    if ($DNSEvents) { $EnabledCategories += "DNSEvents" }
    if ($ProcessInjection) { $EnabledCategories += "ProcessInjection" }
    if ($CertificateInstallation) { $EnabledCategories += "CertificateInstallation" }
    if ($NetworkConnections) { $EnabledCategories += "NetworkConnections" }
    if ($ApplicationCrashes) { $EnabledCategories += "ApplicationCrashes" }
    if ($BootStartupEvents) { $EnabledCategories += "BootStartupEvents" }
    if ($PrintSpoolerEvents) { $EnabledCategories += "PrintSpoolerEvents" }
    if ($DriverLoading) { $EnabledCategories += "DriverLoading" }
    if ($SoftwareInstallation) { $EnabledCategories += "SoftwareInstallation" }
    
    $TotalCategories = $EnabledCategories.Count
    
    Write-Host ""
    Write-Host "Time Range: $BeginTime to $EndTime" -ForegroundColor Gray
    Write-Host "Duration: $TotalMinutes minutes" -ForegroundColor Gray
    Write-Host "Categories to scan: $TotalCategories" -ForegroundColor Gray
    Write-Host ""
    
    # Failed Login Attempts
    if ($FailedLogins) {
        $CategoryCount++
        $CategoryStartTime = Get-Date
        Write-Host "[$CategoryCount/$TotalCategories] Checking for Failed Login Attempts..." -ForegroundColor Yellow
        try {
            $FailedLoginEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'Security'
                ID = 4625
                StartTime = $BeginTime
                EndTime = $EndTime
            } -ErrorAction SilentlyContinue | ForEach-Object {
                
                $ForensicData = New-ForensicData -EventRecord $_
                
                [PSCustomObject]@{
                    TimeCreated = $_.TimeCreated
                    EventID = $_.Id
                    Category = "Failed Login"
                    Severity = "Medium"
                    User = $_.Properties[5].Value
                    Source = $_.Properties[19].Value
                    Target = $_.Properties[2].Value
                    Details = "Failed login attempt for '$($_.Properties[2].Value)' from $($_.Properties[19].Value)"
                    Computer = $_.MachineName
                    LogName = $_.LogName
                    RecordId = $_.RecordId
                    EventXML = $_.ToXml()
                    ForensicData = $ForensicData
                }
            }
            $Results += $FailedLoginEvents
            $CategoryTime = [math]::Round(((Get-Date) - $CategoryStartTime).TotalSeconds, 1)
            if ($FailedLoginEvents) {
                Write-Host "    Found $($FailedLoginEvents.Count) failed login events ($($CategoryTime)s)" -ForegroundColor Gray
            } else {
                Write-Host "    No failed login events found ($($CategoryTime)s)" -ForegroundColor Gray
            }
        } catch {
            Write-Warning "Could not access Security log (may need admin privileges)"
        }
    }
    
    # Lateral Movement / Successful Logons
    if ($LateralMovement) {
        $CategoryCount++
        $CategoryStartTime = Get-Date
        Write-Host "[$CategoryCount/$TotalCategories] Checking for Lateral Movement / Suspicious Logons..." -ForegroundColor Yellow
        try {
            $LateralEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'Security'
                ID = 4624
                StartTime = $BeginTime
                EndTime = $EndTime
            } -ErrorAction SilentlyContinue | Where-Object {
                $logonType = $_.Properties[8].Value
                $sourceIP = $_.Properties[18].Value
                $account = $_.Properties[5].Value
                
                # Focus on network logons (3), RDP (10), and unusual accounts
                ($logonType -in @(3, 10)) -and 
                ($sourceIP -ne '-' -and $sourceIP -ne '::1' -and $sourceIP -ne '127.0.0.1') -and
                ($account -notmatch '^DWM-|^UMFD-|ANONYMOUS|^SYSTEM$|^LOCAL SERVICE$|^NETWORK SERVICE$')
            } | ForEach-Object {
                
                $ForensicData = New-ForensicData -EventRecord $_
                
                [PSCustomObject]@{
                    TimeCreated = $_.TimeCreated
                    EventID = $_.Id
                    Category = "Lateral Movement"
                    Severity = "High"
                    User = $_.Properties[5].Value
                    Source = $_.Properties[18].Value
                    Target = $_.Properties[6].Value
                    Details = "Network logon by '$($_.Properties[5].Value)' from $($_.Properties[18].Value) (Type: $($_.Properties[8].Value))"
                    Computer = $_.MachineName
                    LogName = $_.LogName
                    RecordId = $_.RecordId
                    EventXML = $_.ToXml()
                    ForensicData = $ForensicData
                }
            }
            $Results += $LateralEvents
            $CategoryTime = [math]::Round(((Get-Date) - $CategoryStartTime).TotalSeconds, 1)
            if ($LateralEvents) {
                Write-Host "    Found $($LateralEvents.Count) lateral movement events ($($CategoryTime)s)" -ForegroundColor Gray
            } else {
                Write-Host "    No lateral movement events found ($($CategoryTime)s)" -ForegroundColor Gray
            }
        } catch {
            Write-Warning "Could not access Security log for lateral movement"
        }
    }
    
    # Credential Dumping Events
    if ($CredentialDumping) {
        $CategoryCount++
        $CategoryStartTime = Get-Date
        Write-Host "[$CategoryCount/$TotalCategories] Checking for Credential Dumping Activity..." -ForegroundColor Yellow
        try {
            $CredentialEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'Security'
                ID = 4656, 4663
                StartTime = $BeginTime
                EndTime = $EndTime
            } -ErrorAction SilentlyContinue | Where-Object {
                $objectName = $_.Properties[6].Value
                $processName = $_.Properties[11].Value
                # Look for LSASS access or credential files
                ($objectName -match 'lsass|sam|security|system|ntds\.dit') -or
                ($processName -match 'procdump|mimikatz|pwdump|gsecdump')
            } | ForEach-Object {
                
                $ForensicData = New-ForensicData -EventRecord $_
                
                [PSCustomObject]@{
                    TimeCreated = $_.TimeCreated
                    EventID = $_.Id
                    Category = "Credential Dumping"
                    Severity = "High"
                    User = $_.Properties[1].Value
                    Source = $_.Properties[11].Value
                    Target = $_.Properties[6].Value
                    Details = "Suspicious access to credential store: $($_.Properties[6].Value) by $($_.Properties[11].Value)"
                    Computer = $_.MachineName
                    LogName = $_.LogName
                    RecordId = $_.RecordId
                    EventXML = $_.ToXml()
                    ForensicData = $ForensicData
                }
            }
            $Results += $CredentialEvents
            $CategoryTime = [math]::Round(((Get-Date) - $CategoryStartTime).TotalSeconds, 1)
            if ($CredentialEvents) {
                Write-Host "    Found $($CredentialEvents.Count) credential dumping events ($($CategoryTime)s)" -ForegroundColor Gray
            } else {
                Write-Host "    No credential dumping events found ($($CategoryTime)s)" -ForegroundColor Gray
            }
        } catch {
            Write-Warning "Could not access Security log for credential events"
        }
    }
    
    # Service Events
    if ($ServiceEvents) {
        $CategoryCount++
        $CategoryStartTime = Get-Date
        Write-Host "[$CategoryCount/$TotalCategories] Checking for Suspicious Service Activity..." -ForegroundColor Yellow
        
        $SuspiciousServicePatterns = @(
            'powershell', 'cmd.exe', 'wscript', 'cscript', 'mshta', 'rundll32',
            'regsvr32', 'certutil', 'bitsadmin', 'temp', 'tmp', 'AppData',
            'ProgramData', '%temp%', '%tmp%', 'downloads', 'Users\\Public'
        )
        
        $SuspiciousServiceNames = @(
            '^[a-f0-9]{8,}$',  # Random hex strings
            '^[A-Z]{1,3}[0-9]{1,4}$',  # Pattern like ABC123
            'update.*temp', 'temp.*update', 'svchost.*\d+', 'winlogon.*\d+'
        )
        
        # Service Installation (System Log)
        try {
            $ServiceInstallation = Get-WinEvent -FilterHashtable @{
                LogName = 'System'
                ID = 7045
                StartTime = $BeginTime
                EndTime = $EndTime
            } -ErrorAction SilentlyContinue | Where-Object {
                $message = $_.Message
                $serviceName = ""
                $imagePath = ""
                
                # Extract service name and image path from message
                if ($message -match 'Service Name:\s*(.+)') { $serviceName = $matches[1].Trim() }
                if ($message -match 'Image Path:\s*(.+)') { $imagePath = $matches[1].Trim() }
                
                # Check for suspicious patterns
                $suspiciousPath = $SuspiciousServicePatterns | Where-Object { $imagePath -match $_ }
                $suspiciousName = $SuspiciousServiceNames | Where-Object { $serviceName -match $_ }
                
                $suspiciousPath -or $suspiciousName
            } | ForEach-Object {
                
                $ForensicData = New-ForensicData -EventRecord $_
                
                $message = $_.Message
                $serviceName = ""
                $imagePath = ""
                if ($message -match 'Service Name:\s*(.+)') { $serviceName = $matches[1].Trim() }
                if ($message -match 'Image Path:\s*(.+)') { $imagePath = $matches[1].Trim() }
                
                [PSCustomObject]@{
                    TimeCreated = $_.TimeCreated
                    EventID = $_.Id
                    Category = "Service Events"
                    Severity = "Medium"
                    User = if ($_.UserId) { $_.UserId.Value } else { "SYSTEM" }
                    Source = "Service Control Manager"
                    Target = $serviceName
                    Details = "Suspicious service installed: '$serviceName' with path '$imagePath'"
                    Computer = $_.MachineName
                    LogName = $_.LogName
                    RecordId = $_.RecordId
                    EventXML = $_.ToXml()
                    ForensicData = $ForensicData
                }
            }
            $Results += $ServiceInstallation
            $CategoryTime = [math]::Round(((Get-Date) - $CategoryStartTime).TotalSeconds, 1)
            if ($ServiceInstallation) {
                Write-Host "    Found $($ServiceInstallation.Count) suspicious service events ($($CategoryTime)s)" -ForegroundColor Gray
            } else {
                Write-Host "    No suspicious service events found ($($CategoryTime)s)" -ForegroundColor Gray
            }
        } catch {
            Write-Warning "Could not access service installation logs"
        }
    }
    
    # Scheduled Tasks
    if ($ScheduledTasks) {
        $CategoryCount++
        $CategoryStartTime = Get-Date
        Write-Host "[$CategoryCount/$TotalCategories] Checking for Suspicious Scheduled Task Activity..." -ForegroundColor Yellow
        
        $SuspiciousTaskPatterns = @(
            'powershell', 'cmd.exe', 'wscript', 'cscript', 'mshta', 'rundll32',
            'regsvr32', 'certutil', 'bitsadmin', 'wmic', 'temp', 'tmp',
            'AppData', 'ProgramData', '%temp%', '%tmp%', 'downloads'
        )
        
        try {
            $TaskEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'Microsoft-Windows-TaskScheduler/Operational'
                ID = 106, 140, 141, 200, 201
                StartTime = $BeginTime
                EndTime = $EndTime
            } -ErrorAction SilentlyContinue | Where-Object {
                $message = $_.Message
                $SuspiciousTaskPatterns | Where-Object { $message -match $_ }
            } | ForEach-Object {
                $eventType = switch ($_.Id) {
                    106 { "Task Registered" }
                    140 { "Task Updated" }
                    141 { "Task Deleted" }
                    200 { "Task Executed" }
                    201 { "Task Completed" }
                    default { "Task Event" }
                }
                
                $ForensicData = New-ForensicData -EventRecord $_
                
                [PSCustomObject]@{
                    TimeCreated = $_.TimeCreated
                    EventID = $_.Id
                    Category = "Scheduled Tasks"
                    Severity = "Medium"
                    User = if ($_.UserId) { $_.UserId.Value } else { "SYSTEM" }
                    Source = "Task Scheduler"
                    Target = $eventType
                    Details = ($_.Message -split "`n")[0]
                    Computer = $_.MachineName
                    LogName = $_.LogName
                    RecordId = $_.RecordId
                    EventXML = $_.ToXml()
                    ForensicData = $ForensicData
                }
            }
            $Results += $TaskEvents
            $CategoryTime = [math]::Round(((Get-Date) - $CategoryStartTime).TotalSeconds, 1)
            if ($TaskEvents) {
                Write-Host "    Found $($TaskEvents.Count) suspicious task events ($($CategoryTime)s)" -ForegroundColor Gray
            } else {
                Write-Host "    No suspicious task events found ($($CategoryTime)s)" -ForegroundColor Gray
            }
        } catch {
            Write-Warning "Could not access Task Scheduler log"
        }
    }
    
    # Registry Modifications (Quick vs Full implementation)
    if ($RegistryModifications) {
        $CategoryCount++
        $CategoryStartTime = Get-Date
        
        if ($Quick) {
            Write-Host "[$CategoryCount/$TotalCategories] Checking Registry Modifications (Quick)..." -ForegroundColor Yellow
            # Quick version - only critical registry paths
            $SuspiciousRegPaths = @(
                'HKLM.*\\CurrentVersion\\Run', 'HKCU.*\\CurrentVersion\\Run',
                'HKLM.*\\System\\CurrentControlSet\\Services'
            )
        } else {
            Write-Host "[$CategoryCount/$TotalCategories] Checking for Suspicious Registry Modifications (Full)..." -ForegroundColor Yellow
            # Full version - comprehensive registry paths
            $SuspiciousRegPaths = @(
                'HKLM.*\\CurrentVersion\\Run', 'HKCU.*\\CurrentVersion\\Run',
                'HKLM.*\\CurrentVersion\\RunOnce', 'HKCU.*\\CurrentVersion\\RunOnce',
                'HKLM.*\\CurrentVersion\\RunServices', 'HKLM.*\\CurrentVersion\\RunServicesOnce',
                'HKLM.*\\System\\CurrentControlSet\\Services', 'HKLM.*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies',
                'HKLM.*\\SOFTWARE\\Policies', 'HKCU.*\\SOFTWARE\\Policies'
            )
        }
        
        try {
            $RegistryEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'Security'
                ID = 4657
                StartTime = $BeginTime
                EndTime = $EndTime
            } -ErrorAction SilentlyContinue | Where-Object {
                $objectName = $_.Properties[6].Value
                $SuspiciousRegPaths | Where-Object { $objectName -match $_ }
            } | ForEach-Object {
                
                $ForensicData = New-ForensicData -EventRecord $_
                
                [PSCustomObject]@{
                    TimeCreated = $_.TimeCreated
                    EventID = $_.Id
                    Category = if ($Quick) { "Registry Modifications (Quick)" } else { "Registry Modifications" }
                    Severity = "Medium"
                    User = $_.Properties[1].Value
                    Source = $_.Properties[12].Value
                    Target = $_.Properties[6].Value
                    Details = "Registry modification in $($_.Properties[6].Value) by $($_.Properties[12].Value)"
                    Computer = $_.MachineName
                    LogName = $_.LogName
                    RecordId = $_.RecordId
                    EventXML = $_.ToXml()
                    ForensicData = $ForensicData
                }
            }
            $Results += $RegistryEvents
            $CategoryTime = [math]::Round(((Get-Date) - $CategoryStartTime).TotalSeconds, 1)
            if ($RegistryEvents) {
                Write-Host "    Found $($RegistryEvents.Count) registry modification events ($($CategoryTime)s)" -ForegroundColor Gray
            } else {
                Write-Host "    No registry modification events found ($($CategoryTime)s)" -ForegroundColor Gray
            }
        } catch {
            Write-Warning "Could not access Security log for registry events (may require registry auditing)"
        }
    }
    
    # Windows Defender Events
    if ($WindowsDefender) {
        $CategoryCount++
        $CategoryStartTime = Get-Date
        Write-Host "[$CategoryCount/$TotalCategories] Checking for Windows Defender Events..." -ForegroundColor Yellow
        try {
            $DefenderEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'Microsoft-Windows-Windows Defender/Operational'
                ID = 1116, 1117, 5001, 5007, 5010, 5012
                StartTime = $BeginTime
                EndTime = $EndTime
            } -ErrorAction SilentlyContinue | ForEach-Object {
                $eventType = switch ($_.Id) {
                    1116 { "Malware Detected" }
                    1117 { "Malware Blocked" }
                    5001 { "Real-time Protection Disabled" }
                    5007 { "Configuration Changed" }
                    5010 { "Scanning Disabled" }
                    5012 { "Excluded Item Added" }
                    default { "Defender Event" }
                }
                
                $ForensicData = New-ForensicData -EventRecord $_
                
                [PSCustomObject]@{
                    TimeCreated = $_.TimeCreated
                    EventID = $_.Id
                    Category = "Windows Defender"
                    Severity = if ($_.Id -in @(1116, 1117, 5001, 5010)) { "High" } else { "Medium" }
                    User = if ($_.UserId) { $_.UserId.Value } else { "SYSTEM" }
                    Source = "Windows Defender"
                    Target = $eventType
                    Details = ($_.Message -split "`n")[0]
                    Computer = $_.MachineName
                    LogName = $_.LogName
                    RecordId = $_.RecordId
                    EventXML = $_.ToXml()
                    ForensicData = $ForensicData
                }
            }
            $Results += $DefenderEvents
            $CategoryTime = [math]::Round(((Get-Date) - $CategoryStartTime).TotalSeconds, 1)
            if ($DefenderEvents) {
                Write-Host "    Found $($DefenderEvents.Count) Windows Defender events ($($CategoryTime)s)" -ForegroundColor Gray
            } else {
                Write-Host "    No Windows Defender events found ($($CategoryTime)s)" -ForegroundColor Gray
            }
        } catch {
            Write-Warning "Could not access Windows Defender log"
        }
    }
    
    # RDP/Terminal Services Activity
    if ($RDPActivity) {
        $CategoryCount++
        $CategoryStartTime = Get-Date
        Write-Host "[$CategoryCount/$TotalCategories] Checking for RDP/Terminal Services Activity..." -ForegroundColor Yellow
        
        try {
            # Local Session Manager
            $RDPLocalEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
                ID = 21, 22, 25
                StartTime = $BeginTime
                EndTime = $EndTime
            } -ErrorAction SilentlyContinue | ForEach-Object {
                $eventType = switch ($_.Id) {
                    21 { "RDP Logon Success" }
                    22 { "RDP Shell Start" }
                    25 { "RDP Reconnection" }
                    default { "RDP Event" }
                }
                
                $ForensicData = New-ForensicData -EventRecord $_
                $message = $_.Message
                $userMatch = [regex]::Match($message, 'User:\s*([^\r\n]*)')
                $sourceMatch = [regex]::Match($message, 'Source Network Address:\s*([^\r\n]*)')
                
                [PSCustomObject]@{
                    TimeCreated = $_.TimeCreated
                    EventID = $_.Id
                    Category = "RDP Activity"
                    Severity = "Medium"
                    User = if ($userMatch.Success) { $userMatch.Groups[1].Value.Trim() } else { "Unknown" }
                    Source = if ($sourceMatch.Success) { $sourceMatch.Groups[1].Value.Trim() } else { "Local" }
                    Target = "RDP Session"
                    Details = "$eventType - User: $($userMatch.Groups[1].Value) from $($sourceMatch.Groups[1].Value)"
                    Computer = $_.MachineName
                    LogName = $_.LogName
                    RecordId = $_.RecordId
                    EventXML = $_.ToXml()
                    ForensicData = $ForensicData
                }
            }
            $Results += $RDPLocalEvents
            $CategoryTime = [math]::Round(((Get-Date) - $CategoryStartTime).TotalSeconds, 1)
            if ($RDPLocalEvents) {
                Write-Host "    Found $($RDPLocalEvents.Count) RDP activity events ($($CategoryTime)s)" -ForegroundColor Gray
            } else {
                Write-Host "    No RDP activity events found ($($CategoryTime)s)" -ForegroundColor Gray
            }
        } catch {
            Write-Warning "Could not access TerminalServices logs"
        }
    }
    
    # WMI Activity
    if ($WMIActivity) {
        $CategoryCount++
        $CategoryStartTime = Get-Date
        Write-Host "[$CategoryCount/$TotalCategories] Checking for WMI Activity..." -ForegroundColor Yellow
        try {
            $WMIEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'Microsoft-Windows-WMI-Activity/Operational'
                ID = 5857, 5860, 5861
                StartTime = $BeginTime
                EndTime = $EndTime
            } -ErrorAction SilentlyContinue | Where-Object {
                $message = $_.Message
                $message -match 'SELECT.*FROM.*Win32_Process|CREATE.*Win32_Process|ActiveScriptEventConsumer|CommandLineEventConsumer'
            } | ForEach-Object {
                
                $ForensicData = New-ForensicData -EventRecord $_
                
                [PSCustomObject]@{
                    TimeCreated = $_.TimeCreated
                    EventID = $_.Id
                    Category = "WMI Activity"
                    Severity = "High"
                    User = if ($_.UserId) { $_.UserId.Value } else { "SYSTEM" }
                    Source = "WMI"
                    Target = "WMI Query/Command"
                    Details = ($_.Message -split "`n")[0]
                    Computer = $_.MachineName
                    LogName = $_.LogName
                    RecordId = $_.RecordId
                    EventXML = $_.ToXml()
                    ForensicData = $ForensicData
                }
            }
            $Results += $WMIEvents
            $CategoryTime = [math]::Round(((Get-Date) - $CategoryStartTime).TotalSeconds, 1)
            if ($WMIEvents) {
                Write-Host "    Found $($WMIEvents.Count) WMI activity events ($($CategoryTime)s)" -ForegroundColor Gray
            } else {
                Write-Host "    No WMI activity events found ($($CategoryTime)s)" -ForegroundColor Gray
            }
        } catch {
            Write-Warning "Could not access WMI Activity log"
        }
    }
    
    # PowerShell Suspicious Activity (Complete Implementation)
    if ($PowerShellSuspicious) {
        $CategoryCount++
        $CategoryStartTime = Get-Date
        Write-Host "[$CategoryCount/$TotalCategories] Checking for Suspicious PowerShell Activity..." -ForegroundColor Yellow
        
        $SuspiciousKeywords = @(
            'DownloadString', 'DownloadFile', 'Invoke-Expression', 'IEX', 'iex',
            'EncodedCommand', 'enc', 'FromBase64String', 'System.Net.WebClient',
            'Invoke-WebRequest', 'iwr', 'curl', 'wget', 'bypass', 'unrestricted',
            'hidden', 'WindowStyle', 'NonInteractive', 'ExecutionPolicy',
            'Add-Type', 'Reflection.Assembly', 'System.Runtime.InteropServices',
            'VirtualAlloc', 'WriteProcessMemory', 'CreateThread', 'shellcode'
        )
        
        # Script Block Logging (4104)
        try {
            Write-Host "  - Checking Script Block Logging..." -ForegroundColor Gray
            $PSScriptBlocks = Get-WinEvent -FilterHashtable @{
                LogName = 'Microsoft-Windows-PowerShell/Operational'
                ID = 4104
                StartTime = $BeginTime
                EndTime = $EndTime
            } -ErrorAction SilentlyContinue | Where-Object {
                $scriptBlock = $_.Properties[2].Value
                # Check for suspicious keywords
                $matchedKeywords = $SuspiciousKeywords | Where-Object { $scriptBlock -match $_ }
                $matchedKeywords.Count -gt 0
            } | ForEach-Object {
                
                $ForensicData = New-ForensicData -EventRecord $_
                
                [PSCustomObject]@{
                    TimeCreated = $_.TimeCreated
                    EventID = $_.Id
                    Category = "PowerShell Suspicious"
                    Severity = "High"
                    User = if ($_.UserId) { $_.UserId.Value } else { "Unknown" }
                    Source = "PowerShell"
                    Target = "Script Block"
                    Details = ($_.Properties[2].Value -split "`n")[0]
                    Computer = $_.MachineName
                    LogName = $_.LogName
                    RecordId = $_.RecordId
                    EventXML = $_.ToXml()
                    ForensicData = $ForensicData
                }
            }
            $Results += $PSScriptBlocks
            
            # Engine State (4103)
            Write-Host "  - Checking Engine State..." -ForegroundColor Gray
            $PSEngineState = Get-WinEvent -FilterHashtable @{
                LogName = 'Microsoft-Windows-PowerShell/Operational'
                ID = 4103
                StartTime = $BeginTime
                EndTime = $EndTime
            } -ErrorAction SilentlyContinue | Where-Object {
                $_.Message -match 'Started|Stopped'
            } | ForEach-Object {
                
                $ForensicData = New-ForensicData -EventRecord $_
                
                [PSCustomObject]@{
                    TimeCreated = $_.TimeCreated
                    EventID = $_.Id
                    Category = "PowerShell Engine"
                    Severity = "Low"
                    User = if ($_.UserId) { $_.UserId.Value } else { "Unknown" }
                    Source = "PowerShell"
                    Target = "Engine State"
                    Details = ($_.Message -split "`n")[0]
                    Computer = $_.MachineName
                    LogName = $_.LogName
                    RecordId = $_.RecordId
                    EventXML = $_.ToXml()
                    ForensicData = $ForensicData
                }
            }
            $Results += $PSEngineState
            
            $CategoryTime = [math]::Round(((Get-Date) - $CategoryStartTime).TotalSeconds, 1)
            $TotalPSEvents = $PSScriptBlocks.Count + $PSEngineState.Count
            if ($TotalPSEvents -gt 0) {
                Write-Host "    Found $TotalPSEvents PowerShell events ($($PSScriptBlocks.Count) script blocks, $($PSEngineState.Count) engine) ($($CategoryTime)s)" -ForegroundColor Gray
            } else {
                Write-Host "    No suspicious PowerShell events found ($($CategoryTime)s)" -ForegroundColor Gray
            }
        } catch {
            Write-Warning "Could not access PowerShell logs"
        }
    }
    
    # Account Management Events
    if ($AccountManagement) {
        $CategoryCount++
        $CategoryStartTime = Get-Date
        Write-Host "[$CategoryCount/$TotalCategories] Checking for Account Management Activity..." -ForegroundColor Yellow
        try {
            $AccountEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'Security'
                ID = 4720, 4722, 4724, 4726, 4738
                StartTime = $BeginTime
                EndTime = $EndTime
            } -ErrorAction SilentlyContinue | ForEach-Object {
                $eventType = switch ($_.Id) {
                    4720 { "Account Created" }
                    4722 { "Account Enabled" }
                    4724 { "Password Reset" }
                    4726 { "Account Deleted" }
                    4738 { "Account Changed" }
                    default { "Account Event" }
                }
                
                $ForensicData = New-ForensicData -EventRecord $_
                
                [PSCustomObject]@{
                    TimeCreated = $_.TimeCreated
                    EventID = $_.Id
                    Category = "Account Management"
                    Severity = "Medium"
                    User = $_.Properties[4].Value  # Subject Account (who performed the action)
                    Source = $_.Properties[4].Value  # Subject Account
                    Target = $_.Properties[0].Value  # Target Account
                    Details = "$eventType - Target: '$($_.Properties[0].Value)' by '$($_.Properties[4].Value)'"
                    Computer = $_.MachineName
                    LogName = $_.LogName
                    RecordId = $_.RecordId
                    EventXML = $_.ToXml()
                    ForensicData = $ForensicData
                }
            }
            $Results += $AccountEvents
            $CategoryTime = [math]::Round(((Get-Date) - $CategoryStartTime).TotalSeconds, 1)
            if ($AccountEvents) {
                Write-Host "    Found $($AccountEvents.Count) account management events ($($CategoryTime)s)" -ForegroundColor Gray
            } else {
                Write-Host "    No account management events found ($($CategoryTime)s)" -ForegroundColor Gray
            }
        } catch {
            Write-Warning "Could not access Security log for account management"
        }
    }
    
    # Event Log Clearing (Complete Implementation)
    if ($EventLogClearing) {
        $CategoryCount++
        $CategoryStartTime = Get-Date
        Write-Host "[$CategoryCount/$TotalCategories] Checking for Event Log Clearing..." -ForegroundColor Yellow
        
        try {
            $SecurityLogClearing = Get-WinEvent -FilterHashtable @{
                LogName = 'Security'
                ID = 1102
                StartTime = $BeginTime
                EndTime = $EndTime
            } -ErrorAction SilentlyContinue | ForEach-Object {
                
                $ForensicData = New-ForensicData -EventRecord $_
                
                [PSCustomObject]@{
                    TimeCreated = $_.TimeCreated
                    EventID = $_.Id
                    Category = "Event Log Clearing"
                    Severity = "High"
                    User = $_.Properties[1].Value
                    Source = $_.Properties[1].Value
                    Target = "Security Log"
                    Details = "Security log cleared by $($_.Properties[1].Value)"
                    Computer = $_.MachineName
                    LogName = $_.LogName
                    RecordId = $_.RecordId
                    EventXML = $_.ToXml()
                    ForensicData = $ForensicData
                }
            }
            $Results += $SecurityLogClearing
            
            # System Log Clearing
            $SystemLogClearing = Get-WinEvent -FilterHashtable @{
                LogName = 'System'
                ID = 104
                StartTime = $BeginTime
                EndTime = $EndTime
            } -ErrorAction SilentlyContinue | ForEach-Object {
                
                $ForensicData = New-ForensicData -EventRecord $_
                
                [PSCustomObject]@{
                    TimeCreated = $_.TimeCreated
                    EventID = $_.Id
                    Category = "Event Log Clearing"
                    Severity = "High"
                    User = if ($_.UserId) { $_.UserId.Value } else { "SYSTEM" }
                    Source = if ($_.UserId) { $_.UserId.Value } else { "SYSTEM" }
                    Target = "System Log"
                    Details = "System log cleared"
                    Computer = $_.MachineName
                    LogName = $_.LogName
                    RecordId = $_.RecordId
                    EventXML = $_.ToXml()
                    ForensicData = $ForensicData
                }
            }
            $Results += $SystemLogClearing
            
            $CategoryTime = [math]::Round(((Get-Date) - $CategoryStartTime).TotalSeconds, 1)
            $TotalClearingEvents = $SecurityLogClearing.Count + $SystemLogClearing.Count
            if ($TotalClearingEvents -gt 0) {
                Write-Host "    Found $TotalClearingEvents log clearing events ($($SecurityLogClearing.Count) security, $($SystemLogClearing.Count) system) ($($CategoryTime)s)" -ForegroundColor Gray
            } else {
                Write-Host "    No log clearing events found ($($CategoryTime)s)" -ForegroundColor Gray
            }
        } catch {
            Write-Warning "Could not access logs for clearing events"
        }
    }
    
    # Privilege Escalation Events
    if ($PrivilegeEscalation) {
        $CategoryCount++
        $CategoryStartTime = Get-Date
        Write-Host "[$CategoryCount/$TotalCategories] Checking for Privilege Escalation..." -ForegroundColor Yellow
        try {
            $PrivEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'Security'
                ID = 4728, 4732, 4756  # User added to privileged groups
                StartTime = $BeginTime
                EndTime = $EndTime
            } -ErrorAction SilentlyContinue | ForEach-Object {
                
                $ForensicData = New-ForensicData -EventRecord $_
                
                [PSCustomObject]@{
                    TimeCreated = $_.TimeCreated
                    EventID = $_.Id
                    Category = "Privilege Escalation"
                    Severity = "High"
                    User = $_.Properties[6].Value  # Subject Account (who performed the action)
                    Source = $_.Properties[6].Value  # Subject Account
                    Target = $_.Properties[0].Value  # Target Account
                    Details = "User '$($_.Properties[0].Value)' added to privileged group '$($_.Properties[2].Value)' by '$($_.Properties[6].Value)'"
                    Computer = $_.MachineName
                    LogName = $_.LogName
                    RecordId = $_.RecordId
                    EventXML = $_.ToXml()
                    ForensicData = $ForensicData
                }
            }
            $Results += $PrivEvents
            $CategoryTime = [math]::Round(((Get-Date) - $CategoryStartTime).TotalSeconds, 1)
            if ($PrivEvents) {
                Write-Host "    Found $($PrivEvents.Count) privilege escalation events ($($CategoryTime)s)" -ForegroundColor Gray
            } else {
                Write-Host "    No privilege escalation events found ($($CategoryTime)s)" -ForegroundColor Gray
            }
        } catch {
            Write-Warning "Could not access Security log for privilege events"
        }
    }

    # Process Creation Events (Non-PowerShell, Non-Service, Non-Task)
    if ($ProcessCreation) {
        $CategoryCount++
        $CategoryStartTime = Get-Date
        Write-Host "[$CategoryCount/$TotalCategories] Checking for Suspicious Process Creation..." -ForegroundColor Yellow
        
        $SuspiciousProcesses = @(
            'cmd.exe.*powershell', 'wscript.exe', 'cscript.exe', 'mshta.exe',
            'rundll32.exe.*javascript', 'regsvr32.exe.*scrobj.dll',
            'certutil.*-decode', 'bitsadmin.*transfer', 'wmic.*process.*call.*create',
            'rundll32.*comsvcs.*MiniDump', 'tasklist.*\/svc', 'net.*user.*\/add',
            'vssadmin.*delete.*shadows', 'wbadmin.*delete.*catalog', 'bcdedit.*bootstatuspolicy.*ignoreallfailures'
        )
        
        try {
            $ProcessEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'Security'
                ID = 4688  # Process Creation
                StartTime = $BeginTime
                EndTime = $EndTime
            } -ErrorAction SilentlyContinue | Where-Object {
                $cmdLine = $_.Properties[8].Value
                $processName = $_.Properties[5].Value
                # Exclude PowerShell processes, schtasks, and service management tools (already checked above)
                ($processName -notmatch 'powershell\.exe|schtasks\.exe|sc\.exe|services\.exe') -and
                ($SuspiciousProcesses | Where-Object { $cmdLine -match $_ })
            } | ForEach-Object {
                
                $ForensicData = New-ForensicData -EventRecord $_
                
                [PSCustomObject]@{
                    TimeCreated = $_.TimeCreated
                    EventID = $_.Id
                    Category = "Process Creation"
                    Severity = "Medium"
                    User = $_.Properties[1].Value
                    Source = $_.Properties[13].Value  # Parent Process
                    Target = $_.Properties[5].Value   # New Process
                    Details = $_.Properties[8].Value  # Command Line
                    Computer = $_.MachineName
                    LogName = $_.LogName
                    RecordId = $_.RecordId
                    EventXML = $_.ToXml()
                    ForensicData = $ForensicData
                }
            }
            $Results += $ProcessEvents
            $CategoryTime = [math]::Round(((Get-Date) - $CategoryStartTime).TotalSeconds, 1)
            if ($ProcessEvents) {
                Write-Host "    Found $($ProcessEvents.Count) suspicious process creation events ($($CategoryTime)s)" -ForegroundColor Gray
            } else {
                Write-Host "    No suspicious process creation events found ($($CategoryTime)s)" -ForegroundColor Gray
            }
        } catch {
            Write-Warning "Could not access Security log for process events"
        }
    }

    # Share Access Events (Quick vs Full implementation)
    if ($ShareAccess) {
        $CategoryCount++
        $CategoryStartTime = Get-Date
        
        try {
            if ($Quick) {
                Write-Host "[$CategoryCount/$TotalCategories] Checking Share Access (Quick)..." -ForegroundColor Yellow
                # Quick version - only admin shares and suspicious IPs
                $ShareEvents = Get-WinEvent -FilterHashtable @{
                    LogName = 'Security'
                    ID = 5140, 5145  # Network share accessed, object accessed
                    StartTime = $BeginTime
                    EndTime = $EndTime
                } -ErrorAction SilentlyContinue | Where-Object {
                    $shareName = $_.Properties[3].Value
                    $sourceIP = $_.Properties[14].Value
                    # Quick: Only admin shares from external IPs
                    ($shareName -match '\$|ADMIN|IPC') -and
                    ($sourceIP -ne '::1' -and $sourceIP -ne '127.0.0.1' -and $sourceIP -ne '-')
                }
            } else {
                Write-Host "[$CategoryCount/$TotalCategories] Checking for Suspicious Share Access (Full)..." -ForegroundColor Yellow
                # Full version - comprehensive share analysis
                $ShareEvents = Get-WinEvent -FilterHashtable @{
                    LogName = 'Security'
                    ID = 5140, 5145  # Network share accessed, object accessed
                    StartTime = $BeginTime
                    EndTime = $EndTime
                } -ErrorAction SilentlyContinue | Where-Object {
                    $shareName = $_.Properties[3].Value
                    $sourceIP = $_.Properties[14].Value
                    # Full: All admin shares or any external access
                    ($shareName -match '\$|ADMIN|IPC') -and
                    ($sourceIP -ne '::1' -and $sourceIP -ne '127.0.0.1' -and $sourceIP -ne '-')
                }
            }
            
            $ShareAccessEvents = $ShareEvents | ForEach-Object {
                $ForensicData = New-ForensicData -EventRecord $_
                
                [PSCustomObject]@{
                    TimeCreated = $_.TimeCreated
                    EventID = $_.Id
                    Category = if ($Quick) { "Share Access (Quick)" } else { "Share Access" }
                    Severity = "Medium"
                    User = $_.Properties[1].Value
                    Source = $_.Properties[14].Value
                    Target = $_.Properties[3].Value
                    Details = "Share access to '$($_.Properties[3].Value)' from $($_.Properties[14].Value) by $($_.Properties[1].Value)"
                    Computer = $_.MachineName
                    LogName = $_.LogName
                    RecordId = $_.RecordId
                    EventXML = $_.ToXml()
                    ForensicData = $ForensicData
                }
            }
            $Results += $ShareAccessEvents
            $CategoryTime = [math]::Round(((Get-Date) - $CategoryStartTime).TotalSeconds, 1)
            if ($ShareAccessEvents) {
                Write-Host "    Found $($ShareAccessEvents.Count) share access events ($($CategoryTime)s)" -ForegroundColor Gray
            } else {
                Write-Host "    No suspicious share access events found ($($CategoryTime)s)" -ForegroundColor Gray
            }
        } catch {
            Write-Warning "Could not access Security log for share events"
        }
    }

    # Firewall Rule Changes
    if ($FirewallChanges) {
        $CategoryCount++
        $CategoryStartTime = Get-Date
        Write-Host "[$CategoryCount/$TotalCategories] Checking for Firewall Rule Changes..." -ForegroundColor Yellow
        try {
            $FirewallEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'
                ID = 2004, 2005, 2006, 2033  # Rule added, changed, deleted, etc.
                StartTime = $BeginTime
                EndTime = $EndTime
            } -ErrorAction SilentlyContinue | ForEach-Object {
                $eventType = switch ($_.Id) {
                    2004 { "Rule Added" }
                    2005 { "Rule Changed" }
                    2006 { "Rule Deleted" }
                    2033 { "Rule Parsing Error" }
                    default { "Firewall Event" }
                }
                
                $ForensicData = New-ForensicData -EventRecord $_
                
                [PSCustomObject]@{
                    TimeCreated = $_.TimeCreated
                    EventID = $_.Id
                    Category = "Firewall Changes"
                    Severity = "Medium"
                    User = if ($_.UserId) { $_.UserId.Value } else { "SYSTEM" }
                    Source = "Windows Firewall"
                    Target = $eventType
                    Details = ($_.Message -split "`n")[0]
                    Computer = $_.MachineName
                    LogName = $_.LogName
                    RecordId = $_.RecordId
                    EventXML = $_.ToXml()
                    ForensicData = $ForensicData
                }
            }
            $Results += $FirewallEvents
            $CategoryTime = [math]::Round(((Get-Date) - $CategoryStartTime).TotalSeconds, 1)
            if ($FirewallEvents) {
                Write-Host "    Found $($FirewallEvents.Count) firewall change events ($($CategoryTime)s)" -ForegroundColor Gray
            } else {
                Write-Host "    No firewall change events found ($($CategoryTime)s)" -ForegroundColor Gray
            }
        } catch {
            Write-Warning "Could not access Windows Firewall log"
        }
    }

    # DNS Events
    if ($DNSEvents) {
        $CategoryCount++
        $CategoryStartTime = Get-Date
        Write-Host "[$CategoryCount/$TotalCategories] Checking for Suspicious DNS Activity..." -ForegroundColor Yellow
        
        $SuspiciousDomains = @(
            '\.tk$', '\.ml$', '\.ga$', '\.cf$',  # Suspicious TLDs
            'pastebin', 'github\.io', 'ngrok', 'duckdns',  # Common C2 services
            'bit\.ly', 'tinyurl', 'shorturl',  # URL shorteners
            'raw\.githubusercontent', 'paste\.ee', 'hastebin',  # File hosting
            'discord\.com/api/webhooks', 'telegram\.org'  # Communication platforms used for C2
        )
        
        try {
            $DNSQueryEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'Microsoft-Windows-DNS-Client/Operational'
                ID = 3008  # DNS query
                StartTime = $BeginTime
                EndTime = $EndTime
            } -ErrorAction SilentlyContinue | Where-Object {
                $query = $_.Message
                $SuspiciousDomains | Where-Object { $query -match $_ }
            } | ForEach-Object {
                
                $ForensicData = New-ForensicData -EventRecord $_
                
                [PSCustomObject]@{
                    TimeCreated = $_.TimeCreated
                    EventID = $_.Id
                    Category = "DNS Events"
                    Severity = "Medium"
                    User = if ($_.UserId) { $_.UserId.Value } else { "SYSTEM" }
                    Source = "DNS Client"
                    Target = "Suspicious Domain"
                    Details = ($_.Message -split "`n")[0]
                    Computer = $_.MachineName
                    LogName = $_.LogName
                    RecordId = $_.RecordId
                    EventXML = $_.ToXml()
                    ForensicData = $ForensicData
                }
            }
            $Results += $DNSQueryEvents
            $CategoryTime = [math]::Round(((Get-Date) - $CategoryStartTime).TotalSeconds, 1)
            if ($DNSQueryEvents) {
                Write-Host "    Found $($DNSQueryEvents.Count) suspicious DNS events ($($CategoryTime)s)" -ForegroundColor Gray
            } else {
                Write-Host "    No suspicious DNS events found ($($CategoryTime)s)" -ForegroundColor Gray
            }
        } catch {
            Write-Warning "Could not access DNS Client Events log"
        }
    }
    
    # Process Injection Events (Quick vs Full implementation)
    if ($ProcessInjection) {
        $CategoryCount++
        $CategoryStartTime = Get-Date
        
        if ($Quick) {
            Write-Host "[$CategoryCount/$TotalCategories] Checking Process Injection (Quick)..." -ForegroundColor Yellow
            try {
                # Quick version - high-confidence, low-volume indicators
                $QuickInjectionEvents = Get-WinEvent -FilterHashtable @{
                    LogName = 'Security'
                    ID = 4688
                    StartTime = $BeginTime
                    EndTime = $EndTime
                } -ErrorAction SilentlyContinue | Where-Object {
                    $processName = $_.Properties[5].Value
                    $cmdLine = $_.Properties[8].Value
                    
                    # High-confidence injection indicators only
                    ($processName -match 'mavinject\.exe|psinject\.exe|reflectdll\.exe') -or
                    ($cmdLine -match '\bmavinject\b|\bpsinject\b') -or
                    ($cmdLine -match 'VirtualAlloc.*WriteProcessMemory.*CreateRemoteThread') -or
                    ($cmdLine -match 'Process\.Start.*Hollowing|ProcessHollowing') -or
                    ($processName -match 'powershell\.exe' -and $cmdLine -match 'SetWindowsHookEx|CreateRemoteThread|WriteProcessMemory|VirtualAllocEx')
                } | ForEach-Object {
                    
                    $ForensicData = New-ForensicData -EventRecord $_
                    
                    [PSCustomObject]@{
                        TimeCreated = $_.TimeCreated
                        EventID = $_.Id
                        Category = "Process Injection (Quick)"
                        Severity = "High"
                        User = $_.Properties[1].Value
                        Source = $_.Properties[13].Value
                        Target = $_.Properties[5].Value
                        Details = $_.Properties[8].Value
                        Computer = $_.MachineName
                        LogName = $_.LogName
                        RecordId = $_.RecordId
                        EventXML = $_.ToXml()
                        ForensicData = $ForensicData
                    }
                }
                
                # Check if Sysmon is available for dedicated injection events
                try {
                    $SysmonInjection = Get-WinEvent -FilterHashtable @{
                        LogName = 'Microsoft-Windows-Sysmon/Operational'
                        ID = 8  # Process injection detected
                        StartTime = $BeginTime
                        EndTime = $EndTime
                    } -ErrorAction SilentlyContinue | ForEach-Object {
                        
                        $ForensicData = New-ForensicData -EventRecord $_
                        
                        [PSCustomObject]@{
                            TimeCreated = $_.TimeCreated
                            EventID = $_.Id
                            Category = "Process Injection (Sysmon)"
                            Severity = "High"
                            User = if ($_.UserId) { $_.UserId.Value } else { "Unknown" }
                            Source = "Sysmon"
                            Target = "Process Injection"
                            Details = "Sysmon detected process injection"
                            Computer = $_.MachineName
                            LogName = $_.LogName
                            RecordId = $_.RecordId
                            EventXML = $_.ToXml()
                            ForensicData = $ForensicData
                        }
                    }
                    $QuickInjectionEvents += $SysmonInjection
                    if ($SysmonInjection) {
                        Write-Host "    - Found $($SysmonInjection.Count) Sysmon injection events" -ForegroundColor Gray
                    }
                } catch {
                    # Sysmon not available, continue with basic checks
                }
                
                $Results += $QuickInjectionEvents
                $CategoryTime = [math]::Round(((Get-Date) - $CategoryStartTime).TotalSeconds, 1)
                if ($QuickInjectionEvents) {
                    Write-Host "    Found $($QuickInjectionEvents.Count) process injection events ($($CategoryTime)s)" -ForegroundColor Gray
                } else {
                    Write-Host "    No process injection events found ($($CategoryTime)s)" -ForegroundColor Gray
                }
            } catch {
                Write-Warning "Could not access Security log for injection events"
            }
        } else {
            # Full version - comprehensive pattern analysis
            Write-Host "[$CategoryCount/$TotalCategories] Checking for Process Injection (Full)..." -ForegroundColor Yellow
            try {
                $InjectionEvents = Get-WinEvent -FilterHashtable @{
                    LogName = 'Security'
                    ID = 4688  # Process Creation
                    StartTime = $BeginTime
                    EndTime = $EndTime
                } -ErrorAction SilentlyContinue | Where-Object {
                    $cmdLine = $_.Properties[8].Value
                    $processName = $_.Properties[5].Value
                    # Look for comprehensive injection techniques
                    ($cmdLine -match 'SetWindowsHookEx|CreateRemoteThread|WriteProcessMemory|VirtualAllocEx|NtQueueApcThread') -or
                    ($processName -match 'mavinject|psinject') -or
                    ($cmdLine -match 'hollowing|injection|migrate')
                } | ForEach-Object {
                    
                    $ForensicData = New-ForensicData -EventRecord $_
                    
                    [PSCustomObject]@{
                        TimeCreated = $_.TimeCreated
                        EventID = $_.Id
                        Category = "Process Injection"
                        Severity = "High"
                        User = $_.Properties[1].Value
                        Source = $_.Properties[13].Value
                        Target = $_.Properties[5].Value
                        Details = $_.Properties[8].Value
                        Computer = $_.MachineName
                        LogName = $_.LogName
                        RecordId = $_.RecordId
                        EventXML = $_.ToXml()
                        ForensicData = $ForensicData
                    }
                }
                $Results += $InjectionEvents
                $CategoryTime = [math]::Round(((Get-Date) - $CategoryStartTime).TotalSeconds, 1)
                if ($InjectionEvents) {
                    Write-Host "    Found $($InjectionEvents.Count) process injection events ($($CategoryTime)s)" -ForegroundColor Gray
                } else {
                    Write-Host "    No process injection events found ($($CategoryTime)s)" -ForegroundColor Gray
                }
            } catch {
                Write-Warning "Could not access Security log for injection events"
            }
        }
    }

    # File Creation in Suspicious Locations (only if Full or specifically requested)
    if ($FileCreation) {
        $CategoryCount++
        $CategoryStartTime = Get-Date
        Write-Host "[$CategoryCount/$TotalCategories] Checking for File Creation in Suspicious Locations..." -ForegroundColor Yellow
        
        $SuspiciousFilePaths = @(
            'C:\\Windows\\System32.*\.(exe|dll|sys|com|scr|pif|bat|cmd|ps1)', 
            'C:\\Windows\\SysWOW64.*\.(exe|dll|sys|com|scr|pif|bat|cmd|ps1)',
            'C:\\Windows\\Tasks.*\.(exe|bat|cmd|ps1|vbs)',
            'C:\\Windows\\Temp.*\.(exe|bat|cmd|ps1|vbs|com|scr)',
            'C:\\Users\\.*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup.*\.(exe|bat|cmd|ps1|vbs|lnk)',
            'C:\\ProgramData.*\.(exe|bat|cmd|ps1|vbs|com|scr)',
            'C:\\inetpub\\wwwroot.*\.(aspx|asp|php|jsp|js|ps1|bat|cmd|vbs|py|pl|exe|com|scr|pif|dll|sys|zip|rar|7z|doc|docx|pdf|rtf|config|xml|ini)',
            'C:\\xampp\\htdocs.*\.(aspx|asp|php|jsp|js|ps1|bat|cmd|vbs|py|pl|exe|com|scr|pif|dll|sys|zip|rar|7z|doc|docx|pdf|rtf|config|xml|ini)',
            'C:\\wamp\\www.*\.(aspx|asp|php|jsp|js|ps1|bat|cmd|vbs|py|pl|exe|com|scr|pif|dll|sys|zip|rar|7z|doc|docx|pdf|rtf|config|xml|ini)',
            '.*\\wwwroot.*\.(aspx|asp|php|jsp|js|ps1|bat|cmd|vbs|py|pl|exe|com|scr|pif|dll|sys|zip|rar|7z|doc|docx|pdf|rtf|config|xml|ini)',
            '.*\\htdocs.*\.(aspx|asp|php|jsp|js|ps1|bat|cmd|vbs|py|pl|exe|com|scr|pif|dll|sys|zip|rar|7z|doc|docx|pdf|rtf|config|xml|ini)'
        )
        
        try {
            $FileEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'Security'
                ID = 4663
                StartTime = $BeginTime
                EndTime = $EndTime
            } -ErrorAction SilentlyContinue | Where-Object {
                $objectName = $_.Properties[6].Value
                $SuspiciousFilePaths | Where-Object { $objectName -match $_ }
            } | ForEach-Object {
                
                $ForensicData = New-ForensicData -EventRecord $_
                
                [PSCustomObject]@{
                    TimeCreated = $_.TimeCreated
                    EventID = $_.Id
                    Category = "File Creation"
                    Severity = "Medium"
                    User = $_.Properties[1].Value
                    Source = $_.Properties[11].Value
                    Target = $_.Properties[6].Value
                    Details = "File access in suspicious location: $($_.Properties[6].Value)"
                    Computer = $_.MachineName
                    LogName = $_.LogName
                    RecordId = $_.RecordId
                    EventXML = $_.ToXml()
                    ForensicData = $ForensicData
                }
            }
            $Results += $FileEvents
            $CategoryTime = [math]::Round(((Get-Date) - $CategoryStartTime).TotalSeconds, 1)
            if ($FileEvents) {
                Write-Host "    Found $($FileEvents.Count) suspicious file events ($($CategoryTime)s)" -ForegroundColor Gray
            } else {
                Write-Host "    No suspicious file events found ($($CategoryTime)s)" -ForegroundColor Gray
            }
        } catch {
            Write-Warning "Could not access Security log for file events (may require file auditing)"
        }
    }

    # Certificate Installation Events (only if Full or specifically requested)
    if ($CertificateInstallation) {
        $CategoryCount++
        $CategoryStartTime = Get-Date
        Write-Host "[$CategoryCount/$TotalCategories] Checking for Certificate Installation..." -ForegroundColor Yellow
        try {
            $CertEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'System'
                ID = 4104, 4105, 4108  # Certificate related events
                StartTime = $BeginTime
                EndTime = $EndTime
            } -ErrorAction SilentlyContinue | ForEach-Object {
                
                $ForensicData = New-ForensicData -EventRecord $_
                
                [PSCustomObject]@{
                    TimeCreated = $_.TimeCreated
                    EventID = $_.Id
                    Category = "Certificate Installation"
                    Severity = "Medium"
                    User = if ($_.UserId) { $_.UserId.Value } else { "SYSTEM" }
                    Source = "Certificate Services"
                    Target = "Certificate Store"
                    Details = ($_.Message -split "`n")[0]
                    Computer = $_.MachineName
                    LogName = $_.LogName
                    RecordId = $_.RecordId
                    EventXML = $_.ToXml()
                    ForensicData = $ForensicData
                }
            }
            $Results += $CertEvents
            $CategoryTime = [math]::Round(((Get-Date) - $CategoryStartTime).TotalSeconds, 1)
            if ($CertEvents) {
                Write-Host "    Found $($CertEvents.Count) certificate events ($($CategoryTime)s)" -ForegroundColor Gray
            } else {
                Write-Host "    No certificate events found ($($CategoryTime)s)" -ForegroundColor Gray
            }
        } catch {
            Write-Warning "Could not access System log for certificate events"
        }
    }

    # Network Connections (only if Full or specifically requested)
    if ($NetworkConnections) {
        $CategoryCount++
        $CategoryStartTime = Get-Date
        Write-Host "[$CategoryCount/$TotalCategories] Checking for Network Connection Events..." -ForegroundColor Yellow
        try {
            # Check Windows Firewall log for blocked connections
            $FirewallNetworkEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'
                ID = 5152, 5154  # Blocked connections
                StartTime = $BeginTime
                EndTime = $EndTime
            } -ErrorAction SilentlyContinue | ForEach-Object {
                
                $ForensicData = New-ForensicData -EventRecord $_
                
                [PSCustomObject]@{
                    TimeCreated = $_.TimeCreated
                    EventID = $_.Id
                    Category = "Network Connection"
                    Severity = "Medium"
                    User = if ($_.UserId) { $_.UserId.Value } else { "SYSTEM" }
                    Source = "Windows Firewall"
                    Target = "Blocked Connection"
                    Details = ($_.Message -split "`n")[0]
                    Computer = $_.MachineName
                    LogName = $_.LogName
                    RecordId = $_.RecordId
                    EventXML = $_.ToXml()
                    ForensicData = $ForensicData
                }
            }
            $Results += $FirewallNetworkEvents
            $CategoryTime = [math]::Round(((Get-Date) - $CategoryStartTime).TotalSeconds, 1)
            if ($FirewallNetworkEvents) {
                Write-Host "    Found $($FirewallNetworkEvents.Count) network connection events ($($CategoryTime)s)" -ForegroundColor Gray
            } else {
                Write-Host "    No network connection events found ($($CategoryTime)s)" -ForegroundColor Gray
            }
        } catch {
            Write-Warning "Could not access Windows Firewall log"
        }
    }

    # Application Crashes (only if Full or specifically requested)
    if ($ApplicationCrashes) {
        $CategoryCount++
        $CategoryStartTime = Get-Date
        Write-Host "[$CategoryCount/$TotalCategories] Checking for Application Crashes..." -ForegroundColor Yellow
        try {
            $CrashEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'Application'
                ID = 1000, 1001  # Application Error, Windows Error Reporting
                StartTime = $BeginTime
                EndTime = $EndTime
            } -ErrorAction SilentlyContinue | Where-Object {
                $message = $_.Message
                # Look for crashes of critical applications that might indicate exploitation
                $message -match 'lsass|winlogon|csrss|explorer|svchost|spoolsv'
            } | ForEach-Object {
                
                $ForensicData = New-ForensicData -EventRecord $_
                
                [PSCustomObject]@{
                    TimeCreated = $_.TimeCreated
                    EventID = $_.Id
                    Category = "Application Crash"
                    Severity = "Medium"
                    User = if ($_.UserId) { $_.UserId.Value } else { "SYSTEM" }
                    Source = "Application"
                    Target = "Critical Application Crash"
                    Details = ($_.Message -split "`n")[0]
                    Computer = $_.MachineName
                    LogName = $_.LogName
                    RecordId = $_.RecordId
                    EventXML = $_.ToXml()
                    ForensicData = $ForensicData
                }
            }
            $Results += $CrashEvents
            $CategoryTime = [math]::Round(((Get-Date) - $CategoryStartTime).TotalSeconds, 1)
            if ($CrashEvents) {
                Write-Host "    Found $($CrashEvents.Count) critical application crashes ($($CategoryTime)s)" -ForegroundColor Gray
            } else {
                Write-Host "    No critical application crashes found ($($CategoryTime)s)" -ForegroundColor Gray
            }
        } catch {
            Write-Warning "Could not access Application log"
        }
    }

    # Boot/Startup Events (only if Full or specifically requested)
    if ($BootStartupEvents) {
        $CategoryCount++
        $CategoryStartTime = Get-Date
        Write-Host "[$CategoryCount/$TotalCategories] Checking for Boot/Startup Events..." -ForegroundColor Yellow
        try {
            $BootEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'System'
                ID = 6005, 6006, 6008, 6009, 6013  # Boot events
                StartTime = $BeginTime
                EndTime = $EndTime
            } -ErrorAction SilentlyContinue | ForEach-Object {
                $eventType = switch ($_.Id) {
                    6005 { "System Startup" }
                    6006 { "System Shutdown" }
                    6008 { "Unexpected Shutdown" }
                    6009 { "Boot Information" }
                    6013 { "System Uptime" }
                    default { "Boot Event" }
                }
                
                $ForensicData = New-ForensicData -EventRecord $_
                
                [PSCustomObject]@{
                    TimeCreated = $_.TimeCreated
                    EventID = $_.Id
                    Category = "Boot/Startup Events"
                    Severity = if ($_.Id -eq 6008) { "Medium" } else { "Low" }
                    User = "SYSTEM"
                    Source = "System"
                    Target = $eventType
                    Details = ($_.Message -split "`n")[0]
                    Computer = $_.MachineName
                    LogName = $_.LogName
                    RecordId = $_.RecordId
                    EventXML = $_.ToXml()
                    ForensicData = $ForensicData
                }
            }
            $Results += $BootEvents
            $CategoryTime = [math]::Round(((Get-Date) - $CategoryStartTime).TotalSeconds, 1)
            if ($BootEvents) {
                Write-Host "    Found $($BootEvents.Count) boot/startup events ($($CategoryTime)s)" -ForegroundColor Gray
            } else {
                Write-Host "    No boot/startup events found ($($CategoryTime)s)" -ForegroundColor Gray
            }
        } catch {
            Write-Warning "Could not access System log for boot events"
        }
    }

    # Print Spooler Events (only if Full or specifically requested)
    if ($PrintSpoolerEvents) {
        $CategoryCount++
        $CategoryStartTime = Get-Date
        Write-Host "[$CategoryCount/$TotalCategories] Checking for Print Spooler Events..." -ForegroundColor Yellow
        try {
            $SpoolerEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'Microsoft-Windows-PrintService/Operational'
                ID = 307, 316  # Print job events
                StartTime = $BeginTime
                EndTime = $EndTime
            } -ErrorAction SilentlyContinue | Where-Object {
                $message = $_.Message
                # Look for suspicious print operations that might indicate PrintNightmare
                $message -match '\.dll|\.exe|system32|drivers'
            } | ForEach-Object {
                
                $ForensicData = New-ForensicData -EventRecord $_
                
                [PSCustomObject]@{
                    TimeCreated = $_.TimeCreated
                    EventID = $_.Id
                    Category = "Print Spooler"
                    Severity = "High"
                    User = if ($_.UserId) { $_.UserId.Value } else { "SYSTEM" }
                    Source = "Print Spooler"
                    Target = "Print Job"
                    Details = ($_.Message -split "`n")[0]
                    Computer = $_.MachineName
                    LogName = $_.LogName
                    RecordId = $_.RecordId
                    EventXML = $_.ToXml()
                    ForensicData = $ForensicData
                }
            }
            $Results += $SpoolerEvents
            $CategoryTime = [math]::Round(((Get-Date) - $CategoryStartTime).TotalSeconds, 1)
            if ($SpoolerEvents) {
                Write-Host "    Found $($SpoolerEvents.Count) suspicious print spooler events ($($CategoryTime)s)" -ForegroundColor Gray
            } else {
                Write-Host "    No suspicious print spooler events found ($($CategoryTime)s)" -ForegroundColor Gray
            }
        } catch {
            Write-Warning "Could not access PrintService log"
        }
    }

    # Driver Loading (only if Full or specifically requested)
    if ($DriverLoading) {
        $CategoryCount++
        $CategoryStartTime = Get-Date
        Write-Host "[$CategoryCount/$TotalCategories] Checking for Suspicious Driver Loading..." -ForegroundColor Yellow
        
        $SuspiciousDriverPaths = @(
            'temp', 'tmp', 'Users', 'Downloads', 'AppData', 'ProgramData'
        )
        
        try {
            $DriverEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'System'
                ID = 6  # Driver loaded
                StartTime = $BeginTime
                EndTime = $EndTime
            } -ErrorAction SilentlyContinue | Where-Object {
                $message = $_.Message
                # Look for drivers loaded from suspicious locations
                $SuspiciousDriverPaths | Where-Object { $message -match $_ }
            } | ForEach-Object {
                
                $ForensicData = New-ForensicData -EventRecord $_
                
                [PSCustomObject]@{
                    TimeCreated = $_.TimeCreated
                    EventID = $_.Id
                    Category = "Driver Loading"
                    Severity = "High"
                    User = "SYSTEM"
                    Source = "System"
                    Target = "Driver"
                    Details = ($_.Message -split "`n")[0]
                    Computer = $_.MachineName
                    LogName = $_.LogName
                    RecordId = $_.RecordId
                    EventXML = $_.ToXml()
                    ForensicData = $ForensicData
                }
            }
            $Results += $DriverEvents
            $CategoryTime = [math]::Round(((Get-Date) - $CategoryStartTime).TotalSeconds, 1)
            if ($DriverEvents) {
                Write-Host "    Found $($DriverEvents.Count) suspicious driver loading events ($($CategoryTime)s)" -ForegroundColor Gray
            } else {
                Write-Host "    No suspicious driver loading events found ($($CategoryTime)s)" -ForegroundColor Gray
            }
        } catch {
            Write-Warning "Could not access System log for driver events"
        }
    }

    # Software Installation (only if Full or specifically requested)
    if ($SoftwareInstallation) {
        $CategoryCount++
        $CategoryStartTime = Get-Date
        Write-Host "[$CategoryCount/$TotalCategories] Checking for Software Installation..." -ForegroundColor Yellow
        try {
            $SoftwareEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'Application'
                ID = 1033, 1034  # Installation events
                StartTime = $BeginTime
                EndTime = $EndTime
            } -ErrorAction SilentlyContinue | Where-Object {
                $message = $_.Message
                # Look for installation of potentially suspicious software
                $message -match 'install|setup|msi|package'
            } | ForEach-Object {
                
                $ForensicData = New-ForensicData -EventRecord $_
                
                [PSCustomObject]@{
                    TimeCreated = $_.TimeCreated
                    EventID = $_.Id
                    Category = "Software Installation"
                    Severity = "Medium"
                    User = if ($_.UserId) { $_.UserId.Value } else { "SYSTEM" }
                    Source = "Application"
                    Target = "Software Installation"
                    Details = ($_.Message -split "`n")[0]
                    Computer = $_.MachineName
                    LogName = $_.LogName
                    RecordId = $_.RecordId
                    EventXML = $_.ToXml()
                    ForensicData = $ForensicData
                }
            }
            $Results += $SoftwareEvents
            $CategoryTime = [math]::Round(((Get-Date) - $CategoryStartTime).TotalSeconds, 1)
            if ($SoftwareEvents) {
                Write-Host "    Found $($SoftwareEvents.Count) software installation events ($($CategoryTime)s)" -ForegroundColor Gray
            } else {
                Write-Host "    No software installation events found ($($CategoryTime)s)" -ForegroundColor Gray
            }
        } catch {
            Write-Warning "Could not access Application log for software events"
        }
    }

    # Summary
    $ScanEndTime = Get-Date
    $TotalScanTime = [math]::Round(($ScanEndTime - $ScanStartTime).TotalMinutes, 1)
    
    Write-Host ""
    Write-Host "IoC SCAN SUMMARY" -ForegroundColor Cyan
    $HighSeverity = ($Results | Where-Object Severity -eq "High").Count
    $MediumSeverity = ($Results | Where-Object Severity -eq "Medium").Count
    $LowSeverity = ($Results | Where-Object Severity -eq "Low").Count
    $Total = $Results.Count
    
    Write-Host "Total IoCs Found: $Total" -ForegroundColor White
    Write-Host "High Severity: $HighSeverity" -ForegroundColor Red
    Write-Host "Medium Severity: $MediumSeverity" -ForegroundColor Yellow
    Write-Host "Low Severity: $LowSeverity" -ForegroundColor Green
    Write-Host "Time Window: $TotalMinutes minutes" -ForegroundColor Gray
    Write-Host "Scan Duration: $TotalScanTime minutes" -ForegroundColor Gray
    if ($Quick) {
        Write-Host "Scan Mode: QUICK (18 categories)" -ForegroundColor Cyan
    } elseif ($Full) {
        Write-Host "Scan Mode: FULL (26 categories)" -ForegroundColor Cyan
    } else {
        Write-Host "Scan Mode: TARGETED ($TotalCategories categories)" -ForegroundColor Cyan
    }
    
    if ($Results.Count -gt 0) {
        Write-Host ""
        Write-Host "TIP: Save these results for analysis:" -ForegroundColor Cyan
        Write-Host "   Save-IoCs -Results `$results -Path 'scan_$(Get-Date -f "yyyyMMdd_HHmm").json'" -ForegroundColor Gray
    }
    
    Write-Host ""
    
    if ($Results.Count -eq 0) {
        Write-Host "No IoCs detected in the specified time period." -ForegroundColor Green
        return $null
    }
    
    $SortedResults = $Results | Sort-Object TimeCreated -Descending
    
    if ($Table) {
        return $SortedResults | Format-Table TimeCreated, EventID, Category, Severity, User, Source, Target, Computer -AutoSize
    } else {
        return $SortedResults
    }
}
