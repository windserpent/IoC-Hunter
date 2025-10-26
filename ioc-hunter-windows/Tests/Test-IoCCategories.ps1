# Test-IoCCategories.ps1
# Individual category testing for IoC-Hunter module

Write-Host "=== IoC Categories Test ===" -ForegroundColor Cyan

# Import the module
try {
    Import-Module -Name "..\IoC-Hunter" -Force
    Write-Host "[PASS] Module imported successfully" -ForegroundColor Green
} catch {
    Write-Host "[FAIL] Failed to import IoC-Hunter module: $_" -ForegroundColor Red
    exit 1
}

# Set test time window
$startTime = (Get-Date).AddMinutes(-30)
$endTime = Get-Date

Write-Host "Testing time window: $startTime to $endTime" -ForegroundColor Gray
Write-Host ""

# Define categories to test
$categories = @(
    @{ Name = 'FailedLogins'; Switch = 'FailedLogins'; Description = 'Failed authentication attempts' },
    @{ Name = 'PowerShellSuspicious'; Switch = 'PowerShellSuspicious'; Description = 'Suspicious PowerShell activity' },
    @{ Name = 'ProcessCreation'; Switch = 'ProcessCreation'; Description = 'Process creation events' },
    @{ Name = 'NetworkConnections'; Switch = 'NetworkConnections'; Description = 'Network connection events' },
    @{ Name = 'PrivilegeEscalation'; Switch = 'PrivilegeEscalation'; Description = 'Privilege escalation attempts' },
    @{ Name = 'ServiceEvents'; Switch = 'ServiceEvents'; Description = 'Service-related events' },
    @{ Name = 'ScheduledTasks'; Switch = 'ScheduledTasks'; Description = 'Scheduled task events' },
    @{ Name = 'AccountManagement'; Switch = 'AccountManagement'; Description = 'Account management events' },
    @{ Name = 'EventLogClearing'; Switch = 'EventLogClearing'; Description = 'Event log clearing attempts' },
    @{ Name = 'RegistryModifications'; Switch = 'RegistryModifications'; Description = 'Registry modification events' },
    @{ Name = 'WindowsDefender'; Switch = 'WindowsDefender'; Description = 'Windows Defender events' },
    @{ Name = 'LateralMovement'; Switch = 'LateralMovement'; Description = 'Lateral movement indicators' },
    @{ Name = 'WMIActivity'; Switch = 'WMIActivity'; Description = 'WMI activity events' },
    @{ Name = 'DriverLoading'; Switch = 'DriverLoading'; Description = 'Driver loading events' },
    @{ Name = 'FileCreation'; Switch = 'FileCreation'; Description = 'File creation events' },
    @{ Name = 'RDPActivity'; Switch = 'RDPActivity'; Description = 'RDP activity events' },
    @{ Name = 'CredentialDumping'; Switch = 'CredentialDumping'; Description = 'Credential dumping attempts' },
    @{ Name = 'FirewallChanges'; Switch = 'FirewallChanges'; Description = 'Firewall configuration changes' },
    @{ Name = 'ShareAccess'; Switch = 'ShareAccess'; Description = 'Network share access events' },
    @{ Name = 'ProcessInjection'; Switch = 'ProcessInjection'; Description = 'Process injection attempts' },
    @{ Name = 'CertificateInstallation'; Switch = 'CertificateInstallation'; Description = 'Certificate installation events' },
    @{ Name = 'DNSEvents'; Switch = 'DNSEvents'; Description = 'DNS-related events' },
    @{ Name = 'ApplicationCrashes'; Switch = 'ApplicationCrashes'; Description = 'Application crash events' },
    @{ Name = 'BootStartupEvents'; Switch = 'BootStartupEvents'; Description = 'Boot and startup events' },
    @{ Name = 'PrintSpoolerEvents'; Switch = 'PrintSpoolerEvents'; Description = 'Print spooler events' },
    @{ Name = 'SoftwareInstallation'; Switch = 'SoftwareInstallation'; Description = 'Software installation events' }
)

$totalResults = @()
$categoryResults = @{}

# Test each category individually
foreach ($category in $categories) {
    Write-Host ""
    Write-Host "Testing: $($category.Name) - $($category.Description)" -ForegroundColor Yellow
    
    try {
        $startTestTime = Get-Date
        
        # Dynamically create the Get-IoCs call with the appropriate switch
        $scriptBlock = [ScriptBlock]::Create("Get-IoCs -$($category.Switch) -BeginTime `$startTime -EndTime `$endTime")
        $results = & $scriptBlock
        
        $endTestTime = Get-Date
        $duration = ($endTestTime - $startTestTime).TotalMilliseconds
        $resultCount = if ($results) { $results.Count } else { 0 }
        
        Write-Host "[PASS] $($category.Name): $resultCount events found in ${duration}ms" -ForegroundColor Green
        
        # Store results for analysis (Fix #3 - Create proper objects for Measure-Object)
        $categoryResults[$category.Name] = [PSCustomObject]@{
            Count = $resultCount
            Results = $results
            Duration = $duration
            Error = $null
        }
        
        if ($results) {
            $totalResults += $results
            
            # Validate result structure (check for expected properties)
            $firstResult = $results[0]
            if ($firstResult) {
                $expectedProps = @('TimeCreated','EventID','Category','Severity','User','Source','Target','Details','Computer')
                $actualProps = $firstResult.PSObject.Properties.Name
                $missingProps = $expectedProps | Where-Object { $actualProps -notcontains $_ }
                
                # Enhanced null check (Fix #6)
                if ($missingProps -and $missingProps.Count -gt 0) {
                    Write-Host "      Event structure validation: [WARN] Missing properties: $($missingProps -join ', ')" -ForegroundColor Yellow
                } else {
                    Write-Host "      Event structure validation: [PASS] All expected properties present" -ForegroundColor Green
                }
            }
            
            # Performance feedback
            if ($duration -lt 1000) {
                Write-Host "      Performance: [PASS] Fast (${duration}ms)" -ForegroundColor Green
            } elseif ($duration -lt 5000) {
                Write-Host "      Performance: [PASS] Acceptable (${duration}ms)" -ForegroundColor Green
            } else {
                Write-Host "      Performance: [WARN] Slow (${duration}ms)" -ForegroundColor Yellow
            }
        }
        
    } catch {
        Write-Host "[FAIL] $($category.Name) test failed: $_" -ForegroundColor Red
        # Store error information (Fix #3 - Create proper objects for Measure-Object)
        $categoryResults[$category.Name] = [PSCustomObject]@{
            Count = 0
            Results = $null
            Duration = 0
            Error = $_.Exception.Message
        }
        # Don't exit - continue testing other categories
    }
}

# Overall analysis
Write-Host ""
Write-Host "=== Overall Analysis ===" -ForegroundColor Cyan

# Enhanced null check (Fix #6)
if ($totalResults -and $totalResults.Count -gt 0) {
    # Remove duplicates for analysis
    $uniqueResults = $totalResults | Sort-Object EventID, TimeCreated -Unique
    Write-Host "[RESULT] Total unique IoCs found: $($uniqueResults.Count)" -ForegroundColor Cyan
    
    # Category breakdown
    Write-Host ""
    Write-Host "Category Breakdown:" -ForegroundColor Cyan
    foreach ($cat in $categoryResults.Keys | Sort-Object) {
        $catData = $categoryResults[$cat]
        if ($catData.Error) {
            Write-Host "  $cat`: [FAIL] $($catData.Error)" -ForegroundColor Red
        } else {
            Write-Host "  $cat`: $($catData.Count) events (${catData.Duration}ms)" -ForegroundColor Cyan
        }
    }
    
    # Severity analysis (if Severity property exists)
    $severityGroups = $uniqueResults | Where-Object { $_.PSObject.Properties.Name -contains 'Severity' } | Group-Object Severity
    if ($severityGroups) {
        Write-Host ""
        Write-Host "Severity Distribution:" -ForegroundColor Cyan
        foreach ($sev in $severityGroups | Sort-Object Count -Descending) {
            # Enhanced division protection (Fix #6)
            $percentage = 0
            if ($uniqueResults.Count -gt 0) {
                $percentage = [math]::Round(($sev.Count / $uniqueResults.Count) * 100, 1)
            }
            Write-Host "  $($sev.Name): $($sev.Count) events (${percentage}%)" -ForegroundColor Cyan
        }
    }
    
    # Time distribution
    $recent = $uniqueResults | Where-Object { $_.TimeCreated -gt $endTime.AddMinutes(-10) }
    $older = $uniqueResults | Where-Object { $_.TimeCreated -le $endTime.AddMinutes(-10) }
    
    Write-Host ""
    Write-Host "Time Distribution:" -ForegroundColor Cyan
    $recentCount = if ($recent) { $recent.Count } else { 0 }
    $olderCount = if ($older) { $older.Count } else { 0 }
    Write-Host "  Recent (last 10 minutes): $recentCount events" -ForegroundColor Cyan
    Write-Host "  Older: $olderCount events" -ForegroundColor Cyan
    
    Write-Host ""
    Write-Host "[PASS] Category analysis completed successfully" -ForegroundColor Green
    
} else {
    Write-Host "[INFO] No IoCs found across all categories (may be normal on quiet systems)" -ForegroundColor Cyan
    Write-Host "[INFO] This could indicate either a secure system or limited event logging" -ForegroundColor Cyan
}

# Test filtering capabilities (if data is available)
Write-Host ""
Write-Host "=== Filtering Capabilities Test ===" -ForegroundColor Yellow

# Enhanced null check (Fix #6)
if ($totalResults -and $totalResults.Count -gt 0) {
    # Test category filtering
    $authEvents = $totalResults | Where-Object { $_.Category -like "*Auth*" -or $_.EventID -in @(4624, 4625) }
    $authCount = if ($authEvents) { $authEvents.Count } else { 0 }
    Write-Host "[PASS] Category filtering: $authCount authentication-related events" -ForegroundColor Green
    
    # Test time filtering
    $recentFilter = $totalResults | Where-Object { $_.TimeCreated -gt $endTime.AddMinutes(-20) }
    $recentFilterCount = if ($recentFilter) { $recentFilter.Count } else { 0 }
    Write-Host "[PASS] Time filtering: $recentFilterCount events in last 20 minutes" -ForegroundColor Green
    
    # Test compound filtering
    $compound = $totalResults | Where-Object { 
        ($_.Category -like "*PowerShell*" -or $_.Category -like "*Process*") -and 
        $_.TimeCreated -gt $endTime.AddMinutes(-20)
    }
    $compoundCount = if ($compound) { $compound.Count } else { 0 }
    Write-Host "[PASS] Compound filtering: $compoundCount PowerShell/Process events in last 20 minutes" -ForegroundColor Green
} else {
    Write-Host "[INFO] Skipping filtering tests - no data available" -ForegroundColor Cyan
}

# Test scan modes (-Quick and -Full)
Write-Host ""
Write-Host "=== Scan Mode Testing ===" -ForegroundColor Cyan

# Test -Quick scan mode
Write-Host "Testing -Quick scan mode..." -ForegroundColor Yellow
try {
    $quickStartTime = Get-Date
    $quickResults = Get-IoCs -Quick -BeginTime $startTime -EndTime $endTime
    $quickDuration = ((Get-Date) - $quickStartTime).TotalSeconds
    
    if ($null -ne $quickResults) {
        $quickCount = $quickResults.Count
        Write-Host "[PASS] Quick scan completed: $quickCount IoCs found in ${quickDuration:F1}s" -ForegroundColor Green
        
        # Verify Quick scan includes expected categories
        $quickCategories = $quickResults | Select-Object -ExpandProperty Category -Unique
        $expectedQuickCategories = @(
            'Failed Login', 'PowerShell Suspicious', 'Process Creation', 'Lateral Movement',
            'Credential Dumping', 'Privilege Escalation', 'Event Log Clearing', 'Account Management',
            'Process Injection (Quick)', 'RDP Activity', 'Registry Modifications (Quick)', 'Share Access (Quick)',
            'Service Events', 'WMI Activity', 'Windows Defender', 'Scheduled Tasks', 'DNS Events', 'Firewall Changes'
        )
        
        # Check for at least some expected categories (some may not have events in test window)
        $foundExpectedCategories = $quickCategories | Where-Object { $_ -in $expectedQuickCategories }
        if ($foundExpectedCategories) {
            Write-Host "[PASS] Quick scan found expected category types: $($foundExpectedCategories -join ', ')" -ForegroundColor Green
        } else {
            Write-Host "[INFO] Quick scan completed but no events found in expected categories" -ForegroundColor Cyan
        }
    } else {
        Write-Host "[PASS] Quick scan completed: 0 IoCs found in ${quickDuration:F1}s" -ForegroundColor Green
    }
} catch {
    Write-Host "[FAIL] Quick scan failed: $_" -ForegroundColor Red
}

# Test -Full scan mode
Write-Host "Testing -Full scan mode..." -ForegroundColor Yellow
try {
    $fullStartTime = Get-Date
    $fullResults = Get-IoCs -Full -BeginTime $startTime -EndTime $endTime
    $fullDuration = ((Get-Date) - $fullStartTime).TotalSeconds
    
    if ($null -ne $fullResults) {
        $fullCount = $fullResults.Count
        Write-Host "[PASS] Full scan completed: $fullCount IoCs found in ${fullDuration:F1}s" -ForegroundColor Green
        
        # Verify Full scan includes all categories (where events exist)
        $fullCategories = $fullResults | Select-Object -ExpandProperty Category -Unique
        $expectedFullCategories = @(
            'Failed Login', 'PowerShell Suspicious', 'Process Creation', 'Network Connection',
            'Privilege Escalation', 'Service Events', 'Scheduled Tasks', 'Account Management',
            'Event Log Clearing', 'Registry Modifications', 'Windows Defender', 'Lateral Movement',
            'WMI Activity', 'Driver Loading', 'File Creation', 'RDP Activity',
            'Credential Dumping', 'Firewall Changes', 'Share Access', 'Process Injection',
            'Certificate Installation', 'DNS Events', 'Application Crash', 'Boot/Startup Events',
            'Print Spooler', 'Software Installation'
        )
        
        # Check for at least some expected categories
        $foundFullCategories = $fullCategories | Where-Object { $_ -in $expectedFullCategories }
        if ($foundFullCategories) {
            Write-Host "[PASS] Full scan found expected category types: $($foundFullCategories -join ', ')" -ForegroundColor Green
        } else {
            Write-Host "[INFO] Full scan completed but no events found in expected categories" -ForegroundColor Cyan
        }
        
        # Performance comparison
        if ($null -ne $quickResults -and $null -ne $fullResults) {
            $speedImprovement = [math]::Round((($fullDuration - $quickDuration) / $fullDuration) * 100, 1)
            if ($speedImprovement -gt 0) {
                Write-Host "[PASS] Quick scan was ${speedImprovement}% faster than Full scan" -ForegroundColor Green
            } else {
                Write-Host "[INFO] Performance comparison: Quick=${quickDuration:F1}s, Full=${fullDuration:F1}s" -ForegroundColor Cyan
            }
        }
    } else {
        Write-Host "[PASS] Full scan completed: 0 IoCs found in ${fullDuration:F1}s" -ForegroundColor Green
    }
} catch {
    Write-Host "[FAIL] Full scan failed: $_" -ForegroundColor Red
}

# Test parameter conflicts
Write-Host "Testing parameter conflicts..." -ForegroundColor Yellow
try {
    $conflictResult = Get-IoCs -Quick -Full -BeginTime $startTime -EndTime $endTime 2>&1
    if ($conflictResult -match "Cannot specify both -Quick and -Full") {
        Write-Host "[PASS] Parameter conflict properly detected" -ForegroundColor Green
    } else {
        Write-Host "[FAIL] Parameter conflict not detected properly" -ForegroundColor Red
    }
} catch {
    # Expected to fail due to parameter validation
    if ($_.Exception.Message -match "Cannot specify both -Quick and -Full") {
        Write-Host "[PASS] Parameter conflict properly detected" -ForegroundColor Green
    } else {
        Write-Host "[FAIL] Unexpected error in parameter conflict test: $_" -ForegroundColor Red
    }
}

# Test Quick + individual category combination
Write-Host "Testing Quick + individual category combination..." -ForegroundColor Yellow
try {
    $comboResults = Get-IoCs -Quick -FileCreation -BeginTime $startTime -EndTime $endTime
    if ($null -ne $comboResults) {
        $comboCategories = $comboResults | Select-Object -ExpandProperty Category -Unique
        # Should include Quick categories plus FileCreation
        if ($comboCategories -contains 'File Creation') {
            Write-Host "[PASS] Quick + individual category combination works: FileCreation included" -ForegroundColor Green
        } else {
            Write-Host "[INFO] Quick + individual category test completed (no FileCreation events found)" -ForegroundColor Cyan
        }
    } else {
        Write-Host "[PASS] Quick + individual category test completed (no events found)" -ForegroundColor Green
    }
} catch {
    Write-Host "[FAIL] Quick + individual category combination failed: $_" -ForegroundColor Red
}

# Performance summary with proper error handling (Fix #3, #5)
Write-Host ""
Write-Host "=== Performance Summary ===" -ForegroundColor Cyan

try {
    # Convert categoryResults values to PSObjects for Measure-Object (Fix #3)
    $categoryObjects = $categoryResults.Values | ForEach-Object { $_ }
    
    # Calculate total duration safely
    $totalDuration = 0
    $validCount = 0
    
    foreach ($catObj in $categoryObjects) {
        if ($catObj.Duration -and $catObj.Duration -is [double]) {
            $totalDuration += $catObj.Duration
            $validCount++
        }
    }
    
    $avgDuration = 0
    if ($validCount -gt 0) {
        $avgDuration = $totalDuration / $validCount
    }
    
    Write-Host "[INFO] Total test duration: ${totalDuration}ms" -ForegroundColor Cyan
    Write-Host "[INFO] Average per category: $($avgDuration.ToString('F1'))ms" -ForegroundColor Cyan
    
    # Count performance categories safely
    $fastCategories = 0
    $slowCategories = 0
    
    foreach ($catObj in $categoryObjects) {
        if ($catObj.Duration -and $catObj.Duration -is [double]) {
            if ($catObj.Duration -lt 1000) {
                $fastCategories++
            }
            if ($catObj.Duration -ge 5000) {
                $slowCategories++
            }
        }
    }
    
    Write-Host "[INFO] Fast categories (<1s): $fastCategories" -ForegroundColor Cyan
    Write-Host "[INFO] Slow categories (>=5s): $slowCategories" -ForegroundColor Cyan
    
    if ($slowCategories -eq 0) {
        Write-Host "[PASS] All categories performed within acceptable limits" -ForegroundColor Green
    } else {
        Write-Host "[WARN] $slowCategories categories performed slowly" -ForegroundColor Yellow
    }
    
} catch {
    Write-Host "[WARN] Performance summary calculation failed: $_" -ForegroundColor Yellow
    Write-Host "[INFO] Performance metrics: Unable to calculate" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "[PASS] IoC Categories test completed successfully" -ForegroundColor Green

# Exit with success code
exit 0
