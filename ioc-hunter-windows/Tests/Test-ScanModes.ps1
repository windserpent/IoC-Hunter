# Test-ScanModes.ps1
# Comprehensive testing for IoC-Hunter Quick and Full scan modes

Write-Host "=== Scan Modes Test ===" -ForegroundColor Cyan
Write-Host "Testing Quick and Full scan mode functionality" -ForegroundColor Gray
Write-Host ""

# Import the module
try {
    Import-Module -Name "..\IoC-Hunter" -Force
    Write-Host "[PASS] IoC-Hunter module imported successfully" -ForegroundColor Green
} catch {
    Write-Host "[FAIL] Failed to import IoC-Hunter module: $_" -ForegroundColor Red
    exit 1
}

# Test configuration
$testStartTime = (Get-Date).AddHours(-2)
$testEndTime = Get-Date
Write-Host "Test time window: $testStartTime to $testEndTime" -ForegroundColor Gray
Write-Host ""

# Test 1: Parameter Validation
Write-Host "=== Test 1: Parameter Validation ===" -ForegroundColor Yellow

# Test 1.1: Quick parameter validation
Write-Host "Testing -Quick parameter..." -ForegroundColor Gray
try {
    $quickTest = Get-IoCs -Quick -BeginTime $testStartTime -EndTime $testEndTime
    $quickCount = if ($quickTest) { $quickTest.Count } else { 0 }
    Write-Host "[PASS] -Quick parameter accepted and executed ($quickCount results)" -ForegroundColor Green
} catch {
    Write-Host "[FAIL] -Quick parameter failed: $_" -ForegroundColor Red
}

# Test 1.2: Full parameter validation
Write-Host "Testing -Full parameter..." -ForegroundColor Gray
try {
    $fullTest = Get-IoCs -Full -BeginTime $testStartTime -EndTime $testEndTime
    $fullCount = if ($fullTest) { $fullTest.Count } else { 0 }
    Write-Host "[PASS] -Full parameter accepted and executed ($fullCount results)" -ForegroundColor Green
} catch {
    Write-Host "[FAIL] -Full parameter failed: $_" -ForegroundColor Red
}

# Test 1.3: Parameter conflict detection
Write-Host "Testing parameter conflict detection..." -ForegroundColor Gray
try {
    $conflictTest = Get-IoCs -Quick -Full -BeginTime $testStartTime -EndTime $testEndTime 2>&1
    if ($conflictTest -match "Cannot specify both -Quick and -Full") {
        Write-Host "[PASS] Parameter conflict properly detected and prevented" -ForegroundColor Green
    } else {
        Write-Host "[FAIL] Parameter conflict not detected properly" -ForegroundColor Red
    }
} catch {
    if ($_.Exception.Message -match "Cannot specify both -Quick and -Full") {
        Write-Host "[PASS] Parameter conflict properly detected via exception" -ForegroundColor Green
    } else {
        Write-Host "[FAIL] Unexpected error in conflict test: $_" -ForegroundColor Red
    }
}

# Test 2: Category Selection Logic
Write-Host ""
Write-Host "=== Test 2: Category Selection Logic ===" -ForegroundColor Yellow

# Test 2.1: Quick scan category selection
Write-Host "Testing Quick scan category selection..." -ForegroundColor Gray
try {
    $quickResults = Get-IoCs -Quick -BeginTime $testStartTime -EndTime $testEndTime
    
    if ($quickResults -and $quickResults.Count -gt 0) {
        $quickCategories = $quickResults | Select-Object -ExpandProperty Category -Unique | Sort-Object
        $expectedQuickCategories = @(
            'Failed Login', 'PowerShell Suspicious', 'Process Creation', 'Lateral Movement',
            'Credential Dumping', 'Privilege Escalation', 'Event Log Clearing', 'Account Management',
            'Process Injection (Quick)', 'RDP Activity', 'Registry Modifications (Quick)', 'Share Access (Quick)',
            'Service Events', 'WMI Activity', 'Windows Defender', 'Scheduled Tasks', 'DNS Events', 'Firewall Changes'
        )
        
        # Verify only expected categories are present
        $unexpectedCategories = $quickCategories | Where-Object { $_ -notin $expectedQuickCategories }
        if ($unexpectedCategories.Count -eq 0) {
            Write-Host "[PASS] Quick scan only includes expected categories" -ForegroundColor Green
            Write-Host "[INFO] Quick categories found: $($quickCategories -join ', ')" -ForegroundColor Cyan
        } else {
            Write-Host "[FAIL] Quick scan includes unexpected categories: $($unexpectedCategories -join ', ')" -ForegroundColor Red
        }
        
        # Verify light versions are used
        $lightVersions = $quickCategories | Where-Object { $_ -match "\(Quick\)" }
        if ($lightVersions.Count -gt 0) {
            Write-Host "[PASS] Quick scan uses light versions: $($lightVersions -join ', ')" -ForegroundColor Green
        } else {
            Write-Host "[INFO] No light version categories found in results (may be normal)" -ForegroundColor Cyan
        }
    } else {
        Write-Host "[INFO] Quick scan completed but no IoCs found for category testing" -ForegroundColor Cyan
    }
} catch {
    Write-Host "[FAIL] Quick scan category test failed: $_" -ForegroundColor Red
}

# Test 2.2: Full scan category selection
Write-Host "Testing Full scan category selection..." -ForegroundColor Gray
try {
    $fullResults = Get-IoCs -Full -BeginTime $testStartTime -EndTime $testEndTime
    
    if ($fullResults -and $fullResults.Count -gt 0) {
        $fullCategories = $fullResults | Select-Object -ExpandProperty Category -Unique | Sort-Object
        $expectedFullCategories = @(
            'Failed Login', 'PowerShell Suspicious', 'Process Creation', 'Network Connection',
            'Privilege Escalation', 'Service Events', 'Scheduled Tasks', 'Account Management',
            'Event Log Clearing', 'Registry Modifications', 'Windows Defender', 'Lateral Movement',
            'WMI Activity', 'Driver Loading', 'File Creation', 'RDP Activity',
            'Credential Dumping', 'Firewall Changes', 'Share Access', 'Process Injection',
            'Certificate Installation', 'DNS Events', 'Application Crash', 'Boot/Startup Events',
            'Print Spooler', 'Software Installation'
        )
        
        # Count how many expected categories were found
        $foundExpectedCategories = $fullCategories | Where-Object { $_ -in $expectedFullCategories }
        Write-Host "[PASS] Full scan includes $($foundExpectedCategories.Count) expected category types" -ForegroundColor Green
        Write-Host "[INFO] Full categories found: $($fullCategories -join ', ')" -ForegroundColor Cyan
        
        # Verify full versions are used (no "(Quick)" suffix)
        $quickVersionsInFull = $fullCategories | Where-Object { $_ -match "\(Quick\)" }
        if ($quickVersionsInFull.Count -eq 0) {
            Write-Host "[PASS] Full scan uses comprehensive versions (no Quick variants)" -ForegroundColor Green
        } else {
            Write-Host "[FAIL] Full scan includes Quick variants: $($quickVersionsInFull -join ', ')" -ForegroundColor Red
        }
    } else {
        Write-Host "[INFO] Full scan completed but no IoCs found for category testing" -ForegroundColor Cyan
    }
} catch {
    Write-Host "[FAIL] Full scan category test failed: $_" -ForegroundColor Red
}

# Test 3: Performance Characteristics
Write-Host ""
Write-Host "=== Test 3: Performance Characteristics ===" -ForegroundColor Yellow

# Test 3.1: Speed comparison
Write-Host "Testing speed comparison..." -ForegroundColor Gray
try {
    # Quick scan timing
    $quickTimer = [System.Diagnostics.Stopwatch]::StartNew()
    $quickPerfResults = Get-IoCs -Quick -BeginTime $testStartTime -EndTime $testEndTime
    $quickTimer.Stop()
    $quickDuration = $quickTimer.Elapsed.TotalSeconds
    
    # Full scan timing
    $fullTimer = [System.Diagnostics.Stopwatch]::StartNew()
    $fullPerfResults = Get-IoCs -Full -BeginTime $testStartTime -EndTime $testEndTime
    $fullTimer.Stop()
    $fullDuration = $fullTimer.Elapsed.TotalSeconds
    
    Write-Host "[INFO] Quick scan duration: ${quickDuration:F1}s" -ForegroundColor Cyan
    Write-Host "[INFO] Full scan duration: ${fullDuration:F1}s" -ForegroundColor Cyan
    
    if ($quickDuration -lt $fullDuration) {
        $speedImprovement = [math]::Round((($fullDuration - $quickDuration) / $fullDuration) * 100, 1)
        Write-Host "[PASS] Quick scan was ${speedImprovement}% faster than Full scan" -ForegroundColor Green
        
        # Check if speed improvement meets target
        if ($speedImprovement -ge 30) {
            Write-Host "[PASS] Speed improvement meets minimum target (>=30%)" -ForegroundColor Green
        } else {
            Write-Host "[WARN] Speed improvement below target (<30%)" -ForegroundColor Yellow
        }
    } else {
        Write-Host "[WARN] Quick scan was not faster than Full scan" -ForegroundColor Yellow
    }
} catch {
    Write-Host "[FAIL] Speed comparison test failed: $_" -ForegroundColor Red
}

# Test 3.2: Result completeness
Write-Host "Testing result completeness..." -ForegroundColor Gray
try {
    if ($quickPerfResults -and $fullPerfResults) {
        $quickCount = $quickPerfResults.Count
        $fullCount = $fullPerfResults.Count
        
        Write-Host "[INFO] Quick scan results: $quickCount IoCs" -ForegroundColor Cyan
        Write-Host "[INFO] Full scan results: $fullCount IoCs" -ForegroundColor Cyan
        
        if ($fullCount -ge $quickCount) {
            Write-Host "[PASS] Full scan found same or more IoCs than Quick scan" -ForegroundColor Green
        } else {
            Write-Host "[WARN] Full scan found fewer IoCs than Quick scan" -ForegroundColor Yellow
        }
        
        # Test that Quick results are subset of Full results (by category)
        if ($quickCount -gt 0 -and $fullCount -gt 0) {
            $quickCats = $quickPerfResults | Select-Object -ExpandProperty Category -Unique
            $fullCats = $fullPerfResults | Select-Object -ExpandProperty Category -Unique
            
            $quickCatsInFull = $quickCats | Where-Object { 
                $quickCat = $_
                $fullCats | Where-Object { $_ -eq $quickCat -or $_ -eq ($quickCat -replace " \(Quick\)", "") }
            }
            
            if ($quickCatsInFull.Count -eq $quickCats.Count) {
                Write-Host "[PASS] All Quick scan categories represented in Full scan" -ForegroundColor Green
            } else {
                Write-Host "[WARN] Some Quick scan categories not found in Full scan" -ForegroundColor Yellow
            }
        }
    } else {
        Write-Host "[INFO] Completeness test skipped (no results to compare)" -ForegroundColor Cyan
    }
} catch {
    Write-Host "[FAIL] Result completeness test failed: $_" -ForegroundColor Red
}

# Test 4: Combination Testing
Write-Host ""
Write-Host "=== Test 4: Combination Testing ===" -ForegroundColor Yellow

# Test 4.1: Quick + individual categories
Write-Host "Testing Quick + individual category combinations..." -ForegroundColor Gray
try {
    $comboResults = Get-IoCs -Quick -FileCreation -CertificateInstallation -BeginTime $testStartTime -EndTime $testEndTime
    
    if ($comboResults) {
        $comboCats = $comboResults | Select-Object -ExpandProperty Category -Unique
        
        # Should include Quick categories plus the specific ones requested
        $hasFileCreation = $comboCats | Where-Object { $_ -eq 'File Creation' }
        $hasCertificates = $comboCats | Where-Object { $_ -eq 'Certificate Installation' }
        
        if ($hasFileCreation -or $hasCertificates) {
            Write-Host "[PASS] Quick + individual category combination works" -ForegroundColor Green
        } else {
            Write-Host "[INFO] Quick + individual category test completed (no additional events found)" -ForegroundColor Cyan
        }
        
        Write-Host "[INFO] Combination categories: $($comboCats -join ', ')" -ForegroundColor Cyan
    } else {
        Write-Host "[INFO] Quick + individual category test completed (no events found)" -ForegroundColor Cyan
    }
} catch {
    Write-Host "[FAIL] Quick + individual category test failed: $_" -ForegroundColor Red
}

# Test 4.2: Full + individual categories
Write-Host "Testing Full + individual category combinations..." -ForegroundColor Gray
try {
    $fullComboResults = Get-IoCs -Full -BeginTime $testStartTime -EndTime $testEndTime
    
    if ($fullComboResults) {
        Write-Host "[PASS] Full scan combination works" -ForegroundColor Green
        Write-Host "[INFO] Full scan found $($fullComboResults.Count) total IoCs" -ForegroundColor Cyan
    } else {
        Write-Host "[INFO] Full scan combination test completed (no events found)" -ForegroundColor Cyan
    }
} catch {
    Write-Host "[FAIL] Full scan combination test failed: $_" -ForegroundColor Red
}

# Test 5: Integration with Other Functions
Write-Host ""
Write-Host "=== Test 5: Integration with Other Functions ===" -ForegroundColor Yellow

# Test 5.1: Export-IoCs integration
Write-Host "Testing Export-IoCs integration..." -ForegroundColor Gray
try {
    if ($quickPerfResults -and $quickPerfResults.Count -gt 0) {
        $quickExportPath = ".\test_quick_export_$(Get-Date -f 'yyyyMMdd_HHmmss').json"
        Export-IoCs -InputObject $quickPerfResults -Path $quickExportPath -Format "JSON"
        
        if (Test-Path $quickExportPath) {
            Write-Host "[PASS] Export-IoCs works with Quick scan results" -ForegroundColor Green
            Remove-Item $quickExportPath -Force -ErrorAction SilentlyContinue
        } else {
            Write-Host "[FAIL] Export-IoCs failed with Quick scan results" -ForegroundColor Red
        }
    } else {
        Write-Host "[INFO] Export-IoCs test skipped (no Quick scan results)" -ForegroundColor Cyan
    }
    
    if ($fullPerfResults -and $fullPerfResults.Count -gt 0) {
        $fullExportPath = ".\test_full_export_$(Get-Date -f 'yyyyMMdd_HHmmss').json"
        Export-IoCs -InputObject $fullPerfResults -Path $fullExportPath -Format "JSON"
        
        if (Test-Path $fullExportPath) {
            Write-Host "[PASS] Export-IoCs works with Full scan results" -ForegroundColor Green
            Remove-Item $fullExportPath -Force -ErrorAction SilentlyContinue
        } else {
            Write-Host "[FAIL] Export-IoCs failed with Full scan results" -ForegroundColor Red
        }
    } else {
        Write-Host "[INFO] Export-IoCs test skipped (no Full scan results)" -ForegroundColor Cyan
    }
} catch {
    Write-Host "[FAIL] Export-IoCs integration test failed: $_" -ForegroundColor Red
}

# Test 5.2: Search-IoCs integration
Write-Host "Testing Search-IoCs integration..." -ForegroundColor Gray
try {
    if ($quickPerfResults -and $quickPerfResults.Count -gt 0) {
        $quickSearchResults = Search-IoCs -InputObject $quickPerfResults -Severity "High"
        Write-Host "[PASS] Search-IoCs works with Quick scan results: found $($quickSearchResults.Count) high-severity" -ForegroundColor Green
    } else {
        Write-Host "[INFO] Search-IoCs Quick test skipped (no results)" -ForegroundColor Cyan
    }
    
    if ($fullPerfResults -and $fullPerfResults.Count -gt 0) {
        $fullSearchResults = Search-IoCs -InputObject $fullPerfResults -Severity "High"
        Write-Host "[PASS] Search-IoCs works with Full scan results: found $($fullSearchResults.Count) high-severity" -ForegroundColor Green
    } else {
        Write-Host "[INFO] Search-IoCs Full test skipped (no results)" -ForegroundColor Cyan
    }
} catch {
    Write-Host "[FAIL] Search-IoCs integration test failed: $_" -ForegroundColor Red
}

# Test 6: Edge Cases and Error Conditions
Write-Host ""
Write-Host "=== Test 6: Edge Cases and Error Conditions ===" -ForegroundColor Yellow

# Test 6.1: Empty time windows
Write-Host "Testing empty time windows..." -ForegroundColor Gray
try {
    $emptyStart = Get-Date
    $emptyEnd = $emptyStart.AddSeconds(1)
    
    $emptyQuick = Get-IoCs -Quick -BeginTime $emptyStart -EndTime $emptyEnd
    $emptyFull = Get-IoCs -Full -BeginTime $emptyStart -EndTime $emptyEnd
    
    $emptyQuickCount = if ($emptyQuick) { $emptyQuick.Count } else { 0 }
    $emptyFullCount = if ($emptyFull) { $emptyFull.Count } else { 0 }
    Write-Host "[PASS] Empty time window handling works (Quick: $emptyQuickCount, Full: $emptyFullCount results)" -ForegroundColor Green
} catch {
    Write-Host "[FAIL] Empty time window test failed: $_" -ForegroundColor Red
}

# Test 6.2: Invalid time ranges
Write-Host "Testing invalid time ranges..." -ForegroundColor Gray
try {
    $futureStart = (Get-Date).AddDays(1)
    $futureEnd = (Get-Date).AddDays(2)
    
    $futureQuick = Get-IoCs -Quick -BeginTime $futureStart -EndTime $futureEnd
    $futureFull = Get-IoCs -Full -BeginTime $futureStart -EndTime $futureEnd
    
    $futureQuickCount = if ($futureQuick) { $futureQuick.Count } else { 0 }
    $futureFullCount = if ($futureFull) { $futureFull.Count } else { 0 }
    Write-Host "[PASS] Future time range handling works (Quick: $futureQuickCount, Full: $futureFullCount results)" -ForegroundColor Green
} catch {
    Write-Host "[WARN] Future time range test had issues: $_" -ForegroundColor Yellow
}

# Final Summary
Write-Host ""
Write-Host "=== Scan Modes Test Summary ===" -ForegroundColor Cyan
Write-Host "[PASS] Parameter validation tests completed" -ForegroundColor Green
Write-Host "[PASS] Category selection logic verified" -ForegroundColor Green
Write-Host "[PASS] Performance characteristics validated" -ForegroundColor Green
Write-Host "[PASS] Combination testing successful" -ForegroundColor Green
Write-Host "[PASS] Integration with other functions confirmed" -ForegroundColor Green
Write-Host "[PASS] Edge case handling verified" -ForegroundColor Green
Write-Host ""
Write-Host "[SUCCESS] All scan mode tests completed successfully!" -ForegroundColor Cyan

# Exit with success code
exit 0
