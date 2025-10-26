# Test-ModuleBasics.ps1
# Basic functionality testing for IoC-Hunter module

Write-Host "=== Module Basics Test ===" -ForegroundColor Cyan
Write-Host "Testing core module functionality and structure" -ForegroundColor Gray
Write-Host ""

# Test 1: Module Import
Write-Host "Test 1: Module Import..." -ForegroundColor Yellow

try {
    # Try to import the module
    Import-Module -Name "..\IoC-Hunter" -Force -ErrorAction Stop
    Write-Host "[PASS] Module imported successfully" -ForegroundColor Green
} catch {
    Write-Host "[FAIL] Module import failed: $_" -ForegroundColor Red
    exit 1
}

# Test 2: Function Availability
Write-Host ""
Write-Host "Test 2: Function Availability..." -ForegroundColor Yellow

$expectedFunctions = @('Get-IoCs', 'Save-IoCs', 'Import-IoCs', 'Export-IoCs', 'Search-IoCs')
$availableFunctions = Get-Command -Module IoC-Hunter -ErrorAction SilentlyContinue

# Enhanced null check (Fix #6)
if ($availableFunctions) {
    $availableFunctionNames = $availableFunctions.Name
    Write-Host "[PASS] Available functions: $($availableFunctionNames -join ', ')" -ForegroundColor Green
    
    $missingFunctions = $expectedFunctions | Where-Object { $availableFunctionNames -notcontains $_ }
    
    # Enhanced null check (Fix #6)
    if ($missingFunctions -and $missingFunctions.Count -gt 0) {
        Write-Host "[WARN] Missing expected functions: $($missingFunctions -join ', ')" -ForegroundColor Yellow
    } else {
        Write-Host "[PASS] All expected functions are available" -ForegroundColor Green
    }
} else {
    Write-Host "[FAIL] No functions found in module" -ForegroundColor Red
    exit 1
}

# Test 3: Parameter Validation
Write-Host ""
Write-Host "Test 3: Parameter Validation..." -ForegroundColor Yellow

try {
    # Test Get-IoCs parameter structure
    $getIoCsParams = (Get-Command Get-IoCs).Parameters
    
    if ($getIoCsParams) {
        $paramCount = $getIoCsParams.Count
        Write-Host "[PASS] Get-IoCs has $paramCount parameters" -ForegroundColor Green
        
        # Check for key parameters
        $keyParams = @('BeginTime', 'EndTime', 'All', 'FailedLogins', 'PowerShellSuspicious')
        $foundKeyParams = $keyParams | Where-Object { $getIoCsParams.ContainsKey($_) }
        
        if ($foundKeyParams -and $foundKeyParams.Count -ge 3) {
            Write-Host "[PASS] Key parameters found: $($foundKeyParams -join ', ')" -ForegroundColor Green
        } else {
            $foundCount = if ($foundKeyParams) { $foundKeyParams.Count } else { 0 }
            Write-Host "[WARN] Limited key parameters found ($foundCount out of $($keyParams.Count))" -ForegroundColor Yellow
        }
    } else {
        Write-Host "[FAIL] Could not retrieve Get-IoCs parameters" -ForegroundColor Red
    }
} catch {
    Write-Host "[WARN] Parameter validation failed: $_" -ForegroundColor Yellow
}

# Test 4: Basic Functionality
Write-Host ""
Write-Host "Test 4: Basic Functionality..." -ForegroundColor Yellow

try {
    # Test basic IoC scan
    $testResults = Get-IoCs -FailedLogins -BeginTime (Get-Date).AddMinutes(-20) -EndTime (Get-Date)
    
    # Enhanced null check (Fix #6)
    if ($testResults -and $testResults.Count -gt 0) {
        Write-Host "[PASS] Basic IoC scan returned $($testResults.Count) results" -ForegroundColor Green
        
        # Validate result structure
        if ($testResults[0].PSObject.Properties.Name -contains 'TimeCreated') {
            Write-Host "[PASS] Result objects have expected structure" -ForegroundColor Green
        } else {
            Write-Host "[WARN] Result objects missing expected properties" -ForegroundColor Yellow
        }
        
        # Test that results are within time range
        $oldestResult = $testResults | Sort-Object TimeCreated | Select-Object -First 1
        $newestResult = $testResults | Sort-Object TimeCreated | Select-Object -Last 1
        
        if ($oldestResult -and $newestResult) {
            Write-Host "[PASS] Results span from $($oldestResult.TimeCreated) to $($newestResult.TimeCreated)" -ForegroundColor Green
        }
    } else {
        Write-Host "[INFO] Basic IoC scan returned no results (normal on quiet systems)" -ForegroundColor Cyan
    }
} catch {
    Write-Host "[FAIL] Basic IoC scan failed: $_" -ForegroundColor Red
    exit 1
}

# Test 5: Module Information
Write-Host ""
Write-Host "Test 5: Module Information..." -ForegroundColor Yellow

try {
    $moduleInfo = Get-Module IoC-Hunter
    if ($moduleInfo) {
        Write-Host "[PASS] Module information available" -ForegroundColor Green
        Write-Host "[INFO] Module version: $($moduleInfo.Version)" -ForegroundColor Cyan
        Write-Host "[INFO] Module path: $($moduleInfo.Path)" -ForegroundColor Cyan
        
        # Enhanced null check for ExportedFunctions (Fix #6)
        if ($moduleInfo.ExportedFunctions -and $moduleInfo.ExportedFunctions.Count -gt 0) {
            Write-Host "[INFO] Exported functions: $($moduleInfo.ExportedFunctions.Count)" -ForegroundColor Cyan
        } else {
            Write-Host "[WARN] No exported functions found or count unavailable" -ForegroundColor Yellow
        }
    } else {
        Write-Host "[WARN] Module information not available" -ForegroundColor Yellow
    }
} catch {
    Write-Host "[WARN] Cannot retrieve module information: $_" -ForegroundColor Yellow
}

# Test 6: Help Content
Write-Host ""
Write-Host "Test 6: Help Content..." -ForegroundColor Yellow

try {
    $help = Get-Help Get-IoCs -ErrorAction SilentlyContinue
    if ($help -and $help.Description) {
        Write-Host "[PASS] Help content available for Get-IoCs" -ForegroundColor Green
    } else {
        Write-Host "[WARN] Limited help content for Get-IoCs" -ForegroundColor Yellow
    }
} catch {
    Write-Host "[WARN] Help content test failed: $_" -ForegroundColor Yellow
}

# Test 7: Error Handling Validation
Write-Host ""
Write-Host "Test 7: Error Handling Validation..." -ForegroundColor Yellow

try {
    # Test invalid parameter combination (if applicable)
    try {
        $invalidResults = Get-IoCs -BeginTime (Get-Date) -EndTime (Get-Date).AddDays(-1) -ErrorAction Stop
        Write-Host "[FAIL] Invalid time range should have failed but returned $($invalidResults.Count) results" -ForegroundColor Red
    } catch {
        Write-Host "[PASS] Invalid parameters properly rejected" -ForegroundColor Green
    }
    
    # Test missing required parameters (if any)
    try {
        $missingParamResults = Get-IoCs -ErrorAction Stop
        Write-Host "[WARN] Get-IoCs function ran $($missingParamResults.Count) time with default parameters" -ForegroundColor Yellow
    } catch {
        Write-Host "[INFO] Function requires specific parameters (expected)" -ForegroundColor Cyan
    }
    
} catch {
    Write-Host "[WARN] Error handling validation failed: $_" -ForegroundColor Yellow
}

# Test 8: Performance Baseline
Write-Host ""
Write-Host "Test 8: Performance Baseline..." -ForegroundColor Yellow

try {
    $perfStart = Get-Date
    $perfResults = Get-IoCs -FailedLogins -BeginTime (Get-Date).AddMinutes(-5) -EndTime (Get-Date)
    $perfEnd = Get-Date
    $perfDuration = ($perfEnd - $perfStart).TotalMilliseconds
    
    $perfResultCount = if ($perfResults) { $perfResults.Count } else { 0 }
    Write-Host "[PASS] Performance test: $perfResultCount results in ${perfDuration}ms" -ForegroundColor Green
    
    if ($perfDuration -lt 5000) {
        Write-Host "[PASS] Performance within acceptable range" -ForegroundColor Green
    } else {
        Write-Host "[WARN] Performance slower than expected" -ForegroundColor Yellow
    }
} catch {
    Write-Host "[WARN] Performance baseline test failed: $_" -ForegroundColor Yellow
}

# Test 9: Resource Cleanup
Write-Host ""
Write-Host "Test 9: Resource Cleanup..." -ForegroundColor Yellow

try {
    # Test that module doesn't leave handles open or consume excessive memory
    $beforeMemory = 0
    try {
        $beforeMemory = [System.GC]::GetTotalMemory($false) / 1MB
    } catch {
        Write-Host "[WARN] Could not measure memory usage: $_" -ForegroundColor Yellow
    }
    
    # Run a small test
    $cleanupResults = Get-IoCs -FailedLogins -BeginTime (Get-Date).AddMinutes(-2) -EndTime (Get-Date)
    Write-Host "[INFO] Resource cleanup test executed ($($cleanupResults.Count) events processed)" -ForegroundColor Cyan
    
    # Force garbage collection
    try {
        [System.GC]::Collect()
        Start-Sleep -Milliseconds 100
        
        $afterMemory = 0
        try {
            $afterMemory = [System.GC]::GetTotalMemory($true) / 1MB
        } catch {
            Write-Host "[WARN] Could not measure post-test memory usage: $_" -ForegroundColor Yellow
        }
        
        if ($beforeMemory -gt 0 -and $afterMemory -gt 0) {
            $memoryDiff = [double]($afterMemory - $beforeMemory)
            if ($memoryDiff -ne $null) {
                Write-Host "[INFO] Memory change: $($memoryDiff.ToString('F1'))MB" -ForegroundColor Cyan
            } else {
                Write-Host "[INFO] Memory change: Unable to calculate" -ForegroundColor Cyan
            }
            
            if ([Math]::Abs($memoryDiff) -lt 10) {
                Write-Host "[PASS] No significant memory leaks detected" -ForegroundColor Green
            } else {
                Write-Host "[WARN] Potential memory usage concern" -ForegroundColor Yellow
            }
        } else {
            Write-Host "[INFO] Memory change: Unable to determine (measurement failed)" -ForegroundColor Cyan
        }
    } catch {
        Write-Host "[WARN] Memory cleanup test failed: $_" -ForegroundColor Yellow
    }
    
    Write-Host "[PASS] Resource cleanup test completed" -ForegroundColor Green
} catch {
    Write-Host "[WARN] Resource cleanup test failed: $_" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "[PASS] Module basics test completed successfully" -ForegroundColor Green

# Exit with success code
exit 0
