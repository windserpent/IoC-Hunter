# Run-AllTests.ps1
# Comprehensive test runner for IoC-Hunter module test suite

param(
    [switch]$QuickTest,
    [switch]$SkipStressTests,
    [string]$LogFile = "IoC-Hunter-TestResults-$(Get-Date -f 'yyyyMMdd_HHmmss').log"
)

# Redirect all output to log file and console
Start-Transcript -Path $LogFile -Append

Write-Host "=== IoC-Hunter Test Suite ===" -ForegroundColor Cyan
Write-Host "Comprehensive testing of IoC-Hunter module functionality" -ForegroundColor Gray
Write-Host "Log file: $LogFile" -ForegroundColor Gray
Write-Host ""

if ($QuickTest) {
    Write-Host "[INFO] Running in Quick Test mode (skipping stress tests)" -ForegroundColor Cyan
}

if ($SkipStressTests) {
    Write-Host "[INFO] Skipping stress tests as requested" -ForegroundColor Cyan
}

# Test file validation with enhanced null checking (Fix #6)
$testFiles = @("Test-ModuleBasics.ps1", "Test-IoCCategories.ps1", "Test-ScanModes.ps1", "Test-WorkflowIntegration.ps1", "Test-StressAndErrors.ps1")
$missingFiles = @()

foreach ($file in $testFiles) {
    if (-not (Test-Path $file)) {
        $missingFiles += $file
    } else {
        Write-Host "[PASS] $file found" -ForegroundColor Green
    }
}

# Enhanced null check for missing files (Fix #6)
if ($missingFiles -and $missingFiles.Count -gt 0) {
    Write-Host "[FAIL] Missing test files. Please ensure all test scripts are in the current directory:" -ForegroundColor Red
    foreach ($file in $missingFiles) {
        Write-Host "  - $file" -ForegroundColor Red
    }
    exit 1
}

Write-Host "[PASS] All test files found" -ForegroundColor Green

# Execution tracking
$startTime = Get-Date
$testResults = @()
$overallSuccess = $true

# Run each test
foreach ($testFile in $testFiles) {
    # Skip stress tests if requested
    if (($QuickTest -or $SkipStressTests) -and $testFile -eq "Test-StressAndErrors.ps1") {
        Write-Host ""
        Write-Host "[INFO] Skipping $testFile (QuickTest or SkipStressTests mode)" -ForegroundColor Cyan
        continue
    }
    
    Write-Host ""
    Write-Host "=== Running $testFile ===" -ForegroundColor Yellow
    
    $testStartTime = Get-Date
    
    try {
        # Run test script in separate PowerShell process to properly capture exit codes
        $process = Start-Process -FilePath "powershell.exe" -ArgumentList "-ExecutionPolicy", "Bypass", "-File", ".\$testFile" -Wait -PassThru -NoNewWindow -RedirectStandardOutput "$env:TEMP\test_output.tmp" -RedirectStandardError "$env:TEMP\test_error.tmp"
        $exitCode = $process.ExitCode
        
        # Display the output from the test
        if (Test-Path "$env:TEMP\test_output.tmp") {
            Get-Content "$env:TEMP\test_output.tmp" | ForEach-Object { Write-Host $_ }
            Remove-Item "$env:TEMP\test_output.tmp" -Force -ErrorAction SilentlyContinue
        }
        
        # Display any errors
        if (Test-Path "$env:TEMP\test_error.tmp") {
            $errorContent = Get-Content "$env:TEMP\test_error.tmp" -Raw
            if ($errorContent -and $errorContent.Trim()) {
                Write-Host $errorContent -ForegroundColor Red
            }
            Remove-Item "$env:TEMP\test_error.tmp" -Force -ErrorAction SilentlyContinue
        }
        
        $testEndTime = Get-Date
        $testDuration = $testEndTime - $testStartTime
        
        # CRITICAL: Properly handle exit codes to prevent false positives
        if ($exitCode -eq 0) {
            Write-Host "[PASS] $testFile completed successfully" -ForegroundColor Green
            $testResults += @{
                Name = $testFile.Replace('.ps1', '')
                Status = "PASS"
                Duration = $testDuration
                ExitCode = $exitCode
            }
        } else {
            Write-Host "[FAIL] $testFile failed with exit code $exitCode" -ForegroundColor Red
            $testResults += @{
                Name = $testFile.Replace('.ps1', '')
                Status = "FAIL"
                Duration = $testDuration
                ExitCode = $exitCode
            }
            $overallSuccess = $false  # Mark overall test suite as failed
        }
    } catch {
        $testEndTime = Get-Date
        $testDuration = $testEndTime - $testStartTime
        
        # Enhanced exception handling (Fix #2, #8)
        $errorMessage = "Unknown error"
        try {
            if ($_.Exception -and $_.Exception.Message) {
                $errorMessage = $_.Exception.Message
            } elseif ($_ -and $_.ToString()) {
                $errorMessage = $_.ToString()
            }
        } catch {
            $errorMessage = "Error details unavailable"
        }
        
        Write-Host "[FAIL] $testFile failed with exception: $errorMessage" -ForegroundColor Red
        $testResults += @{
            Name = $testFile.Replace('.ps1', '')
            Status = "FAIL"
            Duration = $testDuration
            ExitCode = -1
            Error = $errorMessage
        }
        $overallSuccess = $false  # Mark overall test suite as failed
    }
}

# Results summary
$endTime = Get-Date
$totalDuration = $endTime - $startTime

Write-Host ""
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "   Test Results Summary" -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host ""

# Enhanced null checking for test results (Fix #6)
$passCount = 0
$failCount = 0
$totalCount = 0

if ($testResults -and $testResults.Count -gt 0) {
    $passResults = $testResults | Where-Object { $_.Status -eq "PASS" }
    $failResults = $testResults | Where-Object { $_.Status -eq "FAIL" }
    
    $passCount = if ($passResults) { $passResults.Count } else { 0 }
    $failCount = if ($failResults) { $failResults.Count } else { 0 }
    $totalCount = $testResults.Count
} else {
    Write-Host "[WARN] No test results available for summary" -ForegroundColor Yellow
}

Write-Host "Test Results:" -ForegroundColor Cyan
Write-Host "  [PASS] Successful: $passCount" -ForegroundColor Green
Write-Host "  [FAIL] Failed: $failCount" -ForegroundColor Red
Write-Host "  [TOTAL] Total: $totalCount" -ForegroundColor Cyan
Write-Host ""

# Individual test timing with enhanced error handling (Fix #6, #8)
if ($testResults -and $testResults.Count -gt 0) {
    foreach ($result in $testResults) {
        try {
            $durationStr = "Unknown"
            if ($result.Duration) {
                $minutes = [math]::Floor($result.Duration.TotalMinutes)
                $seconds = $result.Duration.Seconds
                $durationStr = "${minutes}m ${seconds}s"
            }
            
            if ($result.Status -eq "PASS") {
                Write-Host "[PASS] $($result.Name) - $durationStr" -ForegroundColor Green
            } else {
                Write-Host "[FAIL] $($result.Name) - $durationStr" -ForegroundColor Red
                if ($result.Error) {
                    Write-Host "       Error: $($result.Error)" -ForegroundColor Red
                }
            }
        } catch {
            Write-Host "[WARN] Could not format result for $($result.Name)" -ForegroundColor Yellow
        }
    }
} else {
    Write-Host "[WARN] No individual test results to display" -ForegroundColor Yellow
}

Write-Host ""

# Overall timing
try {
    $totalMinutes = [math]::Floor($totalDuration.TotalMinutes)
    $totalSeconds = $totalDuration.Seconds
    Write-Host "Total execution time: ${totalMinutes}m ${totalSeconds}s" -ForegroundColor Cyan
} catch {
    Write-Host "Total execution time: Unable to calculate" -ForegroundColor Cyan
}

Write-Host ""

# Final result
if ($overallSuccess -and $failCount -eq 0) {
    Write-Host "[SUCCESS] ALL TESTS PASSED - IoC-Hunter is ready for production!" -ForegroundColor Green
    $finalExitCode = 0
} else {
    Write-Host "[FAILURE] $failCount test(s) failed - please review and fix issues" -ForegroundColor Red
    $finalExitCode = 1
}

Write-Host ""
Write-Host "======================================================" -ForegroundColor Cyan

# Performance recommendations
if ($testResults -and $testResults.Count -gt 0) {
    try {
        $slowTests = $testResults | Where-Object { $_.Duration -and $_.Duration.TotalMinutes -gt 2 }
        if ($slowTests -and $slowTests.Count -gt 0) {
            Write-Host ""
            Write-Host "Performance Notes:" -ForegroundColor Yellow
            foreach ($slowTest in $slowTests) {
                $slowMinutes = [math]::Round($slowTest.Duration.TotalMinutes, 1)
                Write-Host "  - $($slowTest.Name) took ${slowMinutes} minutes (consider optimizing if this is consistent)" -ForegroundColor Yellow
            }
        }
    } catch {
        Write-Host "[WARN] Could not analyze test performance" -ForegroundColor Yellow
    }
}

# Memory cleanup with enhanced error handling (Fix #2, #7)
try {
    # Clean up any remaining temporary files
    $tempFiles = @("$env:TEMP\test_output.tmp", "$env:TEMP\test_error.tmp")
    foreach ($tempFile in $tempFiles) {
        if (Test-Path $tempFile) {
            try {
                Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
            } catch {
                Write-Host "[WARN] Could not clean up temporary file: $tempFile" -ForegroundColor Yellow
            }
        }
    }
    
    # Force garbage collection
    [System.GC]::Collect()
} catch {
    Write-Host "[WARN] Cleanup operations failed: $_" -ForegroundColor Yellow
}

Stop-Transcript

Write-Host ""
Write-Host "Complete test results saved to: $LogFile" -ForegroundColor Cyan

# Exit with appropriate code
exit $finalExitCode
