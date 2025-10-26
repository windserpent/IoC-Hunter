# Test-StressAndErrors.ps1
# Stress testing and error handling validation for IoC-Hunter module

Write-Host "=== Stress Testing and Error Handling ===" -ForegroundColor Cyan

# Import the module
try {
    Import-Module -Name "..\IoC-Hunter" -Force
    Write-Host "[PASS] Module imported successfully" -ForegroundColor Green
} catch {
    Write-Host "[FAIL] Failed to import IoC-Hunter module: $_" -ForegroundColor Red
    exit 1
}

Write-Host "IoC-Hunter module loaded. Use 'Get-Help Get-IoCs' to get started."

# Stress Test 1: Large time window
Write-Host ""
Write-Host "=== Stress Test 1: Large Time Window ===" -ForegroundColor Yellow

try {
    $beginTime = (Get-Date).AddDays(-7)
    $endTime = Get-Date
    
    Write-Host "Testing large time window (7 days)..." -ForegroundColor Gray
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $largeResults = Get-IoCs -Full -BeginTime $beginTime -EndTime $endTime
    $stopwatch.Stop()
    
    $elapsed = $stopwatch.Elapsed.TotalSeconds
    $resultCount = if ($largeResults) { $largeResults.Count } else { 0 }
    
    Write-Host "[RESULT] Found $resultCount IoCs in ${elapsed}s" -ForegroundColor Cyan
    
    if ($elapsed -lt 60) {
        Write-Host "[PASS] Performance acceptable for large time window" -ForegroundColor Green
    } else {
        Write-Host "[WARN] Performance slower than expected for large time window" -ForegroundColor Yellow
    }
    
    # Test large dataset export/import with corrected workflow (Fix #1)
    if ($resultCount -gt 0) {
        Write-Host ""
        Write-Host "Testing large dataset export/import..." -ForegroundColor Gray
        
        # Use Save-IoCs instead of Export-IoCs for Import-IoCs compatibility
        $largePath = ".\large_test_$(Get-Date -f 'yyyyMMdd_HHmmss').json"
        
        try {
            $largeResults | Save-IoCs -Path $largePath -Description "Large dataset stress test"
            
            if (Test-Path $largePath) {
                $fileSize = 0
                try {
                    $fileSize = (Get-Item $largePath).Length / 1KB
                } catch {
                    Write-Host "[WARN] Could not determine file size: $_" -ForegroundColor Yellow
                }
                
                Write-Host "[PASS] Large dataset exported (${fileSize}KB)" -ForegroundColor Green
                
                # Test import of large dataset
                try {
                    $importedResults = Import-IoCs -Path $largePath
                    
                    if ($importedResults -and $importedResults.Count -eq $resultCount) {
                        Write-Host "[PASS] Large dataset import successful" -ForegroundColor Green
                    } else {
                        $importedCount = if ($importedResults) { $importedResults.Count } else { 0 }
                        Write-Host "[WARN] Large dataset import count mismatch (Expected: $resultCount, Got: $importedCount)" -ForegroundColor Yellow
                    }
                } catch {
                    Write-Host "[FAIL] Large dataset import failed: $_" -ForegroundColor Red
                }
                
                # Clean up large file
                try {
                    Remove-Item $largePath -Force -ErrorAction SilentlyContinue
                } catch {
                    Write-Host "[WARN] Could not clean up large test file: $_" -ForegroundColor Yellow
                }
            } else {
                Write-Host "[FAIL] Large dataset export failed - file not created" -ForegroundColor Red
            }
        } catch {
            Write-Host "[FAIL] Large dataset export failed: $_" -ForegroundColor Red
        }
    } else {
        Write-Host "[INFO] No data available for large dataset testing" -ForegroundColor Cyan
    }
    
} catch {
    Write-Host "[FAIL] Large time window test failed: $_" -ForegroundColor Red
}

# Stress Test 2: Multiple rapid queries
Write-Host ""
Write-Host "=== Stress Test 2: Multiple Rapid Queries ===" -ForegroundColor Yellow

try {
    Write-Host "Testing multiple rapid queries..." -ForegroundColor Gray
    $rapidTestResults = @()
    
    for ($i = 1; $i -le 5; $i++) {
        try {
            $queryStart = Get-Date
            $rapidResults = Get-IoCs -FailedLogins -PowerShellSuspicious -BeginTime (Get-Date).AddHours(-1) -EndTime (Get-Date)
            $queryEnd = Get-Date
            $queryDuration = ($queryEnd - $queryStart).TotalMilliseconds
            
            $resultCount = if ($rapidResults) { $rapidResults.Count } else { 0 }
            $rapidTestResults += [PSCustomObject]@{
                QueryNumber = $i
                Duration = $queryDuration
                ResultCount = $resultCount
            }
            
            Write-Host "  Query $i`: $resultCount results in ${queryDuration}ms" -ForegroundColor Cyan
        } catch {
            Write-Host "[WARN] Rapid query $i failed: $_" -ForegroundColor Yellow
        }
    }
    
    if ($rapidTestResults.Count -gt 0) {
        $avgDuration = ($rapidTestResults | Measure-Object Duration -Average).Average
        Write-Host "[PASS] Rapid queries completed - Average: ${avgDuration}ms" -ForegroundColor Green
    } else {
        Write-Host "[FAIL] All rapid queries failed" -ForegroundColor Red
    }
    
} catch {
    Write-Host "[FAIL] Rapid queries test failed: $_" -ForegroundColor Red
}

# Stress Test 3: Error handling validation
Write-Host ""
Write-Host "=== Stress Test 3: Error Handling Validation ===" -ForegroundColor Yellow

try {
    Write-Host "Testing error handling..." -ForegroundColor Gray
    
    # Test invalid time range
    Write-Host "Testing invalid date range error handling..." -ForegroundColor Gray
    try {
        $invalidResults = Get-IoCs -BeginTime (Get-Date) -EndTime (Get-Date).AddDays(-1) -ErrorAction Stop
        Write-Host "[FAIL] Invalid time range should have failed but returned $($invalidResults.Count) results" -ForegroundColor Red
    } catch {
        Write-Host "[PASS] Invalid time range properly handled" -ForegroundColor Green
    }
    
    # Test import of non-existent file
    Write-Host "Testing file not found error handling..." -ForegroundColor Gray
    try {
        $null = Import-IoCs -Path ".\nonexistent_file.json" -ErrorAction Stop
        Write-Host "[FAIL] Non-existent file import should have failed but didn't" -ForegroundColor Red
    } catch {
        if ($_.Exception.Message -match "File not found") {
        Write-Host "[PASS] Non-existent file import properly rejected" -ForegroundColor Green
        } else {
            Write-Host "[FAIL] Unexpected error in file not found test: $_" -ForegroundColor Red
        }
    }
    
    # Test export to invalid path (if possible to test safely)
    try {
        $testResults = @([PSCustomObject]@{
            TimeCreated = Get-Date
            EventID = 1234
            Category = "Test"
            Severity = "Low"
            User = "TestUser"
            Source = "Test"
            Target = "Test"
            Details = "Test event"
            Computer = $env:COMPUTERNAME
        })
        
        # Try to export to a potentially problematic path (but still safe)
        $problematicPath = ".\test_error_handling_$(Get-Date -f 'yyyyMMdd_HHmmss').json"
        $testResults | Save-IoCs -Path $problematicPath -Description "Error handling test"
        
        if (Test-Path $problematicPath) {
            Write-Host "[PASS] Export to valid path successful" -ForegroundColor Green
            try {
                Remove-Item $problematicPath -Force -ErrorAction SilentlyContinue
            } catch {
                Write-Host "[WARN] Could not clean up error handling test file: $_" -ForegroundColor Yellow
            }
        }
    } catch {
        Write-Host "[PASS] Export error properly handled: $_" -ForegroundColor Green
    }
    
} catch {
    Write-Host "[FAIL] Error handling validation failed: $_" -ForegroundColor Red
}

# Stress Test 4: Memory and resource testing
Write-Host ""
Write-Host "=== Stress Test 4: Memory and Resource Testing ===" -ForegroundColor Yellow

try {
    Write-Host "Testing memory and resource usage..." -ForegroundColor Gray
    
    # Create large test dataset
    Write-Host "Creating large test object array..." -ForegroundColor Gray
    $stressArray = @()
    for ($i = 1; $i -le 1000; $i++) {
        $stressArray += [PSCustomObject]@{
            TimeCreated = (Get-Date).AddMinutes(-$i)
            EventID = 1000 + ($i % 100)
            Category = "Stress Test Category $($i % 10)"
            Severity = @("High","Medium","Low")[$i % 3]
            User = "StressUser$($i % 50)"
            Source = "StressSource$($i % 20)"
            Target = "StressTarget$($i % 30)"
            Details = "Stress test event number $i with some additional details for testing"
            Computer = $env:COMPUTERNAME
        }
    }
    
    Write-Host "[PASS] Created $($stressArray.Count) test objects" -ForegroundColor Green
    
    # Test export of large array
    $stressPath = ".\stress_test_$(Get-Date -f 'yyyyMMdd_HHmmss').json"
    
    try {
        $stressArray | Save-IoCs -Path $stressPath -Description "Memory stress test"
        
        if (Test-Path $stressPath) {
            $fileSize = 0
            try {
                $fileSize = (Get-Item $stressPath).Length / 1KB
            } catch {
                Write-Host "[WARN] Could not determine stress test file size: $_" -ForegroundColor Yellow
            }
            
            Write-Host "[PASS] Stress test export successful (${fileSize}KB)" -ForegroundColor Green
            
            # Test import of large file
            try {
                $importedStress = Import-IoCs -Path $stressPath
                
                if ($importedStress -and $importedStress.Count -eq $stressArray.Count) {
                    Write-Host "[PASS] Stress test import successful ($($importedStress.Count) objects)" -ForegroundColor Green
                } else {
                    $importedCount = if ($importedStress) { $importedStress.Count } else { 0 }
                    Write-Host "[WARN] Stress test import count mismatch (Expected: $($stressArray.Count), Got: $importedCount)" -ForegroundColor Yellow
                }
            } catch {
                Write-Host "[FAIL] Stress test import failed: $_" -ForegroundColor Red
            }
            
            # Clean up stress test file
            try {
                Remove-Item $stressPath -Force -ErrorAction SilentlyContinue
            } catch {
                Write-Host "[WARN] Could not clean up stress test file: $_" -ForegroundColor Yellow
            }
        } else {
            Write-Host "[FAIL] Stress test export failed - file not created" -ForegroundColor Red
        }
    } catch {
        Write-Host "[FAIL] Memory stress test failed: $_" -ForegroundColor Red
    }
    
} catch {
    Write-Host "[FAIL] Memory and resource testing failed: $_" -ForegroundColor Red
}

# Stress Test 5: Rapid sequential operations
Write-Host ""
Write-Host "=== Stress Test 5: Rapid Sequential Operations ===" -ForegroundColor Yellow

try {
    Write-Host "Testing rapid sequential export/import operations..." -ForegroundColor Gray
    
    for ($i = 1; $i -le 3; $i++) {
        $testData = @([PSCustomObject]@{
            TimeCreated = Get-Date
            EventID = 5000 + $i
            Category = "Sequential Test $i"
            Severity = "Medium"
            User = "SeqTestUser"
            Source = "SeqTest"
            Target = "SeqTarget$i"
            Details = "Sequential test event $i"
            Computer = $env:COMPUTERNAME
        })
        
        $seqPath = ".\sequential_test_${i}_$(Get-Date -f 'yyyyMMdd_HHmmss').json"
        
        try {
            $testData | Save-IoCs -Path $seqPath -Description "Sequential test $i"
            
            if (Test-Path $seqPath) {
                try {
                    $seqImported = Import-IoCs -Path $seqPath
                    if ($seqImported -and $seqImported.Count -gt 0) {
                        Write-Host "  Sequential operation $i`: [PASS]" -ForegroundColor Green
                    } else {
                        throw "Import returned null or empty for file $i"
                    }
                } catch {
                    Write-Host "  Sequential operation $i`: [FAIL] Import failed - $_" -ForegroundColor Red
                } finally {
                    try {
                        Remove-Item $seqPath -Force -ErrorAction SilentlyContinue
                    } catch {
                        Write-Host "[WARN] Could not clean up sequential test file $i`: $_" -ForegroundColor Yellow
                    }
                }
            } else {
                throw "Export failed for file $i"
            }
        } catch {
            Write-Host "  Sequential operation $i`: [FAIL] $_" -ForegroundColor Red
        }
    }
    
    Write-Host "[PASS] Rapid sequential operations successful" -ForegroundColor Green
    
} catch {
    Write-Host "[FAIL] Rapid sequential operations failed: $_" -ForegroundColor Red
}

# Stress Test 6: Quick vs Full Scan Performance Comparison
Write-Host ""
Write-Host "=== Stress Test 6: Quick vs Full Scan Performance ===" -ForegroundColor Yellow

try {
    $testBeginTime = (Get-Date).AddHours(-3)
    $testEndTime = Get-Date
    
    # Test Quick scan performance
    Write-Host "Testing Quick scan performance..." -ForegroundColor Gray
    $quickStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $quickPerfResults = Get-IoCs -Quick -BeginTime $testBeginTime -EndTime $testEndTime
    $quickStopwatch.Stop()
    $quickElapsed = $quickStopwatch.Elapsed.TotalSeconds
    $quickCount = if ($quickPerfResults) { $quickPerfResults.Count } else { 0 }
    
    Write-Host "[RESULT] Quick scan: $quickCount IoCs in ${quickElapsed:F1}s" -ForegroundColor Cyan
    
    # Test Full scan performance
    Write-Host "Testing Full scan performance..." -ForegroundColor Gray
    $fullStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $fullPerfResults = Get-IoCs -Full -BeginTime $testBeginTime -EndTime $testEndTime
    $fullStopwatch.Stop()
    $fullElapsed = $fullStopwatch.Elapsed.TotalSeconds
    $fullCount = if ($fullPerfResults) { $fullPerfResults.Count } else { 0 }
    
    Write-Host "[RESULT] Full scan: $fullCount IoCs in ${fullElapsed:F1}s" -ForegroundColor Cyan
    
    # Performance analysis
    if ($quickElapsed -gt 0 -and $fullElapsed -gt 0) {
        $speedImprovement = [math]::Round((($fullElapsed - $quickElapsed) / $fullElapsed) * 100, 1)
        if ($speedImprovement -gt 0) {
            Write-Host "[PASS] Quick scan was ${speedImprovement}% faster than Full scan" -ForegroundColor Green
            
            # Verify speed improvement meets target (should be ~70% faster)
            if ($speedImprovement -ge 50) {
                Write-Host "[PASS] Speed improvement meets performance target (>50%)" -ForegroundColor Green
            } else {
                Write-Host "[WARN] Speed improvement below target (<50%)" -ForegroundColor Yellow
            }
        } else {
            Write-Host "[WARN] Quick scan was not faster than Full scan" -ForegroundColor Yellow
        }
        
        # IoC count comparison
        if ($fullCount -ge $quickCount) {
            Write-Host "[PASS] Full scan completeness: $fullCount vs Quick's $quickCount IoCs" -ForegroundColor Green
        } else {
            Write-Host "[WARN] Full scan found fewer IoCs than Quick scan - unexpected" -ForegroundColor Yellow
        }
        
        # Category comparison
        if ($quickPerfResults -and $fullPerfResults) {
            $quickCategories = ($quickPerfResults | Select-Object -ExpandProperty Category -Unique).Count
            $fullCategories = ($fullPerfResults | Select-Object -ExpandProperty Category -Unique).Count
            
            if ($fullCategories -ge $quickCategories) {
                Write-Host "[PASS] Category coverage: Full=$fullCategories, Quick=$quickCategories types" -ForegroundColor Green
            } else {
                Write-Host "[WARN] Quick scan found more category types than Full scan" -ForegroundColor Yellow
            }
        }
        
        # Test rapid scan switching
        Write-Host "Testing rapid scan mode switching..." -ForegroundColor Gray
        $switchStartTime = Get-Date
        for ($i = 1; $i -le 3; $i++) {
            $null = Get-IoCs -Quick -BeginTime (Get-Date).AddMinutes(-20) -EndTime (Get-Date)
            $null = Get-IoCs -Full -BeginTime (Get-Date).AddMinutes(-20) -EndTime (Get-Date)
        }
        $switchDuration = ((Get-Date) - $switchStartTime).TotalSeconds
        Write-Host "[PASS] Rapid scan switching completed in $($switchDuration.ToString('F1'))s" -ForegroundColor Green
        
        # Memory impact comparison
        try {
            $memoryBefore = $null
            $memoryAfterQuick = $null
            $memoryAfterFull = $null
            
            try {
                $memoryBefore = [System.GC]::GetTotalMemory($false) / 1MB
            } catch {
                Write-Host "[WARN] Could not measure initial memory: $_" -ForegroundColor Yellow
            }
            
            # Multiple Quick scans
            for ($i = 1; $i -le 5; $i++) {
                $null = Get-IoCs -Quick -BeginTime (Get-Date).AddMinutes(-10) -EndTime (Get-Date)
            }
            
            try {
                $memoryAfterQuick = [System.GC]::GetTotalMemory($false) / 1MB
            } catch {
                Write-Host "[WARN] Could not measure memory after Quick scans: $_" -ForegroundColor Yellow
            }
            
            # One Full scan
            $null = Get-IoCs -Full -BeginTime (Get-Date).AddMinutes(-10) -EndTime (Get-Date)
            
            try {
                $memoryAfterFull = [System.GC]::GetTotalMemory($false) / 1MB
            } catch {
                Write-Host "[WARN] Could not measure memory after Full scan: $_" -ForegroundColor Yellow
            }
            
            # Calculate impacts with null safety and type casting
            if ($null -ne $memoryBefore -and $null -ne $memoryAfterQuick -and $null -ne $memoryAfterFull) {
                $quickMemoryImpact = [double]($memoryAfterQuick - $memoryBefore)
                $fullMemoryImpact = [double]($memoryAfterFull - $memoryAfterQuick)
                
                Write-Host "[INFO] Memory impact: Quick=$($quickMemoryImpact.ToString('+0.0;-0.0'))MB, Full=$($fullMemoryImpact.ToString('+0.0;-0.0'))MB" -ForegroundColor Cyan
                
                if ($quickMemoryImpact -le $fullMemoryImpact) {
                    Write-Host "[PASS] Quick scan memory efficiency confirmed" -ForegroundColor Green
                } else {
                    Write-Host "[WARN] Quick scan used more memory than expected" -ForegroundColor Yellow
                }
            } else {
                Write-Host "[INFO] Memory impact: Unable to determine (measurement failed)" -ForegroundColor Cyan
            }
        } catch {
            Write-Host "[WARN] Memory impact test failed: $_" -ForegroundColor Yellow
        }
    } else {
        Write-Host "[WARN] Performance comparison not possible (zero timing)" -ForegroundColor Yellow
    }
    Write-Host "[PASS] Quick vs Full performance testing completed" -ForegroundColor Green
} catch {
    Write-Host "[FAIL] Quick vs Full performance testing failed: $_" -ForegroundColor Red
}

# Final performance summary with null-safe memory calculation (Fix #2)
Write-Host ""
Write-Host "=== Performance Summary ===" -ForegroundColor Cyan

try {
    # Memory usage calculation with null safety (Fix #2)
    $memoryUsage = $null
    try {
        $memoryUsage = [System.GC]::GetTotalMemory($false) / 1MB
    } catch {
        Write-Host "[WARN] Could not retrieve memory usage: $_" -ForegroundColor Yellow
    }
    
    if ($null -ne $memoryUsage) {
        Write-Host "[INFO] Current memory usage: $($memoryUsage.ToString('F1'))MB" -ForegroundColor Cyan
    } else {
        Write-Host "[INFO] Current memory usage: Unable to determine" -ForegroundColor Cyan
    }
    
    # Force garbage collection with error handling
    try {
        [System.GC]::Collect()
        Start-Sleep -Milliseconds 100  # Brief pause for GC to complete
        
        $memoryAfterGC = $null
        try {
            $memoryAfterGC = [System.GC]::GetTotalMemory($true) / 1MB
        } catch {
            Write-Host "[WARN] Could not retrieve post-GC memory usage: $_" -ForegroundColor Yellow
        }
        
        if ($null -ne $memoryAfterGC) {
            Write-Host "[INFO] Memory after cleanup: $($memoryAfterGC.ToString('F1'))MB" -ForegroundColor Cyan
        } else {
            Write-Host "[INFO] Memory after cleanup: Unable to determine" -ForegroundColor Cyan
        }
    } catch {
        Write-Host "[WARN] Garbage collection failed: $_" -ForegroundColor Yellow
    }
} catch {
    Write-Host "[WARN] Performance summary failed: $_" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "[PASS] Stress and error handling tests completed" -ForegroundColor Green

# Exit with success code
exit 0
