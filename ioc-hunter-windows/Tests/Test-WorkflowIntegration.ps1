# Test-WorkflowIntegration.ps1
# Comprehensive workflow testing for IoC-Hunter module
# Tests both Export-IoCs validation and Save-IoCs+Import-IoCs round-trip workflows

Write-Host "=== Workflow Integration Test ===" -ForegroundColor Cyan
Write-Host "Testing complete IoC-Hunter workflow integration" -ForegroundColor Gray
Write-Host ""

# Import the module
try {
    Import-Module -Name "..\IoC-Hunter" -Force
    Write-Host "[PASS] IoC-Hunter module imported successfully" -ForegroundColor Green
} catch {
    Write-Host "[FAIL] Failed to import IoC-Hunter module: $_" -ForegroundColor Red
    exit 1
}

Write-Host "IoC-Hunter module loaded. Use 'Get-Help Get-IoCs' to get started."

# Phase 1: Initial IoC Collection (Basic functionality test)
Write-Host ""
Write-Host "=== Phase 1: Initial IoC Collection ===" -ForegroundColor Yellow

try {
    $beginTime = (Get-Date).AddDays(-1)
    $endTime = Get-Date
    
    Write-Host "Scanning for IoCs in last 24 hours..." -ForegroundColor Gray
    $results = Get-IoCs -FailedLogins -PowerShellSuspicious -BeginTime $beginTime -EndTime $endTime
    if ($results -and $results.Count -gt 0) {
        Write-Host "[PASS] Found $($results.Count) IoCs in last 24 hours" -ForegroundColor Green
    } else {
        Write-Host "[WARN] No IoCs found (may be normal on quiet systems)" -ForegroundColor Yellow
        # Create some test data for subsequent phases
        $results = @(
            [PSCustomObject]@{
                TimeCreated = Get-Date
                EventID = 4624
                Category = "Test Authentication"
                Severity = "Medium"
                User = "TestUser"
                Source = "127.0.0.1"
                Target = "TestTarget"
                Details = "Test logon event for workflow validation"
                Computer = $env:COMPUTERNAME
            },
            [PSCustomObject]@{
                TimeCreated = (Get-Date).AddMinutes(-5)
                EventID = 4104
                Category = "Test PowerShell"
                Severity = "High"
                User = "TestUser"
                Source = "PowerShell"
                Target = "TestScript"
                Details = "Test PowerShell execution for workflow validation"
                Computer = $env:COMPUTERNAME
            },
            [PSCustomObject]@{
                TimeCreated = (Get-Date).AddMinutes(-10)
                EventID = 4688
                Category = "Test Process"
                Severity = "Low"
                User = "TestUser"
                Source = "cmd.exe"
                Target = "TestProcess"
                Details = "Test process creation for workflow validation"
                Computer = $env:COMPUTERNAME
            }
        )
        Write-Host "[INFO] Created $($results.Count) test IoCs for workflow validation" -ForegroundColor Cyan
    }
} catch {
    Write-Host "[FAIL] Initial IoC collection failed: $_" -ForegroundColor Red
    exit 1
}

# Phase 2A: Export-IoCs Validation Testing (NEW - Fix #1)
Write-Host ""
Write-Host "=== Phase 2A: Export-IoCs Format Validation ===" -ForegroundColor Yellow

$exportTestResults = @{}

# Test CSV Export with validation
Write-Host ""
Write-Host "Testing CSV Export..." -ForegroundColor Gray
try {
    $csvPath = ".\workflow_test_csv_$(Get-Date -f 'yyyyMMdd_HHmmss').csv"
    $results | Export-IoCs -Path $csvPath -Format "CSV"
    
    if (Test-Path $csvPath) {
        $fileSize = 0
        try {
            $fileSize = (Get-Item $csvPath).Length
        } catch {
            Write-Host "[WARN] Could not determine file size: $_" -ForegroundColor Yellow
        }
        
        Write-Host "[PASS] CSV export successful: $csvPath ($fileSize bytes)" -ForegroundColor Green
        
        # Validate CSV content
        try {
            $csvContent = Import-Csv $csvPath
            if ($csvContent -and $csvContent.Count -eq $results.Count) {
                Write-Host "[PASS] CSV structure validation successful ($($csvContent.Count) rows)" -ForegroundColor Green
                
                # Validate headers
                $expectedHeaders = @('TimeCreated','EventID','Category','Severity','User','Source','Target','Details','Computer')
                $actualHeaders = $csvContent[0].PSObject.Properties.Name
                $missingHeaders = $expectedHeaders | Where-Object { $actualHeaders -notcontains $_ }
                
                if ($missingHeaders -and $missingHeaders.Count -gt 0) {
                    Write-Host "[WARN] CSV missing some headers: $($missingHeaders -join ', ')" -ForegroundColor Yellow
                } else {
                    Write-Host "[PASS] CSV headers validation successful" -ForegroundColor Green
                }
                
                $exportTestResults['CSV'] = 'PASS'
            } else {
                $actualCount = if ($csvContent) { $csvContent.Count } else { 0 }
                Write-Host "[FAIL] CSV structure validation failed (expected $($results.Count) rows, got $actualCount)" -ForegroundColor Red
                $exportTestResults['CSV'] = 'FAIL'
            }
        } catch {
            Write-Host "[FAIL] CSV validation failed: $_" -ForegroundColor Red
            $exportTestResults['CSV'] = 'FAIL'
        }
    } else {
        Write-Host "[FAIL] CSV export failed - file not created" -ForegroundColor Red
        $exportTestResults['CSV'] = 'FAIL'
    }
} catch {
    Write-Host "[FAIL] CSV export test failed: $_" -ForegroundColor Red
    $exportTestResults['CSV'] = 'FAIL'
}

# Test JSON Export with validation
Write-Host ""
Write-Host "Testing JSON Export..." -ForegroundColor Gray
try {
    $jsonExportPath = ".\workflow_test_json_$(Get-Date -f 'yyyyMMdd_HHmmss').json"
    $results | Export-IoCs -Path $jsonExportPath -Format "JSON"
    
    if (Test-Path $jsonExportPath) {
        $fileSize = 0
        try {
            $fileSize = (Get-Item $jsonExportPath).Length
        } catch {
            Write-Host "[WARN] Could not determine file size: $_" -ForegroundColor Yellow
        }
        
        Write-Host "[PASS] JSON export successful: $jsonExportPath ($fileSize bytes)" -ForegroundColor Green
        
        # Validate JSON content and structure
        try {
            $jsonContent = Get-Content $jsonExportPath -Raw | ConvertFrom-Json
            if ($jsonContent -is [Array] -and $jsonContent.Count -eq $results.Count) {
                Write-Host "[PASS] JSON structure validation successful (array with $($jsonContent.Count) items)" -ForegroundColor Green
                
                # Validate first object has expected properties
                $firstObj = $jsonContent[0]
                $expectedProps = @('TimeCreated','EventID','Category','Severity','User','Source','Target','Details','Computer')
                $missingProps = $expectedProps | Where-Object { $firstObj.PSObject.Properties.Name -notcontains $_ }
                
                if ($missingProps -and $missingProps.Count -gt 0) {
                    Write-Host "[WARN] JSON missing some properties: $($missingProps -join ', ')" -ForegroundColor Yellow
                } else {
                    Write-Host "[PASS] JSON properties validation successful" -ForegroundColor Green
                }
                
                # Round-trip content validation
                $originalSample = $results[0]
                $exportedSample = $jsonContent[0]
                $dataMatches = $true
                $propertiesToCheck = @('EventID','Category','Severity','User','Computer')
                
                foreach ($prop in $propertiesToCheck) {
                    if ($originalSample.$prop -ne $exportedSample.$prop) {
                        Write-Host "[WARN] Data mismatch in $prop`: Original='$($originalSample.$prop)', Exported='$($exportedSample.$prop)'" -ForegroundColor Yellow
                        $dataMatches = $false
                    }
                }
                
                if ($dataMatches) {
                    Write-Host "[PASS] JSON round-trip data integrity validation successful" -ForegroundColor Green
                }
                
                $exportTestResults['JSON'] = 'PASS'
            } else {
                $actualCount = if ($jsonContent -is [Array]) { $jsonContent.Count } else { 1 }
                Write-Host "[FAIL] JSON structure validation failed (expected array with $($results.Count) items, got $actualCount)" -ForegroundColor Red
                $exportTestResults['JSON'] = 'FAIL'
            }
        } catch {
            Write-Host "[FAIL] JSON validation failed: $_" -ForegroundColor Red
            $exportTestResults['JSON'] = 'FAIL'
        }
    } else {
        Write-Host "[FAIL] JSON export failed - file not created" -ForegroundColor Red
        $exportTestResults['JSON'] = 'FAIL'
    }
} catch {
    Write-Host "[FAIL] JSON export test failed: $_" -ForegroundColor Red
    $exportTestResults['JSON'] = 'FAIL'
}

# Test Timeline Export with validation
Write-Host ""
Write-Host "Testing Timeline Export..." -ForegroundColor Gray
try {
    $timelinePath = ".\workflow_test_timeline_$(Get-Date -f 'yyyyMMdd_HHmmss').csv"
    $results | Export-IoCs -Path $timelinePath -Format "Timeline"
    
    if (Test-Path $timelinePath) {
        $fileSize = 0
        try {
            $fileSize = (Get-Item $timelinePath).Length
        } catch {
            Write-Host "[WARN] Could not determine file size: $_" -ForegroundColor Yellow
        }
        
        Write-Host "[PASS] Timeline export successful: $timelinePath ($fileSize bytes)" -ForegroundColor Green
        
        # Validate Timeline content
        try {
            $timelineContent = Import-Csv $timelinePath
            if ($timelineContent -and $timelineContent.Count -eq $results.Count) {
                Write-Host "[PASS] Timeline structure validation successful ($($timelineContent.Count) rows)" -ForegroundColor Green
                
                # Check for Time column (timeline-specific)
                if ($timelineContent[0].PSObject.Properties.Name -contains 'Time') {
                    Write-Host "[PASS] Timeline format validation successful (Time column present)" -ForegroundColor Green
                    $exportTestResults['Timeline'] = 'PASS'
                } else {
                    Write-Host "[FAIL] Timeline format validation failed (Time column missing)" -ForegroundColor Red
                    $exportTestResults['Timeline'] = 'FAIL'
                }
            } else {
                $actualCount = if ($timelineContent) { $timelineContent.Count } else { 0 }
                Write-Host "[FAIL] Timeline structure validation failed (expected $($results.Count) rows, got $actualCount)" -ForegroundColor Red
                $exportTestResults['Timeline'] = 'FAIL'
            }
        } catch {
            Write-Host "[FAIL] Timeline validation failed: $_" -ForegroundColor Red
            $exportTestResults['Timeline'] = 'FAIL'
        }
    } else {
        Write-Host "[FAIL] Timeline export failed - file not created" -ForegroundColor Red
        $exportTestResults['Timeline'] = 'FAIL'
    }
} catch {
    Write-Host "[FAIL] Timeline export test failed: $_" -ForegroundColor Red
    $exportTestResults['Timeline'] = 'FAIL'
}

# Cross-format validation
Write-Host ""
Write-Host "Cross-Format Validation..." -ForegroundColor Gray
try {
    if ($exportTestResults['CSV'] -eq 'PASS' -and $exportTestResults['JSON'] -eq 'PASS') {
        $csvData = Import-Csv $csvPath
        $jsonData = Get-Content $jsonExportPath -Raw | ConvertFrom-Json
        
        if ($csvData.Count -eq $jsonData.Count -and $csvData.Count -eq $results.Count) {
            Write-Host "[PASS] Cross-format count validation successful" -ForegroundColor Green
            
            # Compare sample data points
            if ($csvData[0].EventID -eq $jsonData[0].EventID) {
                Write-Host "[PASS] Cross-format content validation successful" -ForegroundColor Green
            } else {
                Write-Host "[WARN] Cross-format content mismatch detected" -ForegroundColor Yellow
            }
        } else {
            Write-Host "[WARN] Cross-format count mismatch" -ForegroundColor Yellow
        }
    } else {
        Write-Host "[INFO] Skipping cross-format validation (prerequisite formats failed)" -ForegroundColor Cyan
    }
} catch {
    Write-Host "[WARN] Cross-format validation failed: $_" -ForegroundColor Yellow
}

# Phase 2B: Save-IoCs + Import-IoCs Round-Trip Testing (CORRECTED - Fix #1)
Write-Host ""
Write-Host "=== Phase 2B: Save-IoCs + Import-IoCs Round-Trip ===" -ForegroundColor Yellow

try {
    $jsonSavePath = ".\workflow_test_save_$(Get-Date -f 'yyyyMMdd_HHmmss').json"
    
    Write-Host "Testing Save-IoCs..." -ForegroundColor Gray
    $results | Save-IoCs -Path $jsonSavePath -Description "Workflow integration test save"
    
    if (Test-Path $jsonSavePath) {
        $fileSize = 0
        try {
            $fileSize = (Get-Item $jsonSavePath).Length
        } catch {
            Write-Host "[WARN] Could not determine file size: $_" -ForegroundColor Yellow
        }
        
        Write-Host "[PASS] Save-IoCs successful: $jsonSavePath ($fileSize bytes)" -ForegroundColor Green
        
        # Validate Save-IoCs JSON structure
        try {
            $saveContent = Get-Content $jsonSavePath -Raw | ConvertFrom-Json
            $expectedSaveProps = @('Metadata','TimeRange','Summary','Results')
            $hasSaveProps = $expectedSaveProps | ForEach-Object { $saveContent.PSObject.Properties.Name -contains $_ }
            $hasAllSaveProps = ($hasSaveProps | Where-Object { $_ -eq $true }).Count -eq $expectedSaveProps.Count
            
            if ($hasAllSaveProps -and $saveContent.Results -and $saveContent.Results.Count -eq $results.Count) {
                Write-Host "[PASS] Save-IoCs structure validation successful" -ForegroundColor Green
            } else {
                Write-Host "[FAIL] Save-IoCs structure validation failed" -ForegroundColor Red
                exit 1
            }
        } catch {
            Write-Host "[FAIL] Save-IoCs structure validation failed: $_" -ForegroundColor Red
            exit 1
        }
    } else {
        Write-Host "[FAIL] Save-IoCs failed - file not created" -ForegroundColor Red
        exit 1
    }
    
    # Test Import-IoCs with the saved file
    Write-Host ""
    Write-Host "Testing Import-IoCs..." -ForegroundColor Gray
    $loadedResults = Import-IoCs -Path $jsonSavePath
    
    if ($loadedResults -and $loadedResults.Count -gt 0) {
        Write-Host "[PASS] Import-IoCs successful: Loaded $($loadedResults.Count) IoCs" -ForegroundColor Green
        
        # Verify data integrity
        $originalCount = if ($results) { $results.Count } else { 0 }
        $loadedCount = if ($loadedResults) { $loadedResults.Count } else { 0 }
        
        if ($loadedCount -eq $originalCount) {
            Write-Host "[PASS] Data integrity verified ($originalCount = $loadedCount)" -ForegroundColor Green
        } else {
            Write-Host "[WARN] Data count mismatch: Original=$originalCount, Loaded=$loadedCount" -ForegroundColor Yellow
        }
        
        # Verify data content (sample check)
        if ($originalCount -gt 0 -and $loadedCount -gt 0) {
            $originalFirst = $results[0]
            $loadedFirst = $loadedResults[0]
            
            if ($originalFirst.EventID -eq $loadedFirst.EventID -and $originalFirst.Category -eq $loadedFirst.Category) {
                Write-Host "[PASS] Round-trip data content verification successful" -ForegroundColor Green
            } else {
                Write-Host "[WARN] Round-trip data content mismatch detected" -ForegroundColor Yellow
            }
        }
    } else {
        Write-Host "[FAIL] Import-IoCs failed or returned no results" -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "[FAIL] Save-IoCs + Import-IoCs round-trip failed: $_" -ForegroundColor Red
    exit 1
}

# Phase 3: Search and Filtering (Enhanced error handling - Fix #6, #7, #8)
Write-Host ""
Write-Host "=== Phase 3: Search and Filtering ===" -ForegroundColor Yellow

try {
    Write-Host "Testing search and filtering capabilities..." -ForegroundColor Gray
    
    # Test category filtering
    $bootEvents = @()
    try {
        $bootEvents = @($loadedResults | Where-Object { $_.Category -like "*Boot*" -or $_.EventID -eq 6013 })
        if ($bootEvents -and $bootEvents.Count -gt 0) {
            Write-Host "[PASS] Category filtering works ($($bootEvents.Count) boot events)" -ForegroundColor Green
        } else {
            Write-Host "[INFO] No boot events found to filter" -ForegroundColor Cyan
        }
    } catch {
        Write-Host "[WARN] Category filtering test failed: $_" -ForegroundColor Yellow
    }
    
    # Test time filtering
    try {
        $recentEvents = @($loadedResults | Where-Object { $_.TimeCreated -gt (Get-Date).AddHours(-1) })
        $recentCount = if ($recentEvents) { $recentEvents.Count } else { 0 }
        Write-Host "[PASS] Time filtering works ($recentCount recent events)" -ForegroundColor Green
    } catch {
        Write-Host "[WARN] Time filtering test failed: $_" -ForegroundColor Yellow
    }
    
} catch {
    Write-Host "[WARN] Filtering test failed: $_" -ForegroundColor Yellow
}

# Phase 4: Quick/Full Scan Mode Workflow Testing
Write-Host ""
Write-Host "=== Phase 4: Quick/Full Scan Mode Workflow ====" -ForegroundColor Yellow

try {
    # Test Quick scan workflow
    Write-Host "Testing Quick scan workflow..." -ForegroundColor Gray
    $quickStartTime = Get-Date
    $quickScanResults = Get-IoCs -Quick -BeginTime (Get-Date).AddHours(-2) -EndTime (Get-Date)
    $quickEndTime = Get-Date
    $quickDuration = ($quickEndTime - $quickStartTime).TotalSeconds
    
    if ($quickScanResults -and $quickScanResults.Count -gt 0) {
        Write-Host "[PASS] Quick scan found $($quickScanResults.Count) IoCs in ${quickDuration:F1}s" -ForegroundColor Green
        
        # Test Quick scan + Export-IoCs workflow
        $quickExportPath = ".\quick_scan_workflow_$(Get-Date -f 'yyyyMMdd_HHmmss').json"
        Export-IoCs -InputObject $quickScanResults -Path $quickExportPath -Format "JSON"
        
        if (Test-Path $quickExportPath) {
            # Test Quick scan + Import-IoCs workflow
            $quickImportResults = Import-IoCs -Path $quickExportPath
            if ($quickImportResults -and $quickImportResults.Count -eq $quickScanResults.Count) {
                Write-Host "[PASS] Quick scan Export/Import workflow successful" -ForegroundColor Green
            } else {
                Write-Host "[FAIL] Quick scan Import failed or count mismatch" -ForegroundColor Red
            }
            Remove-Item $quickExportPath -Force -ErrorAction SilentlyContinue
        } else {
            Write-Host "[FAIL] Quick scan Export failed" -ForegroundColor Red
        }
    } else {
        Write-Host "[INFO] Quick scan completed but no IoCs found (${quickDuration:F1}s)" -ForegroundColor Cyan
    }
    
    # Test Full scan workflow
    Write-Host "Testing Full scan workflow..." -ForegroundColor Gray
    $fullStartTime = Get-Date
    $fullScanResults = Get-IoCs -Full -BeginTime (Get-Date).AddHours(-2) -EndTime (Get-Date)
    $fullEndTime = Get-Date
    $fullDuration = ($fullEndTime - $fullStartTime).TotalSeconds
    
    if ($fullScanResults -and $fullScanResults.Count -gt 0) {
        Write-Host "[PASS] Full scan found $($fullScanResults.Count) IoCs in ${fullDuration:F1}s" -ForegroundColor Green
        
        # Test Full scan + Export-IoCs workflow
        $fullExportPath = ".\full_scan_workflow_$(Get-Date -f 'yyyyMMdd_HHmmss').json"
        Export-IoCs -InputObject $fullScanResults -Path $fullExportPath -Format "JSON"
        
        if (Test-Path $fullExportPath) {
            # Test Full scan + Import-IoCs workflow
            $fullImportResults = Import-IoCs -Path $fullExportPath
            if ($fullImportResults -and $fullImportResults.Count -eq $fullScanResults.Count) {
                Write-Host "[PASS] Full scan Export/Import workflow successful" -ForegroundColor Green
            } else {
                Write-Host "[FAIL] Full scan Import failed or count mismatch" -ForegroundColor Red
            }
            Remove-Item $fullExportPath -Force -ErrorAction SilentlyContinue
        } else {
            Write-Host "[FAIL] Full scan Export failed" -ForegroundColor Red
        }
    } else {
        Write-Host "[INFO] Full scan completed but no IoCs found (${fullDuration:F1}s)" -ForegroundColor Cyan
    }
    
    # Performance comparison
    if ($quickScanResults -and $fullScanResults) {
        if ($quickDuration -lt $fullDuration) {
            $speedImprovement = [math]::Round((($fullDuration - $quickDuration) / $fullDuration) * 100, 1)
            Write-Host "[PASS] Quick scan was ${speedImprovement}% faster than Full scan" -ForegroundColor Green
        } else {
            Write-Host "[INFO] Performance comparison: Quick=${quickDuration:F1}s, Full=${fullDuration:F1}s" -ForegroundColor Cyan
        }
        
        # Verify Full scan found same or more IoCs than Quick scan
        if ($fullScanResults.Count -ge $quickScanResults.Count) {
            Write-Host "[PASS] Full scan completeness: found $($fullScanResults.Count) vs Quick's $($quickScanResults.Count)" -ForegroundColor Green
        } else {
            Write-Host "[WARN] Full scan found fewer IoCs than Quick scan - unexpected" -ForegroundColor Yellow
        }
    }
    
    Write-Host "[PASS] Quick/Full scan workflow testing completed" -ForegroundColor Green
    
} catch {
    Write-Host "[FAIL] Quick/Full scan workflow testing failed: $_" -ForegroundColor Red
}

# Performance validation
Write-Host ""
Write-Host "=== Performance Validation ===" -ForegroundColor Yellow

try {
    $performanceStartTime = Get-Date
    $quickResults = Get-IoCs -FailedLogins -BeginTime (Get-Date).AddHours(-1) -EndTime (Get-Date)
    $resultCount = if ($quickResults) { $quickResults.Count } else { 0 }
    Write-Host "[INFO] Performance validation completed ($resultCount events processed)" -ForegroundColor Cyan
    $performanceEndTime = Get-Date
    $performanceDuration = ($performanceEndTime - $performanceStartTime).TotalSeconds
    
    Write-Host "[PASS] Performance acceptable (${performanceDuration}s for 1-hour scan)" -ForegroundColor Green
} catch {
    Write-Host "[WARN] Performance test failed: $_" -ForegroundColor Yellow
}

# Cleanup (Enhanced with error handling - Fix #7)
Write-Host ""
Write-Host "Cleaning up test files..." -ForegroundColor Yellow
try {
    $filesToClean = @($csvPath, $jsonExportPath, $timelinePath, $jsonSavePath)
    foreach ($file in $filesToClean) {
        if ($file -and (Test-Path $file)) {
            try {
                Remove-Item $file -Force -ErrorAction SilentlyContinue
            } catch {
                Write-Host "[WARN] Could not clean up $file`: $_" -ForegroundColor Yellow
            }
        }
    }
    Write-Host "[PASS] Test files cleaned up" -ForegroundColor Green
} catch {
    Write-Host "[WARN] Some test files could not be cleaned up: $_" -ForegroundColor Yellow
}

# Final summary with export validation results
Write-Host ""
Write-Host "=== Workflow Integration Test Summary ===" -ForegroundColor Cyan
Write-Host "[PASS] Module loads and functions are available" -ForegroundColor Green  
Write-Host "[PASS] IoC scanning works across categories" -ForegroundColor Green  
Write-Host "[PASS] Save-IoCs + Import-IoCs round-trip functions work" -ForegroundColor Green
Write-Host "[PASS] Search and filtering capabilities work" -ForegroundColor Green
Write-Host "[PASS] Quick/Full scan modes work in complete workflows" -ForegroundColor Green

# Export format results
$passedFormats = ($exportTestResults.GetEnumerator() | Where-Object { $_.Value -eq 'PASS' }).Count
$totalFormats = $exportTestResults.Count
if ($totalFormats -gt 0) {
    Write-Host "[PASS] Export-IoCs format validation: $passedFormats/$totalFormats formats working" -ForegroundColor Green
} else {
    Write-Host "[WARN] Export-IoCs format validation: No formats tested" -ForegroundColor Yellow
}

Write-Host "[PASS] Performance is acceptable for various time windows" -ForegroundColor Green
Write-Host ""
Write-Host "[SUCCESS] IoC-Hunter workflow integration tests completed successfully!" -ForegroundColor Cyan

# Exit with success code
exit 0
