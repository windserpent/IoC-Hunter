# IoC-Hunter Test Suite Usage Guide

## Overview

This comprehensive test suite validates all aspects of the IoC-Hunter PowerShell module, including basic functionality, category testing, scan mode validation, workflow integration, and stress testing. The test suite provides complete coverage of all module features and ensures reliable operation in production environments.

## Test Suite Summary

**Total Tests**: 5 comprehensive test scripts
**Total Execution Time**: ~1 minute 7 seconds
**Module Version**: 1.0.0
**Coverage**: All 26 IoC categories, both scan modes, complete workflows

### Test Scripts Overview
```
Test-ModuleBasics         - 0m 1s  - Core functionality validation
Test-IoCCategories        - 0m 6s  - All 26 categories tested  
Test-ScanModes            - 0m 17s - Quick vs Full scan validation
Test-WorkflowIntegration  - 0m 11s - End-to-end workflow testing
Test-StressAndErrors      - 0m 30s - Performance and error handling
```

## Test Suite Capabilities

### **Core Functionality Testing:**
- Module loading and function availability verification
- Parameter validation for all 43 Get-IoCs parameters
- Basic IoC scanning functionality
- Help content and documentation validation
- Error handling for invalid inputs

### **Comprehensive Category Coverage:**
- Individual testing of all 26 IoC categories
- Performance measurement for each category
- Event structure validation and consistency checking
- Adaptation testing for systems with different event log configurations

### **Scan Mode Validation:**
- Quick scan mode testing (18 critical categories)
- Full scan mode testing (all 26 categories)
- Performance comparison and optimization verification
- Memory usage analysis for both modes

### **Complete Workflow Testing:**
- Save-IoCs and Import-IoCs round-trip data integrity
- Export-IoCs format validation (CSV, JSON, Timeline, SIEM)
- Search-IoCs filtering and query functionality
- Cross-format consistency verification

### **Performance and Stress Testing:**
- Large dataset handling capabilities
- Memory usage monitoring and optimization
- Error scenario simulation and handling
- Resource management and cleanup validation

## Quick Start

1. **Navigate to the Tests directory** within your IoC-Hunter module
2. **Open PowerShell as Administrator** (required for event log access)
3. **Run the complete test suite:**

```powershell
# Full test suite (recommended for production validation)
.\Run-AllTests.ps1

# Quick test (basic functionality only - faster execution)  
.\Run-AllTests.ps1 -QuickTest

# Skip stress tests (reduced execution time)
.\Run-AllTests.ps1 -SkipStressTests

# Custom log file
.\Run-AllTests.ps1 -LogFile "MyTestResults.log"
```

## Individual Test Scripts

### 1. Test-ModuleBasics.ps1
**Purpose:** Validates core module structure, loading, and basic functionality
**Runtime:** ~1 minute  
**Current Features:**
- Module import validation with proper function availability
- Parameter validation for all 43 Get-IoCs parameters
- Basic IoC scanning functionality verification
- Help content availability testing
- Error handling validation for invalid parameters
- Performance baseline establishment
- Resource cleanup verification

**Usage:**
```powershell
.\Test-ModuleBasics.ps1
```

**Expected Results:**
- Module loads successfully with all 5 public functions available
- All 43 parameters recognized and validated
- Basic scan executes without errors
- Performance metrics within acceptable ranges
- Resource cleanup operates correctly

### 2. Test-IoCCategories.ps1
**Purpose:** Tests each of the 26 IoC categories individually for functionality and performance
**Runtime:** ~6 minutes
**Current Features:**
- Individual testing of all 26 IoC categories
- Performance measurement for each category
- Event structure validation
- Result consistency verification
- Category-specific error handling

**Usage:**
```powershell
.\Test-IoCCategories.ps1
```

**Expected Results:**
- All 26 categories execute successfully
- Performance metrics logged for each category
- Event structures validated for consistency
- Categories adapt appropriately to available event logs

### 3. Test-ScanModes.ps1
**Purpose:** Validates Quick vs Full scan modes and performance characteristics
**Runtime:** ~17 minutes
**Current Features:**
- Quick scan mode validation (18 categories)
- Full scan mode validation (26 categories)
- Performance comparison between modes
- Memory usage analysis
- Category inclusion verification
- Scan mode exclusivity testing (cannot use both Quick and Full)

**Usage:**
```powershell
.\Test-ScanModes.ps1
```

**Expected Results:**
- Quick mode completes in 2-4 minutes with 18 categories
- Full mode completes in 5-15 minutes with 26 categories
- Memory usage appropriate for each mode
- Performance characteristics meet expectations

### 4. Test-WorkflowIntegration.ps1
**Purpose:** Tests complete end-to-end workflows including persistence and export functionality
**Runtime:** ~11 minutes
**Current Features:**
- **Save-IoCs + Import-IoCs workflow testing**: Complete round-trip data integrity validation
- **Export-IoCs format validation**: CSV, JSON, Timeline, and SIEM format testing
- **Cross-format consistency**: Ensures equivalent data across all export formats
- **Search-IoCs functionality**: Filtering and query capability testing
- **Data integrity verification**: Validates that saved and loaded data matches exactly
- **Metadata preservation**: Confirms timestamps, descriptions, and summary data retention

**Usage:**
```powershell
.\Test-WorkflowIntegration.ps1
```

**Expected Results:**
- Save/Import operations maintain perfect data integrity
- All export formats generate valid, consistent output
- Search functionality filters correctly across all criteria
- No data loss or corruption in any workflow

### 5. Test-StressAndErrors.ps1
**Purpose:** Performance validation, stress testing, and comprehensive error handling
**Runtime:** ~30 minutes
**Current Features:**
- Large dataset handling (500+ events)
- Memory usage monitoring and optimization
- Performance testing under load
- Error scenario simulation
- Resource management validation
- Invalid input handling
- Edge case testing

**Usage:**
```powershell
.\Test-StressAndErrors.ps1
```

**Expected Results:**
- Handles large datasets without memory issues
- Maintains performance under stress conditions
- Gracefully handles all error scenarios
- Resource cleanup operates effectively

## Prerequisites

- **PowerShell 5.1 or later**
- **Administrator privileges** (required for Windows Event Log access)
- **IoC-Hunter module** properly structured in parent directory
- **Tests folder** containing all test scripts in IoC-Hunter directory
- **Windows Event Logs** accessible and populated
- **Minimum 4GB RAM** recommended for stress testing

## Expected Directory Structure

```
IoC-Hunter/
├── IoC-Hunter.psd1              # Module manifest
├── IoC-Hunter.psm1              # Main module file  
├── Functions/
│   ├── Public/
│   │   ├── Get-IoCs.ps1         # Main detection function (26 categories)
│   │   ├── Export-IoCs.ps1      # Export functions (CSV, JSON, Timeline, SIEM)
│   │   ├── Save-IoCs.ps1        # Persistence functions
│   │   ├── Import-IoCs.ps1      # Load saved results
│   │   └── Search-IoCs.ps1      # Analysis and filtering
│   └── Private/
│       └── New-ForensicData.ps1 # Helper functions
├── Tests/                       # Test folder (run tests from here)
│   ├── Run-AllTests.ps1
│   ├── Test-ModuleBasics.ps1
│   ├── Test-IoCCategories.ps1
│   ├── Test-ScanModes.ps1
│   ├── Test-WorkflowIntegration.ps1
│   ├── Test-StressAndErrors.ps1
│   └── TEST-USAGE-GUIDE.md
├── README.md
├── USAGE-GUIDE.md
└── MODULE-STRUCTURE
```

## Expected Outputs

### Success Indicators
- **[PASS]** Green text for passing tests and successful operations
- **[INFO]** Blue/cyan text for informational messages and statistics
- **[SUCCESS]** Final success confirmation messages

### Warning Indicators
- **[WARN]** Yellow text for acceptable issues that don't affect functionality
- **[SLOW]** Performance warnings for operations exceeding expected timeframes

### Failure Indicators
- **[FAIL]** Red text for failing tests that require attention
- **[ERROR]** Critical errors requiring immediate resolution

## Understanding Test Workflows

### **Export-IoCs Workflow** (External Integration)
```powershell
Get-IoCs → Export-IoCs (CSV/JSON/Timeline/SIEM) → External Systems
```
- **Purpose**: Generate formatted data for external systems, reports, SIEM integration
- **Validation**: Structure verification, format compliance, content integrity
- **Note**: Export formats are optimized for external consumption, not for Import-IoCs

### **Save-IoCs + Import-IoCs Workflow** (Internal Persistence)  
```powershell
Get-IoCs → Save-IoCs → Import-IoCs → Search-IoCs/Analysis
```
- **Purpose**: Complete IoC-Hunter scan persistence with metadata for later analysis
- **Validation**: Round-trip data integrity, metadata preservation, summary statistics
- **Includes**: Full timestamps, scan descriptions, user information, complete event data

### **Search-IoCs Workflow** (Data Analysis)
```powershell
Get-IoCs or Import-IoCs → Search-IoCs → Filtered Results → Export-IoCs
```
- **Purpose**: Filter and analyze IoC results by various criteria
- **Validation**: Filtering accuracy, result consistency, query performance
- **Capabilities**: Category, severity, user, time range, Event ID filtering

## Interpreting Test Results

### Module Basics Test Results
- **All functions available:** Module structure is correct and complete
- **Parameter validation:** All 43 Get-IoCs parameters properly recognized
- **Basic functionality:** Core scanning operations work correctly
- **Performance baseline:** Execution times within acceptable ranges
- **Resource management:** Memory cleanup and resource handling optimal

### IoC Categories Test Results  
- **High success rate (90%+):** Excellent - production ready
- **Moderate success rate (70-90%):** Good - acceptable for most environments
- **Low success rate (50-70%):** Normal for systems with limited activity
- **Very low success rate (<50%):** May indicate logging configuration issues

**Note**: PowerShell categories typically show results due to the test execution itself generating PowerShell events.

### Scan Modes Test Results
- **Quick mode performance:** Should complete in 2-4 minutes with 18 categories
- **Full mode performance:** Should complete in 5-15 minutes with 26 categories
- **Memory efficiency:** Quick mode uses less memory than Full mode
- **Category coverage:** Quick=18 critical categories, Full=all 26 categories

### Workflow Integration Test Results
- **Save/Import round-trip:** Should show perfect data integrity (100% match)
- **Export format validation:** All formats (CSV, JSON, Timeline, SIEM) should validate successfully
- **Cross-format consistency:** All export formats should contain equivalent core data
- **Search functionality:** Should filter accurately across all supported criteria

### Stress and Error Handling Test Results  
- **Large dataset handling:** Should process 500+ events without issues
- **Memory management:** Should maintain stable memory consumption patterns
- **Error scenarios:** Should gracefully handle all invalid inputs and edge cases
- **Performance under load:** Should maintain reasonable response times

## Performance Expectations

### Typical Performance Baselines (Current System Results):
- **15-minute scan:** 1-5 seconds
- **1-hour scan:** 5-15 seconds  
- **24-hour scan:** 30-60 seconds
- **7-day scan:** 2-5 minutes
- **30-day scan:** 10-30 minutes

### Memory Usage Patterns:
- **Baseline (module load):** 50-100 MB
- **Quick scan operation:** +50-150 MB
- **Full scan operation:** +100-250 MB
- **Large datasets (1000+ events):** +100-300 MB
- **Stress testing:** Up to 500 MB (temporary spikes acceptable)

### Category Performance Characteristics:
- **Fast categories:** FailedLogins, EventLogClearing, AccountManagement
- **Medium categories:** PowerShellSuspicious, ProcessCreation, ServiceSuspicious
- **Slower categories:** RegistryModifications (Full), ShareAccess (Full), NetworkConnections

## Troubleshooting Test Issues

### For Test Failures:
1. **Review the generated log file** for detailed error messages and stack traces
2. **Run individual test scripts** to isolate the specific failing component
3. **Verify module structure** matches the expected directory layout exactly
4. **Confirm administrator privileges** are granted for event log access
5. **Check PowerShell execution policy** if scripts are blocked from running
6. **Validate event log availability** using `Get-WinEvent -ListLog *`

### For Performance Issues:
1. **Run tests multiple times** to establish consistent performance baseline
2. **Monitor system resource usage** during test execution
3. **Verify adequate available memory** (4GB+ recommended for full test suite)
4. **Close unnecessary applications** to free system resources
5. **Consider running tests during off-peak hours** for large-scale testing

### For Memory Issues:
1. **Force garbage collection** between tests: `[System.GC]::Collect()`
2. **Restart PowerShell session** before running full test suite
3. **Run individual tests separately** rather than full suite if memory constrained
4. **Monitor memory usage** using Task Manager during test execution

### For Access Issues:
1. **Verify administrator privileges**: Run PowerShell as Administrator
2. **Check event log services**: Ensure Windows Event Log service is running
3. **Validate event log access**: Test with `Get-EventLog -List`
4. **Review user rights assignment**: Ensure "Generate security audits" and "Log on as a service" rights

## Test Environment Recommendations

### Development Environment:
- **Purpose**: Module development and modification testing
- **Configuration**: Test system with limited production data
- **Frequency**: Run after any code changes
- **Scope**: Full test suite execution

### Staging Environment:
- **Purpose**: Pre-production validation
- **Configuration**: Production-like data and configuration
- **Frequency**: Before production deployment
- **Scope**: Full test suite plus performance validation

### Production Environment:
- **Purpose**: Ongoing functionality validation
- **Configuration**: Live production systems
- **Frequency**: Weekly or after system changes
- **Scope**: Quick test or targeted individual tests

## Advanced Testing Scenarios

### Custom Test Execution:
```powershell
# Test specific categories only
.\Test-IoCCategories.ps1 -Categories @('PowerShellSuspicious', 'FailedLogins')

# Performance-focused testing
.\Test-StressAndErrors.ps1 -SkipLargeDatasets

# Memory-constrained testing  
.\Run-AllTests.ps1 -QuickTest -SkipStressTests
```

### Continuous Integration Testing:
```powershell
# Automated testing script for CI/CD pipelines
$test_results = .\Run-AllTests.ps1 -LogFile "CI_Results.log"
if ($test_results.FailedTests -eq 0) {
    Write-Host "All tests passed - ready for deployment" -ForegroundColor Green
    exit 0
} else {
    Write-Host "Test failures detected - deployment blocked" -ForegroundColor Red
    exit 1
}
```

### Performance Regression Testing:
```powershell
# Compare current performance against baseline
$baseline_file = "performance_baseline.json"
$current_results = .\Test-StressAndErrors.ps1 -PerformanceOnly
Compare-Performance -Baseline $baseline_file -Current $current_results
```

## Support and Debugging

### Log File Analysis:
The test suite generates detailed log files containing:
- Execution timestamps for all operations
- Detailed error messages with stack traces
- Performance metrics for each test phase
- Memory usage patterns throughout execution
- Summary statistics and final results

### Debug Mode Execution:
```powershell
# Enable verbose output for debugging
$VerbosePreference = "Continue"
.\Run-AllTests.ps1 -Verbose

# Enable debug mode for detailed tracing
$DebugPreference = "Continue"  
.\Test-WorkflowIntegration.ps1 -Debug
```

### Common Debugging Commands:
```powershell
# Check module loading status
Get-Module IoC-Hunter

# Verify function availability
Get-Command -Module IoC-Hunter

# Test event log accessibility
Get-WinEvent -ListLog Security -ErrorAction SilentlyContinue

# Monitor memory usage
[System.GC]::GetTotalMemory($false) / 1MB
```

## Conclusion

The IoC-Hunter test suite provides comprehensive validation of all module functionality, ensuring production readiness and reliable operation. The test suite covers all 26 IoC categories, both scan modes, complete workflows, and stress scenarios to thoroughly validate the module's capabilities.

**For additional support or advanced testing scenarios, consult the main USAGE-GUIDE.md or examine the test script source code for detailed implementation examples.**

---

**Run `.\Run-AllTests.ps1` to validate your IoC-Hunter deployment.**
