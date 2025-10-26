<#
.SYNOPSIS
    Saves IoC scan results to a structured JSON file for later analysis and sharing.

.DESCRIPTION
    Save-IoCs exports IoC scan results from Get-IoCs into a standardized JSON format that preserves
    all scan metadata, timing information, and forensic data. The saved files can be imported later
    using Import-IoCs for analysis, reporting, or sharing with security teams.

.PARAMETER Results
    The IoC scan results to save. Accepts pipeline input from Get-IoCs or arrays of IoC objects.
    This parameter is mandatory and accepts input from the pipeline.

.PARAMETER Path
    The file path where the IoC data will be saved. Must include .json extension.
    The directory will be created if it doesn't exist.

.PARAMETER Description
    Optional description of the scan for documentation purposes. Helps identify the purpose
    and context of the scan when reviewing saved results later.

.PARAMETER Compress
    Compresses the JSON output to reduce file size. Useful for large scans or storage optimization.

.EXAMPLE
    Get-IoCs -Quick | Save-IoCs -Path "daily_scan.json" -Description "Daily security scan"
    
    Performs a quick scan and saves results with a descriptive label.

.EXAMPLE
    $results = Get-IoCs -Full -BeginTime (Get-Date).AddDays(-7)
    $results | Save-IoCs -Path "weekly_scan.json" -Description "Weekly comprehensive scan" -Compress
    
    Saves a week-long comprehensive scan with compression enabled.

.INPUTS
    System.Object[]
    Accepts IoC scan results from Get-IoCs via pipeline.

.OUTPUTS
    None
    Saves data to specified file path.

.NOTES
    Author: IoC-Hunter Module
    Version: 1.0.0
    
    The saved file includes:
    - All original IoC data and properties
    - Scan metadata (timestamp, user, computer, description)
    - Summary statistics (total events, severity breakdown)
    - Time range information
    - Module version for compatibility tracking

.LINK
    Get-IoCs
.LINK
    Import-IoCs
.LINK
    Export-IoCs
.LINK
    Search-IoCs
#>

function Save-IoCs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSObject[]]$Results,
        
        [Parameter(Mandatory)]
        [string]$Path,
        
        [string]$Description = "",
        [switch]$Compress
    )
    
    begin {
        $AllResults = @()
    }
    
    process {
        $AllResults += $Results
    }
    
    end {
        try {
            $SavedScan = @{
                Metadata = @{
                    SavedTimestamp = Get-Date
                    SavedBy = $env:USERNAME
                    SavedFrom = $env:COMPUTERNAME
                    Description = $Description
                    Version = "1.0"
                }
                TimeRange = @{
                    Start = ($AllResults | Measure-Object TimeCreated -Minimum).Minimum
                    End = ($AllResults | Measure-Object TimeCreated -Maximum).Maximum
                    DurationMinutes = [math]::Round((($AllResults | Measure-Object TimeCreated -Maximum).Maximum - ($AllResults | Measure-Object TimeCreated -Minimum).Minimum).TotalMinutes, 1)
                }
                Summary = @{
                    TotalEvents = $AllResults.Count
                    HighSeverity = ($AllResults | Where-Object Severity -eq "High").Count
                    MediumSeverity = ($AllResults | Where-Object Severity -eq "Medium").Count
                    LowSeverity = ($AllResults | Where-Object Severity -eq "Low").Count
                    UniqueUsers = ($AllResults | Where-Object User -ne "SYSTEM" | Group-Object User | Measure-Object).Count
                    UniqueComputers = ($AllResults | Group-Object Computer | Measure-Object).Count
                    Categories = ($AllResults | Group-Object Category | Sort-Object Count -Descending | Select-Object Name, Count)
                }
                Results = $AllResults
            }
            
            if ($Compress) {
                $SavedScan | ConvertTo-Json -Depth 15 -Compress | Out-File $Path -Encoding UTF8
            } else {
                $SavedScan | ConvertTo-Json -Depth 15 | Out-File $Path -Encoding UTF8
            }
            
            Write-Host "Saved $($AllResults.Count) IoCs to: $Path" -ForegroundColor Green
            Write-Host "Summary: $($SavedScan.Summary.HighSeverity) High, $($SavedScan.Summary.MediumSeverity) Medium, $($SavedScan.Summary.LowSeverity) Low" -ForegroundColor Gray
        } catch {
            Write-Error "Failed to save IoCs: $_"
        }
    }
}