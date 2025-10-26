<#
.SYNOPSIS
    Imports previously saved IoC scan results for analysis and review.

.DESCRIPTION
    Import-IoCs loads IoC scan results that were previously saved using Save-IoCs. This enables
    analysis of historical scans, comparison between different time periods, and sharing of
    security findings between team members or systems.

.PARAMETER Path
    Path to the JSON file containing saved IoC results. Must be a file created by Save-IoCs.

.EXAMPLE
    $pastResults = Import-IoCs -Path "daily_scan.json"
    $pastResults | Where-Object Severity -eq "High"
    
    Imports a previous scan and filters for high-severity threats.

.EXAMPLE
    Import-IoCs -Path "incident_scan.json" | Search-IoCs -User "suspicious_account"
    
    Imports saved results and searches for activity by a specific user account.

.INPUTS
    None
    This function does not accept pipeline input.

.OUTPUTS
    System.Object[]
    Returns the same IoC objects that were originally saved, maintaining all properties
    and forensic data for continued analysis.

.NOTES
    Author: IoC-Hunter Module
    Version: 1.0.0
    
    Displays summary information upon import:
    - Original scan date and time range
    - Total events and severity breakdown  
    - Description (if provided during save)
    - Compatibility with current module version

.LINK
    Get-IoCs
.LINK
    Save-IoCs
.LINK
    Export-IoCs
.LINK
    Search-IoCs
#>

function Import-IoCs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )
    
    try {
        if (-not (Test-Path $Path)) {
            throw "File not found: $Path"
        }
        
        Write-Host "Loading IoC scan from: $Path" -ForegroundColor Green
        
        $SavedScan = Get-Content $Path -Raw | ConvertFrom-Json
        
        Write-Host "Scan Date: $($SavedScan.Metadata.SavedTimestamp)" -ForegroundColor Gray
        Write-Host "Time Range: $($SavedScan.TimeRange.Start) to $($SavedScan.TimeRange.End)" -ForegroundColor Gray
        Write-Host "Total Events: $($SavedScan.Summary.TotalEvents) ($($SavedScan.Summary.HighSeverity) High, $($SavedScan.Summary.MediumSeverity) Medium)" -ForegroundColor Gray
        
        if ($SavedScan.Metadata.Description) {
            Write-Host "Description: $($SavedScan.Metadata.Description)" -ForegroundColor Gray
        }
        
        Write-Host ""
        
        return $SavedScan.Results
    } catch {
        Write-Error "Failed to import IoCs: $_"
        return $null
    }
}