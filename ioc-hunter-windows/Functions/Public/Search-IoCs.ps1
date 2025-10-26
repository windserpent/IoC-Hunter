<#
.SYNOPSIS
    Searches and filters IoC scan results using multiple criteria for targeted analysis.

.DESCRIPTION
    Search-IoCs provides powerful filtering capabilities for IoC scan results, enabling security
    analysts to quickly locate specific events, patterns, or indicators of interest. Supports
    filtering by user, computer, time range, severity, and other key attributes.

.PARAMETER InputObject
    The IoC scan results to search. Accepts pipeline input from Get-IoCs or Import-IoCs.

.PARAMETER User
    Filters results by user account. Supports partial matching and wildcards.

.PARAMETER Computer
    Filters results by computer/machine name. Useful for investigating specific systems.

.PARAMETER Category
    Filters results by IoC category (e.g., "Failed Login", "PowerShell Suspicious").

.PARAMETER Severity
    Filters results by severity level: High, Medium, or Low.

.PARAMETER After
    Shows only events that occurred after the specified date/time.

.PARAMETER Before
    Shows only events that occurred before the specified date/time.

.PARAMETER Source
    Filters results by event source or generating system.

.PARAMETER Target
    Filters results by target system, user, or resource.

.PARAMETER Details
    Searches within event details using partial text matching.

.PARAMETER EventID
    Filters results by specific Windows Event IDs. Accepts single ID or array of IDs.

.EXAMPLE
    Get-IoCs -Quick | Search-IoCs -Severity "High"
    
    Finds all high-severity threats from a quick scan.

.EXAMPLE
    Import-IoCs -Path "scan.json" | Search-IoCs -User "admin*" -Category "Failed Login"
    
    Searches for failed login attempts by admin accounts.

.EXAMPLE
    Get-IoCs -Full | Search-IoCs -After (Get-Date).AddHours(-2) -Computer "SERVER01"
    
    Finds recent events (last 2 hours) from a specific server.

.EXAMPLE
    $results | Search-IoCs -EventID 4625,4648,4672 -Details "*suspicious*"
    
    Searches for specific event IDs containing "suspicious" in the details.

.INPUTS
    System.Object[]
    Accepts IoC scan results via pipeline.

.OUTPUTS
    System.Object[]
    Returns filtered IoC objects matching the specified criteria.

.NOTES
    Author: IoC-Hunter Module
    Version: 1.0.0
    
    Search Tips:
    - Use wildcards (*) for partial matching in text fields
    - Combine multiple criteria for precise filtering
    - Time-based searches use the TimeCreated property
    - Case-insensitive searching for text fields
    - Empty results indicate no matches for the criteria

.LINK
    Get-IoCs
.LINK
    Save-IoCs
.LINK
    Import-IoCs
.LINK
    Export-IoCs
#>

function Search-IoCs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSObject[]]$InputObject,
        
        [string]$User,
        [string]$Computer,
        [string]$Category,
        [ValidateSet("High", "Medium", "Low")]
        [string]$Severity,
        [datetime]$After,
        [datetime]$Before,
        [string]$Source,
        [string]$Target,
        [string]$Details,
        [int[]]$EventID
    )
    
    begin {
        $AllResults = @()
    }
    
    process {
        $AllResults += $InputObject
    }
    
    end {
        $filtered = $AllResults
        
        if ($User) { $filtered = $filtered | Where-Object User -like "*$User*" }
        if ($Computer) { $filtered = $filtered | Where-Object Computer -like "*$Computer*" }
        if ($Category) { $filtered = $filtered | Where-Object Category -like "*$Category*" }
        if ($Severity) { $filtered = $filtered | Where-Object Severity -eq $Severity }
        if ($After) { $filtered = $filtered | Where-Object TimeCreated -gt $After }
        if ($Before) { $filtered = $filtered | Where-Object TimeCreated -lt $Before }
        if ($Source) { $filtered = $filtered | Where-Object Source -like "*$Source*" }
        if ($Target) { $filtered = $filtered | Where-Object Target -like "*$Target*" }
        if ($Details) { $filtered = $filtered | Where-Object Details -like "*$Details*" }
        if ($EventID) { $filtered = $filtered | Where-Object EventID -in $EventID }
        
        Write-Host "Filtered to $($filtered.Count) events from $($AllResults.Count) total" -ForegroundColor Green
        
        return $filtered
    }
}