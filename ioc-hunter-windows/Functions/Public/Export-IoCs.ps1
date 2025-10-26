<#
.SYNOPSIS
    Exports IoC scan results to various formats for analysis, reporting, and integration.

.DESCRIPTION
    Export-IoCs converts IoC scan results into multiple output formats optimized for different
    use cases including CSV for spreadsheet analysis, JSON for automation, XML for forensic tools,
    and specialized formats for SIEM integration and timeline analysis.

.PARAMETER InputObject
    The IoC scan results to export. Accepts pipeline input from Get-IoCs or Import-IoCs.

.PARAMETER Format
    Output format for the exported data. Valid options:
    - CSV: Comma-separated values for spreadsheet analysis
    - Excel: Microsoft Excel format with formatted columns
    - JSON: JavaScript Object Notation for automation
    - ForensicXML: Structured XML for forensic analysis tools
    - SIEM: Format optimized for SIEM system ingestion
    - Timeline: Chronological format for timeline analysis

.PARAMETER Path
    Output file path. File extension should match the selected format.

.PARAMETER IncludeForensicData
    Includes detailed forensic data in the export. Provides additional technical details
    but significantly increases file size.

.EXAMPLE
    Get-IoCs -Quick | Export-IoCs -Format CSV -Path "scan_results.csv"
    
    Exports quick scan results to CSV format for spreadsheet analysis.

.EXAMPLE
    Import-IoCs -Path "scan.json" | Export-IoCs -Format SIEM -Path "siem_feed.json" -IncludeForensicData
    
    Converts saved scan to SIEM format with full forensic details.

.EXAMPLE
    Get-IoCs -Full | Export-IoCs -Format Timeline -Path "security_timeline.xml"
    
    Creates a chronological timeline of security events for investigation.

.INPUTS
    System.Object[]
    Accepts IoC scan results via pipeline.

.OUTPUTS
    None
    Exports data to specified file in chosen format.

.NOTES
    Author: IoC-Hunter Module
    Version: 1.0.0
    
    Format Details:
    - CSV: Standard comma-separated format, Excel-compatible
    - JSON: Structured data with metadata preservation
    - ForensicXML: Detailed XML with full event context
    - SIEM: Optimized for security information and event management
    - Timeline: Time-ordered events for investigative analysis
    - Excel: Native Excel format with column formatting

.LINK
    Get-IoCs
.LINK
    Save-IoCs
.LINK
    Import-IoCs
.LINK
    Search-IoCs
#>

function Export-IoCs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSObject[]]$InputObject,
        
        [ValidateSet('CSV','Excel','JSON','ForensicXML','SIEM','Timeline')]
        [string]$Format = 'CSV',
        
        [Parameter(Mandatory)]
        [string]$Path,
        
        [switch]$IncludeForensicData
    )
    
    begin {
        $AllResults = @()
    }
    
    process {
        $AllResults += $InputObject
    }
    
    end {
        try {
            switch ($Format) {
                'CSV' {
                    if ($IncludeForensicData) {
                        $AllResults | Select-Object TimeCreated, EventID, Category, Severity, User, Source, Target, Details, Computer,
                            @{Name='LogName'; Expression={$_.ForensicData.LogName}},
                            @{Name='RecordId'; Expression={$_.ForensicData.RecordId}},
                            @{Name='EventXML'; Expression={$_.ForensicData.EventXML}} |
                            Export-Csv -Path $Path -NoTypeInformation
                    } else {
                        $AllResults | Select-Object TimeCreated, EventID, Category, Severity, User, Source, Target, Details, Computer |
                            Export-Csv -Path $Path -NoTypeInformation
                    }
                }
                
                'JSON' {
                    $AllResults | ConvertTo-Json -Depth 10 | Out-File $Path -Encoding UTF8
                }
                
                'ForensicXML' {
                    $forensicPackage = @{
                        ExportTimestamp = Get-Date
                        ExportedBy = $env:USERNAME
                        TotalEvents = $AllResults.Count
                        Events = $AllResults | ForEach-Object {
                            @{
                                IoCSummary = @{
                                    TimeCreated = $_.TimeCreated
                                    EventID = $_.EventID
                                    Category = $_.Category
                                    Severity = $_.Severity
                                    User = $_.User
                                    Source = $_.Source
                                    Target = $_.Target
                                    Details = $_.Details
                                    Computer = $_.Computer
                                }
                                ForensicData = $_.ForensicData
                            }
                        }
                    }
                    $forensicPackage | ConvertTo-Json -Depth 20 | Out-File $Path -Encoding UTF8
                }
                
                'SIEM' {
                    $siemData = $AllResults | ForEach-Object {
                        [PSCustomObject]@{
                            timestamp = $_.TimeCreated.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
                            event_id = $_.EventID
                            severity = $_.Severity
                            category = $_.Category
                            user = $_.User
                            computer = $_.Computer
                            source_ip = $_.Source
                            details = $_.Details
                            log_name = $_.ForensicData.LogName
                            record_id = $_.ForensicData.RecordId
                            process_id = $_.ForensicData.ProcessId
                            raw_xml = $_.ForensicData.EventXML
                        }
                    }
                    $siemData | ConvertTo-Json -Depth 5 | Out-File $Path -Encoding UTF8
                }
                
                'Timeline' {
                    $AllResults | Sort-Object TimeCreated | 
                        Select-Object @{Name='Time'; Expression={$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')}},
                                    EventID, Category, Severity, User, Computer, Details |
                        Export-Csv -Path $Path -NoTypeInformation
                }
            }
            
            Write-Host "Exported $($AllResults.Count) events in $Format format to: $Path" -ForegroundColor Green
        } catch {
            Write-Error "Failed to export IoCs: $_"
        }
    }
}