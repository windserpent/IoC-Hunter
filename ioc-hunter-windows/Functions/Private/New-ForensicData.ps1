function New-ForensicData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Diagnostics.Eventing.Reader.EventLogRecord]$EventRecord  # Changed from $Event
    )
    
    try {
        $ForensicData = [PSCustomObject]@{
            EventXML = $EventRecord.ToXml()                    # Updated references
            LogName = $EventRecord.LogName
            RecordId = $EventRecord.RecordId
            ThreadId = $EventRecord.ThreadId
            ProcessId = $EventRecord.ProcessId
            UserId = if ($EventRecord.UserId) { $EventRecord.UserId.Value } else { $null }
            TimeGenerated = $EventRecord.TimeCreated
            Keywords = $EventRecord.Keywords
            Level = $EventRecord.Level
            Task = $EventRecord.Task
            AllProperties = ($EventRecord.Properties | ForEach-Object { $_.Value })
            RawEventObject = $EventRecord                      # Updated reference
        }
        
        return $ForensicData
    } catch {
        Write-Warning "Failed to create forensic data for event $($EventRecord.Id): $_"  # Updated reference
        return $null
    }
}