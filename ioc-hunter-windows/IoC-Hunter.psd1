@{
    # Module metadata
    ModuleVersion = '1.0.0'
    RootModule = 'IoC-Hunter.psm1'
    GUID = 'a1b2c3d4-e5f6-7890-1234-567890abcdef'
    
    # Author information
    Author = 'Security Team'
    Description = 'Comprehensive Windows IoC Detection, Analysis, and Forensic Data Platform'
    PowerShellVersion = '5.1'
    
    # Functions to export
    FunctionsToExport = @(
        'Get-IoCs',
        'Save-IoCs', 'Import-IoCs', 'Get-SavedIoCs',
        'Search-IoCs', 'Get-IoCSummary', 'Compare-IoCs', 'Get-IoCTimeline',
        'Export-IoCs'
    )
    
    # Cmdlets and aliases
    CmdletsToExport = @()
    AliasesToExport = @()
    
    # Private data
    PrivateData = @{
        PSData = @{
            Tags = @('Security', 'IoC', 'Forensics', 'EventLog', 'IR')
            ProjectUri = 'https://github.com/yourorg/IoC-Hunter'
        }
    }
}