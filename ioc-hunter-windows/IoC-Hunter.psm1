# Get all function files
$Public = @(Get-ChildItem -Path $PSScriptRoot\Functions\Public\*.ps1 -ErrorAction SilentlyContinue)
$Private = @(Get-ChildItem -Path $PSScriptRoot\Functions\Private\*.ps1 -ErrorAction SilentlyContinue)

# Dot source the files
foreach ($import in @($Public + $Private)) {
    try {
        . $import.FullName
    } catch {
        Write-Error "Failed to import function $($import.FullName): $_"
    }
}

# Export public functions
Export-ModuleMember -Function $Public.BaseName

# Module variables
$Script:ModuleRoot = $PSScriptRoot
$Script:DefaultPatternsPath = Join-Path $PSScriptRoot "Data\DefaultPatterns.json"

Write-Host "IoC-Hunter module loaded. Use 'Get-Help Get-IoCs' to get started." -ForegroundColor Green