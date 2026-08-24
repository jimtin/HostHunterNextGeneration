[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $ReportPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$expectedModules = [ordered]@{
    Pester           = [version] '6.1.0'
    PSScriptAnalyzer = [version] '1.25.0'
}

$report = foreach ($entry in $expectedModules.GetEnumerator()) {
    $availableVersions = @(
        Get-Module -ListAvailable -Name $entry.Key |
            Select-Object -ExpandProperty Version -Unique |
            Sort-Object
    )

    if ($availableVersions.Count -ne 1 -or $availableVersions[0] -ne $entry.Value) {
        $renderedVersions = $availableVersions -join ', '
        throw "Module pin mismatch for $($entry.Key). Expected only $($entry.Value); found: $renderedVersions"
    }

    Import-Module -Name $entry.Key -RequiredVersion $entry.Value -Force -ErrorAction Stop

    [pscustomobject]@{
        Name    = $entry.Key
        Version = $entry.Value.ToString()
        Path    = (Get-Module -Name $entry.Key).Path
    }
}

$parentDirectory = Split-Path -Parent $ReportPath
if (-not (Test-Path -LiteralPath $parentDirectory)) {
    New-Item -ItemType Directory -Path $parentDirectory -Force | Out-Null
}

[pscustomobject]@{
    PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    Modules           = @($report)
} |
    ConvertTo-Json -Depth 4 |
    Set-Content -LiteralPath $ReportPath -Encoding utf8NoBOM

if ($PSVersionTable.PSVersion.ToString() -ne '7.6.5') {
    throw "PowerShell pin mismatch. Expected 7.6.5; found $($PSVersionTable.PSVersion)."
}

Write-Output 'PowerShell and module pins verified.'
