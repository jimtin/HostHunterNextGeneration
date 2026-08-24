[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$TestPath,

    [Parameter(Mandatory)]
    [string]$Tag,

    [Parameter(Mandatory)]
    [string]$ResultPath,

    [string]$PesterVersion = '6.1.0'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module Pester -RequiredVersion $PesterVersion -Force
$configuration = New-PesterConfiguration
$configuration.Run.Path = @((Resolve-Path -LiteralPath $TestPath).Path)
$configuration.Run.PassThru = $true
$configuration.Run.Exit = $false
$configuration.Filter.Tag = @($Tag)
$configuration.Output.Verbosity = 'Detailed'
$configuration.TestResult.Enabled = $true
$configuration.TestResult.OutputFormat = 'JUnitXml'
$configuration.TestResult.OutputPath = [System.IO.Path]::GetFullPath($ResultPath)

$result = Invoke-Pester -Configuration $configuration
if ($result.Result -ne 'Passed' -or $result.FailedCount -gt 0) {
    throw "$Tag tests failed: $($result.FailedCount) failure(s)."
}
if ($result.PassedCount -eq 0) {
    throw "$Tag lane executed zero tests."
}

[pscustomobject]@{
    Status = 'passed'
    Tag = $Tag
    Passed = $result.PassedCount
    ResultPath = [System.IO.Path]::GetFullPath($ResultPath)
}
