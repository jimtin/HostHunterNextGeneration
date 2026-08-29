[CmdletBinding()]
param(
    [string]$SourceRoot = 'src/HostHunterNextGeneration',
    [string]$ClientSourceRoot = 'client/HostHunter.Client',
    [string]$TestPath = 'tests/unit',
    [string]$ArtifactRoot = '.artifacts/unit-smoke',
    [string]$PesterVersion = '6.1.0'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$startedAt = [DateTime]::UtcNow
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path

function Resolve-HHUnitPath([string]$Path) {
    if ([IO.Path]::IsPathRooted($Path)) { return [IO.Path]::GetFullPath($Path) }
    [IO.Path]::GetFullPath((Join-Path $repoRoot $Path))
}

function Write-HHUnitJson {
    param([Parameter(Mandatory)]$Value, [Parameter(Mandatory)][string]$Path)
    $directory = Split-Path -Parent $Path
    [IO.Directory]::CreateDirectory($directory) | Out-Null
    $temporary = "$Path.$([Guid]::NewGuid().ToString('N')).tmp"
    [IO.File]::WriteAllText(
        $temporary,
        ($Value | ConvertTo-Json -Depth 8),
        [Text.UTF8Encoding]::new($false)
    )
    [IO.File]::Move($temporary, $Path, $true)
}

$sourcePath = Resolve-HHUnitPath $SourceRoot
$clientSourcePath = Resolve-HHUnitPath $ClientSourceRoot
$testsPath = Resolve-HHUnitPath $TestPath
$artifactPath = Resolve-HHUnitPath $ArtifactRoot
$summaryPath = Join-Path $artifactPath 'unit-summary.json'
$junitPath = Join-Path $artifactPath 'unit-tests.xml'
$originalTestSourceRoot = $env:HH_TEST_SOURCE_ROOT
$originalClientSourceRoot = $env:HH_TEST_CLIENT_SOURCE_ROOT

[IO.Directory]::CreateDirectory($artifactPath) | Out-Null
foreach ($staleArtifact in @($summaryPath, $junitPath)) {
    if (Test-Path -LiteralPath $staleArtifact) {
        Remove-Item -LiteralPath $staleArtifact -Force
    }
}
$testFiles = @(
    if (Test-Path -LiteralPath $testsPath -PathType Leaf) {
        Get-Item -LiteralPath $testsPath
    }
    else {
        Get-ChildItem -LiteralPath $testsPath -Filter '*.Tests.ps1' -File |
            Sort-Object FullName
    }
)
if ($testFiles.Count -eq 0) { throw 'No unit test files were selected.' }

try {
    Import-Module Pester -RequiredVersion $PesterVersion -Force
    $configuration = New-PesterConfiguration
    $configuration.Run.Path = @($testFiles.FullName)
    $configuration.Run.PassThru = $true
    $configuration.Run.Exit = $false
    $configuration.Filter.Tag = @('Unit')
    $configuration.Output.Verbosity = 'Normal'
    $configuration.TestResult.Enabled = $true
    $configuration.TestResult.OutputFormat = 'JUnitXml'
    $configuration.TestResult.OutputPath = $junitPath
    $configuration.CodeCoverage.Enabled = $false

    try {
        $env:HH_TEST_SOURCE_ROOT = $sourcePath
        $env:HH_TEST_CLIENT_SOURCE_ROOT = $clientSourcePath
        Remove-Module HostHunterNextGeneration -Force -ErrorAction Ignore
        $result = Invoke-Pester -Configuration $configuration
    }
    finally {
        $env:HH_TEST_SOURCE_ROOT = $originalTestSourceRoot
        $env:HH_TEST_CLIENT_SOURCE_ROOT = $originalClientSourceRoot
        Remove-Module HostHunterNextGeneration -Force -ErrorAction Ignore
    }

    $status = if ($result.Result -eq 'Passed' -and $result.FailedCount -eq 0) {
        'passed'
    } else { 'test_failed' }
    $summary = [ordered]@{
        schemaVersion = 1
        status = $status
        passed = $status -eq 'passed'
        invocationCount = 1
        testCount = $result.TotalCount
        passedCount = $result.PassedCount
        failedCount = $result.FailedCount
        skippedCount = $result.SkippedCount
        pesterVersion = $PesterVersion
        durationMs = [math]::Round(([DateTime]::UtcNow - $startedAt).TotalMilliseconds)
        durationSeconds = [math]::Round(([DateTime]::UtcNow - $startedAt).TotalSeconds, 3)
    }
    Write-HHUnitJson -Value $summary -Path $summaryPath
    if ($status -ne 'passed') {
        throw "Unit smoke ended with status '$status'. See '$summaryPath'."
    }
    [pscustomobject]@{
        Status = 'passed'
        Tests = $result.PassedCount
        ArtifactRoot = $artifactPath
    }
}
catch {
    if (-not (Test-Path -LiteralPath $summaryPath)) {
        Write-HHUnitJson -Path $summaryPath -Value ([ordered]@{
            schemaVersion = 1
            status = 'tooling_blocked'
            passed = $false
            invocationCount = 1
            testCount = 0
            error = $_.Exception.Message
            durationMs = [math]::Round(([DateTime]::UtcNow - $startedAt).TotalMilliseconds)
            durationSeconds = [math]::Round(([DateTime]::UtcNow - $startedAt).TotalSeconds, 3)
        })
    }
    throw
}
finally {
    $env:HH_TEST_SOURCE_ROOT = $originalTestSourceRoot
    $env:HH_TEST_CLIENT_SOURCE_ROOT = $originalClientSourceRoot
    Remove-Module HostHunterNextGeneration -Force -ErrorAction Ignore
}
