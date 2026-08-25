[CmdletBinding()]
param(
    [string]$ArtifactRoot = '.artifacts/unit/product',
    [double]$Minimum = 90,
    [string]$PesterVersion = '6.1.0'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$artifactPath = if ([System.IO.Path]::IsPathRooted($ArtifactRoot)) {
    [System.IO.Path]::GetFullPath($ArtifactRoot)
}
else {
    Join-Path $repoRoot $ArtifactRoot
}
$instrumentedRoot = Join-Path $artifactPath 'instrumented-source'
$manifestPath = Join-Path $artifactPath 'branch-manifest.json'
$eventPath = Join-Path $artifactPath 'branch-events.tsv'
$reportPath = Join-Path $artifactPath 'branch-report.json'
$unitPath = Join-Path $repoRoot 'tests/unit'
$sourceRoot = Join-Path $repoRoot 'src/HostHunterNextGeneration'

if (Test-Path -LiteralPath $artifactPath) {
    Remove-Item -LiteralPath $artifactPath -Recurse -Force
}
[System.IO.Directory]::CreateDirectory($artifactPath) | Out-Null

& (Join-Path $repoRoot 'scripts/coverage/Prepare-HHInstrumentedModule.ps1') `
    -SourceRoot $sourceRoot `
    -OutputRoot $instrumentedRoot `
    -ManifestPath $manifestPath | Out-Null

Import-Module Pester -RequiredVersion $PesterVersion -Force
$env:HH_TEST_SOURCE_ROOT = $instrumentedRoot
$env:HH_BRANCH_LOG = $eventPath

$publicCmdletTest = Join-Path $unitPath 'PublicCmdlets.Tests.ps1'
$otherUnitTests = @(Get-ChildItem -LiteralPath $unitPath -Filter '*.Tests.ps1' -File |
        Where-Object FullName -ne $publicCmdletTest |
        Sort-Object FullName |
        ForEach-Object FullName)
$branchTestPhases = @(
    [pscustomobject]@{ Name = 'module internals'; Paths = $otherUnitTests; Tag = 'Unit' }
    [pscustomobject]@{ Name = 'public cmdlets'; Paths = @($publicCmdletTest); Tag = 'Unit' }
    [pscustomobject]@{
        Name = 'authenticated SQLite migration'
        Paths = @(Join-Path $repoRoot 'tests/integration/SqliteMigrationV2.Tests.ps1')
        Tag = 'Integration'
    }
)

try {
    foreach ($phase in $branchTestPhases) {
        # Module discovery executes instrumented top-level branches before any
        # test-level BeforeEach block can establish a case identifier.
        $env:HH_COVERAGE_CASE = [Guid]::NewGuid().ToString('N')
        $branchConfiguration = New-PesterConfiguration
        $branchConfiguration.Run.Path = $phase.Paths
        $branchConfiguration.Run.PassThru = $true
        $branchConfiguration.Run.Exit = $false
        $branchConfiguration.Filter.Tag = @($phase.Tag)
        $branchConfiguration.Output.Verbosity = 'Detailed'
        $branchResult = Invoke-Pester -Configuration $branchConfiguration
        if ($branchResult.Result -ne 'Passed' -or $branchResult.FailedCount -gt 0) {
            throw "Instrumented $($phase.Name) tests failed: $($branchResult.FailedCount) failure(s)."
        }
    }
}
finally {
    $env:HH_TEST_SOURCE_ROOT = $null
    $env:HH_BRANCH_LOG = $null
    $env:HH_COVERAGE_CASE = $null
}

& (Join-Path $repoRoot 'scripts/coverage/Test-HHBranchCoverage.ps1') `
    -ManifestPath $manifestPath `
    -EventPath $eventPath `
    -Minimum $Minimum `
    -ReportPath $reportPath | Out-Null

$coverageScript = Join-Path $repoRoot 'scripts/coverage/Invoke-HHUnitCoverage.ps1'
& (Get-Command pwsh -ErrorAction Stop).Source `
    -NoLogo `
    -NoProfile `
    -NonInteractive `
    -File $coverageScript `
    -SourcePath $sourceRoot `
    -TestPath $unitPath `
    -BranchReportPath $reportPath `
    -ArtifactRoot $artifactPath `
    -Minimum $Minimum `
    -PesterVersion $PesterVersion
if ($LASTEXITCODE -ne 0) {
    throw "The isolated ordinary source-coverage process failed with exit code $LASTEXITCODE."
}
