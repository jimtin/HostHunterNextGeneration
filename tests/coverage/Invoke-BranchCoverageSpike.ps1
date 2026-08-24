[CmdletBinding()]
param(
    [string]$ArtifactRoot = '.artifacts/coverage-spike'
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
[System.IO.Directory]::CreateDirectory($artifactPath) | Out-Null

$fixturePath = Join-Path $repoRoot 'tests/coverage/fixtures/BranchFixture.ps1'
$instrumentedPath = Join-Path $artifactPath 'BranchFixture.instrumented.ps1'
$manifestPath = Join-Path $artifactPath 'branch-manifest.json'
$eventPath = Join-Path $artifactPath 'branch-events.tsv'
$reportPath = Join-Path $artifactPath 'branch-report.json'

Remove-Item -LiteralPath $eventPath -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath "$eventPath.shards" -Recurse -Force -ErrorAction SilentlyContinue

& (Join-Path $repoRoot 'scripts/coverage/Instrument-HHBranches.ps1') `
    -Path $fixturePath `
    -OutputPath $instrumentedPath `
    -ManifestPath $manifestPath

$tokens = $null
$errors = $null
[System.Management.Automation.Language.Parser]::ParseFile(
    $instrumentedPath,
    [ref]$tokens,
    [ref]$errors
) | Out-Null
if ($errors.Count -gt 0) {
    throw "Instrumented fixture does not parse: $($errors[0].Message)"
}

$env:HH_BRANCH_LOG = $eventPath
. $instrumentedPath

$cases = @(
    @{ Id = 'positive-alpha'; Mode = 'alpha'; Value = 2; Items = @(1, 2, 4); ThrowInTrapScope = $false },
    @{ Id = 'zero-beta-empty'; Mode = 'beta'; Value = 0; Items = @(); ThrowInTrapScope = $false },
    @{ Id = 'negative-default'; Mode = 'other'; Value = -1; Items = @(-1, 0, 4); ThrowInTrapScope = $false },
    @{ Id = 'regex-match'; Mode = 'regex-42'; Value = 2; Items = @(1); ThrowInTrapScope = $false },
    @{ Id = 'wildcard-and-trap'; Mode = 'wildcard-value'; Value = 1; Items = @(1); ThrowInTrapScope = $true },
    @{ Id = 'catch-invalid'; Mode = 'throw-invalid'; Value = 1; Items = @(1); ThrowInTrapScope = $false },
    @{ Id = 'catch-other'; Mode = 'throw-other'; Value = 1; Items = @(1); ThrowInTrapScope = $false }
)

foreach ($case in $cases) {
    $env:HH_COVERAGE_CASE = $case.Id
    Invoke-HHBranchFixture -Mode $case.Mode -Value $case.Value -Items $case.Items `
        -ThrowInTrapScope:([bool]$case.ThrowInTrapScope) | Out-Null
}

& (Join-Path $repoRoot 'scripts/coverage/Test-HHBranchCoverage.ps1') `
    -ManifestPath $manifestPath `
    -EventPath $eventPath `
    -Minimum 100 `
    -ReportPath $reportPath | Out-Null

$originalCases = @(
    . $fixturePath
    foreach ($case in $cases) {
        [pscustomobject]@{
            id = $case.Id
            output = @(Invoke-HHBranchFixture -Mode $case.Mode -Value $case.Value -Items $case.Items `
                    -ThrowInTrapScope:([bool]$case.ThrowInTrapScope))
        }
    }
)
. $instrumentedPath
$instrumentedCases = @(
    foreach ($case in $cases) {
        $env:HH_COVERAGE_CASE = "equivalence-$($case.Id)"
        [pscustomobject]@{
            id = $case.Id
            output = @(Invoke-HHBranchFixture -Mode $case.Mode -Value $case.Value -Items $case.Items `
                    -ThrowInTrapScope:([bool]$case.ThrowInTrapScope))
        }
    }
)
$originalJson = $originalCases | ConvertTo-Json -Depth 12 -Compress
$instrumentedJson = $instrumentedCases | ConvertTo-Json -Depth 12 -Compress
if ($originalJson -cne $instrumentedJson) {
    throw 'Instrumented and original fixture outputs are not semantically equivalent.'
}

$goldenPath = Join-Path $repoRoot 'tests/coverage/fixtures/BranchFixture.expected.json'
$goldenJson = Get-Content -LiteralPath $goldenPath -Raw |
    ConvertFrom-Json |
    ConvertTo-Json -Depth 12 -Compress
if ($originalJson -cne $goldenJson) {
    throw 'The original fixture output differs from its reviewed golden result.'
}

$negativeEventPath = Join-Path $artifactPath 'branch-events-negative.jsonl'
$env:HH_BRANCH_LOG = $negativeEventPath
$env:HH_COVERAGE_CASE = 'threshold-negative-single-case'
Invoke-HHBranchFixture -Mode alpha -Value 2 -Items @(1) | Out-Null

$negativeFailed = $false
try {
    & (Join-Path $repoRoot 'scripts/coverage/Test-HHBranchCoverage.ps1') `
        -ManifestPath $manifestPath `
        -EventPath $negativeEventPath `
        -Minimum 100 | Out-Null
}
catch {
    $negativeFailed = $true
}
if (-not $negativeFailed) {
    throw 'The negative fixture unexpectedly passed 100% branch coverage.'
}

$integrity = & (Join-Path $PSScriptRoot 'Invoke-CoverageIntegritySelfTest.ps1') `
    -ArtifactRoot (Join-Path $artifactPath 'integrity')
if ($integrity.Status -cne 'passed') {
    throw 'The coverage-integrity self-test did not pass.'
}

[pscustomobject]@{
    Status = 'passed'
    Manifest = $manifestPath
    Report = $reportPath
    SemanticEquivalence = $true
    GoldenOutput = $goldenPath
    NegativeThresholdProof = $true
    IntegrityReport = $integrity.Report
}
