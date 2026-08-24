[CmdletBinding()]
param(
    [string]$ArtifactRoot = '.artifacts/coverage-thresholds'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$fixtureRoot = Join-Path $PSScriptRoot 'fixtures/thresholds'
$artifactPath = if ([System.IO.Path]::IsPathRooted($ArtifactRoot)) {
    [System.IO.Path]::GetFullPath($ArtifactRoot)
}
else {
    Join-Path $repoRoot $ArtifactRoot
}
[System.IO.Directory]::CreateDirectory($artifactPath) | Out-Null
$gatePath = Join-Path $repoRoot 'scripts/coverage/Test-HHCoverageThresholds.ps1'

$cases = @(
    @{ Name = 'all-pass'; ExpectedFailures = @() },
    @{ Name = 'statements-below'; ExpectedFailures = @('statements') },
    @{ Name = 'branches-below'; ExpectedFailures = @('branches') },
    @{ Name = 'functions-below'; ExpectedFailures = @('functions') },
    @{ Name = 'lines-below'; ExpectedFailures = @('lines') },
    @{ Name = 'zero-statements'; ExpectedFailures = @('statements') },
    @{ Name = 'missing-functions'; ExpectedFailures = @('functions') }
)

foreach ($case in $cases) {
    $report = & $gatePath `
        -MetricsPath (Join-Path $fixtureRoot "$($case.Name).json") `
        -Minimum 90 `
        -ReportPath (Join-Path $artifactPath "$($case.Name)-report.json") `
        -JUnitPath (Join-Path $artifactPath "$($case.Name)-junit.xml") `
        -NoThrow `
        -PassThru

    $actualFailures = @(
        $report.metrics |
            Where-Object { -not $_.passed } |
            Select-Object -ExpandProperty name
    )
    $difference = Compare-Object -ReferenceObject @($case.ExpectedFailures) `
        -DifferenceObject @($actualFailures)
    if ($difference) {
        throw "Threshold case '$($case.Name)' failed the wrong metrics."
    }
    if (($case.ExpectedFailures.Count -eq 0) -ne [bool]$report.passed) {
        throw "Threshold case '$($case.Name)' returned an incorrect overall result."
    }

    if ($case.ExpectedFailures.Count -gt 0) {
        $threw = $false
        try {
            & $gatePath `
                -MetricsPath (Join-Path $fixtureRoot "$($case.Name).json") `
                -Minimum 90 `
                -ReportPath (Join-Path $artifactPath "$($case.Name)-throw-report.json") `
                -JUnitPath (Join-Path $artifactPath "$($case.Name)-throw-junit.xml") | Out-Null
        }
        catch {
            $threw = $true
        }
        if (-not $threw) {
            throw "Threshold case '$($case.Name)' did not fail closed."
        }
    }
}

[pscustomobject]@{
    Status = 'passed'
    Cases = $cases.Count
    ArtifactRoot = $artifactPath
}
