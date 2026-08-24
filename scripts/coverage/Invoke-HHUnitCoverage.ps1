[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string[]]$SourcePath,

    [Parameter(Mandatory)]
    [string[]]$TestPath,

    [Parameter(Mandatory)]
    [string]$BranchReportPath,

    [Parameter(Mandatory)]
    [string]$ArtifactRoot,

    [string]$ExpectedMetricsPath,

    [ValidateRange(0, 100)]
    [double]$Minimum = 90,

    [string]$PesterVersion = '6.1.0'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-HHPointInExtent {
    param(
        [Parameter(Mandatory)]$Point,
        [Parameter(Mandatory)]$Extent
    )

    $afterStart = $Point.StartLine -gt $Extent.StartLineNumber -or
        ($Point.StartLine -eq $Extent.StartLineNumber -and
            $Point.StartColumn -ge $Extent.StartColumnNumber)
    $beforeEnd = $Point.StartLine -lt $Extent.EndLineNumber -or
        ($Point.StartLine -eq $Extent.EndLineNumber -and
            $Point.StartColumn -lt $Extent.EndColumnNumber)
    return $afterStart -and $beforeEnd
}

function Test-HHInsideClassMethod {
    param([Parameter(Mandatory)]$FunctionAst)

    $parent = $FunctionAst.Parent
    while ($null -ne $parent) {
        if ($parent -is [System.Management.Automation.Language.FunctionMemberAst]) {
            return $true
        }
        $parent = $parent.Parent
    }
    return $false
}

$artifactPath = [System.IO.Path]::GetFullPath($ArtifactRoot)
[System.IO.Directory]::CreateDirectory($artifactPath) | Out-Null

$sourceFiles = @(
    @(
        foreach ($path in $SourcePath) {
            $item = Get-Item -LiteralPath $path
            if ($item.PSIsContainer) {
                Get-ChildItem -LiteralPath $item.FullName -Recurse -File |
                    Where-Object { $_.Extension -in @('.ps1', '.psm1') } |
                    Select-Object -ExpandProperty FullName
            }
            else {
                $item.FullName
            }
        }
    ) | Sort-Object -Unique
)

if ($sourceFiles.Count -eq 0) {
    throw 'No PowerShell source files were selected for unit coverage.'
}

$resolvedTests = @(
    foreach ($path in $TestPath) {
        (Resolve-Path -LiteralPath $path).Path
    }
)
if ($resolvedTests.Count -eq 0) {
    throw 'No Pester test paths were selected for unit coverage.'
}

$functionInventory = [System.Collections.Generic.List[object]]::new()
foreach ($sourceFile in $sourceFiles) {
    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $sourceFile,
        [ref]$tokens,
        [ref]$parseErrors
    )
    if ($parseErrors.Count -gt 0) {
        throw "Coverage source '$sourceFile' has parse errors: $($parseErrors[0].Message)"
    }

    $functions = @(
        $ast.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
            }, $true) |
            Where-Object { -not (Test-HHInsideClassMethod -FunctionAst $_) }
        $ast.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionMemberAst]
            }, $true)
    )

    foreach ($functionAst in $functions) {
        $kind = if ($functionAst -is [System.Management.Automation.Language.FunctionMemberAst]) {
            'class-method'
        }
        else {
            'function'
        }
        $functionInventory.Add([pscustomobject]@{
                id = ('{0}:{1}:{2}:{3}' -f @(
                        $sourceFile
                        $functionAst.Extent.StartLineNumber
                        $functionAst.Extent.StartColumnNumber
                        $functionAst.Name
                    ))
                file = $sourceFile
                name = $functionAst.Name
                kind = $kind
                extent = $functionAst.Extent
                size = $functionAst.Extent.EndOffset - $functionAst.Extent.StartOffset
                covered = $false
                hasCoveragePoint = $false
            })
    }
}

Import-Module Pester -RequiredVersion $PesterVersion -Force
$configuration = New-PesterConfiguration
$configuration.Run.Path = $resolvedTests
$configuration.Run.PassThru = $true
$configuration.Run.Exit = $false
$configuration.Filter.Tag = @('Unit')
$configuration.Output.Verbosity = 'Detailed'
$configuration.TestResult.Enabled = $true
$configuration.TestResult.OutputFormat = 'JUnitXml'
$configuration.TestResult.OutputPath = Join-Path $artifactPath 'unit-tests.xml'
$configuration.CodeCoverage.Enabled = $true
$configuration.CodeCoverage.Path = $sourceFiles
$configuration.CodeCoverage.OutputFormat = 'JaCoCo'
$configuration.CodeCoverage.OutputPath = Join-Path $artifactPath 'pester-coverage.xml'
$configuration.CodeCoverage.CoveragePercentTarget = $Minimum

$result = Invoke-Pester -Configuration $configuration
if ($null -eq $result.CodeCoverage) {
    throw 'Pester returned no code-coverage result.'
}

$coveragePoints = @($result.CodeCoverage.CommandsExecuted) +
    @($result.CodeCoverage.CommandsMissed)
if ($coveragePoints.Count -ne $result.CodeCoverage.CommandsAnalyzedCount) {
    throw 'Pester coverage point counts are internally inconsistent.'
}

$normalizedSourceFiles = @($sourceFiles | ForEach-Object { [System.IO.Path]::GetFullPath($_) })
$analyzedFiles = @(
    $result.CodeCoverage.FilesAnalyzed |
        ForEach-Object { [System.IO.Path]::GetFullPath([string]$_) } |
        Sort-Object -Unique
)
$missingFiles = @($normalizedSourceFiles | Where-Object { $_ -notin $analyzedFiles })
if ($missingFiles.Count -gt 0) {
    throw "Pester omitted coverage source files: $($missingFiles -join ', ')"
}

foreach ($point in $coveragePoints) {
    $pointFile = [System.IO.Path]::GetFullPath([string]$point.File)
    $owners = @(
        $functionInventory |
            Where-Object {
                $_.file -eq $pointFile -and
                (Test-HHPointInExtent -Point $point -Extent $_.extent)
            } |
            Sort-Object size
    )
    if ($owners.Count -gt 0) {
        $owner = $owners[0]
        $owner.hasCoveragePoint = $true
        if ($point.HitCount -gt 0) {
            $owner.covered = $true
        }
    }
}

$functionsWithoutPoints = @($functionInventory | Where-Object { -not $_.hasCoveragePoint })
if ($functionsWithoutPoints.Count -gt 0) {
    $names = $functionsWithoutPoints | ForEach-Object { "$($_.file):$($_.name)" }
    throw "Functions without measurable executable entry points are not allowed: $($names -join ', ')"
}

$lineGroups = @($coveragePoints | Group-Object {
        '{0}:{1}' -f ([System.IO.Path]::GetFullPath([string]$_.File)), $_.StartLine
    })
$coveredLines = @(
    $lineGroups | Where-Object {
        @($_.Group | Where-Object { $_.HitCount -le 0 }).Count -eq 0
    }
).Count

$branchReport = Get-Content -LiteralPath $BranchReportPath -Raw | ConvertFrom-Json
if ($null -eq $branchReport.PSObject.Properties['totalOutcomes'] -or
    $null -eq $branchReport.PSObject.Properties['coveredOutcomes']) {
    throw 'The branch report is missing outcome totals.'
}

$metrics = [ordered]@{
    statements = [ordered]@{
        covered = [int]$result.CodeCoverage.CommandsExecutedCount
        total = [int]$result.CodeCoverage.CommandsAnalyzedCount
        definition = 'Pester executable command/statement locations'
    }
    branches = [ordered]@{
        covered = [int]$branchReport.coveredOutcomes
        total = [int]$branchReport.totalOutcomes
        definition = 'instrumented runtime branch outcomes'
    }
    functions = [ordered]@{
        covered = @($functionInventory | Where-Object covered).Count
        total = $functionInventory.Count
        definition = 'AST functions and class methods with a directly owned executed point'
    }
    lines = [ordered]@{
        covered = $coveredLines
        total = $lineGroups.Count
        definition = 'executable source lines with every Pester point executed'
    }
}

if (-not [string]::IsNullOrWhiteSpace($ExpectedMetricsPath)) {
    $expectedMetrics = Get-Content -LiteralPath $ExpectedMetricsPath -Raw | ConvertFrom-Json
    foreach ($metricName in @('statements', 'branches', 'functions', 'lines')) {
        $expected = $expectedMetrics.PSObject.Properties[$metricName]
        if ($null -eq $expected) {
            throw "Expected metric '$metricName' is missing."
        }
        if ([int]$expected.Value.covered -ne [int]$metrics[$metricName].covered -or
            [int]$expected.Value.total -ne [int]$metrics[$metricName].total) {
            $driftMessage = 'Coverage-model drift for ''{0}'': expected {1}/{2}, got {3}/{4}.' -f @(
                $metricName
                $expected.Value.covered
                $expected.Value.total
                $metrics[$metricName].covered
                $metrics[$metricName].total
            )
            throw $driftMessage
        }
    }
}

$rawMetricsPath = Join-Path $artifactPath 'coverage-metrics.raw.json'
$metrics | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $rawMetricsPath -Encoding utf8NoBOM
$thresholdReport = & (Join-Path $PSScriptRoot 'Test-HHCoverageThresholds.ps1') `
    -MetricsPath $rawMetricsPath `
    -Minimum $Minimum `
    -ReportPath (Join-Path $artifactPath 'coverage-summary.json') `
    -JUnitPath (Join-Path $artifactPath 'coverage-thresholds.xml') `
    -PassThru

if ($result.Result -ne 'Passed' -or $result.FailedCount -gt 0) {
    throw "Pester unit tests failed: $($result.FailedCount) failure(s)."
}

[pscustomobject]@{
    Status = 'passed'
    Tests = $result.PassedCount
    Metrics = $thresholdReport.metrics
    ArtifactRoot = $artifactPath
}
