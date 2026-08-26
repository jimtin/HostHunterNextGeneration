[CmdletBinding()]
param(
    [string]$SourceRoot = 'src/HostHunterNextGeneration',
    [string]$TestPath = 'tests/unit',
    [string]$ArtifactRoot = '.artifacts/unit',
    [ValidateRange(0, 100)][double]$Minimum = 90,
    [string]$PesterVersion = '6.1.0'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$startedAt = [DateTime]::UtcNow
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
function Resolve-HHPath([string]$Path) {
    if ([IO.Path]::IsPathRooted($Path)) { return [IO.Path]::GetFullPath($Path) }
    [IO.Path]::GetFullPath((Join-Path $repoRoot $Path))
}
$sourcePath = Resolve-HHPath $SourceRoot
$testsPath = Resolve-HHPath $TestPath
$artifactPath = Resolve-HHPath $ArtifactRoot
$summaryPath = Join-Path $artifactPath 'coverage-summary.json'
$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) "hosthunter-coverage-$([Guid]::NewGuid().ToString('N'))"
$originalTestSourceRoot = $env:HH_TEST_SOURCE_ROOT
$originalCoverageHits = [AppDomain]::CurrentDomain.GetData('HostHunterCoverageHits')

function Write-HHJsonAtomic {
    param([Parameter(Mandatory)]$Value, [Parameter(Mandatory)][string]$Path, [int]$Depth = 12)
    $directory = Split-Path -Parent $Path
    [IO.Directory]::CreateDirectory($directory) | Out-Null
    $temporary = "$Path.$([Guid]::NewGuid().ToString('N')).tmp"
    [IO.File]::WriteAllText($temporary, ($Value | ConvertTo-Json -Depth $Depth), [Text.UTF8Encoding]::new($false))
    [IO.File]::Move($temporary, $Path, $true)
}
function Test-HHPointInExtent($Point, $Extent) {
    ($Point.StartLine -gt $Extent.StartLineNumber -or
        ($Point.StartLine -eq $Extent.StartLineNumber -and $Point.StartColumn -ge $Extent.StartColumnNumber)) -and
    ($Point.StartLine -lt $Extent.EndLineNumber -or
        ($Point.StartLine -eq $Extent.EndLineNumber -and $Point.StartColumn -lt $Extent.EndColumnNumber))
}
function Test-HHInsideClassMethod($FunctionAst) {
    for ($parent = $FunctionAst.Parent; $null -ne $parent; $parent = $parent.Parent) {
        if ($parent -is [Management.Automation.Language.FunctionMemberAst]) { return $true }
    }
    $false
}
[IO.Directory]::CreateDirectory($artifactPath) | Out-Null
foreach ($staleArtifact in @('coverage-summary.json', 'coverage.xml', 'unit-tests.xml')) {
    $stalePath = Join-Path $artifactPath $staleArtifact
    if (Test-Path -LiteralPath $stalePath) { Remove-Item -LiteralPath $stalePath -Force }
}
$sourceFiles = @(Get-ChildItem -LiteralPath $sourcePath -Recurse -File |
        Where-Object Extension -in @('.ps1', '.psm1') | Sort-Object FullName)
if ($sourceFiles.Count -eq 0) { throw 'No shipped PowerShell source files were selected for coverage.' }
$testFiles = @(
    if (Test-Path -LiteralPath $testsPath -PathType Leaf) {
        Get-Item -LiteralPath $testsPath
    }
    else {
        Get-ChildItem -LiteralPath $testsPath -Filter '*.Tests.ps1' -File | Sort-Object FullName
    }
)
if ($testFiles.Count -eq 0) { throw 'No unit test files were selected for coverage.' }

$inventory = @($sourceFiles | ForEach-Object {
        [pscustomobject][ordered]@{
            path = [IO.Path]::GetRelativePath($repoRoot, $_.FullName).Replace([IO.Path]::DirectorySeparatorChar, '/')
            sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    })
$inventoryPayload = $inventory | ConvertTo-Json -Compress
$sourceHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData(
        [Text.Encoding]::UTF8.GetBytes($inventoryPayload))).ToLowerInvariant()
$candidateSha = if (-not [string]::IsNullOrWhiteSpace($env:HH_CANDIDATE_SHA)) {
    $env:HH_CANDIDATE_SHA
} else { try { (& git -C $repoRoot rev-parse HEAD 2>$null).Trim() } catch { $null } }
$candidateTree = if (-not [string]::IsNullOrWhiteSpace($env:HH_CANDIDATE_TREE)) {
    $env:HH_CANDIDATE_TREE
} else { try { (& git -C $repoRoot rev-parse 'HEAD^{tree}' 2>$null).Trim() } catch { $null } }
$functions = [Collections.Generic.List[object]]::new()

try {
    foreach ($sourceFile in $sourceFiles) {
        $tokens = $null; $parseErrors = $null
        $ast = [Management.Automation.Language.Parser]::ParseFile($sourceFile.FullName, [ref]$tokens, [ref]$parseErrors)
        if ($parseErrors.Count -gt 0) { throw "Coverage source '$($sourceFile.FullName)' has parse errors." }
        $nodes = @(
            $ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] }, $true) |
                Where-Object { -not (Test-HHInsideClassMethod $_) }
            $ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionMemberAst] }, $true)
        )
        foreach ($node in $nodes) {
            $functions.Add([pscustomobject]@{
                    file = $sourceFile.FullName; name = $node.Name; extent = $node.Extent
                    size = $node.Extent.EndOffset - $node.Extent.StartOffset
                    covered = $false; hasPoint = $false
                })
        }
    }

    Import-Module Pester -RequiredVersion $PesterVersion -Force
    $nativeConfiguration = New-PesterConfiguration
    $nativeConfiguration.Run.Path = @($testFiles.FullName)
    $nativeConfiguration.Run.PassThru = $true
    $nativeConfiguration.Run.Exit = $false
    $nativeConfiguration.Filter.Tag = @('Unit')
    $nativeConfiguration.Output.Verbosity = 'Normal'
    $nativeConfiguration.TestResult.Enabled = $true
    $nativeConfiguration.TestResult.OutputFormat = 'JUnitXml'
    $nativeConfiguration.TestResult.OutputPath = Join-Path $artifactPath 'unit-tests.xml'
    $nativeConfiguration.CodeCoverage.Enabled = $true
    $nativeConfiguration.CodeCoverage.Path = @($sourceFiles.FullName)
    $nativeConfiguration.CodeCoverage.OutputFormat = 'JaCoCo'
    $nativeConfiguration.CodeCoverage.OutputPath = Join-Path $artifactPath 'coverage.xml'
    $nativeConfiguration.CodeCoverage.CoveragePercentTarget = 0
    try {
        $env:HH_TEST_SOURCE_ROOT = $sourcePath
        Remove-Module HostHunterNextGeneration -Force -ErrorAction Ignore
        $nativeResult = Invoke-Pester -Configuration $nativeConfiguration
    }
    finally {
        $env:HH_TEST_SOURCE_ROOT = $originalTestSourceRoot
        Remove-Module HostHunterNextGeneration -Force -ErrorAction Ignore
    }
    if ($null -eq $nativeResult.CodeCoverage) { throw 'Pester returned no native coverage result.' }

    $points = @($nativeResult.CodeCoverage.CommandsExecuted) + @($nativeResult.CodeCoverage.CommandsMissed)
    if ($points.Count -ne $nativeResult.CodeCoverage.CommandsAnalyzedCount) {
        throw 'Pester native coverage point counts are inconsistent.'
    }
    $analyzedFiles = @($nativeResult.CodeCoverage.FilesAnalyzed | ForEach-Object { [IO.Path]::GetFullPath([string]$_) })
    $missingFiles = @($sourceFiles.FullName | Where-Object { [IO.Path]::GetFullPath($_) -notin $analyzedFiles })
    if ($missingFiles.Count -gt 0) { throw "Pester omitted shipped source: $($missingFiles -join ', ')" }
    foreach ($point in $points) {
        $pointFile = [IO.Path]::GetFullPath([string]$point.File)
        $owner = @($functions | Where-Object {
                    $_.file -eq $pointFile -and (Test-HHPointInExtent $point $_.extent)
                } | Sort-Object size | Select-Object -First 1)
        if ($owner.Count -eq 1) {
            $owner[0].hasPoint = $true
            if ($point.HitCount -gt 0) { $owner[0].covered = $true }
        }
    }
    $unmeasurable = @($functions | Where-Object { -not $_.hasPoint })
    if ($unmeasurable.Count -gt 0) { throw "Functions without executable coverage points: $($unmeasurable.name -join ', ')" }

    $instrumentedRoot = Join-Path $temporaryRoot 'source'
    [IO.Directory]::CreateDirectory($instrumentedRoot) | Out-Null
    $manifests = [Collections.Generic.List[object]]::new()
    foreach ($file in Get-ChildItem -LiteralPath $sourcePath -Recurse -File) {
        $relative = [IO.Path]::GetRelativePath($sourcePath, $file.FullName)
        $destination = Join-Path $instrumentedRoot $relative
        [IO.Directory]::CreateDirectory((Split-Path -Parent $destination)) | Out-Null
        if ($file.Extension -in @('.ps1', '.psm1')) {
            $manifestPath = "$destination.coverage.json"
            & (Join-Path $PSScriptRoot 'Instrument-HHBranches.ps1') -Path $file.FullName `
                -OutputPath $destination -ManifestPath $manifestPath
            $manifests.Add((Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json))
            Remove-Item -LiteralPath $manifestPath -Force
        } else {
            Copy-Item -LiteralPath $file.FullName -Destination $destination
        }
    }
    $branches = @($manifests | ForEach-Object { @($_.branches) })
    $allOutcomes = @($branches | ForEach-Object { @($_.outcomes) })
    if ($allOutcomes.Count -eq 0) { throw 'Branch denominator is zero.' }
    $hits = [Collections.Concurrent.ConcurrentDictionary[string, byte]]::new([StringComparer]::Ordinal)
    [AppDomain]::CurrentDomain.SetData('HostHunterCoverageHits', $hits)
    try {
        $env:HH_TEST_SOURCE_ROOT = $instrumentedRoot
        Remove-Module HostHunterNextGeneration -Force -ErrorAction Ignore
        $branchConfiguration = New-PesterConfiguration
        $branchConfiguration.Run.Path = @($testFiles.FullName)
        $branchConfiguration.Run.PassThru = $true
        $branchConfiguration.Run.Exit = $false
        $branchConfiguration.Filter.Tag = @('Unit')
        $branchConfiguration.Output.Verbosity = 'Normal'
        $branchResult = Invoke-Pester -Configuration $branchConfiguration
    } finally {
        $env:HH_TEST_SOURCE_ROOT = $originalTestSourceRoot
        [AppDomain]::CurrentDomain.SetData('HostHunterCoverageHits', $originalCoverageHits)
        Remove-Module HostHunterNextGeneration -Force -ErrorAction Ignore
    }

    $outcomes = @(
        foreach ($branch in $branches) {
            foreach ($outcome in @($branch.outcomes)) {
                [pscustomobject][ordered]@{
                    branchId = $branch.id; kind = $branch.kind; source = $branch.source
                    function = $branch.function; line = [int]$branch.line; column = [int]$branch.column
                    outcomeId = $outcome.id; label = $outcome.label
                    covered = $hits.ContainsKey([string]$outcome.id)
                }
            }
        }
    )
    $lineGroups = @($points | Group-Object { '{0}:{1}' -f ([IO.Path]::GetFullPath([string]$_.File)), $_.StartLine })
    $coveredLines = @($lineGroups | Where-Object { @($_.Group | Where-Object HitCount -le 0).Count -eq 0 }).Count
    $rawMetrics = [ordered]@{
        statements = [pscustomobject]@{
            covered = $nativeResult.CodeCoverage.CommandsExecutedCount
            total = $nativeResult.CodeCoverage.CommandsAnalyzedCount
            definition = 'Pester executable command locations'
        }
        branches = [pscustomobject]@{
            covered = @($outcomes | Where-Object covered).Count
            total = $outcomes.Count
            definition = 'instrumented runtime outcomes'
        }
        functions = [pscustomobject]@{
            covered = @($functions | Where-Object covered).Count
            total = $functions.Count
            definition = 'AST functions with an owned executed point'
        }
        lines = [pscustomobject]@{
            covered = $coveredLines
            total = $lineGroups.Count
            definition = 'executable lines with every command executed'
        }
    }
    $metricEvaluation = & (Join-Path $PSScriptRoot 'Test-HHCoverageMetrics.ps1') `
        -Metrics $rawMetrics -Minimum $Minimum
    $metrics = $metricEvaluation.metrics
    $testsPassed = $nativeResult.Result -eq 'Passed' -and $nativeResult.FailedCount -eq 0 -and
        $branchResult.Result -eq 'Passed' -and $branchResult.FailedCount -eq 0
    $thresholdsPassed = $metricEvaluation.passed
    $status = if (-not $testsPassed) { 'test_failed' } elseif (-not $thresholdsPassed) { 'threshold_failed' } else { 'passed' }
    $summary = [ordered]@{
        schemaVersion = 2; status = $status; passed = $status -eq 'passed'; minimum = $Minimum
        candidateSha = $candidateSha; candidateTree = $candidateTree
        sourceHash = $sourceHash; sourceSha256 = $sourceHash
        sourceInventory = $inventory; sourceFileCount = $inventory.Count
        pesterVersion = $PesterVersion; collectorVersion = 1
        invocationCount = 2
        testCount = $nativeResult.TotalCount
        tests = [ordered]@{
            native = $nativeResult.TotalCount
            branch = $branchResult.TotalCount
            failed = $nativeResult.FailedCount + $branchResult.FailedCount
        }
        metrics = $metrics
        uncovered = [ordered]@{
            commands = @($nativeResult.CodeCoverage.CommandsMissed | ForEach-Object {
                    [pscustomobject]@{ file = $_.File; line = $_.StartLine; column = $_.StartColumn; command = $_.Command }
                })
            branches = @($outcomes | Where-Object { -not $_.covered })
            functions = @($functions | Where-Object { -not $_.covered } | ForEach-Object {
                    [pscustomobject]@{ file = $_.file; name = $_.name; line = $_.extent.StartLineNumber }
                })
        }
        durationMs = [math]::Round(([DateTime]::UtcNow - $startedAt).TotalMilliseconds)
        durationSeconds = [math]::Round(([DateTime]::UtcNow - $startedAt).TotalSeconds, 3)
    }
    Write-HHJsonAtomic -Value $summary -Path $summaryPath
    if ($status -ne 'passed') { throw "Coverage lane ended with status '$status'. See '$summaryPath'." }
    [pscustomobject]@{ Status = 'passed'; Tests = $nativeResult.PassedCount; Metrics = $metrics; ArtifactRoot = $artifactPath }
}
catch {
    if (-not (Test-Path -LiteralPath $summaryPath)) {
        $failure = [ordered]@{
            schemaVersion = 2; status = 'tooling_blocked'; passed = $false; minimum = $Minimum
            candidateSha = $candidateSha; candidateTree = $candidateTree
            sourceHash = $sourceHash; sourceSha256 = $sourceHash
            sourceInventory = $inventory; sourceFileCount = $inventory.Count
            pesterVersion = $PesterVersion; collectorVersion = 1
            testCount = 0
            error = $_.Exception.Message
            durationMs = [math]::Round(([DateTime]::UtcNow - $startedAt).TotalMilliseconds)
            durationSeconds = [math]::Round(([DateTime]::UtcNow - $startedAt).TotalSeconds, 3)
        }
        Write-HHJsonAtomic -Value $failure -Path $summaryPath
    }
    throw
}
finally {
    $env:HH_TEST_SOURCE_ROOT = $originalTestSourceRoot
    [AppDomain]::CurrentDomain.SetData('HostHunterCoverageHits', $originalCoverageHits)
    if (Test-Path -LiteralPath $temporaryRoot) { Remove-Item -LiteralPath $temporaryRoot -Recurse -Force }
}
