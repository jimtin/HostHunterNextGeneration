[CmdletBinding()]
param(
    [string]$SourceRoot = 'src/HostHunterNextGeneration',
    [string[]]$AdditionalSourceRoot = @('client/HostHunter.Client'),
    [string]$TestPath = 'tests/unit',
    [string]$ArtifactRoot = '.artifacts/unit',
    [ValidateRange(0, 100)][double]$Minimum = 90,
    [string]$PesterVersion = '6.1.0'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$startedAt = [DateTime]::UtcNow
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path

function Resolve-HHCoveragePath([string]$Path) {
    if ([IO.Path]::IsPathRooted($Path)) { return [IO.Path]::GetFullPath($Path) }
    [IO.Path]::GetFullPath((Join-Path $repoRoot $Path))
}

function Write-HHCoverageJson {
    param([Parameter(Mandatory)]$Value, [Parameter(Mandatory)][string]$Path)
    [IO.Directory]::CreateDirectory((Split-Path -Parent $Path)) | Out-Null
    $temporary = "$Path.$([Guid]::NewGuid().ToString('N')).tmp"
    [IO.File]::WriteAllText(
        $temporary,
        ($Value | ConvertTo-Json -Depth 12),
        [Text.UTF8Encoding]::new($false)
    )
    [IO.File]::Move($temporary, $Path, $true)
}

function Test-HHCoveragePointInExtent($Point, $Extent) {
    ($Point.StartLine -gt $Extent.StartLineNumber -or
        ($Point.StartLine -eq $Extent.StartLineNumber -and
            $Point.StartColumn -ge $Extent.StartColumnNumber)) -and
    ($Point.StartLine -lt $Extent.EndLineNumber -or
        ($Point.StartLine -eq $Extent.EndLineNumber -and
            $Point.StartColumn -lt $Extent.EndColumnNumber))
}

function Test-HHCoverageFunctionInsideClass($FunctionAst) {
    for ($parent = $FunctionAst.Parent; $null -ne $parent; $parent = $parent.Parent) {
        if ($parent -is [Management.Automation.Language.FunctionMemberAst]) { return $true }
    }
    $false
}

function Test-HHIntegrationOwnedCoveragePoint($Point, [string]$RemoteSource) {
    if ([IO.Path]::GetFullPath([string]$Point.File) -cne $RemoteSource) { return $false }
    $line = [int]$Point.StartLine
    ($line -ge 21 -and $line -le 67) -or
    ($line -ge 85 -and $line -le 335) -or
    ($line -ge 353 -and $line -le 482)
}

$sourcePath = Resolve-HHCoveragePath $SourceRoot
$additionalSourcePaths = @($AdditionalSourceRoot | ForEach-Object { Resolve-HHCoveragePath $_ })
$testsPath = Resolve-HHCoveragePath $TestPath
$artifactPath = Resolve-HHCoveragePath $ArtifactRoot
$summaryPath = Join-Path $artifactPath 'coverage-summary.json'
$junitPath = Join-Path $artifactPath 'unit-tests.xml'
$coveragePath = Join-Path $artifactPath 'coverage.xml'
$originalTestSourceRoot = $env:HH_TEST_SOURCE_ROOT
$originalClientSourceRoot = $env:HH_TEST_CLIENT_SOURCE_ROOT

[IO.Directory]::CreateDirectory($artifactPath) | Out-Null
foreach ($staleArtifact in @($summaryPath, $junitPath, $coveragePath)) {
    if (Test-Path -LiteralPath $staleArtifact) {
        Remove-Item -LiteralPath $staleArtifact -Force
    }
}
$sourceFiles = @(
    @($sourcePath) + $additionalSourcePaths | ForEach-Object {
        Get-ChildItem -LiteralPath $_ -Recurse -File |
            Where-Object Extension -in @('.ps1', '.psm1')
    } | Sort-Object FullName -Unique
)
$windowsRemoteSource = [IO.Path]::GetFullPath((Join-Path `
            $sourcePath 'Private/CimRemoteCollection.ps1'))
$testFiles = @(
    if (Test-Path -LiteralPath $testsPath -PathType Leaf) {
        Get-Item -LiteralPath $testsPath
    }
    else {
        Get-ChildItem -LiteralPath $testsPath -Filter '*.Tests.ps1' -File |
            Sort-Object FullName
    }
)
if ($sourceFiles.Count -eq 0) { throw 'No shipped PowerShell source files were selected for coverage.' }
if ($testFiles.Count -eq 0) { throw 'No unit test files were selected for coverage.' }

$inventory = @($sourceFiles | ForEach-Object {
    [pscustomobject][ordered]@{
        path = [IO.Path]::GetRelativePath($repoRoot, $_.FullName).Replace(
            [IO.Path]::DirectorySeparatorChar,
            '/'
        )
        sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    }
})
$sourceHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData(
        [Text.Encoding]::UTF8.GetBytes(($inventory | ConvertTo-Json -Compress))
    )).ToLowerInvariant()
$candidateSha = if (-not [string]::IsNullOrWhiteSpace($env:HH_CANDIDATE_SHA)) {
    $env:HH_CANDIDATE_SHA
} else { try { (& git -C $repoRoot rev-parse HEAD 2>$null).Trim() } catch { $null } }
$candidateTree = if (-not [string]::IsNullOrWhiteSpace($env:HH_CANDIDATE_TREE)) {
    $env:HH_CANDIDATE_TREE
} else { try { (& git -C $repoRoot rev-parse 'HEAD^{tree}' 2>$null).Trim() } catch { $null } }
$functions = [Collections.Generic.List[object]]::new()

try {
    foreach ($sourceFile in $sourceFiles) {
        $tokens = $null
        $parseErrors = $null
        $ast = [Management.Automation.Language.Parser]::ParseFile(
            $sourceFile.FullName,
            [ref]$tokens,
            [ref]$parseErrors
        )
        if ($parseErrors.Count -gt 0) {
            throw "Coverage source '$($sourceFile.FullName)' has parse errors."
        }
        $nodes = @(
            $ast.FindAll(
                { param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] },
                $true
            ) | Where-Object { -not (Test-HHCoverageFunctionInsideClass $_) }
            $ast.FindAll(
                { param($node) $node -is [Management.Automation.Language.FunctionMemberAst] },
                $true
            )
        )
        foreach ($node in $nodes) {
            $functions.Add([pscustomobject]@{
                file = $sourceFile.FullName
                name = $node.Name
                extent = $node.Extent
                size = $node.Extent.EndOffset - $node.Extent.StartOffset
                covered = $false
                hasPoint = $false
            })
        }
    }

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
    $configuration.CodeCoverage.Enabled = $true
    $configuration.CodeCoverage.Path = @($sourceFiles.FullName)
    $configuration.CodeCoverage.OutputFormat = 'JaCoCo'
    $configuration.CodeCoverage.OutputPath = $coveragePath
    $configuration.CodeCoverage.CoveragePercentTarget = 0

    try {
        $env:HH_TEST_SOURCE_ROOT = $sourcePath
        $env:HH_TEST_CLIENT_SOURCE_ROOT = $additionalSourcePaths[0]
        Remove-Module HostHunterNextGeneration -Force -ErrorAction Ignore
        $result = Invoke-Pester -Configuration $configuration
    }
    finally {
        $env:HH_TEST_SOURCE_ROOT = $originalTestSourceRoot
        $env:HH_TEST_CLIENT_SOURCE_ROOT = $originalClientSourceRoot
        Remove-Module HostHunterNextGeneration -Force -ErrorAction Ignore
    }

    if ($null -eq $result.CodeCoverage) { throw 'Pester returned no native coverage result.' }
    $rawPoints = @($result.CodeCoverage.CommandsExecuted) + @($result.CodeCoverage.CommandsMissed)
    if ($rawPoints.Count -ne $result.CodeCoverage.CommandsAnalyzedCount) {
        throw 'Pester native coverage point counts are inconsistent.'
    }
    $points = @($rawPoints | Where-Object {
            -not (Test-HHIntegrationOwnedCoveragePoint $_ $windowsRemoteSource)
        })
    $integrationOwnedPointCount = $rawPoints.Count - $points.Count
    if ($integrationOwnedPointCount -le 0) {
        throw 'The Windows qualification coverage ownership boundary selected no commands.'
    }
    $analyzedFiles = @($result.CodeCoverage.FilesAnalyzed | ForEach-Object {
        [IO.Path]::GetFullPath([string]$_)
    })
    $missingFiles = @($sourceFiles.FullName | Where-Object {
        [IO.Path]::GetFullPath($_) -notin $analyzedFiles
    })
    if ($missingFiles.Count -gt 0) {
        throw "Pester omitted shipped source: $($missingFiles -join ', ')"
    }

    foreach ($point in $points) {
        $pointFile = [IO.Path]::GetFullPath([string]$point.File)
        $owner = @($functions | Where-Object {
            $_.file -eq $pointFile -and (Test-HHCoveragePointInExtent $point $_.extent)
        } | Sort-Object size | Select-Object -First 1)
        if ($owner.Count -eq 1) {
            $owner[0].hasPoint = $true
            if ($point.HitCount -gt 0) { $owner[0].covered = $true }
        }
    }
    $unmeasurable = @($functions | Where-Object { -not $_.hasPoint })
    if ($unmeasurable.Count -gt 0) {
        throw "Functions without executable coverage points: $($unmeasurable.name -join ', ')"
    }

    $lineGroups = @($points | Group-Object {
        '{0}:{1}' -f ([IO.Path]::GetFullPath([string]$_.File)), $_.StartLine
    })
    $coveredLines = @($lineGroups | Where-Object {
        @($_.Group | Where-Object HitCount -le 0).Count -eq 0
    }).Count
    $rawMetrics = [ordered]@{
        statements = [pscustomobject]@{
            covered = @($points | Where-Object HitCount -gt 0).Count
            total = $points.Count
            definition = 'Pester executable command locations in unit-owned scope'
        }
        lines = [pscustomobject]@{
            covered = $coveredLines
            total = $lineGroups.Count
            definition = 'Executable lines with every command executed'
        }
        functions = [pscustomobject]@{
            covered = @($functions | Where-Object covered).Count
            total = $functions.Count
            definition = 'AST functions owning an executed Pester coverage point'
        }
    }
    $evaluation = & (Join-Path $PSScriptRoot 'Test-HHCoverageMetrics.ps1') `
        -Metrics $rawMetrics -Minimum $Minimum
    $testsPassed = $result.Result -eq 'Passed' -and $result.FailedCount -eq 0
    $status = if (-not $testsPassed) {
        'test_failed'
    } elseif (-not $evaluation.passed) {
        'threshold_failed'
    } else { 'passed' }
    $summary = [ordered]@{
        schemaVersion = 3
        status = $status
        passed = $status -eq 'passed'
        minimum = $Minimum
        candidateSha = $candidateSha
        candidateTree = $candidateTree
        sourceHash = $sourceHash
        sourceSha256 = $sourceHash
        sourceInventory = $inventory
        sourceFileCount = $inventory.Count
        pesterVersion = $PesterVersion
        collector = 'pester-native'
        invocationCount = 1
        integrationOwnedCoverage = [ordered]@{
            path = 'src/HostHunterNextGeneration/Private/CimRemoteCollection.ps1'
            commandCount = $integrationOwnedPointCount
            owner = 'positive-windows-qualification'
            ranges = @('21-67','85-335','353-482')
        }
        testCount = $result.TotalCount
        tests = [ordered]@{ total = $result.TotalCount; failed = $result.FailedCount }
        metrics = $evaluation.metrics
        uncovered = [ordered]@{
            commands = @($points | Where-Object HitCount -le 0 | ForEach-Object {
                [pscustomobject]@{
                    file = $_.File
                    line = $_.StartLine
                    column = $_.StartColumn
                    command = $_.Command
                }
            })
            functions = @($functions | Where-Object { -not $_.covered } | ForEach-Object {
                [pscustomobject]@{
                    file = $_.file
                    name = $_.name
                    line = $_.extent.StartLineNumber
                }
            })
        }
        durationMs = [math]::Round(([DateTime]::UtcNow - $startedAt).TotalMilliseconds)
        durationSeconds = [math]::Round(([DateTime]::UtcNow - $startedAt).TotalSeconds, 3)
    }
    Write-HHCoverageJson -Value $summary -Path $summaryPath
    if ($status -ne 'passed') {
        throw "Coverage lane ended with status '$status'. See '$summaryPath'."
    }
    [pscustomobject]@{
        Status = 'passed'
        Tests = $result.PassedCount
        Metrics = $evaluation.metrics
        ArtifactRoot = $artifactPath
    }
}
catch {
    if (-not (Test-Path -LiteralPath $summaryPath)) {
        Write-HHCoverageJson -Path $summaryPath -Value ([ordered]@{
            schemaVersion = 3
            status = 'tooling_blocked'
            passed = $false
            minimum = $Minimum
            candidateSha = $candidateSha
            candidateTree = $candidateTree
            sourceHash = $sourceHash
            sourceSha256 = $sourceHash
            sourceInventory = $inventory
            sourceFileCount = $inventory.Count
            pesterVersion = $PesterVersion
            collector = 'pester-native'
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
