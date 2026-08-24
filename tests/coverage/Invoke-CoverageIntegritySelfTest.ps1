[CmdletBinding()]
param([string]$ArtifactRoot = '.artifacts/coverage-integrity')

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$artifactPath = if ([IO.Path]::IsPathRooted($ArtifactRoot)) {
    [IO.Path]::GetFullPath($ArtifactRoot)
} else { Join-Path $repoRoot $ArtifactRoot }
if (Test-Path -LiteralPath $artifactPath) {
    Remove-Item -LiteralPath $artifactPath -Recurse -Force
}
[IO.Directory]::CreateDirectory($artifactPath) | Out-Null

$fixturePath = Join-Path $PSScriptRoot 'fixtures/EarlyControlFixture.ps1'
$instrumentedPath = Join-Path $artifactPath 'EarlyControlFixture.instrumented.ps1'
$manifestPath = Join-Path $artifactPath 'branch-manifest.json'
$eventPath = Join-Path $artifactPath 'branch-events.jsonl'
$reportPath = Join-Path $artifactPath 'branch-report.json'
$gatePath = Join-Path $repoRoot 'scripts/coverage/Test-HHBranchCoverage.ps1'
& (Join-Path $repoRoot 'scripts/coverage/Instrument-HHBranches.ps1') `
    -Path $fixturePath -OutputPath $instrumentedPath -ManifestPath $manifestPath

function Get-HHEarlyControlResult {
    $escaped = $null
    try { Invoke-HHTryOutcomeFixture -Mode escaped | Out-Null } catch { $escaped = $_.Exception }
    [ordered]@{
        Return = @(Invoke-HHTryReturnFixture -Value alpha)
        Break = @(Invoke-HHTryLoopControlFixture -Mode break)
        Continue = @(Invoke-HHTryLoopControlFixture -Mode continue)
        Normal = @(Invoke-HHTryOutcomeFixture -Mode normal)
        Caught = @(Invoke-HHTryOutcomeFixture -Mode caught)
        AssignmentNormal = @((Invoke-HHTryAssignmentFixture -Mode normal).Value)
        AssignmentCaught = @((Invoke-HHTryAssignmentFixture -Mode caught).Value)
        EscapedType = $escaped.GetType().FullName
        EscapedMessage = $escaped.Message
    }
}

. $fixturePath
$original = Get-HHEarlyControlResult | ConvertTo-Json -Depth 8 -Compress
$env:HH_BRANCH_LOG = $eventPath
$env:HH_COVERAGE_CASE = 'early-control-shared-phase'
. $instrumentedPath
$instrumented = Get-HHEarlyControlResult | ConvertTo-Json -Depth 8 -Compress
Invoke-HHCorrelatedLoopFixture -Items @(1) | Out-Null
Invoke-HHCorrelatedLoopFixture -Items @() | Out-Null
if ($instrumented -cne $original) {
    throw 'Early-control instrumentation changed returned values or escaping errors.'
}

$report = & $gatePath -ManifestPath $manifestPath -EventPath $eventPath `
    -Minimum 0 -ReportPath $reportPath | ConvertFrom-Json
$returnTry = @($report.outcomes | Where-Object function -CEQ 'Invoke-HHTryReturnFixture')
$loopTry = @($report.outcomes | Where-Object function -CEQ 'Invoke-HHTryLoopControlFixture')
$outcomeTry = @($report.outcomes | Where-Object function -CEQ 'Invoke-HHTryOutcomeFixture')
$assignmentTry = @($report.outcomes | Where-Object function -CEQ 'Invoke-HHTryAssignmentFixture')
$correlatedLoop = @($report.outcomes | Where-Object function -CEQ 'Invoke-HHCorrelatedLoopFixture')
if (-not ($returnTry | Where-Object { $_.label -ceq 'normal' -and $_.covered }) -or
    -not ($loopTry | Where-Object { $_.label -ceq 'normal' -and $_.covered }) -or
    -not ($outcomeTry | Where-Object { $_.label -ceq 'normal' -and $_.covered }) -or
    -not ($outcomeTry | Where-Object { $_.label -ceq 'catch-0' -and $_.covered }) -or
    -not ($assignmentTry | Where-Object { $_.label -ceq 'normal' -and $_.covered }) -or
    -not ($assignmentTry | Where-Object { $_.label -ceq 'catch-0' -and $_.covered }) -or
    @($correlatedLoop | Where-Object covered).Count -ne 2) {
    throw 'Return, break, continue, assignment, normal, and caught try outcomes were not recorded correctly.'
}

$concurrentEventPath = Join-Path $artifactPath 'concurrent-events.jsonl'
$workers = [Collections.Generic.List[Diagnostics.Process]]::new()
foreach ($workerIndex in 1..6) {
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = (Get-Command pwsh -ErrorAction Stop).Source
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in @(
            '-NoLogo', '-NoProfile', '-NonInteractive', '-Command',
            ". '$instrumentedPath'; Invoke-HHTryReturnFixture -Value worker | Out-Null"
        )) {
        $null = $startInfo.ArgumentList.Add($argument)
    }
    $startInfo.Environment['HH_BRANCH_LOG'] = $concurrentEventPath
    $startInfo.Environment['HH_COVERAGE_CASE'] = "concurrent-worker-$workerIndex"
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    if (-not $process.Start()) { throw "Coverage worker $workerIndex did not start." }
    $workers.Add($process)
}
foreach ($worker in $workers) {
    $worker.WaitForExit()
    $stderr = $worker.StandardError.ReadToEnd()
    if ($worker.ExitCode -ne 0) {
        throw "Concurrent coverage worker failed with exit $($worker.ExitCode): $stderr"
    }
    $worker.Dispose()
}
$concurrentReport = & $gatePath -ManifestPath $manifestPath -EventPath $concurrentEventPath `
    -Minimum 0 -ReportPath (Join-Path $artifactPath 'concurrent-report.json') |
    ConvertFrom-Json
if ($concurrentReport.shardCount -ne 6 -or $concurrentReport.eventCount -lt 6) {
    throw 'Concurrent branch shards were not merged completely.'
}

function Assert-HHCorruptShardRejected {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Corrupt
    )

    $caseEventPath = Join-Path $artifactPath "$Name-events.jsonl"
    Copy-Item -LiteralPath "$concurrentEventPath.shards" `
        -Destination "$caseEventPath.shards" -Recurse
    & $Corrupt "$caseEventPath.shards"
    $threw = $false
    try {
        & $gatePath -ManifestPath $manifestPath -EventPath $caseEventPath -Minimum 0 | Out-Null
    }
    catch { $threw = $true }
    if (-not $threw) { throw "Corrupt shard case '$Name' did not fail closed." }
}

Assert-HHCorruptShardRejected -Name malformed -Corrupt {
    param($ShardRoot)
    $eventFile = Get-ChildItem -LiteralPath $ShardRoot -Filter '*.events.jsonl' -File |
        Select-Object -First 1
    Add-Content -LiteralPath $eventFile.FullName -Value '{'
}
Assert-HHCorruptShardRejected -Name unknown -Corrupt {
    param($ShardRoot)
    $eventFile = Get-ChildItem -LiteralPath $ShardRoot -Filter '*.events.jsonl' -File |
        Select-Object -First 1
    $lines = @(Get-Content -LiteralPath $eventFile.FullName)
    $record = $lines[0] | ConvertFrom-Json
    $record.eventId = 'aaaaaaaaaaaa-if-L1C1-0-unknown'
    $lines[0] = $record | ConvertTo-Json -Compress
    Set-Content -LiteralPath $eventFile.FullName -Value $lines -Encoding utf8NoBOM
}
Assert-HHCorruptShardRejected -Name lost-event -Corrupt {
    param($ShardRoot)
    $indexFile = Get-ChildItem -LiteralPath $ShardRoot -Filter '*.index.tsv' -File |
        Select-Object -First 1
    $lines = @(Get-Content -LiteralPath $indexFile.FullName)
    Set-Content -LiteralPath $indexFile.FullName -Value @($lines | Select-Object -SkipLast 1) `
        -Encoding utf8NoBOM
}
Assert-HHCorruptShardRejected -Name lost-shard -Corrupt {
    param($ShardRoot)
    $eventFile = Get-ChildItem -LiteralPath $ShardRoot -Filter '*.events.jsonl' -File |
        Select-Object -First 1
    Remove-Item -LiteralPath $eventFile.FullName -Force
}

$env:HH_BRANCH_LOG = $null
$env:HH_COVERAGE_CASE = $null
[pscustomobject]@{
    Status = 'passed'
    SemanticEquivalence = $true
    EarlyControl = $true
    ConcurrentShards = $concurrentReport.shardCount
    CorruptionCases = 4
    Report = $reportPath
}
