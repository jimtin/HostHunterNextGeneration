[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ManifestPath,
    [Parameter(Mandatory)][string]$EventPath,
    [double]$Minimum = 90,
    [string]$ReportPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-HHBranchEventChecksum {
    param([Parameter(Mandatory)][string]$Payload)

    $bytes = [Text.Encoding]::UTF8.GetBytes($Payload)
    return [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($bytes)
    ).ToLowerInvariant()
}

function Get-HHBranchKnownEventId {
    param([Parameter(Mandatory)]$Branch)

    if ($Branch.strategy -ceq 'direct') {
        @($Branch.outcomes | ForEach-Object id)
    }
    else {
        foreach ($propertyName in @('evaluationId', 'bodyId', 'rhsId', 'handlerId', 'completedId')) {
            $property = $Branch.PSObject.Properties[$propertyName]
            if ($null -ne $property -and -not [string]::IsNullOrWhiteSpace([string]$property.Value)) {
                [string]$property.Value
            }
        }
    }
}

function Assert-HHBranchObjectPropertySet {
    param(
        [Parameter(Mandatory)]$Object,
        [Parameter(Mandatory)][string[]]$Expected,
        [Parameter(Mandatory)][string]$Description
    )

    $actual = @($Object.PSObject.Properties.Name | Sort-Object)
    $expectedSorted = @($Expected | Sort-Object)
    if (($actual -join "`n") -cne ($expectedSorted -join "`n")) {
        throw "$Description has an invalid property set."
    }
}

$manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
if ([int]$manifest.schemaVersion -ne 2) {
    throw "Unsupported branch manifest schema '$($manifest.schemaVersion)'."
}
$knownEventIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($branch in $manifest.branches) {
    foreach ($id in @(Get-HHBranchKnownEventId -Branch $branch)) {
        if (-not $knownEventIds.Add([string]$id)) {
            throw "Duplicate branch event identifier '$id' in the manifest."
        }
    }
}

$resolvedEventPath = [IO.Path]::GetFullPath($EventPath)
$shardRoot = "$resolvedEventPath.shards"
if (-not [IO.Directory]::Exists($shardRoot)) {
    throw "Branch shard directory '$shardRoot' does not exist."
}
$markerFiles = @(Get-ChildItem -LiteralPath $shardRoot -Filter '*.expected.json' -File |
        Sort-Object Name)
if ($markerFiles.Count -eq 0) {
    throw 'No expected branch-event shards were registered.'
}

$markerSuffix = '.expected.json'
$expectedShardIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$validatedEvents = [Collections.Generic.List[object]]::new()
foreach ($markerFile in $markerFiles) {
    $shardId = $markerFile.Name.Substring(0, $markerFile.Name.Length - $markerSuffix.Length)
    if (-not $expectedShardIds.Add($shardId)) {
        throw "Duplicate expected branch shard '$shardId'."
    }
    $marker = Get-Content -LiteralPath $markerFile.FullName -Raw | ConvertFrom-Json
    Assert-HHBranchObjectPropertySet -Object $marker -Expected @(
        'schemaVersion', 'shardId', 'processId', 'processStartUtcTicks', 'runspaceId'
    ) -Description "Branch shard marker '$($markerFile.Name)'"
    if ([int]$marker.schemaVersion -ne 2 -or [string]$marker.shardId -cne $shardId -or
        $shardId -notmatch '^[0-9]+-[0-9]+-[a-f0-9]{32}$') {
        throw "Branch shard marker '$($markerFile.Name)' is malformed."
    }

    $eventFile = Join-Path $shardRoot "$shardId.events.jsonl"
    $indexFile = Join-Path $shardRoot "$shardId.index.tsv"
    if (-not [IO.File]::Exists($eventFile) -or -not [IO.File]::Exists($indexFile)) {
        throw "Expected branch shard '$shardId' is incomplete or lost."
    }
    $eventLines = @(Get-Content -LiteralPath $eventFile)
    $indexLines = @(Get-Content -LiteralPath $indexFile)
    if ($eventLines.Count -eq 0 -or $eventLines.Count -ne $indexLines.Count) {
        throw "Branch shard '$shardId' has lost or unindexed events."
    }

    $previousChecksum = '0' * 64
    for ($index = 0; $index -lt $eventLines.Count; $index++) {
        try {
            $branchEvent = $eventLines[$index] | ConvertFrom-Json -ErrorAction Stop
        }
        catch {
            throw "Branch shard '$shardId' contains malformed JSON at sequence $($index + 1)."
        }
        Assert-HHBranchObjectPropertySet -Object $branchEvent -Expected @(
            'schemaVersion', 'shardId', 'sequence', 'caseId', 'eventId',
            'correlationId', 'previousChecksum', 'checksum'
        ) -Description "Branch shard '$shardId' event $($index + 1)"
        $sequence = [long]$branchEvent.sequence
        if ([int]$branchEvent.schemaVersion -ne 2 -or [string]$branchEvent.shardId -cne $shardId -or
            $sequence -ne ($index + 1) -or
            [string]$branchEvent.previousChecksum -cne $previousChecksum) {
            throw "Branch shard '$shardId' has a broken sequence or hash chain at event $($index + 1)."
        }
        if ([string]::IsNullOrWhiteSpace([string]$branchEvent.caseId)) {
            throw "Branch shard '$shardId' event $sequence has no coverage case."
        }
        if (-not $knownEventIds.Contains([string]$branchEvent.eventId)) {
            throw "Branch shard '$shardId' contains unknown event '$($branchEvent.eventId)'."
        }
        $correlationId = [string]$branchEvent.correlationId
        if (-not [string]::IsNullOrEmpty($correlationId) -and
            $correlationId -notmatch '^[a-f0-9]{32}$') {
            throw "Branch shard '$shardId' event $sequence has an invalid correlation identifier."
        }
        $payload = '{0}{1}{2}{1}{3}{1}{4}{1}{5}{1}{6}' -f @(
            $shardId, [char]9, $sequence, [string]$branchEvent.caseId,
            [string]$branchEvent.eventId, $correlationId, $previousChecksum
        )
        $checksum = Get-HHBranchEventChecksum -Payload $payload
        if ([string]$branchEvent.checksum -cne $checksum) {
            throw "Branch shard '$shardId' event $sequence failed checksum validation."
        }
        $indexParts = $indexLines[$index] -split "`t", 2
        if ($indexParts.Count -ne 2 -or [long]$indexParts[0] -ne $sequence -or
            $indexParts[1] -cne $checksum) {
            throw "Branch shard '$shardId' has a corrupt index at sequence $sequence."
        }
        $previousChecksum = $checksum
        $validatedEvents.Add([pscustomobject]@{
                shardId = $shardId
                sequence = $sequence
                caseId = [string]$branchEvent.caseId
                eventId = [string]$branchEvent.eventId
                correlationId = $correlationId
                checksum = $checksum
            })
    }
}

foreach ($eventFile in @(Get-ChildItem -LiteralPath $shardRoot -Filter '*.events.jsonl' -File)) {
    $shardId = $eventFile.Name.Substring(0, $eventFile.Name.Length - '.events.jsonl'.Length)
    if (-not $expectedShardIds.Contains($shardId)) {
        throw "Orphan branch event shard '$shardId' was not registered."
    }
}
foreach ($indexFile in @(Get-ChildItem -LiteralPath $shardRoot -Filter '*.index.tsv' -File)) {
    $shardId = $indexFile.Name.Substring(0, $indexFile.Name.Length - '.index.tsv'.Length)
    if (-not $expectedShardIds.Contains($shardId)) {
        throw "Orphan branch index shard '$shardId' was not registered."
    }
}

$sortedEvents = @($validatedEvents | Sort-Object shardId, sequence)
$mergedDirectory = Split-Path -Parent $resolvedEventPath
if ($mergedDirectory) { [IO.Directory]::CreateDirectory($mergedDirectory) | Out-Null }
$mergedLines = @($sortedEvents | ForEach-Object { $_ | ConvertTo-Json -Compress })
[IO.File]::WriteAllLines($resolvedEventPath, $mergedLines, [Text.UTF8Encoding]::new($false))

$eventsByCase = @{}
$eventsByEventId = @{}
$coveredEventIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($branchEvent in $sortedEvents) {
    if (-not $eventsByCase.ContainsKey($branchEvent.caseId)) {
        $eventsByCase[$branchEvent.caseId] = [Collections.Generic.List[string]]::new()
    }
    $eventsByCase[$branchEvent.caseId].Add($branchEvent.eventId)
    $null = $coveredEventIds.Add($branchEvent.eventId)
    if (-not $eventsByEventId.ContainsKey($branchEvent.eventId)) {
        $eventsByEventId[$branchEvent.eventId] = [Collections.Generic.List[object]]::new()
    }
    $eventsByEventId[$branchEvent.eventId].Add($branchEvent)
}

$outcomeResults = [Collections.Generic.List[object]]::new()
function Add-HHBranchOutcomeResult {
    param($Branch, $Outcome, [bool]$Covered)

    $outcomeResults.Add([pscustomobject][ordered]@{
            branchId = $Branch.id
            kind = $Branch.kind
            source = $Branch.source
            function = $Branch.function
            line = [int]$Branch.line
            column = [int]$Branch.column
            outcomeId = $Outcome.id
            label = $Outcome.label
            covered = $Covered
        })
}

foreach ($branch in $manifest.branches) {
    switch ($branch.strategy) {
        'direct' {
            foreach ($outcome in $branch.outcomes) {
                $covered = $coveredEventIds.Contains([string]$outcome.id)
                Add-HHBranchOutcomeResult -Branch $branch -Outcome $outcome -Covered:$covered
            }
        }
        'evaluation-vs-body' {
            $evaluations = if ($eventsByEventId.ContainsKey([string]$branch.evaluationId)) {
                @($eventsByEventId[[string]$branch.evaluationId])
            }
            else { @() }
            $bodies = if ($eventsByEventId.ContainsKey([string]$branch.bodyId)) {
                @($eventsByEventId[[string]$branch.bodyId])
            }
            else { @() }
            if (@($evaluations | Where-Object { [string]::IsNullOrEmpty($_.correlationId) }).Count -gt 0 -or
                @($bodies | Where-Object { [string]::IsNullOrEmpty($_.correlationId) }).Count -gt 0) {
                throw "Loop branch '$($branch.id)' contains an uncorrelated event."
            }
            $evaluationTokens = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
            foreach ($branchEvent in $evaluations) {
                if (-not $evaluationTokens.Add($branchEvent.correlationId)) {
                    throw "Loop branch '$($branch.id)' reused correlation '$($branchEvent.correlationId)'."
                }
            }
            $bodyTokens = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
            foreach ($branchEvent in $bodies) {
                if (-not $evaluationTokens.Contains($branchEvent.correlationId)) {
                    throw "Loop branch '$($branch.id)' has a body event without its evaluation."
                }
                $null = $bodyTokens.Add($branchEvent.correlationId)
            }
            $emptyCovered = $false
            foreach ($token in $evaluationTokens) {
                if (-not $bodyTokens.Contains($token)) { $emptyCovered = $true; break }
            }
            Add-HHBranchOutcomeResult -Branch $branch -Outcome $branch.outcomes[0] `
                -Covered:($bodyTokens.Count -gt 0)
            Add-HHBranchOutcomeResult -Branch $branch -Outcome $branch.outcomes[1] `
                -Covered:$emptyCovered
        }
        { $_ -in @('evaluation-vs-rhs', 'evaluation-vs-handler') } {
            $selectedId = if ($branch.strategy -eq 'evaluation-vs-rhs') {
                $branch.rhsId
            } else { $branch.handlerId }
            $selectedCovered = $false
            $notSelectedCovered = $false
            foreach ($events in $eventsByCase.Values) {
                if ($events.Contains([string]$selectedId)) { $selectedCovered = $true }
                if ($events.Contains([string]$branch.evaluationId) -and
                    -not $events.Contains([string]$selectedId)) { $notSelectedCovered = $true }
            }
            Add-HHBranchOutcomeResult -Branch $branch -Outcome $branch.outcomes[0] -Covered:$selectedCovered
            Add-HHBranchOutcomeResult -Branch $branch -Outcome $branch.outcomes[1] -Covered:$notSelectedCovered
        }
        'post-test-loop' {
            $repeatedCovered = $false
            $exitCovered = $false
            foreach ($events in $eventsByCase.Values) {
                if (@($events | Where-Object { $_ -ceq $branch.bodyId }).Count -gt 1) {
                    $repeatedCovered = $true
                }
                if ($events.Contains([string]$branch.completedId)) { $exitCovered = $true }
            }
            Add-HHBranchOutcomeResult -Branch $branch -Outcome $branch.outcomes[0] -Covered:$repeatedCovered
            Add-HHBranchOutcomeResult -Branch $branch -Outcome $branch.outcomes[1] -Covered:$exitCovered
        }
        default { throw "Unknown branch strategy '$($branch.strategy)'." }
    }
}

$total = $outcomeResults.Count
if ($total -eq 0) { throw 'Branch denominator is zero.' }
$coveredCount = @($outcomeResults | Where-Object covered).Count
$percentage = [math]::Round(($coveredCount / $total) * 100, 4)
$report = [ordered]@{
    schemaVersion = 2
    sourceSha256 = $manifest.sourceSha256
    totalBranches = $manifest.branchCount
    totalOutcomes = $total
    coveredOutcomes = $coveredCount
    branchCoveragePercent = $percentage
    minimum = $Minimum
    passed = $percentage -ge $Minimum
    shardCount = $markerFiles.Count
    eventCount = $sortedEvents.Count
    mergedEventPath = $resolvedEventPath
    outcomes = $outcomeResults.ToArray()
}
if ($ReportPath) {
    $directory = Split-Path -Parent $ReportPath
    if ($directory) { [IO.Directory]::CreateDirectory($directory) | Out-Null }
    $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $ReportPath -Encoding utf8NoBOM
}
$report | ConvertTo-Json -Depth 8
if (-not $report.passed) {
    throw "Branch coverage $percentage% is below the required $Minimum%."
}
