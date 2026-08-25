[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ManifestPath,
    [Parameter(Mandatory)][string]$EventPath,
    [double]$Minimum = 90,
    [string]$ReportPath
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$budgetBytes = 20MB

function Get-HHBranchChecksum {
    param([Parameter(Mandatory)][string]$Payload)
    [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData(
        [Text.Encoding]::UTF8.GetBytes($Payload))).ToLowerInvariant()
}
function Assert-HHPropertySet {
    param($Object, [string[]]$Expected, [string]$Description)
    $actual = @($Object.PSObject.Properties.Name | Sort-Object)
    if (($actual -join "`n") -cne (@($Expected | Sort-Object) -join "`n")) {
        throw "$Description has an invalid property set."
    }
}
function Get-HHKnownEventId {
    param($Branch)
    if ($Branch.strategy -ceq 'direct') { @($Branch.outcomes | ForEach-Object id) }
    else {
        foreach ($name in @('evaluationId', 'rhsId', 'handlerId', 'bodyId', 'completedId')) {
            $property = $Branch.PSObject.Properties[$name]
            if ($null -ne $property -and -not [string]::IsNullOrWhiteSpace([string]$property.Value)) {
                [string]$property.Value
            }
        }
    }
}

$manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
if ([int]$manifest.schemaVersion -ne 2) { throw "Unsupported branch manifest schema '$($manifest.schemaVersion)'." }
$knownEventIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($branch in $manifest.branches) {
    if ($branch.strategy -ceq 'evaluation-vs-body') {
        throw "Legacy correlation-heavy branch strategy '$($branch.strategy)' is not compact-proof compatible."
    }
    foreach ($id in @(Get-HHKnownEventId $branch)) {
        if (-not $knownEventIds.Add([string]$id)) { throw "Duplicate branch event identifier '$id' in the manifest." }
    }
}

$resolvedEventPath = [IO.Path]::GetFullPath($EventPath)
$shardRoot = "$resolvedEventPath.shards"
if (-not [IO.Directory]::Exists($shardRoot)) { throw "Branch shard directory '$shardRoot' does not exist." }
$allFiles = @(Get-ChildItem -LiteralPath $shardRoot -File | Sort-Object Name)
$unexpected = @($allFiles | Where-Object Name -cnotmatch '^[0-9]+-[0-9]+-[a-f0-9]{32}\.(compact|expected)\.json$')
if ($unexpected.Count -gt 0) { throw "Branch shard directory contains non-compact or incomplete data '$($unexpected[0].Name)'." }
$shardFiles = @($allFiles | Where-Object Name -CLike '*.compact.json')
if ($shardFiles.Count -eq 0) { throw 'No compact branch shards were registered.' }
$markerFiles = @($allFiles | Where-Object Name -CLike '*.expected.json')
if ($markerFiles.Count -ne $shardFiles.Count) { throw 'One or more expected compact branch shards are incomplete or lost.' }
$workingBytes = [long]($allFiles | Measure-Object Length -Sum).Sum
if ($workingBytes -gt $budgetBytes) {
    throw "ArtifactBudgetExceeded: coverage working data is $workingBytes bytes; limit is $budgetBytes bytes."
}

$seenShards = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$coveredEvents = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$eventsByCase = @{}
$countsByEvent = @{}
$eventCount = 0L
foreach ($file in $shardFiles) {
    try { $shard = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json -ErrorAction Stop }
    catch { throw "Compact branch shard '$($file.Name)' contains malformed JSON." }
    $shardProperties = @(
        'schemaVersion', 'shardId', 'processId', 'processStartUtcTicks',
        'runspaceId', 'eventCount', 'hits', 'checksum'
    )
    Assert-HHPropertySet $shard $shardProperties `
        "Compact branch shard '$($file.Name)'"
    $expectedId = $file.Name.Substring(0, $file.Name.Length - '.compact.json'.Length)
    $markerPath = Join-Path $shardRoot "$expectedId.expected.json"
    if (-not [IO.File]::Exists($markerPath)) { throw "Expected compact branch shard '$expectedId' is missing its marker." }
    try { $marker = Get-Content -LiteralPath $markerPath -Raw | ConvertFrom-Json -ErrorAction Stop }
    catch { throw "Compact branch marker '$expectedId.expected.json' contains malformed JSON." }
    $markerProperties = @(
        'schemaVersion', 'shardId', 'processId', 'processStartUtcTicks',
        'runspaceId', 'checksum'
    )
    Assert-HHPropertySet $marker $markerProperties `
        "Compact branch marker '$expectedId.expected.json'"
    $markerContent = [ordered]@{
        schemaVersion = [int]$marker.schemaVersion; shardId = [string]$marker.shardId
        processId = [int]$marker.processId; processStartUtcTicks = [long]$marker.processStartUtcTicks
        runspaceId = [string]$marker.runspaceId
    }
    if ([int]$marker.schemaVersion -ne 3 -or [string]$marker.shardId -cne $expectedId -or
        [string]$marker.checksum -cne (Get-HHBranchChecksum ($markerContent | ConvertTo-Json -Compress))) {
        throw "Compact branch marker '$expectedId.expected.json' failed validation."
    }
    if ([int]$shard.schemaVersion -ne 3 -or [string]$shard.shardId -cne $expectedId -or
        $expectedId -notmatch '^[0-9]+-[0-9]+-[a-f0-9]{32}$' -or -not $seenShards.Add($expectedId)) {
        throw "Compact branch shard '$($file.Name)' has an invalid or duplicate identity."
    }
    if ([int]$shard.processId -ne $markerContent.processId -or
        [long]$shard.processStartUtcTicks -ne $markerContent.processStartUtcTicks -or
        [string]$shard.runspaceId -cne $markerContent.runspaceId) {
        throw "Compact branch shard '$($file.Name)' does not match its marker."
    }
    $canonicalHits = @(
        foreach ($hit in @($shard.hits)) {
            [ordered]@{ caseId = [string]$hit.caseId; eventId = [string]$hit.eventId; count = [int]$hit.count }
        }
    )
    $content = [ordered]@{
        schemaVersion = 3; shardId = [string]$shard.shardId; processId = [int]$shard.processId
        processStartUtcTicks = [long]$shard.processStartUtcTicks; runspaceId = [string]$shard.runspaceId
        eventCount = [long]$shard.eventCount; hits = $canonicalHits
    }
    $expectedChecksum = Get-HHBranchChecksum ($content | ConvertTo-Json -Depth 5 -Compress)
    if ([string]$shard.checksum -cne $expectedChecksum) { throw "Compact branch shard '$($file.Name)' failed checksum validation." }
    if ($content.eventCount -lt 1 -or $content.hits.Count -lt 1) { throw "Compact branch shard '$($file.Name)' contains no events." }
    $eventCount += $content.eventCount
    $seenHits = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $minimumEvents = 0L
    foreach ($hit in @($shard.hits)) {
        Assert-HHPropertySet $hit @('caseId', 'eventId', 'count') "Compact hit in '$($file.Name)'"
        $caseId = [string]$hit.caseId
        $eventId = [string]$hit.eventId
        $count = [int]$hit.count
        $key = "$caseId`t$eventId"
        if ([string]::IsNullOrWhiteSpace($caseId) -or $caseId.Length -gt 256 -or
            $caseId -match "[`r`n`t]" -or -not $knownEventIds.Contains($eventId) -or
            $count -lt 1 -or $count -gt 2 -or -not $seenHits.Add($key)) {
            throw "Compact branch shard '$($file.Name)' contains an invalid hit."
        }
        $minimumEvents += $count
        $null = $coveredEvents.Add($eventId)
        if (-not $eventsByCase.ContainsKey($caseId)) {
            $eventsByCase[$caseId] = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        }
        $null = $eventsByCase[$caseId].Add($eventId)
        $priorCount = if ($countsByEvent.ContainsKey($eventId)) { [int]$countsByEvent[$eventId] } else { 0 }
        $countsByEvent[$eventId] = [math]::Min(2, $priorCount + $count)
    }
    if ($content.eventCount -lt $minimumEvents) { throw "Compact branch shard '$($file.Name)' has an impossible event count." }
}

$outcomes = [Collections.Generic.List[object]]::new()
function Add-HHOutcome {
    param($Branch, $Outcome, [bool]$Covered)
    $outcomes.Add([pscustomobject][ordered]@{
        branchId = $Branch.id; kind = $Branch.kind; source = $Branch.source; function = $Branch.function
        line = [int]$Branch.line; column = [int]$Branch.column; outcomeId = $Outcome.id
        label = $Outcome.label; covered = $Covered
    })
}
foreach ($branch in $manifest.branches) {
    switch ($branch.strategy) {
        'direct' {
            foreach ($outcome in $branch.outcomes) { Add-HHOutcome $branch $outcome $coveredEvents.Contains([string]$outcome.id) }
        }
        { $_ -in @('evaluation-vs-rhs', 'evaluation-vs-handler') } {
            $selectedId = if ($branch.strategy -ceq 'evaluation-vs-rhs') { [string]$branch.rhsId } else { [string]$branch.handlerId }
            $selected = $false; $notSelected = $false
            foreach ($caseEvents in $eventsByCase.Values) {
                if ($caseEvents.Contains($selectedId)) { $selected = $true }
                if ($caseEvents.Contains([string]$branch.evaluationId) -and -not $caseEvents.Contains($selectedId)) { $notSelected = $true }
            }
            Add-HHOutcome $branch $branch.outcomes[0] $selected
            Add-HHOutcome $branch $branch.outcomes[1] $notSelected
        }
        'post-test-loop' {
            $bodyCount = if ($countsByEvent.ContainsKey([string]$branch.bodyId)) { [int]$countsByEvent[[string]$branch.bodyId] } else { 0 }
            Add-HHOutcome $branch $branch.outcomes[0] ($bodyCount -ge 2)
            Add-HHOutcome $branch $branch.outcomes[1] $coveredEvents.Contains([string]$branch.completedId)
        }
        default { throw "Unknown branch strategy '$($branch.strategy)'." }
    }
}

$total = $outcomes.Count
if ($total -eq 0) { throw 'Branch denominator is zero.' }
$covered = @($outcomes | Where-Object covered).Count
$percentage = [math]::Round(($covered / $total) * 100, 4)
$report = [ordered]@{
    schemaVersion = 3; sourceSha256 = $manifest.sourceSha256; totalBranches = $manifest.branchCount
    totalOutcomes = $total; coveredOutcomes = $covered; branchCoveragePercent = $percentage
    minimum = $Minimum; passed = $percentage -ge $Minimum; shardCount = $shardFiles.Count
    eventCount = $eventCount; compactWorkingBytes = $workingBytes; compactShardRoot = $shardRoot
    outcomes = $outcomes.ToArray()
}
if ($ReportPath) {
    $directory = Split-Path -Parent $ReportPath
    if ($directory) { [IO.Directory]::CreateDirectory($directory) | Out-Null }
    $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $ReportPath -Encoding utf8NoBOM
}
$report | ConvertTo-Json -Depth 8
if (-not $report.passed) { throw "Branch coverage $percentage% is below the required $Minimum%." }
