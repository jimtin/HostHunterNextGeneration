Set-StrictMode -Version Latest

$script:HHForensicsBatchMaximumCount = 250
$script:HHForensicsBatchMaximumBytes = 524288
$script:HHForensicsSingletonMaximumBytes = 1048576

function ConvertTo-HHForensicsHex {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes)

    return [Convert]::ToHexString($Bytes).ToLowerInvariant()
}

function Assert-HHForensicsResourceUri {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ResourceUri)

    $parsed = $null
    if ([string]::IsNullOrWhiteSpace($ResourceUri) -or
        -not [Uri]::TryCreate($ResourceUri, [UriKind]::Relative, [ref]$parsed) -or
        -not $ResourceUri.StartsWith('/', [StringComparison]::Ordinal) -or
        $ResourceUri.Contains('?') -or $ResourceUri.Contains('#') -or
        $ResourceUri.Contains('..')) {
        Stop-HHForensicsOperation -ErrorId ForensicsRouteRejected `
            -Message 'The outbox resource URI must be a canonical relative path without query or fragment.' `
            -Category InvalidArgument -TargetObject $ResourceUri
    }
}

function Get-HHForensicsOutboxRow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$ResourceKey
    )

    $rows = @(Invoke-HHSqliteQuery -Connection $Context.Connection -Sql @'
SELECT resource_key,idempotency_key,method,resource_uri,body_digest,body_size,
    request_body_envelope,first_ordinal,last_ordinal,event_count,status,
    creation_order,attempt_count,last_status_code,last_problem_code,
    receipt_digest,receipt_envelope,created_at_utc,updated_at_utc
FROM forensics_outbox
WHERE resource_key=@resource_key;
'@ -Parameters @{ resource_key = $ResourceKey })
    if ($rows.Count -eq 0) { return $null }
    if ($rows.Count -ne 1) {
        Stop-HHForensicsOperation -ErrorId ForensicsIntegrityFailed `
            -Message 'The forensics outbox resource identity is ambiguous.' `
            -Category InvalidData -TargetObject $ResourceKey
    }
    return $rows[0]
}

function Get-HHForensicsOutboxItem {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$ResourceKey,
        [switch]$IncludeBody
    )

    $row = Get-HHForensicsOutboxRow -Context $Context -ResourceKey $ResourceKey
    if ($null -eq $row) { return $null }
    $body = $null
    if ($IncludeBody) {
        if ($null -eq $row.request_body_envelope -or
            $row.request_body_envelope -is [DBNull]) {
            if ([string]$row.status -cne 'ACCEPTED') {
                Stop-HHForensicsOperation -ErrorId ForensicsIntegrityFailed `
                    -Message 'A dispatchable outbox row is missing its protected request body.' `
                    -Category SecurityError -TargetObject $ResourceKey
            }
        }
        else {
            $body = Unprotect-HHForensicsValue `
                -Envelope ([byte[]]$row.request_body_envelope) `
                -ForensicsKey $Context.ForensicsKey -Purpose RequestBody `
                -RoutingKey ([string]$row.resource_key) -Digest ([byte[]]$row.body_digest)
            $actualDigest = Get-HHForensicsHash -Bytes $body
            if (-not (Test-HHForensicsBytesEqual `
                        -Left $actualDigest -Right ([byte[]]$row.body_digest))) {
                [Array]::Clear($body, 0, $body.Length)
                Stop-HHForensicsOperation -ErrorId ForensicsIntegrityFailed `
                    -Message 'The decrypted outbox request does not match its digest.' `
                    -Category SecurityError -TargetObject $ResourceKey
            }
        }
    }
    return [pscustomobject]@{
        ResourceKey = [string]$row.resource_key
        IdempotencyKey = [string]$row.idempotency_key
        Method = [string]$row.method
        ResourceUri = [string]$row.resource_uri
        BodyDigest = [byte[]]$row.body_digest
        BodySize = [long]$row.body_size
        Body = $body
        FirstOrdinal = [long]$row.first_ordinal
        LastOrdinal = [long]$row.last_ordinal
        EventCount = [long]$row.event_count
        Status = [string]$row.status
        CreationOrder = [long]$row.creation_order
        AttemptCount = [long]$row.attempt_count
        LastStatusCode = $row.last_status_code
        LastProblemCode = $row.last_problem_code
        ReceiptDigest = $row.receipt_digest
        CreatedAtUtc = [string]$row.created_at_utc
        UpdatedAtUtc = [string]$row.updated_at_utc
    }
}

function Add-HHForensicsQuarantineRecord {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Records a fail-closed conflict in the authenticated forensics database.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$ConflictKind,
        [Parameter(Mandatory)][string]$RoutingKey,
        [AllowNull()][byte[]]$ExpectedDigest,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$ObservedDigest,
        [string]$OccurredAtUtc = ([DateTimeOffset]::UtcNow.ToString('o'))
    )

    if ($ObservedDigest.Length -ne 32 -or
        ($null -ne $ExpectedDigest -and $ExpectedDigest.Length -ne 32)) {
        throw [ArgumentException]::new('Quarantine digests must contain 32 bytes.')
    }
    $expectedEvidence = if ($null -eq $ExpectedDigest) { 'none' } else { $ExpectedDigest }
    $identityBytes = Join-HHForensicsEvidence -Value @(
        $ConflictKind, $RoutingKey, $expectedEvidence, $ObservedDigest
    )
    try { $identityDigest = Get-HHForensicsHash -Bytes $identityBytes }
    finally { [Array]::Clear($identityBytes, 0, $identityBytes.Length) }
    $quarantineId = "q:$((ConvertTo-HHForensicsHex -Bytes $identityDigest).Substring(0, 32))"
    $exists = [long](Invoke-HHSqliteScalar -Connection $Context.Connection -Sql @'
SELECT COUNT(*) FROM forensics_quarantine WHERE quarantine_id=@id;
'@ -Parameters @{ id = $quarantineId })
    if ($exists -gt 0) { return $quarantineId }

    $action = {
        param($Connection, $Transaction, $Key)
        $null = $Key
        $null = Invoke-HHSqliteNonQuery `
            -Connection $Connection -Transaction $Transaction -Sql @'
INSERT INTO forensics_quarantine(
    quarantine_id,conflict_kind,routing_key,expected_digest,observed_digest,status,created_at_utc
)
VALUES(@id,@kind,@routing,@expected,@observed,'QUARANTINED',@created);
'@ -Parameters @{
            id = $quarantineId
            kind = $ConflictKind
            routing = $RoutingKey
            expected = $ExpectedDigest
            observed = $ObservedDigest
            created = $OccurredAtUtc
        }
        return $quarantineId
    }
    return Invoke-HHForensicsAnchoredTransaction `
        -Context $Context -MutationId "quarantine:$quarantineId" `
        -MutationType Quarantine -RoutingKey $RoutingKey `
        -PayloadDigest $identityDigest -Action $action -OccurredAtUtc $OccurredAtUtc
}

function Assert-HHForensicsCanonicalEventBody {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$BodyBytes)

    try {
        $jsonText = [Text.UTF8Encoding]::new($false, $true).GetString($BodyBytes)
        $document = [Text.Json.JsonDocument]::Parse($jsonText)
        try {
            if ($document.RootElement.ValueKind -ne [Text.Json.JsonValueKind]::Object -or
                $document.RootElement.GetRawText() -cne $jsonText) {
                throw [FormatException]::new(
                    'Canonical event bytes must contain exactly one JSON object without outer whitespace.'
                )
            }
        }
        finally { $document.Dispose() }
    }
    catch {
        Stop-HHForensicsOperation -ErrorId ForensicsBatchRejected `
            -Message 'Canonical event bytes must contain exactly one strict UTF-8 JSON object.' `
            -Category InvalidData -TargetObject $null -InnerException $_.Exception
    }
}

function New-HHForensicsCanonicalBatchBody {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Constructs deterministic request bytes in memory only.'
    )]
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)][string]$RunId,
        [Parameter(Mandatory)][long]$CreationOrder,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$CanonicalEvents
    )

    $ordered = @($CanonicalEvents | Sort-Object { [long]$_.Ordinal })
    if ($ordered.Count -eq 0) {
        throw [ArgumentException]::new('A canonical batch body requires at least one event.')
    }
    $builder = [Text.StringBuilder]::new()
    $null = $builder.Append('{"schema":"hosthunter.event-batch/1","run_id":')
    $null = $builder.Append('"')
    $null = $builder.Append([Text.Json.JsonEncodedText]::Encode($RunId).ToString())
    $null = $builder.Append('"')
    $null = $builder.Append(',"sequence":')
    $null = $builder.Append($CreationOrder.ToString([Globalization.CultureInfo]::InvariantCulture))
    $null = $builder.Append(',"first_ordinal":')
    $null = $builder.Append(
        ([long]$ordered[0].Ordinal).ToString([Globalization.CultureInfo]::InvariantCulture)
    )
    $null = $builder.Append(',"last_ordinal":')
    $null = $builder.Append(
        ([long]$ordered[$ordered.Count - 1].Ordinal).ToString(
            [Globalization.CultureInfo]::InvariantCulture
        )
    )
    $null = $builder.Append(',"event_count":')
    $null = $builder.Append($ordered.Count.ToString([Globalization.CultureInfo]::InvariantCulture))
    $null = $builder.Append(',"events":[')
    for ($index = 0; $index -lt $ordered.Count; $index++) {
        $eventBytes = [byte[]]$ordered[$index].BodyBytes
        Assert-HHForensicsCanonicalEventBody -BodyBytes $eventBytes
        if ($index -gt 0) { $null = $builder.Append(',') }
        $null = $builder.Append([Text.UTF8Encoding]::new($false, $true).GetString($eventBytes))
    }
    $null = $builder.Append(']}')
    return [Text.UTF8Encoding]::new($false, $true).GetBytes($builder.ToString())
}

function Test-HHForensicsDependencyCycle {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][object]$Connection,
        [Parameter(Mandatory)][object]$Transaction,
        [Parameter(Mandatory)][string]$ResourceKey,
        [Parameter(Mandatory)][string]$Dependency
    )

    if ($ResourceKey -ceq $Dependency) { return $true }
    $count = Invoke-HHSqliteScalar `
        -Connection $Connection -Transaction $Transaction -Sql @'
WITH RECURSIVE reachable(resource_key) AS (
    SELECT depends_on_resource_key
    FROM forensics_outbox_dependencies
    WHERE resource_key=@dependency
    UNION
    SELECT dependency.depends_on_resource_key
    FROM forensics_outbox_dependencies AS dependency
    JOIN reachable ON dependency.resource_key=reachable.resource_key
)
SELECT COUNT(*) FROM reachable WHERE resource_key=@resource_key;
'@ -Parameters @{ resource_key = $ResourceKey; dependency = $Dependency }
    return [long]$count -gt 0
}

function Write-HHForensicsEventBatch {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Durably stages the explicitly supplied forensic event batch and API request.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$RunId,
        [Parameter(Mandatory)][string]$ResourceKey,
        [Parameter(Mandatory)][string]$IdempotencyKey,
        [Parameter(Mandatory)][string]$ResourceUri,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$CanonicalEvents,
        [Parameter(Mandatory)][long]$CreationOrder,
        [string[]]$Dependencies = @(),
        [AllowNull()][scriptblock]$CommitInvoker,
        [string]$OccurredAtUtc = ([DateTimeOffset]::UtcNow.ToString('o'))
    )

    Assert-HHForensicsResourceUri -ResourceUri $ResourceUri
    if ([string]::IsNullOrWhiteSpace($RunId) -or
        [string]::IsNullOrWhiteSpace($ResourceKey) -or
        [string]::IsNullOrWhiteSpace($IdempotencyKey) -or $CreationOrder -lt 0) {
        throw [ArgumentException]::new('Batch routing identifiers must be non-empty and canonical.')
    }
    $eventCount = @($CanonicalEvents).Count
    if ($eventCount -lt 1 -or $eventCount -gt $script:HHForensicsBatchMaximumCount) {
        Stop-HHForensicsOperation -ErrorId ForensicsBatchRejected `
            -Message 'A forensics batch must contain between 1 and 250 events.' `
            -Category LimitsExceeded -TargetObject $eventCount
    }
    $ordered = @($CanonicalEvents | Sort-Object { [long]$_.Ordinal })
    $eventRows = [Collections.Generic.List[object]]::new()
    $seenIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $seenOrdinals = [Collections.Generic.HashSet[long]]::new()
    foreach ($canonicalEvent in $ordered) {
        foreach ($name in @('EventId', 'SourceKey', 'Ordinal', 'OccurredAtUtc', 'BodyBytes')) {
            if ($null -eq $canonicalEvent.PSObject.Properties[$name]) {
                throw [ArgumentException]::new("Canonical event is missing $name.")
            }
        }
        $eventId = [string]$canonicalEvent.EventId
        $ordinal = [long]$canonicalEvent.Ordinal
        $eventBytes = [byte[]]$canonicalEvent.BodyBytes
        if ([string]::IsNullOrWhiteSpace($eventId) -or
            [string]::IsNullOrWhiteSpace([string]$canonicalEvent.SourceKey) -or
            $ordinal -lt 0 -or $eventBytes.Length -gt $script:HHForensicsSingletonMaximumBytes -or
            -not $seenIds.Add($eventId) -or -not $seenOrdinals.Add($ordinal)) {
            Stop-HHForensicsOperation -ErrorId ForensicsBatchRejected `
                -Message 'Canonical event identifiers, ordinals, or body limits are invalid.' `
                -Category InvalidData -TargetObject $eventId
        }
        Assert-HHForensicsCanonicalEventBody -BodyBytes $eventBytes
        $eventDigest = Get-HHForensicsHash -Bytes $eventBytes
        $eventRows.Add([pscustomobject]@{
                EventId = $eventId
                SourceKey = [string]$canonicalEvent.SourceKey
                Ordinal = $ordinal
                OccurredAtUtc = [string]$canonicalEvent.OccurredAtUtc
                BodySize = $eventBytes.Length
                BodyBytes = $eventBytes
                Digest = $eventDigest
                Envelope = $null
            })
    }
    for ($index = 1; $index -lt $ordered.Count; $index++) {
        if ([long]$ordered[$index].Ordinal -ne [long]$ordered[$index - 1].Ordinal + 1L) {
            Stop-HHForensicsOperation -ErrorId ForensicsBatchRejected `
                -Message 'Forensics event batch ordinals must be contiguous.' `
                -Category InvalidData -TargetObject $RunId
        }
    }

    $requestBody = New-HHForensicsCanonicalBatchBody `
        -RunId $RunId -CreationOrder $CreationOrder -CanonicalEvents $ordered
    if ($requestBody.Length -gt $script:HHForensicsSingletonMaximumBytes -or
        ($eventCount -gt 1 -and $requestBody.Length -gt $script:HHForensicsBatchMaximumBytes)) {
        Stop-HHForensicsOperation -ErrorId ForensicsBatchRejected `
            -Message 'The internally constructed request body exceeds the deterministic batch byte limit.' `
            -Category LimitsExceeded -TargetObject $requestBody.Length
    }
    $bodyDigest = Get-HHForensicsHash -Bytes $requestBody
    $existingRows = @(Invoke-HHSqliteQuery -Connection $Context.Connection -Sql @'
SELECT resource_key,idempotency_key,resource_uri,body_digest,status
FROM forensics_outbox
WHERE resource_key=@resource_key OR idempotency_key=@idempotency_key;
'@ -Parameters @{ resource_key = $ResourceKey; idempotency_key = $IdempotencyKey })
    if ($existingRows.Count -gt 0) {
        $existing = $existingRows[0]
        $same = $existingRows.Count -eq 1 -and
            [string]$existing.resource_key -ceq $ResourceKey -and
            [string]$existing.idempotency_key -ceq $IdempotencyKey -and
            [string]$existing.resource_uri -ceq $ResourceUri -and
            (Test-HHForensicsBytesEqual `
                -Left ([byte[]]$existing.body_digest) -Right $bodyDigest)
        if ($same) {
            if ([string]$existing.status -cne 'ACCEPTED') {
                $verified = Get-HHForensicsOutboxItem `
                    -Context $Context -ResourceKey $ResourceKey -IncludeBody
                try {
                    if (-not (Test-HHForensicsBytesEqual `
                                -Left $verified.Body -Right $requestBody)) {
                        Stop-HHForensicsOperation -ErrorId ForensicsIntegrityFailed `
                            -Message 'The persisted replay request does not match canonical reconstruction.' `
                            -Category SecurityError -TargetObject $ResourceKey
                    }
                }
                finally {
                    if ($null -ne $verified.Body) {
                        [Array]::Clear($verified.Body, 0, $verified.Body.Length)
                    }
                }
            }
            return [pscustomobject]@{
                ResourceKey = $ResourceKey
                IdempotencyKey = $IdempotencyKey
                BodyDigest = $bodyDigest
                Status = [string]$existing.status
                WasReplay = $true
            }
        }
        $expected = if ($existingRows.Count -eq 1) {
            [byte[]]$existing.body_digest
        }
        else { $null }
        $null = Add-HHForensicsQuarantineRecord `
            -Context $Context -ConflictKind IdempotencyConflict `
            -RoutingKey $IdempotencyKey -ExpectedDigest $expected `
            -ObservedDigest $bodyDigest -OccurredAtUtc $OccurredAtUtc
        Stop-HHForensicsOperation -ErrorId ForensicsIdempotencyConflict `
            -Message 'The idempotency or resource key was reused with different content or routing.' `
            -Category InvalidData -TargetObject $IdempotencyKey
    }

    foreach ($eventRow in $eventRows) {
        $existingEvent = @(Invoke-HHSqliteQuery -Connection $Context.Connection -Sql @'
SELECT event_digest FROM forensics_events WHERE event_id=@event_id;
'@ -Parameters @{ event_id = $eventRow.EventId })
        if ($existingEvent.Count -gt 0) {
            $null = Add-HHForensicsQuarantineRecord `
                -Context $Context -ConflictKind EventIdentityConflict `
                -RoutingKey $eventRow.EventId `
                -ExpectedDigest ([byte[]]$existingEvent[0].event_digest) `
                -ObservedDigest $eventRow.Digest -OccurredAtUtc $OccurredAtUtc
            Stop-HHForensicsOperation -ErrorId ForensicsEventConflict `
                -Message 'An event identity already exists outside an exact batch replay.' `
                -Category InvalidData -TargetObject $eventRow.EventId
        }
        $eventRow.Envelope = Protect-HHForensicsValue `
            -Plaintext $eventRow.BodyBytes -ForensicsKey $Context.ForensicsKey `
            -Purpose EventBody -RoutingKey $eventRow.EventId -Digest $eventRow.Digest
    }
    $requestEnvelope = Protect-HHForensicsValue `
        -Plaintext $requestBody -ForensicsKey $Context.ForensicsKey `
        -Purpose RequestBody -RoutingKey $ResourceKey -Digest $bodyDigest
    $digestEvidence = [Collections.Generic.List[object]]::new()
    $digestEvidence.Add('HHF-BATCH-1')
    $digestEvidence.Add($RunId)
    $digestEvidence.Add($ResourceKey)
    $digestEvidence.Add($bodyDigest)
    foreach ($eventRow in $eventRows) {
        $digestEvidence.Add($eventRow.EventId)
        $digestEvidence.Add($eventRow.Digest)
    }
    $joinedEvidence = Join-HHForensicsEvidence -Value @($digestEvidence)
    try { $mutationDigest = Get-HHForensicsHash -Bytes $joinedEvidence }
    finally { [Array]::Clear($joinedEvidence, 0, $joinedEvidence.Length) }

    $dependencyList = @($Dependencies | Sort-Object -Unique)
    $action = {
        param($Connection, $Transaction, $Key)
        $null = $Key
        foreach ($eventRow in $eventRows) {
            $null = Invoke-HHSqliteNonQuery `
                -Connection $Connection -Transaction $Transaction -Sql @'
INSERT INTO forensics_events(
    event_id,event_digest,source_key,run_id,ordinal,occurred_at_utc,body_size,
    event_body_envelope,status,created_at_utc
)
VALUES(
    @event_id,@event_digest,@source_key,@run_id,@ordinal,@occurred,@body_size,
    @envelope,'OUTBOXED',@created
);
'@ -Parameters @{
                event_id = $eventRow.EventId
                event_digest = $eventRow.Digest
                source_key = $eventRow.SourceKey
                run_id = $RunId
                ordinal = $eventRow.Ordinal
                occurred = $eventRow.OccurredAtUtc
                body_size = $eventRow.BodySize
                envelope = $eventRow.Envelope
                created = $OccurredAtUtc
            }
        }
        $null = Invoke-HHSqliteNonQuery `
            -Connection $Connection -Transaction $Transaction -Sql @'
INSERT INTO forensics_outbox(
    resource_key,idempotency_key,method,resource_uri,body_digest,body_size,
    request_body_envelope,first_ordinal,last_ordinal,event_count,status,
    creation_order,created_at_utc,updated_at_utc
)
VALUES(
    @resource_key,@idempotency_key,'PUT',@resource_uri,@body_digest,@body_size,
    @request_envelope,@first_ordinal,@last_ordinal,@event_count,'PREPARED',
    @creation_order,@created,@created
);
'@ -Parameters @{
            resource_key = $ResourceKey
            idempotency_key = $IdempotencyKey
            resource_uri = $ResourceUri
            body_digest = $bodyDigest
            body_size = $requestBody.Length
            request_envelope = $requestEnvelope
            first_ordinal = $eventRows[0].Ordinal
            last_ordinal = $eventRows[$eventRows.Count - 1].Ordinal
            event_count = $eventRows.Count
            creation_order = $CreationOrder
            created = $OccurredAtUtc
        }
        foreach ($eventRow in $eventRows) {
            $null = Invoke-HHSqliteNonQuery `
                -Connection $Connection -Transaction $Transaction -Sql @'
INSERT INTO forensics_outbox_events(resource_key,event_id,event_ordinal)
VALUES(@resource_key,@event_id,@ordinal);
'@ -Parameters @{
                resource_key = $ResourceKey
                event_id = $eventRow.EventId
                ordinal = $eventRow.Ordinal
            }
        }
        foreach ($dependency in $dependencyList) {
            if ([string]::IsNullOrWhiteSpace($dependency) -or
                (Test-HHForensicsDependencyCycle `
                    -Connection $Connection -Transaction $Transaction `
                    -ResourceKey $ResourceKey -Dependency $dependency)) {
                throw [ArgumentException]::new('Outbox dependencies must be non-empty and non-cyclic.')
            }
            $null = Invoke-HHSqliteNonQuery `
                -Connection $Connection -Transaction $Transaction -Sql @'
INSERT INTO forensics_outbox_dependencies(resource_key,depends_on_resource_key)
VALUES(@resource_key,@dependency);
'@ -Parameters @{ resource_key = $ResourceKey; dependency = $dependency }
        }
        return [pscustomobject]@{
            ResourceKey = $ResourceKey
            IdempotencyKey = $IdempotencyKey
            BodyDigest = $bodyDigest
            Status = 'PREPARED'
            WasReplay = $false
        }
    }
    return Invoke-HHForensicsAnchoredTransaction `
        -Context $Context `
        -MutationId "batch:${ResourceKey}:$((ConvertTo-HHForensicsHex -Bytes $bodyDigest).Substring(0, 16))" `
        -MutationType BatchPrepared -RoutingKey $ResourceKey `
        -PayloadDigest $mutationDigest -Action $action -CommitInvoker $CommitInvoker `
        -OccurredAtUtc $OccurredAtUtc
}

function Get-HHForensicsNextOutboxItem {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Context)

    $rows = @(Invoke-HHSqliteQuery -Connection $Context.Connection -Sql @'
SELECT o.resource_key
FROM forensics_outbox AS o
WHERE o.status IN ('PREPARED','RETRYABLE')
    AND NOT EXISTS (
        SELECT 1
        FROM forensics_outbox_dependencies AS d
        LEFT JOIN forensics_outbox AS dependency
            ON dependency.resource_key=d.depends_on_resource_key
        WHERE d.resource_key=o.resource_key
            AND (dependency.resource_key IS NULL OR dependency.status <> 'ACCEPTED')
    )
ORDER BY o.creation_order
LIMIT 1;
'@)
    if ($rows.Count -eq 0) { return $null }
    return Get-HHForensicsOutboxItem `
        -Context $Context -ResourceKey ([string]$rows[0].resource_key)
}

function Start-HHForensicsDeliveryAttempt {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Durably marks one explicitly selected outbox request before HTTP dispatch.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$ResourceKey,
        [Parameter(Mandatory)][string]$AttemptId,
        [string]$OccurredAtUtc = ([DateTimeOffset]::UtcNow.ToString('o'))
    )

    $item = Get-HHForensicsOutboxItem `
        -Context $Context -ResourceKey $ResourceKey -IncludeBody
    if ($null -eq $item -or $item.Status -notin @('PREPARED', 'RETRYABLE')) {
        if ($null -ne $item -and $null -ne $item.Body) {
            [Array]::Clear($item.Body, 0, $item.Body.Length)
        }
        Stop-HHForensicsOperation -ErrorId ForensicsOutboxStateRejected `
            -Message 'Only prepared or retryable outbox items may start an HTTP attempt.' `
            -Category InvalidOperation -TargetObject $ResourceKey
    }
    $eligible = Get-HHForensicsNextOutboxItem -Context $Context
    if ($null -eq $eligible -or $eligible.ResourceKey -cne $ResourceKey) {
        [Array]::Clear($item.Body, 0, $item.Body.Length)
        Stop-HHForensicsOperation -ErrorId ForensicsDependencyBlocked `
            -Message 'The requested outbox item is not the next dependency-satisfied item.' `
            -Category ResourceBusy -TargetObject $ResourceKey
    }
    $attemptNumber = $item.AttemptCount + 1L
    $evidence = Join-HHForensicsEvidence -Value @(
        'HHF-ATTEMPT-START-1', $ResourceKey, $AttemptId, $attemptNumber, $item.BodyDigest
    )
    try { $mutationDigest = Get-HHForensicsHash -Bytes $evidence }
    finally { [Array]::Clear($evidence, 0, $evidence.Length) }
    $action = {
        param($Connection, $Transaction, $Key)
        $null = $Key
        $changed = Invoke-HHSqliteNonQuery `
            -Connection $Connection -Transaction $Transaction -Sql @'
UPDATE forensics_outbox
SET status='SENDING',attempt_count=@attempt_number,updated_at_utc=@started
WHERE resource_key=@resource_key AND status IN ('PREPARED','RETRYABLE');
'@ -Parameters @{
            attempt_number = $attemptNumber
            started = $OccurredAtUtc
            resource_key = $ResourceKey
        }
        if ($changed -ne 1) { throw 'The outbox state changed before the attempt was armed.' }
        $null = Invoke-HHSqliteNonQuery `
            -Connection $Connection -Transaction $Transaction -Sql @'
INSERT INTO forensics_delivery_attempts(
    resource_key,attempt_number,attempt_id,started_at_utc,outcome
)
VALUES(@resource_key,@attempt_number,@attempt_id,@started,'SENDING');
'@ -Parameters @{
            resource_key = $ResourceKey
            attempt_number = $attemptNumber
            attempt_id = $AttemptId
            started = $OccurredAtUtc
        }
    }
    $null = Invoke-HHForensicsAnchoredTransaction `
        -Context $Context -MutationId "attempt-start:$AttemptId" `
        -MutationType DeliveryStarted -RoutingKey $ResourceKey `
        -PayloadDigest $mutationDigest -Action $action -OccurredAtUtc $OccurredAtUtc
    return [pscustomobject]@{
        Item = $item
        AttemptId = $AttemptId
        AttemptNumber = $attemptNumber
    }
}

function Complete-HHForensicsDeliveryAttempt {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Durably records the bounded result of an explicitly armed HTTP attempt.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$ResourceKey,
        [Parameter(Mandatory)][long]$AttemptNumber,
        [Parameter(Mandatory)]
        [ValidateSet('ACCEPTED', 'RETRYABLE', 'UNKNOWN', 'PAUSED', 'REJECTED', 'CONFLICT')]
        [string]$Outcome,
        [AllowNull()][Nullable[int]]$StatusCode,
        [AllowNull()][string]$ProblemCode,
        [AllowNull()][byte[]]$ResponseBody,
        [string]$OccurredAtUtc = ([DateTimeOffset]::UtcNow.ToString('o'))
    )

    $item = Get-HHForensicsOutboxItem -Context $Context -ResourceKey $ResourceKey
    if ($null -eq $item -or $item.Status -cne 'SENDING' -or
        $item.AttemptCount -ne $AttemptNumber) {
        Stop-HHForensicsOperation -ErrorId ForensicsOutboxStateRejected `
            -Message 'Only the currently sending attempt may be completed.' `
            -Category InvalidOperation -TargetObject $ResourceKey
    }
    if ($Outcome -ceq 'ACCEPTED' -and
        ($null -eq $ResponseBody -or $ResponseBody.Length -eq 0)) {
        Stop-HHForensicsOperation -ErrorId ForensicsReceiptBindingRejected `
            -Message 'An accepted attempt requires its exact validated receipt body.' `
            -Category InvalidData -TargetObject $ResourceKey
    }
    if ($Outcome -ceq 'ACCEPTED') {
        $null = ConvertFrom-HHForensicsReceipt -Body $ResponseBody -Item $item
    }
    $responseDigest = $null
    $responseEnvelope = $null
    if ($null -ne $ResponseBody) {
        $responseDigest = Get-HHForensicsHash -Bytes $ResponseBody
        $purpose = if ($Outcome -ceq 'ACCEPTED') { 'ReceiptBody' } else { 'ResponseBody' }
        $responseEnvelope = Protect-HHForensicsValue `
            -Plaintext $ResponseBody -ForensicsKey $Context.ForensicsKey `
            -Purpose $purpose -RoutingKey "$ResourceKey/$AttemptNumber" `
            -Digest $responseDigest
    }
    $statusEvidence = if ($null -eq $StatusCode) { 'none' } else { [string]$StatusCode }
    $problemEvidence = if ($null -eq $ProblemCode) { 'none' } else { $ProblemCode }
    $responseEvidence = if ($null -eq $responseDigest) { 'none' } else { $responseDigest }
    $evidence = Join-HHForensicsEvidence -Value @(
        'HHF-ATTEMPT-COMPLETE-1', $ResourceKey, $AttemptNumber, $Outcome,
        $statusEvidence, $problemEvidence, $responseEvidence
    )
    try { $mutationDigest = Get-HHForensicsHash -Bytes $evidence }
    finally { [Array]::Clear($evidence, 0, $evidence.Length) }
    $action = {
        param($Connection, $Transaction, $Key)
        $null = $Key
        $changed = Invoke-HHSqliteNonQuery `
            -Connection $Connection -Transaction $Transaction -Sql @'
UPDATE forensics_delivery_attempts
SET completed_at_utc=@completed,outcome=@outcome,status_code=@status_code,
    problem_code=@problem_code,response_digest=@response_digest,
    response_envelope=@response_envelope
WHERE resource_key=@resource_key AND attempt_number=@attempt_number AND outcome='SENDING';
'@ -Parameters @{
            completed = $OccurredAtUtc
            outcome = $Outcome
            status_code = $StatusCode
            problem_code = $ProblemCode
            response_digest = $responseDigest
            response_envelope = $responseEnvelope
            resource_key = $ResourceKey
            attempt_number = $AttemptNumber
        }
        if ($changed -ne 1) { throw 'The delivery attempt is no longer in the sending state.' }
        $null = Invoke-HHSqliteNonQuery `
            -Connection $Connection -Transaction $Transaction -Sql @'
UPDATE forensics_outbox
SET status=@outcome,last_status_code=@status_code,last_problem_code=@problem_code,
    request_body_envelope=CASE WHEN @outcome='ACCEPTED' THEN NULL ELSE request_body_envelope END,
    receipt_digest=CASE WHEN @outcome='ACCEPTED' THEN @response_digest ELSE receipt_digest END,
    receipt_envelope=CASE WHEN @outcome='ACCEPTED' THEN @response_envelope ELSE receipt_envelope END,
    updated_at_utc=@completed
WHERE resource_key=@resource_key AND status='SENDING' AND attempt_count=@attempt_number;
'@ -Parameters @{
            outcome = $Outcome
            status_code = $StatusCode
            problem_code = $ProblemCode
            response_digest = $responseDigest
            response_envelope = $responseEnvelope
            completed = $OccurredAtUtc
            resource_key = $ResourceKey
            attempt_number = $AttemptNumber
        }
        if ($Outcome -ceq 'ACCEPTED') {
            $null = Invoke-HHSqliteNonQuery `
                -Connection $Connection -Transaction $Transaction -Sql @'
UPDATE forensics_events
SET status='ACCEPTED'
WHERE event_id IN (
    SELECT event_id FROM forensics_outbox_events WHERE resource_key=@resource_key
);
'@ -Parameters @{ resource_key = $ResourceKey }
        }
    }
    $null = Invoke-HHForensicsAnchoredTransaction `
        -Context $Context `
        -MutationId "attempt-complete:${ResourceKey}:${AttemptNumber}:$Outcome" `
        -MutationType DeliveryCompleted -RoutingKey $ResourceKey `
        -PayloadDigest $mutationDigest -Action $action -OccurredAtUtc $OccurredAtUtc
    if ($Outcome -ceq 'CONFLICT') {
        $null = Add-HHForensicsQuarantineRecord `
            -Context $Context -ConflictKind ApiIdempotencyConflict `
            -RoutingKey $item.IdempotencyKey -ExpectedDigest $null `
            -ObservedDigest $item.BodyDigest -OccurredAtUtc $OccurredAtUtc
    }
    return Get-HHForensicsOutboxItem -Context $Context -ResourceKey $ResourceKey
}

function Repair-HHForensicsInterruptedDelivery {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Conservatively marks only interrupted SENDING rows as UNKNOWN for receipt reconciliation.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [string]$OccurredAtUtc = ([DateTimeOffset]::UtcNow.ToString('o'))
    )

    $rows = @(Invoke-HHSqliteQuery -Connection $Context.Connection -Sql @'
SELECT resource_key,attempt_count
FROM forensics_outbox
WHERE status='SENDING'
ORDER BY creation_order;
'@)
    foreach ($row in $rows) {
        $null = Complete-HHForensicsDeliveryAttempt `
            -Context $Context -ResourceKey ([string]$row.resource_key) `
            -AttemptNumber ([long]$row.attempt_count) -Outcome UNKNOWN `
            -ProblemCode InterruptedBeforeReceipt -OccurredAtUtc $OccurredAtUtc
    }
    return @($rows).Count
}

function Resolve-HHForensicsUnknownDelivery {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Applies an explicit receipt-reconciliation result to one UNKNOWN outbox row.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$ResourceKey,
        [Parameter(Mandatory)]
        [ValidateSet('ACCEPTED', 'RETRYABLE', 'PAUSED', 'REJECTED', 'CONFLICT')]
        [string]$Outcome,
        [AllowNull()][Nullable[int]]$StatusCode,
        [AllowNull()][string]$ProblemCode,
        [AllowNull()][byte[]]$ReceiptBody,
        [string]$OccurredAtUtc = ([DateTimeOffset]::UtcNow.ToString('o'))
    )

    $item = Get-HHForensicsOutboxItem -Context $Context -ResourceKey $ResourceKey
    if ($null -eq $item -or $item.Status -cne 'UNKNOWN') {
        Stop-HHForensicsOperation -ErrorId ForensicsOutboxStateRejected `
            -Message 'Only an UNKNOWN outbox item may be receipt-reconciled.' `
            -Category InvalidOperation -TargetObject $ResourceKey
    }
    if ($Outcome -ceq 'ACCEPTED' -and
        ($null -eq $ReceiptBody -or $ReceiptBody.Length -eq 0)) {
        Stop-HHForensicsOperation -ErrorId ForensicsReceiptBindingRejected `
            -Message 'An accepted reconciliation requires its exact validated receipt body.' `
            -Category InvalidData -TargetObject $ResourceKey
    }
    if ($Outcome -ceq 'ACCEPTED') {
        $null = ConvertFrom-HHForensicsReceipt -Body $ReceiptBody -Item $item
    }
    $receiptDigest = $null
    $receiptEnvelope = $null
    if ($null -ne $ReceiptBody) {
        $receiptDigest = Get-HHForensicsHash -Bytes $ReceiptBody
        $purpose = if ($Outcome -ceq 'ACCEPTED') { 'ReceiptBody' } else { 'ResponseBody' }
        $receiptEnvelope = Protect-HHForensicsValue `
            -Plaintext $ReceiptBody -ForensicsKey $Context.ForensicsKey `
            -Purpose $purpose -RoutingKey "$ResourceKey/reconcile" -Digest $receiptDigest
    }
    $statusEvidence = if ($null -eq $StatusCode) { 'none' } else { [string]$StatusCode }
    $problemEvidence = if ($null -eq $ProblemCode) { 'none' } else { $ProblemCode }
    $receiptEvidence = if ($null -eq $receiptDigest) { 'none' } else { $receiptDigest }
    $evidence = Join-HHForensicsEvidence -Value @(
        'HHF-RECONCILE-1', $ResourceKey, $item.AttemptCount, $Outcome,
        $statusEvidence, $problemEvidence, $receiptEvidence
    )
    try { $mutationDigest = Get-HHForensicsHash -Bytes $evidence }
    finally { [Array]::Clear($evidence, 0, $evidence.Length) }
    $action = {
        param($Connection, $Transaction, $Key)
        $null = $Key
        $changed = Invoke-HHSqliteNonQuery `
            -Connection $Connection -Transaction $Transaction -Sql @'
UPDATE forensics_outbox
SET status=@outcome,last_status_code=@status_code,last_problem_code=@problem_code,
    request_body_envelope=CASE WHEN @outcome='ACCEPTED' THEN NULL ELSE request_body_envelope END,
    receipt_digest=CASE WHEN @outcome='ACCEPTED' THEN @receipt_digest ELSE receipt_digest END,
    receipt_envelope=CASE WHEN @outcome='ACCEPTED' THEN @receipt_envelope ELSE receipt_envelope END,
    updated_at_utc=@completed
WHERE resource_key=@resource_key AND status='UNKNOWN';
'@ -Parameters @{
            outcome = $Outcome
            status_code = $StatusCode
            problem_code = $ProblemCode
            receipt_digest = $receiptDigest
            receipt_envelope = $receiptEnvelope
            completed = $OccurredAtUtc
            resource_key = $ResourceKey
        }
        if ($changed -ne 1) { throw 'The unknown delivery changed before reconciliation completed.' }
        if ($Outcome -ceq 'ACCEPTED') {
            $null = Invoke-HHSqliteNonQuery `
                -Connection $Connection -Transaction $Transaction -Sql @'
UPDATE forensics_events
SET status='ACCEPTED'
WHERE event_id IN (
    SELECT event_id FROM forensics_outbox_events WHERE resource_key=@resource_key
);
'@ -Parameters @{ resource_key = $ResourceKey }
        }
    }
    $null = Invoke-HHForensicsAnchoredTransaction `
        -Context $Context `
        -MutationId "reconcile:${ResourceKey}:$($item.AttemptCount):$Outcome" `
        -MutationType ReceiptReconciled -RoutingKey $ResourceKey `
        -PayloadDigest $mutationDigest -Action $action -OccurredAtUtc $OccurredAtUtc
    if ($Outcome -ceq 'CONFLICT') {
        $null = Add-HHForensicsQuarantineRecord `
            -Context $Context -ConflictKind ApiReceiptConflict `
            -RoutingKey $item.IdempotencyKey -ExpectedDigest $null `
            -ObservedDigest $item.BodyDigest -OccurredAtUtc $OccurredAtUtc
    }
    return Get-HHForensicsOutboxItem -Context $Context -ResourceKey $ResourceKey
}
