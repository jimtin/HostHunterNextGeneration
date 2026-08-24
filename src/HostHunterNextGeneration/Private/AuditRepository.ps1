Set-StrictMode -Version Latest

function ConvertTo-HHPersistenceIdentifierByte {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param([Parameter(Mandatory)][object]$Identifier)

    if ($Identifier -is [byte[]] -and $Identifier.Length -eq 16) {
        Write-Output -InputObject ([byte[]]$Identifier.Clone()) -NoEnumerate
        return
    }
    $text = [string]$Identifier
    if ($text -cnotmatch '^[0-9a-fA-F]{32}$') {
        throw [ArgumentException]::new('Persistence identifiers must contain exactly 32 hexadecimal characters.')
    }
    Write-Output -InputObject ([Convert]::FromHexString($text)) -NoEnumerate
}

function ConvertTo-HHPersistenceIdentifierText {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Identifier)

    if ($Identifier.Length -ne 16) {
        throw [ArgumentException]::new('Persistence identifiers must contain exactly 16 bytes.')
    }
    return [Convert]::ToHexString($Identifier).ToLowerInvariant()
}

function Get-HHAuditRepositoryAssociatedData {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)][byte[]]$DatabaseId,
        [Parameter(Mandatory)][byte[]]$RowId,
        [Parameter(Mandatory)][string]$Table,
        [Parameter(Mandatory)][string]$Column
    )

    if ($DatabaseId.Length -ne 16 -or $RowId.Length -ne 16 -or
        $Table -cnotmatch '^[a-z_]{1,64}$' -or $Column -cnotmatch '^[a-z_0-9]{1,64}$') {
        throw [ArgumentException]::new('Audit repository associated-data identity is invalid.')
    }
    $document = [ordered]@{
        domain = 'HostHunterNextGeneration/sqlite-row/v1'
        databaseId = ConvertTo-HHPersistenceIdentifierText -Identifier $DatabaseId
        table = $Table
        rowId = ConvertTo-HHPersistenceIdentifierText -Identifier $RowId
        column = $Column
        schemaVersion = 1
    }
    return [Text.UTF8Encoding]::new($false).GetBytes(
        ($document | ConvertTo-Json -Compress)
    )
}

function Get-HHSqliteAuditEventMac {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)][long]$Sequence,
        [Parameter(Mandatory)][byte[]]$EventId,
        [Parameter(Mandatory)][string]$EventKind,
        [Parameter(Mandatory)][string]$EventAtUtc,
        [AllowNull()][byte[]]$InvocationId,
        [AllowNull()][byte[]]$TargetMutationId,
        [Parameter(Mandatory)][byte[]]$ProjectionHash,
        [Parameter(Mandatory)][byte[]]$RelatedEnvelopeHash,
        [Parameter(Mandatory)][byte[]]$PreviousMac,
        [Parameter(Mandatory)][byte[]]$MasterKey
    )

    $document = [ordered]@{
        domain = 'HostHunterNextGeneration/audit-event/v1'
        sequence = $Sequence
        eventId = ConvertTo-HHPersistenceIdentifierText -Identifier $EventId
        eventKind = $EventKind
        eventAtUtc = $EventAtUtc
        invocationId = if ($null -eq $InvocationId) {
            $null
        }
        else { ConvertTo-HHPersistenceIdentifierText -Identifier $InvocationId }
        targetMutationId = if ($null -eq $TargetMutationId) {
            $null
        }
        else { ConvertTo-HHPersistenceIdentifierText -Identifier $TargetMutationId }
        projectionHash = [Convert]::ToHexString($ProjectionHash).ToLowerInvariant()
        relatedEnvelopeHash = [Convert]::ToHexString($RelatedEnvelopeHash).ToLowerInvariant()
        previousMac = [Convert]::ToHexString($PreviousMac).ToLowerInvariant()
    }
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(
        ($document | ConvertTo-Json -Compress)
    )
    $key = Get-HHPersistenceDerivedKey -MasterKey $MasterKey -Purpose AuditIntegrity
    try {
        return Get-HHPersistenceMac -Key $key -Bytes $bytes
    }
    finally {
        [Array]::Clear($bytes, 0, $bytes.Length)
        [Array]::Clear($key, 0, $key.Length)
    }
}

function Write-HHSqliteAuditEvent {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Writes inside an already authorized caller-owned SQLite transaction.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Connection,
        [Parameter(Mandatory)][object]$Transaction,
        [Parameter(Mandatory)][string]$EventKind,
        [Parameter(Mandatory)][DateTimeOffset]$EventAtUtc,
        [AllowNull()][byte[]]$InvocationId,
        [AllowNull()][byte[]]$TargetMutationId,
        [Parameter(Mandatory)][byte[]]$ProjectionHash,
        [Parameter(Mandatory)][byte[]]$RelatedEnvelopeHash,
        [Parameter(Mandatory)][byte[]]$MasterKey
    )

    if (($null -eq $InvocationId) -eq ($null -eq $TargetMutationId)) {
        throw 'Exactly one audit-event relationship is required.'
    }
    $lastRows = @(Invoke-HHSqliteQuery `
            -Connection $Connection `
            -Transaction $Transaction `
            -Sql 'SELECT sequence,event_mac FROM audit_events ORDER BY sequence DESC LIMIT 1;')
    $sequence = if ($lastRows.Count -eq 0) { 1L } else { [long]$lastRows[0].sequence + 1L }
    [byte[]]$previousMac = if ($lastRows.Count -eq 0) {
        [byte[]]::new(32)
    }
    else { [byte[]]$lastRows[0].event_mac }
    [byte[]]$eventId = [Guid]::NewGuid().ToByteArray()
    $eventText = $EventAtUtc.UtcDateTime.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
    [byte[]]$eventMac = Get-HHSqliteAuditEventMac `
        -Sequence $sequence `
        -EventId $eventId `
        -EventKind $EventKind `
        -EventAtUtc $eventText `
        -InvocationId $InvocationId `
        -TargetMutationId $TargetMutationId `
        -ProjectionHash $ProjectionHash `
        -RelatedEnvelopeHash $RelatedEnvelopeHash `
        -PreviousMac $previousMac `
        -MasterKey $MasterKey
    $null = Invoke-HHSqliteNonQuery `
        -Connection $Connection `
        -Transaction $Transaction `
        -Sql @'
INSERT INTO audit_events(
    sequence,event_id,event_kind,event_at_utc,invocation_id,target_mutation_id,
    projection_hash,related_envelope_hash,previous_mac,event_mac
) VALUES(@sequence,@event,@kind,@at,@invocation,@mutation,@projection,@related,@previous,@mac);
'@ `
        -Parameters @{
            sequence = $sequence
            event = $eventId
            kind = $EventKind
            at = $eventText
            invocation = $InvocationId
            mutation = $TargetMutationId
            projection = $ProjectionHash
            related = $RelatedEnvelopeHash
            previous = $previousMac
            mac = $eventMac
        }
    [pscustomobject][ordered]@{
        Sequence = $sequence
        EventId = $eventId
        EventMac = $eventMac
        PreviousMac = $previousMac
    }
}

function Test-HHSqliteAuditChain {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Connection,
        [Parameter(Mandatory)][byte[]]$MasterKey,
        [ValidateRange(1, 60)][int]$TimeoutSeconds = 60,
        [scriptblock]$Clock
    )

    $clockProvider = if ($null -eq $Clock) { { [DateTimeOffset]::UtcNow } } else { $Clock }
    $started = & $clockProvider
    $rows = @(Invoke-HHSqliteQuery `
            -Connection $Connection `
            -Sql @'
SELECT sequence,event_id,event_kind,event_at_utc,invocation_id,target_mutation_id,
        projection_hash,related_envelope_hash,previous_mac,event_mac
FROM audit_events ORDER BY sequence;
'@)
    $previousMac = [byte[]]::new(32)
    $expectedSequence = 1L
    foreach ($row in $rows) {
        if (((& $clockProvider) - $started).TotalSeconds -ge $TimeoutSeconds) {
            Stop-HHPersistenceOperation `
                -ErrorId 'AuditIntegrityVerificationTimedOut' `
                -Message 'Audit integrity verification exceeded its bounded time limit.' `
                -Category ([Management.Automation.ErrorCategory]::OperationTimeout) `
                -TargetObject $Connection.DataSource
        }
        if ([long]$row.sequence -ne $expectedSequence -or
            -not (Test-HHPersistenceBytesEqual -Left ([byte[]]$row.previous_mac) -Right $previousMac)) {
            Stop-HHPersistenceOperation `
                -ErrorId 'AuditIntegrityFailed' `
                -Message 'The audit event chain is not contiguous.' `
                -Category ([Management.Automation.ErrorCategory]::SecurityError) `
                -TargetObject $Connection.DataSource
        }
        $expectedMac = Get-HHSqliteAuditEventMac `
            -Sequence ([long]$row.sequence) `
            -EventId ([byte[]]$row.event_id) `
            -EventKind ([string]$row.event_kind) `
            -EventAtUtc ([string]$row.event_at_utc) `
            -InvocationId $(if ($null -eq $row.invocation_id) { $null } else { [byte[]]$row.invocation_id }) `
            -TargetMutationId $(if ($null -eq $row.target_mutation_id) { $null } else { [byte[]]$row.target_mutation_id }) `
            -ProjectionHash ([byte[]]$row.projection_hash) `
            -RelatedEnvelopeHash ([byte[]]$row.related_envelope_hash) `
            -PreviousMac $previousMac `
            -MasterKey $MasterKey
        if (-not (Test-HHPersistenceBytesEqual -Left ([byte[]]$row.event_mac) -Right $expectedMac)) {
            Stop-HHPersistenceOperation `
                -ErrorId 'AuditIntegrityFailed' `
                -Message 'An audit event failed authentication.' `
                -Category ([Management.Automation.ErrorCategory]::SecurityError) `
                -TargetObject $Connection.DataSource
        }
        $previousMac = [byte[]]$row.event_mac
        $expectedSequence++
    }
    [pscustomobject][ordered]@{
        Sequence = $expectedSequence - 1L
        LastMac = $previousMac
        EventCount = $rows.Count
    }
}

function Register-HHSqliteAuditBatch {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Writes inside an already authorized caller-owned SQLite transaction.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Connection,
        [Parameter(Mandatory)][object]$Transaction,
        [Parameter(Mandatory)][byte[]]$MasterKey,
        [Parameter(Mandatory)][ValidateSet('ValidateTarget', 'TestTarget', 'InvokeCommand', 'EnableSshKeyAuthentication')]
        [string]$Operation,
        [Parameter(Mandatory)][ValidateCount(1, 8)][object[]]$Request,
        [Parameter(Mandatory)][DateTimeOffset]$IntentAtUtc,
        [AllowNull()][byte[]]$BatchId
    )

    [byte[]]$batchBytes = if ($null -eq $BatchId) {
        [Guid]::NewGuid().ToByteArray()
    }
    else { $BatchId }
    if ($batchBytes.Length -ne 16) { throw 'BatchId must contain exactly 16 bytes.' }
    $identity = @(Invoke-HHSqliteQuery `
            -Connection $Connection `
            -Transaction $Transaction `
            -Sql 'SELECT database_id FROM database_identity WHERE singleton_id=1;')
    if ($identity.Count -ne 1) { throw 'Database identity is unavailable.' }
    $databaseId = [byte[]]$identity[0].database_id
    $intentText = $IntentAtUtc.UtcDateTime.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
    $null = Invoke-HHSqliteNonQuery `
        -Connection $Connection `
        -Transaction $Transaction `
        -Sql @'
INSERT INTO operation_batches(batch_id,operation,created_at_utc,invocation_count)
VALUES(@batch,@operation,@created,@count);
'@ `
        -Parameters @{ batch = $batchBytes; operation = $Operation; created = $intentText; count = $Request.Count }
    $results = [Collections.Generic.List[object]]::new()
    foreach ($item in $Request) {
        $target = $item.Target
        $manifest = @(ConvertTo-HHCanonicalRemoteOperationManifest -RemoteOperations $item.RemoteOperations)
        $invocationId = [Guid]::NewGuid().ToByteArray()
        $artifactId = [Guid]::NewGuid().ToByteArray()
        $runtime = [string]$target.PowerShellRuntime
        $executionMode = if ($runtime -ceq 'WindowsPowerShell51') {
            'WindowsPowerShellCompatibility'
        }
        else { 'Direct' }
        $targetJson = $target | ConvertTo-Json -Depth 8 -Compress
        $targetPlaintext = [Text.UTF8Encoding]::new($false).GetBytes($targetJson)
        $commandPlaintext = [Text.UTF8Encoding]::new($false).GetBytes([string]$item.CommandText)
        $targetAad = Get-HHAuditRepositoryAssociatedData -DatabaseId $databaseId `
            -RowId $invocationId -Table invocations -Column target_snapshot_envelope
        $commandAad = Get-HHAuditRepositoryAssociatedData -DatabaseId $databaseId `
            -RowId $invocationId -Table invocations -Column command_envelope
        $targetEnvelope = Protect-HHPersistenceValue -Plaintext $targetPlaintext `
            -MasterKey $MasterKey -AssociatedData $targetAad
        $commandEnvelope = Protect-HHPersistenceValue -Plaintext $commandPlaintext `
            -MasterKey $MasterKey -AssociatedData $commandAad
        $reasonEnvelope = $null
        $caseEnvelope = $null
        $caseLookup = $null
        try {
            if (-not [string]::IsNullOrWhiteSpace([string]$item.Reason)) {
                $reasonBytes = [Text.UTF8Encoding]::new($false).GetBytes([string]$item.Reason)
                $reasonAad = Get-HHAuditRepositoryAssociatedData -DatabaseId $databaseId `
                    -RowId $invocationId -Table invocations -Column reason_envelope
                $reasonEnvelope = Protect-HHPersistenceValue -Plaintext $reasonBytes `
                    -MasterKey $MasterKey -AssociatedData $reasonAad
            }
            if (-not [string]::IsNullOrWhiteSpace([string]$item.CaseId)) {
                $caseBytes = [Text.UTF8Encoding]::new($false).GetBytes([string]$item.CaseId)
                $caseAad = Get-HHAuditRepositoryAssociatedData -DatabaseId $databaseId `
                    -RowId $invocationId -Table invocations -Column case_envelope
                $caseEnvelope = Protect-HHPersistenceValue -Plaintext $caseBytes `
                    -MasterKey $MasterKey -AssociatedData $caseAad
                $lookupKey = Get-HHPersistenceDerivedKey -MasterKey $MasterKey -Purpose CaseLookup
                try { $caseLookup = Get-HHPersistenceMac -Key $lookupKey -Bytes $caseBytes }
                finally { [Array]::Clear($lookupKey, 0, $lookupKey.Length) }
            }
            $requestParts = [Collections.Generic.List[object]]::new()
            $requestParts.Add($targetEnvelope)
            $requestParts.Add($commandEnvelope)
            [byte[]]$reasonPart = if ($null -eq $reasonEnvelope) {
                [Text.Encoding]::ASCII.GetBytes('ABSENT')
            }
            else { $reasonEnvelope }
            [byte[]]$casePart = if ($null -eq $caseEnvelope) {
                [Text.Encoding]::ASCII.GetBytes('ABSENT')
            }
            else { $caseEnvelope }
            $requestParts.Add($reasonPart)
            $requestParts.Add($casePart)
            $requestHashInput = Join-HHAuditArtifactV2Buffer -Part @($requestParts)
            $requestHash = Get-HHPersistenceHash -Bytes $requestHashInput
            $intentSequence = [long](Invoke-HHSqliteScalar -Connection $Connection -Transaction $Transaction `
                    -Sql 'SELECT COALESCE(MAX(sequence),0)+1 FROM audit_events;')
            $null = Invoke-HHSqliteNonQuery -Connection $Connection -Transaction $Transaction -Sql @'
INSERT INTO invocations(
    invocation_id,sequence,batch_id,target_name,transport,host_name,port,user_name,
    authentication,requested_runtime,requested_execution_mode,intent_at_utc,
    target_snapshot_envelope,command_envelope,reason_envelope,case_envelope,case_lookup,
    request_envelope_hash,reserved_artifact_id
) VALUES(
    @id,@sequence,@batch,@name,@transport,@host,@port,@user,@authentication,@runtime,@mode,@at,
    @target,@command,@reason,@case,@lookup,@request_hash,@artifact
);
'@ -Parameters @{
                id = $invocationId; sequence = $intentSequence; batch = $batchBytes
                name = [string]$target.Name; transport = [string]$target.Transport
                host = [string]$target.HostName; port = [int]$target.Port; user = [string]$target.UserName
                authentication = [string]$target.Authentication; runtime = $runtime; mode = $executionMode
                at = $intentText; target = $targetEnvelope; command = $commandEnvelope
                reason = $reasonEnvelope; case = $caseEnvelope; lookup = $caseLookup
                request_hash = $requestHash; artifact = $artifactId
            }
            $manifestHashes = [Collections.Generic.List[byte[]]]::new()
            for ($ordinal = 0; $ordinal -lt $manifest.Count; $ordinal++) {
                $operationItem = $manifest[$ordinal]
                $scriptBytes = [Text.UTF8Encoding]::new($false).GetBytes($operationItem.ScriptText)
                $argumentBytes = [Text.UTF8Encoding]::new($false).GetBytes($operationItem.SerializedArguments)
                $scriptAad = Get-HHAuditRepositoryAssociatedData -DatabaseId $databaseId `
                    -RowId $invocationId -Table remote_operations -Column "script_envelope_$ordinal"
                $argumentAad = Get-HHAuditRepositoryAssociatedData -DatabaseId $databaseId `
                    -RowId $invocationId -Table remote_operations -Column "arguments_envelope_$ordinal"
                $scriptEnvelope = Protect-HHPersistenceValue -Plaintext $scriptBytes `
                    -MasterKey $MasterKey -AssociatedData $scriptAad
                $argumentEnvelope = Protect-HHPersistenceValue -Plaintext $argumentBytes `
                    -MasterKey $MasterKey -AssociatedData $argumentAad
                $declarationInput = Join-HHAuditArtifactV2Buffer -Part @($scriptEnvelope, $argumentEnvelope)
                $declarationHash = Get-HHPersistenceHash -Bytes $declarationInput
                $manifestHashes.Add($declarationHash)
                $null = Invoke-HHSqliteNonQuery -Connection $Connection -Transaction $Transaction -Sql @'
INSERT INTO remote_operations(
    invocation_id,ordinal,phase,powershell_runtime,script_envelope,arguments_envelope,
    conditional,declaration_hash
) VALUES(@id,@ordinal,@phase,@runtime,@script,@arguments,@conditional,@hash);
'@ -Parameters @{
                    id = $invocationId; ordinal = $ordinal; phase = $operationItem.Phase
                    runtime = $operationItem.PowerShellRuntime; script = $scriptEnvelope
                    arguments = $argumentEnvelope; conditional = [int][bool]$operationItem.Conditional
                    hash = $declarationHash
                }
            }
            $relatedParts = [Collections.Generic.List[object]]::new()
            $relatedParts.Add($requestHash)
            foreach ($manifestHash in $manifestHashes) { $relatedParts.Add($manifestHash) }
            $relatedInput = Join-HHAuditArtifactV2Buffer -Part @($relatedParts)
            $relatedHash = Get-HHPersistenceHash -Bytes $relatedInput
            $projectionBytes = [Text.UTF8Encoding]::new($false).GetBytes((
                    [ordered]@{ operation = $Operation; batchId = ConvertTo-HHPersistenceIdentifierText -Identifier $batchBytes
                        invocationId = ConvertTo-HHPersistenceIdentifierText -Identifier $invocationId
                        targetName = [string]$target.Name; transport = [string]$target.Transport
                        hostName = [string]$target.HostName; port = [int]$target.Port
                        userName = [string]$target.UserName; authentication = [string]$target.Authentication
                        requestedRuntime = $runtime; requestedExecutionMode = $executionMode
                        intentAtUtc = $intentText } | ConvertTo-Json -Compress))
            $projectionHash = Get-HHPersistenceHash -Bytes $projectionBytes
            $auditEvent = Write-HHSqliteAuditEvent -Connection $Connection -Transaction $Transaction `
                -EventKind Intent -EventAtUtc $IntentAtUtc -InvocationId $invocationId `
                -ProjectionHash $projectionHash -RelatedEnvelopeHash $relatedHash -MasterKey $MasterKey
            if ($auditEvent.Sequence -ne $intentSequence) { throw 'Audit sequence allocation drifted.' }
            $result = [pscustomobject][ordered]@{
                BatchId = ConvertTo-HHPersistenceIdentifierText -Identifier $batchBytes
                InvocationId = ConvertTo-HHPersistenceIdentifierText -Identifier $invocationId
                InvocationIdBytes = $invocationId
                ArtifactId = ConvertTo-HHPersistenceIdentifierText -Identifier $artifactId
                ArtifactIdBytes = $artifactId
                Sequence = $auditEvent.Sequence
                RequestedPowerShellRuntime = $runtime
                ExpectedHostKeyFingerprint = [string]$target.HostKeyFingerprint
                RemoteOperations = [object[]]$manifest
                IntentRecord = [pscustomobject]@{
                    payload = [pscustomobject]@{
                        operation = $Operation
                        requestedPowerShellRuntime = $runtime
                        expectedHostKeyFingerprint = [string]$target.HostKeyFingerprint
                    }
                }
            }
            $result.PSObject.TypeNames.Insert(0, 'HostHunter.SqliteAuditIntent')
            $results.Add($result)
        }
        finally {
            foreach ($buffer in @($targetPlaintext, $commandPlaintext, $targetAad, $commandAad)) {
                if ($null -ne $buffer) { [Array]::Clear($buffer, 0, $buffer.Length) }
            }
        }
    }
    return [object[]]$results
}

function Write-HHSqliteRemoteOperationEvent {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Writes inside an already authorized caller-owned SQLite transaction.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Connection,
        [Parameter(Mandatory)][object]$Transaction,
        [Parameter(Mandatory)][byte[]]$MasterKey,
        [Parameter(Mandatory)][object]$Intent,
        [Parameter(Mandatory)][ValidateRange(0, 63)][int]$Ordinal,
        [Parameter(Mandatory)][ValidateSet('DispatchArmed', 'Completed', 'Skipped', 'DispatchUncertain')]
        [string]$EventKind,
        [Parameter(Mandatory)][DateTimeOffset]$EventAtUtc,
        [AllowNull()][object]$Evidence,
        [AllowNull()][object]$ExpectedOperation
    )

    $invocationId = ConvertTo-HHPersistenceIdentifierByte -Identifier $Intent.InvocationId
    $rows = @(Invoke-HHSqliteQuery -Connection $Connection -Transaction $Transaction -Sql @'
SELECT r.*,d.database_id FROM remote_operations r CROSS JOIN database_identity d
WHERE r.invocation_id=@id AND r.ordinal=@ordinal;
'@ -Parameters @{ id = $invocationId; ordinal = $Ordinal })
    if ($rows.Count -ne 1) { throw "Remote operation ordinal $Ordinal is not declared." }
    if ($EventKind -ceq 'DispatchArmed') {
        if ($null -eq $ExpectedOperation) { throw 'DispatchArmed requires the exact expected operation.' }
        $row = $rows[0]
        $scriptText = Unprotect-HHAuditRepositoryText -Envelope ([byte[]]$row.script_envelope) `
            -MasterKey $MasterKey -DatabaseId ([byte[]]$row.database_id) `
            -InvocationId $invocationId -Column "script_envelope_$Ordinal" -Table remote_operations
        $arguments = Unprotect-HHAuditRepositoryText -Envelope ([byte[]]$row.arguments_envelope) `
            -MasterKey $MasterKey -DatabaseId ([byte[]]$row.database_id) `
            -InvocationId $invocationId -Column "arguments_envelope_$Ordinal" -Table remote_operations
        if ([string]$row.phase -cne [string]$ExpectedOperation.Phase -or
            [string]$row.powershell_runtime -cne [string]$ExpectedOperation.PowerShellRuntime -or
            $scriptText -cne [string]$ExpectedOperation.ScriptText -or
            $arguments -cne [string]$ExpectedOperation.SerializedArguments) {
            Stop-HHPersistenceOperation -ErrorId AuditIntegrityFailed `
                -Message 'The operation being armed differs from its authenticated declaration.' `
                -Category ([Management.Automation.ErrorCategory]::SecurityError) -TargetObject $Intent.InvocationId
        }
    }
    $evidenceJson = if ($null -eq $Evidence) { '{}' } else {
        $Evidence | ConvertTo-Json -Depth 12 -Compress
    }
    $evidenceBytes = [Text.UTF8Encoding]::new($false).GetBytes($evidenceJson)
    $evidenceAad = Get-HHAuditRepositoryAssociatedData `
        -DatabaseId ([byte[]]$rows[0].database_id) -RowId $invocationId `
        -Table remote_operation_events -Column "evidence_envelope_$Ordinal"
    $evidenceEnvelope = Protect-HHPersistenceValue -Plaintext $evidenceBytes `
        -MasterKey $MasterKey -AssociatedData $evidenceAad
    $evidenceHash = Get-HHPersistenceHash -Bytes $evidenceEnvelope
    $eventText = $EventAtUtc.UtcDateTime.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
    $null = Invoke-HHSqliteNonQuery -Connection $Connection -Transaction $Transaction -Sql @'
INSERT INTO remote_operation_events(
    invocation_id,ordinal,event_kind,event_at_utc,evidence_envelope,evidence_hash
) VALUES(@id,@ordinal,@kind,@at,@evidence,@hash);
'@ -Parameters @{ id = $invocationId; ordinal = $Ordinal; kind = $EventKind
        at = $eventText; evidence = $evidenceEnvelope; hash = $evidenceHash }
    $projectionBytes = [Text.UTF8Encoding]::new($false).GetBytes((
            [ordered]@{ invocationId = $Intent.InvocationId; ordinal = $Ordinal
                eventKind = $EventKind; eventAtUtc = $eventText } | ConvertTo-Json -Compress))
    $projectionHash = Get-HHPersistenceHash -Bytes $projectionBytes
    Write-HHSqliteAuditEvent -Connection $Connection -Transaction $Transaction `
        -EventKind "RemoteOperation$EventKind" -EventAtUtc $EventAtUtc `
        -InvocationId $invocationId -ProjectionHash $projectionHash `
        -RelatedEnvelopeHash $evidenceHash -MasterKey $MasterKey
}

function Complete-HHSqliteAuditIntent {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Writes inside an already authorized caller-owned SQLite transaction.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Connection,
        [Parameter(Mandatory)][object]$Transaction,
        [Parameter(Mandatory)][byte[]]$MasterKey,
        [Parameter(Mandatory)][object]$Intent,
        [Parameter(Mandatory)][ValidateSet('Succeeded', 'Failed', 'Cancelled', 'Unknown')]
        [string]$Status,
        [Parameter(Mandatory)][ValidateSet('NotDispatched', 'Dispatched', 'DispatchUncertain', 'Completed')]
        [string]$DispatchState,
        [Parameter(Mandatory)][ValidateSet('Succeeded', 'Failed', 'Unknown')]
        [string]$OutcomeStatus,
        [AllowNull()][string]$FailureKind,
        [Parameter(Mandatory)][DateTimeOffset]$CompletedAtUtc,
        [Parameter(Mandatory)][object]$Payload,
        [ValidateSet('None', 'RecoveredNotDispatched', 'RecoveredDispatchUncertain', 'RecoveredPartialEvidence')]
        [string]$RecoveryState = 'None',
        [AllowNull()][object]$ArtifactReceipt
    )

    $invocationId = ConvertTo-HHPersistenceIdentifierByte -Identifier $Intent.InvocationId
    $identity = @(Invoke-HHSqliteQuery -Connection $Connection -Transaction $Transaction `
            -Sql 'SELECT database_id FROM database_identity WHERE singleton_id=1;')
    if ($identity.Count -ne 1) { throw 'Database identity is unavailable.' }
    $payloadJson = $Payload | ConvertTo-Json -Depth 20 -Compress
    $payloadBytes = [Text.UTF8Encoding]::new($false).GetBytes($payloadJson)
    $payloadAad = Get-HHAuditRepositoryAssociatedData `
        -DatabaseId ([byte[]]$identity[0].database_id) -RowId $invocationId `
        -Table invocation_outcomes -Column outcome_envelope
    $payloadEnvelope = Protect-HHPersistenceValue -Plaintext $payloadBytes `
        -MasterKey $MasterKey -AssociatedData $payloadAad
    $payloadHash = Get-HHPersistenceHash -Bytes $payloadEnvelope
    $completedText = $CompletedAtUtc.UtcDateTime.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
    $null = Invoke-HHSqliteNonQuery -Connection $Connection -Transaction $Transaction -Sql @'
INSERT INTO invocation_outcomes(
    invocation_id,status,failure_kind,dispatch_state,outcome_status,completed_at_utc,
    identity_envelope,outcome_envelope,outcome_envelope_hash,recovery_state
) VALUES(@id,@status,@failure,@dispatch,@outcome,@completed,NULL,@envelope,@hash,@recovery);
'@ -Parameters @{ id = $invocationId; status = $Status; failure = $FailureKind
        dispatch = $DispatchState; outcome = $OutcomeStatus; completed = $completedText
        envelope = $payloadEnvelope; hash = $payloadHash; recovery = $RecoveryState }
    $relatedParts = [Collections.Generic.List[object]]::new()
    $relatedParts.Add($payloadHash)
    if ($null -ne $ArtifactReceipt) {
        $relativePath = "output/$($ArtifactReceipt.RelativeFileName)"
        $null = Invoke-HHSqliteNonQuery -Connection $Connection -Transaction $Transaction -Sql @'
INSERT INTO output_artifacts(
    invocation_id,artifact_id,relative_path,ciphertext_hash,ciphertext_bytes,
    plaintext_bytes,format_version,stream_event_count,published_at_utc
) VALUES(@id,@artifact,@path,@hash,@ciphertext,@plaintext,2,@events,@published);
'@ -Parameters @{ id = $invocationId; artifact = (ConvertTo-HHPersistenceIdentifierByte $Intent.ArtifactId)
            path = $relativePath; hash = $ArtifactReceipt.CiphertextSha256
            ciphertext = [long]$ArtifactReceipt.Bytes; plaintext = [long]$ArtifactReceipt.PlaintextBytes
            events = [long]$ArtifactReceipt.StreamEventCount; published = $completedText }
        $relatedParts.Add([byte[]]$ArtifactReceipt.CiphertextSha256)
    }
    $relatedHash = Get-HHPersistenceHash `
        -Bytes (Join-HHAuditArtifactV2Buffer -Part @($relatedParts))
    $projectionBytes = [Text.UTF8Encoding]::new($false).GetBytes((
            [ordered]@{ invocationId = $Intent.InvocationId; status = $Status
                failureKind = $FailureKind; dispatchState = $DispatchState
                outcomeStatus = $OutcomeStatus; completedAtUtc = $completedText
                recoveryState = $RecoveryState } | ConvertTo-Json -Compress))
    $projectionHash = Get-HHPersistenceHash -Bytes $projectionBytes
    Write-HHSqliteAuditEvent -Connection $Connection -Transaction $Transaction `
        -EventKind Terminal -EventAtUtc $CompletedAtUtc -InvocationId $invocationId `
        -ProjectionHash $projectionHash -RelatedEnvelopeHash $relatedHash -MasterKey $MasterKey
}

function Save-HHSqliteTransportArtifact {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Writes an already authorized invocation artifact.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$PersistenceContext,
        [Parameter(Mandatory)][object]$Intent,
        [Parameter(Mandatory)][byte[]]$DatabaseId,
        [Parameter(Mandatory)][byte[]]$LedgerId,
        [Parameter(Mandatory)][byte[]]$MasterKey,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$StreamEvent
    )

    $writer = Open-HHAuditArtifactV2Writer -DataRoot $PersistenceContext.DataRoot `
        -OutputRoot $PersistenceContext.OutputRoot -RecoveryRoot $PersistenceContext.RecoveryRoot `
        -DatabaseId $DatabaseId -LedgerId $LedgerId `
        -InvocationId (ConvertTo-HHPersistenceIdentifierByte $Intent.InvocationId) `
        -ArtifactId (ConvertTo-HHPersistenceIdentifierByte $Intent.ArtifactId) -MasterKey $MasterKey
    try {
        for ($index = 0; $index -lt $StreamEvent.Count; $index++) {
            $source = $StreamEvent[$index]
            $canonical = [pscustomobject][ordered]@{
                Sequence = [long]$index
                RemoteSequence = if ($null -eq $source.RemoteSequence) { $null } else { [long]$source.RemoteSequence }
                ObservedAtUtc = if ($null -eq $source.ObservedAtUtc) {
                    [DateTimeOffset]::UtcNow.ToString('o')
                }
                else { [string]$source.ObservedAtUtc }
                Phase = [string]$source.Phase
                Stream = [string]$source.Stream
                TypeName = [string]$source.TypeName
                SerializedByteCount = [long]$source.SerializedByteCount
                IsTerminating = [bool]$source.IsTerminating
                Value = $source.Value
            }
            Write-HHAuditArtifactV2Event -Writer $writer -EventRecord $canonical
        }
        return Complete-HHAuditArtifactV2Writer -Writer $writer
    }
    catch {
        $null = Abort-HHAuditArtifactV2Writer -Writer $writer
        throw
    }
}
