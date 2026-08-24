Set-StrictMode -Version Latest

function Unprotect-HHAuditRepositoryText {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()][byte[]]$Envelope,
        [Parameter(Mandatory)][byte[]]$MasterKey,
        [Parameter(Mandatory)][byte[]]$DatabaseId,
        [Parameter(Mandatory)][byte[]]$InvocationId,
        [Parameter(Mandatory)][string]$Column,
        [string]$Table = 'invocations'
    )

    if ($null -eq $Envelope) { return $null }
    $associatedData = Get-HHAuditRepositoryAssociatedData `
        -DatabaseId $DatabaseId `
        -RowId $InvocationId `
        -Table $Table `
        -Column $Column
    $plaintext = Unprotect-HHPersistenceValue `
        -Envelope $Envelope `
        -MasterKey $MasterKey `
        -AssociatedData $associatedData
    try {
        return [Text.UTF8Encoding]::new($false, $true).GetString($plaintext)
    }
    finally {
        [Array]::Clear($plaintext, 0, $plaintext.Length)
        [Array]::Clear($associatedData, 0, $associatedData.Length)
    }
}

function Get-HHSqliteAuditRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Connection,
        [Parameter(Mandatory)][byte[]]$MasterKey,
        [AllowNull()][string]$InvocationId,
        [AllowNull()][string]$BatchId,
        [AllowEmptyCollection()][string[]]$TargetName,
        [AllowNull()][string]$CaseId,
        [AllowNull()][Nullable[DateTimeOffset]]$FromUtc,
        [AllowNull()][Nullable[DateTimeOffset]]$ToUtc,
        [AllowEmptyCollection()][string[]]$Operation,
        [AllowEmptyCollection()][string[]]$Status,
        [AllowNull()][Nullable[long]]$BeforeSequence,
        [ValidateRange(1, 1000)][int]$First = 100
    )

    $identity = @(Invoke-HHSqliteQuery -Connection $Connection `
            -Sql 'SELECT database_id FROM database_identity WHERE singleton_id=1;')
    if ($identity.Count -ne 1) { throw 'Database identity is unavailable.' }
    $databaseId = [byte[]]$identity[0].database_id
    $rows = @(Invoke-HHSqliteQuery -Connection $Connection -Sql @'
SELECT i.*, b.operation, o.status, o.failure_kind, o.dispatch_state, o.outcome_status,
        o.completed_at_utc, o.recovery_state, a.relative_path, a.ciphertext_bytes,
        a.plaintext_bytes, a.stream_event_count
FROM invocations i
JOIN operation_batches b ON b.batch_id=i.batch_id
LEFT JOIN invocation_outcomes o ON o.invocation_id=i.invocation_id
LEFT JOIN output_artifacts a ON a.invocation_id=i.invocation_id
ORDER BY i.sequence DESC;
'@)
    $invocationFilter = if ([string]::IsNullOrWhiteSpace($InvocationId)) {
        $null
    }
    else { ConvertTo-HHPersistenceIdentifierText (ConvertTo-HHPersistenceIdentifierByte $InvocationId) }
    $batchFilter = if ([string]::IsNullOrWhiteSpace($BatchId)) {
        $null
    }
    else { ConvertTo-HHPersistenceIdentifierText (ConvertTo-HHPersistenceIdentifierByte $BatchId) }
    $targetFilter = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($name in @($TargetName)) { $null = $targetFilter.Add($name) }
    $operationFilter = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($name in @($Operation)) { $null = $operationFilter.Add($name) }
    $statusFilter = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($name in @($Status)) { $null = $statusFilter.Add($name) }
    $hasBeforeSequence = $PSBoundParameters.ContainsKey('BeforeSequence')
    $hasFromUtc = $PSBoundParameters.ContainsKey('FromUtc')
    $hasToUtc = $PSBoundParameters.ContainsKey('ToUtc')
    $hasCaseId = $PSBoundParameters.ContainsKey('CaseId')
    $hasTargetName = $PSBoundParameters.ContainsKey('TargetName')
    $hasOperation = $PSBoundParameters.ContainsKey('Operation')
    $hasStatus = $PSBoundParameters.ContainsKey('Status')
    $results = [Collections.Generic.List[object]]::new()
    foreach ($row in $rows) {
        if ($results.Count -ge $First) { break }
        $rowInvocationText = ConvertTo-HHPersistenceIdentifierText ([byte[]]$row.invocation_id)
        $rowBatchText = ConvertTo-HHPersistenceIdentifierText ([byte[]]$row.batch_id)
        $rowStatus = if ($null -eq $row.status) { 'Pending' } else { [string]$row.status }
        $intentAt = [DateTimeOffset]::Parse([string]$row.intent_at_utc).ToUniversalTime()
        if (($null -ne $invocationFilter -and $rowInvocationText -cne $invocationFilter) -or
            ($null -ne $batchFilter -and $rowBatchText -cne $batchFilter) -or
            ($hasTargetName -and -not $targetFilter.Contains([string]$row.target_name)) -or
            ($hasOperation -and -not $operationFilter.Contains([string]$row.operation)) -or
            ($hasStatus -and -not $statusFilter.Contains($rowStatus)) -or
            ($hasBeforeSequence -and [long]$row.sequence -ge [long]$BeforeSequence) -or
            ($hasFromUtc -and $intentAt -lt $FromUtc.ToUniversalTime()) -or
            ($hasToUtc -and $intentAt -ge $ToUtc.ToUniversalTime())) {
            continue
        }
        $rowId = [byte[]]$row.invocation_id
        $command = Unprotect-HHAuditRepositoryText -Envelope ([byte[]]$row.command_envelope) `
            -MasterKey $MasterKey -DatabaseId $databaseId -InvocationId $rowId `
            -Column command_envelope
        $reason = if ($null -eq $row.reason_envelope) { $null } else {
            Unprotect-HHAuditRepositoryText -Envelope ([byte[]]$row.reason_envelope) `
                -MasterKey $MasterKey -DatabaseId $databaseId -InvocationId $rowId `
                -Column reason_envelope
        }
        $caseValue = if ($null -eq $row.case_envelope) { $null } else {
            Unprotect-HHAuditRepositoryText -Envelope ([byte[]]$row.case_envelope) `
                -MasterKey $MasterKey -DatabaseId $databaseId -InvocationId $rowId `
                -Column case_envelope
        }
        if ($hasCaseId -and $caseValue -cne $CaseId) { continue }
        $record = [pscustomobject][ordered]@{
            Sequence = [long]$row.sequence
            InvocationId = $rowInvocationText
            BatchId = $rowBatchText
            Operation = [string]$row.operation
            TargetName = [string]$row.target_name
            Transport = [string]$row.transport
            HostName = [string]$row.host_name
            Port = [int]$row.port
            UserName = [string]$row.user_name
            Authentication = [string]$row.authentication
            RequestedPowerShellRuntime = [string]$row.requested_runtime
            RequestedExecutionMode = [string]$row.requested_execution_mode
            IntentAtUtc = $intentAt.ToString('o')
            Status = $rowStatus
            FailureKind = $row.failure_kind
            DispatchState = $row.dispatch_state
            OutcomeStatus = $row.outcome_status
            CompletedAtUtc = $row.completed_at_utc
            RecoveryState = $row.recovery_state
            CommandText = $command
            Reason = $reason
            CaseId = $caseValue
            OutputRelativePath = $row.relative_path
            CiphertextBytes = $row.ciphertext_bytes
            PlaintextBytes = $row.plaintext_bytes
            StreamEventCount = $row.stream_event_count
        }
        $record.PSObject.TypeNames.Insert(0, 'HostHunter.AuditRecord')
        $results.Add($record)
    }
    return [object[]]$results
}

function Get-HHSqliteAuditOutput {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Connection,
        [Parameter(Mandatory)][object]$PersistenceContext,
        [Parameter(Mandatory)][byte[]]$MasterKey,
        [Parameter(Mandatory)][string]$InvocationId
    )

    $invocationBytes = ConvertTo-HHPersistenceIdentifierByte -Identifier $InvocationId
    $rows = @(Invoke-HHSqliteQuery -Connection $Connection -Sql @'
SELECT i.invocation_id,i.reserved_artifact_id,d.database_id,d.ledger_id,
        a.relative_path,a.ciphertext_hash,a.ciphertext_bytes
FROM invocations i
CROSS JOIN database_identity d
LEFT JOIN output_artifacts a ON a.invocation_id=i.invocation_id
WHERE i.invocation_id=@id;
'@ -Parameters @{ id = $invocationBytes })
    if ($rows.Count -ne 1) { throw "No audit invocation exists with id '$InvocationId'." }
    if ($null -eq $rows[0].relative_path) {
        throw "Audit output is not available for invocation '$InvocationId'."
    }
    $path = [IO.Path]::GetFullPath((Join-Path $PersistenceContext.AuditRoot ([string]$rows[0].relative_path)))
    if (-not (Test-HHPersistencePathContained -Root $PersistenceContext.OutputRoot -Candidate $path)) {
        Stop-HHPersistenceOperation -ErrorId AuditIntegrityFailed `
            -Message 'The stored audit output path escapes its authenticated output root.' `
            -Category ([Management.Automation.ErrorCategory]::SecurityError) -TargetObject $path
    }
    Read-HHAuditArtifactV2 -Path $path -DataRoot $PersistenceContext.DataRoot `
        -DatabaseId ([byte[]]$rows[0].database_id) -LedgerId ([byte[]]$rows[0].ledger_id) `
        -InvocationId ([byte[]]$rows[0].invocation_id) -ArtifactId ([byte[]]$rows[0].reserved_artifact_id) `
        -MasterKey $MasterKey -ExpectedCiphertextSha256 ([byte[]]$rows[0].ciphertext_hash) `
        -ExpectedLength ([long]$rows[0].ciphertext_bytes)
}
