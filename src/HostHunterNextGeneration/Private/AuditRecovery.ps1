Set-StrictMode -Version Latest

function Resolve-HHInterruptedAuditArtifact {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Crash recovery preserves an uncommitted artifact inside the private recovery root.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$PersistenceContext,
        [Parameter(Mandatory)][string]$InvocationId,
        [Parameter(Mandatory)][string]$ArtifactId,
        [Parameter(Mandatory)][byte[]]$DatabaseId,
        [Parameter(Mandatory)][byte[]]$LedgerId,
        [Parameter(Mandatory)][byte[]]$MasterKey
    )

    $completeArtifact = $null
    $finalPath = Join-Path $PersistenceContext.OutputRoot "$InvocationId.hhout"
    if ([IO.File]::Exists($finalPath)) {
        if (-not (Test-HHAuditArtifactV2 -Path $finalPath `
                -DataRoot $PersistenceContext.DataRoot -DatabaseId $DatabaseId `
                -LedgerId $LedgerId `
                -InvocationId (ConvertTo-HHPersistenceIdentifierByte $InvocationId) `
                -ArtifactId (ConvertTo-HHPersistenceIdentifierByte $ArtifactId) `
                -MasterKey $MasterKey)) {
            Stop-HHPersistenceOperation -ErrorId AuditIntegrityFailed `
                -Message 'An orphan audit artifact failed identity and cryptographic verification.' `
                -Category ([Management.Automation.ErrorCategory]::SecurityError) `
                -TargetObject $finalPath
        }
        $expectedHeader = Get-HHAuditArtifactV2Header `
            -DatabaseId $DatabaseId -LedgerId $LedgerId `
            -InvocationId (ConvertTo-HHPersistenceIdentifierByte $InvocationId) `
            -ArtifactId (ConvertTo-HHPersistenceIdentifierByte $ArtifactId) `
            -ChunkSize $script:HHAuditArtifactV2DefaultChunkBytes
        $stream = [IO.FileStream]::new(
            $finalPath, [IO.FileMode]::Open, [IO.FileAccess]::Read,
            [IO.FileShare]::Read, 65536, [IO.FileOptions]::SequentialScan
        )
        try {
            $verified = Read-HHAuditArtifactV2Pass `
                -Stream $stream -MasterKey $MasterKey -ExpectedHeader $expectedHeader
        }
        finally { $stream.Dispose() }
        $info = [IO.FileInfo]::new($finalPath)
        $completeArtifact = [pscustomobject]@{
                Path = $finalPath
                RelativeFileName = $info.Name
                Bytes = $info.Length
                CiphertextSha256 = [Convert]::FromHexString((
                        Get-FileHash -LiteralPath $finalPath -Algorithm SHA256
                    ).Hash)
                FormatVersion = 2
                ChunkCount = [long]$verified.ChunkCount
                StreamEventCount = [long]$verified.EventCount
                PlaintextBytes = [long]$verified.PlaintextBytes
        }
    }

    $quarantinePath = $null
    $candidate = Join-Path $PersistenceContext.OutputRoot ".$InvocationId.$ArtifactId.tmp"
    if ([IO.File]::Exists($candidate)) {
        [IO.Directory]::CreateDirectory($PersistenceContext.RecoveryRoot) | Out-Null
        $destination = Join-Path $PersistenceContext.RecoveryRoot `
            "$InvocationId.$ArtifactId.$([Guid]::NewGuid().ToString('N')).partial"
        [IO.File]::Move($candidate, $destination, $false)
        if (-not $IsWindows) {
            [IO.File]::SetUnixFileMode(
                $destination,
                [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite
            )
        }
        $quarantinePath = $destination
    }
    return [pscustomobject]@{
        CompleteArtifact = $completeArtifact
        QuarantinePath = $quarantinePath
    }
}

function Remove-HHRecoveredCapacityReservation {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Deletes only stale HostHunter reservation files after anchored recovery.'
    )]
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$PersistenceContext)

    if (-not [IO.Directory]::Exists($PersistenceContext.RecoveryRoot)) { return }
    foreach ($file in @(Get-ChildItem -LiteralPath $PersistenceContext.RecoveryRoot `
                -Filter '.*.capacity.reserve' -File -Force)) {
        if ($file.Name -cnotmatch '^\.[a-f0-9]{32}\.capacity\.reserve$' -or
            ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            $null -ne $file.LinkTarget) {
            Stop-HHPersistenceOperation -ErrorId PersistencePathUnsafe `
                -Message 'A stale capacity reservation has an unsafe identity.' `
                -Category ([Management.Automation.ErrorCategory]::SecurityError) `
                -TargetObject $file.FullName
        }
        [IO.File]::Delete($file.FullName)
    }
}

function Recover-HHAuthenticatedAuditState {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseApprovedVerbs',
        '',
        Justification = 'Recover names the mandatory crash-reconciliation boundary precisely.'
    )]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Recovery is a mandatory fail-closed startup transition before new work.'
    )]
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Context)

    $pending = @(Invoke-HHSqliteQuery -Connection $Context.Connection -Sql @'
SELECT i.invocation_id,i.reserved_artifact_id
FROM invocations i
LEFT JOIN invocation_outcomes o ON o.invocation_id=i.invocation_id
WHERE o.invocation_id IS NULL
ORDER BY i.sequence;
'@)
    if ($pending.Count -eq 0) {
        Remove-HHRecoveredCapacityReservation -PersistenceContext $Context.PersistenceContext
        return @()
    }

    $recoveryInput = [Collections.Generic.List[object]]::new()
    foreach ($row in $pending) {
        $invocationId = ConvertTo-HHPersistenceIdentifierText ([byte[]]$row.invocation_id)
        $artifactId = ConvertTo-HHPersistenceIdentifierText ([byte[]]$row.reserved_artifact_id)
        $artifactState = Resolve-HHInterruptedAuditArtifact `
            -PersistenceContext $Context.PersistenceContext `
            -InvocationId $invocationId -ArtifactId $artifactId `
            -DatabaseId ([byte[]]$Context.Anchor.DatabaseId) `
            -LedgerId ([byte[]]$Context.Anchor.LedgerId) `
            -MasterKey $Context.MasterKey
        $recoveryInput.Add([pscustomobject]@{
            InvocationId = $invocationId
            ArtifactId = $artifactId
            CompleteArtifact = $artifactState.CompleteArtifact
            QuarantinePath = $artifactState.QuarantinePath
            })
    }

    $arguments = [pscustomobject]@{
        Pending = [object[]]$recoveryInput
        At = [DateTimeOffset]::UtcNow
    }
    $receipt = Invoke-HHAnchoredPersistenceTransaction -Context $Context `
        -ArgumentList @($arguments) -Action {
            param($Connection, $Transaction, $WriterContext, $ArgumentList)
            $inputData = $ArgumentList[0]
            $receipts = [Collections.Generic.List[object]]::new()
            foreach ($item in $inputData.Pending) {
                $invocationBytes = ConvertTo-HHPersistenceIdentifierByte $item.InvocationId
                $operations = @(Invoke-HHSqliteQuery -Connection $Connection `
                        -Transaction $Transaction -Sql @'
SELECT r.ordinal,
        MAX(CASE WHEN e.event_kind='DispatchArmed' THEN 1 ELSE 0 END) AS armed,
        MAX(CASE WHEN e.event_kind IN ('Completed','Skipped','DispatchUncertain') THEN 1 ELSE 0 END) AS terminal
FROM remote_operations r
LEFT JOIN remote_operation_events e
    ON e.invocation_id=r.invocation_id AND e.ordinal=r.ordinal
WHERE r.invocation_id=@id
GROUP BY r.ordinal
ORDER BY r.ordinal;
'@ -Parameters @{ id = $invocationBytes })
                $anyArmed = @($operations | Where-Object { [int]$_.armed -eq 1 }).Count -gt 0
                if ($null -ne $item.CompleteArtifact -and -not $anyArmed) {
                    Stop-HHPersistenceOperation -ErrorId AuditIntegrityFailed `
                        -Message 'A complete audit artifact exists for an invocation that was never armed.' `
                        -Category ([Management.Automation.ErrorCategory]::SecurityError) `
                        -TargetObject $item.InvocationId
                }
                $intent = [pscustomobject]@{
                    InvocationId = $item.InvocationId
                    ArtifactId = $item.ArtifactId
                }
                $payload = [ordered]@{
                    reason = 'RecoveredUnterminatedInvocation'
                    remoteRetryAttempted = $false
                    partialEvidenceQuarantined = $null -ne $item.QuarantinePath
                    completeEvidenceAttached = $null -ne $item.CompleteArtifact
                    quarantinePath = $item.QuarantinePath
                }
                foreach ($operation in $operations) {
                    if ([int]$operation.terminal -eq 1) { continue }
                    $kind = if ([int]$operation.armed -eq 1) {
                        'DispatchUncertain'
                    }
                    else { 'Skipped' }
                    $null = Write-HHSqliteRemoteOperationEvent -Connection $Connection `
                        -Transaction $Transaction -MasterKey $WriterContext.MasterKey `
                        -Intent $intent -Ordinal ([int]$operation.ordinal) `
                        -EventKind $kind -EventAtUtc $inputData.At -Evidence $payload
                }
                $recoveryState = if ($null -ne $item.QuarantinePath -or
                    $null -ne $item.CompleteArtifact) {
                    'RecoveredPartialEvidence'
                }
                elseif ($anyArmed) { 'RecoveredDispatchUncertain' }
                else { 'RecoveredNotDispatched' }
                $status = if ($anyArmed) { 'Unknown' } else { 'Failed' }
                $outcomeStatus = if ($anyArmed) { 'Unknown' } else { 'Failed' }
                $null = Complete-HHSqliteAuditIntent -Connection $Connection `
                    -Transaction $Transaction -MasterKey $WriterContext.MasterKey `
                    -Intent $intent -Status $status -FailureKind TransportFailure `
                    -DispatchState $(if ($anyArmed) { 'DispatchUncertain' } else { 'NotDispatched' }) `
                    -OutcomeStatus $outcomeStatus -CompletedAtUtc $inputData.At `
                    -Payload $payload -RecoveryState $recoveryState `
                    -ArtifactReceipt $item.CompleteArtifact
                $receipts.Add([pscustomobject]@{
                        InvocationId = $item.InvocationId
                        Status = $status
                        OutcomeStatus = $outcomeStatus
                        RecoveryState = $recoveryState
                        DispatchState = if ($anyArmed) { 'DispatchUncertain' } else { 'NotDispatched' }
                    })
            }
            [pscustomobject]@{ Recovered = [object[]]$receipts }
        }
    Remove-HHRecoveredCapacityReservation -PersistenceContext $Context.PersistenceContext
    return [object[]]$receipt.Recovered
}
