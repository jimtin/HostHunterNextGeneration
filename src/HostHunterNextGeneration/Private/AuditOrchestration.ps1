Set-StrictMode -Version Latest

function Register-HHAuthenticatedAuditBatch {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Private orchestration occurs after the public authorization boundary.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$Operation,
        [Parameter(Mandatory)][object[]]$Request
    )

    $arguments = [pscustomobject]@{
        Operation = $Operation
        Request = $Request
        IntentAtUtc = [DateTimeOffset]::UtcNow
    }
    @(Invoke-HHAnchoredPersistenceTransaction -Context $Context `
            -ArgumentList @($arguments) -Action {
            param($Connection, $Transaction, $WriterContext, $ArgumentList)
            $inputData = $ArgumentList[0]
            Register-HHSqliteAuditBatch -Connection $Connection -Transaction $Transaction `
                -MasterKey $WriterContext.MasterKey -Operation $inputData.Operation `
                -Request $inputData.Request -IntentAtUtc $inputData.IntentAtUtc
        })
}

function Start-HHAuthenticatedAuditCapacityReservation {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Private orchestration occurs after the public authorization boundary.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][ValidateCount(1, 8)][object[]]$Intent
    )

    try {
        New-HHPersistenceCapacityReservation `
            -PersistenceContext $Context.PersistenceContext `
            -BatchId ([string]$Intent[0].BatchId) `
            -InvocationCount $Intent.Count
    }
    catch {
        $capacityFailure = $_
        foreach ($item in $Intent) {
            try {
                Complete-HHAuthenticatedUnstartedAuditIntent -Context $Context `
                    -Intent $item -Reason PersistenceCapacityInsufficient
            }
            catch {
                $capacityFailure.Exception.Data['HHAuditCancellationFailure'] = $true
            }
        }
        throw $capacityFailure
    }
}

function Open-HHAuthenticatedAuditArtifactWriter {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][object]$Intent
    )

    Open-HHAuditArtifactV2Writer `
        -DataRoot $Context.PersistenceContext.DataRoot `
        -OutputRoot $Context.PersistenceContext.OutputRoot `
        -RecoveryRoot $Context.PersistenceContext.RecoveryRoot `
        -DatabaseId ([byte[]]$Context.Anchor.DatabaseId) `
        -LedgerId ([byte[]]$Context.Anchor.LedgerId) `
        -InvocationId (ConvertTo-HHPersistenceIdentifierByte $Intent.InvocationId) `
        -ArtifactId (ConvertTo-HHPersistenceIdentifierByte $Intent.ArtifactId) `
        -MasterKey $Context.MasterKey
}

function Arm-HHAuthenticatedRemoteOperation {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseApprovedVerbs',
        '',
        Justification = 'Arm is the explicit security state transition immediately before dispatch.'
    )]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Private orchestration occurs after the public authorization boundary.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][object]$Intent,
        [Parameter(Mandatory)][ValidateCount(1, 64)][int[]]$Ordinal
    )

    $arguments = [pscustomobject]@{ Intent = $Intent; Ordinal = $Ordinal; At = [DateTimeOffset]::UtcNow }
    $null = Invoke-HHAnchoredPersistenceTransaction -Context $Context `
        -ArgumentList @($arguments) -Action {
        param($Connection, $Transaction, $WriterContext, $ArgumentList)
        $inputData = $ArgumentList[0]
        $events = [Collections.Generic.List[object]]::new()
        foreach ($item in $inputData.Ordinal) {
            $events.Add((Write-HHSqliteRemoteOperationEvent -Connection $Connection `
                    -Transaction $Transaction -MasterKey $WriterContext.MasterKey `
                    -Intent $inputData.Intent -Ordinal $item -EventKind DispatchArmed `
                    -EventAtUtc $inputData.At `
                    -ExpectedOperation $inputData.Intent.RemoteOperations[$item]))
        }
        [pscustomobject]@{ Events = [object[]]$events; Prepared = $true; Committed = $false }
    }
}

function Complete-HHAuthenticatedUnstartedAuditIntent {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Private orchestration occurs after the public authorization boundary.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][object]$Intent,
        [Parameter(Mandatory)][string]$Reason
    )

    $arguments = [pscustomobject]@{
        Intent = $Intent
        At = [DateTimeOffset]::UtcNow
        Payload = [ordered]@{ reason = $Reason; remoteActivityStarted = $false }
    }
    $null = Invoke-HHAnchoredPersistenceTransaction -Context $Context `
        -ArgumentList @($arguments) -Action {
        param($Connection, $Transaction, $WriterContext, $ArgumentList)
        $inputData = $ArgumentList[0]
        for ($ordinal = 0; $ordinal -lt $inputData.Intent.RemoteOperations.Count; $ordinal++) {
            $null = Write-HHSqliteRemoteOperationEvent -Connection $Connection `
                -Transaction $Transaction -MasterKey $WriterContext.MasterKey `
                -Intent $inputData.Intent -Ordinal $ordinal -EventKind Skipped `
                -EventAtUtc $inputData.At -Evidence $inputData.Payload
        }
        $null = Complete-HHSqliteAuditIntent -Connection $Connection -Transaction $Transaction `
            -MasterKey $WriterContext.MasterKey -Intent $inputData.Intent `
            -Status Cancelled -FailureKind $null -DispatchState NotDispatched `
            -OutcomeStatus Failed -CompletedAtUtc $inputData.At -Payload $inputData.Payload
    }
}

function Complete-HHAuthenticatedTransportAudit {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Private orchestration occurs after the public authorization boundary.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][object]$Intent,
        [Parameter(Mandatory)][object]$TransportResult,
        [Parameter(Mandatory)][AllowEmptyCollection()][int[]]$ArmedOrdinal,
        [object]$ArtifactWriter
    )

    $intentMetadata = Get-HHAuditIntentTransportContext -Intent $Intent
    $validated = Assert-HHTransportAuditResult `
        -TransportResult $TransportResult `
        -IntentMetadata $intentMetadata
    $artifact = if ($null -eq $ArtifactWriter) {
        Save-HHSqliteTransportArtifact `
            -PersistenceContext $Context.PersistenceContext `
            -Intent $Intent `
            -DatabaseId ([byte[]]$Context.Anchor.DatabaseId) `
            -LedgerId ([byte[]]$Context.Anchor.LedgerId) `
            -MasterKey $Context.MasterKey `
            -StreamEvent ([object[]]$validated.StreamEvents)
    }
    else {
        for ($index = [int]$ArtifactWriter.EventCount;
            $index -lt $validated.StreamEvents.Count; $index++) {
            Write-HHAuditArtifactV2Event -Writer $ArtifactWriter `
                -EventRecord $validated.StreamEvents[$index]
        }
        Complete-HHAuditArtifactV2Writer -Writer $ArtifactWriter
    }
    $payload = [ordered]@{
        failureKind = $validated.FailureKind
        dispatchState = $validated.DispatchState
        outcomeStatus = $validated.OutcomeStatus
        remoteIdentity = $validated.RemoteIdentity
        remotePowerShellVersion = $validated.RemotePowerShellVersion
        remotePSEdition = $validated.RemotePSEdition
        executionMode = $validated.ExecutionMode
        validatedAtUtc = $validated.ValidatedAtUtc
        observedHostKeyFingerprint = $validated.HostKeyFingerprint
        outputBytes = $validated.OutputBytes
        streamEventCount = @($validated.StreamEvents).Count
        exceptionType = $validated.ExceptionType
    }
    if ($validated.HasSessionRemovalFailure) {
        $payload.sessionRemovalFailure = $validated.SessionRemovalFailure
    }
    if ($validated.HasBootstrapOutcome) {
        $payload.installed = $validated.Installed
        $payload.rollbackAttempted = $validated.RollbackAttempted
        $payload.rollbackSucceeded = $validated.RollbackSucceeded
        $payload.reconciliationRequired = $validated.ReconciliationRequired
        $payload.commitState = $validated.CommitState
    }
    $arguments = [pscustomobject]@{
        Intent = $Intent
        Validated = $validated
        ArmedOrdinal = $ArmedOrdinal
        Artifact = $artifact
        Payload = $payload
        At = [DateTimeOffset]::UtcNow
    }
    $null = Invoke-HHAnchoredPersistenceTransaction -Context $Context `
        -ArgumentList @($arguments) -Action {
        param($Connection, $Transaction, $WriterContext, $ArgumentList)
        $inputData = $ArgumentList[0]
        $armed = [Collections.Generic.HashSet[int]]::new()
        foreach ($ordinal in $inputData.ArmedOrdinal) { $null = $armed.Add($ordinal) }
        for ($ordinal = 0; $ordinal -lt $inputData.Intent.RemoteOperations.Count; $ordinal++) {
            $eventKind = if ($armed.Contains($ordinal)) { 'Completed' } else { 'Skipped' }
            $null = Write-HHSqliteRemoteOperationEvent -Connection $Connection `
                -Transaction $Transaction -MasterKey $WriterContext.MasterKey `
                -Intent $inputData.Intent -Ordinal $ordinal -EventKind $eventKind `
                -EventAtUtc $inputData.At -Evidence $inputData.Payload
        }
        $status = if ($inputData.Validated.OutcomeStatus -ceq 'Succeeded') {
            'Succeeded'
        }
        elseif ($inputData.Validated.OutcomeStatus -ceq 'Unknown') { 'Unknown' }
        else { 'Failed' }
        $null = Complete-HHSqliteAuditIntent -Connection $Connection -Transaction $Transaction `
            -MasterKey $WriterContext.MasterKey -Intent $inputData.Intent `
            -Status $status -FailureKind $inputData.Validated.FailureKind `
            -DispatchState $inputData.Validated.DispatchState `
            -OutcomeStatus $inputData.Validated.OutcomeStatus `
            -CompletedAtUtc $inputData.At -Payload $inputData.Payload `
            -ArtifactReceipt $inputData.Artifact
    }
    return $artifact
}
