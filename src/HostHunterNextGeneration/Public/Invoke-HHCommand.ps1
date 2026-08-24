function Invoke-HHCommand {
    <#
    .SYNOPSIS
    Runs a PowerShell command against active or selected HostHunter targets.
    .DESCRIPTION
    Records durable per-target intent before opening any connection, captures
    every PowerShell stream into encrypted artifacts, and never retries an
    uncertain command automatically.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Command,

        [ValidateCount(1, 8)]
        [string[]]$Target,

        [ValidateRange(1, 8)]
        [int]$ThrottleLimit = 8,

        [string]$Reason,
        [string]$CaseId
    )

    $tokens = $null
    $parseErrors = $null
    [System.Management.Automation.Language.Parser]::ParseInput(
        $Command,
        [ref]$tokens,
        [ref]$parseErrors
    ) | Out-Null
    if ($parseErrors.Count -gt 0) {
        throw "Command text is not valid PowerShell: $($parseErrors[0].Message)"
    }

    $runtime = Get-HHRuntimeContext
    if (-not [IO.File]::Exists($runtime.DatabasePath)) {
        throw 'No active HostHunter targets are available.'
    }
    $context = Open-HHAuthenticatedPersistence -PersistenceContext $runtime `
        -OperationLock -AllowAnchorAdvance
    $capacityReservation = $null
    $artifactWriterByName = @{}
    try {
    $snapshotParameters = @{
        Connection = $context.Connection
        MasterKey = $context.MasterKey
        ExpectedAnchor = $context.Anchor
    }
    if ($PSBoundParameters.ContainsKey('Target')) { $snapshotParameters.Name = $Target }
    $savedTargets = @((Read-HHTargetRepositorySnapshot @snapshotParameters).Targets)
    $selectedTargets = @(
        if ($null -eq $Target) {
            @($savedTargets | Where-Object IsActive)
        }
        else {
            $storedNames = @($savedTargets | ForEach-Object Name)
            $missing = @($Target | Where-Object { $_ -notin $storedNames })
            if ($missing.Count -gt 0) {
                throw "Unknown target(s): $($missing -join ', ')."
            }
            $savedTargets
        }
    )
    if ($selectedTargets.Count -eq 0) {
        throw 'No active HostHunter targets are available.'
    }
    if (@($selectedTargets | Where-Object Transport -ne 'SSH').Count -gt 0) {
        Assert-HHWinRmControllerSupported
        throw 'WinRM command execution is not qualified in this release.'
    }

    $remoteCommand = {
        param([Parameter(Mandatory)][string]$CommandText)
        $remoteScript = [scriptblock]::Create($CommandText)
        & $remoteScript
    }

    $request = @(
        foreach ($selectedTarget in $selectedTargets) {
            [pscustomobject]@{
                Target = $selectedTarget
                CommandText = $Command
                RemoteOperations = @(Get-HHCommandRemoteOperationManifest `
                        -Target $selectedTarget -ScriptBlock $remoteCommand `
                        -ArgumentList @($Command))
                Reason = $Reason
                CaseId = $CaseId
            }
        }
    )
    $registered = @(Register-HHAuthenticatedAuditBatch -Context $context `
            -Operation InvokeCommand -Request $request)
    $capacityReservation = Start-HHAuthenticatedAuditCapacityReservation `
        -Context $context -Intent $registered
    $batchId = $registered[0].BatchId
    $intentByName = @{}
    for ($intentIndex = 0; $intentIndex -lt $registered.Count; $intentIndex++) {
        $intentByName[$selectedTargets[$intentIndex].Name] = $registered[$intentIndex]
        $artifactWriterByName[$selectedTargets[$intentIndex].Name] = `
            Open-HHAuthenticatedAuditArtifactWriter -Context $context `
            -Intent $registered[$intentIndex]
    }

    $sessionByName = @{}
    $resultByName = @{}
    $cleanupFailureEventByName = @{}
    $armedOrdinalByName = @{}
    try {
        foreach ($selectedTarget in $selectedTargets) {
            $intent = $intentByName[$selectedTarget.Name]
            $identityOrdinals = @(0..($intent.RemoteOperations.Count - 2))
            Arm-HHAuthenticatedRemoteOperation -Context $context `
                -Intent $intent -Ordinal $identityOrdinals
            $armedOrdinalByName[$selectedTarget.Name] = [Collections.Generic.List[int]]::new()
            foreach ($ordinal in $identityOrdinals) {
                $armedOrdinalByName[$selectedTarget.Name].Add($ordinal)
            }
            try {
                $sessionByName[$selectedTarget.Name] = Open-HHSshSession `
                    -Target $selectedTarget `
                    -KnownHostsPath $runtime.KnownHostsPath
                foreach ($identityEvent in @($sessionByName[$selectedTarget.Name].IdentityEvents)) {
                    Write-HHAuditArtifactV2Event `
                        -Writer $artifactWriterByName[$selectedTarget.Name] `
                        -EventRecord $identityEvent
                }
            }
            catch {
                $openFailureKind = Get-HHSshFailureKind -ErrorObject $_
                $observedPropertyByResultName = [ordered]@{
                    RemoteIdentity = 'HHObservedIdentity'
                    RemotePowerShellVersion = 'HHObservedRemotePowerShellVersion'
                    RemotePSEdition = 'HHObservedRemotePSEdition'
                    ExecutionMode = 'HHObservedExecutionMode'
                    ValidatedAtUtc = 'HHObservedValidatedAtUtc'
                    HostKeyFingerprint = 'HHObservedHostKeyFingerprint'
                }
                $hasCompleteObservedMismatch = $openFailureKind -ceq 'RuntimeMismatch'
                foreach ($dataKey in $observedPropertyByResultName.Values) {
                    if (-not $_.Exception.Data.Contains($dataKey) -or
                        $null -eq $_.Exception.Data[$dataKey]) {
                        $hasCompleteObservedMismatch = $false
                    }
                }
                if ($openFailureKind -ceq 'RuntimeMismatch' -and
                    -not $hasCompleteObservedMismatch) {
                    # A mismatch is evidence-bearing. If the transport cannot
                    # attribute the requested-runtime identity, fail closed as
                    # a protocol/transport failure rather than inventing one.
                    $openFailureKind = 'TransportFailure'
                }
                $openEvents = [Collections.Generic.List[object]]::new()
                if ($_.Exception.Data.Contains('HHStreamEvents')) {
                    foreach ($eventRecord in @($_.Exception.Data['HHStreamEvents'])) {
                        $eventRecord.Sequence = $openEvents.Count
                        $openEvents.Add($eventRecord)
                    }
                }
                $openEvents.Add((New-HHSshStreamEvent `
                            -Sequence $openEvents.Count `
                            -Phase Transport `
                            -InputObject ([string] $_) `
                            -StreamOverride Error `
                            -TypeNameOverride $_.Exception.GetType().FullName))
                $resultByName[$selectedTarget.Name] = [pscustomobject]@{
                    Succeeded = $false
                    FailureKind = $openFailureKind
                    RemoteIdentity = if ($hasCompleteObservedMismatch) {
                        $_.Exception.Data[$observedPropertyByResultName.RemoteIdentity]
                    }
                    else { $null }
                    RemotePowerShellVersion = if ($hasCompleteObservedMismatch) {
                        [string] $_.Exception.Data[
                            $observedPropertyByResultName.RemotePowerShellVersion
                        ]
                    }
                    else { $null }
                    RemotePSEdition = if ($hasCompleteObservedMismatch) {
                        [string] $_.Exception.Data[$observedPropertyByResultName.RemotePSEdition]
                    }
                    else { $null }
                    ExecutionMode = if ($hasCompleteObservedMismatch) {
                        [string] $_.Exception.Data[$observedPropertyByResultName.ExecutionMode]
                    }
                    else { $null }
                    ValidatedAtUtc = if ($hasCompleteObservedMismatch) {
                        [string] $_.Exception.Data[$observedPropertyByResultName.ValidatedAtUtc]
                    }
                    else { $null }
                    HostKeyFingerprint = if ($hasCompleteObservedMismatch) {
                        [string] $_.Exception.Data[
                            $observedPropertyByResultName.HostKeyFingerprint
                        ]
                    }
                    else { $null }
                    StreamEvents = @($openEvents)
                    OutputBytes = Get-HHSshStreamEventByteCount `
                        -StreamEvents @($openEvents) `
                        -ExcludePhase Transport
                    ExceptionType = $_.Exception.GetType().FullName
                    DispatchState = if ($_.Exception.Data.Contains('HHDispatchState')) {
                        [string] $_.Exception.Data['HHDispatchState']
                    }
                    else {
                        'NotDispatched'
                    }
                    OutcomeStatus = if ($_.Exception.Data.Contains('HHOutcomeStatus')) {
                        [string] $_.Exception.Data['HHOutcomeStatus']
                    }
                    else {
                        'Failed'
                    }
                }
            }
        }

        if ($sessionByName.Count -gt 0) {
            foreach ($targetName in $sessionByName.Keys) {
                $intent = $intentByName[$targetName]
                $commandOrdinal = $intent.RemoteOperations.Count - 1
                Arm-HHAuthenticatedRemoteOperation -Context $context `
                    -Intent $intent -Ordinal @($commandOrdinal)
                $armedOrdinalByName[$targetName].Add($commandOrdinal)
            }
            $streamObserver = {
                param([string]$ObservedTargetName, [object]$EventRecord)
                Write-HHAuditArtifactV2Event `
                    -Writer $artifactWriterByName[$ObservedTargetName] `
                    -EventRecord $EventRecord
            }
            $fanOutResults = Invoke-HHSshSessionFanOut `
                -SessionContextByName $sessionByName `
                -ScriptBlock $remoteCommand `
                -ArgumentList @($Command) `
                -ThrottleLimit $ThrottleLimit `
                -EventObserver $streamObserver
            foreach ($targetName in $fanOutResults.Keys) {
                $resultByName[$targetName] = $fanOutResults[$targetName]
            }
        }
    }
    finally {
        foreach ($sessionEntry in $sessionByName.GetEnumerator()) {
            try {
                Close-HHSshSession -Session $sessionEntry.Value.Session
            }
            catch {
                [object[]] $existingEvents = if ($resultByName.ContainsKey($sessionEntry.Key)) {
                    @($resultByName[$sessionEntry.Key].StreamEvents)
                }
                else {
                    @($sessionEntry.Value.IdentityEvents)
                }
                $cleanupFailureEventByName[$sessionEntry.Key] = New-HHSshStreamEvent `
                    -Sequence (@($existingEvents).Count) `
                    -Phase Transport `
                    -InputObject ([string] $_) `
                    -StreamOverride Error `
                    -TypeNameOverride $_.Exception.GetType().FullName
            }
        }
    }

    @(
        foreach ($selectedTarget in $selectedTargets) {
            $commandResult = $resultByName[$selectedTarget.Name]
            $hasCommandMismatchEvidence = $commandResult.FailureKind -ceq 'RuntimeMismatch' -and
                $null -ne $commandResult.PSObject.Properties['RemoteIdentity'] -and
                $null -ne $commandResult.RemoteIdentity -and
                -not [string]::IsNullOrWhiteSpace(
                    [string] $commandResult.RemotePowerShellVersion
                ) -and
                -not [string]::IsNullOrWhiteSpace([string] $commandResult.RemotePSEdition) -and
                -not [string]::IsNullOrWhiteSpace([string] $commandResult.ExecutionMode) -and
                -not [string]::IsNullOrWhiteSpace([string] $commandResult.ValidatedAtUtc)
            if ($commandResult.FailureKind -ceq 'RuntimeMismatch' -and
                -not $hasCommandMismatchEvidence) {
                $commandResult.FailureKind = 'TransportFailure'
                $commandResult.OutcomeStatus = if ($commandResult.DispatchState -cin @(
                        'Dispatched', 'DispatchUncertain'
                    )) {
                    'Unknown'
                }
                else {
                    'Failed'
                }
            }
            if ($cleanupFailureEventByName.ContainsKey($selectedTarget.Name)) {
                $commandResult.StreamEvents = @($commandResult.StreamEvents) + @(
                    $cleanupFailureEventByName[$selectedTarget.Name]
                )
                if ($commandResult.Succeeded) {
                    $commandResult.Succeeded = $false
                    $commandResult.FailureKind = 'TransportFailure'
                    $commandResult.ExceptionType = $cleanupFailureEventByName[
                        $selectedTarget.Name
                    ].TypeName
                    $commandResult.OutcomeStatus = 'Failed'
                }
            }
            $transportResult = [pscustomobject]@{
                Succeeded = $commandResult.Succeeded
                FailureKind = $commandResult.FailureKind
                ValidatedAtUtc = if ($hasCommandMismatchEvidence) {
                    $commandResult.ValidatedAtUtc
                }
                elseif ($null -eq $sessionByName[$selectedTarget.Name]) {
                    $null
                }
                else {
                    $sessionByName[$selectedTarget.Name].ValidatedAtUtc
                }
                RemotePowerShellVersion = if ($hasCommandMismatchEvidence) {
                    $commandResult.RemotePowerShellVersion
                }
                elseif ($null -eq $sessionByName[$selectedTarget.Name]) {
                    $null
                }
                else {
                    $sessionByName[$selectedTarget.Name].RemotePowerShellVersion
                }
                RemotePSEdition = if ($hasCommandMismatchEvidence) {
                    $commandResult.RemotePSEdition
                }
                elseif ($null -eq $sessionByName[$selectedTarget.Name]) {
                    $null
                }
                else {
                    $sessionByName[$selectedTarget.Name].RemotePSEdition
                }
                ExecutionMode = if ($hasCommandMismatchEvidence) {
                    $commandResult.ExecutionMode
                }
                elseif ($null -eq $sessionByName[$selectedTarget.Name]) {
                    $null
                }
                else {
                    $sessionByName[$selectedTarget.Name].ExecutionMode
                }
                RemoteIdentity = if ($hasCommandMismatchEvidence) {
                    $commandResult.RemoteIdentity
                }
                elseif ($null -eq $sessionByName[$selectedTarget.Name]) {
                    $null
                }
                else {
                    $sessionByName[$selectedTarget.Name].Identity
                }
                HostKeyFingerprint = if ($hasCommandMismatchEvidence -and
                    $null -ne $commandResult.PSObject.Properties['HostKeyFingerprint'] -and
                    -not [string]::IsNullOrWhiteSpace(
                        [string] $commandResult.HostKeyFingerprint
                    )) {
                    $commandResult.HostKeyFingerprint
                }
                elseif ($hasCommandMismatchEvidence -and
                    $null -ne $sessionByName[$selectedTarget.Name]) {
                    $sessionByName[$selectedTarget.Name].HostKeyFingerprint
                }
                elseif ($null -eq $sessionByName[$selectedTarget.Name]) {
                    $null
                }
                else {
                    $sessionByName[$selectedTarget.Name].HostKeyFingerprint
                }
                StreamEvents = $commandResult.StreamEvents
                OutputBytes = $commandResult.OutputBytes
                ExceptionType = $commandResult.ExceptionType
                SessionRemovalFailure = $cleanupFailureEventByName.ContainsKey(
                    $selectedTarget.Name
                )
                DispatchState = $commandResult.DispatchState
                OutcomeStatus = $commandResult.OutcomeStatus
            }
            Complete-HHAuthenticatedTransportAudit -Context $context `
                -Intent $intentByName[$selectedTarget.Name] `
                -TransportResult $transportResult `
                -ArmedOrdinal $armedOrdinalByName[$selectedTarget.Name].ToArray() `
                -ArtifactWriter $artifactWriterByName[$selectedTarget.Name] | Out-Null
            [pscustomobject]@{
                BatchId = $batchId
                InvocationId = $intentByName[$selectedTarget.Name].InvocationId
                Target = $selectedTarget.Name
                PowerShellRuntime = $selectedTarget.PowerShellRuntime
                Succeeded = $commandResult.Succeeded
                FailureKind = $commandResult.FailureKind
                DispatchState = $commandResult.DispatchState
                OutcomeStatus = $commandResult.OutcomeStatus
                RemotePowerShellVersion = $transportResult.RemotePowerShellVersion
                RemotePSEdition = $transportResult.RemotePSEdition
                ExecutionMode = $transportResult.ExecutionMode
                HostKeyFingerprint = $transportResult.HostKeyFingerprint
                OutputBytes = $commandResult.OutputBytes
                ExceptionType = $commandResult.ExceptionType
                SessionRemovalFailure = $transportResult.SessionRemovalFailure
                StreamEvents = $commandResult.StreamEvents
            }
        }
    )
    }
    finally {
        foreach ($writer in $artifactWriterByName.Values) {
            if ($null -ne $writer) { Abort-HHAuditArtifactV2Writer -Writer $writer | Out-Null }
        }
        if ($null -ne $capacityReservation) {
            Remove-HHPersistenceCapacityReservation -Reservation $capacityReservation
        }
        Close-HHAuthenticatedPersistence -Context $context
    }
}
