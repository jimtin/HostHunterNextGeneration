# This file owns every controller-to-managed-host operation. Public cmdlets
# validate their public parameters and cross this boundary exactly once.

function Invoke-HHManagedHostOperation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet(
            'ValidateTarget',
            'TestTarget',
            'InvokeCommand',
            'EnableSshKeyAuthentication',
            'SetWindowsProcessAuditPolicy'
        )]
        [string]$Operation,

        [Parameter(Mandatory)]
        [Collections.IDictionary]$Arguments
    )

    switch ($Operation) {
        'ValidateTarget' {
            return Invoke-HHManagedHostValidateTargetOperation @Arguments
        }
        'TestTarget' {
            return Invoke-HHManagedHostTestTargetOperation @Arguments
        }
        'InvokeCommand' {
            return Invoke-HHManagedHostInvokeCommandOperation @Arguments
        }
        'EnableSshKeyAuthentication' {
            return Invoke-HHManagedHostEnableSshKeyAuthenticationOperation @Arguments
        }
        'SetWindowsProcessAuditPolicy' {
            return Invoke-HHManagedHostSetWindowsProcessAuditPolicyOperation @Arguments
        }
        default {
            throw [ArgumentOutOfRangeException]::new(
                'Operation',
                $Operation,
                'Unsupported managed-host operation.'
            )
        }
    }
}

function Assert-HHManagedTargetSupported {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object[]]$Target)

    foreach ($item in $Target) {
        if ([string]$item.Transport -cne 'SSH' -or
            [string]$item.PowerShellRuntime -cne 'PowerShell7') {
            $message = "Target '$($item.Name)' uses a historical transport or " +
                'runtime profile. It may be inspected or removed, but managed-host ' +
                'dispatch supports only SSH with PowerShell 7.'
            throw $message
        }
    }
}

function Invoke-HHManagedHostValidateTargetOperation {
    <#
    .SYNOPSIS
    Validates and atomically saves one or more PowerShell remoting targets.
    .DESCRIPTION
    SSH targets use an interactive native password prompt by default. Supply an
    explicit SHA256 host-key fingerprint on first trust. The active set is
    replaced unless Add is specified.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium', DefaultParameterSetName = 'Properties')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Properties')]
        [ValidateCount(1, 8)]
        [string[]]$Name,

        [Parameter(Mandatory, ParameterSetName = 'Properties')]
        [ValidateCount(1, 8)]
        [string[]]$HostName,

        [Parameter(Mandatory, ParameterSetName = 'Properties')]
        [ValidateCount(1, 8)]
        [string[]]$UserName,

        [Parameter(ParameterSetName = 'Properties')]
        [ValidateRange(1, 65535)]
        [int]$Port = 22,

        [Parameter(ParameterSetName = 'Properties')]
        [ValidateSet('Password', 'PublicKey')]
        [string]$Authentication = 'Password',

        [Parameter(ParameterSetName = 'Properties')]
        [string[]]$HostKeyFingerprint,

        [Parameter(ParameterSetName = 'Properties')]
        [string[]]$KeyPath,

        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'Object')]
        [ValidateCount(1, 8)]
        [object[]]$InputObject,

        [switch]$Add,
        [string]$Reason,
        [string]$CaseId
    )

    begin {
        $proposed = [System.Collections.Generic.List[object]]::new()
    }
    process {
        if ($PSCmdlet.ParameterSetName -eq 'Object') {
            foreach ($item in $InputObject) {
                $proposed.Add((ConvertTo-HHProposedTarget -InputObject $item))
            }
        }
        else {
            if ($HostName.Count -ne $Name.Count) {
                throw "HostName must contain $($Name.Count) value(s)."
            }
            for ($index = 0; $index -lt $Name.Count; $index++) {
                $targetInput = [pscustomobject]@{
                    Name = $Name[$index]
                    Transport = 'SSH'
                    HostName = $HostName[$index]
                    Port = $Port
                    UserName = Get-HHInputValue -Value $UserName -Index $index -ExpectedCount $Name.Count -Name UserName
                    Authentication = $Authentication
                    PowerShellRuntime = 'PowerShell7'
                    HostKeyFingerprint = if ($null -eq $HostKeyFingerprint) {
                        $null
                    }
                    else {
                        Get-HHInputValue -Value $HostKeyFingerprint -Index $index -ExpectedCount $Name.Count -Name HostKeyFingerprint
                    }
                    KeyPath = if ($null -eq $KeyPath) {
                        $null
                    }
                    else {
                        Get-HHInputValue -Value $KeyPath -Index $index -ExpectedCount $Name.Count -Name KeyPath
                    }
                }
                $proposed.Add((ConvertTo-HHProposedTarget -InputObject $targetInput))
            }
        }
    }
    end {
        $proposedTargets = @(Assert-HHTargetSet -Target $proposed.ToArray())
        foreach ($target in $proposedTargets) {
            if ($target.Transport -eq 'SSH' -and
                $target.HostKeyFingerprint -notmatch '^SHA256:[A-Za-z0-9+/]{43}$') {
                throw "SSH target '$($target.Name)' requires a complete SHA256 host-key fingerprint."
            }
        }
        $operation = if ($Add) { 'Add validated HostHunter target(s)' } else { 'Replace active HostHunter target set' }
        if (-not $PSCmdlet.ShouldProcess(($proposedTargets.Name -join ', '), $operation)) {
            return
        }

        $runtime = Get-HHRuntimeContext
        $context = Open-HHAuthenticatedPersistence -PersistenceContext $runtime `
            -OperationLock -AllowAnchorAdvance
        $capacityReservation = $null
        try {
            $request = @(
                foreach ($target in $proposedTargets) {
                    [pscustomobject]@{
                        Target = $target
                        CommandText = 'Discover pinned host identity and run HostHunter.PowerShellIdentity.v1 probe'
                        RemoteOperations = @(Get-HHTargetValidationRemoteOperationManifest `
                                -Target $target -IncludeHostTrustDiscovery)
                        Reason = $Reason
                        CaseId = $CaseId
                    }
                }
            )
            $intents = @(Register-HHAuthenticatedAuditBatch -Context $context `
                    -Operation ValidateTarget -Request $request)
            $capacityReservation = Start-HHAuthenticatedAuditCapacityReservation `
                -Context $context -Intent $intents
            $intentByName = @{}
            for ($intentIndex = 0; $intentIndex -lt $intents.Count; $intentIndex++) {
                $intentByName[$request[$intentIndex].Target.Name] = $intents[$intentIndex]
            }

            $validated = [Collections.Generic.List[object]]::new()
            $terminalTargetNames = [Collections.Generic.HashSet[string]]::new(
                [StringComparer]::OrdinalIgnoreCase
            )
            $armedOrdinalByName = @{}
            try {
                foreach ($target in $proposedTargets) {
                    $intent = $intentByName[$target.Name]
                    $armed = [Collections.Generic.List[int]]::new()
                    $armedOrdinalByName[$target.Name] = $armed
                    if ($target.Transport -eq 'SSH') {
                        $trustOrdinal = 0
                        Arm-HHAuthenticatedRemoteOperation -Context $context `
                            -Intent $intent -Ordinal @($trustOrdinal)
                        $armed.Add($trustOrdinal)
                        try {
                            Register-HHSshHostTrust `
                                -HostName $target.HostName `
                                -Port $target.Port `
                                -ExpectedFingerprint $target.HostKeyFingerprint `
                                -KnownHostsPath $runtime.KnownHostsPath `
                                -Confirm:$false | Out-Null
                        }
                        catch {
                            $trustException = $_.Exception
                            $trustEvent = New-HHSshStreamEvent `
                                -InputObject ([string]$trustException.Message) `
                                -Phase HostTrustDiscovery -Sequence 0 -RemoteSequence 0 `
                                -StreamOverride Error `
                                -TypeNameOverride $trustException.GetType().FullName `
                                -IsTerminating $true
                            $trustResult = [pscustomobject][ordered]@{
                                Succeeded = $false
                                FailureKind = Get-HHSshFailureKind -ErrorObject $_
                                DispatchState = 'NotDispatched'
                                OutcomeStatus = 'Failed'
                                RemotePowerShellVersion = $null
                                RemotePSEdition = $null
                                ExecutionMode = $null
                                HostKeyFingerprint = $null
                                StreamEvents = [object[]]@($trustEvent)
                                OutputBytes = [long]$trustEvent.SerializedByteCount
                                ExceptionType = $trustException.GetType().FullName
                                RemoteIdentity = $null
                                ValidatedAtUtc = $null
                                SessionRemovalFailure = $false
                            }
                            Complete-HHAuthenticatedTransportAudit -Context $context `
                                -Intent $intent -TransportResult $trustResult `
                                -ArmedOrdinal $armed.ToArray() | Out-Null
                            $null = $terminalTargetNames.Add($target.Name)
                            throw
                        }
                    }
                    if ($intent.RemoteOperations.Count -gt 1) {
                        $identityOrdinals = @(1..($intent.RemoteOperations.Count - 1))
                        Arm-HHAuthenticatedRemoteOperation -Context $context `
                            -Intent $intent -Ordinal $identityOrdinals
                        foreach ($ordinal in $identityOrdinals) { $armed.Add($ordinal) }
                    }
                    $result = Invoke-HHTargetProbe -Target $target -RuntimeContext $runtime
                    Complete-HHAuthenticatedTransportAudit -Context $context `
                        -Intent $intent -TransportResult $result `
                        -ArmedOrdinal $armed.ToArray() | Out-Null
                    $null = $terminalTargetNames.Add($target.Name)
                    Test-HHTransportResult -Result $result | Out-Null
                    $validated.Add((ConvertTo-HHValidatedProbeTarget `
                                -Target $target -TransportResult $result))
                }
            }
            catch {
                foreach ($target in $proposedTargets) {
                    if (-not $terminalTargetNames.Contains($target.Name) -and
                        (-not $armedOrdinalByName.ContainsKey($target.Name) -or
                            $armedOrdinalByName[$target.Name].Count -eq 0)) {
                        try {
                            Complete-HHAuthenticatedUnstartedAuditIntent -Context $context `
                                -Intent $intentByName[$target.Name] `
                                -Reason TargetBatchValidationAborted
                        }
                        catch {
                            Write-Debug "Unable to record cancellation for '$($target.Name)': $($_.Exception.Message)"
                        }
                    }
                }
                throw
            }
            $arguments = [pscustomobject]@{
                Target = $validated.ToArray()
                ExpectedGeneration = [long]$context.TargetSnapshot.Generation
                Add = [bool]$Add
            }
            Invoke-HHAnchoredPersistenceTransaction -Context $context `
                -ArgumentList @($arguments) -Action {
                param($Connection, $Transaction, $WriterContext, $ArgumentList)
                $inputData = $ArgumentList[0]
                Set-HHTargetRepository -Connection $Connection -Transaction $Transaction `
                    -MasterKey $WriterContext.MasterKey -Target $inputData.Target `
                    -ExpectedGeneration $inputData.ExpectedGeneration `
                    -MutationId ([Guid]::NewGuid().ToByteArray()) `
                    -RequestedAtUtc ([DateTimeOffset]::UtcNow) `
                    -ExpectedAnchor $WriterContext.Anchor -Add:$inputData.Add
            } | Select-Object -ExpandProperty CurrentTargets
        }
        finally {
            if ($null -ne $capacityReservation) {
                Remove-HHPersistenceCapacityReservation -Reservation $capacityReservation
            }
            Close-HHAuthenticatedPersistence -Context $context
        }
    }
}

function Invoke-HHManagedHostTestTargetOperation {
    <#
    .SYNOPSIS
    Revalidates saved targets using an authenticated PowerShell identity probe.
    #>
    [CmdletBinding()]
    param(
        [ValidateCount(1, 8)]
        [string[]]$Name,
        [string]$Reason,
        [string]$CaseId
    )

    $runtime = Get-HHRuntimeContext
    if (-not [IO.File]::Exists($runtime.DatabasePath)) {
        if ($null -ne $Name) { throw "Unknown target(s): $($Name -join ', ')." }
        return @()
    }
    $context = Open-HHAuthenticatedPersistence -PersistenceContext $runtime `
        -OperationLock -AllowAnchorAdvance
    $capacityReservation = $null
    try {
        $parameters = @{
            Connection = $context.Connection
            MasterKey = $context.MasterKey
            ExpectedAnchor = $context.Anchor
        }
        if ($PSBoundParameters.ContainsKey('Name')) { $parameters.Name = $Name }
        $targets = @((Read-HHTargetRepositorySnapshot @parameters).Targets)
        if ($null -ne $Name) {
            $storedNames = @($targets | ForEach-Object Name)
            $missing = @($Name | Where-Object { $_ -notin $storedNames })
            if ($missing.Count -gt 0) { throw "Unknown target(s): $($missing -join ', ')." }
        }
        if ($targets.Count -eq 0) { return @() }
        Assert-HHManagedTargetSupported -Target $targets

        $request = @(
            foreach ($target in $targets) {
                [pscustomobject]@{
                    Target = $target
                    CommandText = 'Run HostHunter.PowerShellIdentity.v1 probe'
                    RemoteOperations = @(Get-HHTargetValidationRemoteOperationManifest -Target $target)
                    Reason = $Reason
                    CaseId = $CaseId
                }
            }
        )
        $registered = @(Register-HHAuthenticatedAuditBatch -Context $context `
                -Operation TestTarget -Request $request)
        $capacityReservation = Start-HHAuthenticatedAuditCapacityReservation `
            -Context $context -Intent $registered
        @(
            for ($index = 0; $index -lt $targets.Count; $index++) {
                $target = $targets[$index]
                $intent = $registered[$index]
                $ordinals = @(0..($intent.RemoteOperations.Count - 1))
                Arm-HHAuthenticatedRemoteOperation -Context $context `
                    -Intent $intent -Ordinal $ordinals
                $result = Invoke-HHTargetProbe -Target $target -RuntimeContext $runtime
                Complete-HHAuthenticatedTransportAudit -Context $context `
                    -Intent $intent -TransportResult $result -ArmedOrdinal $ordinals | Out-Null
                [pscustomobject]@{
                    Name = $target.Name
                    PowerShellRuntime = $target.PowerShellRuntime
                    Succeeded = $result.Succeeded
                    FailureKind = $result.FailureKind
                    DispatchState = $result.DispatchState
                    OutcomeStatus = $result.OutcomeStatus
                    ValidatedAtUtc = $result.ValidatedAtUtc
                    RemotePSEdition = $result.RemotePSEdition
                    RemotePowerShellVersion = $result.RemotePowerShellVersion
                    ExecutionMode = $result.ExecutionMode
                    RemoteIdentity = $result.RemoteIdentity
                    HostKeyFingerprint = $result.HostKeyFingerprint
                    OutputBytes = $result.OutputBytes
                    ExceptionType = $result.ExceptionType
                }
            }
        )
    }
    finally {
        if ($null -ne $capacityReservation) {
            Remove-HHPersistenceCapacityReservation -Reservation $capacityReservation
        }
        Close-HHAuthenticatedPersistence -Context $context
    }
}

function Invoke-HHManagedHostCommandCoordinator {
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
        [string]$CaseId,

        [ValidateSet('InvokeCommand', 'SetWindowsProcessAuditPolicy')]
        [string]$Operation = 'InvokeCommand',

        [scriptblock]$RemoteScriptBlock,

        [AllowEmptyCollection()]
        [object[]]$RemoteArgumentList = @(),

        [scriptblock]$RemoteOperationManifestFactory,

        [scriptblock]$TransportResultAugmenter
    )

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
    Assert-HHManagedTargetSupported -Target $selectedTargets

    $remoteCommand = if ($null -eq $RemoteScriptBlock) {
        {
            param([Parameter(Mandatory)][string]$CommandText)
            $remoteScript = [scriptblock]::Create($CommandText)
            & $remoteScript
        }
    }
    else { $RemoteScriptBlock }
    $remoteArguments = if ($null -eq $RemoteScriptBlock) {
        @($Command)
    }
    else { @($RemoteArgumentList) }

    $request = @(
        foreach ($selectedTarget in $selectedTargets) {
            [pscustomobject]@{
                Target = $selectedTarget
                CommandText = $Command
                RemoteOperations = @(
                    if ($null -eq $RemoteOperationManifestFactory) {
                        Get-HHCommandRemoteOperationManifest `
                            -Target $selectedTarget -ScriptBlock $remoteCommand `
                            -ArgumentList $remoteArguments
                    }
                    else {
                        & $RemoteOperationManifestFactory $selectedTarget $remoteCommand `
                            $remoteArguments
                    }
                )
                Reason = $Reason
                CaseId = $CaseId
            }
        }
    )
    $registered = @(Register-HHAuthenticatedAuditBatch -Context $context `
            -Operation $Operation -Request $request)
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
                -ArgumentList $remoteArguments `
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
            if ($null -ne $TransportResultAugmenter) {
                $augmentedResult = & $TransportResultAugmenter `
                    $selectedTarget $transportResult $commandResult
                if ($null -eq $augmentedResult) {
                    throw 'The transport result augmenter returned no result.'
                }
                $transportResult = $augmentedResult
            }
            Complete-HHAuthenticatedTransportAudit -Context $context `
                -Intent $intentByName[$selectedTarget.Name] `
                -TransportResult $transportResult `
                -ArmedOrdinal $armedOrdinalByName[$selectedTarget.Name].ToArray() `
                -ArtifactWriter $artifactWriterByName[$selectedTarget.Name] | Out-Null
            $publicResult = [pscustomobject]@{
                BatchId = $batchId
                InvocationId = $intentByName[$selectedTarget.Name].InvocationId
                Target = $selectedTarget.Name
                PowerShellRuntime = $selectedTarget.PowerShellRuntime
                Succeeded = $transportResult.Succeeded
                FailureKind = $transportResult.FailureKind
                DispatchState = $transportResult.DispatchState
                OutcomeStatus = $transportResult.OutcomeStatus
                RemotePowerShellVersion = $transportResult.RemotePowerShellVersion
                RemotePSEdition = $transportResult.RemotePSEdition
                ExecutionMode = $transportResult.ExecutionMode
                HostKeyFingerprint = $transportResult.HostKeyFingerprint
                OutputBytes = $commandResult.OutputBytes
                ExceptionType = $transportResult.ExceptionType
                SessionRemovalFailure = $transportResult.SessionRemovalFailure
                StreamEvents = $commandResult.StreamEvents
            }
            $policyOutcomeProperty = $transportResult.PSObject.Properties['PolicyOutcome']
            if ($null -ne $policyOutcomeProperty) {
                $publicResult | Add-Member -NotePropertyName PolicyOutcome `
                    -NotePropertyValue $policyOutcomeProperty.Value
            }
            $publicResult
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

function Invoke-HHManagedHostInvokeCommandOperation {
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

    $parameters = @{
        Command = $Command
        ThrottleLimit = $ThrottleLimit
        Reason = $Reason
        CaseId = $CaseId
    }
    if ($PSBoundParameters.ContainsKey('Target')) { $parameters.Target = $Target }
    Invoke-HHManagedHostCommandCoordinator @parameters
}

function Invoke-HHManagedHostEnableSshKeyAuthenticationOperation {
    <#
    .SYNOPSIS
    Converts a password-authenticated SSH target to a proven Ed25519 key.
    .DESCRIPTION
    Installs one exact marker-tagged key through the password session, proves a
    separate key-only session, and changes the saved profile only after proof.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$Name,
        [string]$KeyPath,
        [switch]$UseExistingKey,
        [string]$Reason,
        [string]$CaseId
    )

    process {
        $runtime = Get-HHRuntimeContext
        if (-not [IO.File]::Exists($runtime.DatabasePath)) { throw "Unknown target '$Name'." }
        $readContext = Open-HHAuthenticatedPersistence -PersistenceContext $runtime
        try {
            $targets = @((Read-HHTargetRepositorySnapshot `
                        -Connection $readContext.Connection `
                        -MasterKey $readContext.MasterKey `
                        -ExpectedAnchor $readContext.Anchor `
                        -Name @($Name)).Targets)
        }
        finally { Close-HHAuthenticatedPersistence -Context $readContext }
        if ($targets.Count -ne 1) { throw "Unknown target '$Name'." }
        $target = $targets[0]
        Assert-HHManagedTargetSupported -Target @($target)
        if ($target.Transport -ne 'SSH' -or $target.Authentication -ne 'Password') {
            throw "Target '$Name' must use SSH password authentication."
        }
        $selectedKeyPath = if ([string]::IsNullOrWhiteSpace($KeyPath)) {
            Join-Path $runtime.KeyRoot 'hosthunter_ed25519'
        }
        else { [IO.Path]::GetFullPath($KeyPath) }

        if (-not $PSCmdlet.ShouldProcess(
                $Name,
                'Install and prove HostHunter SSH key authentication'
            )) {
            New-HHSshKeyBootstrapPlan -Target $target `
                -KnownHostsPath $runtime.KnownHostsPath `
                -KeyPath $selectedKeyPath -UseExistingKey:$UseExistingKey
            return
        }

        $context = Open-HHAuthenticatedPersistence -PersistenceContext $runtime `
            -OperationLock -AllowAnchorAdvance
        $capacityReservation = $null
        try {
            $currentTargets = @((Read-HHTargetRepositorySnapshot `
                        -Connection $context.Connection -MasterKey $context.MasterKey `
                        -ExpectedAnchor $context.Anchor -Name @($Name)).Targets)
            if ($currentTargets.Count -ne 1 -or
                -not (Test-HHTargetRepositoryRecordExactMatch `
                    -ActualTarget $currentTargets[0] -ExpectedTarget $target)) {
                throw 'The saved target changed before SSH key bootstrap began.'
            }
            $prepared = Prepare-HHSshKeyBootstrapOperation -Target $target `
                -KnownHostsPath $runtime.KnownHostsPath -KeyPath $selectedKeyPath `
                -UseExistingKey:$UseExistingKey -Confirm:$false
            try {
                $request = [pscustomobject]@{
                    Target = $target
                    CommandText = "Enable SSH key authentication using $($prepared.Plan.KeyAction)"
                    RemoteOperations = [object[]]$prepared.RemoteOperations
                    Reason = $Reason
                    CaseId = $CaseId
                }
                $intent = @(Register-HHAuthenticatedAuditBatch -Context $context `
                        -Operation EnableSshKeyAuthentication -Request @($request))[0]
                $capacityReservation = Start-HHAuthenticatedAuditCapacityReservation `
                    -Context $context -Intent @($intent)
            }
            catch {
                $intentFailure = $_
                $cleanup = Undo-HHSshKeyBootstrapPreparation `
                    -PreparedOperation $prepared -Confirm:$false
                if ($cleanup.Attempted -and -not $cleanup.Removed) {
                    $intentFailure.Exception.Data['HHLocalKeyCleanupFailureType'] =
                        [string]$cleanup.FailureType
                }
                throw $intentFailure
            }

            $armed = [Collections.Generic.List[int]]::new()
            $operationArmer = {
                param([string[]]$Phase)
                $ordinals = @(
                    for ($index = 0; $index -lt $intent.RemoteOperations.Count; $index++) {
                        if ($intent.RemoteOperations[$index].Phase -cin $Phase -and
                            -not $armed.Contains($index)) {
                            $index
                        }
                    }
                )
                if ($ordinals.Count -gt 0) {
                    Arm-HHAuthenticatedRemoteOperation -Context $context `
                        -Intent $intent -Ordinal $ordinals
                    foreach ($ordinal in $ordinals) { $armed.Add($ordinal) }
                }
            }
            $profileTransitionCommitter = {
                param($transition, $expectedTarget)
                $arguments = [pscustomobject]@{
                    Transition = $transition
                    ExpectedTarget = $expectedTarget
                }
                Invoke-HHAnchoredPersistenceTransaction -Context $context `
                    -ArgumentList @($arguments) -Action {
                    param($Connection, $Transaction, $WriterContext, $ArgumentList)
                    $inputData = $ArgumentList[0]
                    Update-HHTargetRepositoryRecord -Connection $Connection `
                        -Transaction $Transaction -MasterKey $WriterContext.MasterKey `
                        -Target $inputData.Transition `
                        -ExpectedTarget $inputData.ExpectedTarget `
                        -MutationId ([Guid]::NewGuid().ToByteArray()) `
                        -RequestedAtUtc ([DateTimeOffset]::UtcNow) `
                        -ExpectedAnchor $WriterContext.Anchor
                }
            }
            $result = Invoke-HHSshKeyBootstrap -PreparedOperation $prepared `
                -OperationArmer $operationArmer `
                -ProfileTransitionCommitter $profileTransitionCommitter `
                -Confirm:$false
            Complete-HHAuthenticatedTransportAudit -Context $context `
                -Intent $intent -TransportResult $result `
                -ArmedOrdinal $armed.ToArray() | Out-Null
            if (-not $result.Succeeded) {
                throw ('SSH key bootstrap failed ({0}; outcome {1}; commit {2}).' -f
                    $result.FailureKind, $result.OutcomeStatus, $result.CommitState)
            }
            if ($result.CommitState -cne 'Committed' -or
                $null -eq $result.ProfileTransition) {
                throw 'SSH key bootstrap did not return a proven committed profile transition.'
            }
            return $result.ProfileTransition
        }
        finally {
            if ($null -ne $capacityReservation) {
                Remove-HHPersistenceCapacityReservation -Reservation $capacityReservation
            }
            Close-HHAuthenticatedPersistence -Context $context
        }
    }
}

function Invoke-HHManagedHostSetWindowsProcessAuditPolicyOperation {
    <#
    .SYNOPSIS
    Sets effective Windows process-creation or process-termination audit policy.
    .DESCRIPTION
    Uses the Windows audit-policy APIs without auditpol.exe. Process command-line
    logging is an independent, explicit option because it records arguments in
    plaintext in Security event 4688. HostHunter verifies the effective state,
    records exact intent before dispatch, and never retries an uncertain change.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Enabled', 'Disabled')]
        [string]$State,

        [ValidateSet('ProcessCreation', 'ProcessTermination')]
        [ValidateCount(1, 2)]
        [string[]]$Subcategory = @('ProcessCreation'),

        [ValidateSet('Unchanged', 'Enabled', 'Disabled', 'NotConfigured')]
        [string]$CommandLineLogging = 'Unchanged',

        [ValidateCount(1, 8)]
        [string[]]$Target,

        [ValidateRange(1, 8)]
        [int]$ThrottleLimit = 8,

        [switch]$Escalate,

        [ValidateSet('WindowsTokenPrivilege')]
        [string]$EscalationMethod,

        [string]$Reason,
        [string]$CaseId
    )

    $uniqueSubcategories = @($Subcategory | Sort-Object -Unique)
    if ($uniqueSubcategories.Count -ne $Subcategory.Count) {
        throw 'Subcategory cannot contain duplicate values.'
    }
    $includesCreation = $Subcategory -ccontains 'ProcessCreation'
    if ($CommandLineLogging -cne 'Unchanged' -and -not $includesCreation) {
        throw 'CommandLineLogging can be changed only when ProcessCreation is selected.'
    }
    if ($CommandLineLogging -ceq 'Enabled' -and $State -cne 'Enabled') {
        throw 'CommandLineLogging cannot be enabled while ProcessCreation auditing is disabled.'
    }
    if ($PSBoundParameters.ContainsKey('EscalationMethod') -and -not $Escalate) {
        throw 'EscalationMethod requires -Escalate.'
    }

    if ($CommandLineLogging -ceq 'Enabled') {
        Write-Warning (
            'Enabling command-line logging records process arguments in plaintext in ' +
            'Security event 4688. Arguments may contain passwords, tokens, or private ' +
            'data and are readable by users who can read the Security log. Execution ' +
            'will continue.'
        )
    }

    $targetDescription = if ($PSBoundParameters.ContainsKey('Target')) {
        $Target -join ', '
    }
    else { 'all active HostHunter targets' }
    $action = "Set $($Subcategory -join ',') audit state to $State"
    if ($CommandLineLogging -cne 'Unchanged') {
        $action += "; set command-line logging to $CommandLineLogging"
    }
    if (-not $PSCmdlet.ShouldProcess($targetDescription, $action)) { return }

    $resolvedMethod = if (-not $Escalate) {
        'CurrentToken'
    }
    elseif ($PSBoundParameters.ContainsKey('EscalationMethod')) {
        $EscalationMethod
    }
    else {
        [string] (Get-HHManagedHostEscalationPreference).Method
    }
    if ($Escalate -and $resolvedMethod -cne 'WindowsTokenPrivilege') {
        throw "The configured escalation method '$resolvedMethod' is unsupported."
    }

    $policyRequest = New-HHWindowsProcessAuditPolicyRequest `
        -State $State `
        -Subcategory $uniqueSubcategories `
        -CommandLineLogging $CommandLineLogging `
        -EscalationRequested ([bool]$Escalate) `
        -EscalationMethod $resolvedMethod
    $remoteScript = Get-HHWindowsProcessAuditPolicyScriptBlock
    $commandText = (
        'Set-HHWindowsProcessAuditPolicy -State {0} -Subcategory {1} ' +
        '-CommandLineLogging {2} -Escalate:{3} -EscalationMethod {4}'
    ) -f $State, ($uniqueSubcategories -join ','), $CommandLineLogging,
        ([bool]$Escalate).ToString().ToLowerInvariant(), $resolvedMethod

    $manifestFactory = {
        param($SelectedTarget, $ScriptBlock, $ArgumentList)
        Get-HHWindowsProcessAuditRemoteOperationManifest `
            -Target $SelectedTarget `
            -ScriptBlock $ScriptBlock `
            -Request $ArgumentList[0]
    }
    $augmenter = {
        param($SelectedTarget, $TransportResult, $CommandResult)
        $null = $SelectedTarget
        $policyOutcome = Get-HHWindowsProcessAuditPolicyOutcomeFromStreamEvents `
            -StreamEvents @($CommandResult.StreamEvents) `
            -Required ($CommandResult.DispatchState -ceq 'Completed')
        if ($null -ne $policyOutcome) {
            $TransportResult | Add-Member -NotePropertyName PolicyOutcome `
                -NotePropertyValue $policyOutcome
            if (-not [bool]$policyOutcome.Succeeded) {
                $TransportResult.Succeeded = $false
                $TransportResult.FailureKind = 'RemoteCommandFailure'
                $TransportResult.DispatchState = 'Completed'
                $TransportResult.OutcomeStatus = 'Failed'
                $TransportResult.ExceptionType = if (
                    [string]::IsNullOrWhiteSpace([string]$policyOutcome.FailureKind)
                ) { 'HostHunter.WindowsProcessAuditPolicyFailure' }
                else { [string]$policyOutcome.FailureKind }
            }
        }
        return $TransportResult
    }

    $parameters = @{
        Command = $commandText
        ThrottleLimit = $ThrottleLimit
        Reason = $Reason
        CaseId = $CaseId
        Operation = 'SetWindowsProcessAuditPolicy'
        RemoteScriptBlock = $remoteScript
        RemoteArgumentList = @($policyRequest)
        RemoteOperationManifestFactory = $manifestFactory
        TransportResultAugmenter = $augmenter
    }
    if ($PSBoundParameters.ContainsKey('Target')) { $parameters.Target = $Target }
    Invoke-HHManagedHostCommandCoordinator @parameters
}

function Get-HHManagedHostEscalationPreference {
    [CmdletBinding()]
    param()

    $runtime = Get-HHRuntimeContext
    if (-not [IO.File]::Exists($runtime.DatabasePath)) {
        return [pscustomobject][ordered]@{
            Method = 'WindowsTokenPrivilege'
            Scope = 'Global'
            Source = 'BuiltIn'
            IsPersisted = $false
        }
    }

    $context = Open-HHAuthenticatedPersistence -PersistenceContext $runtime
    try {
        Get-HHAuthenticatedEscalationPreference -Context $context
    }
    finally {
        Close-HHAuthenticatedPersistence -Context $context
    }
}
