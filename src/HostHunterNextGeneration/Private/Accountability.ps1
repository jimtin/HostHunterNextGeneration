Set-StrictMode -Version Latest

function Get-HHAuditObjectPropertyState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object] $InputObject,

        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter(Mandatory)]
        [string] $Context,

        [switch] $Optional
    )

    if ($null -eq $InputObject) {
        throw "$Context cannot be null."
    }

    $exists = $false
    $value = $null
    if ($InputObject -is [Collections.IDictionary]) {
        $matchingKeys = @($InputObject.Keys | Where-Object { [string] $_ -ceq $Name })
        if ($matchingKeys.Count -eq 1) {
            $exists = $true
            $value = $InputObject[$matchingKeys[0]]
        }
    }
    else {
        $matchingProperties = @(
            $InputObject.PSObject.Properties |
                Where-Object { $_.Name -ceq $Name -and $_.IsGettable }
        )
        if ($matchingProperties.Count -eq 1) {
            $exists = $true
            $value = $matchingProperties[0].Value
        }
    }

    if (-not $exists -and -not $Optional) {
        throw "$Context property '$Name' is required."
    }
    return [pscustomobject]@{
        Exists = $exists
        Value = $value
    }
}
function ConvertTo-HHCanonicalRemoteOperationManifest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $RemoteOperations
    )

    if ($RemoteOperations.Count -eq 0) {
        throw 'At least one exact remote operation is required for an audit intent.'
    }
    if ($RemoteOperations.Count -gt 64) {
        throw 'An audit intent cannot contain more than 64 remote operations.'
    }

    $requiredNames = @(
        'Phase',
        'PowerShellRuntime',
        'ScriptText',
        'SerializedArguments',
        'Conditional'
    )
    $supportedPhases = @(
        'HostTrustDiscovery',
        'OuterIdentity',
        'RuntimeIdentity',
        'Command',
        'BootstrapInstall',
        'BootstrapReconcile',
        'BootstrapKeyOnlyOuterIdentity',
        'BootstrapKeyOnlyRuntimeIdentity',
        'BootstrapRollback',
        'ProcessAuditPolicyMutation'
    )
    $canonicalOperations = [Collections.Generic.List[object]]::new()
    for ($index = 0; $index -lt $RemoteOperations.Count; $index++) {
        $operation = $RemoteOperations[$index]
        $actualNames = if ($operation -is [Collections.IDictionary]) {
            @($operation.Keys | ForEach-Object { [string] $_ })
        }
        else {
            @(
                $operation.PSObject.Properties |
                    Where-Object IsGettable |
                    ForEach-Object Name
            )
        }
        $missingNames = @($requiredNames | Where-Object { $_ -cnotin $actualNames })
        $extraNames = @($actualNames | Where-Object { $_ -cnotin $requiredNames })
        if ($missingNames.Count -gt 0 -or $extraNames.Count -gt 0 -or
            $actualNames.Count -ne $requiredNames.Count) {
            throw "Remote operation manifest entry $index must contain exactly: $($requiredNames -join ', ')."
        }

        $context = "Remote operation manifest entry $index"
        $phase = (Get-HHAuditObjectPropertyState `
                -InputObject $operation `
                -Name Phase `
                -Context $context).Value
        $runtime = (Get-HHAuditObjectPropertyState `
                -InputObject $operation `
                -Name PowerShellRuntime `
                -Context $context).Value
        $scriptText = (Get-HHAuditObjectPropertyState `
                -InputObject $operation `
                -Name ScriptText `
                -Context $context).Value
        $serializedArguments = (Get-HHAuditObjectPropertyState `
                -InputObject $operation `
                -Name SerializedArguments `
                -Context $context).Value
        $conditional = (Get-HHAuditObjectPropertyState `
                -InputObject $operation `
                -Name Conditional `
                -Context $context).Value

        if ($phase -isnot [string] -or $phase -cnotin $supportedPhases) {
            throw "$context Phase is unsupported."
        }
        if ($runtime -isnot [string] -or
            $runtime -cnotin @('PowerShell7', 'WindowsPowerShell51')) {
            throw "$context PowerShellRuntime is unsupported."
        }
        if ($scriptText -isnot [string] -or [string]::IsNullOrWhiteSpace($scriptText)) {
            throw "$context ScriptText must be a nonempty string."
        }
        if ($serializedArguments -isnot [string] -or
            [string]::IsNullOrWhiteSpace($serializedArguments)) {
            throw "$context SerializedArguments must be a nonempty string."
        }
        if ($conditional -isnot [bool]) {
            throw "$context Conditional must be Boolean."
        }

        $canonicalOperations.Add([pscustomobject][ordered]@{
                Phase = $phase
                PowerShellRuntime = $runtime
                ScriptText = $scriptText
                SerializedArguments = $serializedArguments
                Conditional = [bool] $conditional
            })
    }
    return [object[]] $canonicalOperations
}

function Get-HHAuditIntentTransportContext {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object] $Intent)

    $recordState = Get-HHAuditObjectPropertyState `
        -InputObject $Intent `
        -Name IntentRecord `
        -Context 'Audit intent'
    $payloadState = Get-HHAuditObjectPropertyState `
        -InputObject $recordState.Value `
        -Name payload `
        -Context 'Audit intent record'
    $runtimeState = Get-HHAuditObjectPropertyState `
        -InputObject $payloadState.Value `
        -Name requestedPowerShellRuntime `
        -Context 'Audit intent payload'
    $fingerprintState = Get-HHAuditObjectPropertyState `
        -InputObject $payloadState.Value `
        -Name expectedHostKeyFingerprint `
        -Context 'Audit intent payload'
    $operationState = Get-HHAuditObjectPropertyState `
        -InputObject $payloadState.Value `
        -Name operation `
        -Context 'Audit intent payload'

    $directRuntimeState = Get-HHAuditObjectPropertyState `
        -InputObject $Intent `
        -Name RequestedPowerShellRuntime `
        -Context 'Audit intent' `
        -Optional
    $directFingerprintState = Get-HHAuditObjectPropertyState `
        -InputObject $Intent `
        -Name ExpectedHostKeyFingerprint `
        -Context 'Audit intent' `
        -Optional
    if (($directRuntimeState.Exists -and
            [string] $directRuntimeState.Value -cne [string] $runtimeState.Value) -or
        ($directFingerprintState.Exists -and
            [string] $directFingerprintState.Value -cne [string] $fingerprintState.Value)) {
        throw 'Audit intent convenience metadata contradicts the persisted intent payload.'
    }

    $runtime = [string] $runtimeState.Value
    if ($runtime -cnotin @('PowerShell7', 'WindowsPowerShell51')) {
        throw 'Audit intent requested PowerShell runtime is invalid.'
    }
    $operation = $operationState.Value
    if ($operation -isnot [string] -or [string]::IsNullOrWhiteSpace($operation)) {
        throw 'Audit intent operation is invalid.'
    }
    $fingerprint = $fingerprintState.Value
    $isFirstTrust = $operation -ceq 'ValidateTarget' -and
        ($null -eq $fingerprint -or [string]::IsNullOrWhiteSpace([string]$fingerprint))
    if (-not $isFirstTrust -and
        ($fingerprint -isnot [string] -or
            $fingerprint -cnotmatch '^SHA256:[A-Za-z0-9+/]{43}$')) {
        throw 'Audit intent expected SSH host fingerprint is invalid.'
    }
    return [pscustomobject]@{
        Operation = $operation
        RequestedPowerShellRuntime = $runtime
        ExpectedHostKeyFingerprint = if ($isFirstTrust) { $null } else { $fingerprint }
    }
}

function Get-HHTransportAuditBootstrapOutcome {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object] $TransportResult,
        [Parameter(Mandatory)][object] $IntentMetadata
    )

    $propertyNames = @(
        'Installed',
        'RollbackAttempted',
        'RollbackSucceeded',
        'ReconciliationRequired',
        'CommitState'
    )
    $propertyStates = [ordered]@{}
    foreach ($name in $propertyNames) {
        $propertyStates[$name] = Get-HHAuditObjectPropertyState `
            -InputObject $TransportResult `
            -Name $name `
            -Context 'Transport result' `
            -Optional
    }
    $presentCount = @($propertyStates.Values | Where-Object Exists).Count
    $isBootstrapIntent = $IntentMetadata.Operation -ceq 'EnableSshKeyAuthentication'
    if (($isBootstrapIntent -or $presentCount -gt 0) -and
        $presentCount -ne $propertyNames.Count) {
        throw (
            'Transport result bootstrap outcome requires all properties: {0}.' -f
            ($propertyNames -join ', ')
        )
    }
    if ($presentCount -eq 0) {
        return [pscustomobject]@{
            HasOutcome = $false
            Installed = $null
            RollbackAttempted = $null
            RollbackSucceeded = $null
            ReconciliationRequired = $null
            CommitState = $null
        }
    }

    $installed = $propertyStates.Installed.Value
    $rollbackAttempted = $propertyStates.RollbackAttempted.Value
    $rollbackSucceeded = $propertyStates.RollbackSucceeded.Value
    $reconciliationRequired = $propertyStates.ReconciliationRequired.Value
    $commitState = $propertyStates.CommitState.Value
    if ($null -ne $installed -and $installed -isnot [bool]) {
        throw "Transport result property 'Installed' must be Boolean or null."
    }
    if ($rollbackAttempted -isnot [bool]) {
        throw "Transport result property 'RollbackAttempted' must be Boolean."
    }
    if ($null -ne $rollbackSucceeded -and $rollbackSucceeded -isnot [bool]) {
        throw "Transport result property 'RollbackSucceeded' must be Boolean or null."
    }
    if ($reconciliationRequired -isnot [bool]) {
        throw "Transport result property 'ReconciliationRequired' must be Boolean."
    }
    if ($commitState -isnot [string] -or
        $commitState -cnotin @('NotRequested', 'Committed', 'Failed', 'Unknown')) {
        throw "Transport result property 'CommitState' is unsupported."
    }
    if (-not [bool] $rollbackAttempted -and $null -ne $rollbackSucceeded) {
        throw 'Transport result rollback outcome exists without a rollback attempt.'
    }
    if ($commitState -ceq 'Unknown' -and -not [bool] $reconciliationRequired) {
        throw 'An Unknown bootstrap commit state requires reconciliation.'
    }

    return [pscustomobject]@{
        HasOutcome = $true
        Installed = $installed
        RollbackAttempted = [bool] $rollbackAttempted
        RollbackSucceeded = $rollbackSucceeded
        ReconciliationRequired = [bool] $reconciliationRequired
        CommitState = $commitState
    }
}

function Get-HHTransportAuditPolicyOutcome {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$TransportResult,
        [Parameter(Mandatory)][object]$IntentMetadata,
        [Parameter(Mandatory)][string]$DispatchState
    )

    $state = Get-HHAuditObjectPropertyState -InputObject $TransportResult `
        -Name PolicyOutcome -Context 'Transport result' -Optional
    $isPolicyIntent =
        $IntentMetadata.Operation -ceq 'SetWindowsProcessAuditPolicy'
    if (-not $state.Exists) {
        if ($isPolicyIntent -and $DispatchState -ceq 'Completed') {
            throw 'A completed process audit policy operation requires a policy outcome.'
        }
        return [pscustomobject]@{ HasOutcome = $false; Outcome = $null }
    }
    if (-not $isPolicyIntent) {
        throw 'A process audit policy outcome is valid only for its matching operation.'
    }
    $outcome = $state.Value
    if ($null -eq $outcome -or
        -not (Test-HHWindowsProcessAuditPolicyOutcome -Outcome $outcome)) {
        throw 'Transport result supplied an invalid process audit policy outcome.'
    }
    foreach ($name in @(
            'Succeeded', 'Changed', 'ConflictDetected', 'ReconciliationRequired',
            'EscalationRequested', 'PrivilegeActivated', 'PrivilegeChanged'
        )) {
        if ($outcome.$name -isnot [bool]) {
            throw "Process audit policy outcome property '$name' must be Boolean."
        }
    }
    if ($null -ne $outcome.PrivilegeRestored -and
        $outcome.PrivilegeRestored -isnot [bool]) {
        throw "Process audit policy outcome property 'PrivilegeRestored' must be Boolean or null."
    }
    if ([string]$outcome.RequiredPrivilege -cne 'SeSecurityPrivilege') {
        throw 'Process audit policy outcome supplied an unsupported privilege.'
    }
    if ([bool]$outcome.EscalationRequested) {
        if ([string]$outcome.EscalationMethod -cne 'WindowsTokenPrivilege') {
            throw 'Escalated process audit policy outcome supplied an unsupported method.'
        }
    }
    elseif ($null -ne $outcome.EscalationMethod) {
        throw 'A non-escalated process audit policy outcome cannot contain an escalation method.'
    }
    if ([bool]$outcome.ReconciliationRequired -and [bool]$outcome.Succeeded) {
        throw 'A process audit policy outcome requiring reconciliation cannot succeed.'
    }
    return [pscustomobject]@{ HasOutcome = $true; Outcome = $outcome }
}

function Assert-HHAuditRemoteIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object] $Identity,
        [Parameter(Mandatory)][string] $RemotePSEdition,
        [Parameter(Mandatory)][string] $PowerShellVersion
    )

    $identityValues = [ordered]@{}
    foreach ($name in @(
            'Marker',
            'PSEdition',
            'PowerShellVersion',
            'ProcessPath',
            'UserName',
            'MachineName'
        )) {
        $value = (Get-HHAuditObjectPropertyState `
                -InputObject $Identity `
                -Name $name `
                -Context 'Transport result RemoteIdentity').Value
        if ($value -isnot [string] -or [string]::IsNullOrWhiteSpace($value)) {
            throw "Transport result RemoteIdentity property '$name' must be a nonempty string."
        }
        $identityValues[$name] = $value
    }
    if ($identityValues.Marker -cne 'HostHunter.PowerShellIdentity.v1' -or
        $identityValues.PSEdition -cne $RemotePSEdition -or
        $identityValues.PowerShellVersion -cne $PowerShellVersion) {
        throw 'Transport result RemoteIdentity contradicts observed runtime metadata.'
    }
    $processLeaf = @([string] $identityValues.ProcessPath -split '[\\/]')[-1]
    $processName = [IO.Path]::GetFileNameWithoutExtension($processLeaf)
    $expectedProcess = switch ($RemotePSEdition) {
        'Core' { 'pwsh' }
        'Desktop' { 'powershell' }
        default {
            throw 'Transport result RemoteIdentity supplied an unsupported PowerShell edition.'
        }
    }
    if ($processName -cne $expectedProcess) {
        throw 'Transport result RemoteIdentity process contradicts observed runtime metadata.'
    }
}

function Assert-HHTransportAuditResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object] $TransportResult,
        [Parameter(Mandatory)][object] $IntentMetadata
    )

    $requiredNames = @(
        'Succeeded',
        'FailureKind',
        'DispatchState',
        'OutcomeStatus',
        'RemotePowerShellVersion',
        'RemotePSEdition',
        'ExecutionMode',
        'HostKeyFingerprint',
        'StreamEvents',
        'OutputBytes',
        'ExceptionType',
        'RemoteIdentity',
        'ValidatedAtUtc'
    )
    $values = @{}
    foreach ($name in $requiredNames) {
        $values[$name] = (Get-HHAuditObjectPropertyState `
                -InputObject $TransportResult `
                -Name $name `
                -Context 'Transport result').Value
    }

    if ($values.Succeeded -isnot [bool]) {
        throw "Transport result property 'Succeeded' must be Boolean."
    }
    $succeeded = [bool] $values.Succeeded
    $allowedFailureKinds = @(
        'TrustFailure',
        'AuthenticationFailure',
        'Timeout',
        'SubsystemFailure',
        'RuntimeMismatch',
        'RuntimeUnavailable',
        'TransportFailure',
        'RemoteCommandFailure',
        'OutputLimitExceeded'
    )
    $failureKind = $values.FailureKind
    if ($succeeded) {
        if ($null -ne $failureKind) {
            throw 'A successful transport result cannot contain FailureKind.'
        }
    }
    elseif ($failureKind -isnot [string] -or
        [string]::IsNullOrWhiteSpace($failureKind) -or
        $failureKind -cnotin $allowedFailureKinds) {
        throw 'A failed transport result requires a supported nonempty FailureKind.'
    }

    $dispatchState = $values.DispatchState
    if ($dispatchState -isnot [string] -or
        $dispatchState -cnotin @('NotDispatched', 'Dispatched', 'DispatchUncertain', 'Completed')) {
        throw "Transport result supplied unsupported dispatch state '$dispatchState'."
    }
    $outcomeStatus = $values.OutcomeStatus
    if ($outcomeStatus -isnot [string] -or
        $outcomeStatus -cnotin @('Succeeded', 'Failed', 'Unknown')) {
        throw "Transport result supplied unsupported outcome status '$outcomeStatus'."
    }
    $bootstrapOutcome = Get-HHTransportAuditBootstrapOutcome `
        -TransportResult $TransportResult `
        -IntentMetadata $IntentMetadata
    $policyOutcome = Get-HHTransportAuditPolicyOutcome `
        -TransportResult $TransportResult `
        -IntentMetadata $IntentMetadata `
        -DispatchState $dispatchState
    if ($policyOutcome.HasOutcome -and
        [bool]$policyOutcome.Outcome.Succeeded -ne $succeeded) {
        throw 'Transport success contradicts the process audit policy outcome.'
    }
    if ($bootstrapOutcome.HasOutcome) {
        if ($bootstrapOutcome.CommitState -ceq 'Unknown' -and
            $outcomeStatus -cne 'Unknown') {
            throw 'An Unknown bootstrap commit state requires an Unknown aggregate outcome.'
        }
        $isSuccessfulExistingKeyProof =
            $IntentMetadata.Operation -ceq 'EnableSshKeyAuthentication' -and
            $bootstrapOutcome.Installed -is [bool] -and
            -not [bool]$bootstrapOutcome.Installed -and
            -not $bootstrapOutcome.RollbackAttempted -and
            $null -eq $bootstrapOutcome.RollbackSucceeded -and
            -not $bootstrapOutcome.ReconciliationRequired -and
            $bootstrapOutcome.CommitState -ceq 'NotRequested'
        if ($succeeded -and
            -not $isSuccessfulExistingKeyProof -and
            ($bootstrapOutcome.CommitState -cne 'Committed' -or
                $bootstrapOutcome.ReconciliationRequired)) {
            throw 'A successful SSH key bootstrap requires a committed, reconciled profile transition.'
        }
    }

    if ($succeeded) {
        if ($outcomeStatus -cne 'Succeeded' -or
            $dispatchState -cnotin @('NotDispatched', 'Completed')) {
            throw 'Successful transport result dispatch and outcome metadata is inconsistent.'
        }
    }
    else {
        if ($outcomeStatus -ceq 'Succeeded') {
            throw 'A failed transport result cannot have a Succeeded outcome.'
        }
        if (($outcomeStatus -ceq 'Unknown' -and
                $dispatchState -cnotin @('Dispatched', 'DispatchUncertain', 'Completed')) -or
            ($outcomeStatus -ceq 'Failed' -and $dispatchState -ceq 'DispatchUncertain')) {
            throw 'Failed transport result dispatch and outcome metadata is inconsistent.'
        }
        if ($outcomeStatus -ceq 'Unknown' -and
            $failureKind -cnotin @('Timeout', 'TransportFailure')) {
            throw 'Only timeout or transport failures can have an Unknown outcome.'
        }
        if ($outcomeStatus -ceq 'Unknown' -and
            $dispatchState -ceq 'Completed' -and
            $failureKind -cne 'TransportFailure') {
            throw 'Only a transport failure can have a completed remote operation and Unknown aggregate outcome.'
        }
        $isCompletedBootstrapRuntimeMismatch =
            $failureKind -ceq 'RuntimeMismatch' -and
            $dispatchState -ceq 'Completed' -and
            $outcomeStatus -ceq 'Failed'
        if ($isCompletedBootstrapRuntimeMismatch) {
            $isCompensatedMutation =
                $IntentMetadata.Operation -ceq 'EnableSshKeyAuthentication' -and
                $bootstrapOutcome.HasOutcome -and
                $bootstrapOutcome.Installed -is [bool] -and
                [bool] $bootstrapOutcome.Installed -and
                $bootstrapOutcome.RollbackAttempted -and
                $bootstrapOutcome.RollbackSucceeded -is [bool] -and
                [bool] $bootstrapOutcome.RollbackSucceeded -and
                -not $bootstrapOutcome.ReconciliationRequired -and
                $bootstrapOutcome.CommitState -ceq 'NotRequested'
            $isCompletedWithoutMutation =
                $IntentMetadata.Operation -ceq 'EnableSshKeyAuthentication' -and
                $bootstrapOutcome.HasOutcome -and
                $bootstrapOutcome.Installed -is [bool] -and
                -not [bool] $bootstrapOutcome.Installed -and
                -not $bootstrapOutcome.RollbackAttempted -and
                $null -eq $bootstrapOutcome.RollbackSucceeded -and
                -not $bootstrapOutcome.ReconciliationRequired -and
                $bootstrapOutcome.CommitState -ceq 'NotRequested'
            if (-not $isCompensatedMutation -and -not $isCompletedWithoutMutation) {
                throw (
                    'A completed RuntimeMismatch is permitted only for a proven ' +
                    'compensated or non-mutating SSH key bootstrap.'
                )
            }
        }
        switch ($failureKind) {
            { $_ -cin @(
                    'TrustFailure',
                    'AuthenticationFailure',
                    'SubsystemFailure',
                    'RuntimeUnavailable'
                ) } {
                if ($dispatchState -cne 'NotDispatched' -or $outcomeStatus -cne 'Failed') {
                    throw "FailureKind '$failureKind' must fail before dispatch."
                }
            }
            'RuntimeMismatch' {
                if (-not $isCompletedBootstrapRuntimeMismatch -and
                    ($dispatchState -cne 'NotDispatched' -or $outcomeStatus -cne 'Failed')) {
                    throw "FailureKind '$failureKind' must fail before dispatch."
                }
            }
            'RemoteCommandFailure' {
                if ($dispatchState -cne 'Completed' -or $outcomeStatus -cne 'Failed') {
                    throw 'RemoteCommandFailure requires a completed failed outcome.'
                }
            }
            'OutputLimitExceeded' {
                if ($dispatchState -cnotin @('NotDispatched', 'Dispatched') -or
                    $outcomeStatus -cne 'Failed') {
                    throw 'OutputLimitExceeded dispatch and outcome metadata is inconsistent.'
                }
            }
        }
    }

    if ($null -eq $values.StreamEvents -or
        $values.StreamEvents -isnot [Collections.IList]) {
        throw "Transport result property 'StreamEvents' must be a finite list."
    }
    $streamEvents = @($values.StreamEvents)
    if (@($streamEvents | Where-Object { $null -eq $_ }).Count -gt 0) {
        throw "Transport result property 'StreamEvents' cannot contain null entries."
    }
    if (($values.OutputBytes -isnot [int]) -and ($values.OutputBytes -isnot [long])) {
        throw "Transport result property 'OutputBytes' must be an integer."
    }
    $outputBytes = [long] $values.OutputBytes
    if ($outputBytes -lt 0) {
        throw "Transport result property 'OutputBytes' cannot be negative."
    }

    $exceptionType = $values.ExceptionType
    if ($succeeded) {
        if ($null -ne $exceptionType) {
            throw 'A successful transport result cannot contain ExceptionType.'
        }
    }
    elseif ($exceptionType -isnot [string] -or [string]::IsNullOrWhiteSpace($exceptionType)) {
        throw 'A failed transport result requires a nonempty ExceptionType.'
    }

    $cleanupState = Get-HHAuditObjectPropertyState `
        -InputObject $TransportResult `
        -Name SessionRemovalFailure `
        -Context 'Transport result' `
        -Optional
    if ($cleanupState.Exists -and $cleanupState.Value -isnot [bool]) {
        throw "Transport result property 'SessionRemovalFailure' must be Boolean when present."
    }
    if ($succeeded -and $cleanupState.Exists -and [bool] $cleanupState.Value) {
        throw 'A transport result with a session cleanup failure cannot be successful.'
    }

    $runtimeValues = @(
        $values.RemotePowerShellVersion,
        $values.RemotePSEdition,
        $values.ExecutionMode,
        $values.RemoteIdentity,
        $values.ValidatedAtUtc
    )
    foreach ($runtimeString in @(
            $values.RemotePowerShellVersion,
            $values.RemotePSEdition,
            $values.ExecutionMode
        )) {
        if ($null -ne $runtimeString -and
            ($runtimeString -isnot [string] -or [string]::IsNullOrWhiteSpace($runtimeString))) {
            throw 'Observed runtime string metadata must be null or a nonempty string.'
        }
    }
    if ($null -ne $values.ValidatedAtUtc -and
        $values.ValidatedAtUtc -is [string] -and
        [string]::IsNullOrWhiteSpace($values.ValidatedAtUtc)) {
        throw "Transport result property 'ValidatedAtUtc' cannot be blank."
    }
    $observedValueCount = @($runtimeValues | Where-Object { $null -ne $_ }).Count
    if ($observedValueCount -notin @(0, $runtimeValues.Count)) {
        throw 'Transport result observed runtime metadata must be entirely present or entirely null.'
    }
    $hasObservedRuntime = $observedValueCount -eq $runtimeValues.Count
    $cleanupFailed = $cleanupState.Exists -and [bool] $cleanupState.Value
    if (-not $hasObservedRuntime -and
        ($succeeded -or $dispatchState -cne 'NotDispatched' -or $cleanupFailed)) {
        throw 'The transport result requires complete observed runtime metadata.'
    }

    $fingerprint = $values.HostKeyFingerprint
    if ($hasObservedRuntime) {
        $expectedFingerprint = $IntentMetadata.ExpectedHostKeyFingerprint
        $fingerprintMismatch = -not [string]::IsNullOrWhiteSpace([string]$expectedFingerprint) -and
            $fingerprint -cne $expectedFingerprint
        if ($fingerprint -isnot [string] -or
            $fingerprint -cnotmatch '^SHA256:[A-Za-z0-9+/]{43}$' -or
            $fingerprintMismatch) {
            throw 'Transport result observed SSH host fingerprint is missing, invalid, or contradicts the intent.'
        }
    }
    elseif ($null -ne $fingerprint) {
        throw 'Transport result observed SSH host fingerprint must be null before identity evidence exists.'
    }

    $validatedAt = $null
    if ($hasObservedRuntime) {
        $version = $null
        if (-not [version]::TryParse([string] $values.RemotePowerShellVersion, [ref] $version)) {
            throw 'Transport result RemotePowerShellVersion is invalid.'
        }
        $isPowerShell7 = $values.RemotePSEdition -ceq 'Core' -and
            $version.Major -ge 7 -and
            $values.ExecutionMode -ceq 'Direct'
        $isWindowsPowerShell51 = $values.RemotePSEdition -ceq 'Desktop' -and
            $version.Major -eq 5 -and
            $version.Minor -eq 1 -and
            $values.ExecutionMode -ceq 'WindowsPowerShellCompatibility'
        $isRequestedRuntime = if (
            $IntentMetadata.RequestedPowerShellRuntime -ceq 'PowerShell7'
        ) {
            $isPowerShell7
        }
        else {
            $isWindowsPowerShell51
        }
        $isProvenRuntimeMismatch = -not $succeeded -and
            $failureKind -ceq 'RuntimeMismatch'
        if ($isProvenRuntimeMismatch) {
            if ($values.RemotePSEdition -cnotin @('Core', 'Desktop') -or
                $values.ExecutionMode -cnotin @(
                    'Direct',
                    'WindowsPowerShellCompatibility'
                )) {
                throw 'RuntimeMismatch observed runtime metadata is not finite or attributable.'
            }
            if ($isRequestedRuntime) {
                throw 'RuntimeMismatch cannot report an identity satisfying the requested runtime.'
            }
        }
        else {
            if (-not $isPowerShell7 -and -not $isWindowsPowerShell51) {
                throw 'Transport result observed runtime metadata is not a supported runtime mapping.'
            }
            if (-not $isRequestedRuntime) {
                throw 'Transport result observed runtime contradicts the requested runtime.'
            }
        }
        Assert-HHAuditRemoteIdentity `
            -Identity $values.RemoteIdentity `
            -RemotePSEdition $values.RemotePSEdition `
            -PowerShellVersion $values.RemotePowerShellVersion

        $parsedValidatedAt = [DateTimeOffset]::MinValue
        if (-not [DateTimeOffset]::TryParse([string] $values.ValidatedAtUtc, [ref] $parsedValidatedAt)) {
            throw "Transport result property 'ValidatedAtUtc' is invalid."
        }
        $validatedAt = $parsedValidatedAt.ToUniversalTime().ToString('o')
    }
    elseif ($failureKind -ceq 'RuntimeMismatch') {
        throw 'RuntimeMismatch requires complete observed runtime evidence.'
    }

    return [pscustomobject][ordered]@{
        Succeeded = $succeeded
        FailureKind = $failureKind
        DispatchState = $dispatchState
        OutcomeStatus = $outcomeStatus
        RemoteIdentity = $values.RemoteIdentity
        RemotePowerShellVersion = $values.RemotePowerShellVersion
        RemotePSEdition = $values.RemotePSEdition
        ExecutionMode = $values.ExecutionMode
        ValidatedAtUtc = $validatedAt
        HostKeyFingerprint = $fingerprint
        StreamEvents = [object[]] $streamEvents
        OutputBytes = $outputBytes
        ExceptionType = $exceptionType
        SessionRemovalFailure = if ($cleanupState.Exists) {
            [bool] $cleanupState.Value
        }
        else {
            $null
        }
        HasSessionRemovalFailure = $cleanupState.Exists
        HasBootstrapOutcome = $bootstrapOutcome.HasOutcome
        Installed = $bootstrapOutcome.Installed
        RollbackAttempted = $bootstrapOutcome.RollbackAttempted
        RollbackSucceeded = $bootstrapOutcome.RollbackSucceeded
        ReconciliationRequired = $bootstrapOutcome.ReconciliationRequired
        CommitState = $bootstrapOutcome.CommitState
        HasPolicyOutcome = $policyOutcome.HasOutcome
        PolicyOutcome = $policyOutcome.Outcome
    }
}
