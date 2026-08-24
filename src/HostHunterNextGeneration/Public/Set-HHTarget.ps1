function Set-HHTarget {
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
        [ValidateSet('SSH', 'WinRM')]
        [string]$Transport = 'SSH',

        [Parameter(ParameterSetName = 'Properties')]
        [ValidateRange(1, 65535)]
        [int]$Port = 22,

        [Parameter(ParameterSetName = 'Properties')]
        [ValidateSet('Password', 'PublicKey', 'Kerberos', 'Certificate')]
        [string]$Authentication = 'Password',

        [Parameter(ParameterSetName = 'Properties')]
        [ValidateCount(1, 8)]
        [ValidateSet('PowerShell7', 'WindowsPowerShell51')]
        [string[]]$PowerShellRuntime = 'PowerShell7',

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
            $effectivePort = if ($Transport -eq 'WinRM' -and -not $PSBoundParameters.ContainsKey('Port')) {
                5985
            }
            else {
                $Port
            }
            for ($index = 0; $index -lt $Name.Count; $index++) {
                $targetInput = [pscustomobject]@{
                    Name = $Name[$index]
                    Transport = $Transport
                    HostName = $HostName[$index]
                    Port = $effectivePort
                    UserName = Get-HHInputValue -Value $UserName -Index $index -ExpectedCount $Name.Count -Name UserName
                    Authentication = $Authentication
                    PowerShellRuntime = Get-HHInputValue `
                        -Value $PowerShellRuntime `
                        -Index $index `
                        -ExpectedCount $Name.Count `
                        -Name PowerShellRuntime
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
