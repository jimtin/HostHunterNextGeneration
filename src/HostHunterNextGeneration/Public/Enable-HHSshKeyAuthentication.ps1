function Enable-HHSshKeyAuthentication {
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
