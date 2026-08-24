function Test-HHTarget {
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
