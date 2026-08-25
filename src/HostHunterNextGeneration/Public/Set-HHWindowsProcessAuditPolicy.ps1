function Set-HHWindowsProcessAuditPolicy {
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
        [string] (Get-HHEscalationPreference).Method
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
    Invoke-HHRemoteCommandCoordinator @parameters
}
