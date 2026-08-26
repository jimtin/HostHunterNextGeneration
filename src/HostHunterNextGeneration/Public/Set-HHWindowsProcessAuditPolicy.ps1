function Set-HHWindowsProcessAuditPolicy {
    <#
    .SYNOPSIS
    Sets effective Windows process-creation or process-termination audit policy.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSShouldProcess',
        '',
        Justification = 'The public adapter forwards WhatIf and Confirm to the private engine implementation that owns ShouldProcess.'
    )]
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

    Invoke-HHManagedHostOperation -Operation SetWindowsProcessAuditPolicy -Arguments $PSBoundParameters
}
