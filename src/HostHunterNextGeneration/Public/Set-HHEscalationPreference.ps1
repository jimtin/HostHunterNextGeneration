function Set-HHEscalationPreference {
    <#
    .SYNOPSIS
    Saves the default escalation method used by HostHunter.
    .DESCRIPTION
    Stores an authenticated global preference. An explicit
    -EscalationMethod on a supported operation always takes precedence.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateSet('WindowsTokenPrivilege')]
        [string]$Method
    )

    if (-not $PSCmdlet.ShouldProcess(
            'HostHunter global escalation preference',
            "Set method to '$Method'"
        )) {
        return
    }

    $runtime = Get-HHRuntimeContext
    $context = Open-HHAuthenticatedPersistence -PersistenceContext $runtime `
        -AllowAnchorAdvance
    try {
        Set-HHAuthenticatedEscalationPreference -Context $context -Method $Method
    }
    finally {
        Close-HHAuthenticatedPersistence -Context $context
    }
}
