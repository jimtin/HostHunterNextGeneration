function Get-HHEscalationPreference {
    <#
    .SYNOPSIS
    Gets the escalation method HostHunter uses when -Escalate is requested.
    .DESCRIPTION
    Returns the authenticated global preference when one has been saved.
    Without persisted HostHunter state, returns the sole built-in method
    without creating a data root or database.
    #>
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
