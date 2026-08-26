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

    Invoke-HHManagedHostOperation -Operation TestTarget -Arguments $PSBoundParameters
}
