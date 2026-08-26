function Invoke-HHCommand {
    <#
    .SYNOPSIS
    Runs a PowerShell command against active or selected HostHunter targets.
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

    Invoke-HHManagedHostOperation -Operation InvokeCommand -Arguments $PSBoundParameters
}
