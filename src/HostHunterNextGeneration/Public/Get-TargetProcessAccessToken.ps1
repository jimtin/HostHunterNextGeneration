function Get-TargetProcessAccessToken {
    <#
    .SYNOPSIS
    Collects the primary access token for exact processes on a saved Windows target.
    #>
    [CmdletBinding(DefaultParameterSetName = 'ProcessId')]
    param(
        [ValidateCount(1, 8)][string[]]$Name,
        [Parameter(Mandatory, ParameterSetName = 'ProcessId')]
        [ValidateCount(1, 64)][ValidateRange(0, [uint32]::MaxValue)][uint32[]]$ProcessId,
        [Parameter(Mandatory, ParameterSetName = 'ProcessName')]
        [ValidateCount(1, 64)][ValidateNotNullOrEmpty()][string[]]$ProcessName,
        [ValidateRange(1, 8)][int]$ThrottleLimit = 8,
        [string]$Reason,
        [string]$CaseId
    )
    foreach ($candidate in @($ProcessName)) {
        if ([string]::IsNullOrWhiteSpace($candidate) -or $candidate.Length -gt 255 -or
            $candidate.IndexOfAny([char[]]'*?[]\/') -ge 0) {
            throw (
                'ProcessName accepts an exact process basename without wildcard ' +
                'or path characters.'
            )
        }
    }
    $arguments = @{}
    foreach ($entry in $PSBoundParameters.GetEnumerator()) { $arguments[$entry.Key] = $entry.Value }
    Invoke-HHManagedHostOperation -Operation GetProcessAccessToken -Arguments $arguments
}
