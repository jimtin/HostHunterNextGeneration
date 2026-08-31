function Get-TargetProcessStartEvents {
    <#
    .SYNOPSIS
    Collects bounded Windows Security 4688 process-start events from a saved target.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseSingularNouns',
        '',
        Justification = 'The approved public command returns multiple process-start events.'
    )]
    [CmdletBinding()]
    param(
        [ValidateCount(1, 8)][string[]]$Name,
        [DateTimeOffset]$Since,
        [DateTimeOffset]$Until,
        [ValidateRange(1, 500)][int]$First = 100,
        [ValidateRange(1, 8)][int]$ThrottleLimit = 8,
        [string]$Reason,
        [string]$CaseId
    )
    if ($PSBoundParameters.ContainsKey('Until') -and
        $PSBoundParameters.ContainsKey('Since') -and $Until -lt $Since) {
        throw 'Until must be greater than or equal to Since.'
    }
    $arguments = @{}
    foreach ($entry in $PSBoundParameters.GetEnumerator()) { $arguments[$entry.Key] = $entry.Value }
    Invoke-HHManagedHostOperation -Operation GetProcessStartEvents -Arguments $arguments
}
