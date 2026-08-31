function Get-TargetProcessEndEvents {
    <#
    .SYNOPSIS
    Collects bounded Windows Security 4689 process-end events from a saved target.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseSingularNouns',
        '',
        Justification = 'The approved public command returns multiple process-end events.'
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
    Invoke-HHManagedHostOperation -Operation GetProcessEndEvents -Arguments $arguments
}
