function Get-TargetHostDetails {
    <#
    .SYNOPSIS
    Collects fresh ECS-compatible details from saved HostHunter targets.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseSingularNouns',
        '',
        Justification = 'Get-TargetHostDetails is the explicitly approved public command name.'
    )]
    [CmdletBinding()]
    param(
        [ValidateCount(1,8)][string[]]$Name,
        [ValidateRange(1,8)][int]$ThrottleLimit=8,
        [string]$Reason,
        [string]$CaseId
    )
    $arguments=@{}
    foreach($entry in $PSBoundParameters.GetEnumerator()){$arguments[$entry.Key]=$entry.Value}
    Invoke-HHManagedHostOperation -Operation GetHostDetails -Arguments $arguments
}
