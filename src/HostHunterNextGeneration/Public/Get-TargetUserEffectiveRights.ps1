function Get-TargetUserEffectiveRights {
    <#
    .SYNOPSIS
    Collects effective Windows user rights for an identity on a saved target.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseSingularNouns',
        '',
        Justification = 'The user-approved public cmdlet name describes the complete effective-rights set.'
    )]
    [CmdletBinding()]
    param(
        [ValidateCount(1, 8)][string[]]$Name,
        [ValidateNotNullOrEmpty()][string]$Identity,
        [ValidateRange(1, 8)][int]$ThrottleLimit = 8,
        [string]$Reason,
        [string]$CaseId
    )
    if ($PSBoundParameters.ContainsKey('Identity') -and
        [string]::IsNullOrWhiteSpace($Identity)) {
        throw 'Identity cannot be blank.'
    }
    $arguments = @{}
    foreach ($entry in $PSBoundParameters.GetEnumerator()) { $arguments[$entry.Key] = $entry.Value }
    Invoke-HHManagedHostOperation -Operation GetUserEffectiveRights -Arguments $arguments
}
