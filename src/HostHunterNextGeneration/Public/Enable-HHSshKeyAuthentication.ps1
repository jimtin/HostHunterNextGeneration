function Enable-HHSshKeyAuthentication {
    <#
    .SYNOPSIS
    Converts a password-authenticated SSH target to a proven Ed25519 key.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSShouldProcess',
        '',
        Justification = 'The public adapter forwards WhatIf and Confirm to the private engine implementation that owns ShouldProcess.'
    )]
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$Name,
        [string]$KeyPath,
        [switch]$UseExistingKey,
        [string]$Reason,
        [string]$CaseId
    )

    process {
        Invoke-HHManagedHostOperation -Operation EnableSshKeyAuthentication -Arguments $PSBoundParameters
    }
}
