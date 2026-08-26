function Set-HHTarget {
    <#
    .SYNOPSIS
    Validates and atomically saves one or more PowerShell remoting targets.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSShouldProcess',
        '',
        Justification = 'The public adapter forwards WhatIf and Confirm to the private engine implementation that owns ShouldProcess.'
    )]
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium', DefaultParameterSetName = 'Properties')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Properties')]
        [ValidateCount(1, 8)]
        [string[]]$Name,
        [Parameter(Mandatory, ParameterSetName = 'Properties')]
        [ValidateCount(1, 8)]
        [string[]]$HostName,
        [Parameter(Mandatory, ParameterSetName = 'Properties')]
        [ValidateCount(1, 8)]
        [string[]]$UserName,
        [Parameter(ParameterSetName = 'Properties')]
        [ValidateRange(1, 65535)]
        [int]$Port = 22,
        [Parameter(ParameterSetName = 'Properties')]
        [ValidateSet('Password', 'PublicKey')]
        [string]$Authentication = 'Password',
        [Parameter(ParameterSetName = 'Properties')]
        [string[]]$HostKeyFingerprint,
        [Parameter(ParameterSetName = 'Properties')]
        [string[]]$KeyPath,
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'Object')]
        [ValidateCount(1, 8)]
        [object[]]$InputObject,
        [switch]$Add,
        [string]$Reason,
        [string]$CaseId
    )

    begin { $managedHostInput = [Collections.Generic.List[object]]::new() }
    process {
        if ($PSCmdlet.ParameterSetName -eq 'Object') {
            foreach ($item in $InputObject) { $managedHostInput.Add($item) }
        }
    }
    end {
        $arguments = @{}
        foreach ($entry in $PSBoundParameters.GetEnumerator()) {
            if ($entry.Key -cne 'InputObject') { $arguments[$entry.Key] = $entry.Value }
        }
        if ($PSCmdlet.ParameterSetName -eq 'Object') {
            $arguments.InputObject = [object[]]$managedHostInput.ToArray()
        }
        Invoke-HHManagedHostOperation -Operation ValidateTarget -Arguments $arguments
    }
}
