function Set-HHTarget {
    <#
    .SYNOPSIS
    Discovers, validates, and additively saves PowerShell remoting targets.
    .DESCRIPTION
    HostName and UserName are the normal required inputs. On first contact,
    HostHunter discovers, announces, and pins the server's public SSH host key
    before requesting a password. After authentication, the saved Name defaults
    to the remote computer name. Supply Name to override it or an independently
    verified HostKeyFingerprint when onboarding across a higher-risk network.
    Existing targets remain active.
    .EXAMPLE
    Set-HHTarget -HostName 'BestLaptopEver' -UserName 'RemoteAdmin'

    Discovers and pins the host identity, securely prompts for a password
    if SSH requires one, and saves the target under its remote computer name.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSShouldProcess',
        '',
        Justification = 'The public adapter forwards WhatIf and Confirm to the private engine implementation that owns ShouldProcess.'
    )]
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium', DefaultParameterSetName = 'Properties')]
    param(
        [Parameter(ParameterSetName = 'Properties')]
        [ValidateLength(1, 128)]
        [string]$Name,
        [Parameter(Mandatory, ParameterSetName = 'Properties')]
        [string]$HostName,
        [Parameter(Mandatory, ParameterSetName = 'Properties')]
        [string]$UserName,
        [Parameter(ParameterSetName = 'Properties')]
        [ValidateRange(1, 65535)]
        [int]$Port = 22,
        [Parameter(ParameterSetName = 'Properties')]
        [ValidateSet('Password', 'PublicKey')]
        [string]$Authentication = 'Password',
        [Parameter(ParameterSetName = 'Properties')]
        [string]$HostKeyFingerprint,
        [Parameter(ParameterSetName = 'Properties')]
        [string]$KeyPath,
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
