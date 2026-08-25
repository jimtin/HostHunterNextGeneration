Set-StrictMode -Version Latest

function Get-HHRemoteOperationManifestEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet(
            'HostTrustDiscovery',
            'OuterIdentity',
            'RuntimeIdentity',
            'Command',
            'BootstrapInstall',
            'BootstrapReconcile',
            'BootstrapKeyOnlyOuterIdentity',
            'BootstrapKeyOnlyRuntimeIdentity',
            'BootstrapRollback',
            'ProcessAuditPolicyMutation'
        )]
        [string] $Phase,

        [Parameter(Mandatory)]
        [ValidateSet('PowerShell7', 'WindowsPowerShell51')]
        [string] $PowerShellRuntime,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $ScriptText,

        [AllowEmptyCollection()]
        [object[]] $ArgumentList = @(),

        [bool] $Conditional = $false
    )

    if ([string]::IsNullOrWhiteSpace($ScriptText)) {
        throw [ArgumentException]::new('Remote operation script text must not be blank.')
    }

    $serializedArguments = [Management.Automation.PSSerializer]::Serialize(
        [object[]] $ArgumentList,
        20
    )
    if ([string]::IsNullOrWhiteSpace($serializedArguments)) {
        throw [InvalidOperationException]::new(
            'Remote operation arguments could not be serialized deterministically.'
        )
    }

    [pscustomobject][ordered]@{
        Phase = $Phase
        PowerShellRuntime = $PowerShellRuntime
        ScriptText = $ScriptText
        SerializedArguments = $serializedArguments
        Conditional = $Conditional
    }
}

function Get-HHSshIdentityRemoteOperationManifest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('PowerShell7', 'WindowsPowerShell51')]
        [string] $PowerShellRuntime,

        [ValidateSet(
            'OuterIdentity',
            'RuntimeIdentity',
            'BootstrapKeyOnlyOuterIdentity',
            'BootstrapKeyOnlyRuntimeIdentity'
        )]
        [string] $Phase = 'OuterIdentity'
    )

    Get-HHRemoteOperationManifestEntry `
        -Phase $Phase `
        -PowerShellRuntime $PowerShellRuntime `
        -ScriptText ((Get-HHSshIdentityProbeScriptBlock).ToString()) `
        -ArgumentList @()
}

function Get-HHTargetValidationRemoteOperationManifest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object] $Target,

        [switch] $IncludeHostTrustDiscovery,

        [ValidateRange(1, 300)]
        [int] $HostTrustTimeoutSeconds = 15
    )

    $runtimeProperty = $Target.PSObject.Properties['PowerShellRuntime']
    if ($null -eq $runtimeProperty -or
        [string]::IsNullOrWhiteSpace([string] $runtimeProperty.Value) -or
        [string] $runtimeProperty.Value -cnotin @('PowerShell7', 'WindowsPowerShell51')) {
        throw [ArgumentException]::new(
            'A remote-operation manifest requires an explicit supported PowerShell runtime.'
        )
    }
    $requestedRuntime = [string] $runtimeProperty.Value
    $operations = [Collections.Generic.List[object]]::new()
    if ($IncludeHostTrustDiscovery) {
        $operations.Add((Get-HHRemoteOperationManifestEntry `
                    -Phase HostTrustDiscovery `
                    -PowerShellRuntime $requestedRuntime `
                    -ScriptText 'ssh-keyscan' `
                    -ArgumentList @(
                        '-p', [string] $Target.Port,
                        '-T', [string] $HostTrustTimeoutSeconds,
                        [string] $Target.HostName
                    )))
    }
    $operations.Add((Get-HHSshIdentityRemoteOperationManifest `
                -PowerShellRuntime PowerShell7 `
                -Phase OuterIdentity))
    if ($requestedRuntime -ceq 'WindowsPowerShell51') {
        $operations.Add((Get-HHSshIdentityRemoteOperationManifest `
                    -PowerShellRuntime WindowsPowerShell51 `
                    -Phase RuntimeIdentity))
    }
    return @($operations)
}

function Get-HHCommandRemoteOperationManifest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object] $Target,

        [Parameter(Mandatory)]
        [scriptblock] $ScriptBlock,

        [AllowEmptyCollection()]
        [object[]] $ArgumentList = @()
    )

    $operations = [Collections.Generic.List[object]]::new()
    foreach ($operation in @(Get-HHTargetValidationRemoteOperationManifest -Target $Target)) {
        $operations.Add($operation)
    }
    $operations.Add((Get-HHRemoteOperationManifestEntry `
                -Phase Command `
                -PowerShellRuntime ([string] $Target.PowerShellRuntime) `
                -ScriptText $ScriptBlock.ToString() `
                -ArgumentList $ArgumentList))
    return @($operations)
}

function Get-HHWindowsProcessAuditRemoteOperationManifest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object] $Target,

        [Parameter(Mandatory)]
        [scriptblock] $ScriptBlock,

        [Parameter(Mandatory)]
        [object] $Request
    )

    $operations = [Collections.Generic.List[object]]::new()
    foreach ($operation in @(Get-HHTargetValidationRemoteOperationManifest -Target $Target)) {
        $operations.Add($operation)
    }
    $operations.Add((Get-HHRemoteOperationManifestEntry `
                -Phase ProcessAuditPolicyMutation `
                -PowerShellRuntime ([string] $Target.PowerShellRuntime) `
                -ScriptText $ScriptBlock.ToString() `
                -ArgumentList @($Request)))
    return @($operations)
}
