Set-StrictMode -Version Latest

function Invoke-HHTargetProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Target,
        [Parameter(Mandatory)]$RuntimeContext,
        [scriptblock]$SshSessionFactory,
        [scriptblock]$SshRemoteInvoker,
        [scriptblock]$SshBridgeInvoker,
        [scriptblock]$SshSessionRemover,
        [bool]$IsWindowsController = $IsWindows
    )

    switch ([string]$Target.Transport) {
        'SSH' {
            return Invoke-HHSshTransport `
                -Target $Target `
                -KnownHostsPath $RuntimeContext.KnownHostsPath `
                -SessionFactory $SshSessionFactory `
                -RemoteInvoker $SshRemoteInvoker `
                -BridgeInvoker $SshBridgeInvoker `
                -SessionRemover $SshSessionRemover
        }
        'WinRM' {
            return Test-HHWinRmPowerShellEndpoint `
                -Target $Target `
                -IsWindowsController $IsWindowsController
        }
        default {
            throw "Unsupported target transport '$($Target.Transport)'."
        }
    }
}

function Test-HHTransportResult {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Result)

    if (-not $Result.Succeeded) {
        throw "Remote PowerShell validation failed ($($Result.FailureKind))."
    }
    $Result
}
