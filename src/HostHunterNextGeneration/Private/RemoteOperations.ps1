Set-StrictMode -Version Latest

function Invoke-HHTargetProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Target,
        [Parameter(Mandatory)]$RuntimeContext,
        [scriptblock]$SshSessionFactory,
        [scriptblock]$SshRemoteInvoker,
        [scriptblock]$SshSessionRemover
    )

    switch ([string]$Target.Transport) {
        'SSH' {
            return Invoke-HHSshTransport `
                -Target $Target `
                -KnownHostsPath $RuntimeContext.KnownHostsPath `
                -SessionFactory $SshSessionFactory `
                -RemoteInvoker $SshRemoteInvoker `
                -SessionRemover $SshSessionRemover
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
