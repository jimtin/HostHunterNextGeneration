Set-StrictMode -Version Latest

function Assert-HHWinRmControllerSupported {
    [CmdletBinding()]
    param([bool]$IsWindowsController = $IsWindows)

    if (-not $IsWindowsController) {
        throw [System.PlatformNotSupportedException]::new(
            'WinRM targets require HostHunterNextGeneration on a supported Windows controller.'
        )
    }
}

function Test-HHWinRmPowerShellEndpoint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Target,
        [bool]$IsWindowsController = $IsWindows
    )

    Assert-HHWinRmControllerSupported -IsWindowsController $IsWindowsController
    $null = $Target
    throw [System.NotSupportedException]::new(
        'WinRM runtime qualification is blocked until controlled Windows validation is complete.'
    )
}
