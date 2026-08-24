[CmdletBinding()]
param(
    [version]$ExpectedPowerShellVersion = '7.6.5'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($PSVersionTable.PSVersion -ne $ExpectedPowerShellVersion) {
    throw "PowerShell pin drift: $($PSVersionTable.PSVersion)"
}

Import-Module Pester -RequiredVersion 6.1.0 -Force
Import-Module PSScriptAnalyzer -RequiredVersion 1.25.0 -Force

"PowerShell $ExpectedPowerShellVersion/Pester/PSScriptAnalyzer pins verified"
