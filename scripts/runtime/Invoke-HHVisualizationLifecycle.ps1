[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('status', 'start', 'new', 'pause')]
    [string]$Action
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module $env:HH_RUNTIME_MODULE_PATH -Force -ErrorAction Stop
$result = & (Get-Module HostHunterNextGeneration) {
    param($RequestedAction)
    Invoke-HHVisualizationLifecycleCore -Action $RequestedAction
} $Action
$result | ConvertTo-Json -Compress -Depth 8
