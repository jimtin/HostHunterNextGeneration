[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet(
        'Set-HHTarget',
        'Get-HHTarget',
        'Test-HHTarget',
        'Remove-HHTarget',
        'Invoke-HHCommand',
        'Enable-HHSshKeyAuthentication',
        'Get-HHAuditRecord',
        'Get-HHAuditOutput',
        'Set-HHWindowsProcessAuditPolicy',
        'Set-HHEscalationPreference',
        'Get-HHEscalationPreference'
    )]
    [string]$CommandName,

    [ValidateNotNullOrEmpty()]
    [string]$ParametersJson = '{}'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module $env:HH_RUNTIME_MODULE_PATH -Force
$decoded = $ParametersJson | ConvertFrom-Json -AsHashtable -Depth 20
if ($decoded -isnot [Collections.IDictionary]) {
    throw 'ParametersJson must contain one JSON object.'
}

$result = @(& $CommandName @decoded)
if ($result.Count -gt 0) {
    $result | ConvertTo-Json -Depth 20
}
