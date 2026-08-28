Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:HHModuleRoot = $PSScriptRoot

$privateFiles = @(Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'Private') -Filter '*.ps1' -File |
        Sort-Object Name)
$publicFiles = @(Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'Public') -Filter '*.ps1' -File |
        Sort-Object Name)

foreach ($file in $privateFiles) {
    . $file.FullName
}

foreach ($file in $publicFiles) {
    . $file.FullName
}

Set-Alias -Name Get-HHTargets -Value Get-HHTarget -Scope Script

Export-ModuleMember -Function @(
    'Set-HHTarget'
    'Get-HHTarget'
    'Test-HHTarget'
    'Remove-HHTarget'
    'Invoke-HHCommand'
    'Enable-HHSshKeyAuthentication'
    'Get-HHAuditRecord'
    'Get-HHAuditOutput'
    'Set-HHWindowsProcessAuditPolicy'
    'Set-HHEscalationPreference'
    'Get-HHEscalationPreference'
    'Get-TargetHostDetails'
) -Alias @('Get-HHTargets')
