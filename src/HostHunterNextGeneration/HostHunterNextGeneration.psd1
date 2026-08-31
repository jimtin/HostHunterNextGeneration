@{
    RootModule = 'HostHunterNextGeneration.psm1'
    ModuleVersion = '0.4.0'
    GUID = 'a29e4ed1-e148-49ec-9b3b-ab930d2e968d'
    Author = 'James Hinton'
    CompanyName = 'HostHunter'
    Copyright = '(c) 2026 James Hinton. MIT License.'
    Description = 'Containerized accountable PowerShell 7 remoting and Windows process-audit policy control over SSH.'
    PowerShellVersion = '7.4'
    CompatiblePSEditions = @('Core')
    FunctionsToExport = @(
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
        'Get-TargetProcessStartEvents'
        'Get-TargetProcessEndEvents'
        'Get-TargetAuthenticationEvents'
        'Get-TargetProcessAccessToken'
        'Get-TargetUserEffectiveRights'
    )
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @('Get-HHTargets')
    PrivateData = @{
        PSData = @{
            Tags = @('PowerShell', 'Remoting', 'SSH', 'Audit', 'Docker', 'SQLite')
            LicenseUri = 'https://opensource.org/license/mit'
            ProjectUri = 'https://github.com/jimtin/HostHunterNextGeneration'
            Prerelease = 'preview1'
        }
    }
}
