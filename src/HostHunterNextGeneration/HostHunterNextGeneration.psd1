@{
    RootModule = 'HostHunterNextGeneration.psm1'
    ModuleVersion = '0.2.1'
    GUID = 'a29e4ed1-e148-49ec-9b3b-ab930d2e968d'
    Author = 'James Hinton'
    CompanyName = 'HostHunter'
    Copyright = '(c) 2026 James Hinton. MIT License.'
    Description = 'Accountable PowerShell remoting target management and command execution.'
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
    )
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
    PrivateData = @{
        PSData = @{
            Tags = @('PowerShell', 'Remoting', 'SSH', 'Audit')
            LicenseUri = 'https://opensource.org/license/mit'
            ProjectUri = 'https://github.com/jimtin/HostHunterNextGeneration'
            Prerelease = 'preview1'
        }
    }
}
