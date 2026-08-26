@{
    RootModule = 'HostHunter.Client.psm1'
    ModuleVersion = '0.1.0'
    GUID = 'a41f4447-88a8-48dd-9cd5-7972edb6c253'
    Author = 'HostHunter'
    CompanyName = 'HostHunter'
    Copyright = '(c) HostHunter. All rights reserved.'
    Description = 'Native PowerShell client for the containerized HostHunter runtime.'
    PowerShellVersion = '7.4'
    FunctionsToExport = '*'
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = '*'
    PrivateData = @{
        PSData = @{
            Tags = @('HostHunter', 'Docker', 'PowerShell')
        }
    }
}
