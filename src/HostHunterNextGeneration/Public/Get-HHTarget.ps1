function Get-HHTarget {
    <#
    .SYNOPSIS
    Lists saved HostHunter targets.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSAvoidUsingWriteHost',
        '',
        Justification = 'The requested empty-state notice must remain visible in native PS7 hosts.'
    )]
    [CmdletBinding()]
    param([string[]]$Name)

    $runtime = Get-HHRuntimeContext
    if (-not [IO.File]::Exists($runtime.DatabasePath)) {
        Write-Host 'No currently set'
        return
    }
    $targets = @()
    try {
        $context = Open-HHAuthenticatedPersistence -PersistenceContext $runtime
        try {
            $parameters = @{
                Connection = $context.Connection
                MasterKey = $context.MasterKey
                ExpectedAnchor = $context.Anchor
            }
            if ($PSBoundParameters.ContainsKey('Name')) { $parameters.Name = $Name }
            $targets = @((Read-HHTargetRepositorySnapshot @parameters).Targets)
        }
        finally { Close-HHAuthenticatedPersistence -Context $context }
    }
    catch {
        $errorId = ($_.FullyQualifiedErrorId -split ',', 2)[0]
        if ($errorId -notin @('AuditKeyUnavailable', 'AuditKeychainUnavailable')) { throw }
        Write-Warning 'The saved target rows cannot be authenticated because the audit key or anchor is unavailable.'
        $connection = New-HHSqliteConnection -DatabasePath $runtime.DatabasePath -Mode ReadOnly
        try {
            $null = Test-HHSqliteDatabaseSchema `
                -Connection $connection `
                -MigrationPath $runtime.MigrationPath
            $parameters = @{ Connection = $connection }
            if ($PSBoundParameters.ContainsKey('Name')) { $parameters.Name = $Name }
            $targets = @((Read-HHTargetRepositoryDisplaySnapshot @parameters).Targets)
        }
        finally { $connection.Dispose() }
    }
    if ($targets.Count -eq 0) {
        Write-Host 'No currently set'
        return
    }
    $targets
}
