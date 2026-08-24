function Get-HHAuditOutput {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[0-9a-fA-F]{32}$')]
        [string]$InvocationId
    )

    $runtime = Get-HHRuntimeContext
    if (-not [IO.Directory]::Exists($runtime.DataRoot)) {
        throw "No audit invocation exists with id '$InvocationId'."
    }
    $context = Open-HHAuthenticatedPersistence -PersistenceContext $runtime
    try {
        Get-HHSqliteAuditOutput -Connection $context.Connection `
            -PersistenceContext $runtime -MasterKey $context.MasterKey `
            -InvocationId $InvocationId
    }
    finally { Close-HHAuthenticatedPersistence -Context $context }
}
