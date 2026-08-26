Set-StrictMode -Version Latest

function Get-HHAuditKeyStoreErrorRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ErrorId,
        [Parameter(Mandatory)][string]$Message,
        [Parameter(Mandatory)][System.Management.Automation.ErrorCategory]$Category
    )

    $exception = [System.InvalidOperationException]::new($Message)
    [System.Management.Automation.ErrorRecord]::new(
        $exception,
        $ErrorId,
        $Category,
        $null
    )
}
