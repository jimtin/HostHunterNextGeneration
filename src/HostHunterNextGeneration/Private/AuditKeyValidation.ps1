Set-StrictMode -Version Latest

function Get-HHAuditErrorRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ErrorId,
        [Parameter(Mandatory)][string]$Message,
        [Parameter(Mandatory)][Management.Automation.ErrorCategory]$Category,
        [AllowNull()][object]$TargetObject,
        [AllowNull()][Exception]$InnerException
    )

    $exception = if ($null -eq $InnerException) {
        [InvalidOperationException]::new($Message)
    }
    else { [InvalidOperationException]::new($Message, $InnerException) }
    [Management.Automation.ErrorRecord]::new(
        $exception,
        $ErrorId,
        $Category,
        $TargetObject
    )
}

function Assert-HHAuditMasterKey {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$MasterKey)

    if ($MasterKey.Length -ne 32) {
        throw (Get-HHAuditErrorRecord -ErrorId AuditMasterKeyInvalid `
                -Message 'The audit master key must contain exactly 32 bytes.' `
                -Category InvalidArgument -TargetObject $MasterKey)
    }
}
