Set-StrictMode -Version Latest

function Get-HHPersistenceErrorRecord {
    [CmdletBinding()]
    [OutputType([System.Management.Automation.ErrorRecord])]
    param(
        [Parameter(Mandatory)][string]$ErrorId,
        [Parameter(Mandatory)][string]$Message,
        [Parameter(Mandatory)][System.Management.Automation.ErrorCategory]$Category,
        [AllowNull()][object]$TargetObject,
        [AllowNull()][System.Exception]$InnerException
    )

    $exception = if ($null -eq $InnerException) {
        [System.InvalidOperationException]::new($Message)
    }
    else {
        [System.InvalidOperationException]::new($Message, $InnerException)
    }
    [System.Management.Automation.ErrorRecord]::new(
        $exception,
        $ErrorId,
        $Category,
        $TargetObject
    )
}

function Stop-HHPersistenceOperation {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Throws a terminating error and does not mutate external state.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ErrorId,
        [Parameter(Mandatory)][string]$Message,
        [Parameter(Mandatory)][System.Management.Automation.ErrorCategory]$Category,
        [AllowNull()][object]$TargetObject,
        [AllowNull()][System.Exception]$InnerException
    )

    $errorRecord = Get-HHPersistenceErrorRecord @PSBoundParameters
    $PSCmdlet.ThrowTerminatingError($errorRecord)
}
