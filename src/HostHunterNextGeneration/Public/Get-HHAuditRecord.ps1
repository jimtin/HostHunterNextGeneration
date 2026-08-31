function Get-HHAuditRecord {
    [CmdletBinding()]
    param(
        [ValidatePattern('^[0-9a-fA-F]{32}$')][string]$InvocationId,
        [ValidatePattern('^[0-9a-fA-F]{32}$')][string]$BatchId,
        [string[]]$TargetName,
        [string]$CaseId,
        [DateTimeOffset]$FromUtc,
        [DateTimeOffset]$ToUtc,
        [ValidateSet(
            'ValidateTarget',
            'TestTarget',
            'InvokeCommand',
            'GetHostDetails',
            'GetProcessStartEvents',
            'GetProcessEndEvents',
            'GetAuthenticationEvents',
            'GetProcessAccessToken',
            'GetUserEffectiveRights',
            'EnableSshKeyAuthentication',
            'SetWindowsProcessAuditPolicy'
        )]
        [string[]]$Operation,
        [ValidateSet('Succeeded', 'Failed', 'Cancelled', 'Unknown', 'Pending')]
        [string[]]$Status,
        [ValidateRange(1, [long]::MaxValue)][long]$BeforeSequence,
        [ValidateRange(1, 1000)][int]$First = 100
    )

    if ($PSBoundParameters.ContainsKey('FromUtc') -and
        $PSBoundParameters.ContainsKey('ToUtc') -and $FromUtc -ge $ToUtc) {
        throw 'FromUtc must be earlier than ToUtc.'
    }
    $runtime = Get-HHRuntimeContext
    if (-not [IO.Directory]::Exists($runtime.DataRoot)) { return }
    $context = Open-HHAuthenticatedPersistence -PersistenceContext $runtime
    try {
        $parameters = @{ Connection = $context.Connection; MasterKey = $context.MasterKey; First = $First }
        foreach ($name in @('InvocationId', 'BatchId', 'TargetName', 'CaseId', 'FromUtc',
                'ToUtc', 'Operation', 'Status', 'BeforeSequence')) {
            if ($PSBoundParameters.ContainsKey($name)) { $parameters[$name] = $PSBoundParameters[$name] }
        }
        Get-HHSqliteAuditRecord @parameters
    }
    finally { Close-HHAuthenticatedPersistence -Context $context }
}
