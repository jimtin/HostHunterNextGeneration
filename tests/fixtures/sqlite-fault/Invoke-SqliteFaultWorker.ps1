[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ModulePath,
    [Parameter(Mandatory)][string]$DataRoot,
    [Parameter(Mandatory)]
    [ValidateSet('CreateUnarmed', 'CreateArmed', 'HoldOperation', 'Recover')]
    [string]$Mode,
    [Parameter(Mandatory)][string]$ReceiptPath,
    [string]$CounterPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$faultReceiptPath = $ReceiptPath
$endpointCounterPath = $CounterPath

function Write-HHSqliteFaultReceipt {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Writes only the explicitly supplied test receipt path.'
    )]
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Value)

    $json = $Value | ConvertTo-Json -Depth 8 -Compress
    [IO.File]::WriteAllText($faultReceiptPath, $json, [Text.UTF8Encoding]::new($false))
}

try {
    Import-Module $ModulePath -Force
    $module = Get-Module HostHunterNextGeneration
    $providerRoot = Join-Path (Split-Path -Parent $ModulePath) 'lib'
    $masterKeyProvider = { ,([byte[]](1..32)) }

    if ($Mode -ceq 'Recover') {
        $result = & $module {
            param($Root, $Provider, $KeyProvider)
            $persistence = Get-HHPersistenceContext -DataRoot $Root
            $context = Open-HHAuthenticatedPersistence -PersistenceContext $persistence `
                -OperationLock -AllowAnchorAdvance -ProviderRoot $Provider `
                -MasterKeyProvider $KeyProvider
            try {
                $row = @(Invoke-HHSqliteQuery -Connection $context.Connection -Sql @'
SELECT i.invocation_id,o.status,o.dispatch_state,o.outcome_status,o.recovery_state
FROM invocations i
JOIN invocation_outcomes o ON o.invocation_id=i.invocation_id
ORDER BY i.sequence DESC LIMIT 1;
'@)[0]
                [ordered]@{
                    RecoveryReceipts = @($context.RecoveryReceipts)
                    InvocationId = ConvertTo-HHPersistenceIdentifierText ([byte[]]$row.invocation_id)
                    Status = [string]$row.status
                    DispatchState = [string]$row.dispatch_state
                    OutcomeStatus = [string]$row.outcome_status
                    RecoveryState = [string]$row.recovery_state
                }
            }
            finally { Close-HHAuthenticatedPersistence -Context $context }
        } $DataRoot $providerRoot $masterKeyProvider
        Write-HHSqliteFaultReceipt -Value $result
        exit 0
    }

    $created = & $module {
        param($Root, $Provider, $KeyProvider, $WorkerMode, $EndpointCounter)
        $persistence = Get-HHPersistenceContext -DataRoot $Root
        $context = Open-HHAuthenticatedPersistence -PersistenceContext $persistence `
            -OperationLock -AllowAnchorAdvance -ProviderRoot $Provider `
            -MasterKeyProvider $KeyProvider
        if ($WorkerMode -ceq 'HoldOperation') {
            return [ordered]@{ Ready = $true; Mode = $WorkerMode; Context = $context }
        }
        $target = New-HHTargetRecord -Name fault-target -Transport SSH `
            -HostName fault.example.test -Port 22 -UserName operator `
            -Authentication Password -PowerShellRuntime PowerShell7 `
            -HostKeyFingerprint ('SHA256:' + ('A' * 43)) -KeyPath $null `
            -IsActive $true -LastValidatedAtUtc '2026-08-24T00:00:00Z' `
            -LastValidatedPSEdition Core -LastValidatedPowerShellVersion '7.6.5' `
            -LastValidatedExecutionMode Direct
        $remoteOperation = Get-HHRemoteOperationManifestEntry -Phase Command `
            -PowerShellRuntime PowerShell7 -ScriptText "'fault-probe'" -ArgumentList @()
        $request = [pscustomobject]@{
            Target = $target
            CommandText = "'fault-probe'"
            Reason = $null
            CaseId = 'fault-case'
            RemoteOperations = @($remoteOperation)
        }
        $intent = @(Register-HHAuthenticatedAuditBatch -Context $context `
                -Operation InvokeCommand -Request @($request))[0]
        if ($WorkerMode -ceq 'CreateArmed') {
            Arm-HHAuthenticatedRemoteOperation -Context $context -Intent $intent -Ordinal 0
            if (-not [string]::IsNullOrWhiteSpace($EndpointCounter)) {
                $count = if ([IO.File]::Exists($EndpointCounter)) {
                    [int][IO.File]::ReadAllText($EndpointCounter)
                }
                else { 0 }
                [IO.File]::WriteAllText($EndpointCounter, [string]($count + 1))
            }
        }
        [ordered]@{
            Ready = $true
            Mode = $WorkerMode
            InvocationId = $intent.InvocationId
            Context = $context
        }
    } $DataRoot $providerRoot $masterKeyProvider $Mode $endpointCounterPath

    $createdInvocationId = if ($created -is [System.Collections.IDictionary] -and
        $created.Contains('InvocationId')) {
        $created['InvocationId']
    }
    else { $null }
    Write-HHSqliteFaultReceipt -Value @{
        ready = $true
        mode = $Mode
        invocationId = $createdInvocationId
    }
    while ($true) { Start-Sleep -Seconds 1 }
}
catch {
    Write-HHSqliteFaultReceipt -Value @{
        ready = $false
        mode = $Mode
        errorId = [string]$_.FullyQualifiedErrorId
        exceptionType = $_.Exception.GetType().FullName
        message = $_.Exception.Message
    }
    exit 1
}
