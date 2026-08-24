[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$CandidateSha,
    [Parameter(Mandatory)][string]$ModuleManifestPath,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$PackageArchiveSha256,
    [Parameter(Mandatory)][string]$ReceiptPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $IsMacOS) { throw 'Native macOS qualification requires macOS.' }
$manifest = (Resolve-Path -LiteralPath $ModuleManifestPath).Path
$receipt = [IO.Path]::GetFullPath($ReceiptPath)
$canonicalTempRoot = (& /bin/realpath ([IO.Path]::GetTempPath())).Trim()
if ([string]::IsNullOrWhiteSpace($canonicalTempRoot) -or
    -not [IO.Directory]::Exists($canonicalTempRoot)) {
    throw 'The native macOS qualification temporary root could not be canonicalized.'
}
$dataRoot = Join-Path $canonicalTempRoot (
    'hosthunter-native-qualification-' + [Guid]::NewGuid().ToString('N')
)
$module = Import-Module $manifest -Force -PassThru
$startedAt = [DateTimeOffset]::UtcNow
$cleanupComplete = $false
$account = $null
$keychainPath = $null
$initialSequence = $null
$advancedSequence = $null
$rollbackRejected = $false

function Invoke-HHQualificationSecurityDelete {
    param(
        [Parameter(Mandatory)][string]$Service,
        [Parameter(Mandatory)][string]$Account,
        [Parameter(Mandatory)][string]$KeychainPath
    )

    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = '/usr/bin/security'
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in @(
            'delete-generic-password', '-s', $Service, '-a', $Account, $KeychainPath
        )) {
        $null = $startInfo.ArgumentList.Add($argument)
    }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    if (-not $process.Start()) { throw 'The exact Keychain cleanup process did not start.' }
    try {
        if (-not $process.WaitForExit(15000)) {
            $process.Kill($true)
            $process.WaitForExit()
            throw 'The exact Keychain cleanup process timed out.'
        }
        $null = $process.StandardOutput.ReadToEnd()
        $null = $process.StandardError.ReadToEnd()
        if ($process.ExitCode -notin @(0, 44)) {
            throw 'The exact Keychain item could not be deleted safely.'
        }
    }
    finally { $process.Dispose() }
}

try {
    $identity = & $module {
        param($QualificationDataRoot)
        [pscustomobject]@{
            Account = Get-HHAuditKeychainAccount -DataRoot $QualificationDataRoot
            KeychainPath = Get-HHMacOSLoginKeychainPath
        }
    } $dataRoot
    $account = [string]$identity.Account
    $keychainPath = [string]$identity.KeychainPath

    $result = & $module {
        param($QualificationDataRoot)

        $persistenceContext = Get-HHPersistenceContext -DataRoot $QualificationDataRoot
        $context = Open-HHAuthenticatedPersistence `
            -PersistenceContext $persistenceContext -AllowAnchorAdvance
        try {
            $initial = [long]$context.Anchor.AuditSequence
            $null = Invoke-HHSqliteNonQuery -Connection $context.Connection `
                -Sql 'PRAGMA wal_checkpoint(TRUNCATE);'
            $oldDatabase = "$($persistenceContext.DatabasePath).qualification-old"
            [IO.File]::Copy($persistenceContext.DatabasePath, $oldDatabase, $false)

            $null = Invoke-HHAnchoredPersistenceTransaction -Context $context -Action {
                param($Connection, $Transaction, $WriterContext)

                $target = New-HHTargetRecord -Name qualification -Transport SSH `
                    -HostName qualification.invalid -Port 22 -UserName operator `
                    -Authentication Password -PowerShellRuntime PowerShell7 `
                    -HostKeyFingerprint 'SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' `
                    -KeyPath $null -IsActive $true `
                    -LastValidatedAtUtc '2026-08-24T00:00:00Z' `
                    -LastValidatedPSEdition Core `
                    -LastValidatedPowerShellVersion 7.6.5 `
                    -LastValidatedExecutionMode Direct
                $request = [pscustomobject]@{
                    Target = $target
                    CommandText = 'qualification-command-redacted'
                    Reason = $null
                    CaseId = 'native-macos-anchor'
                    RemoteOperations = @([pscustomobject][ordered]@{
                            Phase = 'Command'
                            PowerShellRuntime = 'PowerShell7'
                            ScriptText = 'qualification-command-redacted'
                            SerializedArguments = '<Objs />'
                            Conditional = $false
                        })
                }
                @(Register-HHSqliteAuditBatch -Connection $Connection `
                        -Transaction $Transaction -MasterKey $WriterContext.MasterKey `
                        -Operation InvokeCommand -Request @($request) `
                        -IntentAtUtc ([DateTimeOffset]::UtcNow))[0]
            }
            $advanced = [long]$context.Anchor.AuditSequence
            $null = Invoke-HHSqliteNonQuery -Connection $context.Connection `
                -Sql 'PRAGMA wal_checkpoint(TRUNCATE);'
            $newDatabase = "$($persistenceContext.DatabasePath).qualification-new"
        }
        finally { Close-HHAuthenticatedPersistence -Context $context }

        [IO.File]::Copy($persistenceContext.DatabasePath, $newDatabase, $false)
        foreach ($sidecar in @("$($persistenceContext.DatabasePath)-wal", "$($persistenceContext.DatabasePath)-shm")) {
            if ([IO.File]::Exists($sidecar)) { [IO.File]::Delete($sidecar) }
        }
        [IO.File]::Copy($oldDatabase, $persistenceContext.DatabasePath, $true)
        try {
            $blocked = Open-HHAuthenticatedPersistence -PersistenceContext $persistenceContext
            Close-HHAuthenticatedPersistence -Context $blocked
            throw 'A stale database backup was accepted against the newer Keychain anchor.'
        }
        catch {
            if ($_.FullyQualifiedErrorId -notlike 'AuditRollbackDetected*') { throw }
        }
        [IO.File]::Copy($newDatabase, $persistenceContext.DatabasePath, $true)
        $recovered = Open-HHAuthenticatedPersistence `
            -PersistenceContext $persistenceContext -AllowAnchorAdvance
        try {
            if ($recovered.RecoveryReceipts.Count -ne 1 -or
                $recovered.RecoveryReceipts[0].RecoveryState -cne 'RecoveredNotDispatched') {
                throw 'The unarmed native qualification intent was not recovered exactly once.'
            }
        }
        finally { Close-HHAuthenticatedPersistence -Context $recovered }

        [pscustomobject]@{
            InitialSequence = $initial
            AdvancedSequence = $advanced
            RollbackRejected = $true
        }
    } $dataRoot

    $initialSequence = [long]$result.InitialSequence
    $advancedSequence = [long]$result.AdvancedSequence
    $rollbackRejected = [bool]$result.RollbackRejected
    if ($advancedSequence -le $initialSequence -or -not $rollbackRejected) {
        throw 'The Keychain-backed authenticated head did not advance and reject rollback.'
    }
}
finally {
    if (-not [string]::IsNullOrWhiteSpace($account) -and
        -not [string]::IsNullOrWhiteSpace($keychainPath)) {
        Invoke-HHQualificationSecurityDelete `
            -Service 'com.hosthunter.nextgeneration.audit-master-key' `
            -Account $account -KeychainPath $keychainPath
        Invoke-HHQualificationSecurityDelete `
            -Service 'com.hosthunter.nextgeneration.database-anchor.v1' `
            -Account $account -KeychainPath $keychainPath
        $cleanupComplete = $true
    }
    if ([IO.Directory]::Exists($dataRoot)) {
        [IO.Directory]::Delete($dataRoot, $true)
    }
    Remove-Module $module -Force -ErrorAction SilentlyContinue
}

if (-not $cleanupComplete) { throw 'Native qualification cleanup was not proven.' }
$receiptDirectory = Split-Path -Parent $receipt
[IO.Directory]::CreateDirectory($receiptDirectory) | Out-Null
[ordered]@{
    status = 'passed'
    candidateSha = $CandidateSha
    packageArchiveSha256 = $PackageArchiveSha256
    platform = 'macOS'
    macOSVersion = [Environment]::OSVersion.VersionString
    powerShellVersion = $PSVersionTable.PSVersion.ToString()
    initialAuditSequence = $initialSequence
    advancedAuditSequence = $advancedSequence
    rollbackRejected = $rollbackRejected
    keychainItemCount = 2
    cleanupComplete = $cleanupComplete
    redacted = $true
    startedAtUtc = $startedAt.ToString('O')
    finishedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $receipt -Encoding utf8NoBOM
