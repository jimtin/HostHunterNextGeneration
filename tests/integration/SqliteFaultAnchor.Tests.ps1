if ([string]::IsNullOrWhiteSpace($env:HH_TEST_MODULE_PATH)) {
    throw 'HH_TEST_MODULE_PATH is required for SQLite fault integration proof.'
}

Describe 'packaged SQLite anchor and rollback fault recovery' -Tag Integration {
    BeforeAll {
        Import-Module $env:HH_TEST_MODULE_PATH -Force
        $script:loadedModule = Get-Module HostHunterNextGeneration
        $script:providerRoot = Join-Path `
            (Split-Path -Parent $env:HH_TEST_MODULE_PATH) 'lib'
        $script:keyProvider = { ,([byte[]](1..32)) }
    }

    It 'classifies commit-ahead as unknown then reseals the verified extension' {
        $dataRoot = Join-Path $TestDrive 'commit-ahead'
        $result = & $script:loadedModule {
            param($Root, $Provider, $KeyProvider)
            $persistence = Get-HHPersistenceContext -DataRoot $Root
            $context = Open-HHAuthenticatedPersistence -PersistenceContext $persistence `
                -AllowAnchorAdvance -ProviderRoot $Provider -MasterKeyProvider $KeyProvider
            try {
                $context.AnchorWriter = { throw 'injected external seal failure' }
                $target = New-HHTargetRecord -Name anchor-target -Transport SSH `
                    -HostName anchor.example.test -Port 22 -UserName operator `
                    -Authentication Password -PowerShellRuntime PowerShell7 `
                    -HostKeyFingerprint ('SHA256:' + ('A' * 43)) -KeyPath $null `
                    -IsActive $true -LastValidatedAtUtc '2026-08-24T00:00:00Z' `
                    -LastValidatedPSEdition Core -LastValidatedPowerShellVersion '7.6.5' `
                    -LastValidatedExecutionMode Direct
                $remote = Get-HHRemoteOperationManifestEntry -Phase Command `
                    -PowerShellRuntime PowerShell7 -ScriptText "'anchor-probe'"
                $request = [pscustomobject]@{
                    Target = $target; CommandText = "'anchor-probe'"
                    Reason = $null; CaseId = 'anchor-case'; RemoteOperations = @($remote)
                }
                $commitError = $null
                try {
                    $null = Register-HHAuthenticatedAuditBatch -Context $context `
                        -Operation InvokeCommand -Request @($request)
                }
                catch { $commitError = $_ }
            }
            finally { Close-HHAuthenticatedPersistence -Context $context }

            $readError = $null
            try {
                $readContext = Open-HHAuthenticatedPersistence `
                    -PersistenceContext $persistence -ProviderRoot $Provider `
                    -MasterKeyProvider $KeyProvider
                Close-HHAuthenticatedPersistence -Context $readContext
            }
            catch { $readError = $_ }

            $recovered = Open-HHAuthenticatedPersistence -PersistenceContext $persistence `
                -AllowAnchorAdvance -ProviderRoot $Provider -MasterKeyProvider $KeyProvider
            try {
                [ordered]@{
                    CommitState = [string]$commitError.Exception.Data['HHPersistenceCommitState']
                    ReadErrorId = [string]$readError.FullyQualifiedErrorId
                    AuditSequence = [long]$recovered.Anchor.AuditSequence
                }
            }
            finally { Close-HHAuthenticatedPersistence -Context $recovered }
        } $dataRoot $script:providerRoot $script:keyProvider

        $result.CommitState | Should -BeExactly Unknown
        $result.ReadErrorId | Should -Match '^AuditRecoveryRequired'
        $result.AuditSequence | Should -BeGreaterThan 1
    }

    It 'detects a database rollback behind the external anchor' {
        $dataRoot = Join-Path $TestDrive 'rollback'
        $databaseBackup = Join-Path $TestDrive 'pre-mutation.db'
        $result = & $script:loadedModule {
            param($Root, $Backup, $Provider, $KeyProvider)
            $persistence = Get-HHPersistenceContext -DataRoot $Root
            $initial = Open-HHAuthenticatedPersistence -PersistenceContext $persistence `
                -AllowAnchorAdvance -ProviderRoot $Provider -MasterKeyProvider $KeyProvider
            Close-HHAuthenticatedPersistence -Context $initial
            [IO.File]::Copy($persistence.DatabasePath, $Backup, $false)

            $writer = Open-HHAuthenticatedPersistence -PersistenceContext $persistence `
                -AllowAnchorAdvance -ProviderRoot $Provider -MasterKeyProvider $KeyProvider
            try {
                $target = New-HHTargetRecord -Name rollback-target -Transport SSH `
                    -HostName rollback.example.test -Port 22 -UserName operator `
                    -Authentication Password -PowerShellRuntime PowerShell7 `
                    -HostKeyFingerprint ('SHA256:' + ('A' * 43)) -KeyPath $null `
                    -IsActive $true -LastValidatedAtUtc '2026-08-24T00:00:00Z' `
                    -LastValidatedPSEdition Core -LastValidatedPowerShellVersion '7.6.5' `
                    -LastValidatedExecutionMode Direct
                $remote = Get-HHRemoteOperationManifestEntry -Phase Command `
                    -PowerShellRuntime PowerShell7 -ScriptText "'rollback-probe'"
                $request = [pscustomobject]@{
                    Target = $target; CommandText = "'rollback-probe'"
                    Reason = $null; CaseId = 'rollback-case'; RemoteOperations = @($remote)
                }
                $null = Register-HHAuthenticatedAuditBatch -Context $writer `
                    -Operation InvokeCommand -Request @($request)
            }
            finally { Close-HHAuthenticatedPersistence -Context $writer }

            [IO.File]::Copy($Backup, $persistence.DatabasePath, $true)
            foreach ($suffix in @('-wal', '-shm')) {
                $sidecar = "$($persistence.DatabasePath)$suffix"
                if ([IO.File]::Exists($sidecar)) { [IO.File]::Delete($sidecar) }
            }
            try {
                $read = Open-HHAuthenticatedPersistence -PersistenceContext $persistence `
                    -ProviderRoot $Provider -MasterKeyProvider $KeyProvider
                Close-HHAuthenticatedPersistence -Context $read
                return 'unexpected-success'
            }
            catch { return [string]$_.FullyQualifiedErrorId }
        } $dataRoot $databaseBackup $script:providerRoot $script:keyProvider

        $result | Should -Match '^AuditRollbackDetected'
    }

    It 'detects a tampered authenticated audit row before permitting work' {
        $dataRoot = Join-Path $TestDrive 'tamper'
        $result = & $script:loadedModule {
            param($Root, $Provider, $KeyProvider)
            $persistence = Get-HHPersistenceContext -DataRoot $Root
            $context = Open-HHAuthenticatedPersistence -PersistenceContext $persistence `
                -AllowAnchorAdvance -ProviderRoot $Provider -MasterKeyProvider $KeyProvider
            try {
                $target = New-HHTargetRecord -Name tamper-target -Transport SSH `
                    -HostName tamper.example.test -Port 22 -UserName operator `
                    -Authentication Password -PowerShellRuntime PowerShell7 `
                    -HostKeyFingerprint ('SHA256:' + ('A' * 43)) -KeyPath $null `
                    -IsActive $true -LastValidatedAtUtc '2026-08-24T00:00:00Z' `
                    -LastValidatedPSEdition Core -LastValidatedPowerShellVersion '7.6.5' `
                    -LastValidatedExecutionMode Direct
                $remote = Get-HHRemoteOperationManifestEntry -Phase Command `
                    -PowerShellRuntime PowerShell7 -ScriptText "'tamper-probe'"
                $request = [pscustomobject]@{
                    Target = $target; CommandText = "'tamper-probe'"
                    Reason = $null; CaseId = 'tamper-case'; RemoteOperations = @($remote)
                }
                $null = Register-HHAuthenticatedAuditBatch -Context $context `
                    -Operation InvokeCommand -Request @($request)
            }
            finally { Close-HHAuthenticatedPersistence -Context $context }

            $connection = New-HHSqliteConnection -DatabasePath $persistence.DatabasePath `
                -Mode ReadWrite -ProviderRoot $Provider
            try {
                $null = Invoke-HHSqliteNonQuery -Connection $connection `
                    -Sql 'DROP TRIGGER audit_events_no_update;'
                $null = Invoke-HHSqliteNonQuery -Connection $connection `
                    -Sql "UPDATE audit_events SET event_kind='Intent' WHERE sequence=1;"
            }
            finally { $connection.Dispose() }
            try {
                $read = Open-HHAuthenticatedPersistence -PersistenceContext $persistence `
                    -ProviderRoot $Provider -MasterKeyProvider $KeyProvider
                Close-HHAuthenticatedPersistence -Context $read
                return 'unexpected-success'
            }
            catch { return [string]$_.FullyQualifiedErrorId }
        } $dataRoot $script:providerRoot $script:keyProvider

        $result | Should -Match '^(AuditIntegrityFailed|PersistenceSchemaUnsupported)'
    }
}
