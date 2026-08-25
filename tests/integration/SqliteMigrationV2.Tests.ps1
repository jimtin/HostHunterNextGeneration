$sourceRoot = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
    Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration'
}
else { $env:HH_TEST_SOURCE_ROOT }
Import-Module (Join-Path $sourceRoot 'HostHunterNextGeneration.psd1') -Force
if ([IO.Directory]::Exists('/opt/hosthunter-sqlite/lib')) {
    $env:HH_SQLITE_PROVIDER_ROOT = '/opt/hosthunter-sqlite/lib'
}

Describe 'SQLite v1 to v2 authenticated migration' -Tag Integration {
    InModuleScope HostHunterNextGeneration {
        BeforeEach {
            $script:dataRoot = Join-Path $TestDrive ([Guid]::NewGuid().ToString('N'))
            $script:persistence = Get-HHPersistenceContext -DataRoot $script:dataRoot
            $script:masterKey = [byte[]](0..31)
        }

        $script:newTestSchemaV1Database = {
            Initialize-HHPersistenceRoot -PersistenceContext $script:persistence
            [IO.Directory]::CreateDirectory($script:persistence.AuditRoot) | Out-Null
            $connection = New-HHSqliteConnection `
                -DatabasePath $script:persistence.DatabasePath -Mode ReadWriteCreate
            try {
                $null = Invoke-HHSqliteNonQuery -Connection $connection `
                    -Sql 'PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=OFF;'
                $migrationBytes = Get-HHSqliteMigrationContent `
                    -MigrationPath $script:persistence.MigrationPath
                $migrationSql = [Text.UTF8Encoding]::new($false, $true).GetString($migrationBytes)
                $migrationHash = Get-HHPersistenceHash -Bytes $migrationBytes
                $databaseId = [Guid]::NewGuid().ToByteArray()
                $ledgerId = [Guid]::NewGuid().ToByteArray()
                $zero = [byte[]]::new(32)
                $targetEvidence = Get-HHTargetRepositoryStateEvidence `
                    -DatabaseId $databaseId -LedgerId $ledgerId -SchemaVersion 1 `
                    -Generation 0 -PriorMutationMac $zero -Target @() `
                    -MasterKey $script:masterKey
                $transaction = $connection.BeginTransaction()
                try {
                    $null = Invoke-HHSqliteNonQuery -Connection $connection `
                        -Transaction $transaction -Sql $migrationSql
                    $null = Invoke-HHSqliteNonQuery -Connection $connection `
                        -Transaction $transaction -Sql @'
INSERT INTO schema_migrations(version,name,sql_checksum,applied_at_utc)
VALUES(1,'0001_initial_sqlite',@checksum,'2026-08-25T00:00:00.0000000Z');
INSERT INTO database_identity(singleton_id,database_id,ledger_id,format_version,created_at_utc)
VALUES(1,@database,@ledger,1,'2026-08-25T00:00:00.0000000Z');
INSERT INTO target_store_state(singleton_id,generation,snapshot_hash,target_state_mac,prior_mutation_mac,last_mutation_id)
VALUES(1,0,@snapshot,@state,@prior,NULL);
'@ -Parameters @{
                        checksum = $migrationHash
                        database = $databaseId
                        ledger = $ledgerId
                        snapshot = $targetEvidence.SnapshotHash
                        state = $targetEvidence.TargetStateMac
                        prior = $zero
                    }
                    $transaction.Commit()
                }
                finally { $transaction.Dispose() }
                $null = Invoke-HHSqliteNonQuery -Connection $connection -Sql 'PRAGMA foreign_keys=ON;'
                $schema = Test-HHSqliteDatabaseSchema -Connection $connection `
                    -MigrationPath $script:persistence.MigrationPath
                $anchor = [pscustomobject]@{
                    DatabaseId = $databaseId
                    LedgerId = $ledgerId
                    SchemaVersion = 1
                    AuditSequence = 0L
                    AuditMac = $zero
                    TargetGeneration = 0L
                    TargetStateMac = $targetEvidence.TargetStateMac
                    SchemaFingerprint = $schema.SchemaFingerprint
                }
                $artifact = ConvertTo-HHPersistenceAnchorArtifact `
                    -Anchor $anchor -MasterKey $script:masterKey
                Write-HHFilePersistenceAnchor -Path $script:persistence.AnchorPath `
                    -ExpectedArtifact $null -NewArtifact $artifact
            }
            finally { $connection.Dispose() }
        }

        It 'authenticates v1 before applying the ordered checksummed v2 migration' -Skip:$IsMacOS {
            & $script:newTestSchemaV1Database
            $provider = { [byte[]]$script:masterKey.Clone() }
            $context = Open-HHAuthenticatedPersistence `
                -PersistenceContext $script:persistence `
                -MasterKeyProvider $provider `
                -AllowAnchorAdvance
            try {
                $context.Schema.SchemaVersion | Should -Be 2
                $context.Anchor.ConfigurationGeneration | Should -Be 0
                (Get-HHAuthenticatedEscalationPreference -Context $context).Source |
                    Should -BeExactly BuiltIn
                @(Invoke-HHSqliteQuery -Connection $context.Connection `
                        -Sql 'SELECT version,name FROM schema_migrations ORDER BY version;').Count |
                    Should -Be 2
                $operationSql = [string](Invoke-HHSqliteScalar -Connection $context.Connection `
                        -Sql "SELECT sql FROM sqlite_schema WHERE name='operation_batches';")
                $operationSql | Should -Match 'SetWindowsProcessAuditPolicy'
            }
            finally { Close-HHAuthenticatedPersistence -Context $context }
        }

        It 'recovers a committed migration whose external anchor reseal crashed' -Skip:$IsMacOS {
            & $script:newTestSchemaV1Database
            $provider = { [byte[]]$script:masterKey.Clone() }
            {
                Open-HHAuthenticatedPersistence `
                    -PersistenceContext $script:persistence `
                    -MasterKeyProvider $provider `
                    -AnchorWriter { throw 'simulated migration seal crash' } `
                    -AllowAnchorAdvance
            } | Should -Throw '*simulated migration seal crash*'

            $connection = New-HHSqliteConnection -DatabasePath $script:persistence.DatabasePath
            try {
                (Test-HHSqliteDatabaseSchema -Connection $connection `
                        -MigrationPath $script:persistence.MigrationPath).SchemaVersion |
                    Should -Be 2
            }
            finally { $connection.Dispose() }
            (Read-HHFilePersistenceAnchor -Path $script:persistence.AnchorPath `
                    -MasterKey $script:masterKey).PSObject.Properties['ConfigurationGeneration'] |
                Should -BeNullOrEmpty

            $recovered = Open-HHAuthenticatedPersistence `
                -PersistenceContext $script:persistence `
                -MasterKeyProvider $provider `
                -AllowAnchorAdvance
            try {
                $recovered.Anchor.ConfigurationGeneration | Should -Be 0
                $recovered.Anchor.Artifact.Length | Should -Be 236
            }
            finally { Close-HHAuthenticatedPersistence -Context $recovered }
        }

        It 'rejects a tampered v1 anchor before migration and leaves schema v1' -Skip:$IsMacOS {
            & $script:newTestSchemaV1Database
            $artifact = [IO.File]::ReadAllBytes($script:persistence.AnchorPath)
            $artifact[140] = $artifact[140] -bxor 1
            [IO.File]::WriteAllBytes($script:persistence.AnchorPath, $artifact)
            [IO.File]::SetUnixFileMode(
                $script:persistence.AnchorPath,
                [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite
            )
            {
                Open-HHAuthenticatedPersistence `
                    -PersistenceContext $script:persistence `
                    -MasterKeyProvider { [byte[]]$script:masterKey.Clone() } `
                    -AllowAnchorAdvance
            } | Should -Throw -ErrorId 'AuditIntegrityFailed*'
            $connection = New-HHSqliteConnection -DatabasePath $script:persistence.DatabasePath
            try {
                (Test-HHSqliteDatabaseSchema -Connection $connection `
                        -MigrationPath $script:persistence.MigrationPath).SchemaVersion |
                    Should -Be 1
            }
            finally { $connection.Dispose() }
        }

        It 'persists the preference across independent PowerShell processes' -Skip:$IsMacOS {
            $workerPath = Join-Path $TestDrive 'configuration-worker.ps1'
            [IO.File]::WriteAllText($workerPath, @'
param([string]$ModulePath,[string]$DataRoot,[ValidateSet('Set','Get')][string]$Mode)
$ErrorActionPreference = 'Stop'
Import-Module $ModulePath -Force
& (Get-Module HostHunterNextGeneration) {
    param($Root,$Operation)
    $persistence = Get-HHPersistenceContext -DataRoot $Root
    $context = Open-HHAuthenticatedPersistence -PersistenceContext $persistence `
        -AllowAnchorAdvance:($Operation -eq 'Set')
    try {
        if ($Operation -eq 'Set') {
            Set-HHAuthenticatedEscalationPreference -Context $context `
                -Method WindowsTokenPrivilege | ConvertTo-Json -Compress
        }
        else {
            Get-HHAuthenticatedEscalationPreference -Context $context |
                ConvertTo-Json -Compress
        }
    }
    finally { Close-HHAuthenticatedPersistence -Context $context }
} $DataRoot $Mode
'@)
            $modulePath = (Get-Module HostHunterNextGeneration).Path
            $setOutput = & pwsh -NoLogo -NoProfile -NonInteractive -File $workerPath `
                -ModulePath $modulePath -DataRoot $script:dataRoot -Mode Set
            $LASTEXITCODE | Should -Be 0
            ($setOutput | ConvertFrom-Json).IsPersisted | Should -BeTrue

            $getOutput = & pwsh -NoLogo -NoProfile -NonInteractive -File $workerPath `
                -ModulePath $modulePath -DataRoot $script:dataRoot -Mode Get
            $LASTEXITCODE | Should -Be 0
            $preference = $getOutput | ConvertFrom-Json
            $preference.Method | Should -BeExactly WindowsTokenPrivilege
            $preference.Source | Should -BeExactly Persisted
            $preference.Generation | Should -Be 1
        }
    }
}
