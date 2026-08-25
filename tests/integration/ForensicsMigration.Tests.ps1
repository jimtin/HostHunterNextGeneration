$modulePath = if (-not [string]::IsNullOrWhiteSpace($env:HH_TEST_MODULE_PATH)) {
    $env:HH_TEST_MODULE_PATH
}
elseif (-not [string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
    Join-Path $env:HH_TEST_SOURCE_ROOT 'HostHunterNextGeneration.psd1'
}
else {
    Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration/HostHunterNextGeneration.psd1'
}
$moduleRoot = Split-Path -Parent $modulePath
$module = New-Module -Name HostHunterForensicsMigrationTest -ArgumentList $moduleRoot -ScriptBlock {
    param($Root)
    $script:HHModuleRoot = $Root
    . (Join-Path $Root 'Private/PersistenceErrors.ps1')
    . (Join-Path $Root 'Private/PersistencePath.ps1')
    . (Join-Path $Root 'Private/SqliteProvider.ps1')
    . (Join-Path $Root 'Private/SqlitePersistence.ps1')
    . (Join-Path $Root 'Forensics/Private/Persistence/ForensicsCrypto.ps1')
    . (Join-Path $Root 'Forensics/Private/Migrations/ForensicsMigrations.ps1')
    . (Join-Path $Root 'Forensics/Private/Persistence/ForensicsPersistence.ps1')
}
$module | Import-Module -Force

Describe 'forensics schema migration and recovery' -Tag Integration {
    InModuleScope HostHunterForensicsMigrationTest {
        BeforeAll {
            if ([IO.Directory]::Exists('/opt/hosthunter-sqlite/lib')) {
                $env:HH_SQLITE_PROVIDER_ROOT = '/opt/hosthunter-sqlite/lib'
            }
        }

        BeforeEach {
            $script:testRoot = Join-Path $TestDrive ([Guid]::NewGuid().ToString('N'))
            $script:persistence = New-HHForensicsPersistenceContext -DataRoot $script:testRoot
            $script:testKey = [byte[]](32..63)
            $script:testAnchor = $null
            $script:keyProvider = {
                [pscustomobject]@{
                    Service = 'HostHunterNextGeneration.Forensics.v1'
                    Account = 'ledger-key'
                    KeyBytes = [byte[]]$script:testKey.Clone()
                }
            }
            $script:anchorReader = { param($Persistence) $null = $Persistence; $script:testAnchor }
            $script:anchorWriter = {
                param($Expected, $New, $Persistence)
                $null = $Expected
                $null = $Persistence
                $script:testAnchor = $New
            }
            $script:context = Open-HHForensicsPersistence `
                -PersistenceContext $script:persistence `
                -ForensicsKeyProvider $script:keyProvider `
                -AnchorReader $script:anchorReader -AnchorWriter $script:anchorWriter `
                -AllowAnchorInitialize
        }

        AfterEach {
            if ($null -ne $script:context) {
                Close-HHForensicsPersistence -Context $script:context
                $script:context = $null
            }
        }

        It 'records exactly schema version one and its committed checksum' {
            $schema = Test-HHForensicsSchema `
                -Connection $script:context.Connection `
                -MigrationPath $script:persistence.MigrationPath `
                -ProviderRoot $script:persistence.ProviderRoot
            $schema.SchemaVersion | Should -Be 1
            @(Invoke-HHSqliteQuery -Connection $script:context.Connection -Sql @'
SELECT version,name,length(sql_checksum) AS checksum_length
FROM forensics_schema_migrations;
'@) | Should -HaveCount 1
            (Invoke-HHSqliteScalar -Connection $script:context.Connection `
                    -Sql 'PRAGMA user_version;') | Should -Be 1
        }

        It 'fingerprints an empty SQLite schema deterministically' {
            $connection = New-HHSqliteConnection `
                -DatabasePath ':memory:' -Mode ReadWriteCreate
            try {
                $actual = Get-HHForensicsSchemaFingerprint -Connection $connection
                $expected = Get-HHForensicsHash -Bytes ([byte[]]::new(0))
                $actual | Should -Be $expected
            }
            finally { $connection.Dispose() }
        }

        It 'rejects missing migrations, invalid initialization, and non-empty initialization' {
            {
                Get-HHForensicsMigrationContent `
                    -MigrationPath (Join-Path $TestDrive 'missing.sql')
            } | Should -Throw -ErrorId 'ForensicsSchemaUnsupported*'
            {
                Initialize-HHForensicsSchema `
                    -Connection $script:context.Connection -DatabaseId ([byte[]](1)) `
                    -InitialStateDigest ([byte[]]::new(32)) `
                    -InitialStateMac ([byte[]]::new(32)) `
                    -InitialProjectionDigest ([byte[]]::new(32)) `
                    -InitialProjectionMac ([byte[]]::new(32)) `
                    -AppliedAtUtc '2026-08-25T00:00:00Z'
            } | Should -Throw '*invalid lengths*'
            {
                Initialize-HHForensicsSchema `
                    -Connection $script:context.Connection -DatabaseId ([byte[]](0..15)) `
                    -InitialStateDigest ([byte[]]::new(32)) `
                    -InitialStateMac ([byte[]]::new(32)) `
                    -InitialProjectionDigest ([byte[]]::new(32)) `
                    -InitialProjectionMac ([byte[]]::new(32)) `
                    -AppliedAtUtc '2026-08-25T00:00:00Z'
            } | Should -Throw -ErrorId 'ForensicsSchemaUnsupported*'
        }

        It 'rolls back a migration whose schema cannot accept the control records' {
            $connection = New-HHSqliteConnection `
                -DatabasePath ':memory:' -Mode ReadWriteCreate
            $migrationPath = Join-Path $TestDrive 'incomplete-forensics.sql'
            [IO.File]::WriteAllText(
                $migrationPath,
                'PRAGMA user_version=1;',
                [Text.UTF8Encoding]::new($false)
            )
            try {
                {
                    Initialize-HHForensicsSchema `
                        -Connection $connection -DatabaseId ([byte[]](0..15)) `
                        -InitialStateDigest ([byte[]]::new(32)) `
                        -InitialStateMac ([byte[]]::new(32)) `
                        -InitialProjectionDigest ([byte[]]::new(32)) `
                        -InitialProjectionMac ([byte[]]::new(32)) `
                        -AppliedAtUtc '2026-08-25T00:00:00Z' `
                        -MigrationPath $migrationPath
                } | Should -Throw
                (Test-HHForensicsDatabaseEmpty -Connection $connection) |
                    Should -BeTrue
                (Invoke-HHSqliteScalar -Connection $connection `
                        -Sql 'PRAGMA user_version;') | Should -Be 0
            }
            finally { $connection.Dispose() }
        }

        It 'rejects a changed migration checksum without repairing it' {
            $null = Invoke-HHSqliteNonQuery -Connection $script:context.Connection -Sql @'
UPDATE forensics_schema_migrations
SET sql_checksum=zeroblob(32)
WHERE version=1;
'@
            Close-HHForensicsPersistence -Context $script:context
            $script:context = $null

            {
                Open-HHForensicsPersistence -PersistenceContext $script:persistence `
                    -ForensicsKeyProvider $script:keyProvider `
                    -AnchorReader $script:anchorReader -AnchorWriter $script:anchorWriter
            } | Should -Throw -ErrorId 'ForensicsIntegrityFailed*'
        }

        It 'rejects schema drift even when the migration ledger is unchanged' {
            $null = Invoke-HHSqliteNonQuery -Connection $script:context.Connection `
                -Sql 'CREATE TABLE unexpected_table(id INTEGER PRIMARY KEY) STRICT;'
            Close-HHForensicsPersistence -Context $script:context
            $script:context = $null

            {
                Open-HHForensicsPersistence -PersistenceContext $script:persistence `
                    -ForensicsKeyProvider $script:keyProvider `
                    -AnchorReader $script:anchorReader -AnchorWriter $script:anchorWriter
            } | Should -Throw -ErrorId 'ForensicsIntegrityFailed*'
        }

        It 'rejects unsupported user version and malformed authenticated state rows' {
            $null = Invoke-HHSqliteNonQuery -Connection $script:context.Connection `
                -Sql 'PRAGMA user_version=2;'
            {
                Test-HHForensicsSchema `
                    -Connection $script:context.Connection `
                    -MigrationPath $script:persistence.MigrationPath
            } | Should -Throw -ErrorId 'ForensicsSchemaUnsupported*'
            $null = Invoke-HHSqliteNonQuery -Connection $script:context.Connection `
                -Sql 'PRAGMA user_version=1; PRAGMA ignore_check_constraints=ON;'
            $null = Invoke-HHSqliteNonQuery -Connection $script:context.Connection `
                -Sql 'UPDATE forensics_state SET state_mac=x''01'' WHERE singleton_id=1;'
            $null = Invoke-HHSqliteNonQuery -Connection $script:context.Connection `
                -Sql 'PRAGMA ignore_check_constraints=OFF;'
            {
                Test-HHForensicsSchema `
                    -Connection $script:context.Connection `
                    -MigrationPath $script:persistence.MigrationPath
            } | Should -Throw -ErrorId 'ForensicsIntegrityFailed*'
        }

        It 'authenticates <ControlField> control metadata' -TestCases @(
            @{
                ControlField = 'migration application time'
                Sql = "UPDATE forensics_schema_migrations SET applied_at_utc='tampered';"
                RequiresMutation = $false
            }
            @{
                ControlField = 'database creation time'
                Sql = "UPDATE forensics_database_identity SET created_at_utc='tampered';"
                RequiresMutation = $false
            }
            @{
                ControlField = 'mutation creation time'
                Sql = "UPDATE forensics_mutations SET created_at_utc='tampered' WHERE sequence=1;"
                RequiresMutation = $true
            }
            @{
                ControlField = 'last mutation identity'
                Sql = "UPDATE forensics_state SET last_mutation_id='tampered' WHERE singleton_id=1;"
                RequiresMutation = $true
            }
        ) {
            param($ControlField, $Sql, $RequiresMutation)

            $null = $ControlField
            if ($RequiresMutation) {
                $payload = Get-HHForensicsHash -Bytes ([byte[]](9))
                $null = Invoke-HHForensicsAnchoredTransaction `
                    -Context $script:context -MutationId control-mutation `
                    -MutationType ControlFixture -RoutingKey fixture `
                    -PayloadDigest $payload -Action {
                        param($Connection, $Transaction, $Key)
                        $null = $Connection
                        $null = $Transaction
                        $null = $Key
                    }
            }
            $null = Invoke-HHSqliteNonQuery -Connection $script:context.Connection -Sql $Sql
            {
                Get-HHForensicsDatabaseHead `
                    -Connection $script:context.Connection `
                    -ForensicsKey $script:context.ForensicsKey `
                    -MigrationPath $script:persistence.MigrationPath
            } | Should -Throw -ErrorId 'ForensicsIntegrityFailed*'
        }

        It 'requires explicit verified anchor advance after commit-seal failure' {
            $oldAnchor = $script:testAnchor
            $script:context.AnchorWriter = { throw 'simulated anchor seal failure' }
            $payload = Get-HHForensicsHash -Bytes ([Text.Encoding]::UTF8.GetBytes('mutation'))
            {
                Invoke-HHForensicsAnchoredTransaction `
                    -Context $script:context -MutationId test-mutation `
                    -MutationType TestMutation -RoutingKey fixture `
                    -PayloadDigest $payload -Action {
                        param($Connection, $Transaction, $Key)
                        $null = $Connection
                        $null = $Transaction
                        $null = $Key
                    }
            } | Should -Throw -ErrorId 'ForensicsCommitUnknown*'
            Close-HHForensicsPersistence -Context $script:context
            $script:context = $null
            $script:testAnchor = $oldAnchor

            {
                Open-HHForensicsPersistence -PersistenceContext $script:persistence `
                    -ForensicsKeyProvider $script:keyProvider `
                    -AnchorReader $script:anchorReader -AnchorWriter $script:anchorWriter
            } | Should -Throw -ErrorId 'ForensicsAnchorAdvanceRequired*'

            $script:context = Open-HHForensicsPersistence `
                -PersistenceContext $script:persistence `
                -ForensicsKeyProvider $script:keyProvider `
                -AnchorReader $script:anchorReader -AnchorWriter $script:anchorWriter `
                -AllowAnchorAdvance
            $script:context.Anchor.Generation | Should -Be 1
            $script:testAnchor.Generation | Should -Be 1
        }
    }
}
