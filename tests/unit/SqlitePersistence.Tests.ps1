$sourceRoot = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
    Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration'
}
else {
    $env:HH_TEST_SOURCE_ROOT
}
Import-Module (Join-Path $sourceRoot 'HostHunterNextGeneration.psd1') -Force
if ([IO.Directory]::Exists('/opt/hosthunter-sqlite/lib')) {
    $env:HH_SQLITE_PROVIDER_ROOT = '/opt/hosthunter-sqlite/lib'
}

Describe 'SQLite persistence foundation' -Tag Unit {
    BeforeEach {
        $env:HH_COVERAGE_CASE = [Guid]::NewGuid().ToString('N')
    }

    InModuleScope HostHunterNextGeneration {
        It 'maps only the two qualified Linux container runtime identifiers' {
            Resolve-HHSqliteControllerRid -OperatingSystem Linux -Architecture Arm64 |
                Should -BeExactly 'linux-arm64'
            Resolve-HHSqliteControllerRid -OperatingSystem Linux -Architecture X64 |
                Should -BeExactly 'linux-x64'
            {
                Resolve-HHSqliteControllerRid `
                    -OperatingSystem Linux `
                    -Architecture X64 `
                    -RuntimeIdentifier linux-musl-x64
            } | Should -Throw -ErrorId 'PersistenceRuntimeUnsupported*'
            {
                Resolve-HHSqliteControllerRid -OperatingSystem Windows -Architecture Arm64
            } | Should -Throw -ErrorId 'PersistenceRuntimeUnsupported*'
        }

        It 'resolves current and explicit provider roots and native asset names' -Skip:(!$IsLinux) {
            Resolve-HHSqliteControllerRid | Should -BeIn @('linux-arm64', 'linux-x64')
            Get-HHSqliteProviderAssetName -ControllerRid linux-x64 |
                Should -Contain 'libe_sqlite3.so'

            Resolve-HHSqliteProviderRoot -ProviderRoot $TestDrive -ControllerRid linux-x64 |
                Should -Be (Join-Path $TestDrive 'linux-x64')
            $savedEnvironment = $env:HH_SQLITE_PROVIDER_ROOT
            $savedOverride = $script:HHSqliteProviderRootOverride
            try {
                $script:HHSqliteProviderRootOverride = $TestDrive
                Resolve-HHSqliteProviderRoot -ControllerRid linux-x64 |
                    Should -Be (Join-Path $TestDrive 'linux-x64')
                $script:HHSqliteProviderRootOverride = $null
                $env:HH_SQLITE_PROVIDER_ROOT = $TestDrive
                Resolve-HHSqliteProviderRoot -ControllerRid linux-x64 |
                    Should -Be (Join-Path $TestDrive 'linux-x64')
            }
            finally {
                $env:HH_SQLITE_PROVIDER_ROOT = $savedEnvironment
                $script:HHSqliteProviderRootOverride = $savedOverride
            }
        }

        It 'fails closed for a missing packaged provider asset' {
            $script:HHSqliteProviderInitialized = $false
            { Initialize-HHSqliteProvider -ProviderRoot $TestDrive } |
                Should -Throw -ErrorId 'PersistenceRuntimeUnsupported*'
        }

        It 'derives purpose-separated keys and authenticates row identity' {
            $masterKey = [byte[]](0..31)
            $plaintext = [Text.Encoding]::UTF8.GetBytes('complete command text')
            $identity = [Text.Encoding]::UTF8.GetBytes('invocations/request/001122')
            $wrongIdentity = [Text.Encoding]::UTF8.GetBytes('invocations/request/ffeedd')

            $rowKey = Get-HHPersistenceDerivedKey -MasterKey $masterKey -Purpose RowEncryption
            $auditKey = Get-HHPersistenceDerivedKey -MasterKey $masterKey -Purpose AuditIntegrity
            $rowKey.Length | Should -Be 32
            [Convert]::ToHexString($rowKey) |
                Should -Not -BeExactly ([Convert]::ToHexString($auditKey))

            $first = Protect-HHPersistenceValue `
                -Plaintext $plaintext `
                -MasterKey $masterKey `
                -AssociatedData $identity
            $second = Protect-HHPersistenceValue `
                -Plaintext $plaintext `
                -MasterKey $masterKey `
                -AssociatedData $identity
            [Convert]::ToHexString($first) |
                Should -Not -BeExactly ([Convert]::ToHexString($second))
            [Text.Encoding]::UTF8.GetString((Unprotect-HHPersistenceValue `
                        -Envelope $first `
                        -MasterKey $masterKey `
                        -AssociatedData $identity)) | Should -BeExactly 'complete command text'
            {
                Unprotect-HHPersistenceValue `
                    -Envelope $first `
                    -MasterKey $masterKey `
                    -AssociatedData $wrongIdentity
            } | Should -Throw -ErrorId 'AuditIntegrityFailed*'
        }

        It 'rejects malformed encrypted values and invalid MAC keys' {
            {
                Unprotect-HHPersistenceValue `
                    -Envelope ([byte[]](1, 2, 3)) `
                    -MasterKey ([byte[]](0..31)) `
                    -AssociatedData ([byte[]]::new(0))
            } | Should -Throw -ErrorId 'AuditIntegrityFailed*'
            {
                Get-HHPersistenceMac -Key ([byte[]]::new(31)) -Bytes ([byte[]]::new(0))
            } | Should -Throw '*32 bytes*'
            (Test-HHPersistenceBytesEqual -Left ([byte[]](1, 2)) -Right ([byte[]](1))) |
                Should -BeFalse
        }

        It 'round-trips and authenticates the fixed-size external anchor' {
            $masterKey = [byte[]](0..31)
            $anchor = [pscustomobject]@{
                DatabaseId = [byte[]](0..15)
                LedgerId = [byte[]](16..31)
                SchemaVersion = 1
                AuditSequence = 42L
                AuditMac = [byte[]](32..63)
                TargetGeneration = 7L
                TargetStateMac = [byte[]](64..95)
                SchemaFingerprint = [byte[]](96..127)
            }
            $artifact = ConvertTo-HHPersistenceAnchorArtifact `
                -Anchor $anchor `
                -MasterKey $masterKey
            $artifact.Length | Should -Be 196
            $decoded = ConvertFrom-HHPersistenceAnchorArtifact `
                -Artifact $artifact `
                -MasterKey $masterKey
            $decoded.AuditSequence | Should -Be 42
            $decoded.TargetGeneration | Should -Be 7
            [Convert]::ToHexString($decoded.TargetStateMac) |
                Should -BeExactly ([Convert]::ToHexString($anchor.TargetStateMac))

            $tampered = [byte[]]$artifact.Clone()
            $tampered[100] = $tampered[100] -bxor 1
            {
                ConvertFrom-HHPersistenceAnchorArtifact `
                    -Artifact $tampered `
                    -MasterKey $masterKey
            } | Should -Throw -ErrorId 'AuditIntegrityFailed*'
        }

        It 'rejects incomplete, invalid, short, and wrong-magic anchor artifacts' {
            $masterKey = [byte[]](0..31)
            $incomplete = [pscustomobject]@{ DatabaseId = [byte[]](0..15) }
            { ConvertTo-HHPersistenceAnchorArtifact -Anchor $incomplete -MasterKey $masterKey } |
                Should -Throw '*missing LedgerId*'
            $invalid = [pscustomobject]@{
                DatabaseId = [byte[]](0..15)
                LedgerId = [byte[]](16..31)
                SchemaVersion = 2
                AuditSequence = 0L
                AuditMac = [byte[]]::new(32)
                TargetGeneration = 0L
                TargetStateMac = [byte[]]::new(32)
                SchemaFingerprint = [byte[]]::new(32)
            }
            { ConvertTo-HHPersistenceAnchorArtifact -Anchor $invalid -MasterKey $masterKey } |
                Should -Throw '*fields are invalid*'
            $partialConfiguration = $invalid.PSObject.Copy()
            $partialConfiguration.SchemaVersion = 1
            $partialConfiguration | Add-Member -NotePropertyName ConfigurationGeneration `
                -NotePropertyValue 0
            {
                ConvertTo-HHPersistenceAnchorArtifact `
                    -Anchor $partialConfiguration -MasterKey $masterKey
            } | Should -Throw '*configuration fields are incomplete*'
            { ConvertFrom-HHPersistenceAnchorArtifact -Artifact ([byte[]](1, 2, 3)) `
                    -MasterKey $masterKey } | Should -Throw -ErrorId 'AuditIntegrityFailed*'
            $wrongMagic = [byte[]]::new(196)
            [Text.Encoding]::ASCII.GetBytes('NOTANCHR').CopyTo($wrongMagic, 0)
            { ConvertFrom-HHPersistenceAnchorArtifact -Artifact $wrongMagic -MasterKey $masterKey } |
                Should -Throw -ErrorId 'AuditIntegrityFailed*'
        }

        It 'writes a mode-0600 anchor with exact compare-and-swap semantics' -Skip:$IsWindows {
            $path = Join-Path $TestDrive 'audit/anchor.bin'
            $first = [byte[]](0..31)
            $second = [byte[]](32..63)
            Write-HHFilePersistenceAnchor -Path $path -ExpectedArtifact $null -NewArtifact $first
            [IO.File]::GetUnixFileMode($path) |
                Should -Be ([IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite)
            {
                Write-HHFilePersistenceAnchor `
                    -Path $path `
                    -ExpectedArtifact $null `
                    -NewArtifact $second
            } | Should -Throw -ErrorId 'AuditIntegrityFailed*'
            Write-HHFilePersistenceAnchor `
                -Path $path `
                -ExpectedArtifact $first `
                -NewArtifact $second
            [Convert]::ToHexString([IO.File]::ReadAllBytes($path)) |
                Should -BeExactly ([Convert]::ToHexString($second))
        }

        It 'rejects linked and non-private anchor files and cleans failed staging' -Skip:$IsWindows {
            $masterKey = [byte[]](0..31)
            $real = Join-Path $TestDrive 'real-anchor.bin'
            $link = Join-Path $TestDrive 'linked-anchor.bin'
            [IO.File]::WriteAllBytes($real, [byte[]]::new(196))
            [IO.File]::SetUnixFileMode($real, [IO.UnixFileMode]::UserRead)
            { Read-HHFilePersistenceAnchor -Path $real -MasterKey $masterKey } |
                Should -Throw -ErrorId 'PersistencePathUnsafe*'
            [IO.File]::SetUnixFileMode(
                $real,
                [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite
            )
            [IO.File]::CreateSymbolicLink($link, $real) | Out-Null
            { Read-HHFilePersistenceAnchor -Path $link -MasterKey $masterKey } |
                Should -Throw -ErrorId 'PersistencePathUnsafe*'
            Read-HHFilePersistenceAnchor -Path (Join-Path $TestDrive 'missing-anchor.bin') `
                -MasterKey $masterKey | Should -BeNullOrEmpty

            $directoryDestination = Join-Path $TestDrive 'anchor-directory'
            [IO.Directory]::CreateDirectory($directoryDestination) | Out-Null
            { Write-HHFilePersistenceAnchor -Path $directoryDestination `
                    -ExpectedArtifact $null -NewArtifact ([byte[]](0..31)) } | Should -Throw
            @(Get-ChildItem -LiteralPath $TestDrive -Filter 'anchor-directory.*.tmp').Count |
                Should -Be 0
        }

        It 'uses injected anchor reader and writer seams without filesystem fallback' {
            $context = Get-HHPersistenceContext `
                -DataRoot (Join-Path $TestDrive ([Guid]::NewGuid().ToString('N')))
            $masterKey = [byte[]](0..31)
            $anchor = [pscustomobject]@{
                DatabaseId = [byte[]](0..15)
                LedgerId = [byte[]](16..31)
                SchemaVersion = 1
                AuditSequence = 0L
                AuditMac = [byte[]]::new(32)
                TargetGeneration = 0L
                TargetStateMac = [byte[]]::new(32)
                SchemaFingerprint = [byte[]]::new(32)
            }
            $readerValue = [pscustomobject]@{ Marker = 'injected' }
            (Read-HHPersistenceAnchor -PersistenceContext $context -MasterKey $masterKey `
                    -AnchorReader { $readerValue }.GetNewClosure()).Marker |
                Should -BeExactly injected
            $writeState = [pscustomobject]@{ Count = 0; Length = 0 }
            $writer = {
                param($PersistenceContext, $ExpectedArtifact, $NewArtifact, $Key)
                $null = $PersistenceContext, $ExpectedArtifact, $Key
                $writeState.Count++
                $writeState.Length = $NewArtifact.Length
            }.GetNewClosure()
            Write-HHPersistenceAnchor -PersistenceContext $context -Anchor $anchor `
                -MasterKey $masterKey -ExpectedArtifact $null -AnchorWriter $writer
            $writeState.Count | Should -Be 1
            $writeState.Length | Should -Be 196
            Test-Path -LiteralPath $context.AnchorPath | Should -BeFalse
        }

        It 'resolves a contained private state tree and rejects legacy state' {
            $root = Join-Path $TestDrive 'state'
            $context = Get-HHPersistenceContext -DataRoot $root
            $context.DatabasePath | Should -Be (Join-Path $root 'hosthunter.db')
            $context.RecoveryRoot | Should -Be (Join-Path $root 'recovery')
            Test-HHPersistencePathContained -Root $root -Candidate $context.OutputRoot |
                Should -BeTrue
            Test-HHPersistencePathContained -Root $root -Candidate (Join-Path $root '../escape') |
                Should -BeFalse

            Initialize-HHPersistenceRoot -PersistenceContext $context
            [IO.File]::WriteAllText((Join-Path $root 'targets.json'), '{}')
            {
                Assert-HHLegacyPersistenceAbsent -PersistenceContext $context
            } | Should -Throw -ErrorId 'LegacyPersistenceMigrationRequired*'
        }

    It 'creates and reopens an exact schema-v5 database using parameterized blobs' {
            $root = Join-Path $TestDrive 'database'
            $context = Get-HHPersistenceContext -DataRoot $root
            $masterKey = [byte[]](0..31)
            $writtenAnchor = $null
            $anchorWriter = {
                param($PersistenceContext, $ExpectedArtifact, $NewArtifact, $Key)
                $null = $PersistenceContext, $ExpectedArtifact, $Key
                $script:writtenAnchor = [byte[]]$NewArtifact.Clone()
            }

            $created = Initialize-HHSqliteDatabase `
                -PersistenceContext $context `
                -MasterKey $masterKey `
                -AnchorWriter $anchorWriter `
                -Clock { [DateTimeOffset]'2026-08-24T00:00:00Z' }
        $created.SchemaVersion | Should -Be 5
        $script:writtenAnchor.Length | Should -Be 276

            $connection = New-HHSqliteConnection -DatabasePath $context.DatabasePath
            try {
                $databaseId = Invoke-HHSqliteScalar `
                    -Connection $connection `
                    -Sql 'SELECT database_id FROM database_identity WHERE singleton_id = @id;' `
                    -Parameters @{ id = 1 }
                ([byte[]]$databaseId).Length | Should -Be 16
                (Invoke-HHSqliteScalar -Connection $connection -Sql 'PRAGMA journal_mode;') |
                    Should -BeExactly 'wal'
                $verified = Test-HHSqliteDatabaseSchema `
                    -Connection $connection `
                    -MigrationPath $context.MigrationPath
                $verified.SchemaVersion | Should -Be 5
            }
            finally {
                $connection.Dispose()
            }

            $reopened = Initialize-HHSqliteDatabase `
                -PersistenceContext $context `
                -MasterKey $masterKey `
                -AnchorWriter $anchorWriter
            [Convert]::ToHexString($reopened.DatabaseId) |
                Should -BeExactly ([Convert]::ToHexString($created.DatabaseId))
        }

        It 'fails closed when an allowlisted schema object is altered' {
            $root = Join-Path $TestDrive 'tamper'
            $context = Get-HHPersistenceContext -DataRoot $root
            $masterKey = [byte[]](0..31)
            $null = Initialize-HHSqliteDatabase `
                -PersistenceContext $context `
                -MasterKey $masterKey `
                -AnchorWriter { }
            $connection = New-HHSqliteConnection -DatabasePath $context.DatabasePath
            try {
                $null = Invoke-HHSqliteNonQuery `
                    -Connection $connection `
                    -Sql 'DROP INDEX ix_batches_operation_created;'
                {
                    Test-HHSqliteDatabaseSchema `
                        -Connection $connection `
                        -MigrationPath $context.MigrationPath
                } | Should -Throw -ErrorId 'PersistenceSchemaUnsupported*'
            }
            finally {
                $connection.Dispose()
            }
        }

        It 'fails closed when migration integrity metadata is malformed' {
            $root = Join-Path $TestDrive 'migration-tamper'
            $context = Get-HHPersistenceContext -DataRoot $root
            $null = Initialize-HHSqliteDatabase `
                -PersistenceContext $context `
                -MasterKey ([byte[]](0..31)) `
                -AnchorWriter { }
            $connection = New-HHSqliteConnection -DatabasePath $context.DatabasePath
            try {
                $alteredMigration = Join-Path $TestDrive 'altered-migration.sql'
                $migrationText = [IO.File]::ReadAllText($context.MigrationPath)
                [IO.File]::WriteAllText($alteredMigration, "$migrationText`n")
                {
                    Test-HHSqliteDatabaseSchema `
                        -Connection $connection `
                        -MigrationPath $alteredMigration
                } | Should -Throw -ErrorId 'PersistenceSchemaUnsupported*'
            }
            finally { $connection.Dispose() }
        }

        It 'rejects missing and malformed persistence head rows' {
            $root = Join-Path $TestDrive 'head-integrity'
            $context = Get-HHPersistenceContext -DataRoot $root
            $null = Initialize-HHSqliteDatabase `
                -PersistenceContext $context `
                -MasterKey ([byte[]](0..31)) `
                -AnchorWriter { }
            $connection = New-HHSqliteConnection -DatabasePath $context.DatabasePath
            try {
                $schema = Test-HHSqliteDatabaseSchema `
                    -Connection $connection `
                    -MigrationPath $context.MigrationPath
                $null = Invoke-HHSqliteNonQuery `
                    -Connection $connection `
                    -Sql 'PRAGMA ignore_check_constraints = ON;'
                $null = Invoke-HHSqliteNonQuery `
                    -Connection $connection `
                    -Sql 'UPDATE target_store_state SET target_state_mac = @mac WHERE singleton_id = 1;' `
                    -Parameters @{ mac = [byte[]](1, 2, 3) }
                {
                    Get-HHSqlitePersistenceHead `
                        -Connection $connection `
                        -SchemaFingerprint $schema.SchemaFingerprint
                } | Should -Throw -ErrorId 'AuditIntegrityFailed*'

                $null = Invoke-HHSqliteNonQuery `
                    -Connection $connection `
                    -Sql 'DELETE FROM target_store_state WHERE singleton_id = 1;'
                {
                    Get-HHSqlitePersistenceHead `
                        -Connection $connection `
                        -SchemaFingerprint $schema.SchemaFingerprint
                } | Should -Throw -ErrorId 'AuditIntegrityFailed*'
            }
            finally { $connection.Dispose() }
        }

        It 'rejects negative generations and malformed audit event heads' {
            $root = Join-Path $TestDrive 'negative-head'
            $context = Get-HHPersistenceContext -DataRoot $root
            $masterKey = [byte[]](0..31)
            $null = Initialize-HHSqliteDatabase `
                -PersistenceContext $context `
                -MasterKey $masterKey `
                -AnchorWriter { }
            $connection = New-HHSqliteConnection -DatabasePath $context.DatabasePath
            try {
                $schema = Test-HHSqliteDatabaseSchema `
                    -Connection $connection `
                    -MigrationPath $context.MigrationPath
                $null = Invoke-HHSqliteNonQuery `
                    -Connection $connection `
                    -Sql 'PRAGMA ignore_check_constraints = ON; PRAGMA foreign_keys = OFF;'
                $null = Invoke-HHSqliteNonQuery `
                    -Connection $connection `
                    -Sql 'UPDATE target_store_state SET generation = -1 WHERE singleton_id = 1;'
                {
                    Get-HHSqlitePersistenceHead `
                        -Connection $connection `
                        -SchemaFingerprint $schema.SchemaFingerprint
                } | Should -Throw -ErrorId 'AuditIntegrityFailed*'

                $null = Invoke-HHSqliteNonQuery `
                    -Connection $connection `
                    -Sql 'UPDATE target_store_state SET generation = 0 WHERE singleton_id = 1;'
                $null = Invoke-HHSqliteNonQuery `
                    -Connection $connection `
                    -Sql @'
INSERT INTO audit_events(
    sequence,event_id,event_kind,event_at_utc,invocation_id,target_mutation_id,
    projection_hash,related_envelope_hash,previous_mac,event_mac
)
VALUES(-1,@event,'Test',@at,NULL,@mutation,@projection,@related,@previous,@mac);
'@ `
                    -Parameters @{
                        event = [byte[]](0..15)
                        at = '2026-08-24T00:00:00Z'
                        mutation = [byte[]](16..31)
                        projection = [byte[]]::new(32)
                        related = [byte[]]::new(32)
                        previous = [byte[]]::new(32)
                        mac = [byte[]](1, 2, 3)
                    }
                {
                    Get-HHSqlitePersistenceHead `
                        -Connection $connection `
                        -SchemaFingerprint $schema.SchemaFingerprint
                } | Should -Throw -ErrorId 'AuditIntegrityFailed*'
            }
            finally { $connection.Dispose() }
        }

        It 'covers prefixed and null parameters, null scalars, and query materialization' {
            $connection = New-HHSqliteConnection -DatabasePath ':memory:' -Mode ReadWriteCreate
            try {
                $command = $connection.CreateCommand()
                try {
                    Add-HHSqliteParameter -Command $command -Parameters ([ordered]@{
                            ':named' = 7
                            missing = $null
                            bytes = [byte[]](1, 2, 3)
                        })
                    $command.Parameters[':named'].Value | Should -Be 7
                    $command.Parameters['@missing'].Value | Should -Be ([DBNull]::Value)
                    ([byte[]]$command.Parameters['@bytes'].Value).Length | Should -Be 3
                }
                finally { $command.Dispose() }

                Invoke-HHSqliteScalar -Connection $connection -Sql 'SELECT NULL;' |
                    Should -BeNullOrEmpty
                $rows = @(Invoke-HHSqliteQuery -Connection $connection `
                        -Sql 'SELECT 1 AS value, NULL AS optional;')
                $rows.Count | Should -Be 1
                $rows[0].value | Should -Be 1
                $rows[0].optional | Should -BeNullOrEmpty
                @(Invoke-HHSqliteQuery -Connection $connection `
                        -Sql 'SELECT 1 AS value WHERE 0;').Count | Should -Be 0
            }
            finally { $connection.Dispose() }
        }

        It 'maps database-open failure and missing migration to stable errors' {
            $readOnlyPath = Join-Path $TestDrive 'read-only.db'
            $created = New-HHSqliteConnection -DatabasePath $readOnlyPath -Mode ReadWriteCreate
            $created.Dispose()
            $readOnly = New-HHSqliteConnection -DatabasePath $readOnlyPath -Mode ReadOnly
            try {
                (Invoke-HHSqliteScalar -Connection $readOnly -Sql 'SELECT 1;') |
                    Should -Be 1
            }
            finally { $readOnly.Dispose() }
            {
                New-HHSqliteConnection -DatabasePath (Join-Path $TestDrive 'missing.db') -Mode ReadWrite
            } | Should -Throw -ErrorId 'PersistenceRuntimeUnsupported*'
            {
                Get-HHSqliteMigrationContent -MigrationPath (Join-Path $TestDrive 'missing.sql')
            } | Should -Throw -ErrorId 'PersistenceSchemaUnsupported*'
        }

        It 'rejects a missing migration entry path before enumerating its directory' {
            $missing = Join-Path $TestDrive 'missing/0001_initial_sqlite.sql'
            {
                Get-HHSqliteMigrationPath -MigrationPath $missing
            } | Should -Throw -ErrorId 'PersistenceSchemaUnsupported*'
        }

        It 'rejects absent and misnumbered migration identity rows' {
            $connection = [pscustomobject]@{ DataSource = 'mock.db' }
            $migrationPath = Join-Path (Get-Module HostHunterNextGeneration).ModuleBase `
                'Private/Migrations/0001_initial_sqlite.sql'
            Mock Invoke-HHSqliteScalar { 'ok' }
            Mock Get-HHSqliteSchemaFingerprintFromConnection { [byte[]]::new(32) }

            Mock Invoke-HHSqliteQuery {
                if ($Sql -match 'foreign_key_check') { return @() }
                if ($Sql -match 'schema_migrations') { return @() }
                throw 'unexpected query'
            }
            {
                Test-HHSqliteDatabaseSchema -Connection $connection `
                    -MigrationPath $migrationPath
            } | Should -Throw -ErrorId 'PersistenceSchemaUnsupported*'

            Mock Invoke-HHSqliteQuery {
                if ($Sql -match 'foreign_key_check') { return @() }
                if ($Sql -match 'schema_migrations') {
                    return [pscustomobject]@{
                        version = 2L
                        name = '0001_initial_sqlite'
                        sql_checksum = [byte[]]::new(32)
                    }
                }
                throw 'unexpected query'
            }
            {
                Test-HHSqliteDatabaseSchema -Connection $connection `
                    -MigrationPath $migrationPath
            } | Should -Throw -ErrorId 'PersistenceSchemaUnsupported*'
        }

    It 'rejects an upgrade request that is already at the latest schema' {
            {
                Update-HHSqliteDatabaseToLatest `
                    -Connection ([pscustomobject]@{ DataSource = 'mock.db' }) `
                    -PersistenceContext ([pscustomobject]@{}) `
                    -MasterKey ([byte[]]::new(32)) `
                -ExistingSchema ([pscustomobject]@{ SchemaVersion = 5 }) `
                    -ExistingAnchor ([pscustomobject]@{})
            } | Should -Throw -ErrorId 'PersistenceSchemaUnsupported*'
        }

        It 'repairs only an unmutated legacy migration seal with matching authenticated state' {
            # Old uncovered outcomes: SqlitePersistence.ps1 L493 clause-0,
            # L499 clause-0, and L522 clause-0.
            $connection = [pscustomobject]@{ DataSource = 'repair-fixture.db' }
            $context = [pscustomobject]@{ MigrationPath = 'fixture.sql' }
            $key = [byte[]]::new(32)
            $schema = [pscustomobject]@{
                SchemaVersion = 2
                SchemaFingerprint = [byte[]]::new(32)
            }

            Mock Read-HHPersistenceAnchor { $null }
            (Repair-HHSqliteMigrationSeal `
                    -Connection $connection `
                    -PersistenceContext $context `
                    -MasterKey $key `
                    -Schema $schema) | Should -Be $schema

            Mock Read-HHPersistenceAnchor {
                [pscustomobject]@{ ConfigurationGeneration = 0L }
            }
            (Repair-HHSqliteMigrationSeal `
                    -Connection $connection `
                    -PersistenceContext $context `
                    -MasterKey $key `
                    -Schema $schema) | Should -Be $schema

            $legacyAnchor = [pscustomobject]@{ Artifact = [byte[]]::new(32) }
            Mock Read-HHPersistenceAnchor { $legacyAnchor }
            Mock Read-HHConfigurationRepositorySnapshot {
                [pscustomobject]@{ Generation = 1L; EscalationMethod = $null }
            }
            {
                Repair-HHSqliteMigrationSeal `
                    -Connection $connection `
                    -PersistenceContext $context `
                    -MasterKey $key `
                    -Schema $schema
            } | Should -Throw -ErrorId 'AuditRecoveryRequired*'

            Mock Read-HHConfigurationRepositorySnapshot {
                [pscustomobject]@{ Generation = 0L; EscalationMethod = 'WindowsTokenPrivilege' }
            }
            {
                Repair-HHSqliteMigrationSeal `
                    -Connection $connection `
                    -PersistenceContext $context `
                    -MasterKey $key `
                    -Schema $schema
            } | Should -Throw -ErrorId 'AuditRecoveryRequired*'

            Mock Read-HHConfigurationRepositorySnapshot {
                [pscustomobject]@{ Generation = 0L; EscalationMethod = $null }
            }
            Mock Test-HHSqliteAuditChain {
                [pscustomobject]@{ Sequence = 0L; LastMac = [byte[]]::new(32) }
            }
            Mock Read-HHTargetRepositorySnapshot {
                [pscustomobject]@{
                    Generation = 0L
                    StateEvidence = [pscustomobject]@{ TargetStateMac = [byte[]]::new(32) }
                }
            }
            Mock Invoke-HHSqliteQuery {
                [pscustomobject]@{
                    database_id = [byte[]]::new(16)
                    ledger_id = [byte[]]::new(16)
                }
            }
            Mock Get-HHExpectedSqliteSchemaFingerprint { [byte[]]::new(32) }
            Mock Test-HHPersistenceAnchorState { [pscustomobject]@{ IsEqual = $false } }
            {
                Repair-HHSqliteMigrationSeal `
                    -Connection $connection `
                    -PersistenceContext $context `
                    -MasterKey $key `
                    -Schema $schema
            } | Should -Throw -ErrorId 'AuditRecoveryRequired*'
        }

        It 'rejects a missing singleton state after schema verification' {
            $root = Join-Path $TestDrive 'identity-tamper'
            $context = Get-HHPersistenceContext -DataRoot $root
            $null = Initialize-HHSqliteDatabase -PersistenceContext $context `
                -MasterKey ([byte[]](0..31)) -AnchorWriter { }
            $connection = New-HHSqliteConnection -DatabasePath $context.DatabasePath
            try {
                $null = Invoke-HHSqliteNonQuery -Connection $connection `
                    -Sql 'DELETE FROM target_store_state WHERE singleton_id = 1;'
                {
                    Test-HHSqliteDatabaseSchema -Connection $connection `
                        -MigrationPath $context.MigrationPath
                } | Should -Throw -ErrorId 'PersistenceSchemaUnsupported*'
            }
            finally { $connection.Dispose() }
        }

        It 'rolls back an invalid initial migration and releases its writer lock' {
            $root = Join-Path $TestDrive 'invalid-initial-migration'
            $context = Get-HHPersistenceContext -DataRoot $root
            $invalidMigration = Join-Path $TestDrive 'invalid.sql'
            [IO.File]::WriteAllText($invalidMigration, 'CREATE TABLE broken(')
            $context.MigrationPath = $invalidMigration
            {
                Initialize-HHSqliteDatabase -PersistenceContext $context `
                    -MasterKey ([byte[]](0..31)) -AnchorWriter { }
            } | Should -Throw
            Test-Path -LiteralPath $context.AnchorPath | Should -BeFalse
            $lock = Enter-HHPersistenceFileLock `
                -Path $context.WriterLockPath -FailureId PersistenceBusy
            Exit-HHPersistenceFileLock -LockContext $lock
        }

        It 'fails the schema gate for a real SQLite foreign-key violation' {
            $root = Join-Path $TestDrive 'foreign-key-tamper'
            $context = Get-HHPersistenceContext -DataRoot $root
            $null = Initialize-HHSqliteDatabase -PersistenceContext $context `
                -MasterKey ([byte[]](0..31)) -AnchorWriter { }
            $connection = New-HHSqliteConnection -DatabasePath $context.DatabasePath
            try {
                $null = Invoke-HHSqliteNonQuery -Connection $connection -Sql 'PRAGMA foreign_keys = OFF;'
                $null = Invoke-HHSqliteNonQuery -Connection $connection -Sql @'
INSERT INTO remote_operation_events(
    invocation_id,ordinal,event_kind,event_at_utc,evidence_envelope,evidence_hash
) VALUES(@invocation,0,'Completed',@at,NULL,@hash);
'@ -Parameters @{
                    invocation = [byte[]](0..15)
                    at = '2026-08-24T00:00:00Z'
                    hash = [byte[]]::new(32)
                }
                $null = Invoke-HHSqliteNonQuery -Connection $connection -Sql 'PRAGMA foreign_keys = ON;'
                { Test-HHSqliteDatabaseSchema -Connection $connection `
                        -MigrationPath $context.MigrationPath } |
                    Should -Throw -ErrorId 'AuditIntegrityFailed*'
            }
            finally { $connection.Dispose() }
        }

        It 'initializes the locked provider through injected loader and batteries seams' {
            $script:HHSqliteProviderInitialized = $false
            $loaderState = [pscustomobject]@{ Count = 0 }
            $loader = {
                param($Path)
                $loaderState.Count++
                if ([IO.Path]::GetFileName($Path) -in @(
                        'Humanizer.dll', 'Json.More.dll',
                        'JsonPointer.Net.dll', 'JsonSchema.Net.dll'
                    )) {
                    [Reflection.Assembly]::LoadFile($Path)
                }
                else { [Reflection.Assembly]::LoadFrom($Path) }
            }.GetNewClosure()
            $batteryState = [pscustomobject]@{ Count = 0 }
            $batteries = {
                $batteryState.Count++
                [SQLitePCL.Batteries_V2]::Init()
            }.GetNewClosure()
            Initialize-HHSqliteProvider -ProviderRoot '/opt/hosthunter-sqlite/lib' `
                -AssemblyLoader $loader -BatteriesInitializer $batteries
            $loaderState.Count | Should -Be 8
            $batteryState.Count | Should -Be 1
            $script:HHSqliteProviderInitialized | Should -BeTrue
        }
    }
}
