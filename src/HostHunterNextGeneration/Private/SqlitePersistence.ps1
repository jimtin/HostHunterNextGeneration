Set-StrictMode -Version Latest

$script:HHSqliteSchemaVersion = 1
$script:HHSqliteMigrationName = '0001_initial_sqlite'
$script:HHSqliteCommandTimeoutSeconds = 5

function New-HHSqliteConnection {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Constructs and opens a scoped connection; callers own persistence mutation policy.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DatabasePath,
        [ValidateSet('ReadOnly', 'ReadWrite', 'ReadWriteCreate')][string]$Mode = 'ReadWrite',
        [string]$ProviderRoot
    )

    Initialize-HHSqliteProvider -ProviderRoot $ProviderRoot
    $builder = [Microsoft.Data.Sqlite.SqliteConnectionStringBuilder]::new()
    $builder.DataSource = $DatabasePath
    $builder.Pooling = $false
    $builder.Cache = [Microsoft.Data.Sqlite.SqliteCacheMode]::Private
    $builder.Mode = switch ($Mode) {
        'ReadOnly' { [Microsoft.Data.Sqlite.SqliteOpenMode]::ReadOnly }
        'ReadWriteCreate' { [Microsoft.Data.Sqlite.SqliteOpenMode]::ReadWriteCreate }
        default { [Microsoft.Data.Sqlite.SqliteOpenMode]::ReadWrite }
    }
    $connection = [Microsoft.Data.Sqlite.SqliteConnection]::new($builder.ConnectionString)
    try {
        $connection.Open()
        $command = $connection.CreateCommand()
        try {
            $command.CommandTimeout = $script:HHSqliteCommandTimeoutSeconds
            $command.CommandText = 'PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;'
            $null = $command.ExecuteNonQuery()
        }
        finally {
            $command.Dispose()
        }
        return $connection
    }
    catch {
        $connection.Dispose()
        Stop-HHPersistenceOperation `
            -ErrorId 'PersistenceRuntimeUnsupported' `
            -Message 'The HostHunter SQLite provider could not open the database.' `
            -Category ([System.Management.Automation.ErrorCategory]::OpenError) `
            -TargetObject $DatabasePath `
            -InnerException $_.Exception
    }
}

function Add-HHSqliteParameter {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Command,
        [Parameter(Mandatory)][Collections.IDictionary]$Parameters
    )

    foreach ($entry in $Parameters.GetEnumerator()) {
        $name = if ([string]$entry.Key -match '^[@:$]') {
            [string]$entry.Key
        }
        else { "@$($entry.Key)" }
        if ($null -eq $entry.Value) {
            $value = [DBNull]::Value
        }
        elseif ($entry.Value -is [byte[]]) {
            $value = [byte[]]$entry.Value
        }
        else {
            $value = $entry.Value
        }
        $null = $Command.Parameters.AddWithValue($name, $value)
    }
}

function New-HHSqliteCommand {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Creates an in-memory command object without executing it.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Connection,
        [Parameter(Mandatory)][string]$Sql,
        [Collections.IDictionary]$Parameters = @{},
        [AllowNull()][object]$Transaction
    )

    $command = $Connection.CreateCommand()
    $command.CommandText = $Sql
    $command.CommandTimeout = $script:HHSqliteCommandTimeoutSeconds
    if ($null -ne $Transaction) {
        $command.Transaction = $Transaction
    }
    Add-HHSqliteParameter -Command $command -Parameters $Parameters
    return $command
}

function Invoke-HHSqliteNonQuery {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)][object]$Connection,
        [Parameter(Mandatory)][string]$Sql,
        [Collections.IDictionary]$Parameters = @{},
        [AllowNull()][object]$Transaction
    )

    $command = New-HHSqliteCommand @PSBoundParameters
    try {
        return $command.ExecuteNonQuery()
    }
    finally {
        $command.Dispose()
    }
}

function Invoke-HHSqliteScalar {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Connection,
        [Parameter(Mandatory)][string]$Sql,
        [Collections.IDictionary]$Parameters = @{},
        [AllowNull()][object]$Transaction
    )

    $command = New-HHSqliteCommand @PSBoundParameters
    try {
        $value = $command.ExecuteScalar()
        if ($value -is [DBNull]) { return $null }
        return $value
    }
    finally {
        $command.Dispose()
    }
}

function Invoke-HHSqliteQuery {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)][object]$Connection,
        [Parameter(Mandatory)][string]$Sql,
        [Collections.IDictionary]$Parameters = @{},
        [AllowNull()][object]$Transaction
    )

    $command = New-HHSqliteCommand @PSBoundParameters
    try {
        $reader = $command.ExecuteReader()
        try {
            $rows = [Collections.Generic.List[object]]::new()
            while ($reader.Read()) {
                $row = [ordered]@{}
                for ($index = 0; $index -lt $reader.FieldCount; $index++) {
                    $value = $reader.GetValue($index)
                    $row[$reader.GetName($index)] = if ($value -is [DBNull]) { $null } else { $value }
                }
                $rows.Add([pscustomobject]$row)
            }
            return @($rows)
        }
        finally {
            $reader.Dispose()
        }
    }
    finally {
        $command.Dispose()
    }
}

function Get-HHSqliteMigrationContent {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param([Parameter(Mandatory)][string]$MigrationPath)

    if (-not [System.IO.File]::Exists($MigrationPath)) {
        Stop-HHPersistenceOperation `
            -ErrorId 'PersistenceSchemaUnsupported' `
            -Message 'The committed SQLite migration is missing.' `
            -Category ([System.Management.Automation.ErrorCategory]::ResourceUnavailable) `
            -TargetObject $MigrationPath
    }
    $bytes = [System.IO.File]::ReadAllBytes($MigrationPath)
    Write-Output -InputObject $bytes -NoEnumerate
}

function Get-HHSqliteSchemaFingerprintFromConnection {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param([Parameter(Mandatory)][object]$Connection)

    $rows = Invoke-HHSqliteQuery `
        -Connection $Connection `
        -Sql @'
SELECT type, name, tbl_name, sql
FROM sqlite_schema
WHERE name NOT LIKE 'sqlite_%'
ORDER BY type COLLATE BINARY, name COLLATE BINARY;
'@
    $builder = [System.Text.StringBuilder]::new()
    foreach ($row in $rows) {
        $null = $builder.Append([string]$row.type).Append("`u{001f}")
        $null = $builder.Append([string]$row.name).Append("`u{001f}")
        $null = $builder.Append([string]$row.tbl_name).Append("`u{001f}")
        $null = $builder.Append([string]$row.sql).Append("`n")
    }
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($builder.ToString())
    try {
        $fingerprint = Get-HHPersistenceHash -Bytes $bytes
        Write-Output -InputObject $fingerprint -NoEnumerate
    }
    finally {
        [Array]::Clear($bytes, 0, $bytes.Length)
    }
}

function Get-HHExpectedSqliteSchemaFingerprint {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)][string]$MigrationPath,
        [string]$ProviderRoot
    )

    $connection = New-HHSqliteConnection -DatabasePath ':memory:' -Mode ReadWriteCreate -ProviderRoot $ProviderRoot
    try {
        $migrationBytes = Get-HHSqliteMigrationContent -MigrationPath $MigrationPath
        try {
            $sql = [System.Text.UTF8Encoding]::new($false, $true).GetString($migrationBytes)
            $null = Invoke-HHSqliteNonQuery -Connection $connection -Sql $sql
        }
        finally {
            [Array]::Clear($migrationBytes, 0, $migrationBytes.Length)
        }
        return Get-HHSqliteSchemaFingerprintFromConnection -Connection $connection
    }
    finally {
        $connection.Dispose()
    }
}

function Test-HHSqliteDatabaseSchema {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Connection,
        [Parameter(Mandatory)][string]$MigrationPath,
        [string]$ProviderRoot
    )

    $quickCheck = [string](Invoke-HHSqliteScalar -Connection $Connection -Sql 'PRAGMA quick_check;')
    $foreignKeyFailures = @(Invoke-HHSqliteQuery -Connection $Connection -Sql 'PRAGMA foreign_key_check;')
    if ($quickCheck -cne 'ok' -or $foreignKeyFailures.Count -ne 0) {
        Stop-HHPersistenceOperation `
            -ErrorId 'AuditIntegrityFailed' `
            -Message 'The HostHunter database failed its SQLite integrity checks.' `
            -Category ([System.Management.Automation.ErrorCategory]::InvalidData) `
            -TargetObject $Connection.DataSource
    }

    $migrationBytes = Get-HHSqliteMigrationContent -MigrationPath $MigrationPath
    try {
        $expectedMigrationHash = Get-HHPersistenceHash -Bytes $migrationBytes
    }
    finally {
        [Array]::Clear($migrationBytes, 0, $migrationBytes.Length)
    }
    $migrationRows = @(Invoke-HHSqliteQuery `
            -Connection $Connection `
            -Sql 'SELECT version, name, sql_checksum FROM schema_migrations ORDER BY version;')
    if ($migrationRows.Count -ne 1 -or
        [long]$migrationRows[0].version -ne $script:HHSqliteSchemaVersion -or
        [string]$migrationRows[0].name -cne $script:HHSqliteMigrationName -or
        -not (Test-HHPersistenceBytesEqual `
            -Left ([byte[]]$migrationRows[0].sql_checksum) `
            -Right $expectedMigrationHash)) {
        Stop-HHPersistenceOperation `
            -ErrorId 'PersistenceSchemaUnsupported' `
            -Message 'The HostHunter database migration identity or checksum is unsupported.' `
            -Category ([System.Management.Automation.ErrorCategory]::InvalidData) `
            -TargetObject $Connection.DataSource
    }

    $actualFingerprint = Get-HHSqliteSchemaFingerprintFromConnection -Connection $Connection
    $expectedFingerprint = Get-HHExpectedSqliteSchemaFingerprint `
        -MigrationPath $MigrationPath `
        -ProviderRoot $ProviderRoot
    if (-not (Test-HHPersistenceBytesEqual -Left $actualFingerprint -Right $expectedFingerprint)) {
        Stop-HHPersistenceOperation `
            -ErrorId 'PersistenceSchemaUnsupported' `
            -Message 'The HostHunter database schema objects do not match the committed migration.' `
            -Category ([System.Management.Automation.ErrorCategory]::InvalidData) `
            -TargetObject $Connection.DataSource
    }

    $identityRows = @(Invoke-HHSqliteQuery `
            -Connection $Connection `
            -Sql 'SELECT database_id, ledger_id, format_version, created_at_utc FROM database_identity;')
    $stateCount = [long](Invoke-HHSqliteScalar `
            -Connection $Connection `
            -Sql 'SELECT COUNT(*) FROM target_store_state WHERE singleton_id = 1;')
    if ($identityRows.Count -ne 1 -or [long]$identityRows[0].format_version -ne 1 -or
        ([byte[]]$identityRows[0].database_id).Length -ne 16 -or
        ([byte[]]$identityRows[0].ledger_id).Length -ne 16 -or $stateCount -ne 1) {
        Stop-HHPersistenceOperation `
            -ErrorId 'PersistenceSchemaUnsupported' `
            -Message 'The HostHunter database identity or target state is invalid.' `
            -Category ([System.Management.Automation.ErrorCategory]::InvalidData) `
            -TargetObject $Connection.DataSource
    }
    [pscustomobject]@{
        DatabaseId = [byte[]]$identityRows[0].database_id
        LedgerId = [byte[]]$identityRows[0].ledger_id
        SchemaVersion = $script:HHSqliteSchemaVersion
        SchemaFingerprint = $actualFingerprint
    }
}

function Initialize-HHSqliteDatabase {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$PersistenceContext,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$MasterKey,
        [scriptblock]$AnchorWriter,
        [scriptblock]$Clock,
        [string]$ProviderRoot
    )

    Assert-HHAuditMasterKey -MasterKey $MasterKey
    Initialize-HHPersistenceRoot -PersistenceContext $PersistenceContext
    Assert-HHLegacyPersistenceAbsent -PersistenceContext $PersistenceContext
    $writerLock = Enter-HHPersistenceFileLock `
        -Path $PersistenceContext.WriterLockPath `
        -FailureId PersistenceBusy
    try {
        if ([System.IO.File]::Exists($PersistenceContext.DatabasePath)) {
            if ($IsWindows) {
                Assert-HHWindowsPrivatePathAcl -Path $PersistenceContext.DatabasePath
            }
            $existing = New-HHSqliteConnection `
                -DatabasePath $PersistenceContext.DatabasePath `
                -Mode ReadWrite `
                -ProviderRoot $ProviderRoot
            try {
                return Test-HHSqliteDatabaseSchema `
                    -Connection $existing `
                    -MigrationPath $PersistenceContext.MigrationPath `
                    -ProviderRoot $ProviderRoot
            }
            finally {
                $existing.Dispose()
            }
        }

        [System.IO.Directory]::CreateDirectory($PersistenceContext.AuditRoot) | Out-Null
        [System.IO.Directory]::CreateDirectory($PersistenceContext.OutputRoot) | Out-Null
        [System.IO.Directory]::CreateDirectory($PersistenceContext.RecoveryRoot) | Out-Null
        [System.IO.Directory]::CreateDirectory($PersistenceContext.KeyRoot) | Out-Null
        if (-not $IsWindows) {
            foreach ($directory in @(
                    $PersistenceContext.AuditRoot,
                    $PersistenceContext.OutputRoot,
                    $PersistenceContext.RecoveryRoot,
                    $PersistenceContext.KeyRoot
                )) {
                [System.IO.File]::SetUnixFileMode(
                    $directory,
                    [System.IO.UnixFileMode]::UserRead -bor
                        [System.IO.UnixFileMode]::UserWrite -bor
                        [System.IO.UnixFileMode]::UserExecute
                )
            }
        }

        $now = if ($null -eq $Clock) { [DateTimeOffset]::UtcNow } else { & $Clock }
        $databaseId = [Guid]::NewGuid().ToByteArray()
        $ledgerId = [Guid]::NewGuid().ToByteArray()
        $migrationBytes = Get-HHSqliteMigrationContent -MigrationPath $PersistenceContext.MigrationPath
        $migrationHash = Get-HHPersistenceHash -Bytes $migrationBytes
        $zeroMac = [byte[]]::new(32)
        $initialTargetEvidence = Get-HHTargetRepositoryStateEvidence `
            -DatabaseId $databaseId `
            -LedgerId $ledgerId `
            -SchemaVersion 1 `
            -Generation 0 `
            -PriorMutationMac $zeroMac `
            -Target @() `
            -MasterKey $MasterKey
        $snapshotHash = $initialTargetEvidence.SnapshotHash
        $targetMac = $initialTargetEvidence.TargetStateMac
        try {
            $connection = New-HHSqliteConnection `
                -DatabasePath $PersistenceContext.DatabasePath `
                -Mode ReadWriteCreate `
                -ProviderRoot $ProviderRoot
            try {
                $null = Invoke-HHSqliteNonQuery `
                    -Connection $connection `
                    -Sql 'PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;'
                $transaction = $connection.BeginTransaction(
                    [System.Data.IsolationLevel]::Serializable,
                    $false
                )
                try {
                    $migrationSql = [System.Text.UTF8Encoding]::new($false, $true).GetString($migrationBytes)
                    $null = Invoke-HHSqliteNonQuery `
                        -Connection $connection `
                        -Transaction $transaction `
                        -Sql $migrationSql
                    $utcText = $now.UtcDateTime.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
                    $migrationInsertSql = @'
INSERT INTO schema_migrations(version, name, sql_checksum, applied_at_utc)
VALUES(@version, @name, @checksum, @applied);
'@
                    $null = Invoke-HHSqliteNonQuery `
                        -Connection $connection `
                        -Transaction $transaction `
                        -Sql $migrationInsertSql `
                        -Parameters @{ version = 1; name = $script:HHSqliteMigrationName; checksum = $migrationHash; applied = $utcText }
                    $identityInsertSql = @'
INSERT INTO database_identity(
    singleton_id, database_id, ledger_id, format_version, created_at_utc
)
VALUES(1, @database, @ledger, 1, @created);
'@
                    $null = Invoke-HHSqliteNonQuery `
                        -Connection $connection `
                        -Transaction $transaction `
                        -Sql $identityInsertSql `
                        -Parameters @{ database = $databaseId; ledger = $ledgerId; created = $utcText }
                    $stateInsertSql = @'
INSERT INTO target_store_state(
    singleton_id, generation, snapshot_hash, target_state_mac,
    prior_mutation_mac, last_mutation_id
)
VALUES(1, 0, @snapshot, @state, @prior, NULL);
'@
                    $null = Invoke-HHSqliteNonQuery `
                        -Connection $connection `
                        -Transaction $transaction `
                        -Sql $stateInsertSql `
                        -Parameters @{ snapshot = $snapshotHash; state = $targetMac; prior = $zeroMac }
                    $transaction.Commit()
                }
                catch {
                    $transaction.Rollback()
                    throw
                }
                finally {
                    $transaction.Dispose()
                }
                $verified = Test-HHSqliteDatabaseSchema `
                    -Connection $connection `
                    -MigrationPath $PersistenceContext.MigrationPath `
                    -ProviderRoot $ProviderRoot
            }
            finally {
                $connection.Dispose()
            }

            if ($IsWindows) {
                Protect-HHWindowsPrivatePathAcl -Path $PersistenceContext.DatabasePath
            }

            $anchor = [pscustomobject]@{
                DatabaseId = $databaseId
                LedgerId = $ledgerId
                SchemaVersion = 1
                AuditSequence = 0L
                AuditMac = $zeroMac
                TargetGeneration = 0L
                TargetStateMac = $targetMac
                SchemaFingerprint = $verified.SchemaFingerprint
            }
            if ($null -ne $AnchorWriter) {
                & $AnchorWriter $PersistenceContext $null `
                    (ConvertTo-HHPersistenceAnchorArtifact -Anchor $anchor -MasterKey $MasterKey) `
                    $MasterKey
            }
            else {
                Write-HHPersistenceAnchor `
                    -PersistenceContext $PersistenceContext `
                    -Anchor $anchor `
                    -MasterKey $MasterKey `
                    -ExpectedArtifact $null
            }
            return $verified
        }
        finally {
            [Array]::Clear($migrationBytes, 0, $migrationBytes.Length)
        }
    }
    finally {
        Exit-HHPersistenceFileLock -LockContext $writerLock
    }
}
