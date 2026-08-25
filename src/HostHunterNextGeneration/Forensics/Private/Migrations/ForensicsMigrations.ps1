Set-StrictMode -Version Latest

$script:HHForensicsSchemaVersion = 1
$script:HHForensicsMigrationName = '0001_forensics'

function Get-HHForensicsMigrationPath {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    return Join-Path $PSScriptRoot "$($script:HHForensicsMigrationName).sql"
}

function Get-HHForensicsMigrationContent {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param([string]$MigrationPath = (Get-HHForensicsMigrationPath))

    if (-not [IO.File]::Exists($MigrationPath)) {
        Stop-HHForensicsOperation -ErrorId ForensicsSchemaUnsupported `
            -Message 'The committed forensics SQLite migration is missing.' `
            -Category ResourceUnavailable -TargetObject $MigrationPath
    }
    $bytes = [IO.File]::ReadAllBytes($MigrationPath)
    Write-Output -InputObject $bytes -NoEnumerate
}

function Get-HHForensicsSchemaFingerprint {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)][object]$Connection,
        [AllowNull()][object]$Transaction
    )

    $rows = @(Invoke-HHSqliteQuery -Connection $Connection -Sql @'
SELECT type, name, tbl_name, sql
FROM sqlite_schema
WHERE name NOT LIKE 'sqlite_%'
ORDER BY type COLLATE BINARY, name COLLATE BINARY;
'@ -Transaction $Transaction)
    $builder = [Text.StringBuilder]::new()
    foreach ($row in $rows) {
        $null = $builder.Append([string]$row.type).Append("`u{001f}")
        $null = $builder.Append([string]$row.name).Append("`u{001f}")
        $null = $builder.Append([string]$row.tbl_name).Append("`u{001f}")
        $null = $builder.Append([string]$row.sql).Append("`n")
    }
    $bytes = [Text.Encoding]::UTF8.GetBytes($builder.ToString())
    try {
        $fingerprint = Get-HHForensicsHash -Bytes $bytes
        Write-Output -InputObject $fingerprint -NoEnumerate
    }
    finally { [Array]::Clear($bytes, 0, $bytes.Length) }
}

function Get-HHExpectedForensicsSchemaFingerprint {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [string]$MigrationPath = (Get-HHForensicsMigrationPath),
        [string]$ProviderRoot
    )

    $connection = New-HHSqliteConnection `
        -DatabasePath ':memory:' -Mode ReadWriteCreate -ProviderRoot $ProviderRoot
    try {
        $migrationBytes = Get-HHForensicsMigrationContent -MigrationPath $MigrationPath
        try {
            $sql = [Text.UTF8Encoding]::new($false, $true).GetString($migrationBytes)
            $null = Invoke-HHSqliteNonQuery -Connection $connection -Sql $sql
        }
        finally { [Array]::Clear($migrationBytes, 0, $migrationBytes.Length) }
        return Get-HHForensicsSchemaFingerprint -Connection $connection
    }
    finally { $connection.Dispose() }
}

function Test-HHForensicsDatabaseEmpty {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][object]$Connection)

    $count = [long](Invoke-HHSqliteScalar -Connection $Connection -Sql @'
SELECT COUNT(*)
FROM sqlite_schema
WHERE name NOT LIKE 'sqlite_%';
'@)
    return $count -eq 0
}

function Initialize-HHForensicsSchema {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Initializes only the explicitly supplied new forensics database.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Connection,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$DatabaseId,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$InitialStateDigest,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$InitialStateMac,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$InitialProjectionDigest,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$InitialProjectionMac,
        [Parameter(Mandatory)][string]$AppliedAtUtc,
        [string]$MigrationPath = (Get-HHForensicsMigrationPath)
    )

    if ($DatabaseId.Length -ne 16 -or $InitialStateDigest.Length -ne 32 -or
        $InitialStateMac.Length -ne 32 -or $InitialProjectionDigest.Length -ne 32 -or
        $InitialProjectionMac.Length -ne 32) {
        throw [ArgumentException]::new('Forensics schema initialization values have invalid lengths.')
    }
    if (-not (Test-HHForensicsDatabaseEmpty -Connection $Connection)) {
        Stop-HHForensicsOperation -ErrorId ForensicsSchemaUnsupported `
            -Message 'Schema initialization refuses a non-empty SQLite database.' `
            -Category InvalidData -TargetObject $Connection.DataSource
    }

    $migrationBytes = Get-HHForensicsMigrationContent -MigrationPath $MigrationPath
    try {
        $migrationHash = Get-HHForensicsHash -Bytes $migrationBytes
        $sql = [Text.UTF8Encoding]::new($false, $true).GetString($migrationBytes)
        $transaction = $Connection.BeginTransaction()
        try {
            $null = Invoke-HHSqliteNonQuery `
                -Connection $Connection -Transaction $transaction -Sql $sql
            $null = Invoke-HHSqliteNonQuery `
                -Connection $Connection -Transaction $transaction -Sql @'
INSERT INTO forensics_schema_migrations(version,name,sql_checksum,applied_at_utc)
VALUES(1,@name,@checksum,@applied);
INSERT INTO forensics_database_identity(singleton_id,database_id,format_version,created_at_utc)
VALUES(1,@database_id,1,@applied);
INSERT INTO forensics_state(
    singleton_id,generation,state_digest,state_mac,projection_digest,projection_mac,
    last_mutation_id
)
VALUES(1,0,@state_digest,@state_mac,@projection_digest,@projection_mac,NULL);
'@ -Parameters @{
                name = $script:HHForensicsMigrationName
                checksum = $migrationHash
                applied = $AppliedAtUtc
                database_id = $DatabaseId
                state_digest = $InitialStateDigest
                state_mac = $InitialStateMac
                projection_digest = $InitialProjectionDigest
                projection_mac = $InitialProjectionMac
            }
            $transaction.Commit()
        }
        catch {
            try { $transaction.Rollback() }
            catch { Write-Debug 'The already-failed schema transaction could not be rolled back.' }
            throw
        }
        finally { $transaction.Dispose() }
    }
    finally { [Array]::Clear($migrationBytes, 0, $migrationBytes.Length) }
}

function Test-HHForensicsSchema {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Connection,
        [string]$MigrationPath = (Get-HHForensicsMigrationPath),
        [string]$ProviderRoot,
        [AllowNull()][object]$Transaction
    )

    $quickCheck = [string](Invoke-HHSqliteScalar -Connection $Connection `
            -Transaction $Transaction -Sql 'PRAGMA quick_check;')
    $foreignKeyFailures = @(Invoke-HHSqliteQuery -Connection $Connection `
            -Transaction $Transaction -Sql 'PRAGMA foreign_key_check;')
    if ($quickCheck -cne 'ok' -or $foreignKeyFailures.Count -ne 0) {
        Stop-HHForensicsOperation -ErrorId ForensicsIntegrityFailed `
            -Message 'The forensics database failed SQLite integrity checks.' `
            -Category InvalidData -TargetObject $Connection.DataSource
    }

    $userVersion = [long](Invoke-HHSqliteScalar -Connection $Connection `
            -Transaction $Transaction -Sql 'PRAGMA user_version;')
    $migrationRows = @(Invoke-HHSqliteQuery -Connection $Connection -Sql @'
SELECT version,name,sql_checksum,applied_at_utc
FROM forensics_schema_migrations
ORDER BY version;
'@ -Transaction $Transaction)
    if ($userVersion -ne $script:HHForensicsSchemaVersion -or $migrationRows.Count -ne 1 -or
        [long]$migrationRows[0].version -ne 1 -or
        [string]$migrationRows[0].name -cne $script:HHForensicsMigrationName) {
        Stop-HHForensicsOperation -ErrorId ForensicsSchemaUnsupported `
            -Message 'The forensics database schema version is unsupported.' `
            -Category InvalidData -TargetObject $Connection.DataSource
    }

    $migrationBytes = Get-HHForensicsMigrationContent -MigrationPath $MigrationPath
    try {
        $expectedChecksum = Get-HHForensicsHash -Bytes $migrationBytes
        if (-not (Test-HHForensicsBytesEqual `
                    -Left ([byte[]]$migrationRows[0].sql_checksum) `
                    -Right $expectedChecksum)) {
            Stop-HHForensicsOperation -ErrorId ForensicsIntegrityFailed `
                -Message 'The forensics migration checksum does not match the committed migration.' `
                -Category SecurityError -TargetObject $Connection.DataSource
        }
    }
    finally { [Array]::Clear($migrationBytes, 0, $migrationBytes.Length) }

    $actualFingerprint = Get-HHForensicsSchemaFingerprint `
        -Connection $Connection -Transaction $Transaction
    $expectedFingerprint = Get-HHExpectedForensicsSchemaFingerprint `
        -MigrationPath $MigrationPath -ProviderRoot $ProviderRoot
    if (-not (Test-HHForensicsBytesEqual -Left $actualFingerprint -Right $expectedFingerprint)) {
        Stop-HHForensicsOperation -ErrorId ForensicsIntegrityFailed `
            -Message 'The forensics database schema fingerprint is not canonical.' `
            -Category SecurityError -TargetObject $Connection.DataSource
    }

    $identityRows = @(Invoke-HHSqliteQuery -Connection $Connection -Sql @'
SELECT database_id,format_version,created_at_utc
FROM forensics_database_identity
WHERE singleton_id=1;
'@ -Transaction $Transaction)
    $stateRows = @(Invoke-HHSqliteQuery -Connection $Connection -Sql @'
SELECT generation,state_digest,state_mac,projection_digest,projection_mac,last_mutation_id
FROM forensics_state
WHERE singleton_id=1;
'@ -Transaction $Transaction)
    if ($identityRows.Count -ne 1 -or $stateRows.Count -ne 1 -or
        ([byte[]]$identityRows[0].database_id).Length -ne 16 -or
        [long]$identityRows[0].format_version -ne 1 -or
        [string]::IsNullOrWhiteSpace([string]$identityRows[0].created_at_utc) -or
        [string]::IsNullOrWhiteSpace([string]$migrationRows[0].applied_at_utc) -or
        [long]$stateRows[0].generation -lt 0 -or
        ([byte[]]$stateRows[0].state_digest).Length -ne 32 -or
        ([byte[]]$stateRows[0].state_mac).Length -ne 32 -or
        ([byte[]]$stateRows[0].projection_digest).Length -ne 32 -or
        ([byte[]]$stateRows[0].projection_mac).Length -ne 32) {
        Stop-HHForensicsOperation -ErrorId ForensicsIntegrityFailed `
            -Message 'The forensics database identity or authenticated state head is malformed.' `
            -Category InvalidData -TargetObject $Connection.DataSource
    }

    return [pscustomobject]@{
        SchemaVersion = $script:HHForensicsSchemaVersion
        SchemaFingerprint = $actualFingerprint
        DatabaseId = [byte[]]$identityRows[0].database_id
        DatabaseCreatedAtUtc = [string]$identityRows[0].created_at_utc
        MigrationAppliedAtUtc = [string]$migrationRows[0].applied_at_utc
        Generation = [long]$stateRows[0].generation
        StateDigest = [byte[]]$stateRows[0].state_digest
        StateMac = [byte[]]$stateRows[0].state_mac
        ProjectionDigest = [byte[]]$stateRows[0].projection_digest
        ProjectionMac = [byte[]]$stateRows[0].projection_mac
        LastMutationId = $stateRows[0].last_mutation_id
    }
}
