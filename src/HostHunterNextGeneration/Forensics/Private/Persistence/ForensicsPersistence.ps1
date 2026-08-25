Set-StrictMode -Version Latest

function Initialize-HHForensicsSqliteFileControl {
    [CmdletBinding()]
    param()

    if ($null -ne ('HostHunter.Forensics.NativeSqlite' -as [type])) {
        return
    }
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace HostHunter.Forensics
{
    public static class NativeSqlite
    {
        [DllImport("e_sqlite3", CallingConvention = CallingConvention.Cdecl)]
        public static extern int sqlite3_file_control(
            IntPtr database,
            byte[] databaseName,
            int operation,
            ref int argument);
    }
}
'@
}

function Assert-HHForensicsSqlitePathBinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Connection,
        [Parameter(Mandatory)][string]$ExpectedDatabasePath
    )

    Initialize-HHForensicsSqliteFileControl
    if ($null -eq $Connection.Handle -or $Connection.Handle.IsInvalid) {
        Stop-HHForensicsOperation -ErrorId ForensicsPathRejected `
            -Message 'The opened forensics database has no verifiable SQLite file handle.' `
            -Category SecurityError -TargetObject $ExpectedDatabasePath
    }
    $expected = [IO.Path]::GetFullPath($ExpectedDatabasePath)
    $reported = [IO.Path]::GetFullPath([string]$Connection.DataSource)
    if ($reported -cne $expected) {
        Stop-HHForensicsOperation -ErrorId ForensicsPathRejected `
            -Message 'SQLite opened a different forensics database path than requested.' `
            -Category SecurityError -TargetObject $reported
    }

    $moved = 0
    $addedReference = $false
    try {
        $Connection.Handle.DangerousAddRef([ref]$addedReference)
        $result = [HostHunter.Forensics.NativeSqlite]::sqlite3_file_control(
            $Connection.Handle.DangerousGetHandle(),
            [Text.Encoding]::UTF8.GetBytes("main`0"),
            20,
            [ref]$moved
        )
    }
    catch {
        Stop-HHForensicsOperation -ErrorId ForensicsPathRejected `
            -Message 'SQLite could not verify the opened forensics database file binding.' `
            -Category SecurityError -TargetObject $ExpectedDatabasePath `
            -InnerException $_.Exception
    }
    finally {
        if ($addedReference) {
            $Connection.Handle.DangerousRelease()
        }
    }
    if ($result -ne 0 -or $moved -ne 0) {
        Stop-HHForensicsOperation -ErrorId ForensicsPathRejected `
            -Message 'The opened forensics database was moved, replaced, or deleted.' `
            -Category SecurityError -TargetObject $ExpectedDatabasePath
    }
}

function New-HHForensicsPersistenceContext {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Builds an in-memory persistence descriptor without opening or changing files.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DataRoot,
        [string]$MigrationPath = (Get-HHForensicsMigrationPath),
        [string]$ProviderRoot
    )

    $root = [IO.Path]::GetFullPath($DataRoot)
    Assert-HHPersistencePathSafety -DataRoot $root -AllowMissingRoot
    $databasePath = [IO.Path]::GetFullPath((Join-Path $root 'forensics.db'))
    $coreDatabasePath = [IO.Path]::GetFullPath((Join-Path $root 'hosthunter.db'))
    if ($databasePath -ceq $coreDatabasePath -or
        [IO.Path]::GetFileName($databasePath) -cne 'forensics.db' -or
        -not (Test-HHPersistencePathContained -Root $root -Candidate $databasePath)) {
        Stop-HHForensicsOperation -ErrorId ForensicsPathRejected `
            -Message 'Forensics persistence must use its dedicated forensics.db file.' `
            -Category SecurityError -TargetObject $databasePath
    }
    return [pscustomobject]@{
        DataRoot = $root
        DatabasePath = $databasePath
        CoreDatabasePath = $coreDatabasePath
        LockPath = [IO.Path]::GetFullPath((Join-Path $root 'forensics.writer.lock'))
        MigrationPath = [IO.Path]::GetFullPath($MigrationPath)
        ProviderRoot = $ProviderRoot
    }
}

function Protect-HHForensicsPrivatePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$Directory
    )

    if ($IsWindows) {
        if ($null -eq (Get-Command Protect-HHWindowsPrivatePathAcl -ErrorAction SilentlyContinue)) {
            Stop-HHForensicsOperation -ErrorId ForensicsPathRejected `
                -Message 'Windows private-path ACL support is unavailable.' `
                -Category SecurityError -TargetObject $Path
        }
        Protect-HHWindowsPrivatePathAcl -Path $Path -Directory:$Directory
        return
    }
    $mode = if ($Directory) {
        [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite -bor
            [IO.UnixFileMode]::UserExecute
    }
    else { [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite }
    [IO.File]::SetUnixFileMode($Path, $mode)
}

function Assert-HHForensicsStorePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$PersistenceContext,
        [switch]$AllowMissingRoot
    )

    $root = [IO.Path]::GetFullPath($PersistenceContext.DataRoot)
    $existingAncestor = $root
    while (-not [IO.Directory]::Exists($existingAncestor)) {
        $parent = [IO.Directory]::GetParent($existingAncestor)
        if ($null -eq $parent) { break }
        $existingAncestor = $parent.FullName
    }
    if ([IO.Directory]::Exists($existingAncestor)) {
        $current = [IO.DirectoryInfo]::new($existingAncestor)
        while ($null -ne $current) {
            if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                $null -ne $current.LinkTarget) {
                Stop-HHForensicsOperation -ErrorId ForensicsPathRejected `
                    -Message 'The forensics root cannot be created through a link or reparse point.' `
                    -Category SecurityError -TargetObject $current.FullName
            }
            $current = $current.Parent
        }
    }
    Assert-HHPersistencePathSafety -DataRoot $root -AllowMissingRoot:$AllowMissingRoot
    $expectedDatabase = [IO.Path]::GetFullPath((Join-Path $root 'forensics.db'))
    $expectedCore = [IO.Path]::GetFullPath((Join-Path $root 'hosthunter.db'))
    $expectedLock = [IO.Path]::GetFullPath((Join-Path $root 'forensics.writer.lock'))
    if ([IO.Path]::GetFullPath($PersistenceContext.DatabasePath) -cne $expectedDatabase -or
        [IO.Path]::GetFullPath($PersistenceContext.CoreDatabasePath) -cne $expectedCore -or
        [IO.Path]::GetFullPath($PersistenceContext.LockPath) -cne $expectedLock) {
        Stop-HHForensicsOperation -ErrorId ForensicsPathRejected `
            -Message 'The forensics persistence paths escaped or changed from their private root.' `
            -Category SecurityError -TargetObject $PersistenceContext.DatabasePath
    }
    foreach ($path in @(
            $expectedDatabase,
            "$expectedDatabase-wal",
            "$expectedDatabase-shm",
            $expectedLock
        )) {
        $info = [IO.FileInfo]::new($path)
        if ($null -ne $info.LinkTarget -or
            ($info.Exists -and
                ($info.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            Stop-HHForensicsOperation -ErrorId ForensicsPathRejected `
                -Message 'A forensics database or lock path cannot be a link or reparse point.' `
                -Category SecurityError -TargetObject $path
        }
        if ([IO.File]::Exists($path)) {
            continue
        }
        elseif ([IO.Directory]::Exists($path)) {
            Stop-HHForensicsOperation -ErrorId ForensicsPathRejected `
                -Message 'A forensics database or lock path cannot be a directory.' `
                -Category SecurityError -TargetObject $path
        }
    }
}

function Protect-HHForensicsStoreFile {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$PersistenceContext)

    foreach ($path in @(
            $PersistenceContext.DatabasePath,
            "$($PersistenceContext.DatabasePath)-wal",
            "$($PersistenceContext.DatabasePath)-shm",
            $PersistenceContext.LockPath
        )) {
        if ([IO.File]::Exists($path)) {
            Protect-HHForensicsPrivatePath -Path $path
        }
    }
}

function Get-HHForensicsProjectionTable {
    [CmdletBinding()]
    [OutputType([object[]])]
    param()

    return @(
        [pscustomobject]@{ Name = 'events'; Sql = @'
SELECT event_id,event_digest,source_key,run_id,ordinal,occurred_at_utc,body_size,
    event_body_envelope,status,created_at_utc
FROM forensics_events ORDER BY event_id COLLATE BINARY;
'@ }
        [pscustomobject]@{ Name = 'outbox'; Sql = @'
SELECT resource_key,idempotency_key,method,resource_uri,body_digest,body_size,
    request_body_envelope,first_ordinal,last_ordinal,event_count,status,creation_order,
    attempt_count,last_status_code,last_problem_code,receipt_digest,receipt_envelope,
    created_at_utc,updated_at_utc
FROM forensics_outbox ORDER BY creation_order,resource_key COLLATE BINARY;
'@ }
        [pscustomobject]@{ Name = 'outbox_events'; Sql = @'
SELECT resource_key,event_id,event_ordinal
FROM forensics_outbox_events
ORDER BY resource_key COLLATE BINARY,event_ordinal,event_id COLLATE BINARY;
'@ }
        [pscustomobject]@{ Name = 'dependencies'; Sql = @'
SELECT resource_key,depends_on_resource_key
FROM forensics_outbox_dependencies
ORDER BY resource_key COLLATE BINARY,depends_on_resource_key COLLATE BINARY;
'@ }
        [pscustomobject]@{ Name = 'attempts'; Sql = @'
SELECT resource_key,attempt_number,attempt_id,started_at_utc,completed_at_utc,outcome,
    status_code,problem_code,response_digest,response_envelope
FROM forensics_delivery_attempts
ORDER BY resource_key COLLATE BINARY,attempt_number;
'@ }
        [pscustomobject]@{ Name = 'quarantine'; Sql = @'
SELECT quarantine_id,conflict_kind,routing_key,expected_digest,observed_digest,status,
    created_at_utc
FROM forensics_quarantine ORDER BY quarantine_id COLLATE BINARY;
'@ }
    )
}

function Add-HHForensicsProjectionValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][Security.Cryptography.IncrementalHash]$Hash,
        [AllowNull()][object]$Value
    )

    [byte[]]$bytes = @()
    $marker = 0
    if ($null -eq $Value -or $Value -is [DBNull]) {
        $marker = 0
    }
    elseif ($Value -is [byte[]]) {
        $marker = 1
        $bytes = [byte[]]$Value
    }
    elseif ($Value -is [int] -or $Value -is [long]) {
        $marker = 2
        $bytes = [BitConverter]::GetBytes([long]$Value)
    }
    else {
        $marker = 3
        $bytes = [Text.Encoding]::UTF8.GetBytes([string]$Value)
    }
    $Hash.AppendData([byte[]]($marker))
    $Hash.AppendData([BitConverter]::GetBytes([int]$bytes.Length))
    if ($bytes.Length -gt 0) { $Hash.AppendData($bytes) }
}

function Add-HHForensicsProjectionBoundary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][Security.Cryptography.IncrementalHash]$Hash,
        [Parameter(Mandatory)][string]$TableName,
        [Parameter(Mandatory)][ValidateSet('Begin', 'End')][string]$Position
    )

    Add-HHForensicsProjectionValue `
        -Hash $Hash -Value "HHF-PROJECTION-1/$Position/$TableName"
}

function Get-HHForensicsProjectionEvidence {
    [CmdletBinding()]
    param(
        [AllowNull()][object]$Connection,
        [AllowNull()][object]$Transaction,
        [switch]$Empty
    )

    $hash = [Security.Cryptography.IncrementalHash]::CreateHash(
        [Security.Cryptography.HashAlgorithmName]::SHA256
    )
    try {
        foreach ($table in @(Get-HHForensicsProjectionTable)) {
            Add-HHForensicsProjectionBoundary `
                -Hash $hash -TableName $table.Name -Position Begin
            if (-not $Empty) {
                $command = New-HHSqliteCommand `
                    -Connection $Connection -Transaction $Transaction -Sql $table.Sql
                try {
                    $reader = $command.ExecuteReader()
                    try {
                        while ($reader.Read()) {
                            for ($index = 0; $index -lt $reader.FieldCount; $index++) {
                                Add-HHForensicsProjectionValue `
                                    -Hash $hash -Value $reader.GetValue($index)
                            }
                        }
                    }
                    finally { $reader.Dispose() }
                }
                finally { $command.Dispose() }
            }
            Add-HHForensicsProjectionBoundary `
                -Hash $hash -TableName $table.Name -Position End
        }
        $digest = $hash.GetHashAndReset()
        Write-Output -InputObject $digest -NoEnumerate
    }
    finally { $hash.Dispose() }
}

function Get-HHForensicsProtectedProjection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$DatabaseId,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$SchemaFingerprint,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$ForensicsKey,
        [AllowNull()][object]$Connection,
        [AllowNull()][object]$Transaction,
        [switch]$Empty
    )

    $digest = Get-HHForensicsProjectionEvidence `
        -Connection $Connection -Transaction $Transaction -Empty:$Empty
    $stateKey = Get-HHForensicsDerivedKey `
        -ForensicsKey $ForensicsKey -Purpose StateIntegrity
    $macEvidence = Join-HHForensicsEvidence -Value @(
        'HHF-PROJECTION-MAC-1', $DatabaseId, $SchemaFingerprint, $digest
    )
    try { $mac = Get-HHForensicsMac -Key $stateKey -Bytes $macEvidence }
    finally {
        [Array]::Clear($stateKey, 0, $stateKey.Length)
        [Array]::Clear($macEvidence, 0, $macEvidence.Length)
    }
    return [pscustomobject]@{ Digest = $digest; Mac = $mac }
}

function Get-HHForensicsInitialState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$DatabaseId,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$SchemaFingerprint,
        [Parameter(Mandatory)][string]$DatabaseCreatedAtUtc,
        [Parameter(Mandatory)][string]$MigrationAppliedAtUtc,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$ForensicsKey
    )

    $projection = Get-HHForensicsProtectedProjection `
        -DatabaseId $DatabaseId -SchemaFingerprint $SchemaFingerprint `
        -ForensicsKey $ForensicsKey -Empty
    $evidence = Join-HHForensicsEvidence -Value @(
        'HHF-STATE-INITIAL-1', $DatabaseId, 1L, $SchemaFingerprint,
        $DatabaseCreatedAtUtc, $MigrationAppliedAtUtc,
        $projection.Digest, $projection.Mac
    )
    $stateKey = Get-HHForensicsDerivedKey `
        -ForensicsKey $ForensicsKey -Purpose StateIntegrity
    try {
        $digest = Get-HHForensicsHash -Bytes $evidence
        $macEvidence = Join-HHForensicsEvidence -Value @(
            'HHF-STATE-MAC-1', $DatabaseId, 0L, $digest
        )
        try { $mac = Get-HHForensicsMac -Key $stateKey -Bytes $macEvidence }
        finally { [Array]::Clear($macEvidence, 0, $macEvidence.Length) }
        return [pscustomobject]@{
            Digest = $digest
            Mac = $mac
            ProjectionDigest = $projection.Digest
            ProjectionMac = $projection.Mac
        }
    }
    finally {
        [Array]::Clear($evidence, 0, $evidence.Length)
        [Array]::Clear($stateKey, 0, $stateKey.Length)
    }
}

function Get-HHForensicsMutationState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$DatabaseId,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$SchemaFingerprint,
        [Parameter(Mandatory)][long]$Sequence,
        [Parameter(Mandatory)][string]$MutationId,
        [Parameter(Mandatory)][string]$MutationType,
        [Parameter(Mandatory)][string]$RoutingKey,
        [Parameter(Mandatory)][string]$OccurredAtUtc,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$PayloadDigest,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$ProjectionDigest,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$ProjectionMac,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$PreviousMac,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$ForensicsKey
    )

    if ($Sequence -lt 1 -or $PayloadDigest.Length -ne 32 -or
        $ProjectionDigest.Length -ne 32 -or $ProjectionMac.Length -ne 32 -or
        $PreviousMac.Length -ne 32) {
        throw [ArgumentException]::new('Forensics mutation evidence is malformed.')
    }
    $evidence = Join-HHForensicsEvidence -Value @(
        'HHF-MUTATION-1', $DatabaseId, $SchemaFingerprint, $Sequence,
        $MutationId, $MutationType, $RoutingKey, $OccurredAtUtc, $PayloadDigest,
        $ProjectionDigest, $ProjectionMac, $PreviousMac
    )
    $stateKey = Get-HHForensicsDerivedKey `
        -ForensicsKey $ForensicsKey -Purpose StateIntegrity
    try {
        $digest = Get-HHForensicsHash -Bytes $evidence
        $macEvidence = Join-HHForensicsEvidence -Value @($evidence, $digest)
        try { $mac = Get-HHForensicsMac -Key $stateKey -Bytes $macEvidence }
        finally { [Array]::Clear($macEvidence, 0, $macEvidence.Length) }
        return [pscustomobject]@{ Digest = $digest; Mac = $mac }
    }
    finally {
        [Array]::Clear($evidence, 0, $evidence.Length)
        [Array]::Clear($stateKey, 0, $stateKey.Length)
    }
}

function New-HHForensicsAnchor {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Constructs authenticated anchor bytes in memory only.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$DatabaseId,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$SchemaFingerprint,
        [Parameter(Mandatory)][long]$Generation,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$StateDigest,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$StateMac,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$ProjectionDigest,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$ProjectionMac,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$ForensicsKey
    )

    $evidence = Join-HHForensicsEvidence -Value @(
        'HHF-ANCHOR-1', $script:HHForensicsCredentialService,
        $script:HHForensicsAnchorAccount, $DatabaseId, 1L, $SchemaFingerprint,
        $Generation, $StateDigest, $StateMac, $ProjectionDigest, $ProjectionMac
    )
    $anchorKey = Get-HHForensicsDerivedKey `
        -ForensicsKey $ForensicsKey -Purpose AnchorIntegrity
    try { $anchorMac = Get-HHForensicsMac -Key $anchorKey -Bytes $evidence }
    finally {
        [Array]::Clear($anchorKey, 0, $anchorKey.Length)
        [Array]::Clear($evidence, 0, $evidence.Length)
    }
    return [pscustomobject]@{
        Schema = 'hosthunter.forensics-anchor/1'
        Service = $script:HHForensicsCredentialService
        Account = $script:HHForensicsAnchorAccount
        DatabaseId = [byte[]]$DatabaseId.Clone()
        SchemaVersion = 1L
        SchemaFingerprint = [byte[]]$SchemaFingerprint.Clone()
        Generation = $Generation
        StateDigest = [byte[]]$StateDigest.Clone()
        StateMac = [byte[]]$StateMac.Clone()
        ProjectionDigest = [byte[]]$ProjectionDigest.Clone()
        ProjectionMac = [byte[]]$ProjectionMac.Clone()
        AnchorMac = $anchorMac
    }
}

function Test-HHForensicsAnchorMac {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Anchor,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$ForensicsKey
    )

    foreach ($name in @(
            'Schema', 'Service', 'Account', 'DatabaseId', 'SchemaVersion',
            'SchemaFingerprint', 'Generation', 'StateDigest', 'StateMac',
            'ProjectionDigest', 'ProjectionMac', 'AnchorMac'
        )) {
        if ($null -eq $Anchor.PSObject.Properties[$name]) {
            Stop-HHForensicsOperation -ErrorId ForensicsIntegrityFailed `
                -Message 'The external forensics anchor is incomplete.' `
                -Category InvalidData -TargetObject $name
        }
    }
    if ([string]$Anchor.Schema -cne 'hosthunter.forensics-anchor/1' -or
        [string]$Anchor.Service -cne $script:HHForensicsCredentialService -or
        [string]$Anchor.Account -cne $script:HHForensicsAnchorAccount -or
        ([byte[]]$Anchor.DatabaseId).Length -ne 16 -or
        ([byte[]]$Anchor.SchemaFingerprint).Length -ne 32 -or
        ([byte[]]$Anchor.StateDigest).Length -ne 32 -or
        ([byte[]]$Anchor.StateMac).Length -ne 32 -or
        ([byte[]]$Anchor.ProjectionDigest).Length -ne 32 -or
        ([byte[]]$Anchor.ProjectionMac).Length -ne 32 -or
        ([byte[]]$Anchor.AnchorMac).Length -ne 32 -or
        [long]$Anchor.SchemaVersion -ne 1 -or [long]$Anchor.Generation -lt 0) {
        Stop-HHForensicsOperation -ErrorId ForensicsIntegrityFailed `
            -Message 'The external forensics anchor is malformed.' `
            -Category InvalidData -TargetObject $Anchor
    }
    $expected = New-HHForensicsAnchor `
        -DatabaseId ([byte[]]$Anchor.DatabaseId) `
        -SchemaFingerprint ([byte[]]$Anchor.SchemaFingerprint) `
        -Generation ([long]$Anchor.Generation) `
        -StateDigest ([byte[]]$Anchor.StateDigest) `
        -StateMac ([byte[]]$Anchor.StateMac) `
        -ProjectionDigest ([byte[]]$Anchor.ProjectionDigest) `
        -ProjectionMac ([byte[]]$Anchor.ProjectionMac) `
        -ForensicsKey $ForensicsKey
    if (-not (Test-HHForensicsBytesEqual `
                -Left ([byte[]]$Anchor.AnchorMac) -Right $expected.AnchorMac)) {
        Stop-HHForensicsOperation -ErrorId ForensicsIntegrityFailed `
            -Message 'The external forensics anchor failed authentication.' `
            -Category SecurityError -TargetObject $Anchor
    }
}

function Compare-HHForensicsAnchor {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$DatabaseHead,
        [Parameter(Mandatory)][object]$Anchor,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$ForensicsKey
    )

    Test-HHForensicsAnchorMac -Anchor $Anchor -ForensicsKey $ForensicsKey
    foreach ($name in @('DatabaseId', 'SchemaFingerprint')) {
        if (-not (Test-HHForensicsBytesEqual `
                    -Left ([byte[]]$DatabaseHead.$name) `
                    -Right ([byte[]]$Anchor.$name))) {
            Stop-HHForensicsOperation -ErrorId ForensicsIntegrityFailed `
                -Message 'The database and external forensics anchor identities disagree.' `
                -Category SecurityError -TargetObject $name
        }
    }
    if ([long]$Anchor.SchemaVersion -ne [long]$DatabaseHead.SchemaVersion) {
        Stop-HHForensicsOperation -ErrorId ForensicsSchemaUnsupported `
            -Message 'The database and external anchor schema versions disagree.' `
            -Category InvalidData -TargetObject $Anchor.SchemaVersion
    }
    if ([long]$DatabaseHead.Generation -lt [long]$Anchor.Generation) {
        Stop-HHForensicsOperation -ErrorId ForensicsRollbackDetected `
            -Message 'The forensics database is behind its external anchor.' `
            -Category SecurityError -TargetObject $DatabaseHead.Generation
    }
    $isEqual = [long]$DatabaseHead.Generation -eq [long]$Anchor.Generation
    $stateDisagreement = @(
        @('StateDigest', 'StateMac', 'ProjectionDigest', 'ProjectionMac') |
            Where-Object {
            -not (Test-HHForensicsBytesEqual `
                -Left ([byte[]]$DatabaseHead.$_) -Right ([byte[]]$Anchor.$_))
        }
    )
    if ($isEqual -and $stateDisagreement.Count -gt 0) {
        Stop-HHForensicsOperation -ErrorId ForensicsIntegrityFailed `
            -Message 'The database and external anchor state heads disagree at the same generation.' `
            -Category SecurityError -TargetObject $DatabaseHead.Generation
    }
    return [pscustomobject]@{
        IsEqual = $isEqual
        RequiresVerifiedAdvance = -not $isEqual
    }
}

function Test-HHForensicsMutationChain {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Connection,
        [Parameter(Mandatory)][object]$Schema,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$ForensicsKey,
        [AllowNull()][object]$Transaction
    )

    $initial = Get-HHForensicsInitialState `
        -DatabaseId $Schema.DatabaseId `
        -SchemaFingerprint $Schema.SchemaFingerprint `
        -DatabaseCreatedAtUtc $Schema.DatabaseCreatedAtUtc `
        -MigrationAppliedAtUtc $Schema.MigrationAppliedAtUtc `
        -ForensicsKey $ForensicsKey
    $expectedDigest = $initial.Digest
    $expectedMac = $initial.Mac
    $expectedSequence = 0L
    $expectedLastMutationId = $null
    $rows = @(Invoke-HHSqliteQuery -Connection $Connection -Sql @'
SELECT sequence,mutation_id,mutation_type,routing_key,payload_digest,
    state_digest,projection_digest,projection_mac,previous_mac,mutation_mac,created_at_utc
FROM forensics_mutations
ORDER BY sequence;
'@ -Transaction $Transaction)
    foreach ($row in $rows) {
        $expectedSequence++
        if ([long]$row.sequence -ne $expectedSequence -or
            -not (Test-HHForensicsBytesEqual `
                -Left ([byte[]]$row.previous_mac) -Right $expectedMac)) {
            Stop-HHForensicsOperation -ErrorId ForensicsIntegrityFailed `
                -Message 'The authenticated forensics mutation chain is discontinuous.' `
                -Category SecurityError -TargetObject $row.sequence
        }
        $calculated = Get-HHForensicsMutationState `
            -DatabaseId $Schema.DatabaseId `
            -SchemaFingerprint $Schema.SchemaFingerprint `
            -Sequence $expectedSequence `
            -MutationId ([string]$row.mutation_id) `
            -MutationType ([string]$row.mutation_type) `
            -RoutingKey ([string]$row.routing_key) `
            -OccurredAtUtc ([string]$row.created_at_utc) `
            -PayloadDigest ([byte[]]$row.payload_digest) `
            -ProjectionDigest ([byte[]]$row.projection_digest) `
            -ProjectionMac ([byte[]]$row.projection_mac) `
            -PreviousMac $expectedMac `
            -ForensicsKey $ForensicsKey
        if (-not (Test-HHForensicsBytesEqual `
                    -Left ([byte[]]$row.state_digest) -Right $calculated.Digest) -or
            -not (Test-HHForensicsBytesEqual `
                    -Left ([byte[]]$row.mutation_mac) -Right $calculated.Mac)) {
            Stop-HHForensicsOperation -ErrorId ForensicsIntegrityFailed `
                -Message 'The authenticated forensics mutation chain has been altered.' `
                -Category SecurityError -TargetObject $row.sequence
        }
        $expectedDigest = $calculated.Digest
        $expectedMac = $calculated.Mac
        $expectedLastMutationId = [string]$row.mutation_id
    }
    if ([long]$Schema.Generation -ne $expectedSequence -or
        -not (Test-HHForensicsBytesEqual -Left $Schema.StateDigest -Right $expectedDigest) -or
        -not (Test-HHForensicsBytesEqual -Left $Schema.StateMac -Right $expectedMac) -or
        ($rows.Count -eq 0 -and (
            -not (Test-HHForensicsBytesEqual `
                -Left $Schema.ProjectionDigest -Right $initial.ProjectionDigest) -or
            -not (Test-HHForensicsBytesEqual `
                -Left $Schema.ProjectionMac -Right $initial.ProjectionMac))) -or
        ($rows.Count -gt 0 -and (
            -not (Test-HHForensicsBytesEqual `
                -Left $Schema.ProjectionDigest -Right ([byte[]]$rows[-1].projection_digest)) -or
            -not (Test-HHForensicsBytesEqual `
                -Left $Schema.ProjectionMac -Right ([byte[]]$rows[-1].projection_mac))))) {
        Stop-HHForensicsOperation -ErrorId ForensicsIntegrityFailed `
            -Message 'The forensics state head does not match its authenticated mutation chain.' `
            -Category SecurityError -TargetObject $Schema.Generation
    }
    if (($null -eq $expectedLastMutationId -and $null -ne $Schema.LastMutationId) -or
        ($null -ne $expectedLastMutationId -and
            [string]$Schema.LastMutationId -cne $expectedLastMutationId)) {
        Stop-HHForensicsOperation -ErrorId ForensicsIntegrityFailed `
            -Message 'The state head last mutation identity was altered.' `
            -Category SecurityError -TargetObject $Schema.LastMutationId
    }
}

function Test-HHForensicsProtectedProjection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Connection,
        [Parameter(Mandatory)][object]$Schema,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$ForensicsKey,
        [AllowNull()][object]$Transaction
    )

    $projection = Get-HHForensicsProtectedProjection `
        -DatabaseId $Schema.DatabaseId -SchemaFingerprint $Schema.SchemaFingerprint `
        -ForensicsKey $ForensicsKey -Connection $Connection -Transaction $Transaction
    if (-not (Test-HHForensicsBytesEqual `
                -Left $Schema.ProjectionDigest -Right $projection.Digest) -or
        -not (Test-HHForensicsBytesEqual `
                -Left $Schema.ProjectionMac -Right $projection.Mac)) {
        Stop-HHForensicsOperation -ErrorId ForensicsIntegrityFailed `
            -Message 'A protected forensics row was altered, deleted, or reordered.' `
            -Category SecurityError -TargetObject $Connection.DataSource
    }
    return $projection
}

function Get-HHForensicsDatabaseHead {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Connection,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$ForensicsKey,
        [Parameter(Mandatory)][string]$MigrationPath,
        [string]$ProviderRoot,
        [AllowNull()][object]$Transaction
    )

    $schema = Test-HHForensicsSchema `
        -Connection $Connection -MigrationPath $MigrationPath -ProviderRoot $ProviderRoot `
        -Transaction $Transaction
    $null = Test-HHForensicsProtectedProjection `
        -Connection $Connection -Schema $schema -ForensicsKey $ForensicsKey `
        -Transaction $Transaction
    Test-HHForensicsMutationChain `
        -Connection $Connection -Schema $schema -ForensicsKey $ForensicsKey `
        -Transaction $Transaction
    return New-HHForensicsAnchor `
        -DatabaseId $schema.DatabaseId `
        -SchemaFingerprint $schema.SchemaFingerprint `
        -Generation $schema.Generation `
        -StateDigest $schema.StateDigest `
        -StateMac $schema.StateMac `
        -ProjectionDigest $schema.ProjectionDigest `
        -ProjectionMac $schema.ProjectionMac `
        -ForensicsKey $ForensicsKey
}

function Open-HHForensicsPersistence {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Opens or explicitly initializes the requested owner-private forensics store.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$PersistenceContext,
        [Parameter(Mandatory)][scriptblock]$ForensicsKeyProvider,
        [Parameter(Mandatory)][scriptblock]$AnchorReader,
        [Parameter(Mandatory)][scriptblock]$AnchorWriter,
        [switch]$AllowAnchorInitialize,
        [switch]$AllowAnchorAdvance,
        [scriptblock]$ConnectionFactory = ${function:New-HHSqliteConnection}
    )

    Assert-HHForensicsStorePath -PersistenceContext $PersistenceContext -AllowMissingRoot
    $key = Get-HHForensicsKey -ForensicsKeyProvider $ForensicsKeyProvider
    $connection = $null
    $lock = $null
    try {
        $databaseExisted = [IO.File]::Exists($PersistenceContext.DatabasePath)
        if (-not $databaseExisted -and -not $AllowAnchorInitialize) {
            Stop-HHForensicsOperation -ErrorId ForensicsAnchorRequired `
                -Message 'A new forensics database requires explicit anchor initialization.' `
                -Category SecurityError -TargetObject $PersistenceContext.DatabasePath
        }
        $null = [IO.Directory]::CreateDirectory($PersistenceContext.DataRoot)
        Protect-HHForensicsPrivatePath -Path $PersistenceContext.DataRoot -Directory
        Assert-HHForensicsStorePath -PersistenceContext $PersistenceContext
        try {
            $lockOptions = [IO.FileStreamOptions]::new()
            $lockOptions.Mode = [IO.FileMode]::OpenOrCreate
            $lockOptions.Access = [IO.FileAccess]::ReadWrite
            $lockOptions.Share = [IO.FileShare]::None
            $lockOptions.Options = [IO.FileOptions]::WriteThrough
            if (-not $IsWindows) {
                $lockOptions.UnixCreateMode = [IO.UnixFileMode]::UserRead -bor
                    [IO.UnixFileMode]::UserWrite
            }
            $lock = [IO.File]::Open($PersistenceContext.LockPath, $lockOptions)
        }
        catch {
            Stop-HHForensicsOperation -ErrorId ForensicsPersistenceBusy `
                -Message 'Another process owns the forensics persistence writer lock.' `
                -Category ResourceBusy -TargetObject $PersistenceContext.LockPath `
                -InnerException $_.Exception
        }
        if (-not $databaseExisted) {
            try {
                $databaseOptions = [IO.FileStreamOptions]::new()
                $databaseOptions.Mode = [IO.FileMode]::CreateNew
                $databaseOptions.Access = [IO.FileAccess]::ReadWrite
                $databaseOptions.Share = [IO.FileShare]::None
                $databaseOptions.Options = [IO.FileOptions]::WriteThrough
                if (-not $IsWindows) {
                    $databaseOptions.UnixCreateMode = [IO.UnixFileMode]::UserRead -bor
                        [IO.UnixFileMode]::UserWrite
                }
                $placeholder = [IO.File]::Open(
                    $PersistenceContext.DatabasePath,
                    $databaseOptions
                )
                $placeholder.Dispose()
            }
            catch {
                Stop-HHForensicsOperation -ErrorId ForensicsPathRejected `
                    -Message 'The new forensics database path changed before exclusive creation.' `
                    -Category SecurityError -TargetObject $PersistenceContext.DatabasePath `
                    -InnerException $_.Exception
            }
        }
        Assert-HHForensicsStorePath -PersistenceContext $PersistenceContext
        $connection = & $ConnectionFactory `
            -DatabasePath $PersistenceContext.DatabasePath `
            -Mode ReadWriteCreate -ProviderRoot $PersistenceContext.ProviderRoot
        Assert-HHForensicsStorePath -PersistenceContext $PersistenceContext
        Assert-HHForensicsSqlitePathBinding `
            -Connection $connection -ExpectedDatabasePath $PersistenceContext.DatabasePath
        Protect-HHForensicsStoreFile -PersistenceContext $PersistenceContext
        $null = Invoke-HHSqliteNonQuery -Connection $connection `
            -Sql 'PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;'
        Assert-HHForensicsStorePath -PersistenceContext $PersistenceContext
        Assert-HHForensicsSqlitePathBinding `
            -Connection $connection -ExpectedDatabasePath $PersistenceContext.DatabasePath
        Protect-HHForensicsStoreFile -PersistenceContext $PersistenceContext
        if (-not $databaseExisted) {
            $schemaFingerprint = Get-HHExpectedForensicsSchemaFingerprint `
                -MigrationPath $PersistenceContext.MigrationPath `
                -ProviderRoot $PersistenceContext.ProviderRoot
            $databaseId = [Guid]::NewGuid().ToByteArray()
            $initializedAtUtc = [DateTimeOffset]::UtcNow.ToString('o')
            $initial = Get-HHForensicsInitialState `
                -DatabaseId $databaseId -SchemaFingerprint $schemaFingerprint `
                -DatabaseCreatedAtUtc $initializedAtUtc `
                -MigrationAppliedAtUtc $initializedAtUtc `
                -ForensicsKey $key
            Initialize-HHForensicsSchema `
                -Connection $connection -DatabaseId $databaseId `
                -InitialStateDigest $initial.Digest -InitialStateMac $initial.Mac `
                -InitialProjectionDigest $initial.ProjectionDigest `
                -InitialProjectionMac $initial.ProjectionMac `
                -AppliedAtUtc $initializedAtUtc `
                -MigrationPath $PersistenceContext.MigrationPath
        }
        $databaseHead = Get-HHForensicsDatabaseHead `
            -Connection $connection -ForensicsKey $key `
            -MigrationPath $PersistenceContext.MigrationPath `
            -ProviderRoot $PersistenceContext.ProviderRoot
        $anchor = & $AnchorReader $PersistenceContext
        if ($null -eq $anchor) {
            if ($databaseExisted) {
                Stop-HHForensicsOperation -ErrorId ForensicsAnchorRequired `
                    -Message 'The existing forensics database has no external anchor.' `
                    -Category SecurityError -TargetObject $PersistenceContext.DatabasePath
            }
            & $AnchorWriter $null $databaseHead $PersistenceContext
            $anchor = $databaseHead
        }
        else {
            $comparison = Compare-HHForensicsAnchor `
                -DatabaseHead $databaseHead -Anchor $anchor -ForensicsKey $key
            if ($comparison.RequiresVerifiedAdvance) {
                if (-not $AllowAnchorAdvance) {
                    Stop-HHForensicsOperation -ErrorId ForensicsAnchorAdvanceRequired `
                        -Message 'The authenticated database is ahead of its external anchor.' `
                        -Category SecurityError -TargetObject $databaseHead.Generation
                }
                & $AnchorWriter $anchor $databaseHead $PersistenceContext
                $anchor = $databaseHead
            }
        }
        return [pscustomobject]@{
            Persistence = $PersistenceContext
            Connection = $connection
            ForensicsKey = $key
            AnchorReader = $AnchorReader
            AnchorWriter = $AnchorWriter
            Anchor = $anchor
            WriterLock = $lock
            IsUsable = $true
        }
    }
    catch {
        if ($null -ne $connection) { $connection.Dispose() }
        if ($null -ne $lock) { $lock.Dispose() }
        [Array]::Clear($key, 0, $key.Length)
        throw
    }
}

function Close-HHForensicsPersistence {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Closes only the supplied persistence handles and clears its in-memory key.'
    )]
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Context)

    if ($null -ne $Context.Connection) { $Context.Connection.Dispose() }
    if ($null -ne $Context.WriterLock) { $Context.WriterLock.Dispose() }
    if ($null -ne $Context.ForensicsKey) {
        [Array]::Clear($Context.ForensicsKey, 0, $Context.ForensicsKey.Length)
    }
    $Context.IsUsable = $false
}

function Invoke-HHForensicsAnchoredTransaction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$MutationId,
        [Parameter(Mandatory)][string]$MutationType,
        [Parameter(Mandatory)][string]$RoutingKey,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$PayloadDigest,
        [Parameter(Mandatory)][scriptblock]$Action,
        [AllowNull()][scriptblock]$CommitInvoker,
        [string]$OccurredAtUtc = ([DateTimeOffset]::UtcNow.ToString('o'))
    )

    if (-not $Context.IsUsable -or $PayloadDigest.Length -ne 32) {
        Stop-HHForensicsOperation -ErrorId ForensicsPersistenceUnavailable `
            -Message 'The forensics persistence context is unavailable or malformed.' `
            -Category InvalidOperation -TargetObject $Context.Persistence.DatabasePath
    }
    $transaction = $Context.Connection.BeginTransaction(
        [Data.IsolationLevel]::Serializable,
        $false
    )
    # The private writer-lock file coordinates HostHunter writers. This immediate
    # SQLite transaction independently prevents an uncooperative SQLite writer
    # from changing authenticated rows between verification and mutation.
    try {
        try {
            Assert-HHForensicsSqlitePathBinding `
                -Connection $Context.Connection `
                -ExpectedDatabasePath $Context.Persistence.DatabasePath
        }
        catch {
            $Context.IsUsable = $false
            throw
        }
        $databaseHead = Get-HHForensicsDatabaseHead `
            -Connection $Context.Connection -ForensicsKey $Context.ForensicsKey `
            -MigrationPath $Context.Persistence.MigrationPath `
            -ProviderRoot $Context.Persistence.ProviderRoot -Transaction $transaction
        $anchor = & $Context.AnchorReader $Context.Persistence
        if ($null -eq $anchor) {
            Stop-HHForensicsOperation -ErrorId ForensicsAnchorRequired `
                -Message 'The external forensics anchor disappeared before mutation.' `
                -Category SecurityError -TargetObject $Context.Persistence.DatabasePath
        }
        $comparison = Compare-HHForensicsAnchor `
            -DatabaseHead $databaseHead -Anchor $anchor -ForensicsKey $Context.ForensicsKey
        if (-not $comparison.IsEqual) {
            Stop-HHForensicsOperation -ErrorId ForensicsAnchorAdvanceRequired `
                -Message 'The external forensics anchor is stale; reopen with explicit recovery.' `
                -Category SecurityError -TargetObject $databaseHead.Generation
        }
        $sequence = [long]$databaseHead.Generation + 1L
        $result = & $Action $Context.Connection $transaction $Context.ForensicsKey
        $projection = Get-HHForensicsProtectedProjection `
            -DatabaseId $databaseHead.DatabaseId `
            -SchemaFingerprint $databaseHead.SchemaFingerprint `
            -ForensicsKey $Context.ForensicsKey `
            -Connection $Context.Connection -Transaction $transaction
        $next = Get-HHForensicsMutationState `
            -DatabaseId $databaseHead.DatabaseId `
            -SchemaFingerprint $databaseHead.SchemaFingerprint `
            -Sequence $sequence -MutationId $MutationId -MutationType $MutationType `
            -RoutingKey $RoutingKey -OccurredAtUtc $OccurredAtUtc `
            -PayloadDigest $PayloadDigest `
            -ProjectionDigest $projection.Digest -ProjectionMac $projection.Mac `
            -PreviousMac $databaseHead.StateMac -ForensicsKey $Context.ForensicsKey
        $null = Invoke-HHSqliteNonQuery `
            -Connection $Context.Connection -Transaction $transaction -Sql @'
INSERT INTO forensics_mutations(
    sequence,mutation_id,mutation_type,routing_key,payload_digest,state_digest,
    projection_digest,projection_mac,previous_mac,mutation_mac,created_at_utc
)
VALUES(
    @sequence,@mutation_id,@mutation_type,@routing_key,@payload_digest,@state_digest,
    @projection_digest,@projection_mac,@previous_mac,@mutation_mac,@created_at
);
'@ -Parameters @{
            sequence = $sequence
            mutation_id = $MutationId
            mutation_type = $MutationType
            routing_key = $RoutingKey
            payload_digest = $PayloadDigest
            state_digest = $next.Digest
            projection_digest = $projection.Digest
            projection_mac = $projection.Mac
            previous_mac = $databaseHead.StateMac
            mutation_mac = $next.Mac
            created_at = $OccurredAtUtc
        }
        $stateChanged = Invoke-HHSqliteNonQuery `
            -Connection $Context.Connection -Transaction $transaction -Sql @'
UPDATE forensics_state
SET generation=@sequence,state_digest=@state_digest,state_mac=@mutation_mac,
    projection_digest=@projection_digest,projection_mac=@projection_mac,
    last_mutation_id=@mutation_id
WHERE singleton_id=1 AND generation=@previous_sequence AND state_mac=@previous_mac;
'@ -Parameters @{
            sequence = $sequence
            previous_sequence = $sequence - 1L
            mutation_id = $MutationId
            mutation_type = $MutationType
            routing_key = $RoutingKey
            payload_digest = $PayloadDigest
            state_digest = $next.Digest
            projection_digest = $projection.Digest
            projection_mac = $projection.Mac
            previous_mac = $databaseHead.StateMac
            mutation_mac = $next.Mac
        }
        if ($stateChanged -ne 1) {
            throw 'The authenticated forensics state head changed during its transaction.'
        }
    }
    catch {
        try { $transaction.Rollback() }
        catch { Write-Debug 'The already-failed forensics transaction could not be rolled back.' }
        $transaction.Dispose()
        throw
    }
    try {
        if ($null -eq $CommitInvoker) { $transaction.Commit() }
        else { & $CommitInvoker $transaction }
    }
    catch {
        $Context.IsUsable = $false
        $transaction.Dispose()
        Stop-HHForensicsOperation -ErrorId ForensicsCommitUnknown `
            -Message 'The SQLite commit returned an unknown outcome.' `
            -Category SecurityError -TargetObject $MutationId -InnerException $_.Exception
    }
    $transaction.Dispose()
    try {
        # HAS_MOVED binds the reviewed path to SQLite's still-open main handle;
        # it is not a claim that the provider supports SQLITE_OPEN_NOFOLLOW.
        Assert-HHForensicsStorePath -PersistenceContext $Context.Persistence
        Assert-HHForensicsSqlitePathBinding `
            -Connection $Context.Connection `
            -ExpectedDatabasePath $Context.Persistence.DatabasePath
        Protect-HHForensicsStoreFile -PersistenceContext $Context.Persistence
    }
    catch {
        $Context.IsUsable = $false
        Stop-HHForensicsOperation -ErrorId ForensicsCommitUnknown `
            -Message 'The SQLite transaction committed but its database path binding changed.' `
            -Category SecurityError -TargetObject $MutationId -InnerException $_.Exception
    }

    $newAnchor = New-HHForensicsAnchor `
        -DatabaseId $databaseHead.DatabaseId `
        -SchemaFingerprint $databaseHead.SchemaFingerprint `
        -Generation $sequence -StateDigest $next.Digest -StateMac $next.Mac `
        -ProjectionDigest $projection.Digest -ProjectionMac $projection.Mac `
        -ForensicsKey $Context.ForensicsKey
    try { & $Context.AnchorWriter $anchor $newAnchor $Context.Persistence }
    catch {
        $Context.IsUsable = $false
        Stop-HHForensicsOperation -ErrorId ForensicsCommitUnknown `
            -Message 'The SQLite transaction committed but the external forensics anchor was not sealed.' `
            -Category SecurityError -TargetObject $MutationId -InnerException $_.Exception
    }
    $Context.Anchor = $newAnchor
    return $result
}
