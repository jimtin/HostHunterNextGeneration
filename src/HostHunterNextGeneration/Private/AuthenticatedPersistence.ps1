Set-StrictMode -Version Latest

function Get-HHSqlitePersistenceHead {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Connection,
        [Parameter(Mandatory)][byte[]]$SchemaFingerprint
    )

    if ($SchemaFingerprint.Length -ne 32) {
        throw [ArgumentException]::new('SchemaFingerprint must contain 32 bytes.', 'SchemaFingerprint')
    }
    $identityRows = @(Invoke-HHSqliteQuery `
            -Connection $Connection `
            -Sql 'SELECT database_id, ledger_id FROM database_identity WHERE singleton_id = 1;')
    $targetRows = @(Invoke-HHSqliteQuery `
            -Connection $Connection `
            -Sql @'
SELECT generation, target_state_mac
FROM target_store_state
WHERE singleton_id = 1;
'@)
    $auditRows = @(Invoke-HHSqliteQuery `
            -Connection $Connection `
            -Sql @'
SELECT sequence, event_mac
FROM audit_events
ORDER BY sequence DESC
LIMIT 1;
'@)
    if ($identityRows.Count -ne 1 -or $targetRows.Count -ne 1 -or $auditRows.Count -gt 1) {
        Stop-HHPersistenceOperation `
            -ErrorId 'AuditIntegrityFailed' `
            -Message 'The persistence head rows are missing or ambiguous.' `
            -Category ([Management.Automation.ErrorCategory]::InvalidData) `
            -TargetObject $Connection.DataSource
    }
    [byte[]]$databaseId = [byte[]]$identityRows[0].database_id
    [byte[]]$ledgerId = [byte[]]$identityRows[0].ledger_id
    [byte[]]$targetMac = [byte[]]$targetRows[0].target_state_mac
    $auditSequence = if ($auditRows.Count -eq 0) { 0L } else { [long]$auditRows[0].sequence }
    [byte[]]$auditMac = if ($auditRows.Count -eq 0) {
        [byte[]]::new(32)
    }
    else { [byte[]]$auditRows[0].event_mac }
    if ($databaseId.Length -ne 16 -or $ledgerId.Length -ne 16 -or
        $targetMac.Length -ne 32 -or $auditMac.Length -ne 32 -or
        [long]$targetRows[0].generation -lt 0 -or $auditSequence -lt 0) {
        Stop-HHPersistenceOperation `
            -ErrorId 'AuditIntegrityFailed' `
            -Message 'The persistence head contains invalid values.' `
            -Category ([Management.Automation.ErrorCategory]::InvalidData) `
            -TargetObject $Connection.DataSource
    }
    [pscustomobject][ordered]@{
        DatabaseId = $databaseId
        LedgerId = $ledgerId
        SchemaVersion = 1
        AuditSequence = $auditSequence
        AuditMac = $auditMac
        TargetGeneration = [long]$targetRows[0].generation
        TargetStateMac = $targetMac
        SchemaFingerprint = [byte[]]$SchemaFingerprint.Clone()
    }
}

function Test-HHPersistenceAnchorState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$DatabaseHead,
        [Parameter(Mandatory)][object]$Anchor
    )

    foreach ($propertyName in @(
            'DatabaseId', 'LedgerId', 'SchemaVersion', 'AuditSequence', 'AuditMac',
            'TargetGeneration', 'TargetStateMac', 'SchemaFingerprint'
        )) {
        if ($null -eq $DatabaseHead.PSObject.Properties[$propertyName] -or
            $null -eq $Anchor.PSObject.Properties[$propertyName]) {
            Stop-HHPersistenceOperation `
                -ErrorId 'AuditIntegrityFailed' `
                -Message 'The database head or external anchor is incomplete.' `
                -Category ([Management.Automation.ErrorCategory]::InvalidData) `
                -TargetObject $null
        }
    }
    foreach ($identityProperty in @('DatabaseId', 'LedgerId', 'SchemaFingerprint')) {
        if (-not (Test-HHPersistenceBytesEqual `
                -Left ([byte[]]$DatabaseHead.$identityProperty) `
                -Right ([byte[]]$Anchor.$identityProperty))) {
            Stop-HHPersistenceOperation `
                -ErrorId 'AuditIntegrityFailed' `
                -Message 'The database identity does not match its external anchor.' `
                -Category ([Management.Automation.ErrorCategory]::SecurityError) `
                -TargetObject $null
        }
    }
    if ([int]$DatabaseHead.SchemaVersion -ne 1 -or
        [int]$Anchor.SchemaVersion -ne [int]$DatabaseHead.SchemaVersion) {
        Stop-HHPersistenceOperation `
            -ErrorId 'PersistenceSchemaUnsupported' `
            -Message 'The database schema version does not match its external anchor.' `
            -Category ([Management.Automation.ErrorCategory]::InvalidData) `
            -TargetObject $null
    }

    if ([long]$DatabaseHead.AuditSequence -lt 0 -or [long]$Anchor.AuditSequence -lt 0 -or
        [long]$DatabaseHead.TargetGeneration -lt 0 -or [long]$Anchor.TargetGeneration -lt 0) {
        Stop-HHPersistenceOperation `
            -ErrorId 'AuditIntegrityFailed' `
            -Message 'The database head or external anchor contains a negative position.' `
            -Category ([Management.Automation.ErrorCategory]::InvalidData) `
            -TargetObject $null
    }
    $auditComparison = ([long]$DatabaseHead.AuditSequence).CompareTo([long]$Anchor.AuditSequence)
    $targetComparison = ([long]$DatabaseHead.TargetGeneration).CompareTo([long]$Anchor.TargetGeneration)
    if ($auditComparison -lt 0 -or $targetComparison -lt 0) {
        Stop-HHPersistenceOperation `
            -ErrorId 'AuditRollbackDetected' `
            -Message 'The database is behind its external persistence anchor.' `
            -Category ([Management.Automation.ErrorCategory]::SecurityError) `
            -TargetObject $null
    }
    if (($auditComparison -eq 0 -and -not (Test-HHPersistenceBytesEqual `
                -Left ([byte[]]$DatabaseHead.AuditMac) `
                -Right ([byte[]]$Anchor.AuditMac))) -or
        ($targetComparison -eq 0 -and -not (Test-HHPersistenceBytesEqual `
                -Left ([byte[]]$DatabaseHead.TargetStateMac) `
                -Right ([byte[]]$Anchor.TargetStateMac)))) {
        Stop-HHPersistenceOperation `
            -ErrorId 'AuditIntegrityFailed' `
            -Message 'The database head differs from the external anchor at the same position.' `
            -Category ([Management.Automation.ErrorCategory]::SecurityError) `
            -TargetObject $null
    }
    [pscustomobject][ordered]@{
        IsEqual = $auditComparison -eq 0 -and $targetComparison -eq 0
        RequiresVerifiedAdvance = $auditComparison -gt 0 -or $targetComparison -gt 0
        AuditAdvanceRequired = $auditComparison -gt 0
        TargetAdvanceRequired = $targetComparison -gt 0
    }
}

function Open-HHAuthenticatedPersistence {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseApprovedVerbs',
        '',
        Justification = 'Open accurately describes acquisition of owned persistence resources.'
    )]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Private coordinator is called only after the public authorization boundary.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$PersistenceContext,
        [switch]$OperationLock,
        [switch]$AllowAnchorAdvance,
        [scriptblock]$MasterKeyProvider,
        [scriptblock]$AnchorReader,
        [scriptblock]$AnchorWriter,
        [string]$ProviderRoot
    )

    Initialize-HHPersistenceRoot -PersistenceContext $PersistenceContext
    Assert-HHLegacyPersistenceAbsent -PersistenceContext $PersistenceContext
    $operationLockContext = $null
    $writerLockContext = $null
    $connection = $null
    $masterKey = $null
    try {
        if ($OperationLock) {
            $operationLockContext = Enter-HHPersistenceFileLock `
                -Path $PersistenceContext.OperationLockPath `
                -FailureId OperationBusy
            Assert-HHPersistencePathSafety -DataRoot $PersistenceContext.DataRoot
            Assert-HHLegacyPersistenceAbsent -PersistenceContext $PersistenceContext
        }
        $databaseExisted = [IO.File]::Exists($PersistenceContext.DatabasePath)
        $masterKey = if ($null -eq $MasterKeyProvider) {
            Get-HHMasterKey `
                -DataRoot $PersistenceContext.DataRoot `
                -RequireExisting:$databaseExisted
        }
        else { & $MasterKeyProvider $PersistenceContext $databaseExisted }
        Assert-HHAuditMasterKey -MasterKey $masterKey
        $null = Initialize-HHSqliteDatabase `
            -PersistenceContext $PersistenceContext `
            -MasterKey $masterKey `
            -AnchorWriter $AnchorWriter `
            -ProviderRoot $ProviderRoot

        if ($AllowAnchorAdvance) {
            $writerLockContext = Enter-HHPersistenceFileLock `
                -Path $PersistenceContext.WriterLockPath `
                -FailureId PersistenceBusy
        }
        $connection = New-HHSqliteConnection `
            -DatabasePath $PersistenceContext.DatabasePath `
            -Mode ReadWrite `
            -ProviderRoot $ProviderRoot
        $schema = Test-HHSqliteDatabaseSchema `
            -Connection $connection `
            -MigrationPath $PersistenceContext.MigrationPath `
            -ProviderRoot $ProviderRoot
        $anchor = Read-HHPersistenceAnchor `
            -PersistenceContext $PersistenceContext `
            -MasterKey $masterKey `
            -AnchorReader $AnchorReader
        if ($null -eq $anchor) {
            Stop-HHPersistenceOperation `
                -ErrorId 'AuditKeyUnavailable' `
                -Message 'The database external anchor is missing. Remote activity is blocked.' `
                -Category ([Management.Automation.ErrorCategory]::ResourceUnavailable) `
                -TargetObject $PersistenceContext.DataRoot
        }
        $chain = Test-HHSqliteAuditChain -Connection $connection -MasterKey $masterKey
        $snapshot = Read-HHTargetRepositorySnapshot `
            -Connection $connection `
            -MasterKey $masterKey
        $head = Get-HHSqlitePersistenceHead `
            -Connection $connection `
            -SchemaFingerprint $schema.SchemaFingerprint
        if ($chain.Sequence -ne $head.AuditSequence -or
            -not (Test-HHPersistenceBytesEqual -Left $chain.LastMac -Right $head.AuditMac) -or
            $snapshot.Generation -ne $head.TargetGeneration -or
            -not (Test-HHPersistenceBytesEqual `
                -Left $snapshot.StateEvidence.TargetStateMac `
                -Right $head.TargetStateMac)) {
            Stop-HHPersistenceOperation `
                -ErrorId 'AuditIntegrityFailed' `
                -Message 'The authenticated repository heads do not match their verified state.' `
                -Category ([Management.Automation.ErrorCategory]::SecurityError) `
                -TargetObject $PersistenceContext.DatabasePath
        }
        $comparison = Test-HHPersistenceAnchorState -DatabaseHead $head -Anchor $anchor
        if ($comparison.RequiresVerifiedAdvance) {
            if (-not $AllowAnchorAdvance) {
                Stop-HHPersistenceOperation `
                    -ErrorId 'AuditRecoveryRequired' `
                    -Message 'The database contains a verified crash extension that must be resealed before this operation.' `
                    -Category ([Management.Automation.ErrorCategory]::InvalidOperation) `
                    -TargetObject $PersistenceContext.DatabasePath
            }
            Write-HHPersistenceAnchor `
                -PersistenceContext $PersistenceContext `
                -Anchor $head `
                -MasterKey $masterKey `
                -ExpectedArtifact ([byte[]]$anchor.Artifact) `
                -AnchorWriter $AnchorWriter
            $anchor = [pscustomobject]@{}
            foreach ($property in $head.PSObject.Properties) {
                $anchor | Add-Member -NotePropertyName $property.Name -NotePropertyValue $property.Value
            }
            $anchor | Add-Member -NotePropertyName Artifact `
                -NotePropertyValue (ConvertTo-HHPersistenceAnchorArtifact -Anchor $head -MasterKey $masterKey)
        }
        $result = [pscustomobject][ordered]@{
            PersistenceContext = $PersistenceContext
            Connection = $connection
            MasterKey = [byte[]]$masterKey
            Anchor = $anchor
            Schema = $schema
            TargetSnapshot = $snapshot
            OperationLock = $operationLockContext
            WriterLock = $writerLockContext
            ProviderRoot = $ProviderRoot
            AnchorReader = $AnchorReader
            AnchorWriter = $AnchorWriter
        }
        $result.PSObject.TypeNames.Insert(0, 'HostHunter.AuthenticatedPersistenceContext')
        if ($AllowAnchorAdvance) {
            $result | Add-Member -NotePropertyName RecoveryReceipts `
                -NotePropertyValue @(Recover-HHAuthenticatedAuditState -Context $result)
        }
        $connection = $null
        $masterKey = $null
        $operationLockContext = $null
        $writerLockContext = $null
        return $result
    }
    catch {
        if ($null -ne $connection) { $connection.Dispose() }
        if ($null -ne $masterKey) { [Array]::Clear($masterKey, 0, $masterKey.Length) }
        Exit-HHPersistenceFileLock -LockContext $writerLockContext
        Exit-HHPersistenceFileLock -LockContext $operationLockContext
        throw
    }
}

function Close-HHAuthenticatedPersistence {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseApprovedVerbs',
        '',
        Justification = 'Close accurately describes release of owned persistence resources.'
    )]
    [CmdletBinding()]
    param([AllowNull()][object]$Context)

    if ($null -eq $Context) { return }
    if ($null -ne $Context.Connection) {
        $Context.Connection.Dispose()
        $Context.Connection = $null
    }
    if ($null -ne $Context.MasterKey) {
        [Array]::Clear($Context.MasterKey, 0, $Context.MasterKey.Length)
        $Context.MasterKey = $null
    }
    Exit-HHPersistenceFileLock -LockContext $Context.WriterLock
    Exit-HHPersistenceFileLock -LockContext $Context.OperationLock
    $Context.WriterLock = $null
    $Context.OperationLock = $null
}

function Invoke-HHAnchoredPersistenceTransaction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][scriptblock]$Action,
        [object[]]$ArgumentList = @()
    )

    if ($null -eq $Context.WriterLock -or $null -eq $Context.Connection) {
        throw 'An authenticated writer context is required.'
    }
    $transaction = $Context.Connection.BeginTransaction()
    $databaseCommitted = $false
    try {
        $preparedReceipt = & $Action $Context.Connection $transaction $Context $ArgumentList
        $transaction.Commit()
        $databaseCommitted = $true
    }
    catch {
        if (-not $databaseCommitted) {
            try { $transaction.Rollback() }
            catch { Write-Debug 'The failed transaction was already rolled back by SQLite.' }
        }
        throw
    }
    finally {
        $transaction.Dispose()
    }

    try {
        $schema = Test-HHSqliteDatabaseSchema `
            -Connection $Context.Connection `
            -MigrationPath $Context.PersistenceContext.MigrationPath `
            -ProviderRoot $Context.ProviderRoot
        $head = Get-HHSqlitePersistenceHead `
            -Connection $Context.Connection `
            -SchemaFingerprint $schema.SchemaFingerprint
        $chain = Test-HHSqliteAuditChain `
            -Connection $Context.Connection `
            -MasterKey $Context.MasterKey
        $snapshot = Read-HHTargetRepositorySnapshot `
            -Connection $Context.Connection `
            -MasterKey $Context.MasterKey
        if ($chain.Sequence -ne $head.AuditSequence -or
            -not (Test-HHPersistenceBytesEqual -Left $chain.LastMac -Right $head.AuditMac) -or
            $snapshot.Generation -ne $head.TargetGeneration -or
            -not (Test-HHPersistenceBytesEqual `
                -Left $snapshot.StateEvidence.TargetStateMac `
                -Right $head.TargetStateMac)) {
            throw 'The committed database head did not verify before sealing.'
        }
        Write-HHPersistenceAnchor `
            -PersistenceContext $Context.PersistenceContext `
            -Anchor $head `
            -MasterKey $Context.MasterKey `
            -ExpectedArtifact ([byte[]]$Context.Anchor.Artifact) `
            -AnchorWriter $Context.AnchorWriter
        $head | Add-Member -NotePropertyName Artifact `
            -NotePropertyValue (ConvertTo-HHPersistenceAnchorArtifact `
                -Anchor $head `
                -MasterKey $Context.MasterKey)
        $Context.Anchor = $head
        $Context.Schema = $schema
        $Context.TargetSnapshot = $snapshot
        if ($null -ne $preparedReceipt) {
            $preparedReceipt | Add-Member -NotePropertyName Prepared -NotePropertyValue $true -Force
            $preparedReceipt | Add-Member -NotePropertyName Committed -NotePropertyValue $true -Force
        }
        return $preparedReceipt
    }
    catch {
        $exception = [InvalidOperationException]::new(
            'The database committed but the external persistence seal could not be proven.',
            $_.Exception
        )
        $exception.Data['HHPersistenceCommitState'] = 'Unknown'
        throw $exception
    }
}
