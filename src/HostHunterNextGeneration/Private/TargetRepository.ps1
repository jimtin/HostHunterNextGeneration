Set-StrictMode -Version Latest

$script:HHTargetRepositoryDomain = 'HostHunterNextGeneration/target-state/v1'

function Get-HHTargetRepositoryErrorRecord {
    [CmdletBinding()]
    [OutputType([System.Management.Automation.ErrorRecord])]
    param(
        [Parameter(Mandatory)][string]$ErrorId,
        [Parameter(Mandatory)][string]$Message,
        [Parameter(Mandatory)][System.Management.Automation.ErrorCategory]$Category,
        [AllowNull()][object]$TargetObject,
        [AllowNull()][System.Exception]$InnerException
    )

    Get-HHPersistenceErrorRecord @PSBoundParameters
}

function Stop-HHTargetRepositoryOperation {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Throws a terminating repository error and does not mutate state.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ErrorId,
        [Parameter(Mandatory)][string]$Message,
        [Parameter(Mandatory)][System.Management.Automation.ErrorCategory]$Category,
        [AllowNull()][object]$TargetObject,
        [AllowNull()][System.Exception]$InnerException
    )

    $PSCmdlet.ThrowTerminatingError((Get-HHTargetRepositoryErrorRecord @PSBoundParameters))
}

function ConvertTo-HHTargetRepositoryEntry {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowNull()][object]$InputObject)

    if ($null -eq $InputObject) {
        throw 'A target repository entry cannot be null.'
    }
    $candidateTarget = if ($null -ne $InputObject.PSObject.Properties['Target']) {
        $InputObject.Target
    }
    else {
        $InputObject
    }
    if ($null -eq $InputObject.PSObject.Properties['Revision']) {
        throw 'A target repository entry requires an internal Revision.'
    }
    $revision = [long]$InputObject.Revision
    if ($revision -lt 1) {
        throw 'A target repository Revision must be greater than zero.'
    }
    $target = ConvertTo-HHValidatedTargetRecord -InputObject $candidateTarget
    $entry = [pscustomobject][ordered]@{
        Target = $target
        Revision = $revision
    }
    $entry.PSObject.TypeNames.Insert(0, 'HostHunter.TargetRepositoryEntry')
    return $entry
}

function Get-HHOrdinalSortedTargetRepositoryEntry {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Target
    )

    $entries = @(
        foreach ($item in $Target) {
            ConvertTo-HHTargetRepositoryEntry -InputObject $item
        }
    )
    $entryTargets = @(foreach ($entry in $entries) { $entry.Target })
    $null = Assert-HHTargetSet -Target $entryTargets -AllowEmpty
    $sorted = [Collections.Generic.SortedDictionary[string, object]]::new(
        [StringComparer]::Ordinal
    )
    foreach ($entry in $entries) {
        $sorted.Add($entry.Target.Name, $entry)
    }
    return @($sorted.Values)
}

function ConvertTo-HHTargetRepositorySnapshotByte {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Target
    )

    $entries = @(Get-HHOrdinalSortedTargetRepositoryEntry -Target $Target)
    $serializedTargets = @(
        foreach ($entry in $entries) {
            $item = $entry.Target
            [ordered]@{
                name = $item.Name
                transport = $item.Transport
                hostName = $item.HostName
                port = [int]$item.Port
                userName = $item.UserName
                authentication = $item.Authentication
                credentialStorage = $item.CredentialStorage
                powerShellRuntime = $item.PowerShellRuntime
                hostKeyFingerprint = $item.HostKeyFingerprint
                keyPath = $item.KeyPath
                isActive = [bool]$item.IsActive
                lastValidatedAtUtc = $item.LastValidatedAtUtc
                lastValidatedPSEdition = $item.LastValidatedPSEdition
                lastValidatedPowerShellVersion = $item.LastValidatedPowerShellVersion
                lastValidatedExecutionMode = $item.LastValidatedExecutionMode
                revision = [long]$entry.Revision
            }
        }
    )
    $document = [ordered]@{
        formatVersion = 1
        targets = [object[]]$serializedTargets
    }
    $json = $document | ConvertTo-Json -Depth 5 -Compress
    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($json)
    Write-Output -InputObject $bytes -NoEnumerate
}

function Get-HHTargetRepositoryStateEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$DatabaseId,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$LedgerId,
        [Parameter(Mandatory)][ValidateRange(1, [int]::MaxValue)][int]$SchemaVersion,
        [Parameter(Mandatory)][ValidateRange(0, [long]::MaxValue)][long]$Generation,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$PriorMutationMac,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Target,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$MasterKey
    )

    if ($DatabaseId.Length -ne 16 -or $LedgerId.Length -ne 16 -or
        $PriorMutationMac.Length -ne 32) {
        throw 'Target repository identity and prior-mutation values have invalid lengths.'
    }
    Assert-HHAuditMasterKey -MasterKey $MasterKey
    $entries = @(Get-HHOrdinalSortedTargetRepositoryEntry -Target $Target)
    $snapshotBytes = ConvertTo-HHTargetRepositorySnapshotByte -Target $entries
    $snapshotHash = Get-HHPersistenceHash -Bytes $snapshotBytes
    $stateDocument = [ordered]@{
        domain = $script:HHTargetRepositoryDomain
        databaseId = [Convert]::ToHexString($DatabaseId).ToLowerInvariant()
        ledgerId = [Convert]::ToHexString($LedgerId).ToLowerInvariant()
        schemaVersion = $SchemaVersion
        generation = $Generation
        priorMutationMac = [Convert]::ToHexString($PriorMutationMac).ToLowerInvariant()
        snapshotHash = [Convert]::ToHexString($snapshotHash).ToLowerInvariant()
    }
    $stateBytes = [System.Text.UTF8Encoding]::new($false).GetBytes(
        ($stateDocument | ConvertTo-Json -Compress)
    )
    $targetKey = Get-HHPersistenceDerivedKey -MasterKey $MasterKey -Purpose TargetState
    try {
        $targetStateMac = Get-HHPersistenceMac -Key $targetKey -Bytes $stateBytes
        $evidence = [pscustomobject][ordered]@{
            SnapshotHash = $snapshotHash
            TargetStateMac = $targetStateMac
            SnapshotBytes = $snapshotBytes
            Entries = [object[]]$entries
        }
        $evidence.PSObject.TypeNames.Insert(0, 'HostHunter.TargetRepositoryStateEvidence')
        return $evidence
    }
    finally {
        [Array]::Clear($targetKey, 0, $targetKey.Length)
        [Array]::Clear($stateBytes, 0, $stateBytes.Length)
    }
}

function ConvertFrom-HHTargetRepositoryRow {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Row)

    $target = New-HHTargetRecord `
        -Name ([string]$Row.name) `
        -Transport ([string]$Row.transport) `
        -HostName ([string]$Row.host_name) `
        -Port ([int]$Row.port) `
        -UserName ([string]$Row.user_name) `
        -Authentication ([string]$Row.authentication) `
        -CredentialStorage ([string]$Row.credential_storage) `
        -PowerShellRuntime ([string]$Row.powershell_runtime) `
        -HostKeyFingerprint $Row.host_key_fingerprint `
        -KeyPath $Row.key_path `
        -IsActive ([long]$Row.is_active -eq 1) `
        -LastValidatedAtUtc ([string]$Row.last_validated_at_utc) `
        -LastValidatedPSEdition ([string]$Row.last_validated_ps_edition) `
        -LastValidatedPowerShellVersion ([string]$Row.last_validated_powershell_version) `
        -LastValidatedExecutionMode ([string]$Row.last_validated_execution_mode)
    ConvertTo-HHTargetRepositoryEntry -InputObject ([pscustomobject]@{
            Target = $target
            Revision = [long]$Row.revision
        })
}

function Read-HHTargetRepositoryEntry {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)][object]$Connection,
        [AllowNull()][object]$Transaction
    )

    $rows = @(Invoke-HHSqliteQuery `
            -Connection $Connection `
            -Transaction $Transaction `
            -Sql @'
SELECT name, transport, host_name, port, user_name, authentication, credential_storage,
    powershell_runtime, host_key_fingerprint, key_path, is_active,
    last_validated_at_utc, last_validated_ps_edition,
    last_validated_powershell_version, last_validated_execution_mode,
    revision
FROM target_profiles;
'@)
    $entries = @(
        foreach ($row in $rows) {
            ConvertFrom-HHTargetRepositoryRow -Row $row
        }
    )
    return @(Get-HHOrdinalSortedTargetRepositoryEntry -Target $entries)
}

function Read-HHTargetRepositoryIdentityState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Connection,
        [AllowNull()][object]$Transaction
    )

    $rows = @(Invoke-HHSqliteQuery `
            -Connection $Connection `
            -Transaction $Transaction `
            -Sql @'
SELECT d.database_id, d.ledger_id, d.format_version,
    s.generation, s.snapshot_hash, s.target_state_mac,
    s.prior_mutation_mac, s.last_mutation_id
FROM database_identity AS d
CROSS JOIN target_store_state AS s
WHERE d.singleton_id = 1 AND s.singleton_id = 1;
'@)
    if ($rows.Count -ne 1) {
        Stop-HHTargetRepositoryOperation `
            -ErrorId AuditIntegrityFailed `
            -Message 'The target repository identity or state row is missing.' `
            -Category ([System.Management.Automation.ErrorCategory]::InvalidData) `
            -TargetObject $Connection.DataSource
    }
    $state = $rows[0]
    if ([int]$state.format_version -ne 1 -or
        ([byte[]]$state.database_id).Length -ne 16 -or
        ([byte[]]$state.ledger_id).Length -ne 16 -or
        ([byte[]]$state.snapshot_hash).Length -ne 32 -or
        ([byte[]]$state.target_state_mac).Length -ne 32 -or
        ([byte[]]$state.prior_mutation_mac).Length -ne 32 -or
        ($null -ne $state.last_mutation_id -and
            ([byte[]]$state.last_mutation_id).Length -ne 16) -or
        [long]$state.generation -lt 0) {
        Stop-HHTargetRepositoryOperation `
            -ErrorId AuditIntegrityFailed `
            -Message 'The target repository identity or authenticated state is invalid.' `
            -Category ([System.Management.Automation.ErrorCategory]::InvalidData) `
            -TargetObject $Connection.DataSource
    }
    return $state
}

function Select-HHTargetRepositoryTarget {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Target,
        [AllowEmptyCollection()][string[]]$Name
    )

    if ($null -eq $Name -or $Name.Count -eq 0) {
        return @($Target)
    }
    $requested = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($item in $Name) {
        if ([string]::IsNullOrWhiteSpace($item)) {
            throw 'Target name filters cannot be empty.'
        }
        $null = $requested.Add($item.Trim())
    }
    return @($Target | Where-Object { $requested.Contains($_.Name) })
}

function Read-HHTargetRepositorySnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Connection,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$MasterKey,
        [AllowNull()][object]$Transaction,
        [AllowNull()][object]$ExpectedAnchor,
        [AllowEmptyCollection()][string[]]$Name
    )

    $state = Read-HHTargetRepositoryIdentityState -Connection $Connection -Transaction $Transaction
    $entries = @(Read-HHTargetRepositoryEntry -Connection $Connection -Transaction $Transaction)
    $evidence = Get-HHTargetRepositoryStateEvidence `
        -DatabaseId ([byte[]]$state.database_id) `
        -LedgerId ([byte[]]$state.ledger_id) `
        -SchemaVersion ([int]$state.format_version) `
        -Generation ([long]$state.generation) `
        -PriorMutationMac ([byte[]]$state.prior_mutation_mac) `
        -Target $entries `
        -MasterKey $MasterKey
    if (-not (Test-HHPersistenceBytesEqual `
            -Left $evidence.SnapshotHash `
            -Right ([byte[]]$state.snapshot_hash)) -or
        -not (Test-HHPersistenceBytesEqual `
            -Left $evidence.TargetStateMac `
            -Right ([byte[]]$state.target_state_mac))) {
        Stop-HHTargetRepositoryOperation `
            -ErrorId AuditIntegrityFailed `
            -Message 'The target repository state failed authenticated verification.' `
            -Category ([System.Management.Automation.ErrorCategory]::SecurityError) `
            -TargetObject $Connection.DataSource
    }
    if ($null -ne $ExpectedAnchor) {
        foreach ($propertyName in @(
                'DatabaseId', 'LedgerId', 'SchemaVersion',
                'TargetGeneration', 'TargetStateMac'
            )) {
            if ($null -eq $ExpectedAnchor.PSObject.Properties[$propertyName]) {
                Stop-HHTargetRepositoryOperation `
                    -ErrorId AuditIntegrityFailed `
                    -Message 'The expected target anchor is incomplete.' `
                    -Category ([System.Management.Automation.ErrorCategory]::InvalidData) `
                    -TargetObject $Connection.DataSource
            }
        }
        $anchorMatches =
            [int]$ExpectedAnchor.SchemaVersion -eq [int]$state.format_version -and
            [long]$ExpectedAnchor.TargetGeneration -eq [long]$state.generation -and
            (Test-HHPersistenceBytesEqual -Left ([byte[]]$ExpectedAnchor.DatabaseId) -Right ([byte[]]$state.database_id)) -and
            (Test-HHPersistenceBytesEqual -Left ([byte[]]$ExpectedAnchor.LedgerId) -Right ([byte[]]$state.ledger_id)) -and
            (Test-HHPersistenceBytesEqual -Left ([byte[]]$ExpectedAnchor.TargetStateMac) -Right $evidence.TargetStateMac)
        if (-not $anchorMatches) {
            Stop-HHTargetRepositoryOperation `
                -ErrorId AuditIntegrityFailed `
                -Message 'The target repository state does not match the external anchor.' `
                -Category ([System.Management.Automation.ErrorCategory]::SecurityError) `
                -TargetObject $Connection.DataSource
        }
    }
    Assert-HHTargetCredentialState -Connection $Connection -Transaction $Transaction
    $selected = @(Select-HHTargetRepositoryTarget `
            -Target @(foreach ($entry in $entries) { $entry.Target }) `
            -Name $Name)
    $snapshot = [pscustomobject][ordered]@{
        Generation = [long]$state.generation
        Targets = [object[]]$selected
        IntegrityVerified = $true
        LastMutationId = if ($null -eq $state.last_mutation_id) { $null } else { [byte[]]$state.last_mutation_id }
        StateEvidence = $evidence
    }
    $snapshot.PSObject.TypeNames.Insert(0, 'HostHunter.TargetRepositorySnapshot')
    return $snapshot
}

function Read-HHTargetRepositoryDisplaySnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Connection,
        [AllowNull()][object]$Transaction,
        [AllowEmptyCollection()][string[]]$Name
    )

    $state = Read-HHTargetRepositoryIdentityState -Connection $Connection -Transaction $Transaction
    $entries = @(Read-HHTargetRepositoryEntry -Connection $Connection -Transaction $Transaction)
    $selected = @(Select-HHTargetRepositoryTarget `
            -Target @(foreach ($entry in $entries) { $entry.Target }) `
            -Name $Name)
    $snapshot = [pscustomobject][ordered]@{
        Generation = [long]$state.generation
        Targets = [object[]]$selected
        IntegrityVerified = $false
        LastMutationId = if ($null -eq $state.last_mutation_id) { $null } else { [byte[]]$state.last_mutation_id }
    }
    $snapshot.PSObject.TypeNames.Insert(0, 'HostHunter.TargetRepositoryDisplaySnapshot')
    return $snapshot
}

function Test-HHTargetRepositoryRecordExactMatch {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][object]$ActualTarget,
        [Parameter(Mandatory)][object]$ExpectedTarget
    )

    $actual = ConvertTo-HHValidatedTargetRecord -InputObject $ActualTarget
    $expected = ConvertTo-HHValidatedTargetRecord -InputObject $ExpectedTarget
    foreach ($propertyName in $script:HHTargetSchemaProperties) {
        $actualValue = $actual.$propertyName
        $expectedValue = $expected.$propertyName
        if ($null -eq $actualValue -or $null -eq $expectedValue) {
            if ($null -ne $actualValue -or $null -ne $expectedValue) { return $false }
        }
        elseif ($actualValue -is [string] -or $expectedValue -is [string]) {
            if (-not [string]::Equals(
                    [string]$actualValue,
                    [string]$expectedValue,
                    [StringComparison]::Ordinal
                )) { return $false }
        }
        elseif (-not [object]::Equals($actualValue, $expectedValue)) {
            return $false
        }
    }
    return $true
}

function Merge-HHTargetRepositoryRecord {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$ExistingTarget,
        [Parameter(Mandatory)][object[]]$IncomingTarget,
        [switch]$Add
    )

    $existing = @(Assert-HHTargetSet -Target $ExistingTarget -AllowEmpty)
    $incoming = @(Assert-HHTargetSet -Target $IncomingTarget)
    $byName = [Collections.Generic.Dictionary[string, object]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    foreach ($item in $existing) {
        $copy = [ordered]@{}
        foreach ($propertyName in $script:HHTargetSchemaProperties) {
            $copy[$propertyName] = $item.$propertyName
        }
        $copy.IsActive = if ($Add) { $item.IsActive } else { $false }
        $byName[$item.Name] = ConvertTo-HHValidatedTargetRecord -InputObject ([pscustomobject]$copy)
    }
    foreach ($item in $incoming) {
        $copy = [ordered]@{}
        foreach ($propertyName in $script:HHTargetSchemaProperties) {
            $copy[$propertyName] = $item.$propertyName
        }
        $copy.IsActive = $true
        $byName[$item.Name] = ConvertTo-HHValidatedTargetRecord -InputObject ([pscustomobject]$copy)
    }
    $sorted = [Collections.Generic.SortedDictionary[string, object]]::new([StringComparer]::Ordinal)
    foreach ($item in $byName.Values) { $sorted.Add($item.Name, $item) }
    return @(Assert-HHTargetSet -Target @($sorted.Values) -AllowEmpty)
}

function Get-HHTargetRepositoryMutationAssociatedData {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)][byte[]]$DatabaseId,
        [Parameter(Mandatory)][byte[]]$MutationId,
        [Parameter(Mandatory)][ValidateSet('Before', 'After')][string]$Purpose,
        [Parameter(Mandatory)][int]$SchemaVersion
    )

    $text = 'HostHunterNextGeneration/target-mutation/v1|{0}|{1}|{2}|{3}' -f @(
        [Convert]::ToHexString($DatabaseId).ToLowerInvariant()
        [Convert]::ToHexString($MutationId).ToLowerInvariant()
        $Purpose.ToLowerInvariant()
        $SchemaVersion
    )
    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($text)
    Write-Output -InputObject $bytes -NoEnumerate
}

function Get-HHTargetRepositoryMutationMac {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)][byte[]]$MutationId,
        [Parameter(Mandatory)][long]$PreviousGeneration,
        [Parameter(Mandatory)][long]$CurrentGeneration,
        [Parameter(Mandatory)][string]$RequestedAtUtc,
        [Parameter(Mandatory)][byte[]]$PriorMutationMac,
        [Parameter(Mandatory)][byte[]]$BeforeEnvelope,
        [Parameter(Mandatory)][byte[]]$AfterEnvelope,
        [Parameter(Mandatory)][byte[]]$MasterKey
    )

    $beforeHash = Get-HHPersistenceHash -Bytes $BeforeEnvelope
    $afterHash = Get-HHPersistenceHash -Bytes $AfterEnvelope
    $document = [ordered]@{
        domain = 'HostHunterNextGeneration/target-mutation-mac/v1'
        mutationId = [Convert]::ToHexString($MutationId).ToLowerInvariant()
        previousGeneration = $PreviousGeneration
        currentGeneration = $CurrentGeneration
        requestedAtUtc = $RequestedAtUtc
        priorMutationMac = [Convert]::ToHexString($PriorMutationMac).ToLowerInvariant()
        beforeEnvelopeHash = [Convert]::ToHexString($beforeHash).ToLowerInvariant()
        afterEnvelopeHash = [Convert]::ToHexString($afterHash).ToLowerInvariant()
        result = 'Committed'
    }
    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes(
        ($document | ConvertTo-Json -Compress)
    )
    $key = Get-HHPersistenceDerivedKey -MasterKey $MasterKey -Purpose TargetMutation
    try {
        $mac = Get-HHPersistenceMac -Key $key -Bytes $bytes
        Write-Output -InputObject $mac -NoEnumerate
    }
    finally {
        [Array]::Clear($key, 0, $key.Length)
        [Array]::Clear($bytes, 0, $bytes.Length)
    }
}

function Get-HHTargetRepositoryEntriesForMutation {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$ExistingEntry,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Target
    )

    $existingByName = [Collections.Generic.Dictionary[string, object]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    foreach ($entry in $ExistingEntry) { $existingByName[$entry.Target.Name] = $entry }
    $result = @(
        foreach ($item in @(Assert-HHTargetSet -Target $Target -AllowEmpty)) {
            $revision = 1L
            if ($existingByName.ContainsKey($item.Name)) {
                $existing = $existingByName[$item.Name]
                $revision = if (Test-HHTargetRepositoryRecordExactMatch `
                        -ActualTarget $existing.Target `
                        -ExpectedTarget $item) {
                    [long]$existing.Revision
                }
                else { [long]$existing.Revision + 1L }
            }
            ConvertTo-HHTargetRepositoryEntry -InputObject ([pscustomobject]@{
                    Target = $item
                    Revision = $revision
                })
        }
    )
    return @(Get-HHOrdinalSortedTargetRepositoryEntry -Target $result)
}

function Write-HHTargetRepositoryProfile {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Runs inside an already authorized caller-owned SQLite transaction.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Connection,
        [Parameter(Mandatory)][object]$Transaction,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Target
    )

    $null = Invoke-HHSqliteNonQuery `
        -Connection $Connection `
        -Transaction $Transaction `
        -Sql 'DELETE FROM target_profiles;'
    foreach ($entry in @(Get-HHOrdinalSortedTargetRepositoryEntry -Target $Target)) {
        $item = $entry.Target
        $nameKey = $item.Name.ToUpperInvariant()
        $endpointKey = Get-HHTargetEndpointKey `
            -Transport $item.Transport `
            -HostName $item.HostName `
            -Port $item.Port `
            -PowerShellRuntime $item.PowerShellRuntime
        $null = Invoke-HHSqliteNonQuery `
            -Connection $Connection `
            -Transaction $Transaction `
            -Sql @'
INSERT INTO target_profiles(
    name,name_key,endpoint_key,transport,host_name,port,user_name,
    authentication,credential_storage,powershell_runtime,host_key_fingerprint,key_path,is_active,
    last_validated_at_utc,last_validated_ps_edition,
    last_validated_powershell_version,last_validated_execution_mode,revision
) VALUES(
    @name,@name_key,@endpoint_key,@transport,@host_name,@port,@user_name,
    @authentication,@credential_storage,@runtime,@fingerprint,@key_path,@active,@validated_at,
    @edition,@version,@execution_mode,@revision
);
'@ `
            -Parameters @{
                name = $item.Name
                name_key = $nameKey
                endpoint_key = $endpointKey
                transport = $item.Transport
                host_name = $item.HostName
                port = [int]$item.Port
                user_name = $item.UserName
                authentication = $item.Authentication
                credential_storage = $item.CredentialStorage
                runtime = $item.PowerShellRuntime
                fingerprint = $item.HostKeyFingerprint
                key_path = $item.KeyPath
                active = if ($item.IsActive) { 1 } else { 0 }
                validated_at = $item.LastValidatedAtUtc
                edition = $item.LastValidatedPSEdition
                version = $item.LastValidatedPowerShellVersion
                execution_mode = $item.LastValidatedExecutionMode
                revision = [long]$entry.Revision
            }
    }
    $null = Invoke-HHSqliteNonQuery -Connection $Connection -Transaction $Transaction -Sql @'
DELETE FROM target_credentials
WHERE name_key NOT IN (
    SELECT name_key FROM target_profiles WHERE credential_storage = 'Encrypted'
);
'@
}

function Write-HHTargetRepositoryMutation {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Runs inside an already authorized caller-owned SQLite transaction.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Connection,
        [Parameter(Mandatory)][object]$Transaction,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$MasterKey,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$MutationId,
        [Parameter(Mandatory)][DateTimeOffset]$RequestedAtUtc,
        [Parameter(Mandatory)][object]$CurrentSnapshot,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Target
    )

    if ($MutationId.Length -ne 16) {
        throw 'MutationId must contain exactly 16 bytes.'
    }
    $state = Read-HHTargetRepositoryIdentityState -Connection $Connection -Transaction $Transaction
    if ([long]$state.generation -ne [long]$CurrentSnapshot.Generation) {
        Stop-HHTargetRepositoryOperation `
            -ErrorId TargetStoreCompareAndSwapFailed `
            -Message 'TargetStoreCompareAndSwapFailed: the target generation changed before mutation.' `
            -Category ([System.Management.Automation.ErrorCategory]::InvalidData) `
            -TargetObject $Connection.DataSource
    }
    $currentEntries = @($CurrentSnapshot.StateEvidence.Entries)
    $nextEntries = @(Get-HHTargetRepositoryEntriesForMutation `
            -ExistingEntry $currentEntries `
            -Target $Target)
    $beforeBytes = [byte[]]$CurrentSnapshot.StateEvidence.SnapshotBytes
    $afterSnapshotBytes = ConvertTo-HHTargetRepositorySnapshotByte -Target $nextEntries
    $beforeAssociatedData = Get-HHTargetRepositoryMutationAssociatedData `
        -DatabaseId ([byte[]]$state.database_id) `
        -MutationId $MutationId `
        -Purpose Before `
        -SchemaVersion ([int]$state.format_version)
    $afterAssociatedData = Get-HHTargetRepositoryMutationAssociatedData `
        -DatabaseId ([byte[]]$state.database_id) `
        -MutationId $MutationId `
        -Purpose After `
        -SchemaVersion ([int]$state.format_version)
    try {
        $beforeEnvelope = Protect-HHPersistenceValue `
            -Plaintext $beforeBytes `
            -MasterKey $MasterKey `
            -AssociatedData $beforeAssociatedData
        $afterEnvelope = Protect-HHPersistenceValue `
            -Plaintext $afterSnapshotBytes `
            -MasterKey $MasterKey `
            -AssociatedData $afterAssociatedData
        $requestedText = $RequestedAtUtc.UtcDateTime.ToString(
            'o',
            [Globalization.CultureInfo]::InvariantCulture
        )
        $currentGeneration = [long]$CurrentSnapshot.Generation + 1L
        $mutationMac = Get-HHTargetRepositoryMutationMac `
            -MutationId $MutationId `
            -PreviousGeneration ([long]$CurrentSnapshot.Generation) `
            -CurrentGeneration $currentGeneration `
            -RequestedAtUtc $requestedText `
            -PriorMutationMac ([byte[]]$state.prior_mutation_mac) `
            -BeforeEnvelope $beforeEnvelope `
            -AfterEnvelope $afterEnvelope `
            -MasterKey $MasterKey
        $nextEvidence = Get-HHTargetRepositoryStateEvidence `
            -DatabaseId ([byte[]]$state.database_id) `
            -LedgerId ([byte[]]$state.ledger_id) `
            -SchemaVersion ([int]$state.format_version) `
            -Generation $currentGeneration `
            -PriorMutationMac $mutationMac `
            -Target $nextEntries `
            -MasterKey $MasterKey

        Write-HHTargetRepositoryProfile `
            -Connection $Connection `
            -Transaction $Transaction `
            -Target $nextEntries
        $null = Invoke-HHSqliteNonQuery `
            -Connection $Connection `
            -Transaction $Transaction `
            -Sql @'
INSERT INTO target_mutations(
    mutation_id,previous_generation,current_generation,requested_at_utc,
    before_envelope,after_envelope,result,mutation_mac
) VALUES(@id,@previous,@current,@requested,@before,@after,'Committed',@mac);
'@ `
            -Parameters @{
                id = $MutationId
                previous = [long]$CurrentSnapshot.Generation
                current = $currentGeneration
                requested = $requestedText
                before = $beforeEnvelope
                after = $afterEnvelope
                mac = $mutationMac
            }
        $updated = Invoke-HHSqliteNonQuery `
            -Connection $Connection `
            -Transaction $Transaction `
            -Sql @'
UPDATE target_store_state
SET generation=@generation, snapshot_hash=@snapshot, target_state_mac=@state,
    prior_mutation_mac=@mutation_mac, last_mutation_id=@mutation_id
WHERE singleton_id=1 AND generation=@previous;
'@ `
            -Parameters @{
                generation = $currentGeneration
                snapshot = $nextEvidence.SnapshotHash
                state = $nextEvidence.TargetStateMac
                mutation_mac = $mutationMac
                mutation_id = $MutationId
                previous = [long]$CurrentSnapshot.Generation
            }
        if ($updated -ne 1) {
            Stop-HHTargetRepositoryOperation `
                -ErrorId TargetStoreCompareAndSwapFailed `
                -Message 'TargetStoreCompareAndSwapFailed: the target generation changed during mutation.' `
                -Category ([System.Management.Automation.ErrorCategory]::InvalidData) `
                -TargetObject $Connection.DataSource
        }
        $receipt = [pscustomobject][ordered]@{
            PreviousGeneration = [long]$CurrentSnapshot.Generation
            CurrentGeneration = $currentGeneration
            PreviousTargets = [object[]]@(
                foreach ($entry in $currentEntries) { $entry.Target }
            )
            CurrentTargets = [object[]]@(
                foreach ($entry in $nextEntries) { $entry.Target }
            )
            MutationId = $MutationId
            MutationMac = $mutationMac
            TargetStateMac = $nextEvidence.TargetStateMac
            SnapshotHash = $nextEvidence.SnapshotHash
            Prepared = $true
            Committed = $false
        }
        $receipt.PSObject.TypeNames.Insert(0, 'HostHunter.TargetMutationReceipt')
        return $receipt
    }
    finally {
        [Array]::Clear($beforeAssociatedData, 0, $beforeAssociatedData.Length)
        [Array]::Clear($afterAssociatedData, 0, $afterAssociatedData.Length)
        [Array]::Clear($afterSnapshotBytes, 0, $afterSnapshotBytes.Length)
    }
}

function Set-HHTargetRepository {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Runs inside an already authorized caller-owned SQLite transaction.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Connection,
        [Parameter(Mandatory)][object]$Transaction,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$MasterKey,
        [Parameter(Mandatory)][object[]]$Target,
        [Parameter(Mandatory)][ValidateRange(0, [long]::MaxValue)][long]$ExpectedGeneration,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$MutationId,
        [Parameter(Mandatory)][DateTimeOffset]$RequestedAtUtc,
        [Parameter(Mandatory)][object]$ExpectedAnchor,
        [switch]$Add
    )

    $incoming = @(Assert-HHTargetSet -Target $Target)
    $current = Read-HHTargetRepositorySnapshot `
        -Connection $Connection `
        -Transaction $Transaction `
        -MasterKey $MasterKey `
        -ExpectedAnchor $ExpectedAnchor
    if ($current.Generation -ne $ExpectedGeneration) {
        Stop-HHTargetRepositoryOperation `
            -ErrorId TargetStoreCompareAndSwapFailed `
            -Message 'TargetStoreCompareAndSwapFailed: the expected target generation is stale.' `
            -Category ([System.Management.Automation.ErrorCategory]::InvalidData) `
            -TargetObject $Connection.DataSource
    }
    $merged = @(Merge-HHTargetRepositoryRecord `
            -ExistingTarget $current.Targets `
            -IncomingTarget $incoming `
            -Add:$Add)
    Write-HHTargetRepositoryMutation `
        -Connection $Connection `
        -Transaction $Transaction `
        -MasterKey $MasterKey `
        -MutationId $MutationId `
        -RequestedAtUtc $RequestedAtUtc `
        -CurrentSnapshot $current `
        -Target $merged
}

function Update-HHTargetRepositoryRecord {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Runs inside an already authorized caller-owned SQLite transaction.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Connection,
        [Parameter(Mandatory)][object]$Transaction,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$MasterKey,
        [Parameter(Mandatory)][object]$Target,
        [Parameter(Mandatory)][object]$ExpectedTarget,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$MutationId,
        [Parameter(Mandatory)][DateTimeOffset]$RequestedAtUtc,
        [Parameter(Mandatory)][object]$ExpectedAnchor
    )

    $replacement = @(Assert-HHTargetSet -Target @($Target))[0]
    $expected = @(Assert-HHTargetSet -Target @($ExpectedTarget))[0]
    $current = Read-HHTargetRepositorySnapshot `
        -Connection $Connection `
        -Transaction $Transaction `
        -MasterKey $MasterKey `
        -ExpectedAnchor $ExpectedAnchor
    $storedMatches = @($current.Targets | Where-Object { $_.Name -ieq $replacement.Name })
    if ($storedMatches.Count -ne 1 -or
        -not (Test-HHTargetRepositoryRecordExactMatch `
            -ActualTarget $storedMatches[0] `
            -ExpectedTarget $expected)) {
        Stop-HHTargetRepositoryOperation `
            -ErrorId TargetStoreCompareAndSwapFailed `
            -Message 'TargetStoreCompareAndSwapFailed: the stored target does not match the expected target.' `
            -Category ([System.Management.Automation.ErrorCategory]::InvalidData) `
            -TargetObject $Connection.DataSource
    }
    $updatedTargets = @(
        foreach ($item in $current.Targets) {
            if ($item.Name -ieq $replacement.Name) { $replacement } else { $item }
        }
    )
    $receipt = Write-HHTargetRepositoryMutation `
        -Connection $Connection `
        -Transaction $Transaction `
        -MasterKey $MasterKey `
        -MutationId $MutationId `
        -RequestedAtUtc $RequestedAtUtc `
        -CurrentSnapshot $current `
        -Target $updatedTargets
    $result = [pscustomobject][ordered]@{
        PreviousTarget = $storedMatches[0]
        CurrentTarget = @($receipt.CurrentTargets | Where-Object { $_.Name -ieq $replacement.Name })[0]
        PreviousGeneration = $receipt.PreviousGeneration
        CurrentGeneration = $receipt.CurrentGeneration
        MutationId = $receipt.MutationId
        MutationMac = $receipt.MutationMac
        TargetStateMac = $receipt.TargetStateMac
        Prepared = $true
        Committed = $false
    }
    $result.PSObject.TypeNames.Insert(0, 'HostHunter.TargetStoreCommitReceipt')
    return $result
}

function Remove-HHTargetRepository {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Runs inside an already authorized caller-owned SQLite transaction.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Connection,
        [Parameter(Mandatory)][object]$Transaction,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$MasterKey,
        [Parameter(Mandatory)][ValidateCount(1, 8)][string[]]$Name,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$MutationId,
        [Parameter(Mandatory)][DateTimeOffset]$RequestedAtUtc,
        [Parameter(Mandatory)][object]$ExpectedAnchor
    )

    $requested = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($item in $Name) {
        if ([string]::IsNullOrWhiteSpace($item)) {
            throw 'Target names to remove cannot be empty.'
        }
        if (-not $requested.Add($item.Trim())) {
            throw "Target removal names must be unique; duplicate name: '$item'."
        }
    }
    $current = Read-HHTargetRepositorySnapshot `
        -Connection $Connection `
        -Transaction $Transaction `
        -MasterKey $MasterKey `
        -ExpectedAnchor $ExpectedAnchor
    $stored = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($item in $current.Targets) { $null = $stored.Add($item.Name) }
    $missing = @($requested | Where-Object { -not $stored.Contains($_) })
    if ($missing.Count -gt 0) {
        throw "Cannot remove unknown target(s): $($missing -join ', ')."
    }
    $remaining = @($current.Targets | Where-Object { -not $requested.Contains($_.Name) })
    Write-HHTargetRepositoryMutation `
        -Connection $Connection `
        -Transaction $Transaction `
        -MasterKey $MasterKey `
        -MutationId $MutationId `
        -RequestedAtUtc $RequestedAtUtc `
        -CurrentSnapshot $current `
        -Target $remaining
}
