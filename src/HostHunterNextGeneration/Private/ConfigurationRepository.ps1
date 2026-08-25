Set-StrictMode -Version Latest

$script:HHSupportedEscalationMethods = @('WindowsTokenPrivilege')

function Get-HHConfigurationDerivedKey {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param([Parameter(Mandatory)][byte[]]$MasterKey)

    Assert-HHAuditMasterKey -MasterKey $MasterKey
    $label = [Text.UTF8Encoding]::new($false).GetBytes(
        'HostHunterNextGeneration/persistence/configuration/v1'
    )
    $hmac = [Security.Cryptography.HMACSHA256]::new($MasterKey)
    try {
        $key = $hmac.ComputeHash($label)
        Write-Output -InputObject $key -NoEnumerate
    }
    finally {
        $hmac.Dispose()
        [Array]::Clear($label, 0, $label.Length)
    }
}

function Get-HHConfigurationMac {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)][Collections.IDictionary]$Document,
        [Parameter(Mandatory)][byte[]]$MasterKey
    )

    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(
        ($Document | ConvertTo-Json -Compress)
    )
    $key = Get-HHConfigurationDerivedKey -MasterKey $MasterKey
    try {
        return Get-HHPersistenceMac -Key $key -Bytes $bytes
    }
    finally {
        [Array]::Clear($bytes, 0, $bytes.Length)
        [Array]::Clear($key, 0, $key.Length)
    }
}

function Get-HHConfigurationStateMac {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)][byte[]]$DatabaseId,
        [Parameter(Mandatory)][byte[]]$LedgerId,
        [Parameter(Mandatory)][ValidateRange(0, [long]::MaxValue)][long]$Generation,
        [AllowNull()][string]$EscalationMethod,
        [Parameter(Mandatory)][byte[]]$PriorMutationMac,
        [Parameter(Mandatory)][byte[]]$MasterKey
    )

    $normalizedMethod = if ([string]::IsNullOrEmpty($EscalationMethod)) { $null } else { $EscalationMethod }
    if ($DatabaseId.Length -ne 16 -or $LedgerId.Length -ne 16 -or
        $PriorMutationMac.Length -ne 32 -or
        ($null -ne $normalizedMethod -and
            $normalizedMethod -cnotin $script:HHSupportedEscalationMethods)) {
        throw [ArgumentException]::new('Configuration state identity is invalid.')
    }
    return Get-HHConfigurationMac -MasterKey $MasterKey -Document ([ordered]@{
            domain = 'HostHunterNextGeneration/configuration-state/v1'
            databaseId = [Convert]::ToHexString($DatabaseId).ToLowerInvariant()
            ledgerId = [Convert]::ToHexString($LedgerId).ToLowerInvariant()
            generation = $Generation
            escalationMethod = $normalizedMethod
            priorMutationMac = [Convert]::ToHexString($PriorMutationMac).ToLowerInvariant()
        })
}

function Get-HHConfigurationMutationMac {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)][byte[]]$MutationId,
        [Parameter(Mandatory)][ValidateRange(0, [long]::MaxValue)][long]$PreviousGeneration,
        [Parameter(Mandatory)][ValidateRange(1, [long]::MaxValue)][long]$CurrentGeneration,
        [Parameter(Mandatory)][string]$RequestedAtUtc,
        [AllowNull()][string]$BeforeMethod,
        [Parameter(Mandatory)][ValidateSet('WindowsTokenPrivilege')][string]$AfterMethod,
        [Parameter(Mandatory)][byte[]]$PriorMutationMac,
        [Parameter(Mandatory)][byte[]]$MasterKey
    )

    $normalizedBeforeMethod = if ([string]::IsNullOrEmpty($BeforeMethod)) { $null } else { $BeforeMethod }
    if ($MutationId.Length -ne 16 -or $PriorMutationMac.Length -ne 32 -or
        $CurrentGeneration -ne $PreviousGeneration + 1L -or
        ($null -ne $normalizedBeforeMethod -and
            $normalizedBeforeMethod -cnotin $script:HHSupportedEscalationMethods)) {
        throw [ArgumentException]::new('Configuration mutation identity is invalid.')
    }
    return Get-HHConfigurationMac -MasterKey $MasterKey -Document ([ordered]@{
            domain = 'HostHunterNextGeneration/configuration-mutation/v1'
            mutationId = [Convert]::ToHexString($MutationId).ToLowerInvariant()
            previousGeneration = $PreviousGeneration
            currentGeneration = $CurrentGeneration
            requestedAtUtc = $RequestedAtUtc
            beforeMethod = $normalizedBeforeMethod
            afterMethod = $AfterMethod
            priorMutationMac = [Convert]::ToHexString($PriorMutationMac).ToLowerInvariant()
        })
}

function Initialize-HHConfigurationRepositoryState {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Initializes state inside the caller-owned migration transaction.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Connection,
        [Parameter(Mandatory)][object]$Transaction,
        [Parameter(Mandatory)][byte[]]$DatabaseId,
        [Parameter(Mandatory)][byte[]]$LedgerId,
        [Parameter(Mandatory)][byte[]]$MasterKey
    )

    $zeroMac = [byte[]]::new(32)
    $stateMac = Get-HHConfigurationStateMac `
        -DatabaseId $DatabaseId `
        -LedgerId $LedgerId `
        -Generation 0 `
        -EscalationMethod $null `
        -PriorMutationMac $zeroMac `
        -MasterKey $MasterKey
    $null = Invoke-HHSqliteNonQuery `
        -Connection $Connection `
        -Transaction $Transaction `
        -Sql @'
INSERT INTO configuration_store_state(
    singleton_id,generation,escalation_method,state_mac,prior_mutation_mac,last_mutation_id
) VALUES(1,0,NULL,@state,@prior,NULL);
'@ `
        -Parameters @{ state = $stateMac; prior = $zeroMac }
}

function Read-HHConfigurationRepositorySnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Connection,
        [Parameter(Mandatory)][byte[]]$MasterKey,
        [AllowNull()][object]$Transaction
    )

    $identity = @(Invoke-HHSqliteQuery -Connection $Connection -Transaction $Transaction `
            -Sql 'SELECT database_id,ledger_id FROM database_identity WHERE singleton_id = 1;')
    $states = @(Invoke-HHSqliteQuery -Connection $Connection -Transaction $Transaction -Sql @'
SELECT generation,escalation_method,state_mac,prior_mutation_mac,last_mutation_id
FROM configuration_store_state WHERE singleton_id = 1;
'@)
    $mutations = @(Invoke-HHSqliteQuery -Connection $Connection -Transaction $Transaction -Sql @'
SELECT mutation_id,previous_generation,current_generation,requested_at_utc,
        before_method,after_method,mutation_mac
FROM configuration_mutations ORDER BY current_generation;
'@)
    if ($identity.Count -ne 1 -or $states.Count -ne 1) {
        Stop-HHPersistenceOperation -ErrorId AuditIntegrityFailed `
            -Message 'The authenticated configuration state is missing or ambiguous.' `
            -Category ([Management.Automation.ErrorCategory]::InvalidData) `
            -TargetObject $Connection.DataSource
    }

    $state = $states[0]
    $priorMac = [byte[]]::new(32)
    $expectedGeneration = 0L
    $expectedMethod = $null
    $lastMutationId = $null
    foreach ($mutation in $mutations) {
        $mutationId = [byte[]]$mutation.mutation_id
        $beforeMethod = if ($null -eq $mutation.before_method) { $null } else { [string]$mutation.before_method }
        $afterMethod = [string]$mutation.after_method
        $expectedMac = Get-HHConfigurationMutationMac `
            -MutationId $mutationId `
            -PreviousGeneration ([long]$mutation.previous_generation) `
            -CurrentGeneration ([long]$mutation.current_generation) `
            -RequestedAtUtc ([string]$mutation.requested_at_utc) `
            -BeforeMethod $beforeMethod `
            -AfterMethod $afterMethod `
            -PriorMutationMac $priorMac `
            -MasterKey $MasterKey
        if ([long]$mutation.previous_generation -ne $expectedGeneration -or
            [long]$mutation.current_generation -ne $expectedGeneration + 1L -or
            $beforeMethod -cne $expectedMethod -or
            -not (Test-HHPersistenceBytesEqual -Left $expectedMac -Right ([byte[]]$mutation.mutation_mac))) {
            Stop-HHPersistenceOperation -ErrorId AuditIntegrityFailed `
                -Message 'The authenticated configuration mutation chain is invalid.' `
                -Category ([Management.Automation.ErrorCategory]::SecurityError) `
                -TargetObject $Connection.DataSource
        }
        $priorMac = [byte[]]$mutation.mutation_mac
        $expectedGeneration = [long]$mutation.current_generation
        $expectedMethod = $afterMethod
        $lastMutationId = $mutationId
    }

    $stateMethod = if ($null -eq $state.escalation_method) { $null } else { [string]$state.escalation_method }
    $stateMac = Get-HHConfigurationStateMac `
        -DatabaseId ([byte[]]$identity[0].database_id) `
        -LedgerId ([byte[]]$identity[0].ledger_id) `
        -Generation ([long]$state.generation) `
        -EscalationMethod $stateMethod `
        -PriorMutationMac ([byte[]]$state.prior_mutation_mac) `
        -MasterKey $MasterKey
    $lastIdMatches = if ($null -eq $lastMutationId) {
        $null -eq $state.last_mutation_id
    }
    else {
        $null -ne $state.last_mutation_id -and
            (Test-HHPersistenceBytesEqual -Left $lastMutationId -Right ([byte[]]$state.last_mutation_id))
    }
    if ([long]$state.generation -ne $expectedGeneration -or
        $stateMethod -cne $expectedMethod -or
        -not (Test-HHPersistenceBytesEqual -Left $priorMac -Right ([byte[]]$state.prior_mutation_mac)) -or
        -not (Test-HHPersistenceBytesEqual -Left $stateMac -Right ([byte[]]$state.state_mac)) -or
        -not $lastIdMatches) {
        Stop-HHPersistenceOperation -ErrorId AuditIntegrityFailed `
            -Message 'The authenticated configuration head does not match its mutation chain.' `
            -Category ([Management.Automation.ErrorCategory]::SecurityError) `
            -TargetObject $Connection.DataSource
    }
    [pscustomobject][ordered]@{
        Generation = $expectedGeneration
        EscalationMethod = $expectedMethod
        StateMac = $stateMac
        PriorMutationMac = $priorMac
        LastMutationId = $lastMutationId
        IntegrityVerified = $true
    }
}

function Set-HHConfigurationEscalationPreference {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Writes inside an already authorized caller-owned transaction.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Connection,
        [Parameter(Mandatory)][object]$Transaction,
        [Parameter(Mandatory)][byte[]]$MasterKey,
        [Parameter(Mandatory)][ValidateSet('WindowsTokenPrivilege')][string]$Method,
        [Parameter(Mandatory)][DateTimeOffset]$RequestedAtUtc,
        [Parameter(Mandatory)][object]$CurrentSnapshot,
        [byte[]]$MutationId = [Guid]::NewGuid().ToByteArray()
    )

    if ($MutationId.Length -ne 16) {
        throw [ArgumentException]::new('MutationId must contain exactly 16 bytes.', 'MutationId')
    }
    if ([string]$CurrentSnapshot.EscalationMethod -ceq $Method) {
        return [pscustomobject][ordered]@{
            Changed = $false
            Generation = [long]$CurrentSnapshot.Generation
            EscalationMethod = $Method
            MutationId = $null
        }
    }
    $identity = @(Invoke-HHSqliteQuery -Connection $Connection -Transaction $Transaction `
            -Sql 'SELECT database_id,ledger_id FROM database_identity WHERE singleton_id = 1;')
    if ($identity.Count -ne 1) { throw 'The configuration database identity is missing.' }
    $nextGeneration = [long]$CurrentSnapshot.Generation + 1L
    $requestedText = $RequestedAtUtc.UtcDateTime.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
    $mutationMac = Get-HHConfigurationMutationMac `
        -MutationId $MutationId `
        -PreviousGeneration ([long]$CurrentSnapshot.Generation) `
        -CurrentGeneration $nextGeneration `
        -RequestedAtUtc $requestedText `
        -BeforeMethod $CurrentSnapshot.EscalationMethod `
        -AfterMethod $Method `
        -PriorMutationMac ([byte[]]$CurrentSnapshot.PriorMutationMac) `
        -MasterKey $MasterKey
    $stateMac = Get-HHConfigurationStateMac `
        -DatabaseId ([byte[]]$identity[0].database_id) `
        -LedgerId ([byte[]]$identity[0].ledger_id) `
        -Generation $nextGeneration `
        -EscalationMethod $Method `
        -PriorMutationMac $mutationMac `
        -MasterKey $MasterKey
    $null = Invoke-HHSqliteNonQuery -Connection $Connection -Transaction $Transaction -Sql @'
INSERT INTO configuration_mutations(
    mutation_id,previous_generation,current_generation,requested_at_utc,
    before_method,after_method,mutation_mac
) VALUES(@id,@previous,@current,@requested,@before,@after,@mac);
'@ -Parameters @{
        id = $MutationId
        previous = [long]$CurrentSnapshot.Generation
        current = $nextGeneration
        requested = $requestedText
        before = $CurrentSnapshot.EscalationMethod
        after = $Method
        mac = $mutationMac
    }
    $affected = Invoke-HHSqliteNonQuery -Connection $Connection -Transaction $Transaction -Sql @'
UPDATE configuration_store_state
SET generation=@current,escalation_method=@method,state_mac=@state,
    prior_mutation_mac=@prior,last_mutation_id=@id
WHERE singleton_id=1 AND generation=@previous AND state_mac=@expected;
'@ -Parameters @{
        current = $nextGeneration
        method = $Method
        state = $stateMac
        prior = $mutationMac
        id = $MutationId
        previous = [long]$CurrentSnapshot.Generation
        expected = [byte[]]$CurrentSnapshot.StateMac
    }
    if ($affected -ne 1) {
        Stop-HHPersistenceOperation -ErrorId ConfigurationCompareAndSwapFailed `
            -Message 'The escalation preference changed concurrently.' `
            -Category ([Management.Automation.ErrorCategory]::InvalidData) `
            -TargetObject $Connection.DataSource
    }
    [pscustomobject][ordered]@{
        Changed = $true
        Generation = $nextGeneration
        EscalationMethod = $Method
        MutationId = $MutationId
        StateMac = $stateMac
    }
}

function Get-HHAuthenticatedEscalationPreference {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Context)

    $snapshot = Read-HHConfigurationRepositorySnapshot `
        -Connection $Context.Connection `
        -MasterKey $Context.MasterKey
    [pscustomobject][ordered]@{
        Method = if ($null -eq $snapshot.EscalationMethod) {
            'WindowsTokenPrivilege'
        }
        else { $snapshot.EscalationMethod }
        Source = if ($null -eq $snapshot.EscalationMethod) { 'BuiltIn' } else { 'Persisted' }
        IsPersisted = $null -ne $snapshot.EscalationMethod
        Generation = $snapshot.Generation
        IntegrityVerified = $snapshot.IntegrityVerified
    }
}

function Set-HHAuthenticatedEscalationPreference {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Private coordinator is called only after the public authorization boundary.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][ValidateSet('WindowsTokenPrivilege')][string]$Method,
        [DateTimeOffset]$RequestedAtUtc = [DateTimeOffset]::UtcNow
    )

    $arguments = [pscustomobject]@{
        Method = $Method
        RequestedAtUtc = $RequestedAtUtc
    }
    $receipt = Invoke-HHAnchoredPersistenceTransaction -Context $Context `
        -ArgumentList @($arguments) -Action {
        param($Connection, $Transaction, $WriterContext, $ArgumentList)
        $inputData = $ArgumentList[0]
        $current = Read-HHConfigurationRepositorySnapshot `
            -Connection $Connection `
            -Transaction $Transaction `
            -MasterKey $WriterContext.MasterKey
        Set-HHConfigurationEscalationPreference `
            -Connection $Connection `
            -Transaction $Transaction `
            -MasterKey $WriterContext.MasterKey `
            -Method $inputData.Method `
            -RequestedAtUtc $inputData.RequestedAtUtc `
            -CurrentSnapshot $current
    }
    $preference = Get-HHAuthenticatedEscalationPreference -Context $Context
    [pscustomobject][ordered]@{
        Changed = [bool]$receipt.Changed
        Method = $preference.Method
        Source = $preference.Source
        IsPersisted = $preference.IsPersisted
        Generation = $preference.Generation
        MutationId = $receipt.MutationId
        Prepared = $receipt.Prepared
        Committed = $receipt.Committed
    }
}
