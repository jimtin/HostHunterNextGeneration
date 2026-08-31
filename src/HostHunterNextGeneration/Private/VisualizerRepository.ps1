Set-StrictMode -Version Latest

function Get-HHVisualizerMacKey {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param([Parameter(Mandatory)][byte[]]$MasterKey)

    Assert-HHAuditMasterKey -MasterKey $MasterKey
    $label = [Text.UTF8Encoding]::new($false).GetBytes(
        'HostHunterNextGeneration/persistence/visualizer-state/v1'
    )
    $hmac = [Security.Cryptography.HMACSHA256]::new($MasterKey)
    try {
        $value = $hmac.ComputeHash($label)
        Write-Output -InputObject $value -NoEnumerate
    }
    finally {
        $hmac.Dispose()
        [Array]::Clear($label, 0, $label.Length)
    }
}

function Get-HHVisualizerStateDocument {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Connection,
        [AllowNull()][object]$Transaction,
        [Parameter(Mandatory)][long]$Generation,
        [AllowNull()][byte[]]$CurrentMissionId,
        [switch]$ExcludeForensic
    )

    $missions = @(Invoke-HHSqliteQuery -Connection $Connection -Transaction $Transaction -Sql @'
SELECT hex(mission_id) AS mission_id,activation_id,started_at_utc,hex(payload_json) AS payload,
        delivery_status,delivery_attempts,last_status_code,delivered_at_utc
FROM visualizer_missions ORDER BY started_at_utc,mission_id;
'@)
    $identities = @(Invoke-HHSqliteQuery -Connection $Connection -Transaction $Transaction -Sql @'
SELECT target_name_key,endpoint_id,identity_strategy,last_seen_at_utc
FROM visualizer_endpoint_identities ORDER BY target_name_key COLLATE BINARY;
'@)
    $observations = @(Invoke-HHSqliteQuery -Connection $Connection -Transaction $Transaction -Sql @'
SELECT hex(event_id) AS event_id,hex(mission_id) AS mission_id,target_name_key,endpoint_id,
        observed_at_utc,hex(payload_envelope) AS payload,content_sha256,
        delivery_status,delivery_attempts,last_status_code,delivered_at_utc
FROM visualizer_host_observations ORDER BY observed_at_utc,event_id;
'@)
    $document = [ordered]@{
        domain = 'HostHunterNextGeneration/visualizer-state/v1'
        generation = $Generation
        currentMissionId = if ($null -eq $CurrentMissionId) { $null } else {
            [Convert]::ToHexString($CurrentMissionId).ToLowerInvariant()
        }
        missions = @($missions | ForEach-Object { [ordered]@{
                    missionId = ([string]$_.mission_id).ToLowerInvariant()
                    activationId = $_.activation_id
                    startedAtUtc = [string]$_.started_at_utc
                    payload = ([string]$_.payload).ToLowerInvariant()
                    deliveryStatus = [string]$_.delivery_status
                    deliveryAttempts = [long]$_.delivery_attempts
                    lastStatusCode = $_.last_status_code
                    deliveredAtUtc = $_.delivered_at_utc
                } })
        identities = @($identities | ForEach-Object { [ordered]@{
                    targetNameKey = [string]$_.target_name_key
                    endpointId = [string]$_.endpoint_id
                    identityStrategy = [string]$_.identity_strategy
                    lastSeenAtUtc = [string]$_.last_seen_at_utc
                } })
        observations = @($observations | ForEach-Object { [ordered]@{
                    eventId = ([string]$_.event_id).ToLowerInvariant()
                    missionId = ([string]$_.mission_id).ToLowerInvariant()
                    targetNameKey = [string]$_.target_name_key
                    endpointId = [string]$_.endpoint_id
                    observedAtUtc = [string]$_.observed_at_utc
                    payload = ([string]$_.payload).ToLowerInvariant()
                    contentSha256 = [string]$_.content_sha256
                    deliveryStatus = [string]$_.delivery_status
                    deliveryAttempts = [long]$_.delivery_attempts
                    lastStatusCode = $_.last_status_code
                    deliveredAtUtc = $_.delivered_at_utc
                } })
    }
    $forensicTableCount = [long](Invoke-HHSqliteScalar -Connection $Connection `
            -Transaction $Transaction -Sql @'
SELECT COUNT(*) FROM sqlite_master
WHERE type='table' AND name='visualizer_forensic_events';
'@)
    if ($forensicTableCount -eq 1 -and -not $ExcludeForensic) {
        $events = @(Invoke-HHSqliteQuery -Connection $Connection -Transaction $Transaction -Sql @'
SELECT hex(event_id) AS event_id,hex(mission_id) AS mission_id,target_name_key,
    endpoint_id,schema_name,occurred_at_utc,collected_at_utc,
    hex(payload_envelope) AS payload,content_sha256,delivery_status,
    delivery_attempts,last_status_code,delivered_at_utc
FROM visualizer_forensic_events ORDER BY occurred_at_utc,event_id;
'@)
        $cursors = @(Invoke-HHSqliteQuery -Connection $Connection -Transaction $Transaction -Sql @'
SELECT target_name_key,source_name,occurred_at_utc,record_id,updated_at_utc
FROM forensic_collection_cursors
ORDER BY target_name_key COLLATE BINARY,source_name COLLATE BINARY;
'@)
        $document.forensicEvents = @($events | ForEach-Object { [ordered]@{
                    eventId=([string]$_.event_id).ToLowerInvariant()
                    missionId=([string]$_.mission_id).ToLowerInvariant()
                    targetNameKey=[string]$_.target_name_key
                    endpointId=[string]$_.endpoint_id
                    schemaName=[string]$_.schema_name
                    occurredAtUtc=[string]$_.occurred_at_utc
                    collectedAtUtc=[string]$_.collected_at_utc
                    payload=([string]$_.payload).ToLowerInvariant()
                    contentSha256=[string]$_.content_sha256
                    deliveryStatus=[string]$_.delivery_status
                    deliveryAttempts=[long]$_.delivery_attempts
                    lastStatusCode=$_.last_status_code
                    deliveredAtUtc=$_.delivered_at_utc
                } })
        $document.collectionCursors = @($cursors | ForEach-Object { [ordered]@{
                    targetNameKey=[string]$_.target_name_key
                    sourceName=[string]$_.source_name
                    occurredAtUtc=[string]$_.occurred_at_utc
                    recordId=[string]$_.record_id
                    updatedAtUtc=[string]$_.updated_at_utc
                } })
    }
    $document
}

function Get-HHVisualizerStateMac {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)][object]$Connection,
        [AllowNull()][object]$Transaction,
        [Parameter(Mandatory)][long]$Generation,
        [AllowNull()][byte[]]$CurrentMissionId,
        [Parameter(Mandatory)][byte[]]$MasterKey,
        [switch]$ExcludeForensic
    )

    $document = Get-HHVisualizerStateDocument -Connection $Connection `
        -Transaction $Transaction -Generation $Generation `
        -CurrentMissionId $CurrentMissionId -ExcludeForensic:$ExcludeForensic
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($document | ConvertTo-Json -Compress -Depth 12))
    $key = Get-HHVisualizerMacKey -MasterKey $MasterKey
    try { return Get-HHPersistenceMac -Key $key -Bytes $bytes }
    finally {
        [Array]::Clear($bytes, 0, $bytes.Length)
        [Array]::Clear($key, 0, $key.Length)
    }
}

function Initialize-HHVisualizerRepositoryState {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Initializes state in a caller-owned migration transaction.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Connection,
        [Parameter(Mandatory)][object]$Transaction,
        [Parameter(Mandatory)][byte[]]$MasterKey
    )
    $stateMac = Get-HHVisualizerStateMac -Connection $Connection -Transaction $Transaction `
        -Generation 0 -CurrentMissionId $null -MasterKey $MasterKey
    $null = Invoke-HHSqliteNonQuery -Connection $Connection -Transaction $Transaction `
        -Sql 'INSERT INTO visualizer_store_state(singleton_id,generation,current_mission_id,state_mac) VALUES(1,0,NULL,@mac);' `
        -Parameters @{ mac = $stateMac }
}

function Update-HHVisualizerRepositoryStateForMigration {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Re-authenticates an unchanged state document after an additive schema migration.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Connection,
        [Parameter(Mandatory)][object]$Transaction,
        [Parameter(Mandatory)][byte[]]$MasterKey
    )
    $rows = @(Invoke-HHSqliteQuery -Connection $Connection -Transaction $Transaction `
            -Sql 'SELECT generation,current_mission_id FROM visualizer_store_state WHERE singleton_id=1;')
    if ($rows.Count -ne 1) { throw 'The visualizer state is unavailable during migration.' }
    $mission = if ($null -eq $rows[0].current_mission_id) { $null } else {
        [byte[]]$rows[0].current_mission_id
    }
    $mac = Get-HHVisualizerStateMac -Connection $Connection -Transaction $Transaction `
        -Generation ([long]$rows[0].generation) -CurrentMissionId $mission `
        -MasterKey $MasterKey
    $affected = Invoke-HHSqliteNonQuery -Connection $Connection -Transaction $Transaction `
        -Sql 'UPDATE visualizer_store_state SET state_mac=@mac WHERE singleton_id=1;' `
        -Parameters @{ mac=$mac }
    if ($affected -ne 1) { throw 'The visualizer state could not be re-authenticated during migration.' }
}

function Read-HHVisualizerRepositorySnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Connection,
        [Parameter(Mandatory)][byte[]]$MasterKey,
        [AllowNull()][object]$Transaction
    )
    $rows = @(Invoke-HHSqliteQuery -Connection $Connection -Transaction $Transaction `
            -Sql 'SELECT generation,current_mission_id,state_mac FROM visualizer_store_state WHERE singleton_id=1;')
    if ($rows.Count -ne 1) { throw 'The authenticated visualizer state is missing or ambiguous.' }
    $currentId = if ($null -eq $rows[0].current_mission_id) { $null } else { [byte[]]$rows[0].current_mission_id }
    $expected = Get-HHVisualizerStateMac -Connection $Connection -Transaction $Transaction `
        -Generation ([long]$rows[0].generation) -CurrentMissionId $currentId -MasterKey $MasterKey
    if (-not (Test-HHPersistenceBytesEqual -Left $expected -Right ([byte[]]$rows[0].state_mac))) {
        Stop-HHPersistenceOperation -ErrorId AuditIntegrityFailed `
            -Message 'The authenticated visualizer state failed verification.' `
            -Category ([Management.Automation.ErrorCategory]::SecurityError) `
            -TargetObject $Connection.DataSource
    }
    [pscustomobject][ordered]@{
        Generation = [long]$rows[0].generation
        CurrentMissionId = $currentId
        StateMac = $expected
        IntegrityVerified = $true
    }
}

function Update-HHVisualizerStateHead {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Private authenticated repository mutation runs inside a caller-owned transaction.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Connection,
        [Parameter(Mandatory)][object]$Transaction,
        [Parameter(Mandatory)][byte[]]$MasterKey,
        [Parameter(Mandatory)][object]$CurrentSnapshot,
        [AllowNull()][byte[]]$CurrentMissionId
    )
    $next = [long]$CurrentSnapshot.Generation + 1
    $mac = Get-HHVisualizerStateMac -Connection $Connection -Transaction $Transaction `
        -Generation $next -CurrentMissionId $CurrentMissionId -MasterKey $MasterKey
    $affected = Invoke-HHSqliteNonQuery -Connection $Connection -Transaction $Transaction -Sql @'
UPDATE visualizer_store_state
SET generation=@next,current_mission_id=@mission,state_mac=@mac
WHERE singleton_id=1 AND generation=@previous AND state_mac=@expected;
'@ -Parameters @{
        next = $next; mission = $CurrentMissionId; mac = $mac
        previous = [long]$CurrentSnapshot.Generation; expected = [byte[]]$CurrentSnapshot.StateMac
    }
    if ($affected -ne 1) { throw 'The visualizer state changed concurrently.' }
    [pscustomobject]@{ Generation = $next; CurrentMissionId = $CurrentMissionId; StateMac = $mac }
}

function ConvertTo-HHLowerGuid {
    [CmdletBinding()]
    param([Parameter(Mandatory)][byte[]]$Bytes)
    ([Guid]::new($Bytes)).ToString('D').ToLowerInvariant()
}

function Add-HHVisualizerMission {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Connection,
        [Parameter(Mandatory)][object]$Transaction,
        [Parameter(Mandatory)][byte[]]$MasterKey,
        [Parameter(Mandatory)][object]$CurrentSnapshot,
        [Parameter(Mandatory)][byte[]]$MissionId,
        [AllowNull()][string]$ActivationId,
        [Parameter(Mandatory)][DateTimeOffset]$StartedAtUtc,
        [Parameter(Mandatory)][byte[]]$PayloadBytes
    )
    if ($PayloadBytes.Length -gt 262144) { throw 'The collection-run payload exceeds 256 KiB.' }
    $normalizedActivationId = if ([string]::IsNullOrWhiteSpace($ActivationId)) { $null } else { $ActivationId }
    if ($null -ne $normalizedActivationId) {
        $existing = @(Invoke-HHSqliteQuery -Connection $Connection -Transaction $Transaction `
                -Sql 'SELECT mission_id,payload_json FROM visualizer_missions WHERE activation_id=@activation;' `
                -Parameters @{ activation = $normalizedActivationId })
        if ($existing.Count -eq 1) {
            return [pscustomobject]@{ MissionId = [byte[]]$existing[0].mission_id; Existing = $true; PayloadBytes=[byte[]]$existing[0].payload_json }
        }
    }
    $text = $StartedAtUtc.UtcDateTime.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
    $null = Invoke-HHSqliteNonQuery -Connection $Connection -Transaction $Transaction -Sql @'
INSERT INTO visualizer_missions(mission_id,activation_id,started_at_utc,payload_json,delivery_status,delivery_attempts)
VALUES(@id,@activation,@started,@payload,'Pending',0);
'@ -Parameters @{ id=$MissionId; activation=$normalizedActivationId; started=$text; payload=$PayloadBytes }
    $null = Update-HHVisualizerStateHead -Connection $Connection -Transaction $Transaction `
        -MasterKey $MasterKey -CurrentSnapshot $CurrentSnapshot `
        -CurrentMissionId $CurrentSnapshot.CurrentMissionId
    [pscustomobject]@{ MissionId = $MissionId; Existing = $false; PayloadBytes=$PayloadBytes }
}

function Get-HHVisualizerMissionRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Connection,
        [AllowNull()][object]$Transaction,
        [Parameter(Mandatory)][byte[]]$MissionId
    )
    $rows = @(Invoke-HHSqliteQuery -Connection $Connection -Transaction $Transaction -Sql @'
SELECT mission_id,started_at_utc,payload_json,delivery_status,delivery_attempts,last_status_code
FROM visualizer_missions WHERE mission_id=@id;
'@ -Parameters @{ id = $MissionId })
    if ($rows.Count -gt 1) { throw 'The visualizer mission identity is ambiguous.' }
    if ($rows.Count -eq 0) { return $null }
    [pscustomobject]@{
        MissionId = [byte[]]$rows[0].mission_id
        StartedAtUtc = [DateTimeOffset]::Parse([string]$rows[0].started_at_utc)
        PayloadBytes = [byte[]]$rows[0].payload_json
        DeliveryStatus = [string]$rows[0].delivery_status
        DeliveryAttempts = [int]$rows[0].delivery_attempts
        LastStatusCode = $rows[0].last_status_code
    }
}

function Get-HHLatestVisualizerMissionRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Connection,
        [AllowNull()][object]$Transaction
    )
    $rows = @(Invoke-HHSqliteQuery -Connection $Connection -Transaction $Transaction -Sql @'
SELECT mission_id,started_at_utc,payload_json,delivery_status,delivery_attempts,last_status_code
FROM visualizer_missions ORDER BY started_at_utc DESC,mission_id DESC LIMIT 1;
'@)
    if ($rows.Count -eq 0) { return $null }
    [pscustomobject]@{
        MissionId = [byte[]]$rows[0].mission_id
        StartedAtUtc = [DateTimeOffset]::Parse([string]$rows[0].started_at_utc)
        PayloadBytes = [byte[]]$rows[0].payload_json
        DeliveryStatus = [string]$rows[0].delivery_status
        DeliveryAttempts = [int]$rows[0].delivery_attempts
        LastStatusCode = $rows[0].last_status_code
    }
}

function Set-HHVisualizerCurrentMission {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Private authenticated repository mutation controlled by the lifecycle coordinator.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Connection,
        [Parameter(Mandatory)][object]$Transaction,
        [Parameter(Mandatory)][byte[]]$MasterKey,
        [Parameter(Mandatory)][object]$CurrentSnapshot,
        [AllowNull()][byte[]]$MissionId
    )
    if ($null -ne $MissionId) {
        $mission = Get-HHVisualizerMissionRecord -Connection $Connection -Transaction $Transaction -MissionId $MissionId
        if ($null -eq $mission) { throw 'The requested visualizer mission is not present in authenticated local state.' }
    }
    Update-HHVisualizerStateHead -Connection $Connection -Transaction $Transaction `
        -MasterKey $MasterKey -CurrentSnapshot $CurrentSnapshot -CurrentMissionId $MissionId
}

function Set-HHVisualizerMissionReconciled {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Private authenticated recovery mutation controlled by the lifecycle coordinator.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Connection,
        [Parameter(Mandatory)][object]$Transaction,
        [Parameter(Mandatory)][byte[]]$MasterKey,
        [Parameter(Mandatory)][object]$CurrentSnapshot,
        [Parameter(Mandatory)][byte[]]$MissionId,
        [Parameter(Mandatory)][DateTimeOffset]$ReconciledAtUtc
    )
    $when = $ReconciledAtUtc.UtcDateTime.ToString('o',[Globalization.CultureInfo]::InvariantCulture)
    $affected = Invoke-HHSqliteNonQuery -Connection $Connection -Transaction $Transaction -Sql @'
UPDATE visualizer_missions
SET delivery_status='Delivered',last_status_code=200,delivered_at_utc=@when
WHERE mission_id=@id AND delivery_attempts=1 AND delivery_status='Pending';
'@ -Parameters @{ id=$MissionId; when=$when }
    if ($affected -notin @(0,1)) { throw 'Mission recovery updated an unexpected number of rows.' }
    Update-HHVisualizerStateHead -Connection $Connection -Transaction $Transaction `
        -MasterKey $MasterKey -CurrentSnapshot $CurrentSnapshot -CurrentMissionId $MissionId
}

function Read-HHPendingVisualizerObservations {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseSingularNouns',
        '',
        Justification = 'The private query deliberately returns a bounded collection of observations.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Connection,
        [AllowNull()][object]$Transaction,
        [Parameter(Mandatory)][byte[]]$MasterKey,
        [Parameter(Mandatory)][byte[]]$MissionId,
        [ValidateRange(1,1000)][int]$First = 100
    )
    $rows = @(Invoke-HHSqliteQuery -Connection $Connection -Transaction $Transaction -Sql @'
SELECT event_id,mission_id,payload_envelope,content_sha256
FROM visualizer_host_observations
WHERE mission_id=@mission AND delivery_status='Pending' AND delivery_attempts=1
ORDER BY observed_at_utc,event_id LIMIT @first;
'@ -Parameters @{ mission=$MissionId; first=$First })
    @($rows | ForEach-Object {
            $eventId = [byte[]]$_.event_id
            $associated = [Text.Encoding]::UTF8.GetBytes(
                "HostHunter/host-observation/v1`n$(ConvertTo-HHLowerGuid $eventId)"
            )
            try {
                $payload = Unprotect-HHPersistenceValue -Envelope ([byte[]]$_.payload_envelope) `
                    -MasterKey $MasterKey -AssociatedData $associated
            }
            finally { [Array]::Clear($associated,0,$associated.Length) }
            $actualHash = [Convert]::ToHexString(
                (Get-HHPersistenceHash -Bytes $payload)
            ).ToLowerInvariant()
            if ($actualHash -cne [string]$_.content_sha256) {
                [Array]::Clear($payload,0,$payload.Length)
                throw 'A pending visualizer observation failed its plaintext digest check.'
            }
            [pscustomobject]@{
                EventId=$eventId; MissionId=[byte[]]$_.mission_id; PayloadBytes=$payload
            }
        })
}

function Set-HHVisualizerObservationReconciled {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Private authenticated recovery mutation controlled by explicit lifecycle start.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Connection,
        [Parameter(Mandatory)][object]$Transaction,
        [Parameter(Mandatory)][byte[]]$MasterKey,
        [Parameter(Mandatory)][object]$CurrentSnapshot,
        [Parameter(Mandatory)][byte[]]$EventId,
        [Parameter(Mandatory)][DateTimeOffset]$ReconciledAtUtc
    )
    $when = $ReconciledAtUtc.UtcDateTime.ToString('o',[Globalization.CultureInfo]::InvariantCulture)
    $affected = Invoke-HHSqliteNonQuery -Connection $Connection -Transaction $Transaction -Sql @'
UPDATE visualizer_host_observations
SET delivery_status='Delivered',last_status_code=200,delivered_at_utc=@when
WHERE event_id=@id AND delivery_attempts=1 AND delivery_status='Pending';
'@ -Parameters @{ id=$EventId; when=$when }
    if ($affected -ne 1) { throw 'Pending observation reconciliation did not update exactly one row.' }
    Update-HHVisualizerStateHead -Connection $Connection -Transaction $Transaction `
        -MasterKey $MasterKey -CurrentSnapshot $CurrentSnapshot `
        -CurrentMissionId $CurrentSnapshot.CurrentMissionId
}

function Get-HHBase32LowerNoPadding {
    [CmdletBinding()]
    param([Parameter(Mandatory)][byte[]]$Bytes)
    $alphabet = 'abcdefghijklmnopqrstuvwxyz234567'
    $builder = [Text.StringBuilder]::new()
    [int]$buffer = 0; [int]$bits = 0
    foreach ($item in $Bytes) {
        $buffer = ($buffer -shl 8) -bor $item; $bits += 8
        while ($bits -ge 5) { $bits -= 5; $null = $builder.Append($alphabet[($buffer -shr $bits) -band 31]) }
    }
    if ($bits -gt 0) { $null = $builder.Append($alphabet[($buffer -shl (5 - $bits)) -band 31]) }
    $builder.ToString()
}

function Resolve-HHVisualizerEndpointIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Connection,
        [Parameter(Mandatory)][object]$Transaction,
        [Parameter(Mandatory)][byte[]]$MasterKey,
        [Parameter(Mandatory)][string]$TargetName,
        [AllowNull()][string]$NativeIdentityDigest,
        [Parameter(Mandatory)][DateTimeOffset]$ObservedAtUtc
    )
    $nameKey = $TargetName.ToUpperInvariant()
    $existing = @(Invoke-HHSqliteQuery -Connection $Connection -Transaction $Transaction `
            -Sql 'SELECT endpoint_id,identity_strategy FROM visualizer_endpoint_identities WHERE target_name_key=@name;' `
            -Parameters @{ name=$nameKey })
    $strategy = if ($existing.Count -eq 1) { [string]$existing[0].identity_strategy } else { 'persisted_random' }
    if ($existing.Count -eq 1) {
        $endpointId = [string]$existing[0].endpoint_id
    }
    elseif (-not [string]::IsNullOrWhiteSpace($NativeIdentityDigest)) {
        $inputBytes = [Text.UTF8Encoding]::new($false).GetBytes("HostHunter/endpoint/v1`n$NativeIdentityDigest")
        $key = Get-HHVisualizerMacKey -MasterKey $MasterKey
        try {
            $digest = Get-HHPersistenceMac -Key $key -Bytes $inputBytes
            $endpointId = 'hh_' + (Get-HHBase32LowerNoPadding -Bytes $digest)
            $strategy = 'platform_instance_hmac_sha256'
        }
        finally { [Array]::Clear($inputBytes,0,$inputBytes.Length); [Array]::Clear($key,0,$key.Length) }
    }
    else {
        $endpointId = 'hh_' + (Get-HHBase32LowerNoPadding -Bytes (
                [Guid]::NewGuid().ToByteArray() + [Guid]::NewGuid().ToByteArray()
            ))
    }
    $seen = $ObservedAtUtc.UtcDateTime.ToString('o',[Globalization.CultureInfo]::InvariantCulture)
    $null = Invoke-HHSqliteNonQuery -Connection $Connection -Transaction $Transaction -Sql @'
INSERT INTO visualizer_endpoint_identities(target_name_key,endpoint_id,identity_strategy,last_seen_at_utc)
VALUES(@name,@endpoint,@strategy,@seen)
ON CONFLICT(target_name_key) DO UPDATE SET endpoint_id=excluded.endpoint_id,
identity_strategy=excluded.identity_strategy,last_seen_at_utc=excluded.last_seen_at_utc;
'@ -Parameters @{ name=$nameKey; endpoint=$endpointId; strategy=$strategy; seen=$seen }
    [pscustomobject]@{ EndpointId=$endpointId; Strategy=$strategy; TargetNameKey=$nameKey }
}

function Add-HHVisualizerHostObservation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Connection,
        [Parameter(Mandatory)][object]$Transaction,
        [Parameter(Mandatory)][byte[]]$MasterKey,
        [Parameter(Mandatory)][object]$CurrentSnapshot,
        [Parameter(Mandatory)][byte[]]$EventId,
        [Parameter(Mandatory)][byte[]]$MissionId,
        [Parameter(Mandatory)][string]$TargetNameKey,
        [Parameter(Mandatory)][string]$EndpointId,
        [Parameter(Mandatory)][DateTimeOffset]$ObservedAtUtc,
        [Parameter(Mandatory)][byte[]]$PayloadBytes
    )
    if ($PayloadBytes.Length -gt 262144) { throw 'The host observation exceeds 256 KiB.' }
    $associated = [Text.Encoding]::UTF8.GetBytes("HostHunter/host-observation/v1`n$(ConvertTo-HHLowerGuid $EventId)")
    try { $envelope = Protect-HHPersistenceValue -Plaintext $PayloadBytes -MasterKey $MasterKey -AssociatedData $associated }
    finally { [Array]::Clear($associated,0,$associated.Length) }
    $hash = [Convert]::ToHexString((Get-HHPersistenceHash -Bytes $PayloadBytes)).ToLowerInvariant()
    $observed = $ObservedAtUtc.UtcDateTime.ToString('o',[Globalization.CultureInfo]::InvariantCulture)
    $null = Invoke-HHSqliteNonQuery -Connection $Connection -Transaction $Transaction -Sql @'
INSERT INTO visualizer_host_observations(event_id,mission_id,target_name_key,endpoint_id,
observed_at_utc,payload_envelope,content_sha256,delivery_status,delivery_attempts)
VALUES(@event,@mission,@target,@endpoint,@observed,@payload,@hash,'Pending',0);
'@ -Parameters @{ event=$EventId; mission=$MissionId; target=$TargetNameKey; endpoint=$EndpointId; observed=$observed; payload=$envelope; hash=$hash }
    $null = Update-HHVisualizerStateHead -Connection $Connection -Transaction $Transaction `
        -MasterKey $MasterKey -CurrentSnapshot $CurrentSnapshot `
        -CurrentMissionId $CurrentSnapshot.CurrentMissionId
    [pscustomobject]@{ EventId=$EventId; ContentSha256=$hash; PayloadBytes=$PayloadBytes }
}

function Set-HHVisualizerDeliveryResult {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Private authenticated repository mutation runs inside a caller-owned transaction.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Connection,
        [Parameter(Mandatory)][object]$Transaction,
        [Parameter(Mandatory)][byte[]]$MasterKey,
        [Parameter(Mandatory)][object]$CurrentSnapshot,
        [Parameter(Mandatory)][ValidateSet('Mission','Observation','Forensic')][string]$Kind,
        [Parameter(Mandatory)][byte[]]$Id,
        [Parameter(Mandatory)][bool]$Delivered,
        [AllowNull()][Nullable[int]]$StatusCode,
        [Parameter(Mandatory)][DateTimeOffset]$AttemptedAtUtc
    )
    $table = switch ($Kind) {
        'Mission' { 'visualizer_missions' }
        'Observation' { 'visualizer_host_observations' }
        'Forensic' { 'visualizer_forensic_events' }
    }
    $column = if ($Kind -ceq 'Mission') { 'mission_id' } else { 'event_id' }
    # A failed bounded attempt remains pending for explicit operator/release
    # reconciliation. There is deliberately no automatic retry worker.
    $status = if ($Delivered) { 'Delivered' } else { 'Pending' }
    $when = if ($Delivered) {
        $AttemptedAtUtc.UtcDateTime.ToString(
            'o',
            [Globalization.CultureInfo]::InvariantCulture
        )
    }
    else { $null }
    $deliverySql = "UPDATE $table SET delivery_status=@status,delivery_attempts=1," +
        "last_status_code=@code,delivered_at_utc=@when WHERE $column=@id " +
        'AND delivery_attempts=0;'
    $affected = Invoke-HHSqliteNonQuery -Connection $Connection -Transaction $Transaction `
        -Sql $deliverySql `
        -Parameters @{ status=$status; code=$StatusCode; when=$when; id=$Id }
    if ($affected -ne 1) { return $false }
    $nextMissionId = if ($Kind -ceq 'Mission' -and $Delivered) {
        $Id
    }
    else { $CurrentSnapshot.CurrentMissionId }
    $null = Update-HHVisualizerStateHead -Connection $Connection -Transaction $Transaction `
        -MasterKey $MasterKey -CurrentSnapshot $CurrentSnapshot `
        -CurrentMissionId $nextMissionId
    return $true
}
