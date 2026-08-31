Set-StrictMode -Version Latest

function Add-HHVisualizerForensicEventBatch {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Writes immutable evidence inside a caller-owned authenticated transaction.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Connection,
        [Parameter(Mandatory)][object]$Transaction,
        [Parameter(Mandatory)][byte[]]$MasterKey,
        [Parameter(Mandatory)][object]$CurrentSnapshot,
        [Parameter(Mandatory)][ValidateCount(1, 500)][object[]]$ForensicEvent,
        [AllowNull()][object]$Cursor
    )
    $stored = [Collections.Generic.List[object]]::new()
    $inserted = 0
    foreach ($item in $ForensicEvent) {
        $payload = [byte[]]$item.PayloadBytes
        if ($payload.Length -gt 262144) { throw 'A forensic event exceeds 256 KiB.' }
        $eventGuid = [Guid]$item.EventId
        $eventBytes = $eventGuid.ToByteArray()
        $digest = Get-HHForensicPayloadDigest -PayloadBytes $payload
        $existing = @(Invoke-HHSqliteQuery -Connection $Connection -Transaction $Transaction `
                -Sql 'SELECT content_sha256 FROM visualizer_forensic_events WHERE event_id=@id;' `
                -Parameters @{ id=$eventBytes })
        if ($existing.Count -gt 0) {
            if ([string]$existing[0].content_sha256 -cne $digest) {
                throw "Forensic event identity '$eventGuid' already exists with different content."
            }
            $stored.Add([pscustomobject]@{
                    EventId=$eventGuid;ContentSha256=$digest;PayloadBytes=$payload;Created=$false
                })
            continue
        }
        $associated = [Text.Encoding]::UTF8.GetBytes(
            "HostHunter/forensic-event/v1`n$($eventGuid.ToString('D').ToLowerInvariant())"
        )
        try {
            $envelope = Protect-HHPersistenceValue -Plaintext $payload `
                -MasterKey $MasterKey -AssociatedData $associated
        }
        finally { [Array]::Clear($associated, 0, $associated.Length) }
        $occurred = ([DateTimeOffset]$item.OccurredAtUtc).UtcDateTime.ToString(
            'o', [Globalization.CultureInfo]::InvariantCulture
        )
        $collected = ([DateTimeOffset]$item.CollectedAtUtc).UtcDateTime.ToString(
            'o', [Globalization.CultureInfo]::InvariantCulture
        )
        $null = Invoke-HHSqliteNonQuery -Connection $Connection -Transaction $Transaction -Sql @'
INSERT INTO visualizer_forensic_events(
    event_id,mission_id,target_name_key,endpoint_id,schema_name,occurred_at_utc,
    collected_at_utc,payload_envelope,content_sha256,delivery_status,delivery_attempts
) VALUES(@event,@mission,@target,@endpoint,@schema,@occurred,@collected,@payload,@hash,'Pending',0);
'@ -Parameters @{
            event=$eventBytes;mission=([Guid]$item.MissionId).ToByteArray()
            target=[string]$item.TargetNameKey;endpoint=[string]$item.EndpointId
            schema=[string]$item.SchemaName;occurred=$occurred;collected=$collected
            payload=$envelope;hash=$digest
        }
        $inserted++
        $stored.Add([pscustomobject]@{
                EventId=$eventGuid;ContentSha256=$digest;PayloadBytes=$payload;Created=$true
            })
    }
    if ($null -ne $Cursor) {
        $now = [DateTimeOffset]::UtcNow.UtcDateTime.ToString(
            'o', [Globalization.CultureInfo]::InvariantCulture
        )
        $occurred = ([DateTimeOffset]$Cursor.OccurredAtUtc).UtcDateTime.ToString(
            'o', [Globalization.CultureInfo]::InvariantCulture
        )
        $null = Invoke-HHSqliteNonQuery -Connection $Connection -Transaction $Transaction -Sql @'
INSERT INTO forensic_collection_cursors(
    target_name_key,source_name,occurred_at_utc,record_id,updated_at_utc
) VALUES(@target,@source,@occurred,@record,@updated)
ON CONFLICT(target_name_key,source_name) DO UPDATE SET
    occurred_at_utc=excluded.occurred_at_utc,
    record_id=excluded.record_id,
    updated_at_utc=excluded.updated_at_utc
WHERE excluded.occurred_at_utc > forensic_collection_cursors.occurred_at_utc
    OR (excluded.occurred_at_utc = forensic_collection_cursors.occurred_at_utc
        AND CAST(excluded.record_id AS INTEGER) > CAST(forensic_collection_cursors.record_id AS INTEGER));
'@ -Parameters @{
            target=[string]$Cursor.TargetNameKey;source=[string]$Cursor.SourceName
            occurred=$occurred;record=[string]$Cursor.RecordId;updated=$now
        }
    }
    if ($inserted -gt 0 -or $null -ne $Cursor) {
        $null = Update-HHVisualizerStateHead -Connection $Connection -Transaction $Transaction `
            -MasterKey $MasterKey -CurrentSnapshot $CurrentSnapshot `
            -CurrentMissionId $CurrentSnapshot.CurrentMissionId
    }
    @($stored)
}

function Get-HHForensicCollectionCursor {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Connection,
        [AllowNull()][object]$Transaction,
        [Parameter(Mandatory)][string]$TargetNameKey,
        [Parameter(Mandatory)][string]$SourceName
    )
    $rows = @(Invoke-HHSqliteQuery -Connection $Connection -Transaction $Transaction -Sql @'
SELECT occurred_at_utc,record_id FROM forensic_collection_cursors
WHERE target_name_key=@target AND source_name=@source;
'@ -Parameters @{ target=$TargetNameKey;source=$SourceName })
    if ($rows.Count -eq 0) { return $null }
    [pscustomobject]@{
        OccurredAtUtc=[DateTimeOffset]::Parse([string]$rows[0].occurred_at_utc)
        RecordId=[string]$rows[0].record_id
    }
}

function Read-HHPendingVisualizerForensicEvent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Connection,
        [AllowNull()][object]$Transaction,
        [Parameter(Mandatory)][byte[]]$MasterKey,
        [Parameter(Mandatory)][byte[]]$MissionId,
        [ValidateRange(1, 500)][int]$First=100
    )
    $rows = @(Invoke-HHSqliteQuery -Connection $Connection -Transaction $Transaction -Sql @'
SELECT event_id,schema_name,payload_envelope,content_sha256 FROM visualizer_forensic_events
WHERE mission_id=@mission AND delivery_status='Pending'
ORDER BY collected_at_utc,event_id LIMIT @first;
'@ -Parameters @{ mission=$MissionId;first=$First })
    @($rows | ForEach-Object {
            $id = [Guid]::new([byte[]]$_.event_id)
            $associated = [Text.Encoding]::UTF8.GetBytes(
                "HostHunter/forensic-event/v1`n$($id.ToString('D').ToLowerInvariant())"
            )
            try {
                $bytes = Unprotect-HHPersistenceValue -Envelope ([byte[]]$_.payload_envelope) `
                    -MasterKey $MasterKey -AssociatedData $associated
            }
            finally { [Array]::Clear($associated,0,$associated.Length) }
            if((Get-HHForensicPayloadDigest -PayloadBytes $bytes) -cne [string]$_.content_sha256){
                [Array]::Clear($bytes,0,$bytes.Length)
                throw 'A pending forensic event failed its plaintext digest check.'
            }
            [pscustomobject]@{
                EventId=$id;SchemaName=[string]$_.schema_name;PayloadBytes=$bytes
            }
        })
}

function Set-HHVisualizerForensicEventReconciled {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions','',
        Justification = 'Explicit mission lifecycle reconciliation owns this authenticated mutation.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Connection,[Parameter(Mandatory)][object]$Transaction,
        [Parameter(Mandatory)][byte[]]$MasterKey,[Parameter(Mandatory)][object]$CurrentSnapshot,
        [Parameter(Mandatory)][byte[]]$EventId,[Parameter(Mandatory)][DateTimeOffset]$ReconciledAtUtc
    )
    $when=$ReconciledAtUtc.UtcDateTime.ToString('o',[Globalization.CultureInfo]::InvariantCulture)
    $affected=Invoke-HHSqliteNonQuery -Connection $Connection -Transaction $Transaction -Sql @'
UPDATE visualizer_forensic_events
SET delivery_status='Delivered',delivery_attempts=1,last_status_code=200,delivered_at_utc=@when
WHERE event_id=@id AND delivery_status='Pending';
'@ -Parameters @{id=$EventId;when=$when}
    if($affected -ne 1){throw 'Pending forensic-event reconciliation did not update exactly one row.'}
    Update-HHVisualizerStateHead -Connection $Connection -Transaction $Transaction `
        -MasterKey $MasterKey -CurrentSnapshot $CurrentSnapshot `
        -CurrentMissionId $CurrentSnapshot.CurrentMissionId
}
