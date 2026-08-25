$sourceRoot = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
    Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration'
}
else { $env:HH_TEST_SOURCE_ROOT }
$module = New-Module -Name HostHunterForensicsOutboxTest -ArgumentList $sourceRoot -ScriptBlock {
    param($Root)
    $script:HHModuleRoot = $Root
    . (Join-Path $Root 'Private/PersistenceErrors.ps1')
    . (Join-Path $Root 'Private/PersistencePath.ps1')
    . (Join-Path $Root 'Private/SqliteProvider.ps1')
    . (Join-Path $Root 'Private/SqlitePersistence.ps1')
    . (Join-Path $Root 'Forensics/Private/Persistence/ForensicsCrypto.ps1')
    . (Join-Path $Root 'Forensics/Private/Migrations/ForensicsMigrations.ps1')
    . (Join-Path $Root 'Forensics/Private/Persistence/ForensicsPersistence.ps1')
    . (Join-Path $Root 'Forensics/Private/Delivery/ForensicsOutbox.ps1')
    . (Join-Path $Root 'Forensics/Private/Delivery/ForensicsApiClient.ps1')
}
$module | Import-Module -Force

Describe 'forensics encrypted exact-byte outbox' -Tag Unit {
    InModuleScope HostHunterForensicsOutboxTest {
        BeforeAll {
            if ([IO.Directory]::Exists('/opt/hosthunter-sqlite/lib')) {
                $env:HH_SQLITE_PROVIDER_ROOT = '/opt/hosthunter-sqlite/lib'
            }

            function New-HHForensicsTestEvent {
                [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
                    'PSUseShouldProcessForStateChangingFunctions',
                    '',
                    Justification = 'Constructs only an in-memory test event.'
                )]
                param(
                    [Parameter(Mandatory)][string]$Id,
                    [Parameter(Mandatory)][long]$Ordinal,
                    [string]$Body = '{"event":{"kind":"event"}}'
                )
                [pscustomobject]@{
                    EventId = $Id
                    SourceKey = 'fixture-source'
                    Ordinal = $Ordinal
                    OccurredAtUtc = '2026-08-25T00:00:00.0000000Z'
                    BodyBytes = [Text.Encoding]::UTF8.GetBytes($Body)
                }
            }

            function New-HHForensicsTestReceipt {
                [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
                    'PSUseShouldProcessForStateChangingFunctions',
                    '',
                    Justification = 'Constructs only in-memory receipt fixture bytes.'
                )]
                param(
                    [Parameter(Mandatory)][object]$Item,
                    [int]$OriginalStatus = 201
                )
                $json = [ordered]@{
                    schema = 'hosthunter.put-receipt/1'
                    resource_uri = $Item.ResourceUri
                    resource_key = $Item.ResourceKey
                    idempotency_key = $Item.IdempotencyKey
                    content_digest = Get-HHForensicsContentDigestHeader -Digest $Item.BodyDigest
                    original_status = $OriginalStatus
                    receipt_id = 'unit-receipt-1'
                } | ConvertTo-Json -Compress
                return [Text.Encoding]::UTF8.GetBytes($json)
            }

            function Initialize-HHForensicsProjectionFixture {
                $firstEvent = New-HHForensicsTestEvent `
                    -Id projection-event-1 -Ordinal 0 -Body '{"projection":1}'
                $secondEvent = New-HHForensicsTestEvent `
                    -Id projection-event-2 -Ordinal 0 -Body '{"projection":2}'
                $null = Write-HHForensicsEventBatch `
                    -Context $script:context -RunId projection-run-1 `
                    -ResourceKey projection-resource-1 -IdempotencyKey projection-idem-1 `
                    -ResourceUri /api/v1/process-events -CanonicalEvents @($firstEvent) `
                    -CreationOrder 10
                $null = Write-HHForensicsEventBatch `
                    -Context $script:context -RunId projection-run-2 `
                    -ResourceKey projection-resource-2 -IdempotencyKey projection-idem-2 `
                    -ResourceUri /api/v1/process-events -CanonicalEvents @($secondEvent) `
                    -CreationOrder 20 -Dependencies projection-resource-1
                $firstAttempt = Start-HHForensicsDeliveryAttempt `
                    -Context $script:context -ResourceKey projection-resource-1 `
                    -AttemptId projection-attempt-1
                $null = Complete-HHForensicsDeliveryAttempt `
                    -Context $script:context -ResourceKey projection-resource-1 `
                    -AttemptNumber $firstAttempt.AttemptNumber -Outcome RETRYABLE `
                    -StatusCode 503 -ProblemCode FixtureRetry `
                    -ResponseBody ([Text.Encoding]::UTF8.GetBytes('{"code":"retry"}'))
                $secondAttempt = Start-HHForensicsDeliveryAttempt `
                    -Context $script:context -ResourceKey projection-resource-1 `
                    -AttemptId projection-attempt-2
                $null = Complete-HHForensicsDeliveryAttempt `
                    -Context $script:context -ResourceKey projection-resource-1 `
                    -AttemptNumber $secondAttempt.AttemptNumber -Outcome CONFLICT `
                    -StatusCode 409 -ProblemCode FixtureConflict `
                    -ResponseBody ([Text.Encoding]::UTF8.GetBytes('{"code":"conflict"}'))
            }
        }

        BeforeEach {
            $script:testRoot = Join-Path $TestDrive ([Guid]::NewGuid().ToString('N'))
            $script:persistence = New-HHForensicsPersistenceContext -DataRoot $script:testRoot
            $script:testKey = [byte[]](64..95)
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
            }
        }

        It 'atomically encrypts canonical events and an exact request then replays by digest' {
            $canonicalEvent = New-HHForensicsTestEvent -Id event-1 -Ordinal 0 `
                -Body '{"process":{"command_line":"fixture-sensitive-command"}}'
            $request = [Text.Encoding]::UTF8.GetBytes(
                '{"schema":"hosthunter.event-batch/1","run_id":"run-1",' +
                '"sequence":1,"first_ordinal":0,"last_ordinal":0,' +
                '"event_count":1,"events":[' +
                '{"process":{"command_line":"fixture-sensitive-command"}}]}'
            )
            (Get-Command Write-HHForensicsEventBatch).Parameters.ContainsKey('RequestBody') |
                Should -BeFalse
            $first = Write-HHForensicsEventBatch `
                -Context $script:context -RunId run-1 -ResourceKey resource-1 `
                -IdempotencyKey idem-1 -ResourceUri /api/v1/process-events `
                -CanonicalEvents @($canonicalEvent) -CreationOrder 1
            $first.WasReplay | Should -BeFalse

            $stored = Invoke-HHSqliteQuery -Connection $script:context.Connection -Sql @'
SELECT typeof(event_body_envelope) AS event_type,
    hex(event_body_envelope) AS event_envelope
FROM forensics_events WHERE event_id='event-1';
'@
            $stored.event_type | Should -BeExactly blob
            $stored.event_envelope | Should -Not -Match '666978747572652D73656E736974697665'
            $outbox = Get-HHForensicsOutboxItem `
                -Context $script:context -ResourceKey resource-1 -IncludeBody
            try { $outbox.Body | Should -Be $request }
            finally { [Array]::Clear($outbox.Body, 0, $outbox.Body.Length) }

            $replay = Write-HHForensicsEventBatch `
                -Context $script:context -RunId run-1 -ResourceKey resource-1 `
                -IdempotencyKey idem-1 -ResourceUri /api/v1/process-events `
                -CanonicalEvents @($canonicalEvent) -CreationOrder 1
            $replay.WasReplay | Should -BeTrue
            (Invoke-HHSqliteScalar -Connection $script:context.Connection `
                    -Sql 'SELECT COUNT(*) FROM forensics_events;') | Should -Be 1
            (Invoke-HHSqliteScalar -Connection $script:context.Connection `
                    -Sql 'SELECT COUNT(*) FROM forensics_outbox;') | Should -Be 1
        }

        It 'quarantines a different digest for the same idempotency key' {
            $canonicalEvent = New-HHForensicsTestEvent -Id event-1 -Ordinal 0
            $null = Write-HHForensicsEventBatch `
                -Context $script:context -RunId run-1 -ResourceKey resource-1 `
                -IdempotencyKey idem-1 -ResourceUri /api/v1/process-events `
                -CanonicalEvents @($canonicalEvent) -CreationOrder 1

            {
                Write-HHForensicsEventBatch `
                    -Context $script:context -RunId run-2 -ResourceKey resource-2 `
                    -IdempotencyKey idem-1 -ResourceUri /api/v1/process-events `
                    -CanonicalEvents @(
                        New-HHForensicsTestEvent -Id event-2 -Ordinal 0
                    ) -CreationOrder 2
            } | Should -Throw -ErrorId 'ForensicsIdempotencyConflict*'
            (Invoke-HHSqliteScalar -Connection $script:context.Connection `
                    -Sql 'SELECT COUNT(*) FROM forensics_quarantine;') | Should -Be 1
            (Invoke-HHSqliteScalar -Connection $script:context.Connection `
                    -Sql 'SELECT COUNT(*) FROM forensics_outbox;') | Should -Be 1
        }

        It 'returns the same quarantine identity without adding a duplicate record' {
            $digest = Get-HHForensicsHash `
                -Bytes ([Text.Encoding]::UTF8.GetBytes('duplicate-quarantine'))
            $first = Add-HHForensicsQuarantineRecord `
                -Context $script:context -ConflictKind FixtureConflict `
                -RoutingKey duplicate-routing -ObservedDigest $digest
            $second = Add-HHForensicsQuarantineRecord `
                -Context $script:context -ConflictKind FixtureConflict `
                -RoutingKey duplicate-routing -ObservedDigest $digest

            $second | Should -BeExactly $first
            (Invoke-HHSqliteScalar -Connection $script:context.Connection `
                    -Sql 'SELECT COUNT(*) FROM forensics_quarantine;') | Should -Be 1
        }

        It 'quarantines an ambiguous resource and idempotency collision' {
            $null = Write-HHForensicsEventBatch `
                -Context $script:context -RunId run-a -ResourceKey resource-a `
                -IdempotencyKey idem-a -ResourceUri /api/v1/events `
                -CanonicalEvents @(
                    New-HHForensicsTestEvent -Id event-a -Ordinal 0
                ) -CreationOrder 1
            $null = Write-HHForensicsEventBatch `
                -Context $script:context -RunId run-b -ResourceKey resource-b `
                -IdempotencyKey idem-b -ResourceUri /api/v1/events `
                -CanonicalEvents @(
                    New-HHForensicsTestEvent -Id event-b -Ordinal 0
                ) -CreationOrder 2

            {
                Write-HHForensicsEventBatch `
                    -Context $script:context -RunId run-c -ResourceKey resource-a `
                    -IdempotencyKey idem-b -ResourceUri /api/v1/events `
                    -CanonicalEvents @(
                        New-HHForensicsTestEvent -Id event-c -Ordinal 0
                    ) -CreationOrder 3
            } | Should -Throw -ErrorId 'ForensicsIdempotencyConflict*'
            (Invoke-HHSqliteScalar -Connection $script:context.Connection -Sql @'
SELECT COUNT(*) FROM forensics_quarantine WHERE expected_digest IS NULL;
'@) | Should -Be 1
        }

        It 'rolls the whole batch back when its outbox insert fails' {
            $null = Write-HHForensicsEventBatch `
                -Context $script:context -RunId run-1 -ResourceKey resource-1 `
                -IdempotencyKey idem-1 -ResourceUri /api/v1/process-events `
                -CanonicalEvents @(
                    New-HHForensicsTestEvent -Id event-1 -Ordinal 0
                ) -CreationOrder 1
            {
                Write-HHForensicsEventBatch `
                    -Context $script:context -RunId run-2 -ResourceKey resource-2 `
                    -IdempotencyKey idem-2 -ResourceUri /api/v1/process-events `
                    -CanonicalEvents @(
                        New-HHForensicsTestEvent -Id event-2 -Ordinal 0
                    ) -CreationOrder 1
            } | Should -Throw
            (Invoke-HHSqliteScalar -Connection $script:context.Connection -Sql @'
SELECT COUNT(*) FROM forensics_events WHERE event_id='event-2';
'@) | Should -Be 0
            (Invoke-HHSqliteScalar -Connection $script:context.Connection `
                    -Sql 'SELECT COUNT(*) FROM forensics_mutations;') | Should -Be 1
        }

        It 'reuses identical stored bytes across retry attempts' {
            $canonicalEvent = New-HHForensicsTestEvent -Id event-1 -Ordinal 0
            $null = Write-HHForensicsEventBatch `
                -Context $script:context -RunId run-1 -ResourceKey resource-1 `
                -IdempotencyKey idem-1 -ResourceUri /api/v1/process-events `
                -CanonicalEvents @($canonicalEvent) -CreationOrder 1
            $first = Start-HHForensicsDeliveryAttempt `
                -Context $script:context -ResourceKey resource-1 -AttemptId attempt-1
            $firstBytes = [byte[]]$first.Item.Body.Clone()
            $null = Complete-HHForensicsDeliveryAttempt `
                -Context $script:context -ResourceKey resource-1 `
                -AttemptNumber $first.AttemptNumber -Outcome RETRYABLE -StatusCode 503
            $second = Start-HHForensicsDeliveryAttempt `
                -Context $script:context -ResourceKey resource-1 -AttemptId attempt-2
            $second.Item.Body | Should -Be $firstBytes
            $second.Item.BodyDigest | Should -Be $first.Item.BodyDigest
            $second.AttemptNumber | Should -Be 2
            $null = Complete-HHForensicsDeliveryAttempt `
                -Context $script:context -ResourceKey resource-1 `
                -AttemptNumber $second.AttemptNumber -Outcome ACCEPTED -StatusCode 200 `
                -ResponseBody (New-HHForensicsTestReceipt -Item $second.Item -OriginalStatus 200)
            $accepted = Get-HHForensicsOutboxItem `
                -Context $script:context -ResourceKey resource-1 -IncludeBody
            $accepted.Status | Should -BeExactly ACCEPTED
            $accepted.Body | Should -BeNullOrEmpty
            (Invoke-HHSqliteScalar -Connection $script:context.Connection -Sql @'
SELECT COUNT(*) FROM forensics_outbox
WHERE resource_key='resource-1' AND request_body_envelope IS NULL
    AND receipt_envelope IS NOT NULL;
'@) | Should -Be 1
            (Get-HHForensicsNextOutboxItem -Context $script:context) |
                Should -BeNullOrEmpty
            $acceptedReplay = Write-HHForensicsEventBatch `
                -Context $script:context -RunId run-1 -ResourceKey resource-1 `
                -IdempotencyKey idem-1 -ResourceUri /api/v1/process-events `
                -CanonicalEvents @($canonicalEvent) -CreationOrder 1
            $acceptedReplay.Status | Should -BeExactly ACCEPTED
            $acceptedReplay.WasReplay | Should -BeTrue
            (Invoke-HHSqliteScalar -Connection $script:context.Connection `
                    -Sql 'SELECT COUNT(*) FROM forensics_outbox;') | Should -Be 1
        }

        It 'recovers an interrupted sending row only to unknown' {
            $null = Write-HHForensicsEventBatch `
                -Context $script:context -RunId run-1 -ResourceKey resource-1 `
                -IdempotencyKey idem-1 -ResourceUri /api/v1/process-events `
                -CanonicalEvents @(
                    New-HHForensicsTestEvent -Id event-1 -Ordinal 0
                ) -CreationOrder 1
            $null = Start-HHForensicsDeliveryAttempt `
                -Context $script:context -ResourceKey resource-1 -AttemptId interrupted-1

            (Repair-HHForensicsInterruptedDelivery -Context $script:context) |
                Should -Be 1
            $item = Get-HHForensicsOutboxItem `
                -Context $script:context -ResourceKey resource-1
            $item.Status | Should -BeExactly UNKNOWN
            (Invoke-HHSqliteScalar -Connection $script:context.Connection -Sql @'
SELECT COUNT(*)
FROM forensics_delivery_attempts
WHERE resource_key='resource-1' AND outcome='UNKNOWN';
'@) | Should -Be 1
        }

        It 'reports no interrupted delivery when the queue has no sending row' {
            (Repair-HHForensicsInterruptedDelivery -Context $script:context) |
                Should -Be 0
        }

        It 'enforces deterministic count and byte bounds before mutation' {
            $events = @(for ($index = 0; $index -lt 251; $index++) {
                    New-HHForensicsTestEvent -Id "event-$index" -Ordinal $index
                })
            {
                Write-HHForensicsEventBatch `
                    -Context $script:context -RunId run-1 -ResourceKey resource-1 `
                    -IdempotencyKey idem-1 -ResourceUri /api/v1/process-events `
                    -CanonicalEvents $events -CreationOrder 1
            } | Should -Throw -ErrorId 'ForensicsBatchRejected*'

            {
                Write-HHForensicsEventBatch `
                    -Context $script:context -RunId run-1 -ResourceKey resource-1 `
                    -IdempotencyKey idem-1 -ResourceUri /api/v1/process-events `
                    -CanonicalEvents @(
                        New-HHForensicsTestEvent -Id event-a -Ordinal 0 `
                            -Body ('{"payload":"' + ('x' * 263000) + '"}')
                        New-HHForensicsTestEvent -Id event-b -Ordinal 1 `
                            -Body ('{"payload":"' + ('y' * 263000) + '"}')
                    ) -CreationOrder 1
            } | Should -Throw -ErrorId 'ForensicsBatchRejected*'
            (Invoke-HHSqliteScalar -Connection $script:context.Connection `
                    -Sql 'SELECT COUNT(*) FROM forensics_mutations;') | Should -Be 0
        }

        It 'rejects unsafe routing, malformed events, and invalid quarantine input' {
            (Get-HHForensicsOutboxItem `
                    -Context $script:context -ResourceKey missing-resource) |
                Should -BeNullOrEmpty
            {
                Assert-HHForensicsResourceUri -ResourceUri 'https://example.test/events'
            } | Should -Throw -ErrorId 'ForensicsRouteRejected*'
            {
                Add-HHForensicsQuarantineRecord `
                    -Context $script:context -ConflictKind Invalid `
                    -RoutingKey invalid -ObservedDigest ([byte[]](1))
            } | Should -Throw '*32 bytes*'
            {
                Write-HHForensicsEventBatch `
                    -Context $script:context -RunId '   ' -ResourceKey resource-1 `
                    -IdempotencyKey idem-1 -ResourceUri /api/v1/events `
                    -CanonicalEvents @(
                        New-HHForensicsTestEvent -Id event-1 -Ordinal 0
                    ) -CreationOrder 1
            } | Should -Throw '*routing identifiers*'
            {
                Write-HHForensicsEventBatch `
                    -Context $script:context -RunId run-1 -ResourceKey resource-1 `
                    -IdempotencyKey idem-1 -ResourceUri /api/v1/events `
                    -CanonicalEvents @([pscustomobject]@{
                            EventId = 'incomplete'
                            Ordinal = 0L
                            OccurredAtUtc = '2026-08-25T00:00:00Z'
                            BodyBytes = [byte[]](1)
                        }) -CreationOrder 1
            } | Should -Throw '*missing SourceKey*'
            {
                Write-HHForensicsEventBatch `
                    -Context $script:context -RunId run-1 -ResourceKey resource-1 `
                    -IdempotencyKey idem-1 -ResourceUri /api/v1/events `
                    -CanonicalEvents @(
                        New-HHForensicsTestEvent -Id event-1 -Ordinal 0
                        New-HHForensicsTestEvent -Id event-2 -Ordinal 2
                    ) -CreationOrder 1
            } | Should -Throw -ErrorId 'ForensicsBatchRejected*'
            {
                Write-HHForensicsEventBatch `
                    -Context $script:context -RunId run-1 -ResourceKey resource-1 `
                    -IdempotencyKey idem-1 -ResourceUri /api/v1/events `
                    -CanonicalEvents @(
                        New-HHForensicsTestEvent -Id event-1 -Ordinal 0 `
                            -Body ' {"not":"canonical"}'
                    ) -CreationOrder 1
            } | Should -Throw -ErrorId 'ForensicsBatchRejected*'
        }

        It 'rejects an empty canonical body and duplicate event identity' {
            {
                New-HHForensicsCanonicalBatchBody `
                    -RunId empty-run -CreationOrder 0 -CanonicalEvents @()
            } | Should -Throw '*at least one event*'

            {
                Write-HHForensicsEventBatch `
                    -Context $script:context -RunId duplicate-run `
                    -ResourceKey duplicate-resource -IdempotencyKey duplicate-idem `
                    -ResourceUri /api/v1/events -CanonicalEvents @(
                        New-HHForensicsTestEvent -Id duplicate-event -Ordinal 0
                        New-HHForensicsTestEvent -Id duplicate-event -Ordinal 1
                    ) -CreationOrder 1
            } | Should -Throw -ErrorId 'ForensicsBatchRejected*'
            (Invoke-HHSqliteScalar -Connection $script:context.Connection `
                    -Sql 'SELECT COUNT(*) FROM forensics_mutations;') | Should -Be 0
        }

        It 'rejects a missing or digest-divergent protected request body' -TestCases @(
            @{ Kind = 'missing' }
            @{ Kind = 'digest-divergent' }
        ) {
            param($Kind)

            $null = Write-HHForensicsEventBatch `
                -Context $script:context -RunId body-run -ResourceKey body-resource `
                -IdempotencyKey body-idem -ResourceUri /api/v1/events `
                -CanonicalEvents @(
                    New-HHForensicsTestEvent -Id body-event -Ordinal 0
                ) -CreationOrder 1
            $item = Get-HHForensicsOutboxItem `
                -Context $script:context -ResourceKey body-resource
            if ($Kind -ceq 'missing') {
                $null = Invoke-HHSqliteNonQuery `
                    -Connection $script:context.Connection -Sql @'
UPDATE forensics_outbox SET request_body_envelope=NULL WHERE resource_key='body-resource';
'@
            }
            else {
                $differentBody = [Text.Encoding]::UTF8.GetBytes('{"different":true}')
                $differentEnvelope = Protect-HHForensicsValue `
                    -Plaintext $differentBody -ForensicsKey $script:context.ForensicsKey `
                    -Purpose RequestBody -RoutingKey body-resource -Digest $item.BodyDigest
                $null = Invoke-HHSqliteNonQuery `
                    -Connection $script:context.Connection -Sql @'
UPDATE forensics_outbox
SET request_body_envelope=@envelope
WHERE resource_key='body-resource';
'@ -Parameters @{ envelope = $differentEnvelope }
            }

            {
                Get-HHForensicsOutboxItem `
                    -Context $script:context -ResourceKey body-resource -IncludeBody
            } | Should -Throw -ErrorId 'ForensicsIntegrityFailed*'
        }

        It 'quarantines an event identity reused outside exact batch replay' {
            $null = Write-HHForensicsEventBatch `
                -Context $script:context -RunId run-1 -ResourceKey resource-1 `
                -IdempotencyKey idem-1 -ResourceUri /api/v1/events `
                -CanonicalEvents @(
                    New-HHForensicsTestEvent -Id event-1 -Ordinal 0 -Body '{"value":1}'
                ) -CreationOrder 1
            {
                Write-HHForensicsEventBatch `
                    -Context $script:context -RunId run-2 -ResourceKey resource-2 `
                    -IdempotencyKey idem-2 -ResourceUri /api/v1/events `
                    -CanonicalEvents @(
                        New-HHForensicsTestEvent -Id event-1 -Ordinal 0 -Body '{"value":2}'
                    ) -CreationOrder 2
            } | Should -Throw -ErrorId 'ForensicsEventConflict*'
            (Invoke-HHSqliteScalar -Connection $script:context.Connection `
                    -Sql 'SELECT COUNT(*) FROM forensics_quarantine;') | Should -Be 1
        }

        It 'blocks dependencies and rejects invalid delivery state transitions' {
            $null = Write-HHForensicsEventBatch `
                -Context $script:context -RunId run-1 -ResourceKey parent-resource `
                -IdempotencyKey parent-idem -ResourceUri /api/v1/events `
                -CanonicalEvents @(
                    New-HHForensicsTestEvent -Id parent-event -Ordinal 0
                ) -CreationOrder 1
            $null = Write-HHForensicsEventBatch `
                -Context $script:context -RunId run-2 -ResourceKey child-resource `
                -IdempotencyKey child-idem -ResourceUri /api/v1/events `
                -CanonicalEvents @(
                    New-HHForensicsTestEvent -Id child-event -Ordinal 0
                ) -CreationOrder 2 `
                -Dependencies parent-resource
            {
                Start-HHForensicsDeliveryAttempt `
                    -Context $script:context -ResourceKey child-resource -AttemptId blocked-1
            } | Should -Throw -ErrorId 'ForensicsDependencyBlocked*'
            {
                Start-HHForensicsDeliveryAttempt `
                    -Context $script:context -ResourceKey missing-resource -AttemptId missing-1
            } | Should -Throw -ErrorId 'ForensicsOutboxStateRejected*'
            {
                Complete-HHForensicsDeliveryAttempt `
                    -Context $script:context -ResourceKey parent-resource `
                    -AttemptNumber 1 -Outcome ACCEPTED
            } | Should -Throw -ErrorId 'ForensicsOutboxStateRejected*'
            {
                Resolve-HHForensicsUnknownDelivery `
                    -Context $script:context -ResourceKey parent-resource `
                    -Outcome RETRYABLE
            } | Should -Throw -ErrorId 'ForensicsOutboxStateRejected*'

            {
                Write-HHForensicsEventBatch `
                    -Context $script:context -RunId run-3 -ResourceKey invalid-dependency `
                    -IdempotencyKey invalid-dependency-idem -ResourceUri /api/v1/events `
                    -CanonicalEvents @(
                        New-HHForensicsTestEvent -Id invalid-dependency-event -Ordinal 0
                    ) -CreationOrder 3 `
                    -Dependencies invalid-dependency
            } | Should -Throw '*non-empty and non-cyclic*'
        }

        It 'rejects double start and acceptance without a validated receipt' {
            $null = Write-HHForensicsEventBatch `
                -Context $script:context -RunId state-run -ResourceKey state-resource `
                -IdempotencyKey state-idem -ResourceUri /api/v1/events `
                -CanonicalEvents @(
                    New-HHForensicsTestEvent -Id state-event -Ordinal 0
                ) -CreationOrder 1
            $attempt = Start-HHForensicsDeliveryAttempt `
                -Context $script:context -ResourceKey state-resource -AttemptId state-attempt
            {
                Start-HHForensicsDeliveryAttempt `
                    -Context $script:context -ResourceKey state-resource -AttemptId duplicate-attempt
            } | Should -Throw -ErrorId 'ForensicsOutboxStateRejected*'
            {
                Complete-HHForensicsDeliveryAttempt `
                    -Context $script:context -ResourceKey state-resource `
                    -AttemptNumber $attempt.AttemptNumber -Outcome ACCEPTED -StatusCode 201
            } | Should -Throw -ErrorId 'ForensicsReceiptBindingRejected*'
            (Get-HHForensicsOutboxItem `
                    -Context $script:context -ResourceKey state-resource).Status |
                Should -BeExactly SENDING
        }

        It 'rejects empty accepted reconciliation and allows evidence-free retry' {
            $null = Write-HHForensicsEventBatch `
                -Context $script:context -RunId reconcile-run `
                -ResourceKey reconcile-resource -IdempotencyKey reconcile-idem `
                -ResourceUri /api/v1/events -CanonicalEvents @(
                    New-HHForensicsTestEvent -Id reconcile-event -Ordinal 0
                ) -CreationOrder 1
            $attempt = Start-HHForensicsDeliveryAttempt `
                -Context $script:context -ResourceKey reconcile-resource `
                -AttemptId reconcile-attempt
            $null = Complete-HHForensicsDeliveryAttempt `
                -Context $script:context -ResourceKey reconcile-resource `
                -AttemptNumber $attempt.AttemptNumber -Outcome UNKNOWN
            {
                Resolve-HHForensicsUnknownDelivery `
                    -Context $script:context -ResourceKey reconcile-resource `
                    -Outcome ACCEPTED
            } | Should -Throw -ErrorId 'ForensicsReceiptBindingRejected*'

            $resolved = Resolve-HHForensicsUnknownDelivery `
                -Context $script:context -ResourceKey reconcile-resource `
                -Outcome RETRYABLE
            $resolved.Status | Should -BeExactly RETRYABLE
            $resolved.LastStatusCode | Should -BeNullOrEmpty
            $resolved.LastProblemCode | Should -BeNullOrEmpty
        }

        It 'rejects an arbitrary dependency cycle and rolls back the proposed batch' {
            $null = Write-HHForensicsEventBatch `
                -Context $script:context -RunId run-b -ResourceKey resource-b `
                -IdempotencyKey idem-b -ResourceUri /api/v1/events `
                -CanonicalEvents @(
                    New-HHForensicsTestEvent -Id event-b -Ordinal 0
                ) -CreationOrder 1 -Dependencies resource-a
            {
                Write-HHForensicsEventBatch `
                    -Context $script:context -RunId run-a -ResourceKey resource-a `
                    -IdempotencyKey idem-a -ResourceUri /api/v1/events `
                    -CanonicalEvents @(
                        New-HHForensicsTestEvent -Id event-a -Ordinal 0
                    ) -CreationOrder 2 -Dependencies resource-b
            } | Should -Throw '*non-empty and non-cyclic*'
            (Invoke-HHSqliteScalar -Connection $script:context.Connection `
                    -Sql "SELECT COUNT(*) FROM forensics_outbox WHERE resource_key='resource-a';") |
                Should -Be 0
            (Invoke-HHSqliteScalar -Connection $script:context.Connection `
                    -Sql "SELECT COUNT(*) FROM forensics_events WHERE event_id='event-a';") |
                Should -Be 0
        }

        It 'recovers an unknown post-commit result without duplicating the batch' {
            $oldAnchor = $script:testAnchor
            $canonicalEvent = New-HHForensicsTestEvent `
                -Id commit-event -Ordinal 0 -Body '{"commit":"unknown"}'
            {
                Write-HHForensicsEventBatch `
                    -Context $script:context -RunId commit-run -ResourceKey commit-resource `
                    -IdempotencyKey commit-idem -ResourceUri /api/v1/events `
                    -CanonicalEvents @($canonicalEvent) -CreationOrder 1 `
                    -CommitInvoker {
                        param($Transaction)
                        $Transaction.Commit()
                        throw 'simulated post-commit exception'
                    }
            } | Should -Throw -ErrorId 'ForensicsCommitUnknown*'
            $script:context.IsUsable | Should -BeFalse
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
            $replay = Write-HHForensicsEventBatch `
                -Context $script:context -RunId commit-run -ResourceKey commit-resource `
                -IdempotencyKey commit-idem -ResourceUri /api/v1/events `
                -CanonicalEvents @($canonicalEvent) -CreationOrder 1
            $replay.WasReplay | Should -BeTrue
            (Invoke-HHSqliteScalar -Connection $script:context.Connection `
                    -Sql 'SELECT COUNT(*) FROM forensics_events;') | Should -Be 1
            (Invoke-HHSqliteScalar -Connection $script:context.Connection `
                    -Sql 'SELECT COUNT(*) FROM forensics_outbox;') | Should -Be 1
            (Invoke-HHSqliteScalar -Connection $script:context.Connection `
                    -Sql 'SELECT COUNT(*) FROM forensics_mutations;') | Should -Be 1
        }

        It 'detects <Operation> of authenticated <TableName> rows' -TestCases @(
            @{
                TableName = 'events'
                Operation = 'tamper'
                Sql = "UPDATE forensics_events SET source_key='tampered' WHERE event_id='projection-event-1';"
            }
            @{
                TableName = 'events'
                Operation = 'delete'
                Sql = "PRAGMA foreign_keys=OFF; DELETE FROM forensics_events WHERE event_id='projection-event-1';"
            }
            @{
                TableName = 'events'
                Operation = 'reorder'
                Sql = "PRAGMA foreign_keys=OFF; UPDATE forensics_events SET event_id='zzz-projection-event' WHERE event_id='projection-event-1';"
            }
            @{
                TableName = 'outbox'
                Operation = 'tamper'
                Sql = "UPDATE forensics_outbox SET resource_uri='/tampered' WHERE resource_key='projection-resource-1';"
            }
            @{
                TableName = 'outbox'
                Operation = 'delete'
                Sql = "PRAGMA foreign_keys=OFF; DELETE FROM forensics_outbox WHERE resource_key='projection-resource-1';"
            }
            @{
                TableName = 'outbox'
                Operation = 'reorder'
                Sql = "UPDATE forensics_outbox SET creation_order=1000 WHERE resource_key='projection-resource-1';"
            }
            @{
                TableName = 'outbox_events'
                Operation = 'tamper'
                Sql = "UPDATE forensics_outbox_events SET event_ordinal=77 WHERE event_id='projection-event-1';"
            }
            @{
                TableName = 'outbox_events'
                Operation = 'delete'
                Sql = "DELETE FROM forensics_outbox_events WHERE event_id='projection-event-1';"
            }
            @{
                TableName = 'outbox_events'
                Operation = 'reorder'
                Sql = "UPDATE forensics_outbox_events SET event_ordinal=1000 WHERE event_id='projection-event-1';"
            }
            @{
                TableName = 'dependencies'
                Operation = 'tamper'
                Sql = "UPDATE forensics_outbox_dependencies SET depends_on_resource_key='tampered-dependency' WHERE resource_key='projection-resource-2';"
            }
            @{
                TableName = 'dependencies'
                Operation = 'delete'
                Sql = "DELETE FROM forensics_outbox_dependencies WHERE resource_key='projection-resource-2';"
            }
            @{
                TableName = 'dependencies'
                Operation = 'reorder'
                Sql = "UPDATE forensics_outbox_dependencies SET depends_on_resource_key='zzz-dependency' WHERE resource_key='projection-resource-2';"
            }
            @{
                TableName = 'attempts'
                Operation = 'tamper'
                Sql = "UPDATE forensics_delivery_attempts SET problem_code='tampered' WHERE attempt_id='projection-attempt-1';"
            }
            @{
                TableName = 'attempts'
                Operation = 'delete'
                Sql = "DELETE FROM forensics_delivery_attempts WHERE attempt_id='projection-attempt-1';"
            }
            @{
                TableName = 'attempts'
                Operation = 'reorder'
                Sql = "UPDATE forensics_delivery_attempts SET attempt_number=1000 WHERE attempt_id='projection-attempt-1';"
            }
            @{
                TableName = 'quarantine'
                Operation = 'tamper'
                Sql = "UPDATE forensics_quarantine SET routing_key='tampered' WHERE routing_key='projection-idem-1';"
            }
            @{
                TableName = 'quarantine'
                Operation = 'delete'
                Sql = "DELETE FROM forensics_quarantine WHERE routing_key='projection-idem-1';"
            }
            @{
                TableName = 'quarantine'
                Operation = 'reorder'
                Sql = "UPDATE forensics_quarantine SET quarantine_id='zzz-quarantine' WHERE routing_key='projection-idem-1';"
            }
        ) {
            param($TableName, $Operation, $Sql)

            $null = $TableName
            $null = $Operation
            Initialize-HHForensicsProjectionFixture
            $null = Invoke-HHSqliteNonQuery -Connection $script:context.Connection -Sql $Sql
            {
                Get-HHForensicsDatabaseHead `
                    -Connection $script:context.Connection `
                    -ForensicsKey $script:context.ForensicsKey `
                    -MigrationPath $script:persistence.MigrationPath
            } | Should -Throw -ErrorId 'ForensicsIntegrityFailed*'
        }

        It 'detects <Operation> of encrypted <ReceiptLocation> receipt evidence' -TestCases @(
            @{
                ReceiptLocation = 'outbox'
                Operation = 'tamper'
                Sql = @'
UPDATE forensics_outbox
SET receipt_envelope=randomblob(length(receipt_envelope))
WHERE resource_key='receipt-resource';
'@
            }
            @{
                ReceiptLocation = 'outbox'
                Operation = 'delete'
                Sql = @'
UPDATE forensics_outbox
SET receipt_digest=NULL,receipt_envelope=NULL
WHERE resource_key='receipt-resource';
'@
            }
            @{
                ReceiptLocation = 'attempt'
                Operation = 'tamper'
                Sql = @'
UPDATE forensics_delivery_attempts
SET response_envelope=randomblob(length(response_envelope))
WHERE attempt_id='receipt-attempt';
'@
            }
            @{
                ReceiptLocation = 'attempt'
                Operation = 'delete'
                Sql = @'
UPDATE forensics_delivery_attempts
SET response_digest=NULL,response_envelope=NULL
WHERE attempt_id='receipt-attempt';
'@
            }
        ) {
            param($ReceiptLocation, $Operation, $Sql)

            $null = $ReceiptLocation
            $null = $Operation
            $receiptEvent = New-HHForensicsTestEvent -Id receipt-event -Ordinal 0
            $null = Write-HHForensicsEventBatch `
                -Context $script:context -RunId receipt-run -ResourceKey receipt-resource `
                -IdempotencyKey receipt-idem -ResourceUri /api/v1/process-events `
                -CanonicalEvents @($receiptEvent) -CreationOrder 1
            $attempt = Start-HHForensicsDeliveryAttempt `
                -Context $script:context -ResourceKey receipt-resource `
                -AttemptId receipt-attempt
            $null = Complete-HHForensicsDeliveryAttempt `
                -Context $script:context -ResourceKey receipt-resource `
                -AttemptNumber $attempt.AttemptNumber -Outcome ACCEPTED -StatusCode 201 `
                -ResponseBody (New-HHForensicsTestReceipt -Item $attempt.Item)
            $null = Invoke-HHSqliteNonQuery -Connection $script:context.Connection -Sql $Sql
            {
                Get-HHForensicsDatabaseHead `
                    -Connection $script:context.Connection `
                    -ForensicsKey $script:context.ForensicsKey `
                    -MigrationPath $script:persistence.MigrationPath
            } | Should -Throw -ErrorId 'ForensicsIntegrityFailed*'
        }
    }
}
