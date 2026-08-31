$sourceRoot = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
    Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration'
}
else { $env:HH_TEST_SOURCE_ROOT }
Import-Module (Join-Path $sourceRoot 'HostHunterNextGeneration.psd1') -Force

Describe 'forensic repository unit behavior' -Tag Unit {
    InModuleScope HostHunterNextGeneration {
        BeforeEach {
            $script:payload = [Text.Encoding]::UTF8.GetBytes('{"event":"one"}')
            $script:eventId = [Guid]'33333333-3333-4333-8333-333333333333'
            $script:missionId = [Guid]'11111111-1111-4111-8111-111111111111'
            $script:event = [pscustomobject]@{
                EventId=$script:eventId;MissionId=$script:missionId
                TargetNameKey='ALPHA';EndpointId='hh_endpoint';SchemaName='process.start'
                OccurredAtUtc='2026-08-31T00:00:00Z'
                CollectedAtUtc='2026-08-31T00:00:01Z';PayloadBytes=$script:payload
            }
            $script:snapshot = [pscustomobject]@{
                CurrentMissionId=$script:missionId.ToByteArray()
            }
        }

        It 'rejects oversized and conflicting immutable events' {
            $oversized = $script:event.PSObject.Copy()
            $oversized.PayloadBytes = [byte[]]::new(262145)
            { Add-HHVisualizerForensicEventBatch -Connection ([pscustomobject]@{}) `
                    -Transaction ([pscustomobject]@{}) -MasterKey ([byte[]]::new(32)) `
                    -CurrentSnapshot $script:snapshot -ForensicEvent $oversized } |
                Should -Throw '*exceeds 256 KiB*'

            Mock Invoke-HHSqliteQuery {
                [pscustomobject]@{ content_sha256 = ('0' * 64) }
            }
            { Add-HHVisualizerForensicEventBatch -Connection ([pscustomobject]@{}) `
                    -Transaction ([pscustomobject]@{}) -MasterKey ([byte[]]::new(32)) `
                    -CurrentSnapshot $script:snapshot -ForensicEvent $script:event } |
                Should -Throw '*different content*'
        }

        It 'returns an existing byte-identical event without rewriting state' {
            $digest = Get-HHForensicPayloadDigest $script:payload
            Mock Invoke-HHSqliteQuery { [pscustomobject]@{ content_sha256=$digest } }
            Mock Invoke-HHSqliteNonQuery { throw 'must not write' }
            Mock Update-HHVisualizerStateHead { throw 'must not update head' }
            $result = @(Add-HHVisualizerForensicEventBatch `
                    -Connection ([pscustomobject]@{}) -Transaction ([pscustomobject]@{}) `
                    -MasterKey ([byte[]]::new(32)) -CurrentSnapshot $script:snapshot `
                    -ForensicEvent $script:event)
            $result.Count | Should -Be 1
            $result[0].Created | Should -BeFalse
            $result[0].ContentSha256 | Should -BeExactly $digest
        }

        It 'inserts encrypted evidence and advances its monotonic cursor and state head' {
            Mock Invoke-HHSqliteQuery { @() }
            Mock Protect-HHPersistenceValue { [byte[]](1,2,3) }
            Mock Invoke-HHSqliteNonQuery { 1 }
            Mock Update-HHVisualizerStateHead {}
            $cursor = [pscustomobject]@{
                TargetNameKey='ALPHA';SourceName='windows.security.process-start'
                OccurredAtUtc='2026-08-31T00:00:00Z';RecordId='9'
            }
            $result = @(Add-HHVisualizerForensicEventBatch `
                    -Connection ([pscustomobject]@{}) -Transaction ([pscustomobject]@{}) `
                    -MasterKey ([byte[]]::new(32)) -CurrentSnapshot $script:snapshot `
                    -ForensicEvent $script:event -Cursor $cursor)
            $result[0].Created | Should -BeTrue
            Should -Invoke Invoke-HHSqliteNonQuery -Times 2 -Exactly
            Should -Invoke Update-HHVisualizerStateHead -Times 1 -Exactly
        }

        It 'returns absent and saved collection cursors' {
            Mock Invoke-HHSqliteQuery { @() }
            Get-HHForensicCollectionCursor -Connection ([pscustomobject]@{}) `
                -TargetNameKey ALPHA -SourceName source | Should -BeNullOrEmpty
            Mock Invoke-HHSqliteQuery {
                [pscustomobject]@{occurred_at_utc='2026-08-31T00:00:00Z';record_id='9'}
            }
            $cursor = Get-HHForensicCollectionCursor -Connection ([pscustomobject]@{}) `
                -TargetNameKey ALPHA -SourceName source
            $cursor.RecordId | Should -BeExactly '9'
            $cursor.OccurredAtUtc | Should -Be ([DateTimeOffset]'2026-08-31T00:00:00Z')
        }

        It 'decrypts pending evidence and rejects a plaintext digest mismatch' {
            $digest = Get-HHForensicPayloadDigest $script:payload
            Mock Invoke-HHSqliteQuery {
                [pscustomobject]@{
                    event_id=$script:eventId.ToByteArray();schema_name='process.start'
                    payload_envelope=[byte[]](1,2,3);content_sha256=$digest
                }
            }
            Mock Unprotect-HHPersistenceValue { [byte[]]$script:payload.Clone() }
            $pending = @(Read-HHPendingVisualizerForensicEvent `
                    -Connection ([pscustomobject]@{}) -MasterKey ([byte[]]::new(32)) `
                    -MissionId $script:missionId.ToByteArray())
            $pending[0].EventId | Should -Be $script:eventId

            Mock Invoke-HHSqliteQuery {
                [pscustomobject]@{
                    event_id=$script:eventId.ToByteArray();schema_name='process.start'
                    payload_envelope=[byte[]](1,2,3);content_sha256=('0' * 64)
                }
            }
            { Read-HHPendingVisualizerForensicEvent `
                    -Connection ([pscustomobject]@{}) -MasterKey ([byte[]]::new(32)) `
                    -MissionId $script:missionId.ToByteArray() } |
                Should -Throw '*plaintext digest check*'
        }

        It 'requires exactly one pending row when reconciling delivery' {
            Mock Invoke-HHSqliteNonQuery { 1 }
            Mock Update-HHVisualizerStateHead { 'updated' }
            Set-HHVisualizerForensicEventReconciled -Connection ([pscustomobject]@{}) `
                -Transaction ([pscustomobject]@{}) -MasterKey ([byte[]]::new(32)) `
                -CurrentSnapshot $script:snapshot -EventId $script:eventId.ToByteArray() `
                -ReconciledAtUtc '2026-08-31T00:00:00Z' |
                Should -BeExactly updated
            Mock Invoke-HHSqliteNonQuery { 0 }
            { Set-HHVisualizerForensicEventReconciled -Connection ([pscustomobject]@{}) `
                    -Transaction ([pscustomobject]@{}) -MasterKey ([byte[]]::new(32)) `
                    -CurrentSnapshot $script:snapshot -EventId $script:eventId.ToByteArray() `
                    -ReconciledAtUtc '2026-08-31T00:00:00Z' } |
                Should -Throw '*exactly one row*'
        }
    }
}
