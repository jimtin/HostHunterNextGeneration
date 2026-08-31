$sourceRoot = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
    Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration'
}
else { $env:HH_TEST_SOURCE_ROOT }
Import-Module (Join-Path $sourceRoot 'HostHunterNextGeneration.psd1') -Force
if([IO.Directory]::Exists('/opt/hosthunter-sqlite/lib')){
    $env:HH_SQLITE_PROVIDER_ROOT='/opt/hosthunter-sqlite/lib'
}

Describe 'authenticated forensic-event persistence' -Tag Integration {
    It 'builds a fresh schema v5 and atomically stores encrypted evidence with its cursor' {
        InModuleScope HostHunterNextGeneration {
            $root=Join-Path $TestDrive forensic-state
            $runtime=Get-HHPersistenceContext -DataRoot $root
            $key=[byte[]](0..31)
            $schema=Initialize-HHSqliteDatabase `
                -PersistenceContext $runtime -MasterKey $key
            $schema.SchemaVersion|Should -Be 5
            $provider={
                param($Context,$Exists)
                $null=$Context,$Exists
                [byte[]](0..31)
            }
            $context=Open-HHAuthenticatedPersistence `
                -PersistenceContext $runtime -MasterKeyProvider $provider `
                -OperationLock -AllowAnchorAdvance
            try{
                $mission=[Guid]::NewGuid()
                $at=[DateTimeOffset]'2026-08-29T01:00:00Z'
                $missionPayload=[Text.Encoding]::UTF8.GetBytes(
                    '{"schema_version":"1.0.0"}'
                )
                Invoke-HHAnchoredPersistenceTransaction `
                    -Context $context `
                    -ArgumentList @([pscustomobject]@{
                            Id=$mission.ToByteArray();At=$at;Payload=$missionPayload
                        }) `
                    -Action {
                        param($Connection,$Transaction,$WriterContext,$ArgumentList)
                        $missionData=$ArgumentList[0]
                        Add-HHVisualizerMission -Connection $Connection `
                            -Transaction $Transaction `
                            -MasterKey $WriterContext.MasterKey `
                            -CurrentSnapshot $WriterContext.VisualizerSnapshot `
                            -MissionId $missionData.Id -StartedAtUtc $missionData.At `
                            -PayloadBytes $missionData.Payload
                    } | Out-Null
                $marker='HH_FORENSIC_SECRET_COMMANDLINE_CANARY'
                $payload=[Text.UTF8Encoding]::new($false).GetBytes(
                    "{`"command_line`":`"pwsh.exe -Password $marker`"}"
                )
                $eventId=[Guid]::NewGuid()
                $forensicEvent=[pscustomobject]@{
                    EventId=$eventId
                    MissionId=$mission
                    TargetNameKey='ALPHA'
                    EndpointId='hh_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                    SchemaName='process.start'
                    OccurredAtUtc=$at
                    CollectedAtUtc=$at.AddSeconds(1)
                    PayloadBytes=$payload
                }
                $cursor=[pscustomobject]@{
                    TargetNameKey='ALPHA'
                    SourceName='windows.security.process-start'
                    OccurredAtUtc=$at
                    RecordId='2814'
                }
                $stored=Invoke-HHAnchoredPersistenceTransaction `
                    -Context $context `
                    -ArgumentList @([pscustomobject]@{
                            Event=$forensicEvent;Cursor=$cursor
                        }) `
                    -Action {
                        param($Connection,$Transaction,$WriterContext,$ArgumentList)
                        $eventData=$ArgumentList[0]
                        @(Add-HHVisualizerForensicEventBatch `
                                -Connection $Connection -Transaction $Transaction `
                                -MasterKey $WriterContext.MasterKey `
                                -CurrentSnapshot $WriterContext.VisualizerSnapshot `
                                -ForensicEvent @($eventData.Event) `
                                -Cursor $eventData.Cursor)
                    }
                @($stored).Count|Should -Be 1
                @($stored)[0].Created|Should -BeTrue
                $pending=@(Read-HHPendingVisualizerForensicEvent `
                        -Connection $context.Connection -Transaction $null `
                        -MasterKey $context.MasterKey `
                        -MissionId $mission.ToByteArray())
                $pending.Count|Should -Be 1
                [Text.Encoding]::UTF8.GetString(
                    [byte[]]$pending[0].PayloadBytes
                ) | Should -Match $marker
                $savedCursor=Get-HHForensicCollectionCursor `
                    -Connection $context.Connection -Transaction $null `
                    -TargetNameKey ALPHA `
                    -SourceName windows.security.process-start
                $savedCursor.RecordId|Should -BeExactly '2814'
                {
                    Invoke-HHSqliteNonQuery -Connection $context.Connection `
                        -Sql 'DELETE FROM visualizer_forensic_events;'
                } | Should -Throw '*retained evidence*'
                [Array]::Clear(
                    [byte[]]$pending[0].PayloadBytes,
                    0,
                    ([byte[]]$pending[0].PayloadBytes).Length
                )
            }finally{
                Close-HHAuthenticatedPersistence -Context $context
            }
            [Text.Encoding]::UTF8.GetString(
                [IO.File]::ReadAllBytes($runtime.DatabasePath)
            ) | Should -Not -Match $marker
            $reopened=Open-HHAuthenticatedPersistence `
                -PersistenceContext $runtime -MasterKeyProvider $provider
            try{
                $reopened.VisualizerSnapshot.IntegrityVerified|Should -BeTrue
            }
            finally{
                Close-HHAuthenticatedPersistence -Context $reopened
            }
        }
    }
}
