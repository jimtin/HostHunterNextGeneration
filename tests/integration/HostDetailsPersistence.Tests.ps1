$sourceRoot = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
    Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration'
} else { $env:HH_TEST_SOURCE_ROOT }
Import-Module (Join-Path $sourceRoot 'HostHunterNextGeneration.psd1') -Force
if ([IO.Directory]::Exists('/opt/hosthunter-sqlite/lib')) {
    $env:HH_SQLITE_PROVIDER_ROOT='/opt/hosthunter-sqlite/lib'
}

Describe 'authenticated host-details persistence' -Tag Integration {
    It 'builds schema v5 from migrations and stores observations encrypted and rollback sealed' {
        InModuleScope HostHunterNextGeneration {
            $root=Join-Path $TestDrive 'host-details-state'
            $runtime=Get-HHPersistenceContext -DataRoot $root
            $key=[byte[]](0..31)
            $schema=Initialize-HHSqliteDatabase -PersistenceContext $runtime -MasterKey $key
            $schema.SchemaVersion | Should -Be 5
            $provider={param($Context,$Exists);$null=$Context,$Exists;[byte[]](0..31)}
            $context=Open-HHAuthenticatedPersistence -PersistenceContext $runtime `
                -MasterKeyProvider $provider -OperationLock -AllowAnchorAdvance
            try {
                $mission=[Guid]::NewGuid().ToByteArray()
                $observationId=[Guid]::NewGuid().ToByteArray()
                $started=[DateTimeOffset]'2026-08-28T00:00:00Z'
                $missionPayload=[Text.Encoding]::UTF8.GetBytes('{"schema_version":"1.0.0"}')
                Invoke-HHAnchoredPersistenceTransaction -Context $context -ArgumentList @(
                    [pscustomobject]@{Mission=$mission;Started=$started;Payload=$missionPayload}
                ) -Action {
                    param($Connection,$Transaction,$WriterContext,$ArgumentList);$d=$ArgumentList[0]
                    Add-HHVisualizerMission -Connection $Connection -Transaction $Transaction `
                        -MasterKey $WriterContext.MasterKey -CurrentSnapshot $WriterContext.VisualizerSnapshot `
                        -MissionId $d.Mission -StartedAtUtc $d.Started -PayloadBytes $d.Payload
                } | Out-Null
                $marker='HH-SENSITIVE-HOST-DETAIL-MARKER'
                $payload=[Text.Encoding]::UTF8.GetBytes("{`"host`":`"$marker`"}")
                Invoke-HHAnchoredPersistenceTransaction -Context $context -ArgumentList @(
                    [pscustomobject]@{
                        Mission=$mission;Event=$observationId;At=$started;Payload=$payload
                    }
                ) -Action {
                    param($Connection,$Transaction,$WriterContext,$ArgumentList);$d=$ArgumentList[0]
                    $identity=Resolve-HHVisualizerEndpointIdentity -Connection $Connection -Transaction $Transaction `
                        -MasterKey $WriterContext.MasterKey -TargetName alpha `
                        -NativeIdentityDigest ('a'*64) -ObservedAtUtc $d.At
                    Add-HHVisualizerHostObservation -Connection $Connection -Transaction $Transaction `
                        -MasterKey $WriterContext.MasterKey -CurrentSnapshot $WriterContext.VisualizerSnapshot `
                        -EventId $d.Event -MissionId $d.Mission -TargetNameKey $identity.TargetNameKey `
                        -EndpointId $identity.EndpointId -ObservedAtUtc $d.At -PayloadBytes $d.Payload
                } | Out-Null
                Invoke-HHAnchoredPersistenceTransaction -Context $context -ArgumentList @(
                    [pscustomobject]@{Event=$observationId;At=$started.AddSeconds(1)}
                ) -Action {
                    param($Connection,$Transaction,$WriterContext,$ArgumentList);$d=$ArgumentList[0]
                    Set-HHVisualizerDeliveryResult -Connection $Connection -Transaction $Transaction `
                        -MasterKey $WriterContext.MasterKey -CurrentSnapshot $WriterContext.VisualizerSnapshot `
                        -Kind Observation -Id $d.Event -Delivered $false -StatusCode 503 `
                        -AttemptedAtUtc $d.At
                } | Should -BeTrue
                $delivery = @(Invoke-HHSqliteQuery -Connection $context.Connection -Sql `
                    'SELECT delivery_status,delivery_attempts FROM visualizer_host_observations WHERE event_id=@id;' `
                    -Parameters @{id=$observationId})
                $delivery[0].delivery_status | Should -BeExactly Pending
                $delivery[0].delivery_attempts | Should -Be 1
                $pending = @(Read-HHPendingVisualizerObservations `
                    -Connection $context.Connection -Transaction $null `
                    -MasterKey $context.MasterKey -MissionId $mission)
                $pending.Count | Should -Be 1
                [Text.Encoding]::UTF8.GetString([byte[]]$pending[0].PayloadBytes) |
                    Should -Match $marker
                Invoke-HHAnchoredPersistenceTransaction -Context $context -ArgumentList @(
                    [pscustomobject]@{Event=$observationId;At=$started.AddSeconds(1)}
                ) -Action {
                    param($Connection,$Transaction,$WriterContext,$ArgumentList);$d=$ArgumentList[0]
                    Set-HHVisualizerObservationReconciled -Connection $Connection -Transaction $Transaction `
                        -MasterKey $WriterContext.MasterKey -CurrentSnapshot $WriterContext.VisualizerSnapshot `
                        -EventId $d.Event -ReconciledAtUtc $d.At
                } | Out-Null
                [Array]::Clear([byte[]]$pending[0].PayloadBytes,0,([byte[]]$pending[0].PayloadBytes).Length)
                Invoke-HHAnchoredPersistenceTransaction -Context $context -ArgumentList @(
                    [pscustomobject]@{Mission=$mission;At=$started.AddSeconds(2)}
                ) -Action {
                    param($Connection,$Transaction,$WriterContext,$ArgumentList);$d=$ArgumentList[0]
                    Set-HHVisualizerDeliveryResult -Connection $Connection -Transaction $Transaction `
                        -MasterKey $WriterContext.MasterKey -CurrentSnapshot $WriterContext.VisualizerSnapshot `
                        -Kind Mission -Id $d.Mission -Delivered $false -StatusCode 503 `
                        -AttemptedAtUtc $d.At
                } | Should -BeTrue
                Invoke-HHAnchoredPersistenceTransaction -Context $context -Action {
                    param($Connection,$Transaction,$WriterContext)
                    Set-HHVisualizerCurrentMission -Connection $Connection -Transaction $Transaction `
                        -MasterKey $WriterContext.MasterKey -CurrentSnapshot $WriterContext.VisualizerSnapshot `
                        -MissionId $null
                } | Out-Null
                $context.VisualizerSnapshot.CurrentMissionId | Should -BeNullOrEmpty
                Invoke-HHAnchoredPersistenceTransaction -Context $context -ArgumentList @(
                    [pscustomobject]@{Mission=$mission;At=$started.AddSeconds(3)}
                ) -Action {
                    param($Connection,$Transaction,$WriterContext,$ArgumentList);$d=$ArgumentList[0]
                    Set-HHVisualizerMissionReconciled -Connection $Connection -Transaction $Transaction `
                        -MasterKey $WriterContext.MasterKey -CurrentSnapshot $WriterContext.VisualizerSnapshot `
                        -MissionId $d.Mission -ReconciledAtUtc $d.At
                } | Out-Null
                ([Guid]::new([byte[]]$context.VisualizerSnapshot.CurrentMissionId)).ToString('D') |
                    Should -BeExactly ([Guid]::new($mission)).ToString('D')
                $missionDelivery = @(Invoke-HHSqliteQuery -Connection $context.Connection -Sql `
                    'SELECT delivery_status,delivery_attempts FROM visualizer_missions WHERE mission_id=@id;' `
                    -Parameters @{id=$mission})
                $missionDelivery[0].delivery_status | Should -BeExactly Delivered
                $missionDelivery[0].delivery_attempts | Should -Be 1
                $context.VisualizerSnapshot.Generation | Should -Be 7
            }
            finally {Close-HHAuthenticatedPersistence -Context $context}
            $databaseBytes=[IO.File]::ReadAllBytes($runtime.DatabasePath)
            [Text.Encoding]::UTF8.GetString($databaseBytes) | Should -Not -Match $marker
            $reopened=Open-HHAuthenticatedPersistence -PersistenceContext $runtime -MasterKeyProvider $provider
            try{$reopened.VisualizerSnapshot.Generation | Should -Be 7}
            finally{Close-HHAuthenticatedPersistence -Context $reopened}
        }
    }
}
