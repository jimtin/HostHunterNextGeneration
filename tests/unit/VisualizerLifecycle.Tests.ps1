$sourceRoot = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
    Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration'
} else { $env:HH_TEST_SOURCE_ROOT }
Import-Module (Join-Path $sourceRoot 'HostHunterNextGeneration.psd1') -Force
if ([IO.Directory]::Exists('/opt/hosthunter-sqlite/lib')) {
    $env:HH_SQLITE_PROVIDER_ROOT='/opt/hosthunter-sqlite/lib'
}

Describe 'visualization mission lifecycle' -Tag Unit {
    It 'starts, continues, pauses, resumes, recovers, prunes selection, and replays pending observations' {
        InModuleScope HostHunterNextGeneration {
            $previousDataRoot = $env:HH_DATA_ROOT
            $previousProvider = $env:HH_SECRET_PROVIDER
            $env:HH_DATA_ROOT = Join-Path $TestDrive 'lifecycle-state'
            $env:HH_SECRET_PROVIDER = $null
            $script:activeMission = $null
            $script:missionDeliveryMode = 'success'
            $script:observationAttempts = 0
            $script:missionSelectedBeforeAcceptance = $false
            $statusSender = {
                param($Path)
                $Path | Should -BeExactly '/api/v1/producer/status'
                [pscustomobject]@{
                    status='ready'; service='hosthunter-visualizer'; api_version='1.0.0'
                    collection_run_schema_version='1.0.0'
                    host_observation_schema_version='1.0.0'
                    process_event_schema_version=$null
                    active_collection_run_id=if($null -eq $script:activeMission){$null}else{$script:activeMission.ToString('D')}
                }
            }
            $producerSender = {
                param($Path,$Payload,$Digest)
                $null = $Payload
                $Digest | Should -Match '^[a-f0-9]{64}$'
                if ($Path -match '/host-observations/') {
                    $script:observationAttempts++
                    return [pscustomobject]@{Delivered=$true;StatusCode=201;ContentSha256=$Digest}
                }
                $idText = @($Path -split '/')[-1]
                $requested = [Guid]::Parse($idText)
                if ((Get-HHLocalMissionState).CurrentMissionId -eq $requested) {
                    $script:missionSelectedBeforeAcceptance = $true
                }
                if ($script:missionDeliveryMode -ceq 'failure') {
                    return [pscustomobject]@{Delivered=$false;StatusCode=503;ContentSha256=$Digest}
                }
                if ($script:missionDeliveryMode -ceq 'lost-response') {
                    $script:activeMission = $requested
                    return [pscustomobject]@{Delivered=$false;StatusCode=$null;ContentSha256=$Digest}
                }
                $script:activeMission = $requested
                [pscustomobject]@{Delivered=$true;StatusCode=201;ContentSha256=$Digest}
            }
            try {
                $first = Invoke-HHVisualizationLifecycleCore -Action start `
                    -StatusSender $statusSender -ProducerSender $producerSender
                $first.Status | Should -BeExactly started
                $first.CreatedNewMission | Should -BeTrue
                $first.MissionId | Should -Be $script:activeMission
                $first.PendingObservations | Should -Be 0
                $script:missionSelectedBeforeAcceptance | Should -BeFalse

                $status = Invoke-HHVisualizationLifecycleCore -Action status -StatusSender $statusSender
                $status.PublishingState | Should -BeExactly Enabled
                $status.Connection | Should -BeExactly authenticated
                $continued = Invoke-HHVisualizationLifecycleCore -Action start `
                    -StatusSender $statusSender -ProducerSender $producerSender
                $continued.Status | Should -BeExactly continued
                $continued.MissionId | Should -Be $first.MissionId

                $paused = Invoke-HHVisualizationLifecycleCore -Action pause
                $paused.PublishingState | Should -BeExactly Paused
                (Get-HHLocalMissionState).CurrentMissionId | Should -BeNullOrEmpty
                $resumed = Invoke-HHVisualizationLifecycleCore -Action start `
                    -StatusSender $statusSender -ProducerSender $producerSender
                $resumed.Status | Should -BeExactly continued
                $resumed.MissionId | Should -Be $first.MissionId

                $prior = $resumed.MissionId
                $script:missionDeliveryMode = 'failure'
                { Invoke-HHVisualizationLifecycleCore -Action new `
                        -StatusSender $statusSender -ProducerSender $producerSender } |
                    Should -Throw '*prior mission remains selected*'
                (Get-HHLocalMissionState).CurrentMissionId | Should -Be $prior

                $script:missionDeliveryMode = 'lost-response'
                { Invoke-HHVisualizationLifecycleCore -Action new `
                        -StatusSender $statusSender -ProducerSender $producerSender } |
                    Should -Throw '*prior mission remains selected*'
                $lostResponseMission = (Get-HHLocalMissionState).LatestMissionId
                $lostResponseMission | Should -Be $script:activeMission
                (Get-HHLocalMissionState).CurrentMissionId | Should -Be $prior
                $recovered = Invoke-HHVisualizationLifecycleCore -Action start `
                    -StatusSender $statusSender -ProducerSender $producerSender
                $recovered.MissionId | Should -Be $lostResponseMission
                (Get-HHLocalMissionState).CurrentMissionId | Should -Be $lostResponseMission

                $runtime = Get-HHRuntimeContext
                $write = Open-HHAuthenticatedPersistence -PersistenceContext $runtime `
                    -OperationLock -AllowAnchorAdvance
                try {
                    $observationId = [Guid]::NewGuid().ToByteArray()
                    $payload = [Text.Encoding]::UTF8.GetBytes('{"schema_version":"1.0.0"}')
                    $data = [pscustomobject]@{
                        Event=$observationId; Mission=$lostResponseMission.ToByteArray()
                        Payload=$payload; At=[DateTimeOffset]::UtcNow
                    }
                    Invoke-HHAnchoredPersistenceTransaction -Context $write -ArgumentList @($data) -Action {
                        param($Connection,$Transaction,$WriterContext,$ArgumentList);$d=$ArgumentList[0]
                        Add-HHVisualizerHostObservation -Connection $Connection -Transaction $Transaction `
                            -MasterKey $WriterContext.MasterKey -CurrentSnapshot $WriterContext.VisualizerSnapshot `
                            -EventId $d.Event -MissionId $d.Mission -TargetNameKey DEMO `
                            -EndpointId ('hh_'+('a'*52)) -ObservedAtUtc $d.At -PayloadBytes $d.Payload
                    } | Out-Null
                    Invoke-HHAnchoredPersistenceTransaction -Context $write -ArgumentList @($data) -Action {
                        param($Connection,$Transaction,$WriterContext,$ArgumentList);$d=$ArgumentList[0]
                        Set-HHVisualizerDeliveryResult -Connection $Connection -Transaction $Transaction `
                            -MasterKey $WriterContext.MasterKey -CurrentSnapshot $WriterContext.VisualizerSnapshot `
                            -Kind Observation -Id $d.Event -Delivered $false -StatusCode 503 `
                            -AttemptedAtUtc $d.At
                    } | Out-Null
                }
                finally { Close-HHAuthenticatedPersistence -Context $write }
                $script:missionDeliveryMode = 'success'
                $replayed = Invoke-HHVisualizationLifecycleCore -Action start `
                    -StatusSender $statusSender -ProducerSender $producerSender
                $replayed.ReplayedObservations | Should -Be 1
                $replayed.PendingObservations | Should -Be 0
                $script:observationAttempts | Should -Be 1

                $script:activeMission = [Guid]::NewGuid()
                { Invoke-HHVisualizationLifecycleCore -Action start `
                        -StatusSender $statusSender -ProducerSender $producerSender } |
                    Should -Throw '*Refusing to guess or overwrite*'
            }
            finally {
                $env:HH_DATA_ROOT = $previousDataRoot
                $env:HH_SECRET_PROVIDER = $previousProvider
            }
        }
    }
}
