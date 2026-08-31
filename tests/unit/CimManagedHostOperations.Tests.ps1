$sourceRoot = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
    Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration'
}
else { $env:HH_TEST_SOURCE_ROOT }
Import-Module (Join-Path $sourceRoot 'HostHunterNextGeneration.psd1') -Force

Describe 'CIM managed-host collection orchestration' -Tag Unit {
    InModuleScope HostHunterNextGeneration {
        BeforeEach {
            $script:missionId = [Guid]'11111111-1111-4111-8111-111111111111'
            $script:agentId = [Guid]'22222222-2222-4222-8222-222222222222'
            $script:target = [pscustomobject]@{
                Name = 'alpha'
                HostName = 'alpha.example'
                UserName = 'operator'
                IsActive = $true
                LastValidatedAtUtc = [DateTimeOffset]'2026-08-31T00:00:00Z'
            }
            $script:collection = [pscustomobject]@{
                Runtime = [pscustomobject]@{ DatabasePath = '/state/hosthunter.sqlite3' }
                Targets = @($script:target)
                MissionId = $script:missionId
                PublishingEnabled = $false
                AgentId = $script:agentId
                AgentVersion = '0.7.0'
            }
        }

        It 'loads an active mission and closes authenticated persistence' {
            $databasePath = Join-Path $TestDrive 'context/hosthunter.sqlite3'
            [IO.Directory]::CreateDirectory((Split-Path -Parent $databasePath)) | Out-Null
            [IO.File]::WriteAllBytes($databasePath, [byte[]](1))
            Mock Get-HHRuntimeContext { [pscustomobject]@{ DatabasePath = $databasePath } }
            Mock Open-HHAuthenticatedPersistence {
                [pscustomobject]@{
                    Connection = [pscustomobject]@{}
                    MasterKey = [byte[]]::new(32)
                    Anchor = [pscustomobject]@{ DatabaseId = $script:agentId.ToByteArray() }
                    VisualizerSnapshot = [pscustomobject]@{
                        CurrentMissionId = $script:missionId.ToByteArray()
                    }
                }
            }
            Mock Read-HHTargetRepositorySnapshot {
                [pscustomobject]@{ Targets = @($script:target) }
            }
            Mock Get-HHLatestVisualizerMissionRecord { $null }
            Mock Get-HHModuleVersionText { '0.7.0' }
            Mock Close-HHAuthenticatedPersistence {}

            $result = Get-HHForensicCollectionContext -Name alpha
            $result.MissionId | Should -Be $script:missionId
            $result.AgentId | Should -Be $script:agentId
            $result.PublishingEnabled | Should -BeTrue
            @($result.Targets).Count | Should -Be 1
            Should -Invoke Close-HHAuthenticatedPersistence -Times 1 -Exactly
        }

        It 'uses the latest stopped mission and rejects missing mission state' {
            $databasePath = Join-Path $TestDrive 'stopped/hosthunter.sqlite3'
            [IO.Directory]::CreateDirectory((Split-Path -Parent $databasePath)) | Out-Null
            [IO.File]::WriteAllBytes($databasePath, [byte[]](1))
            Mock Get-HHRuntimeContext { [pscustomobject]@{ DatabasePath = $databasePath } }
            Mock Open-HHAuthenticatedPersistence {
                [pscustomobject]@{
                    Connection = [pscustomobject]@{}
                    MasterKey = [byte[]]::new(32)
                    Anchor = [pscustomobject]@{ DatabaseId = $script:agentId.ToByteArray() }
                    VisualizerSnapshot = [pscustomobject]@{ CurrentMissionId = $null }
                }
            }
            Mock Read-HHTargetRepositorySnapshot {
                [pscustomobject]@{ Targets = @($script:target) }
            }
            Mock Get-HHLatestVisualizerMissionRecord {
                [pscustomobject]@{ MissionId = $script:missionId.ToByteArray() }
            }
            Mock Get-HHModuleVersionText { '0.7.0' }
            Mock Close-HHAuthenticatedPersistence {}

            $result = Get-HHForensicCollectionContext
            $result.MissionId | Should -Be $script:missionId
            $result.PublishingEnabled | Should -BeFalse

            Mock Get-HHLatestVisualizerMissionRecord { $null }
            { Get-HHForensicCollectionContext } | Should -Throw '*Start a HostHunter mission*'
        }

        It 'fails before persistence when no target database exists' {
            Mock Get-HHRuntimeContext {
                [pscustomobject]@{ DatabasePath = (Join-Path $TestDrive 'missing.sqlite3') }
            }
            Mock Open-HHAuthenticatedPersistence { throw 'must not open' }
            { Get-HHForensicCollectionContext } | Should -Throw '*No active HostHunter targets*'
            Should -Invoke Open-HHAuthenticatedPersistence -Times 0 -Exactly
        }

        It 'rejects a database with no active target and closes persistence' {
            $databasePath = Join-Path $TestDrive 'inactive/hosthunter.sqlite3'
            [IO.Directory]::CreateDirectory((Split-Path -Parent $databasePath)) | Out-Null
            [IO.File]::WriteAllBytes($databasePath, [byte[]](1))
            Mock Get-HHRuntimeContext { [pscustomobject]@{ DatabasePath = $databasePath } }
            Mock Open-HHAuthenticatedPersistence {
                [pscustomobject]@{
                    Connection=[pscustomobject]@{};MasterKey=[byte[]]::new(32)
                    Anchor=[pscustomobject]@{};VisualizerSnapshot=[pscustomobject]@{}
                }
            }
            Mock Read-HHTargetRepositorySnapshot {
                [pscustomobject]@{ Targets=@([pscustomobject]@{ IsActive=$false }) }
            }
            Mock Close-HHAuthenticatedPersistence {}
            { Get-HHForensicCollectionContext } | Should -Throw '*No active HostHunter targets*'
            Should -Invoke Close-HHAuthenticatedPersistence -Times 1 -Exactly
        }

        It 'rejects malformed forensic envelopes before persistence' {
            { Assert-HHForensicPayloadSchema -PayloadBytes ([byte[]](1)) } |
                Should -Throw '*payload size is invalid*'
            { Assert-HHForensicPayloadSchema -PayloadBytes ([byte[]](0xff,0xff)) } |
                Should -Throw '*valid UTF-8 JSON*'
            $unknown = [Text.Encoding]::UTF8.GetBytes(
                '{"event":{"id":"33333333-3333-4333-8333-333333333333"},' +
                '"hosthunter":{"schema":{"name":"unknown","version":"1.0.0"},' +
                '"collection_run":{"id":"11111111-1111-4111-8111-111111111111"},' +
                '"provenance":{"transport":"powershell7_over_ssh"}}}'
            )
            { Assert-HHForensicPayloadSchema -PayloadBytes $unknown } |
                Should -Throw '*is not registered*'
            $invalidId = [Text.Encoding]::UTF8.GetBytes(
                '{"event":{"id":"bad"},' +
                '"hosthunter":{"schema":{"name":"process.start","version":"1.0.0"},' +
                '"collection_run":{"id":"11111111-1111-4111-8111-111111111111"},' +
                '"provenance":{"transport":"powershell7_over_ssh"}}}'
            )
            { Assert-HHForensicPayloadSchema -PayloadBytes $invalidId } |
                Should -Throw '*identifiers are invalid*'
            $wrongTransport = [Text.Encoding]::UTF8.GetBytes(
                '{"event":{"id":"33333333-3333-4333-8333-333333333333"},' +
                '"hosthunter":{"schema":{"name":"process.start","version":"1.0.0"},' +
                '"collection_run":{"id":"11111111-1111-4111-8111-111111111111"},' +
                '"provenance":{"transport":"winrm"}}}'
            )
            { Assert-HHForensicPayloadSchema -PayloadBytes $wrongTransport } |
                Should -Throw '*managed PowerShell 7 over SSH*'
        }

        It 'checks visualizer mission identity only while publishing is active' {
            Mock Invoke-HHVisualizerStatus { [pscustomobject]@{ ActiveMissionId = $script:missionId } }
            Assert-HHForensicVisualizerCapability -Collection $script:collection
            Should -Invoke Invoke-HHVisualizerStatus -Times 0 -Exactly

            $script:collection.PublishingEnabled = $true
            { Assert-HHForensicVisualizerCapability -Collection $script:collection } |
                Should -Not -Throw
            Mock Invoke-HHVisualizerStatus {
                [pscustomobject]@{ ActiveMissionId = [Guid]::NewGuid() }
            }
            { Assert-HHForensicVisualizerCapability -Collection $script:collection } |
                Should -Throw '*mission state does not match*'
        }

        It 'resolves explicit, saved, validated, and fallback cursor positions' {
            $explicit = Get-HHForensicCursorPosition -Collection $script:collection `
                -Target $script:target -SourceName source `
                -ExplicitSince ([DateTimeOffset]'2026-08-31T01:00:00Z')
            $explicit.Since | Should -Be ([DateTimeOffset]'2026-08-31T01:00:00Z')
            $explicit.AfterRecordId | Should -BeNullOrEmpty

            Mock Open-HHAuthenticatedPersistence {
                [pscustomobject]@{ Connection = [pscustomobject]@{} }
            }
            Mock Close-HHAuthenticatedPersistence {}
            Mock Get-HHForensicCollectionCursor {
                [pscustomobject]@{
                    OccurredAtUtc = '2026-08-31T00:30:00Z'
                    RecordId = '42'
                }
            }
            $saved = Get-HHForensicCursorPosition -Collection $script:collection `
                -Target $script:target -SourceName source
            $saved.AfterRecordId | Should -Be 42

            Mock Get-HHForensicCollectionCursor { $null }
            $validated = Get-HHForensicCursorPosition -Collection $script:collection `
                -Target $script:target -SourceName source
            $validated.Since | Should -Be $script:target.LastValidatedAtUtc

            $targetWithoutValidation = $script:target.PSObject.Copy()
            $targetWithoutValidation.LastValidatedAtUtc = $null
            $fallback = Get-HHForensicCursorPosition -Collection $script:collection `
                -Target $targetWithoutValidation -SourceName source
            $fallback.Since | Should -BeLessThan ([DateTimeOffset]::UtcNow)
        }

        It 'rejects a malformed saved record identifier and still closes persistence' {
            Mock Open-HHAuthenticatedPersistence {
                [pscustomobject]@{ Connection = [pscustomobject]@{} }
            }
            Mock Close-HHAuthenticatedPersistence {}
            Mock Get-HHForensicCollectionCursor {
                [pscustomobject]@{ OccurredAtUtc = '2026-08-31T00:30:00Z'; RecordId = 'bad' }
            }
            { Get-HHForensicCursorPosition -Collection $script:collection `
                    -Target $script:target -SourceName source } |
                Should -Throw '*cursor is invalid*'
            Should -Invoke Close-HHAuthenticatedPersistence -Times 1 -Exactly
        }

        It 'attaches exactly one finite command output to a successful transport' {
            Mock Invoke-HHManagedHostCommandCoordinator {
                $transport = [pscustomobject]@{ Succeeded = $true }
                $commandResult = [pscustomobject]@{
                    StreamEvents = @([pscustomobject]@{
                            Phase = 'Command'; Stream = 'Output'; Value = 'payload'
                        })
                }
                @(& $TransportResultAugmenter $script:target $transport $commandResult)
            }
            $result = Invoke-HHForensicRemoteCollection -Target $script:target `
                -Operation GetProcessStartEvents -Command collect -RemoteScriptBlock { 'remote' }
            $result.ForensicRaw | Should -BeExactly payload
        }

        It 'preserves failed transport and rejects ambiguous finite output' {
            Mock Invoke-HHManagedHostCommandCoordinator {
                $transport = [pscustomobject]@{ Succeeded = $false }
                @(& $TransportResultAugmenter $script:target $transport ([pscustomobject]@{
                            StreamEvents = @()
                        }))
            }
            (Invoke-HHForensicRemoteCollection -Target $script:target `
                    -Operation GetProcessStartEvents -Command collect `
                    -RemoteScriptBlock { 'remote' }).Succeeded | Should -BeFalse

            Mock Invoke-HHManagedHostCommandCoordinator {
                $transport = [pscustomobject]@{ Succeeded = $true }
                & $TransportResultAugmenter $script:target $transport ([pscustomobject]@{
                        StreamEvents = @()
                    })
            }
            { Invoke-HHForensicRemoteCollection -Target $script:target `
                    -Operation GetProcessStartEvents -Command collect `
                    -RemoteScriptBlock { 'remote' } } | Should -Throw '*invalid finite result*'
        }

        It 'builds deterministic identities for every forensic source kind' {
            $security = Get-HHForensicSourceIdentity -Kind Security -HostName host -Raw (
                [pscustomobject]@{ EventId=4688;Version=2;RecordId=9;TimeCreated='2026-08-31T00:00:00Z' }
            )
            $security.Channel | Should -BeExactly Security
            $token = Get-HHForensicSourceIdentity -Kind ProcessToken -HostName host -Raw (
                [pscustomobject]@{ ProcessId=10;ObservedAtUtc='2026-08-31T00:00:00Z' }
            )
            $token.RecordId | Should -Match '^host:10:'
            $rights = Get-HHForensicSourceIdentity -Kind EffectiveRights -HostName host -Raw (
                [pscustomobject]@{
                    ObservedAtUtc='2026-08-31T00:00:00Z'
                    User=[pscustomobject]@{ Id='S-1-5-18' }
                }
            )
            $rights.RecordId | Should -Match '^host:S-1-5-18:'
        }

        It 'returns transport and empty-envelope results without opening a writer' {
            Mock Open-HHAuthenticatedPersistence { throw 'must not open' }
            $failed = [pscustomobject]@{ Succeeded = $false }
            (Save-HHForensicTransportResult -Collection $script:collection `
                    -Target $script:target -Transport $failed -Kind Security) |
                Should -Be $failed
            $empty = [pscustomobject]@{
                Succeeded = $true
                ForensicRaw = [pscustomobject]@{
                    Status='complete';Records=@();Issues=@();HasMore=$false
                }
            }
            $result = Save-HHForensicTransportResult -Collection $script:collection `
                -Target $script:target -Transport $empty -Kind Security
            @($result.Events).Count | Should -Be 0
            Should -Invoke Open-HHAuthenticatedPersistence -Times 0 -Exactly
        }

        It 'stores, deduplicates, and reports each normalized event kind' -TestCases @(
            @{ Kind='Security'; Publishing=$false; Created=$true; Expected='Paused'; Cursor=$true }
            @{ Kind='ProcessToken'; Publishing=$true; Created=$true; Expected='Enabled'; Cursor=$false }
            @{ Kind='EffectiveRights'; Publishing=$true; Created=$false; Expected='Enabled'; Cursor=$false }
        ) {
            param($Kind, $Publishing, $Created, $Expected, $Cursor)
            $script:collection.PublishingEnabled = $Publishing
            $script:created = $Created
            $script:payloadSchema = switch ($Kind) {
                Security { 'process.start' }
                ProcessToken { 'process.access-token' }
                EffectiveRights { 'user.effective-rights' }
            }
            $raw = [pscustomobject]@{
                EventId=4688;Version=2;RecordId=9;ProcessId=10
                TimeCreated=[DateTimeOffset]'2026-08-31T00:00:00Z'
                ObservedAtUtc=[DateTimeOffset]'2026-08-31T00:00:00Z'
                User=[pscustomobject]@{ Id='S-1-5-18' }
            }
            $transport = [pscustomobject]@{
                Succeeded=$true
                ForensicRaw=[pscustomobject]@{
                    Status='complete';ObservedAtUtc=[DateTimeOffset]'2026-08-31T00:00:01Z'
                    Records=@($raw);Issues=@();HasMore=$true
                }
            }
            Mock Open-HHAuthenticatedPersistence {
                [pscustomobject]@{
                    Connection=[pscustomobject]@{}
                    MasterKey=[byte[]]::new(32)
                    VisualizerSnapshot=[pscustomobject]@{}
                }
            }
            Mock Close-HHAuthenticatedPersistence {}
            Mock Resolve-HHVisualizerEndpointIdentity {
                [pscustomobject]@{ EndpointId='hh_endpoint';TargetNameKey='ALPHA' }
            }
            Mock New-HHForensicEventIdentity {
                [Guid]'33333333-3333-4333-8333-333333333333'
            }
            Mock ConvertTo-HHSecurityEventRecord {
                [pscustomobject]@{ hosthunter=[pscustomobject]@{ schema=[pscustomobject]@{ name=$script:payloadSchema } } }
            }
            Mock ConvertTo-HHProcessTokenRecord {
                [pscustomobject]@{ hosthunter=[pscustomobject]@{ schema=[pscustomobject]@{ name=$script:payloadSchema } } }
            }
            Mock Resolve-HHEffectiveRightsRecord {
                [pscustomobject]@{ hosthunter=[pscustomobject]@{ schema=[pscustomobject]@{ name=$script:payloadSchema } } }
            }
            Mock Assert-HHForensicPayloadSchema {}
            Mock Add-HHVisualizerForensicEventBatch {
                @($ForensicEvent | ForEach-Object {
                        [pscustomobject]@{ Created=$script:created }
                    })
            }
            Mock Invoke-HHAnchoredPersistenceTransaction {
                & $Action ([pscustomobject]@{}) ([pscustomobject]@{}) (
                    [pscustomobject]@{
                        MasterKey=[byte[]]::new(32)
                        VisualizerSnapshot=[pscustomobject]@{}
                    }
                ) $ArgumentList
            }
            Mock Send-HHVisualizerForensicEvent {
                [pscustomobject]@{ Delivered=$true;StatusCode=202;FailureKind=$null }
            }
            Mock Set-HHVisualizerDeliveryResult {}
            $cursorValue = if ($Cursor) {
                [pscustomobject]@{
                    SourceName='source';OccurredAtUtc='2026-08-31T00:00:00Z';RecordId='9'
                }
            }
            else { $null }

            $result = @(Save-HHForensicTransportResult -Collection $script:collection `
                    -Target $script:target -Transport $transport -Kind $Kind `
                    -Cursor $cursorValue)
            $result.Count | Should -Be 1
            $result[0].VisualizerPublishingState | Should -BeExactly $Expected
            $result[0].CollectionHasMore | Should -BeTrue
            if ($Publishing -and $Created) {
                $result[0].VisualizerDelivered | Should -BeTrue
                Should -Invoke Set-HHVisualizerDeliveryResult -Times 1 -Exactly
            }
            else {
                $result[0].VisualizerDelivered | Should -BeFalse
            }
        }

        It 'routes every bounded Security collection with its correct event set' -TestCases @(
            @{ Operation='GetProcessStartEvents'; Source='windows.security.process-start'; ExpectedEventId='4688' }
            @{ Operation='GetProcessEndEvents'; Source='windows.security.process-end'; ExpectedEventId='4689' }
            @{ Operation='GetAuthenticationEvents'; Source='windows.security.authentication'; ExpectedEventId='4624' }
        ) {
            param($Operation, $Source, $ExpectedEventId)
            Mock Get-HHForensicCollectionContext { $script:collection }
            Mock Assert-HHForensicVisualizerCapability {}
            Mock Get-HHForensicCursorPosition {
                [pscustomobject]@{ Since='2026-08-31T00:00:00Z';AfterRecordId=8L }
            }
            Mock Get-HHWindowsSecurityEventsRemoteScriptBlock { { 'remote' } }
            Mock Invoke-HHForensicRemoteCollection {
                $script:observedSecurityFilter = $RemoteArgumentList[0]
                [pscustomobject]@{
                    Succeeded=$true
                    ForensicRaw=[pscustomobject]@{
                        Records=@([pscustomobject]@{
                                RecordId=9L;TimeCreated='2026-08-31T00:01:00Z'
                            })
                    }
                }
            }
            Mock Save-HHForensicTransportResult { $Cursor.SourceName }

            Invoke-HHManagedHostSecurityEventOperation -Operation $Operation |
                Should -BeExactly $Source
            Should -Invoke Invoke-HHForensicRemoteCollection -Times 1 -Exactly
            $script:observedSecurityFilter | Should -Match "EventID=$ExpectedEventId"
        }

        It 'covers empty failed Security results and the thin operation wrappers' {
            Mock Get-HHForensicCollectionContext { $script:collection }
            Mock Assert-HHForensicVisualizerCapability {}
            Mock Get-HHForensicCursorPosition {
                [pscustomobject]@{ Since='2026-08-31T00:00:00Z';AfterRecordId=$null }
            }
            Mock Get-HHWindowsSecurityEventsRemoteScriptBlock { { 'remote' } }
            Mock Invoke-HHForensicRemoteCollection { [pscustomobject]@{ Succeeded=$false } }
            Mock Save-HHForensicTransportResult { $Transport }

            $failed = @(Invoke-HHManagedHostSecurityEventOperation `
                    -Operation GetProcessStartEvents `
                    -Since '2026-08-31T00:00:00Z' -Until '2026-08-31T01:00:00Z')
            $failed.Count | Should -Be 1
            $failed[0].Succeeded | Should -BeFalse

            Mock Invoke-HHManagedHostSecurityEventOperation { $Operation }
            Invoke-HHManagedHostGetProcessStartEventsOperation |
                Should -BeExactly GetProcessStartEvents
            Invoke-HHManagedHostGetAuthenticationEventsOperation |
                Should -BeExactly GetAuthenticationEvents
        }

        It 'routes process-token selectors and effective-right identities' {
            Mock Get-HHForensicCollectionContext { $script:collection }
            Mock Assert-HHForensicVisualizerCapability {}
            Mock Get-HHWindowsProcessTokenRemoteScriptBlock { { 'token' } }
            Mock Get-HHWindowsEffectiveRightsRemoteScriptBlock { { 'rights' } }
            Mock Invoke-HHForensicRemoteCollection {
                [pscustomobject]@{ Succeeded=$false }
            }
            Mock Save-HHForensicTransportResult { "${Kind}:$($Target.Name)" }

            Invoke-HHManagedHostGetProcessAccessTokenOperation -ProcessId 10 |
                Should -BeExactly 'ProcessToken:alpha'
            Invoke-HHManagedHostGetProcessAccessTokenOperation -ProcessName pwsh.exe |
                Should -BeExactly 'ProcessToken:alpha'
            Invoke-HHManagedHostGetUserEffectiveRightsOperation |
                Should -BeExactly 'EffectiveRights:alpha'
            Invoke-HHManagedHostGetUserEffectiveRightsOperation -Identity 'LAB\alice' |
                Should -BeExactly 'EffectiveRights:alpha'
            Should -Invoke Invoke-HHForensicRemoteCollection -Times 4 -Exactly
        }

        It 'returns finite unsupported records from each remote factory on Linux' {
            $security = & (Get-HHWindowsSecurityEventsRemoteScriptBlock) '*' 1
            $token = & (Get-HHWindowsProcessTokenRemoteScriptBlock) ProcessId @(1)
            $rights = & (Get-HHWindowsEffectiveRightsRemoteScriptBlock) 'operator'
            $security.Status | Should -BeExactly unsupported
            $token.Status | Should -BeExactly unsupported
            $rights.Status | Should -BeExactly unsupported
            @($security.Records).Count | Should -Be 0
        }
    }
}
