$sourceRoot = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
    Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration'
} else { $env:HH_TEST_SOURCE_ROOT }
Import-Module (Join-Path $sourceRoot 'HostHunterNextGeneration.psd1') -Force
if ([IO.Directory]::Exists('/opt/hosthunter-sqlite/lib')) {
    $env:HH_SQLITE_PROVIDER_ROOT='/opt/hosthunter-sqlite/lib'
}
$script:hostDetailsSourceRoot=$sourceRoot

Describe 'host details and mission public contract' -Tag Unit {
    It 'packages the canonical host observation schema without drift' {
        $canonical=Join-Path (Get-Location) 'CIM_Specification/schemas/host-details-observation.v1.schema.json'
        $packaged=Join-Path (Get-Location) 'src/HostHunterNextGeneration/Private/Schemas/host-details-observation.v1.schema.json'
        (Get-FileHash $packaged -Algorithm SHA256).Hash |
            Should -BeExactly (Get-FileHash $canonical -Algorithm SHA256).Hash
    }

    It 'delegates selected host details through the managed-host engine exactly once' {
        InModuleScope HostHunterNextGeneration {
            Mock Invoke-HHManagedHostOperation { 'delegated' }
            Get-TargetHostDetails -Name alpha,beta -ThrottleLimit 2 | Should -BeExactly delegated
            Should -Invoke Invoke-HHManagedHostOperation -Times 1 -Exactly -ParameterFilter {
                $Operation -ceq 'GetHostDetails' -and
                @($Arguments.Name).Count -eq 2 -and $Arguments.ThrottleLimit -eq 2
            }
        }
    }

    It 'delegates the all-active form without manufacturing a target list' {
        InModuleScope HostHunterNextGeneration {
            Mock Invoke-HHManagedHostOperation { $Arguments.ContainsKey('Name') }
            Get-TargetHostDetails | Should -BeFalse
            Should -Invoke Invoke-HHManagedHostOperation -Times 1 -Exactly
        }
    }

    It 'keeps host details in both audit operation allowlists' {
        InModuleScope HostHunterNextGeneration {
            foreach ($commandName in @(
                    'Register-HHSqliteAuditBatch',
                    'Get-HHAuditRecord'
                )) {
                $command = Get-Command $commandName
                $attribute = @($command.Parameters.Operation.Attributes | Where-Object {
                        $_ -is [Management.Automation.ValidateSetAttribute]
                    })
                $attribute.Count | Should -Be 1
                $attribute[0].ValidValues | Should -Contain 'GetHostDetails'
            }
        }
    }

    It 'rejects an incompatible authenticated producer status response' {
        InModuleScope HostHunterNextGeneration {
            $requestSender = { [pscustomobject]@{
                    status='ready'; service='hosthunter-visualizer'; api_version='2.0.0'
                    collection_run_schema_version='1.0.0'
                    host_observation_schema_version='1.0.0'; active_collection_run_id=$null
                    process_event_schema_version='1.0.0'
                } }
            { Invoke-HHVisualizerStatus -Sender $requestSender } | Should -Throw '*incompatible*'
        }
    }

    It 'accepts only a versioned producer status and parses its active mission id' {
        InModuleScope HostHunterNextGeneration {
            $id = [Guid]::NewGuid()
            $capabilities = @($script:HHForensicEventSchemas | ForEach-Object {
                    $parts = $_ -split '/', 2
                    [pscustomobject]@{
                        name=$parts[0]
                        version=$parts[1]
                        kind=$script:HHForensicEventSchemaKinds[$_]
                    }
                })
            $requestSender = { [pscustomobject]@{
                    status='ready'; service='hosthunter-visualizer'; api_version='1.0.0'
                    collection_run_schema_version='1.0.0'
                    host_observation_schema_version='1.0.0'
                    process_event_schema_version='1.0.0'
                    registered_forensic_schemas=$capabilities
                    active_collection_run_id=$id.ToString('D')
                } }.GetNewClosure()
            $result = Invoke-HHVisualizerStatus -Sender $requestSender
            $result.Status | Should -BeExactly ready
            $result.ActiveMissionId | Should -Be $id
        }
    }

    It 'requires the shared event or state kind for every advertised forensic schema' {
        InModuleScope HostHunterNextGeneration {
            $capabilities = @($script:HHForensicEventSchemas | ForEach-Object {
                    $parts = $_ -split '/', 2
                    [pscustomobject]@{
                        name=$parts[0]
                        version=$parts[1]
                        kind=$script:HHForensicEventSchemaKinds[$_]
                    }
                })
            $processEnd = @($capabilities | Where-Object name -CEQ 'process.end')[0]
            $processEnd.kind = 'state'
            $requestSender = { [pscustomobject]@{
                    status='ready'; service='hosthunter-visualizer'; api_version='1.0.0'
                    collection_run_schema_version='1.0.0'
                    host_observation_schema_version='1.0.0'
                    process_event_schema_version='1.0.0'
                    registered_forensic_schemas=$capabilities
                    active_collection_run_id=$null
                } }.GetNewClosure()
            { Invoke-HHVisualizerStatus -Sender $requestSender } |
                Should -Throw '*process.end/1.0.0*'
        }
    }

    It 'converts a selected mission id into repository bytes without Nullable wrapper assumptions' {
        InModuleScope HostHunterNextGeneration {
            $id = [Guid]::NewGuid()
            $script:capturedId = $null
            Mock Get-HHRuntimeContext { [pscustomobject]@{} }
            Mock Open-HHAuthenticatedPersistence { [pscustomobject]@{} }
            Mock Close-HHAuthenticatedPersistence {}
            Mock Invoke-HHAnchoredPersistenceTransaction {
                $script:capturedId = [byte[]]$ArgumentList[0].Id
            }

            Set-HHCurrentMissionCore -MissionId $id

            [Guid]::new($script:capturedId) | Should -Be $id
        }
    }

    It 'creates stable opaque endpoint ids without exposing the native digest' {
        InModuleScope HostHunterNextGeneration {
            $script:rows=@()
            Mock Invoke-HHSqliteQuery { @() }
            Mock Invoke-HHSqliteNonQuery { 1 }
            $master=[byte[]](0..31)
            $one=Resolve-HHVisualizerEndpointIdentity -Connection ([pscustomobject]@{}) `
                -Transaction ([pscustomobject]@{}) -MasterKey $master -TargetName alpha `
                -NativeIdentityDigest ('a'*64) -ObservedAtUtc ([DateTimeOffset]::UtcNow)
            $two=Resolve-HHVisualizerEndpointIdentity -Connection ([pscustomobject]@{}) `
                -Transaction ([pscustomobject]@{}) -MasterKey $master -TargetName renamed `
                -NativeIdentityDigest ('a'*64) -ObservedAtUtc ([DateTimeOffset]::UtcNow)
            $one.EndpointId | Should -BeExactly $two.EndpointId
            $one.EndpointId | Should -Match '^hh_[a-z2-7]{52}$'
            $one.EndpointId | Should -Not -Match ('a'*16)
            $one.Strategy | Should -BeExactly platform_instance_hmac_sha256
        }
    }

    It 'keeps visualizer producer attempts bounded to one request' {
        InModuleScope HostHunterNextGeneration {
            $script:attempts=0
            $requestSender={
                param($Path,$Payload,$Digest)
                $null = $Path,$Payload
                $script:attempts++
                [pscustomobject]@{
                    Delivered=$false;StatusCode=503;ContentSha256=$Digest
                }
            }
            $result=Invoke-HHVisualizerPut -RelativePath '/api/v1/test' `
                -PayloadBytes ([Text.Encoding]::UTF8.GetBytes('{}')) `
                -Sender $requestSender
            $script:attempts | Should -Be 1
            $result.Delivered | Should -BeFalse
        }
    }

    It 'builds a truthful partial payload when optional endpoint fields are absent' {
        InModuleScope HostHunterNextGeneration {
            $raw = [pscustomobject]@{
                ObservedAtUtc = '2026-08-28T01:02:03.000Z'
                Platform = 'linux'
                Hostname = 'partial-host'
                FieldResults = @([pscustomobject]@{
                        field='host.os.version';status='not_reported';source_method='linux_os_release'
                    })
                SourceMethods = @('linux_os_release')
            }
            $payload = ConvertTo-HHHostDetailsPayload -Raw $raw -Target ([pscustomobject]@{
                    Name='partial';HostName='192.0.2.10';Port=22
                }) -MissionId ([Guid]::NewGuid()) -EventId ([Guid]::NewGuid()) `
                -EndpointId ('hh_' + ('a' * 52)) -IdentityStrategy persisted_random `
                -BatchId ([Guid]::NewGuid().ToByteArray()) `
                -InvocationId ([Guid]::NewGuid().ToByteArray()) `
                -DatabaseId ([Guid]::NewGuid().ToByteArray())
            $payload.host.hostname | Should -BeExactly partial-host
            $payload.host.PSObject.Properties['domain'] | Should -BeNullOrEmpty
            $payload.hosthunter.collection.status | Should -BeExactly partial
            ($payload | ConvertTo-Json -Depth 15) | Should -Not -Match 'NativeIdentity'
        }
    }

    It 'collects a finite Linux inventory with explicit field provenance' {
        InModuleScope HostHunterNextGeneration {
            $collector = Get-HHHostDetailsRemoteScriptBlock
            $collector.ToString() | Should -Not -Match '(?i)\$isWindows\b'
            $raw = & $collector
            $raw.Platform | Should -BeExactly linux
            $raw.Hostname | Should -Not -BeNullOrEmpty
            $raw.ObservedAtUtc | Should -Not -BeNullOrEmpty
            @($raw.FieldResults).Count | Should -BeGreaterThan 5
            @($raw.FieldResults.field | Sort-Object -Unique).Count | Should -Be @($raw.FieldResults).Count
            @($raw.FieldResults.field) | Should -Contain 'hosthunter.boot.time'
            @($raw.SourceMethods) | Should -Contain dotnet_runtime_information
            $ipProperty = $raw.PSObject.Properties['Ip']
            if ($null -ne $ipProperty) {
                @($ipProperty.Value | Where-Object {
                        [Net.IPAddress]::IsLoopback([Net.IPAddress]::Parse($_))
                    }) | Should -HaveCount 0
            }
            else {
                $ipResult = @($raw.FieldResults | Where-Object field -eq 'host.ip')
                $ipResult | Should -HaveCount 1
                $ipResult[0].status | Should -Not -BeExactly observed
            }
            if ($null -ne $raw.PSObject.Properties['Fqdn']) {
                $raw.Fqdn | Should -BeExactly $raw.Fqdn.ToLowerInvariant()
            }
            if ($null -ne $raw.PSObject.Properties['NativeIdentityDigest']) {
                $raw.NativeIdentityDigest | Should -Match '^[a-f0-9]{64}$'
            }
        }
    }

    It 'projects all supported optional host fields without leaking native identity material' {
        InModuleScope HostHunterNextGeneration {
            $raw = [pscustomobject]@{
                ObservedAtUtc='2026-08-28T01:02:03Z';Platform='windows';Hostname='alpha'
                Fqdn='alpha.example.test';Domain='example.test';Architecture='x64'
                Ip=@('192.0.2.10');OsFamily='windows';OsName='Windows 11 Pro'
                OsFull='Microsoft Windows 11 Pro';OsVersion='10.0';OsKernel='10.0.26100'
                OsBuild='26100';OsEdition='Professional';MembershipType='domain'
                MembershipName='example.test';DirectoryRole='member_workstation'
                Manufacturer='Example';Model='Workstation';LogicalProcessors=8
                MemoryBytes=17179869184;Interfaces=@([pscustomobject]@{name='Ethernet';addresses=@('192.0.2.10')})
                BootTime='2026-08-27T22:00:00Z';TimeZoneId='UTC';UtcOffsetSeconds=0
                FieldResults=@([pscustomobject]@{
                        field='host.hostname';status='observed';source_method='dotnet_environment'
                        observed_at='2026-08-28T01:02:03Z'
                    })
                SourceMethods=@('dotnet_environment');NativeIdentityDigest=('b'*64)
            }
            $payload = ConvertTo-HHHostDetailsPayload -Raw $raw -Target ([pscustomobject]@{
                    Name='alpha';HostName='192.0.2.10';Port=22
                }) -MissionId ([Guid]::NewGuid()) -EventId ([Guid]::NewGuid()) `
                -EndpointId ('hh_'+('a'*52)) -IdentityStrategy platform_instance_hmac_sha256 `
                -BatchId ([Guid]::NewGuid().ToByteArray()) -InvocationId ([Guid]::NewGuid().ToByteArray()) `
                -DatabaseId ([Guid]::NewGuid().ToByteArray())
            $payload.host.domain | Should -BeExactly example.test
            $payload.hosthunter.membership.directory_role | Should -BeExactly member_workstation
            $payload.hosthunter.os.edition | Should -BeExactly Professional
            $payload.hosthunter.hardware.total_memory_bytes | Should -Be 17179869184
            $payload.hosthunter.network.interfaces[0].name | Should -BeExactly Ethernet
            $payload.hosthunter.collection.status | Should -BeExactly complete
            @($payload.hosthunter.provenance.source_methods) | Should -Be @(
                'dotnet_environment', 'hosthunter_identity', 'hosthunter_target'
            )
            ($payload|ConvertTo-Json -Depth 15) | Should -Not -Match ('b'*32)
            Initialize-HHSqliteProvider
            $bytes=[Text.UTF8Encoding]::new($false).GetBytes(
                ($payload | ConvertTo-Json -Compress -Depth 15)
            )
            Assert-HHHostDetailsPayloadSchema -PayloadBytes $bytes | Should -BeTrue
        }
    }

    It 'derives a stable installation-scoped agent id and hashes the full finite result' {
        InModuleScope HostHunterNextGeneration {
                $databaseId=[Guid]::NewGuid().ToByteArray()
                $agentOne=Get-HHVisualizerAgentId -DatabaseId $databaseId
                $agentTwo=Get-HHVisualizerAgentId -DatabaseId $databaseId
                $agentOne | Should -BeExactly $agentTwo
                $agentOne | Should -Match '^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
                $raw=[pscustomobject]@{
                    ObservedAtUtc='2026-08-28T01:02:03Z';Platform='linux';Hostname='alpha'
                    FieldResults=@([pscustomobject]@{field='host.hostname';status='observed';source_method='fixture'})
                    SourceMethods=@('fixture')
                }
                $arguments=@{
                    Raw=$raw;Target=[pscustomobject]@{Name='alpha';HostName='192.0.2.10';Port=22}
                    MissionId=[Guid]::NewGuid();EventId=[Guid]::NewGuid();EndpointId=('hh_'+('a'*52))
                    IdentityStrategy='persisted_random';BatchId=[Guid]::NewGuid().ToByteArray()
                    InvocationId=[Guid]::NewGuid().ToByteArray();DatabaseId=$databaseId
                }
                $first=ConvertTo-HHHostDetailsPayload @arguments
                $raw.FieldResults[0].status='not_reported'
                $second=ConvertTo-HHHostDetailsPayload @arguments
                $first.agent.id | Should -BeExactly $agentOne
                $first.event.hash | Should -Not -BeExactly $second.event.hash
        }
    }

    It 'validates exact payload bytes against the packaged JSON Schema 2020-12 contract' {
        InModuleScope HostHunterNextGeneration {
            Initialize-HHSqliteProvider
            $valid=[IO.File]::ReadAllBytes((Join-Path $script:HHModuleRoot '../../CIM_Specification/examples/linux-partial.v1.json'))
            Assert-HHHostDetailsPayloadSchema -PayloadBytes $valid | Should -BeTrue
            $invalid=[Text.UTF8Encoding]::new($false).GetBytes('{"schema_version":"wrong"}')
            { Assert-HHHostDetailsPayloadSchema -PayloadBytes $invalid } | Should -Throw '*does not conform*'
        }
    }

    It 'keeps visualizer connection defaults local and treats missing credentials as finite' {
        InModuleScope HostHunterNextGeneration {
            $previousBase = $env:HH_VISUALIZER_BASE_URI
            $previousToken = $env:HH_VISUALIZER_TOKEN_FILE
            try {
                $env:HH_VISUALIZER_BASE_URI = $null
                $env:HH_VISUALIZER_TOKEN_FILE = $null
                $defaults = Get-HHVisualizerConnectionSettings
                $defaults.BaseUri | Should -BeExactly 'http://hosthunter-visualizer:3000'
                $defaults.TokenPath | Should -BeExactly `
                    '/run/secrets/hosthunter_visualizer_producer_token'

                $env:HH_VISUALIZER_BASE_URI = 'http://visualizer.internal:3000///'
                $env:HH_VISUALIZER_TOKEN_FILE = Join-Path $TestDrive 'missing-token'
                $custom = Get-HHVisualizerConnectionSettings
                $custom.BaseUri | Should -BeExactly 'http://visualizer.internal:3000'
                $result = Invoke-HHVisualizerPut -RelativePath '/api/v1/test' `
                    -PayloadBytes ([Text.Encoding]::UTF8.GetBytes('{}'))
                $result.Delivered | Should -BeFalse
                $result.FailureKind | Should -BeExactly CredentialUnavailable
                $result.ContentSha256 | Should -Match '^[a-f0-9]{64}$'
            }
            finally {
                $env:HH_VISUALIZER_BASE_URI = $previousBase
                $env:HH_VISUALIZER_TOKEN_FILE = $previousToken
            }
        }
    }

    It 'binds visualizer sender paths and payloads to their SHA256 digest' {
        InModuleScope HostHunterNextGeneration {
            $mission = [Guid]::NewGuid()
            $eventId = [Guid]::NewGuid()
            $bytes = [Text.Encoding]::UTF8.GetBytes('{"kind":"asset"}')
            $script:requests = [Collections.Generic.List[object]]::new()
            $requestSender = {
                param($Path,$Payload,$Digest)
                $script:requests.Add([pscustomobject]@{
                        Path=$Path;Payload=[byte[]]$Payload;Digest=$Digest
                    })
                [pscustomobject]@{
                    Delivered=$true;StatusCode=201;FailureKind=$null;ContentSha256=$Digest
                }
            }

            Send-HHVisualizerMission -MissionId $mission -PayloadBytes $bytes `
                -RequestSender $requestSender | Select-Object -ExpandProperty Delivered |
                Should -BeTrue
            Send-HHVisualizerObservation -MissionId $mission -EventId $eventId `
                -PayloadBytes $bytes -RequestSender $requestSender |
                Select-Object -ExpandProperty Delivered | Should -BeTrue

            $script:requests.Count | Should -Be 2
            $script:requests[0].Path | Should -BeExactly `
                "/api/v1/collection-runs/$($mission.ToString('D').ToLowerInvariant())"
            $script:requests[1].Path | Should -BeExactly (
                "/api/v1/collection-runs/$($mission.ToString('D').ToLowerInvariant())" +
                "/host-observations/$($eventId.ToString('D').ToLowerInvariant())"
            )
            $script:requests[0].Digest | Should -BeExactly $script:requests[1].Digest
            { Invoke-HHVisualizerPut -RelativePath '/api/v1/test' `
                    -PayloadBytes ([byte[]]::new(262145)) -RequestSender $requestSender } |
                Should -Throw '*exceeds 256 KiB*'
            $script:requests.Count | Should -Be 2
        }
    }

    It 'rejects malformed visualizer status identity without making another request' {
        InModuleScope HostHunterNextGeneration {
            $script:statusAttempts = 0
            $requestSender = {
                $script:statusAttempts++
                [pscustomobject]@{
                    status='ready';service='hosthunter-visualizer';api_version='1.0.0'
                    collection_run_schema_version='1.0.0'
                    host_observation_schema_version='1.0.0'
                    process_event_schema_version='1.0.0'
                    registered_forensic_schemas=@(
                        $script:HHForensicEventSchemas | ForEach-Object {
                            $parts=$_ -split '/',2
                            [pscustomobject]@{
                                name=$parts[0]
                                version=$parts[1]
                                kind=$script:HHForensicEventSchemaKinds[$_]
                            }
                        }
                    )
                    active_collection_run_id='not-a-guid'
                }
            }
            { Invoke-HHVisualizerStatus -RequestSender $requestSender } |
                Should -Throw '*invalid collection-run identifier*'
            $script:statusAttempts | Should -Be 1
        }
    }
}
