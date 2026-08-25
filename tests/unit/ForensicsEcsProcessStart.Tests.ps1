BeforeAll {
    $sourceRoot = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
        Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration'
    }
    else { $env:HH_TEST_SOURCE_ROOT }
    . (Join-Path $sourceRoot 'Forensics/Private/Identity/ForensicsIdentity.ps1')
    . (Join-Path $sourceRoot 'Forensics/Private/Contracts/StrictJsonValidator.ps1')
    . (Join-Path $sourceRoot 'Forensics/Private/Contracts/EcsProcessStartContract.ps1')
    . (Join-Path $sourceRoot 'Forensics/Private/Parser/EvtxDump.ps1')
    . (Join-Path $sourceRoot 'Forensics/Private/Normalization/EcsProcessStart.ps1')
    $script:fixtureRoot = Join-Path $PSScriptRoot '../fixtures/forensics'
    $script:context = [pscustomobject]@{
        HostId = 'host-001'
        HostName = 'WIN-LAB'
        ArtifactSha256 = ('a' * 64)
        ParserVersion = '0.12.2'
        RunStartedAt = '2026-08-25T05:00:00Z'
    }
    function Read-HHForensicsFixtureRecord {
        param([Parameter(Mandatory)][string]$Name)

        $path = Join-Path $script:fixtureRoot "jsonl/$Name"
        $stream = [IO.MemoryStream]::new([IO.File]::ReadAllBytes($path), $false)
        try {
            return @(Read-HHForensicsJsonlRecord -Stream $stream `
                    -SourceIdentity ('a' * 64))
        }
        finally { $stream.Dispose() }
    }
    function Get-HHTestSysmonEcsEvent {
        $record = @(Read-HHForensicsFixtureRecord 'process-start-sysmon.jsonl')[0]
        return ConvertTo-HHEcsProcessStartEvent -Record $record -Context $script:context
    }
    function Get-HHTestPipelineErrorEcsEvent {
        $record = @(Read-HHForensicsFixtureRecord 'process-start-errors.jsonl')[0]
        return ConvertTo-HHEcsProcessStartEvent -Record $record -Context $script:context
    }
}

Describe 'ECS 9.5.0 Process Start normalization' -Tag Unit {
    It 'maps Sysmon Event 1 without outcome or heuristic arguments' {
        $record = @(Read-HHForensicsFixtureRecord 'process-start-sysmon.jsonl')[0]
        $ecsEvent = ConvertTo-HHEcsProcessStartEvent -Record $record -Context $script:context
        $ecsEvent.ecs.version | Should -BeExactly '9.5.0'
        $ecsEvent.event.kind | Should -BeExactly 'event'
        $ecsEvent.event.category | Should -Be @('process')
        $ecsEvent.event.type | Should -Be @('start')
        $ecsEvent.event.action | Should -BeExactly 'process-started'
        $ecsEvent.event.code | Should -BeExactly '1'
        $ecsEvent.event.Keys | Should -Not -Contain 'outcome'
        $ecsEvent.process.entity_id | Should -BeExactly '{11111111-2222-3333-4444-555555555555}'
        $ecsEvent.process.pid | Should -Be 4242
        $ecsEvent.process.command_line | Should -BeExactly 'powershell.exe -NoProfile -Command "Get-Process"'
        $ecsEvent.process.Keys | Should -Not -Contain 'args'
        $ecsEvent.event.original | Should -BeExactly $record.Original
        $ecsEvent.hosthunter.evidence.source_identity | Should -BeExactly ('a' * 64)
        $ecsEvent.hosthunter.evidence.source_ordinal | Should -Be 1
        Test-HHEcsProcessStartContract -Event $ecsEvent | Should -BeTrue
    }

    It 'maps Security 4688 versions 0, 1, and 2 including v2 target subject' {
        $records = @(Read-HHForensicsFixtureRecord 'process-start-security.jsonl')
        $events = @($records | ForEach-Object {
                ConvertTo-HHEcsProcessStartEvent -Record $_ -Context $script:context
            })
        $events.Count | Should -Be 3
        $events.hosthunter.evidence.source_version | Should -Be @('0', '1', '2')
        $events.process.pid | Should -Be @(256, 257, 258)
        $events.process.entity_id | Select-Object -Unique | Should -HaveCount 3
        $events[0].process.parent.Keys | Should -Not -Contain 'entity_id'
        $events[2].user.name | Should -BeExactly 'LAB\Analyst'
        $events[2].process.user.name | Should -BeExactly 'LAB\ServiceUser'
        $events[2].process.user.id | Should -BeExactly 'S-1-5-21-1000'
    }

    It 'does not invent a Security v2 process user from placeholder target subjects' {
        $cases = @(
            @{ Name = 'ServiceUser'; Sid = 'S-1-0-0'; Reason = 'target_user_sid_placeholder' },
            @{ Name = '-'; Sid = 'S-1-5-21-1000'; Reason = 'target_user_name_placeholder' },
            @{ Name = 'ServiceUser'; Sid = '0x0'; Reason = 'target_user_sid_placeholder' },
            @{ Name = '-'; Sid = '-'; Reason = 'target_subject_placeholders' }
        )
        foreach ($case in $cases) {
            $record = @(Read-HHForensicsFixtureRecord 'process-start-security.jsonl')[2]
            foreach ($pair in @($record.Data.Event.EventData.Data)) {
                if ($pair.'#attributes'.Name -ceq 'TargetUserName') {
                    $pair.'#text' = $case.Name
                }
                if ($pair.'#attributes'.Name -ceq 'TargetUserSid') {
                    $pair.'#text' = $case.Sid
                }
            }
            $ecsEvent = ConvertTo-HHEcsProcessStartEvent -Record $record -Context $script:context
            $ecsEvent.process.Keys | Should -Not -Contain 'user'
            $ecsEvent.hosthunter.normalization.process_user_null_reason |
                Should -BeExactly $case.Reason
            @($ecsEvent.hosthunter.event_data.pairs | Where-Object {
                    $_.name -ceq 'TargetUserSid'
                })[0].value | Should -BeExactly $case.Sid
            Test-HHEcsProcessStartContract -Event $ecsEvent | Should -BeTrue
        }
    }

    It 'maps a valid Security v2 target name without a domain' {
        $record = @(Read-HHForensicsFixtureRecord 'process-start-security.jsonl')[2]
        @($record.Data.Event.EventData.Data | Where-Object {
                $_.'#attributes'.Name -ceq 'TargetDomainName'
            })[0].'#text' = ''
        $ecsEvent = ConvertTo-HHEcsProcessStartEvent -Record $record -Context $script:context
        $ecsEvent.process.user.name | Should -BeExactly 'ServiceUser'
        $ecsEvent.process.user.id | Should -BeExactly 'S-1-5-21-1000'
    }

    It 'matches the committed observation-identity golden summary' {
        $records = @(
            Read-HHForensicsFixtureRecord 'process-start-sysmon.jsonl'
            Read-HHForensicsFixtureRecord 'process-start-security.jsonl'
        )
        $actual = @($records | ForEach-Object {
                $ecsEvent = ConvertTo-HHEcsProcessStartEvent -Record $_ -Context $script:context
                [pscustomobject][ordered]@{
                    code = $ecsEvent.event.code
                    version = $ecsEvent.hosthunter.evidence.source_version
                    event_id = $ecsEvent.event.id
                    entity_id = $ecsEvent.process.entity_id
                    pid = $ecsEvent.process.pid
                    name = $ecsEvent.process.name
                    timestamp = $ecsEvent.'@timestamp'
                }
            }) | ConvertTo-Json -Depth 10
        $expected = (Get-Content -LiteralPath (
                Join-Path $script:fixtureRoot 'golden/process-start-summary.json'
            ) -Raw).TrimEnd()
        $actual | Should -BeExactly $expected
    }

    It 'makes event.id an observation identity while process identity remains logical' {
        $record = @(Read-HHForensicsFixtureRecord 'process-start-security.jsonl')[0]
        $first = ConvertTo-HHEcsProcessStartEvent -Record $record -Context $script:context

        $ordinalRecord = $record.PSObject.Copy()
        $ordinalRecord.SourceOrdinal = 9
        $ordinal = ConvertTo-HHEcsProcessStartEvent -Record $ordinalRecord -Context $script:context
        $ordinal.event.id | Should -Not -BeExactly $first.event.id
        $ordinal.process.entity_id | Should -BeExactly $first.process.entity_id

        $copyRecord = $record.PSObject.Copy()
        $copyRecord.SourceIdentity = 'b' * 64
        $copyContext = $script:context.PSObject.Copy()
        $copyContext.ArtifactSha256 = 'b' * 64
        $copy = ConvertTo-HHEcsProcessStartEvent -Record $copyRecord -Context $copyContext
        $copy.event.id | Should -Not -BeExactly $first.event.id
        $copy.process.entity_id | Should -BeExactly $first.process.entity_id
    }

    It 'preserves ordered EventData pairs, nulls, unnamed values, and unconsumed warnings' {
        $record = @(Read-HHForensicsFixtureRecord 'process-start-sysmon.jsonl')[0]
        $record.Data.Event.EventData.Data = @($record.Data.Event.EventData.Data) + @(
            $null,
            [pscustomobject]@{ '#text' = $null },
            [pscustomobject]@{
                '#attributes' = [pscustomobject]@{ Name = 'UnmappedField' }
                '#text' = 'retained value'
            }
        )
        $ecsEvent = ConvertTo-HHEcsProcessStartEvent -Record $record -Context $script:context
        $pairs = @($ecsEvent.hosthunter.event_data.pairs)
        $pairs.Count | Should -Be 13
        $pairs[10].name | Should -BeNullOrEmpty
        $pairs[10].value | Should -BeNullOrEmpty
        $pairs[11].name | Should -BeNullOrEmpty
        $pairs[12].name | Should -BeExactly 'UnmappedField'
        $pairs[12].value | Should -BeExactly 'retained value'
        $ecsEvent.hosthunter.event_data.unconsumed_names | Should -Contain 'UnmappedField'
        $ecsEvent.hosthunter.event_data.warnings | Should -Contain 'null_event_data_pair:11'
        $ecsEvent.hosthunter.event_data.warnings | Should -Contain 'unnamed_event_data_pair:12'
        $ecsEvent.hosthunter.event_data.warnings | Should -Contain 'unconsumed_event_data:UnmappedField'
    }

    It 'fails a duplicate consumed EventData name without losing the pairs' {
        $record = @(Read-HHForensicsFixtureRecord 'process-start-sysmon.jsonl')[0]
        $record.Data.Event.EventData.Data = @($record.Data.Event.EventData.Data) + @(
            [pscustomobject]@{
                '#attributes' = [pscustomobject]@{ Name = 'CommandLine' }
                '#text' = 'duplicate'
            }
        )
        $ecsEvent = ConvertTo-HHEcsProcessStartEvent -Record $record -Context $script:context
        $ecsEvent.event.kind | Should -BeExactly 'pipeline_error'
        $ecsEvent.error.message | Should -Match "duplicate consumed field 'CommandLine'"
        @($ecsEvent.hosthunter.event_data.pairs | Where-Object name -CEQ CommandLine).Count |
            Should -Be 2
        $ecsEvent.hosthunter.event_data.warnings |
            Should -Contain 'duplicate_event_data_name:CommandLine'
    }

    It 'skips unrelated process-stop records' {
        $records = @(Read-HHForensicsFixtureRecord 'no-supported-process-start.jsonl')
        @($records | ForEach-Object {
                ConvertTo-HHEcsProcessStartEvent -Record $_ -Context $script:context
            } | Where-Object { $null -ne $_ }).Count | Should -Be 0
    }

    It 'emits closed deterministic pipeline errors for version and shape failures' {
        $records = @(Read-HHForensicsFixtureRecord 'process-start-errors.jsonl')
        $events = @($records | ForEach-Object {
                ConvertTo-HHEcsProcessStartEvent -Record $_ -Context $script:context
            })
        $events.event.kind | Should -Be @('pipeline_error', 'pipeline_error')
        $events.error.code | Should -Be @('unsupported_event_version', 'invalid_event_shape')
        $events[0].event.id | Should -BeExactly (
            (ConvertTo-HHEcsProcessStartEvent -Record $records[0] -Context $script:context).event.id
        )
        $events | ForEach-Object { Test-HHEcsProcessStartContract -Event $_ | Should -BeTrue }
    }

    It 'uses explicit unknown provenance when supported metadata is absent' {
        $record = @(Read-HHForensicsFixtureRecord 'process-start-errors.jsonl')[0]
        foreach ($name in @('Version', 'EventRecordID', 'Channel')) {
            $record.Data.Event.System.PSObject.Properties.Remove($name)
        }
        $context = $script:context.PSObject.Copy()
        $context.HostName = ''
        $ecsEvent = ConvertTo-HHEcsProcessStartEvent -Record $record -Context $context
        $ecsEvent.event.kind | Should -BeExactly 'pipeline_error'
        $ecsEvent.host.name | Should -BeExactly 'unknown'
        $ecsEvent.hosthunter.evidence.channel | Should -BeExactly 'unknown'
        $ecsEvent.hosthunter.evidence.event_record_id | Should -BeExactly 'unknown'
        $ecsEvent.hosthunter.evidence.source_version | Should -BeExactly 'unknown'
    }

    It 'omits absent optional Sysmon and Security projections without inventing values' {
        $sysmon = @(Read-HHForensicsFixtureRecord 'process-start-sysmon.jsonl')[0]
        $sysmon.Data.Event.System.Computer = ''
        $sysmon.Data.Event.EventData.Data = @(
            $sysmon.Data.Event.EventData.Data | Where-Object {
                $_.'#attributes'.Name -cnotin @(
                    'CommandLine', 'User', 'ParentProcessGuid', 'ParentProcessId',
                    'ParentImage', 'ParentCommandLine'
                )
            }
        )
        $context = $script:context.PSObject.Copy()
        $context.HostName = ''
        $sysmonEvent = ConvertTo-HHEcsProcessStartEvent -Record $sysmon -Context $context
        $sysmonEvent.host.name | Should -BeExactly 'unknown'
        $sysmonEvent.process.Keys | Should -Not -Contain 'command_line'
        $sysmonEvent.process.Keys | Should -Not -Contain 'parent'
        $sysmonEvent.PSObject.Properties.Name | Should -Not -Contain 'user'

        $security = @(Read-HHForensicsFixtureRecord 'process-start-security.jsonl')[0]
        $security.Data.Event.EventData.Data = @(
            $security.Data.Event.EventData.Data | Where-Object {
                $_.'#attributes'.Name -cnotin @('ProcessId', 'SubjectDomainName')
            }
        )
        @($security.Data.Event.EventData.Data | Where-Object {
                $_.'#attributes'.Name -ceq 'SubjectUserName'
            })[0].'#text' = '-'
        $securityEvent = ConvertTo-HHEcsProcessStartEvent `
            -Record $security -Context $script:context
        $securityEvent.process.Keys | Should -Not -Contain 'parent'
        $securityEvent.PSObject.Properties.Name | Should -Not -Contain 'user'
        Test-HHEcsProcessStartContract -Event $securityEvent | Should -BeTrue
    }

    It 'returns a bounded pipeline error when a required Sysmon field is absent' {
        $record = @(Read-HHForensicsFixtureRecord 'process-start-sysmon.jsonl')[0]
        $record.Data.Event.EventData.Data = @(
            $record.Data.Event.EventData.Data | Where-Object {
                $_.'#attributes'.Name -cne 'Image'
            }
        )
        $ecsEvent = ConvertTo-HHEcsProcessStartEvent -Record $record -Context $script:context
        $ecsEvent.event.kind | Should -BeExactly 'pipeline_error'
        $ecsEvent.error.code | Should -BeExactly 'invalid_event_shape'
        $ecsEvent.error.message | Should -Match "missing required field 'Image'"
        Test-HHEcsProcessStartContract -Event $ecsEvent | Should -BeTrue
    }

    It 'requires source identity to match admitted evidence context' {
        $record = @(Read-HHForensicsFixtureRecord 'process-start-sysmon.jsonl')[0]
        $record.SourceIdentity = 'b' * 64
        { ConvertTo-HHEcsProcessStartEvent -Record $record -Context $script:context } |
            Should -Throw '*does not match*'
    }

    It 'uses source computer fallback and optional acquisition provenance' {
        $record = @(Read-HHForensicsFixtureRecord 'process-start-sysmon.jsonl')[0]
        $context = [pscustomobject]@{
            HostId = 'host-001'; ArtifactSha256 = ('a' * 64); ParserVersion = '0.12.2'
            RunStartedAt = '2026-08-25T05:00:00Z'; ArtifactId = 'artifact-001'
            EvidenceRelativePath = 'immutable/evidence.evtx'; AcquisitionId = 'acquisition-001'
        }
        $ecsEvent = ConvertTo-HHEcsProcessStartEvent -Record $record -Context $context
        $ecsEvent.host.name | Should -BeExactly 'WIN-LAB'
        $ecsEvent.hosthunter.evidence.artifact_id | Should -BeExactly 'artifact-001'
        $ecsEvent.hosthunter.acquisition.id | Should -BeExactly 'acquisition-001'
    }

    It 'rejects malformed helper projections and parser record markers' {
        { ConvertTo-HHForensicsUtcTimestamp -Value 'not-a-time' } | Should -Throw '*invalid*'
        { ConvertTo-HHForensicsProcessId -Value 'not-a-pid' } | Should -Throw '*invalid*'
        $record = @(Read-HHForensicsFixtureRecord 'process-start-sysmon.jsonl')[0]
        $record.Marker = 'untrusted'
        { ConvertTo-HHEcsProcessStartEvent -Record $record -Context $script:context } |
            Should -Throw '*not a HostHunter parser*'
        $missingContext = $script:context.PSObject.Copy()
        $missingContext.HostId = ''
        $record = @(Read-HHForensicsFixtureRecord 'process-start-sysmon.jsonl')[0]
        { ConvertTo-HHEcsProcessStartEvent -Record $record -Context $missingContext } |
            Should -Throw '*requires*HostId*'
    }

    It 'strictly rejects extra fields through the repo-owned contract validator' {
        $record = @(Read-HHForensicsFixtureRecord 'process-start-sysmon.jsonl')[0]
        $ecsEvent = ConvertTo-HHEcsProcessStartEvent -Record $record -Context $script:context
        $ecsEvent | Add-Member -NotePropertyName unexpected -NotePropertyValue 'rejected'
        { Test-HHEcsProcessStartContract -Event $ecsEvent } | Should -Throw '*unexpected field*'

        $ecsEvent = ConvertTo-HHEcsProcessStartEvent -Record $record -Context $script:context
        $ecsEvent.event.outcome = 'success'
        { Test-HHEcsProcessStartContract -Event $ecsEvent } | Should -Throw '*unexpected field*'
    }

    It 'rejects invalid values across every closed contract projection' {
        { Test-HHEcsProcessStartContract -Event 'scalar' } | Should -Throw '*must be an object*'
        $cases = @(
            @{ Pattern = '*missing*'; Mutate = { param($value) $value.PSObject.Properties.Remove('host') } },
            @{ Pattern = '*must be a string*'; Mutate = { param($value) $value.host.name = '' } },
            @{ Pattern = '*must be an object*'; Mutate = { param($value) $value.host.os = 'scalar' } },
            @{ Pattern = '*version must be*'; Mutate = { param($value) $value.ecs.version = '9.4.0' } },
            @{ Pattern = '*host.os.type*'; Mutate = { param($value) $value.host.os.type = 'linux' } },
            @{ Pattern = '*event.id*'; Mutate = { param($value) $value.event.id = 'invalid' } },
            @{ Pattern = '*event.category*'; Mutate = { param($value) $value.event.category = @('file') } },
            @{ Pattern = '*Process Start event projection*'; Mutate = { param($value) $value.event.action = 'started' } },
            @{ Pattern = '*process.pid*'; Mutate = { param($value) $value.process.pid = -1 } },
            @{ Pattern = '*mapping contract identity*'; Mutate = { param($value) $value.hosthunter.contract.name = 'other' } },
            @{ Pattern = '*parser provenance*'; Mutate = { param($value) $value.hosthunter.parser.version = '0.12.1' } },
            @{ Pattern = '*evidence digest*'; Mutate = { param($value) $value.hosthunter.evidence.original_sha256 = 'bad' } },
            @{ Pattern = '*source ordinal*'; Mutate = { param($value) $value.hosthunter.evidence.source_ordinal = 0 } },
            @{ Pattern = '*pair ordinal*'; Mutate = { param($value) $value.hosthunter.event_data.pairs[0].ordinal = 0 } },
            @{ Pattern = '*null or string*'; Mutate = { param($value) $value.hosthunter.event_data.pairs[0].name = 4 } }
        )
        foreach ($case in $cases) {
            $ecsEvent = Get-HHTestSysmonEcsEvent
            & $case.Mutate $ecsEvent
            { Test-HHEcsProcessStartContract -Event $ecsEvent } |
                Should -Throw $case.Pattern
        }

        $pipelineError = Get-HHTestPipelineErrorEcsEvent
        $pipelineError.event.action = 'failed'
        { Test-HHEcsProcessStartContract -Event $pipelineError } |
            Should -Throw '*pipeline error event projection*'

        $invalidNormalization = Get-HHTestSysmonEcsEvent
        $invalidNormalization.hosthunter.normalization = [ordered]@{
            process_user_null_reason = 'not-approved'
        }
        { Test-HHEcsProcessStartContract -Event $invalidNormalization } |
            Should -Throw '*null reason is invalid*'
    }

    It 'accepts empty lossless collections where the schema permits them' {
        $analysis = ConvertTo-HHForensicsEventDataAnalysis -EventData (
            [pscustomobject]@{ Data = @() }
        )
        $completed = Complete-HHForensicsEventDataAnalysis -Analysis $analysis
        @($completed.pairs).Count | Should -Be 0
        @($completed.unconsumed_names).Count | Should -Be 0
        @($completed.warnings).Count | Should -Be 0

        $ecsEvent = Get-HHTestSysmonEcsEvent
        $ecsEvent.hosthunter.sensitive_fields = @()
        $ecsEvent.hosthunter.event_data = [ordered]@{
            pairs = @()
            unconsumed_names = @()
            warnings = @()
        }
        Test-HHEcsProcessStartContract -Event $ecsEvent | Should -BeTrue
        { Assert-HHForensicsExactKey -Value ([ordered]@{}) -Required @() `
                -Path 'empty-object' } | Should -Not -Throw
    }

    It 'ships a closed Process Start-only ECS schema' {
        $schemaPath = Join-Path $sourceRoot `
            'Forensics/Private/Contracts/hosthunter.process_start.v1.schema.json'
        $schemaText = Get-Content -LiteralPath $schemaPath -Raw
        { $schemaText | ConvertFrom-Json } | Should -Not -Throw
        $schemaText | Should -Match 'additionalProperties'
        $schemaText | Should -Match 'source_ordinal'
        $schemaText | Should -Not -Match '(?i)OCSF|process-stop|4689'

        $events = @(
            @(Read-HHForensicsFixtureRecord 'process-start-sysmon.jsonl')[0],
            @(Read-HHForensicsFixtureRecord 'process-start-security.jsonl')[2],
            @(Read-HHForensicsFixtureRecord 'process-start-errors.jsonl')[0]
        ) | ForEach-Object {
            ConvertTo-HHEcsProcessStartEvent -Record $_ -Context $script:context
        }
        foreach ($ecsEvent in $events) {
            ($ecsEvent | ConvertTo-Json -Depth 100) |
                Test-Json -SchemaFile $schemaPath | Should -BeTrue
        }
    }

    It 'enforces the checked-in schema string boundaries at runtime' {
        $schemaPath = Join-Path $sourceRoot `
            'Forensics/Private/Contracts/hosthunter.process_start.v1.schema.json'
        $cases = @(
            @{
                Name = 'process.command_line'; Maximum = 1048576
                Factory = { Get-HHTestSysmonEcsEvent }
                Mutate = { param($value, $text) $value.process.command_line = $text }
            },
            @{
                Name = 'process.parent.command_line'; Maximum = 1048576
                Factory = { Get-HHTestSysmonEcsEvent }
                Mutate = { param($value, $text) $value.process.parent.command_line = $text }
            },
            @{
                Name = 'event.original'; Maximum = 4194304
                Factory = { Get-HHTestSysmonEcsEvent }
                Mutate = { param($value, $text) $value.event.original = $text }
            },
            @{
                Name = 'pipeline event.original'; Maximum = 4194304
                Factory = { Get-HHTestPipelineErrorEcsEvent }
                Mutate = { param($value, $text) $value.event.original = $text }
            },
            @{
                Name = 'evidence.channel'; Maximum = 1024
                Factory = { Get-HHTestSysmonEcsEvent }
                Mutate = { param($value, $text) $value.hosthunter.evidence.channel = $text }
            },
            @{
                Name = 'evidence.event_record_id'; Maximum = 128
                Factory = { Get-HHTestSysmonEcsEvent }
                Mutate = { param($value, $text) $value.hosthunter.evidence.event_record_id = $text }
            },
            @{
                Name = 'evidence.provider'; Maximum = 1024
                Factory = { Get-HHTestSysmonEcsEvent }
                Mutate = { param($value, $text) $value.hosthunter.evidence.provider = $text }
            },
            @{
                Name = 'evidence.source_version'; Maximum = 128
                Factory = { Get-HHTestSysmonEcsEvent }
                Mutate = { param($value, $text) $value.hosthunter.evidence.source_version = $text }
            },
            @{
                Name = 'evidence.artifact_id'; Maximum = 1024
                Factory = { Get-HHTestSysmonEcsEvent }
                Mutate = { param($value, $text) $value.hosthunter.evidence.artifact_id = $text }
            },
            @{
                Name = 'evidence.relative_path'; Maximum = 4096
                Factory = { Get-HHTestSysmonEcsEvent }
                Mutate = { param($value, $text) $value.hosthunter.evidence.relative_path = $text }
            },
            @{
                Name = 'acquisition.id'; Maximum = 1024
                Factory = { Get-HHTestSysmonEcsEvent }
                Mutate = {
                    param($value, $text)
                    $value.hosthunter.acquisition = [ordered]@{ id = $text }
                }
            }
        )
        foreach ($case in $cases) {
            $atBoundary = & $case.Factory
            & $case.Mutate $atBoundary ('x' * $case.Maximum)
            Test-HHEcsProcessStartContract -Event $atBoundary | Should -BeTrue
            ($atBoundary | ConvertTo-Json -Depth 100) |
                Test-Json -SchemaFile $schemaPath | Should -BeTrue

            $overBoundary = & $case.Factory
            & $case.Mutate $overBoundary ('x' * ($case.Maximum + 1))
            { Test-HHEcsProcessStartContract -Event $overBoundary } |
                Should -Throw '*maximum length*'
            {
                ($overBoundary | ConvertTo-Json -Depth 100) |
                    Test-Json -SchemaFile $schemaPath -ErrorAction Stop
            } | Should -Throw '*not valid with the schema*'
        }
    }
}
