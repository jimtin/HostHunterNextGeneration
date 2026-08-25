BeforeAll {
    $sourceRoot = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
        Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration'
    }
    else { $env:HH_TEST_SOURCE_ROOT }
    . (Join-Path $sourceRoot 'Private/PersistenceErrors.ps1')
    . (Join-Path $sourceRoot 'Forensics/Private/Identity/ForensicsIdentity.ps1')
    . (Join-Path $sourceRoot 'Forensics/Private/Contracts/StrictJsonValidator.ps1')
    . (Join-Path $sourceRoot 'Forensics/Private/Contracts/EcsProcessStartContract.ps1')
    . (Join-Path $sourceRoot 'Forensics/Private/Parser/EvtxDump.ps1')
    . (Join-Path $sourceRoot 'Forensics/Private/Normalization/EcsProcessStart.ps1')
    . (Join-Path $sourceRoot 'Forensics/Private/Persistence/ForensicsCrypto.ps1')
    . (Join-Path $sourceRoot 'Forensics/Private/Migrations/ForensicsMigrations.ps1')
    . (Join-Path $sourceRoot 'Forensics/Private/Persistence/ForensicsPersistence.ps1')
    . (Join-Path $sourceRoot 'Forensics/Private/Delivery/ForensicsOutbox.ps1')
    . (Join-Path $sourceRoot 'Forensics/Private/Delivery/ForensicsApiClient.ps1')
    . (Join-Path $sourceRoot 'Forensics/Private/ForensicsPipeline.ps1')
    $fixturePath = Join-Path $PSScriptRoot `
        '../fixtures/forensics/jsonl/process-start-sysmon.jsonl'
    $stream = [IO.MemoryStream]::new([IO.File]::ReadAllBytes($fixturePath), $false)
    try {
        $script:record = @(Read-HHForensicsJsonlRecord -Stream $stream `
                -SourceIdentity ('a' * 64))[0]
    }
    finally { $stream.Dispose() }
    $script:context = [pscustomobject]@{
        HostId = 'pipeline-test-host'; HostName = 'PIPELINE-TEST'
        ArtifactSha256 = ('a' * 64); ParserVersion = '0.12.2'
        RunStartedAt = '2026-08-25T00:00:00Z'
    }
}

Describe 'local Process Start pipeline helpers' -Tag Unit {
    It 'requires one privacy warning when a canonical event contains a command line' {
        $ecsEvent = ConvertTo-HHEcsProcessStartEvent `
            -Record $script:record -Context $script:context
        Test-HHForensicsCommandLinePrivacyWarningRequired -EcsEvent $ecsEvent |
            Should -BeTrue
        $ecsEvent.process.Remove('command_line')
        Test-HHForensicsCommandLinePrivacyWarningRequired -EcsEvent $ecsEvent |
            Should -BeFalse
    }

    It 'serializes an ECS event into a strict canonical outbox item' {
        $ecsEvent = ConvertTo-HHEcsProcessStartEvent `
            -Record $script:record -Context $script:context
        $canonical = ConvertTo-HHForensicsCanonicalEcsEvent -EcsEvent $ecsEvent -Ordinal 1
        try {
            $canonical.EventId | Should -BeExactly $ecsEvent.event.id
            $canonical.SourceKey | Should -BeExactly ('a' * 64)
            { Assert-HHForensicsCanonicalEventBody -BodyBytes $canonical.BodyBytes } |
                Should -Not -Throw
        }
        finally { [Array]::Clear($canonical.BodyBytes, 0, $canonical.BodyBytes.Length) }
    }

    It 'splits batches at their deterministic byte boundary and rejects one oversized event' {
        $small = for ($ordinal = 1; $ordinal -le 2; $ordinal++) {
            [pscustomobject]@{
                EventId = "event-$ordinal"; SourceKey = 'source'; Ordinal = $ordinal
                OccurredAtUtc = '2026-08-25T00:00:00Z'
                BodyBytes = [Text.Encoding]::UTF8.GetBytes('{"event":"small"}')
            }
        }
        (Split-HHForensicsCanonicalEventBatch -RunId run-1 -CanonicalEvents $small).Count |
            Should -Be 1

        $oversized = $small[0].PSObject.Copy()
        $oversized.BodyBytes = [Text.Encoding]::UTF8.GetBytes(
            '{"value":"' + ('x' * 524288) + '"}'
        )
        $splitCommand = Get-Command Split-HHForensicsCanonicalEventBatch
        $caught = $null
        try {
            $null = & $splitCommand `
                -RunId run-1 -CanonicalEvents @($oversized)
        }
        catch { $caught = $_ }
        $caught | Should -Not -BeNullOrEmpty
        $caught.FullyQualifiedErrorId | Should -BeLike 'ForensicsBatchRejected*'

        $many = 1..251 | ForEach-Object {
            [pscustomobject]@{
                EventId = "event-many-$_"; SourceKey = 'source'; Ordinal = $_
                OccurredAtUtc = '2026-08-25T00:00:00Z'
                BodyBytes = [Text.Encoding]::UTF8.GetBytes('{"event":"small"}')
            }
        }
        $countSplit = @(Split-HHForensicsCanonicalEventBatch `
                -RunId run-many -CanonicalEvents $many)
        $countSplit | Should -HaveCount 2
        $countSplit[0].Events | Should -HaveCount 250
        $countSplit[1].Events | Should -HaveCount 1
    }

    It 'coordinates parsing, privacy warning, encrypted persistence, and API delivery' {
        $script:mapOrdinal = 0
        Mock Invoke-HHForensicsEvtxParser {
            param($RecordConsumer)
            & $RecordConsumer ([pscustomobject]@{ Name = 'start' })
            & $RecordConsumer ([pscustomobject]@{ Name = 'ignored' })
            [pscustomobject]@{ Records = 2; PlaintextOutputArtifact = $false }
        }
        Mock ConvertTo-HHEcsProcessStartEvent {
            $script:mapOrdinal++
            if ($script:mapOrdinal -eq 2) { return $null }
            [pscustomobject]@{
                event = [ordered]@{ kind = 'event'; id = 'event-1' }
                process = [ordered]@{ command_line = 'sensitive argument' }
            }
        }
        Mock ConvertTo-HHForensicsCanonicalEcsEvent {
            [pscustomobject]@{
                EventId = 'event-1'; SourceKey = 'source'; Ordinal = 1
                OccurredAtUtc = '2026-08-25T00:00:00Z'
                BodyBytes = [Text.Encoding]::UTF8.GetBytes('{"event":"start"}')
            }
        }
        Mock Open-HHForensicsPersistence { [pscustomobject]@{ Marker = 'context' } }
        Mock Write-HHForensicsEventBatch { [pscustomobject]@{ Status = 'PREPARED' } }
        Mock Invoke-HHForensicsOutboxDelivery { [pscustomobject]@{ Status = 'ACCEPTED' } }
        Mock Close-HHForensicsPersistence { }

        $warnings = @()
        $result = Invoke-HHForensicsLocalProcessStartPipeline `
            -EvidencePath '/evidence.evtx' -ExpectedEvidenceSha256 ('a' * 64) `
            -PersistenceContext ([pscustomobject]@{}) `
            -ForensicsKeyProvider { } -AnchorReader { } -AnchorWriter { } `
            -RunId run-1 -EventContext ([pscustomobject]@{}) `
            -Parser ([pscustomobject]@{}) -BaseUri 'https://collector.invalid' `
            -AccessTokenProvider { 'token' } -WarningVariable warnings

        $result.ParsedRecordCount | Should -Be 2
        $result.CanonicalEventCount | Should -Be 1
        $result.BatchCount | Should -Be 1
        $result.Batches[0].Status | Should -BeExactly 'ACCEPTED'
        $result.CommandLinePrivacyWarningIssued | Should -BeTrue
        $result.PlaintextParserArtifactCreated | Should -BeFalse
        $warnings.Count | Should -Be 1
        Should -Invoke Write-HHForensicsEventBatch -Exactly 1
        Should -Invoke Invoke-HHForensicsOutboxDelivery -Exactly 1
        Should -Invoke Close-HHForensicsPersistence -Exactly 1
    }

    It 'resolves the parser, returns an empty prepared run, and always closes persistence' {
        Mock Resolve-HHForensicsEvtxParser { [pscustomobject]@{ Version = '0.12.2' } }
        Mock Invoke-HHForensicsEvtxParser {
            [pscustomobject]@{ Records = 0; PlaintextOutputArtifact = $false }
        }
        Mock Open-HHForensicsPersistence { [pscustomobject]@{ Marker = 'context' } }
        Mock Close-HHForensicsPersistence { }

        $result = Invoke-HHForensicsLocalProcessStartPipeline `
            -EvidencePath '/evidence.evtx' -ExpectedEvidenceSha256 ('a' * 64) `
            -PersistenceContext ([pscustomobject]@{}) `
            -ForensicsKeyProvider { } -AnchorReader { } -AnchorWriter { } `
            -RunId empty-run -EventContext ([pscustomobject]@{})

        $result.CanonicalEventCount | Should -Be 0
        $result.BatchCount | Should -Be 0
        Should -Invoke Resolve-HHForensicsEvtxParser -Exactly 1
        Should -Invoke Close-HHForensicsPersistence -Exactly 1
    }

    It 'rejects API delivery without a token provider and still closes persistence' {
        Mock Invoke-HHForensicsEvtxParser {
            param($RecordConsumer)
            & $RecordConsumer ([pscustomobject]@{ Name = 'start' })
            [pscustomobject]@{ Records = 1; PlaintextOutputArtifact = $false }
        }
        Mock ConvertTo-HHEcsProcessStartEvent {
            [pscustomobject]@{
                event = [ordered]@{ kind = 'event'; id = 'event-1' }
                process = [ordered]@{}
            }
        }
        Mock ConvertTo-HHForensicsCanonicalEcsEvent {
            [pscustomobject]@{
                EventId = 'event-1'; SourceKey = 'source'; Ordinal = 1
                OccurredAtUtc = '2026-08-25T00:00:00Z'
                BodyBytes = [Text.Encoding]::UTF8.GetBytes('{"event":"start"}')
            }
        }
        Mock Open-HHForensicsPersistence { [pscustomobject]@{ Marker = 'context' } }
        Mock Write-HHForensicsEventBatch { [pscustomobject]@{ Status = 'PREPARED' } }
        Mock Close-HHForensicsPersistence { }

        {
            Invoke-HHForensicsLocalProcessStartPipeline `
                -EvidencePath '/evidence.evtx' -ExpectedEvidenceSha256 ('a' * 64) `
                -PersistenceContext ([pscustomobject]@{}) `
                -ForensicsKeyProvider { } -AnchorReader { } -AnchorWriter { } `
                -RunId run-1 -EventContext ([pscustomobject]@{}) `
                -Parser ([pscustomobject]@{}) -BaseUri 'https://collector.invalid'
        } | Should -Throw '*access-token provider*'
        Should -Invoke Close-HHForensicsPersistence -Exactly 1
    }

    It 'rejects a blank run identifier before parsing or persistence' {
        {
            Invoke-HHForensicsLocalProcessStartPipeline `
                -EvidencePath '/evidence.evtx' -ExpectedEvidenceSha256 ('a' * 64) `
                -PersistenceContext ([pscustomobject]@{}) `
                -ForensicsKeyProvider { } -AnchorReader { } -AnchorWriter { } `
                -RunId ' ' -EventContext ([pscustomobject]@{})
        } | Should -Throw '*requires a run ID*'
    }

    It 'prepares a local-only batch and clears it without API delivery' {
        Mock Invoke-HHForensicsEvtxParser {
            param($RecordConsumer)
            & $RecordConsumer ([pscustomobject]@{ Name = 'start' })
            [pscustomobject]@{ Records = 1; PlaintextOutputArtifact = $false }
        }
        Mock ConvertTo-HHEcsProcessStartEvent {
            [pscustomobject]@{
                event = [ordered]@{ kind = 'event'; id = 'event-local' }
                process = [ordered]@{}
            }
        }
        Mock ConvertTo-HHForensicsCanonicalEcsEvent {
            [pscustomobject]@{
                EventId = 'event-local'; SourceKey = 'source'; Ordinal = 1
                OccurredAtUtc = '2026-08-25T00:00:00Z'
                BodyBytes = [Text.Encoding]::UTF8.GetBytes('{"event":"start"}')
            }
        }
        Mock Open-HHForensicsPersistence { [pscustomobject]@{ Marker = 'context' } }
        Mock Write-HHForensicsEventBatch { [pscustomobject]@{ Status = 'PREPARED' } }
        Mock Invoke-HHForensicsOutboxDelivery { throw 'must not deliver' }
        Mock Close-HHForensicsPersistence { }

        $result = Invoke-HHForensicsLocalProcessStartPipeline `
            -EvidencePath '/evidence.evtx' -ExpectedEvidenceSha256 ('a' * 64) `
            -PersistenceContext ([pscustomobject]@{}) `
            -ForensicsKeyProvider { } -AnchorReader { } -AnchorWriter { } `
            -RunId local-run -EventContext ([pscustomobject]@{}) `
            -Parser ([pscustomobject]@{})
        $result.Batches[0].Status | Should -BeExactly PREPARED
        Should -Invoke Invoke-HHForensicsOutboxDelivery -Exactly 0
    }

    It 'keeps a failed persistence open from invoking close on a null context' {
        Mock Invoke-HHForensicsEvtxParser {
            [pscustomobject]@{ Records = 0; PlaintextOutputArtifact = $false }
        }
        Mock Open-HHForensicsPersistence { throw 'open failed' }
        Mock Close-HHForensicsPersistence { }
        {
            Invoke-HHForensicsLocalProcessStartPipeline `
                -EvidencePath '/evidence.evtx' -ExpectedEvidenceSha256 ('a' * 64) `
                -PersistenceContext ([pscustomobject]@{}) `
                -ForensicsKeyProvider { } -AnchorReader { } -AnchorWriter { } `
                -RunId failed-open -EventContext ([pscustomobject]@{}) `
                -Parser ([pscustomobject]@{})
        } | Should -Throw '*open failed*'
        Should -Invoke Close-HHForensicsPersistence -Exactly 0
    }
}
