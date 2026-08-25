Set-StrictMode -Version Latest

BeforeAll {
    if ([string]::IsNullOrWhiteSpace($env:HH_TEST_MODULE_PATH)) {
        throw 'HH_TEST_MODULE_PATH is required for package-only Forensics parser proof.'
    }
    $script:module = Import-Module $env:HH_TEST_MODULE_PATH -Force -PassThru
    $script:repositoryRoot = '/workspace'
}

AfterAll {
    Remove-Module $script:module -Force -ErrorAction SilentlyContinue
}

Describe 'Packaged Forensics Process Start parser' -Tag Integration {
    It 'parses real Sysmon and Security EVTX through the adjacent pinned binary' {
        $result = & $script:module {
            param($RepositoryRoot)

            $parser = Resolve-HHForensicsEvtxParser
            $counts = [ordered]@{}
            foreach ($fixtureName in @('sysmon-1.evtx', 'security-4688.evtx')) {
                $script:packageParserRecords = [Collections.Generic.List[object]]::new()
                $consumer = {
                    param($Record)
                    $script:packageParserRecords.Add($Record)
                }
                $path = Join-Path $RepositoryRoot `
                    "tests/fixtures/forensics/evtx/$fixtureName"
                $sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
                $parsed = Invoke-HHForensicsEvtxParser -EvidencePath $path `
                    -ExpectedEvidenceSha256 $sha256 -Parser $parser `
                    -RecordConsumer $consumer -StagingRoot '/artifacts'
                $events = @($script:packageParserRecords | ForEach-Object {
                    $Record = $_
                    $context = [pscustomobject]@{
                        HostId = 'package-fixture-host'
                        HostName = 'PACKAGE-FIXTURE'
                        ArtifactSha256 = $Record.SourceIdentity
                        ParserVersion = '0.12.2'
                        RunStartedAt = '2026-08-25T00:00:00Z'
                    }
                    $ecsEvent = ConvertTo-HHEcsProcessStartEvent `
                        -Record $Record -Context $context
                    if ($null -ne $ecsEvent) { $ecsEvent }
                })
                $counts[$fixtureName] = [pscustomobject]@{
                    Records = $parsed.Records
                    Events = $events.Count
                    PlaintextOutputArtifact = $parsed.PlaintextOutputArtifact
                }
            }
            [pscustomobject]@{
                ParserVersion = $parser.Version
                RuntimeIdentifier = $parser.RuntimeIdentifier
                Sysmon = $counts['sysmon-1.evtx']
                Security = $counts['security-4688.evtx']
            }
        } $script:repositoryRoot

        $result.ParserVersion | Should -BeExactly '0.12.2'
        $result.RuntimeIdentifier | Should -BeIn @('linux-arm64', 'linux-x64')
        $result.Sysmon.Records | Should -Be 3
        $result.Sysmon.Events | Should -Be 2
        $result.Security.Records | Should -Be 8
        $result.Security.Events | Should -Be 2
        $result.Sysmon.PlaintextOutputArtifact | Should -BeFalse
        $result.Security.PlaintextOutputArtifact | Should -BeFalse
    }

    It 'runs the protected local Process Start pipeline into the encrypted outbox' {
        $result = & $script:module {
            param($RepositoryRoot, $DataRoot)

            $path = Join-Path $RepositoryRoot 'tests/fixtures/forensics/evtx/sysmon-1.evtx'
            $sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
            $persistence = New-HHForensicsPersistenceContext -DataRoot $DataRoot
            $script:pipelineKey = [byte[]](1..32)
            $script:pipelineAnchor = $null
            $keyProvider = {
                [pscustomobject]@{
                    Service = 'HostHunterNextGeneration.Forensics.v1'
                    Account = 'ledger-key'
                    KeyBytes = [byte[]]$script:pipelineKey.Clone()
                }
            }
            $anchorReader = { param($Context) $null = $Context; $script:pipelineAnchor }
            $anchorWriter = {
                param($Expected, $New, $Context)
                $null = $Expected
                $null = $Context
                $script:pipelineAnchor = $New
            }
            $eventContext = [pscustomobject]@{
                HostId = 'package-pipeline-host'
                HostName = 'PACKAGE-PIPELINE'
                ArtifactSha256 = $sha256.ToLowerInvariant()
                ParserVersion = '0.12.2'
                RunStartedAt = '2026-08-25T00:00:00Z'
            }
            $warnings = @()
            $summary = Invoke-HHForensicsLocalProcessStartPipeline `
                -EvidencePath $path -ExpectedEvidenceSha256 $sha256 `
                -PersistenceContext $persistence -ForensicsKeyProvider $keyProvider `
                -AnchorReader $anchorReader -AnchorWriter $anchorWriter `
                -RunId package-process-start -EventContext $eventContext `
                -StagingRoot '/artifacts' -WarningVariable warnings
            $context = Open-HHForensicsPersistence -PersistenceContext $persistence `
                -ForensicsKeyProvider $keyProvider -AnchorReader $anchorReader `
                -AnchorWriter $anchorWriter
            try {
                $item = Get-HHForensicsOutboxItem -Context $context `
                    -ResourceKey 'event-batch:package-process-start:0' -IncludeBody
                $databaseText = [Text.Encoding]::UTF8.GetString(
                    [IO.File]::ReadAllBytes($persistence.DatabasePath)
                )
                [pscustomobject]@{
                    Summary = $summary
                    WarningCount = $warnings.Count
                    OutboxEventCount = $item.EventCount
                    OutboxStatus = $item.Status
                    ProtectedCommandLine = $databaseText -notmatch 'powershell.exe -NoProfile'
                }
            }
            finally {
                if ($null -ne $item.Body) {
                    [Array]::Clear($item.Body, 0, $item.Body.Length)
                }
                Close-HHForensicsPersistence -Context $context
            }
        } $script:repositoryRoot (Join-Path $TestDrive 'pipeline-state')

        $result.Summary.Marker | Should -BeExactly `
            'HostHunter.Forensics.LocalProcessStartPipeline.v1'
        $result.Summary.CanonicalEventCount | Should -Be 2
        $result.Summary.BatchCount | Should -Be 1
        $result.Summary.Batches[0].Status | Should -BeExactly 'PREPARED'
        $result.Summary.CommandLinePrivacyWarningIssued | Should -BeFalse
        $result.Summary.PlaintextParserArtifactCreated | Should -BeFalse
        $result.WarningCount | Should -Be 0
        $result.OutboxEventCount | Should -Be 2
        $result.OutboxStatus | Should -BeExactly 'PREPARED'
        $result.ProtectedCommandLine | Should -BeTrue
    }
}
