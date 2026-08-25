$modulePath = if (-not [string]::IsNullOrWhiteSpace($env:HH_TEST_MODULE_PATH)) {
    $env:HH_TEST_MODULE_PATH
}
elseif (-not [string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
    Join-Path $env:HH_TEST_SOURCE_ROOT 'HostHunterNextGeneration.psd1'
}
else {
    Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration/HostHunterNextGeneration.psd1'
}
$moduleRoot = Split-Path -Parent $modulePath
$fixturePath = Join-Path $PSScriptRoot '../fixtures/forensics/api/Invoke-ForensicsApiStub.ps1'
$module = New-Module -Name HostHunterForensicsApiClientTest `
    -ArgumentList $moduleRoot, $fixturePath -ScriptBlock {
    param($Root, $FixturePath)
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
    $script:HHForensicsApiFixturePath = $FixturePath
}
$module | Import-Module -Force

Describe 'forensics loopback API delivery contract' -Tag Integration {
    InModuleScope HostHunterForensicsApiClientTest {
        BeforeAll {
            if ([IO.Directory]::Exists('/opt/hosthunter-sqlite/lib')) {
                $env:HH_SQLITE_PROVIDER_ROOT = '/opt/hosthunter-sqlite/lib'
            }

            function Start-HHForensicsApiFixture {
                [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
                    'PSUseShouldProcessForStateChangingFunctions',
                    '',
                    Justification = 'Starts only the bounded disposable loopback test fixture.'
                )]
                param(
                    [Parameter(Mandatory)][string]$Scenario,
                    [Parameter(Mandatory)][string]$Root
                )

                $readyPath = Join-Path $Root 'ready.json'
                $capturePath = Join-Path $Root 'capture.json'
                $start = [Diagnostics.ProcessStartInfo]::new()
                $start.FileName = (Get-Command pwsh -ErrorAction Stop).Source
                $start.UseShellExecute = $false
                $start.RedirectStandardOutput = $true
                $start.RedirectStandardError = $true
                foreach ($argument in @(
                        '-NoLogo', '-NoProfile', '-NonInteractive', '-File',
                        $script:HHForensicsApiFixturePath, '-Scenario', $Scenario,
                        '-ReadyPath', $readyPath, '-CapturePath', $capturePath
                    )) { $null = $start.ArgumentList.Add($argument) }
                $process = [Diagnostics.Process]::new()
                $process.StartInfo = $start
                if (-not $process.Start()) { throw 'The forensics API fixture did not start.' }
                $deadline = [DateTimeOffset]::UtcNow.AddSeconds(10)
                while (-not [IO.File]::Exists($readyPath)) {
                    if ($process.HasExited) {
                        throw "The API fixture exited early: $($process.StandardError.ReadToEnd())"
                    }
                    if ([DateTimeOffset]::UtcNow -ge $deadline) {
                        throw 'The API fixture ready receipt timed out.'
                    }
                    Start-Sleep -Milliseconds 25
                }
                $ready = [IO.File]::ReadAllText($readyPath) | ConvertFrom-Json
                return [pscustomobject]@{
                    Process = $process
                    BaseUri = "http://127.0.0.1:$($ready.port)/"
                    CapturePath = $capturePath
                }
            }

            function Stop-HHForensicsApiFixture {
                [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
                    'PSUseShouldProcessForStateChangingFunctions',
                    '',
                    Justification = 'Stops only the explicitly tracked disposable loopback fixture.'
                )]
                param([Parameter(Mandatory)][object]$Fixture)

                if (-not $Fixture.Process.HasExited) { $Fixture.Process.Kill($true) }
                $null = $Fixture.Process.WaitForExit(10000)
                $Fixture.Process.Dispose()
            }

            function New-HHForensicsApiTestReceipt {
                [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
                    'PSUseShouldProcessForStateChangingFunctions',
                    '',
                    Justification = 'Constructs only in-memory receipt fixture bytes.'
                )]
                param(
                    [Parameter(Mandatory)][object]$Item,
                    [int]$OriginalStatus = 201,
                    [string]$ResourceUri = $Item.ResourceUri,
                    [string]$IdempotencyKey = $Item.IdempotencyKey,
                    [string]$ContentDigest = (
                        Get-HHForensicsContentDigestHeader -Digest $Item.BodyDigest
                    ),
                    [string]$ReceiptId = 'injected-receipt'
                )
                $json = [ordered]@{
                    schema = 'hosthunter.put-receipt/1'
                    resource_uri = $ResourceUri
                    resource_key = $Item.ResourceKey
                    idempotency_key = $IdempotencyKey
                    content_digest = $ContentDigest
                    original_status = $OriginalStatus
                    receipt_id = $ReceiptId
                } | ConvertTo-Json -Compress
                return [Text.Encoding]::UTF8.GetBytes($json)
            }

            function New-HHForensicsInvalidReceipt {
                [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
                    'PSUseShouldProcessForStateChangingFunctions',
                    '',
                    Justification = 'Constructs only in-memory invalid receipt fixture bytes.'
                )]
                param(
                    [Parameter(Mandatory)][object]$Item,
                    [Parameter(Mandatory)][string]$Kind
                )
                if ($Kind -ceq 'empty') { return [byte[]]::new(0) }
                if ($Kind -ceq 'invalid UTF-8') { return [byte[]](0xff, 0xfe) }
                $receipt = [ordered]@{
                    schema = 'hosthunter.put-receipt/1'
                    resource_uri = $Item.ResourceUri
                    resource_key = $Item.ResourceKey
                    idempotency_key = $Item.IdempotencyKey
                    content_digest = Get-HHForensicsContentDigestHeader -Digest $Item.BodyDigest
                    original_status = 201
                    receipt_id = 'invalid-fixture'
                }
                switch ($Kind) {
                    'resource URI' { $receipt.resource_uri = '/api/v1/wrong' }
                    'resource key' { $receipt.resource_key = 'wrong-resource-key' }
                    'idempotency key' { $receipt.idempotency_key = 'wrong-idempotency' }
                    'body digest' { $receipt.content_digest = 'sha-256=:AAAAAAAA:' }
                    'original status' { $receipt.original_status = 202 }
                    'receipt id' { $receipt.receipt_id = 'invalid receipt id' }
                    'schema' { $receipt.schema = 'hosthunter.put-receipt/2' }
                    'missing field' { $receipt.Remove('receipt_id') }
                    'extra field' { $receipt['extra'] = $true }
                }
                $json = $receipt | ConvertTo-Json -Compress
                if ($Kind -ceq 'duplicate field') {
                    $json = $json.Substring(0, $json.Length - 1) +
                        ',"receipt_id":"duplicate"}'
                }
                return [Text.Encoding]::UTF8.GetBytes($json)
            }
        }

        BeforeEach {
            $script:testRoot = Join-Path $TestDrive ([Guid]::NewGuid().ToString('N'))
            $script:persistence = New-HHForensicsPersistenceContext -DataRoot $script:testRoot
            $script:testKey = [byte[]](96..127)
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
            $canonicalEvent = [pscustomobject]@{
                EventId = 'fixture-event'
                SourceKey = 'fixture-source'
                Ordinal = 0L
                OccurredAtUtc = '2026-08-25T00:00:00.0000000Z'
                BodyBytes = [Text.Encoding]::UTF8.GetBytes('{"event":{"id":"fixture-event"}}')
            }
            $script:requestBytes = New-HHForensicsCanonicalBatchBody `
                -RunId run-fixture -CreationOrder 1 -CanonicalEvents @($canonicalEvent)
            $null = Write-HHForensicsEventBatch `
                -Context $script:context -RunId run-fixture -ResourceKey resource-fixture `
                -IdempotencyKey idem-fixture -ResourceUri /api/v1/process-events `
                -CanonicalEvents @($canonicalEvent) -CreationOrder 1
            $script:preparedItem = Get-HHForensicsOutboxItem `
                -Context $script:context -ResourceKey resource-fixture
            $script:tokenProvider = {
                [Convert]::ToBase64String([byte[]](1..24))
            }
        }

        AfterEach {
            if ($null -ne $script:context) {
                Close-HHForensicsPersistence -Context $script:context
            }
        }

        It 'classifies <Scenario> as <ExpectedOutcome>' -TestCases @(
            @{ Scenario = 'Success'; ExpectedOutcome = 'ACCEPTED'; ExpectedCode = 201 }
            @{ Scenario = 'Replay'; ExpectedOutcome = 'ACCEPTED'; ExpectedCode = 200 }
            @{ Scenario = 'Conflict'; ExpectedOutcome = 'CONFLICT'; ExpectedCode = 409 }
            @{ Scenario = 'Retryable'; ExpectedOutcome = 'RETRYABLE'; ExpectedCode = 503 }
            @{ Scenario = 'Permanent'; ExpectedOutcome = 'REJECTED'; ExpectedCode = 422 }
            @{ Scenario = 'ReceiptMismatch'; ExpectedOutcome = 'CONFLICT'; ExpectedCode = 201 }
        ) {
            param($Scenario, $ExpectedOutcome, $ExpectedCode)

            $fixtureRoot = Join-Path $TestDrive "fixture-$Scenario"
            $null = [IO.Directory]::CreateDirectory($fixtureRoot)
            $fixture = Start-HHForensicsApiFixture -Scenario $Scenario -Root $fixtureRoot
            try {
                $result = Invoke-HHForensicsOutboxDelivery `
                    -Context $script:context -BaseUri $fixture.BaseUri `
                    -AccessTokenProvider $script:tokenProvider `
                    -ResourceKey resource-fixture -TimeoutSeconds 5
                $fixture.Process.WaitForExit(10000) | Should -BeTrue
                $result.Status | Should -BeExactly $ExpectedOutcome
                [int]$result.LastStatusCode | Should -Be $ExpectedCode
                $capture = [IO.File]::ReadAllText($fixture.CapturePath) | ConvertFrom-Json
                [Convert]::FromBase64String($capture.bodyBase64) |
                    Should -Be $script:requestBytes
                $capture.idempotencyKey | Should -BeExactly idem-fixture
                $capture.contentDigest | Should -BeExactly (
                    Get-HHForensicsContentDigestHeader `
                        -Digest (Get-HHForensicsHash -Bytes $script:requestBytes)
                )
                $capture.authorizationPresent | Should -BeTrue
                $capture.attemptId | Should -Not -BeNullOrEmpty
                $quarantineCount = Invoke-HHSqliteScalar `
                    -Connection $script:context.Connection `
                    -Sql 'SELECT COUNT(*) FROM forensics_quarantine;'
                if ($ExpectedOutcome -ceq 'CONFLICT') {
                    $quarantineCount | Should -Be 1
                }
                else { $quarantineCount | Should -Be 0 }
                $protectedBodyCount = Invoke-HHSqliteScalar `
                    -Connection $script:context.Connection -Sql @'
SELECT COUNT(*) FROM forensics_outbox
WHERE resource_key='resource-fixture' AND request_body_envelope IS NOT NULL;
'@
                if ($ExpectedOutcome -ceq 'ACCEPTED') {
                    $protectedBodyCount | Should -Be 0
                    (Get-HHForensicsOutboxItem `
                            -Context $script:context -ResourceKey resource-fixture `
                            -IncludeBody).Body | Should -BeNullOrEmpty
                }
                else { $protectedBodyCount | Should -Be 1 }
            }
            finally { Stop-HHForensicsApiFixture -Fixture $fixture }
        }

        It 'quarantines a successful status with a mismatched <Kind> receipt' -TestCases @(
            @{ Kind = 'resource URI' }
            @{ Kind = 'resource key' }
            @{ Kind = 'idempotency key' }
            @{ Kind = 'body digest' }
            @{ Kind = 'original status' }
            @{ Kind = 'receipt id' }
            @{ Kind = 'schema' }
            @{ Kind = 'missing field' }
            @{ Kind = 'extra field' }
            @{ Kind = 'duplicate field' }
            @{ Kind = 'empty' }
            @{ Kind = 'invalid UTF-8' }
        ) {
            param($Kind)

            $invalidReceipt = New-HHForensicsInvalidReceipt `
                -Item $script:preparedItem -Kind $Kind
            $result = Invoke-HHForensicsOutboxDelivery `
                -Context $script:context -BaseUri 'http://127.0.0.1:1/' `
                -AccessTokenProvider $script:tokenProvider -ResourceKey resource-fixture `
                -Transport {
                    [pscustomobject]@{ StatusCode = 201; Body = $invalidReceipt }
                }
            $result.Status | Should -BeExactly CONFLICT
            $result.LastProblemCode | Should -BeExactly ReceiptBindingMismatch
            (Invoke-HHSqliteScalar -Connection $script:context.Connection `
                    -Sql 'SELECT COUNT(*) FROM forensics_quarantine;') | Should -Be 1
            (Invoke-HHSqliteScalar -Connection $script:context.Connection -Sql @'
SELECT COUNT(*) FROM forensics_outbox
WHERE resource_key='resource-fixture' AND request_body_envelope IS NOT NULL;
'@) | Should -Be 1
        }

        It 'marks timeout unknown, reconciles absence, and retries identical bytes' {
            $unknownRoot = Join-Path $TestDrive 'fixture-unknown'
            $null = [IO.Directory]::CreateDirectory($unknownRoot)
            $unknown = Start-HHForensicsApiFixture -Scenario Unknown -Root $unknownRoot
            try {
                $result = Invoke-HHForensicsOutboxDelivery `
                    -Context $script:context -BaseUri $unknown.BaseUri `
                    -AccessTokenProvider $script:tokenProvider `
                    -ResourceKey resource-fixture -TimeoutSeconds 1
                $result.Status | Should -BeExactly UNKNOWN
                $firstCapture = [IO.File]::ReadAllText($unknown.CapturePath) | ConvertFrom-Json
            }
            finally { Stop-HHForensicsApiFixture -Fixture $unknown }

            $missingRoot = Join-Path $TestDrive 'fixture-missing'
            $null = [IO.Directory]::CreateDirectory($missingRoot)
            $missing = Start-HHForensicsApiFixture -Scenario ReceiptMissing -Root $missingRoot
            try {
                $reconciled = Invoke-HHForensicsOutboxDelivery `
                    -Context $script:context -BaseUri $missing.BaseUri `
                    -AccessTokenProvider $script:tokenProvider `
                    -ResourceKey resource-fixture -TimeoutSeconds 5
                $reconciled.Status | Should -BeExactly RETRYABLE
                $missing.Process.WaitForExit(10000) | Should -BeTrue
            }
            finally { Stop-HHForensicsApiFixture -Fixture $missing }

            $retryRoot = Join-Path $TestDrive 'fixture-retry'
            $null = [IO.Directory]::CreateDirectory($retryRoot)
            $retry = Start-HHForensicsApiFixture -Scenario Success -Root $retryRoot
            try {
                $accepted = Invoke-HHForensicsOutboxDelivery `
                    -Context $script:context -BaseUri $retry.BaseUri `
                    -AccessTokenProvider $script:tokenProvider `
                    -ResourceKey resource-fixture -TimeoutSeconds 5
                $accepted.Status | Should -BeExactly ACCEPTED
                $retry.Process.WaitForExit(10000) | Should -BeTrue
                $retryCapture = [IO.File]::ReadAllText($retry.CapturePath) | ConvertFrom-Json
                $retryCapture.bodyBase64 | Should -BeExactly $firstCapture.bodyBase64
                $accepted.AttemptCount | Should -Be 2
            }
            finally { Stop-HHForensicsApiFixture -Fixture $retry }
        }

        It 'bounds <Scenario> response bodies and marks their delivery unknown' -TestCases @(
            @{ Scenario = 'DeclaredOverflow' }
            @{ Scenario = 'ObservedOverflow' }
            @{ Scenario = 'SlowBody' }
            @{ Scenario = 'EndlessBody' }
        ) {
            param($Scenario)

            $fixtureRoot = Join-Path $TestDrive "fixture-$Scenario"
            $null = [IO.Directory]::CreateDirectory($fixtureRoot)
            $fixture = Start-HHForensicsApiFixture -Scenario $Scenario -Root $fixtureRoot
            try {
                $result = Invoke-HHForensicsOutboxDelivery `
                    -Context $script:context -BaseUri $fixture.BaseUri `
                    -AccessTokenProvider $script:tokenProvider `
                    -ResourceKey resource-fixture -TimeoutSeconds 1
                $result.Status | Should -BeExactly UNKNOWN
                $result.LastProblemCode | Should -BeExactly TransportOutcomeUnknown
            }
            finally { Stop-HHForensicsApiFixture -Fixture $fixture }
        }

        It 'rejects non-loopback endpoints before arming an attempt' {
            {
                Invoke-HHForensicsOutboxDelivery `
                    -Context $script:context -BaseUri 'https://example.test/' `
                    -AccessTokenProvider $script:tokenProvider `
                    -ResourceKey resource-fixture
            } | Should -Throw -ErrorId 'ForensicsApiEndpointRejected*'
            (Get-HHForensicsOutboxItem `
                    -Context $script:context -ResourceKey resource-fixture).Status |
                Should -BeExactly PREPARED
        }

        It 'covers injected transport, fallback classification, and an empty queue' {
            {
                Get-HHForensicsContentDigestHeader -Digest ([byte[]](1))
            } | Should -Throw '*32-byte*'
            (Get-HHForensicsApiProblemCode `
                    -StatusCode 418 -Body ([Text.Encoding]::UTF8.GetBytes('not-json'))) |
                Should -BeExactly Http418
            (Get-HHForensicsDeliveryOutcome -StatusCode 204) | Should -BeExactly UNKNOWN

            $result = Invoke-HHForensicsOutboxDelivery `
                -Context $script:context -BaseUri 'http://127.0.0.1:1/' `
                -AccessTokenProvider $script:tokenProvider `
                -Transport {
                    param($Request)
                    $Request.Method | Should -BeExactly PUT
                    [pscustomobject]@{
                        StatusCode = 201
                        Body = New-HHForensicsApiTestReceipt `
                            -Item $script:preparedItem -OriginalStatus 201
                    }
                }
            $result.Status | Should -BeExactly ACCEPTED
            (Invoke-HHForensicsOutboxDelivery `
                    -Context $script:context -BaseUri 'http://127.0.0.1:1/' `
                    -AccessTokenProvider $script:tokenProvider `
                    -Transport { throw 'must not run for an empty queue' }) |
                Should -BeNullOrEmpty
        }

        It 'rejects declared or observed injected response overflow' {
            {
                Invoke-HHForensicsHttpTransport `
                    -Uri ([Uri]'http://127.0.0.1:1/') -Method GET -Body $null `
                    -Headers @{} -TimeoutSeconds 1 -Transport {
                        [pscustomobject]@{
                            StatusCode = 200
                            Body = [byte[]]::new(0)
                            DeclaredLength = 65537
                        }
                    }
            } | Should -Throw -ErrorId 'ForensicsApiResponseRejected*'
            {
                Invoke-HHForensicsHttpTransport `
                    -Uri ([Uri]'http://127.0.0.1:1/') -Method GET -Body $null `
                    -Headers @{} -TimeoutSeconds 1 -Transport {
                        [pscustomobject]@{
                            StatusCode = 200
                            Body = [byte[]]::new(65537)
                        }
                    }
            } | Should -Throw -ErrorId 'ForensicsApiResponseRejected*'
        }

        It 'verifies authenticated state before dispatching any request' {
            $script:transportCalled = $false
            $null = Invoke-HHSqliteNonQuery -Connection $script:context.Connection -Sql @'
UPDATE forensics_outbox SET resource_uri='/tampered' WHERE resource_key='resource-fixture';
'@
            {
                Invoke-HHForensicsOutboxDelivery `
                    -Context $script:context -BaseUri 'http://127.0.0.1:1/' `
                    -AccessTokenProvider $script:tokenProvider -ResourceKey resource-fixture `
                    -Transport {
                        $script:transportCalled = $true
                        throw 'transport must not run'
                    }
            } | Should -Throw -ErrorId 'ForensicsIntegrityFailed*'
            $script:transportCalled | Should -BeFalse
        }

        It 'rejects a failing or malformed access-token provider' -TestCases @(
            @{ Provider = { throw 'provider unavailable' }; ExpectedError = 'provider failed' }
            @{ Provider = { "invalid`ntoken" }; ExpectedError = 'missing or malformed' }
        ) {
            param($Provider, $ExpectedError)

            $selectedProvider = $Provider
            {
                Invoke-HHForensicsOutboxDelivery `
                    -Context $script:context -BaseUri 'http://127.0.0.1:1/' `
                    -AccessTokenProvider $selectedProvider -ResourceKey resource-fixture `
                    -Transport { throw 'transport must not run' }
            } | Should -Throw "*$ExpectedError*"
            (Get-HHForensicsOutboxItem `
                    -Context $script:context -ResourceKey resource-fixture).Status |
                Should -BeExactly PREPARED
        }

        It 'reconciles an unknown receipt response as <Expected>' -TestCases @(
            @{ Code = 200; Expected = 'ACCEPTED' }
            @{ Code = 507; Expected = 'PAUSED' }
            @{ Code = 409; Expected = 'CONFLICT' }
            @{ Code = 400; Expected = 'REJECTED' }
            @{ Code = 503; Expected = 'UNKNOWN' }
        ) {
            param($Code, $Expected)

            $statusCode = $Code
            $armed = Start-HHForensicsDeliveryAttempt `
                -Context $script:context -ResourceKey resource-fixture `
                -AttemptId reconcile-fixture
            $null = Complete-HHForensicsDeliveryAttempt `
                -Context $script:context -ResourceKey resource-fixture `
                -AttemptNumber $armed.AttemptNumber -Outcome UNKNOWN
            $result = Invoke-HHForensicsReceiptReconciliation `
                -Context $script:context -BaseUri 'http://127.0.0.1:1/' `
                -AccessTokenProvider $script:tokenProvider -ResourceKey resource-fixture `
                -Transport {
                    param($Request)
                    $Request.Method | Should -BeExactly GET
                    [pscustomobject]@{
                        StatusCode = $statusCode
                        Body = if ($statusCode -eq 200) {
                            New-HHForensicsApiTestReceipt `
                                -Item $script:preparedItem -OriginalStatus 201
                        }
                        else {
                            [Text.Encoding]::UTF8.GetBytes('{"code":"FixtureProblem"}')
                        }
                    }
                }
            $result.Status | Should -BeExactly $Expected
        }

        It 'keeps unknown when receipt transport itself is unknown' {
            $armed = Start-HHForensicsDeliveryAttempt `
                -Context $script:context -ResourceKey resource-fixture `
                -AttemptId reconcile-timeout
            $null = Complete-HHForensicsDeliveryAttempt `
                -Context $script:context -ResourceKey resource-fixture `
                -AttemptNumber $armed.AttemptNumber -Outcome UNKNOWN
            $result = Invoke-HHForensicsReceiptReconciliation `
                -Context $script:context -BaseUri 'http://127.0.0.1:1/' `
                -AccessTokenProvider $script:tokenProvider -ResourceKey resource-fixture `
                -Transport { throw 'fixture timeout' }
            $result.Status | Should -BeExactly UNKNOWN
        }

        It 'quarantines a receipt lookup that does not bind to the unknown request' {
            $armed = Start-HHForensicsDeliveryAttempt `
                -Context $script:context -ResourceKey resource-fixture `
                -AttemptId reconcile-mismatch
            $null = Complete-HHForensicsDeliveryAttempt `
                -Context $script:context -ResourceKey resource-fixture `
                -AttemptNumber $armed.AttemptNumber -Outcome UNKNOWN
            $result = Invoke-HHForensicsReceiptReconciliation `
                -Context $script:context -BaseUri 'http://127.0.0.1:1/' `
                -AccessTokenProvider $script:tokenProvider -ResourceKey resource-fixture `
                -Transport {
                    [pscustomobject]@{
                        StatusCode = 200
                        Body = New-HHForensicsApiTestReceipt `
                            -Item $script:preparedItem -ResourceUri '/api/v1/wrong'
                    }
                }
            $result.Status | Should -BeExactly CONFLICT
            $result.LastProblemCode | Should -BeExactly ReceiptBindingMismatch
            (Invoke-HHSqliteScalar -Connection $script:context.Connection `
                    -Sql 'SELECT COUNT(*) FROM forensics_quarantine;') | Should -Be 1
        }

        It 'validates loopback URI problem and transport response edge states' {
            foreach ($uri in @(
                    'relative', 'ftp://127.0.0.1/', 'http://example.test/',
                    'http://user@127.0.0.1/', 'http://127.0.0.1/?query=1',
                    'http://127.0.0.1/#fragment'
                )) {
                { Assert-HHForensicsLoopbackBaseUri -BaseUri $uri } |
                    Should -Throw -ErrorId 'ForensicsApiEndpointRejected*'
            }
            (Assert-HHForensicsLoopbackBaseUri -BaseUri 'http://127.0.0.1:1/').IsLoopback |
                Should -BeTrue

            foreach ($case in @(
                    @{ Body = $null; Expected = 'Http422' },
                    @{ Body = [byte[]]::new(0); Expected = 'Http422' },
                    @{ Body = [Text.Encoding]::UTF8.GetBytes('{"problem":"PolicyDenied"}'); Expected = 'PolicyDenied' },
                    @{ Body = [Text.Encoding]::UTF8.GetBytes('{"type":"urn:fixture"}'); Expected = 'urn:fixture' },
                    @{ Body = [Text.Encoding]::UTF8.GetBytes('{"code":"bad value"}'); Expected = 'Http422' },
                    @{ Body = [byte[]](0xff); Expected = 'Http422' }
                )) {
                Get-HHForensicsApiProblemCode -StatusCode 422 -Body $case.Body |
                    Should -BeExactly $case.Expected
            }

            foreach ($response in @(
                    $null,
                    [pscustomobject]@{ StatusCode = 200 },
                    [pscustomobject]@{ StatusCode = 'bad'; Body = [byte[]]::new(0) },
                    [pscustomobject]@{ StatusCode = 99; Body = [byte[]]::new(0) },
                    [pscustomobject]@{ StatusCode = 600; Body = [byte[]]::new(0) },
                    [pscustomobject]@{ StatusCode = 200; Body = [byte[]]::new(0); DeclaredLength = 'bad' },
                    [pscustomobject]@{ StatusCode = 200; Body = [byte[]]::new(0); DeclaredLength = -1 }
                )) {
                { Assert-HHForensicsTransportResponse -Response $response } |
                    Should -Throw -ErrorId 'ForensicsApiResponseRejected*'
            }
            $accepted = Assert-HHForensicsTransportResponse -Response ([pscustomobject]@{
                    StatusCode = 200; Body = $null; DeclaredLength = 0
                })
            $accepted.StatusCode | Should -Be 200
            $accepted.Body | Should -HaveCount 0
        }
    }
}
