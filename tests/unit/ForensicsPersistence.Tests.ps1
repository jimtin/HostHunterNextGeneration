$sourceRoot = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
    Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration'
}
else { $env:HH_TEST_SOURCE_ROOT }
$module = New-Module -Name HostHunterForensicsPersistenceTest -ArgumentList $sourceRoot -ScriptBlock {
    param($Root)
    $script:HHModuleRoot = $Root
    . (Join-Path $Root 'Private/PersistenceErrors.ps1')
    . (Join-Path $Root 'Private/PersistencePath.ps1')
    . (Join-Path $Root 'Private/SqliteProvider.ps1')
    . (Join-Path $Root 'Private/SqlitePersistence.ps1')
    . (Join-Path $Root 'Forensics/Private/Persistence/ForensicsCrypto.ps1')
    . (Join-Path $Root 'Forensics/Private/Migrations/ForensicsMigrations.ps1')
    . (Join-Path $Root 'Forensics/Private/Persistence/ForensicsPersistence.ps1')
}
$module | Import-Module -Force

Describe 'forensics persistence isolation and cryptography' -Tag Unit {
    InModuleScope HostHunterForensicsPersistenceTest {
        BeforeAll {
            if ([IO.Directory]::Exists('/opt/hosthunter-sqlite/lib')) {
                $env:HH_SQLITE_PROVIDER_ROOT = '/opt/hosthunter-sqlite/lib'
            }
        }

        BeforeEach {
            $script:testRoot = Join-Path $TestDrive ([Guid]::NewGuid().ToString('N'))
            $script:persistence = New-HHForensicsPersistenceContext -DataRoot $script:testRoot
            $script:testKey = [byte[]](1..32)
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
            $script:openContext = $null
        }

        AfterEach {
            if ($null -ne $script:openContext -and $script:openContext.IsUsable) {
                Close-HHForensicsPersistence -Context $script:openContext
            }
        }

        It 'requires an explicit independent 32-byte key and anchor initialization' {
            $contract = Get-HHForensicsProviderContract
            $contract.Schema | Should -BeExactly 'hosthunter.forensics-provider/1'
            $contract.Service | Should -BeExactly 'HostHunterNextGeneration.Forensics.v1'
            $contract.KeyAccount | Should -BeExactly 'ledger-key'
            $contract.AnchorAccount | Should -BeExactly 'ledger-anchor'
            {
                Open-HHForensicsPersistence -PersistenceContext $script:persistence `
                    -ForensicsKeyProvider {
                        [pscustomobject]@{
                            Service = 'HostHunterNextGeneration.Forensics.v1'
                            Account = 'ledger-key'
                            KeyBytes = [byte[]](1, 2, 3)
                        }
                    } `
                    -AnchorReader $script:anchorReader -AnchorWriter $script:anchorWriter `
                    -AllowAnchorInitialize
            } | Should -Throw -ErrorId 'ForensicsKeyUnavailable*'

            {
                Open-HHForensicsPersistence -PersistenceContext $script:persistence `
                    -ForensicsKeyProvider $script:keyProvider `
                    -AnchorReader $script:anchorReader -AnchorWriter $script:anchorWriter
            } | Should -Throw -ErrorId 'ForensicsAnchorRequired*'

            {
                Get-HHForensicsKey -ForensicsKeyProvider { throw 'fixture provider failure' }
            } | Should -Throw -ErrorId 'ForensicsKeyUnavailable*'
            foreach ($invalidProvider in @(
                    { [byte[]](1..32) },
                    {
                        [pscustomobject]@{
                            Service = 'wrong-service'
                            Account = 'ledger-key'
                            KeyBytes = [byte[]](1..32)
                        }
                    },
                    {
                        [pscustomobject]@{
                            Service = 'HostHunterNextGeneration.Forensics.v1'
                            Account = 'wrong-account'
                            KeyBytes = [byte[]](1..32)
                        }
                    }
                )) {
                {
                    Get-HHForensicsKey -ForensicsKeyProvider $invalidProvider
                } | Should -Throw -ErrorId 'ForensicsKeyUnavailable*'
            }
        }

        It 'creates only the dedicated forensics database and preserves the core database' {
            $null = [IO.Directory]::CreateDirectory($script:testRoot)
            $coreBytes = [Text.Encoding]::UTF8.GetBytes('core-database-sentinel')
            [IO.File]::WriteAllBytes($script:persistence.CoreDatabasePath, $coreBytes)

            $script:openContext = Open-HHForensicsPersistence `
                -PersistenceContext $script:persistence `
                -ForensicsKeyProvider $script:keyProvider `
                -AnchorReader $script:anchorReader -AnchorWriter $script:anchorWriter `
                -AllowAnchorInitialize

            [IO.File]::Exists($script:persistence.DatabasePath) | Should -BeTrue
            [IO.File]::ReadAllBytes($script:persistence.CoreDatabasePath) |
                Should -Be $coreBytes
            $script:openContext.Anchor.SchemaVersion | Should -Be 1
            $script:openContext.Anchor.Generation | Should -Be 0
        }

        It 'authenticates encrypted bytes against purpose routing and digest' {
            $plaintext = [Text.Encoding]::UTF8.GetBytes('cmd.exe /c fixture-sensitive-value')
            $digest = Get-HHForensicsHash -Bytes $plaintext
            $envelope = Protect-HHForensicsValue `
                -Plaintext $plaintext -ForensicsKey $script:testKey `
                -Purpose EventBody -RoutingKey event-one -Digest $digest
            [Text.Encoding]::UTF8.GetString($envelope) |
                Should -Not -Match 'fixture-sensitive-value'
            $roundTrip = Unprotect-HHForensicsValue `
                -Envelope $envelope -ForensicsKey $script:testKey `
                -Purpose EventBody -RoutingKey event-one -Digest $digest
            $roundTrip | Should -Be $plaintext

            {
                Unprotect-HHForensicsValue `
                    -Envelope $envelope -ForensicsKey $script:testKey `
                    -Purpose EventBody -RoutingKey event-two -Digest $digest
            } | Should -Throw -ErrorId 'ForensicsIntegrityFailed*'

            foreach ($purpose in @('RequestBody', 'ReceiptBody', 'ResponseBody')) {
                $purposeEnvelope = Protect-HHForensicsValue `
                    -Plaintext $plaintext -ForensicsKey $script:testKey `
                    -Purpose $purpose -RoutingKey event-one -Digest $digest
                (Unprotect-HHForensicsValue `
                        -Envelope $purposeEnvelope -ForensicsKey $script:testKey `
                        -Purpose $purpose -RoutingKey event-one -Digest $digest) |
                    Should -Be $plaintext
            }
            (Test-HHForensicsBytesEqual -Left ([byte[]](1)) -Right ([byte[]](1, 2))) |
                Should -BeFalse
            {
                Get-HHForensicsMac -Key ([byte[]](1, 2)) -Bytes $plaintext
            } | Should -Throw '*32 bytes*'
            {
                Get-HHForensicsAssociatedData `
                    -Purpose EventBody -RoutingKey '   ' -Digest $digest
            } | Should -Throw '*associated data*'
            $badEnvelope = [byte[]]$envelope.Clone()
            $badEnvelope[0] = 0
            {
                Unprotect-HHForensicsValue `
                    -Envelope $badEnvelope -ForensicsKey $script:testKey `
                    -Purpose EventBody -RoutingKey event-one -Digest $digest
            } | Should -Throw -ErrorId 'ForensicsIntegrityFailed*'
        }

        It 'encodes an empty evidence sequence deterministically' {
            $empty = Join-HHForensicsEvidence -Value @()
            $empty | Should -HaveCount 0
        }

        It 'rejects AEAD <Kind> tampering' -TestCases @(
            @{ Kind = 'header'; Index = 0; Purpose = 'EventBody'; Routing = 'event-one'; Digest = 'same' }
            @{ Kind = 'version'; Index = 4; Purpose = 'EventBody'; Routing = 'event-one'; Digest = 'same' }
            @{ Kind = 'purpose header'; Index = 5; Purpose = 'EventBody'; Routing = 'event-one'; Digest = 'same' }
            @{ Kind = 'nonce'; Index = 6; Purpose = 'EventBody'; Routing = 'event-one'; Digest = 'same' }
            @{ Kind = 'tag'; Index = 18; Purpose = 'EventBody'; Routing = 'event-one'; Digest = 'same' }
            @{ Kind = 'ciphertext'; Index = 34; Purpose = 'EventBody'; Routing = 'event-one'; Digest = 'same' }
            @{ Kind = 'AAD purpose'; Index = -1; Purpose = 'RequestBody'; Routing = 'event-one'; Digest = 'same' }
            @{ Kind = 'AAD routing'; Index = -1; Purpose = 'EventBody'; Routing = 'event-two'; Digest = 'same' }
            @{ Kind = 'AAD digest'; Index = -1; Purpose = 'EventBody'; Routing = 'event-one'; Digest = 'other' }
        ) {
            param($Kind, $Index, $Purpose, $Routing, $Digest)

            $null = $Kind
            $selectedPurpose = $Purpose
            $selectedRouting = $Routing
            $plaintext = [Text.Encoding]::UTF8.GetBytes('sensitive-aead-fixture')
            $expectedDigest = Get-HHForensicsHash -Bytes $plaintext
            $envelope = Protect-HHForensicsValue `
                -Plaintext $plaintext -ForensicsKey $script:testKey `
                -Purpose EventBody -RoutingKey event-one -Digest $expectedDigest
            if ($Index -ge 0) { $envelope[$Index] = $envelope[$Index] -bxor 0xff }
            $suppliedDigest = if ($Digest -ceq 'other') {
                Get-HHForensicsHash -Bytes ([Text.Encoding]::UTF8.GetBytes('other'))
            }
            else { $expectedDigest }
            {
                Unprotect-HHForensicsValue `
                    -Envelope $envelope -ForensicsKey $script:testKey `
                    -Purpose $selectedPurpose -RoutingKey $selectedRouting `
                    -Digest $suppliedDigest
            } | Should -Throw -ErrorId 'ForensicsIntegrityFailed*'
        }

        It 'uses a unique random AEAD nonce for identical plaintext' {
            $plaintext = [Text.Encoding]::UTF8.GetBytes('identical-sensitive-value')
            $digest = Get-HHForensicsHash -Bytes $plaintext
            $first = Protect-HHForensicsValue `
                -Plaintext $plaintext -ForensicsKey $script:testKey `
                -Purpose EventBody -RoutingKey event-one -Digest $digest
            $second = Protect-HHForensicsValue `
                -Plaintext $plaintext -ForensicsKey $script:testKey `
                -Purpose EventBody -RoutingKey event-one -Digest $digest
            $first | Should -Not -Be $second
            [Convert]::ToHexString($first[6..17]) |
                Should -Not -BeExactly ([Convert]::ToHexString($second[6..17]))
            (Unprotect-HHForensicsValue `
                    -Envelope $first -ForensicsKey $script:testKey `
                    -Purpose EventBody -RoutingKey event-one -Digest $digest) |
                Should -Be $plaintext
            (Unprotect-HHForensicsValue `
                    -Envelope $second -ForensicsKey $script:testKey `
                    -Purpose EventBody -RoutingKey event-one -Digest $digest) |
                Should -Be $plaintext
        }

        It 'rejects linked or escaped persistence paths and applies owner-only modes' {
            $actualRoot = Join-Path $TestDrive 'actual-root'
            $null = [IO.Directory]::CreateDirectory($actualRoot)
            $linkedRoot = Join-Path $TestDrive 'linked-root'
            $null = [IO.Directory]::CreateSymbolicLink($linkedRoot, $actualRoot)
            {
                New-HHForensicsPersistenceContext -DataRoot $linkedRoot
            } | Should -Throw

            $script:persistence.DatabasePath = Join-Path $TestDrive 'escaped.db'
            {
                Open-HHForensicsPersistence -PersistenceContext $script:persistence `
                    -ForensicsKeyProvider $script:keyProvider `
                    -AnchorReader $script:anchorReader -AnchorWriter $script:anchorWriter `
                    -AllowAnchorInitialize
            } | Should -Throw -ErrorId 'ForensicsPathRejected*'

            $script:persistence = New-HHForensicsPersistenceContext -DataRoot $script:testRoot
            $script:openContext = Open-HHForensicsPersistence `
                -PersistenceContext $script:persistence `
                -ForensicsKeyProvider $script:keyProvider `
                -AnchorReader $script:anchorReader -AnchorWriter $script:anchorWriter `
                -AllowAnchorInitialize
            if (-not $IsWindows) {
                [IO.File]::GetUnixFileMode($script:testRoot) | Should -Be (
                    [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite -bor
                    [IO.UnixFileMode]::UserExecute
                )
                [IO.File]::GetUnixFileMode($script:persistence.DatabasePath) | Should -Be (
                    [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite
                )
                [IO.File]::GetUnixFileMode($script:persistence.LockPath) | Should -Be (
                    [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite
                )
            }
        }

        It 'accepts an existing private root and rejects database directory collisions' {
            $null = [IO.Directory]::CreateDirectory($script:testRoot)
            {
                Assert-HHForensicsStorePath `
                    -PersistenceContext $script:persistence -AllowMissingRoot
            } | Should -Not -Throw

            $null = [IO.Directory]::CreateDirectory($script:persistence.DatabasePath)
            {
                Assert-HHForensicsStorePath `
                    -PersistenceContext $script:persistence -AllowMissingRoot
            } | Should -Throw -ErrorId 'ForensicsPathRejected*'

            $emptyContext = [pscustomobject]@{
                Connection = $null
                WriterLock = $null
                ForensicsKey = $null
                IsUsable = $true
            }
            Close-HHForensicsPersistence -Context $emptyContext
            $emptyContext.IsUsable | Should -BeFalse
        }

        It 'rejects a database or lock symlink' -TestCases @(
            @{ Name = 'forensics.db' }
            @{ Name = 'forensics.writer.lock' }
        ) {
            param($Name)

            $null = [IO.Directory]::CreateDirectory($script:testRoot)
            $sentinel = Join-Path $TestDrive "sentinel-$Name"
            [IO.File]::WriteAllText($sentinel, 'sentinel')
            $null = [IO.File]::CreateSymbolicLink(
                (Join-Path $script:testRoot $Name),
                $sentinel
            )
            {
                Open-HHForensicsPersistence -PersistenceContext $script:persistence `
                    -ForensicsKeyProvider $script:keyProvider `
                    -AnchorReader $script:anchorReader -AnchorWriter $script:anchorWriter `
                    -AllowAnchorInitialize
            } | Should -Throw -ErrorId 'ForensicsPathRejected*'
            [IO.File]::ReadAllText($sentinel) | Should -BeExactly sentinel
        }

        It 'fails closed when the external anchor is missing or ahead' {
            $script:openContext = Open-HHForensicsPersistence `
                -PersistenceContext $script:persistence `
                -ForensicsKeyProvider $script:keyProvider `
                -AnchorReader $script:anchorReader -AnchorWriter $script:anchorWriter `
                -AllowAnchorInitialize
            Close-HHForensicsPersistence -Context $script:openContext
            $script:openContext = $null

            $validAnchor = $script:testAnchor
            $script:testAnchor = $null
            {
                Open-HHForensicsPersistence -PersistenceContext $script:persistence `
                    -ForensicsKeyProvider $script:keyProvider `
                    -AnchorReader $script:anchorReader -AnchorWriter $script:anchorWriter
            } | Should -Throw -ErrorId 'ForensicsAnchorRequired*'

            $script:testAnchor = $validAnchor.PSObject.Copy()
            $script:testAnchor.Generation = 1L
            $script:testAnchor = New-HHForensicsAnchor `
                -DatabaseId $validAnchor.DatabaseId `
                -SchemaFingerprint $validAnchor.SchemaFingerprint `
                -Generation 1 -StateDigest $validAnchor.StateDigest `
                -StateMac $validAnchor.StateMac `
                -ProjectionDigest $validAnchor.ProjectionDigest `
                -ProjectionMac $validAnchor.ProjectionMac -ForensicsKey $script:testKey
            {
                Open-HHForensicsPersistence -PersistenceContext $script:persistence `
                    -ForensicsKeyProvider $script:keyProvider `
                    -AnchorReader $script:anchorReader -AnchorWriter $script:anchorWriter
            } | Should -Throw -ErrorId 'ForensicsRollbackDetected*'
        }

        It 'rejects malformed, unauthenticated, or divergent anchors' {
            $script:openContext = Open-HHForensicsPersistence `
                -PersistenceContext $script:persistence `
                -ForensicsKeyProvider $script:keyProvider `
                -AnchorReader $script:anchorReader -AnchorWriter $script:anchorWriter `
                -AllowAnchorInitialize
            $head = $script:openContext.Anchor
            {
                Test-HHForensicsAnchorMac `
                    -Anchor ([pscustomobject]@{ DatabaseId = $head.DatabaseId }) `
                    -ForensicsKey $script:testKey
            } | Should -Throw -ErrorId 'ForensicsIntegrityFailed*'

            $malformed = $head.PSObject.Copy()
            $malformed.StateMac = [byte[]](1, 2)
            {
                Test-HHForensicsAnchorMac -Anchor $malformed -ForensicsKey $script:testKey
            } | Should -Throw -ErrorId 'ForensicsIntegrityFailed*'

            $tampered = $head.PSObject.Copy()
            $tampered.AnchorMac = [byte[]]::new(32)
            {
                Test-HHForensicsAnchorMac -Anchor $tampered -ForensicsKey $script:testKey
            } | Should -Throw -ErrorId 'ForensicsIntegrityFailed*'

            $otherDatabase = New-HHForensicsAnchor `
                -DatabaseId ([byte[]](0..15)) `
                -SchemaFingerprint $head.SchemaFingerprint -Generation 0 `
                -StateDigest $head.StateDigest -StateMac $head.StateMac `
                -ProjectionDigest $head.ProjectionDigest -ProjectionMac $head.ProjectionMac `
                -ForensicsKey $script:testKey
            {
                Compare-HHForensicsAnchor `
                    -DatabaseHead $head -Anchor $otherDatabase -ForensicsKey $script:testKey
            } | Should -Throw -ErrorId 'ForensicsIntegrityFailed*'

            $otherState = New-HHForensicsAnchor `
                -DatabaseId $head.DatabaseId -SchemaFingerprint $head.SchemaFingerprint `
                -Generation 0 -StateDigest ([byte[]]::new(32)) `
                -StateMac $head.StateMac -ProjectionDigest $head.ProjectionDigest `
                -ProjectionMac $head.ProjectionMac -ForensicsKey $script:testKey
            {
                Compare-HHForensicsAnchor `
                    -DatabaseHead $head -Anchor $otherState -ForensicsKey $script:testKey
            } | Should -Throw -ErrorId 'ForensicsIntegrityFailed*'
        }

        It 'reopens against an equal anchor and rejects a schema-version disagreement' {
            $script:openContext = Open-HHForensicsPersistence `
                -PersistenceContext $script:persistence `
                -ForensicsKeyProvider $script:keyProvider `
                -AnchorReader $script:anchorReader -AnchorWriter $script:anchorWriter `
                -AllowAnchorInitialize
            Close-HHForensicsPersistence -Context $script:openContext
            $script:openContext = Open-HHForensicsPersistence `
                -PersistenceContext $script:persistence `
                -ForensicsKeyProvider $script:keyProvider `
                -AnchorReader $script:anchorReader -AnchorWriter $script:anchorWriter
            $script:openContext.Anchor.Generation | Should -Be 0

            $databaseHead = $script:openContext.Anchor.PSObject.Copy()
            $databaseHead.SchemaVersion = 2
            {
                Compare-HHForensicsAnchor `
                    -DatabaseHead $databaseHead -Anchor $script:testAnchor `
                    -ForensicsKey $script:testKey
            } | Should -Throw -ErrorId 'ForensicsSchemaUnsupported*'
        }

        It 'fails closed on a missing or stale mutation anchor and a failed state CAS' {
            $script:openContext = Open-HHForensicsPersistence `
                -PersistenceContext $script:persistence `
                -ForensicsKeyProvider $script:keyProvider `
                -AnchorReader $script:anchorReader -AnchorWriter $script:anchorWriter `
                -AllowAnchorInitialize
            $initialAnchor = $script:testAnchor
            $payload = Get-HHForensicsHash -Bytes ([byte[]](4))

            $script:testAnchor = $null
            {
                Invoke-HHForensicsAnchoredTransaction `
                    -Context $script:openContext -MutationId missing-anchor `
                    -MutationType Fixture -RoutingKey fixture -PayloadDigest $payload `
                    -Action { }
            } | Should -Throw -ErrorId 'ForensicsAnchorRequired*'
            $script:testAnchor = $initialAnchor

            $null = Invoke-HHForensicsAnchoredTransaction `
                -Context $script:openContext -MutationId first-mutation `
                -MutationType Fixture -RoutingKey fixture -PayloadDigest $payload `
                -Action { }
            $currentAnchor = $script:testAnchor
            $script:testAnchor = $initialAnchor
            {
                Invoke-HHForensicsAnchoredTransaction `
                    -Context $script:openContext -MutationId stale-anchor `
                    -MutationType Fixture -RoutingKey fixture -PayloadDigest $payload `
                    -Action { }
            } | Should -Throw -ErrorId 'ForensicsAnchorAdvanceRequired*'
            $script:testAnchor = $currentAnchor

            {
                Invoke-HHForensicsAnchoredTransaction `
                    -Context $script:openContext -MutationId failed-cas `
                    -MutationType Fixture -RoutingKey fixture -PayloadDigest $payload `
                    -Action {
                        param($Connection, $Transaction, $Key)
                        $null = $Key
                        $null = Invoke-HHSqliteNonQuery `
                            -Connection $Connection -Transaction $Transaction -Sql @'
UPDATE forensics_state SET generation=99 WHERE singleton_id=1;
'@
                    }
            } | Should -Throw '*state head changed*'
            $script:openContext.IsUsable | Should -BeTrue
            (Invoke-HHSqliteScalar -Connection $script:openContext.Connection `
                    -Sql 'SELECT generation FROM forensics_state WHERE singleton_id=1;') |
                Should -Be 1
        }

        It 'detects a discontinuous mutation-chain predecessor' {
            $script:openContext = Open-HHForensicsPersistence `
                -PersistenceContext $script:persistence `
                -ForensicsKeyProvider $script:keyProvider `
                -AnchorReader $script:anchorReader -AnchorWriter $script:anchorWriter `
                -AllowAnchorInitialize
            $payload = Get-HHForensicsHash -Bytes ([byte[]](5))
            $null = Invoke-HHForensicsAnchoredTransaction `
                -Context $script:openContext -MutationId mutation-predecessor `
                -MutationType Fixture -RoutingKey fixture -PayloadDigest $payload `
                -Action { }
            $null = Invoke-HHSqliteNonQuery -Connection $script:openContext.Connection -Sql @'
UPDATE forensics_mutations SET previous_mac=zeroblob(32) WHERE sequence=1;
'@
            {
                Get-HHForensicsDatabaseHead `
                    -Connection $script:openContext.Connection `
                    -ForensicsKey $script:openContext.ForensicsKey `
                    -MigrationPath $script:persistence.MigrationPath
            } | Should -Throw -ErrorId 'ForensicsIntegrityFailed*'
        }

        It 'rejects invalid mutation contexts, chain tampering, and a competing writer' {
            {
                Get-HHForensicsMutationState `
                    -DatabaseId ([byte[]](0..15)) -SchemaFingerprint ([byte[]]::new(32)) `
                    -Sequence 0 -MutationId invalid -MutationType Invalid -RoutingKey invalid `
                    -OccurredAtUtc '2026-08-25T00:00:00Z' `
                    -PayloadDigest ([byte[]]::new(32)) `
                    -ProjectionDigest ([byte[]]::new(32)) `
                    -ProjectionMac ([byte[]]::new(32)) -PreviousMac ([byte[]]::new(32)) `
                    -ForensicsKey $script:testKey
            } | Should -Throw '*malformed*'

            $script:openContext = Open-HHForensicsPersistence `
                -PersistenceContext $script:persistence `
                -ForensicsKeyProvider $script:keyProvider `
                -AnchorReader $script:anchorReader -AnchorWriter $script:anchorWriter `
                -AllowAnchorInitialize
            {
                Open-HHForensicsPersistence -PersistenceContext $script:persistence `
                    -ForensicsKeyProvider $script:keyProvider `
                    -AnchorReader $script:anchorReader -AnchorWriter $script:anchorWriter
            } | Should -Throw -ErrorId 'ForensicsPersistenceBusy*'

            $payload = Get-HHForensicsHash -Bytes ([byte[]](1))
            $null = Invoke-HHForensicsAnchoredTransaction `
                -Context $script:openContext -MutationId mutation-1 `
                -MutationType Fixture -RoutingKey fixture -PayloadDigest $payload `
                -Action {
                    param($Connection, $Transaction, $Key)
                    $null = $Connection
                    $null = $Transaction
                    $null = $Key
                }
            $null = Invoke-HHSqliteNonQuery -Connection $script:openContext.Connection -Sql @'
UPDATE forensics_mutations SET mutation_mac=zeroblob(32) WHERE sequence=1;
'@
            {
                Get-HHForensicsDatabaseHead `
                    -Connection $script:openContext.Connection `
                    -ForensicsKey $script:openContext.ForensicsKey `
                    -MigrationPath $script:persistence.MigrationPath
            } | Should -Throw -ErrorId 'ForensicsIntegrityFailed*'

            $unavailable = $script:openContext.PSObject.Copy()
            $unavailable.IsUsable = $false
            {
                Invoke-HHForensicsAnchoredTransaction `
                    -Context $unavailable -MutationId unavailable -MutationType Fixture `
                    -RoutingKey fixture -PayloadDigest $payload -Action { }
            } | Should -Throw -ErrorId 'ForensicsPersistenceUnavailable*'
        }

        It 'takes the immediate writer transaction before authenticating protected rows' {
            $script:openContext = Open-HHForensicsPersistence `
                -PersistenceContext $script:persistence `
                -ForensicsKeyProvider $script:keyProvider `
                -AnchorReader $script:anchorReader -AnchorWriter $script:anchorWriter `
                -AllowAnchorInitialize
            $payload = Get-HHForensicsHash -Bytes ([byte[]](2))
            $script:externalWriterBlocked = $false
            $script:originalGetDatabaseHead = ${function:Get-HHForensicsDatabaseHead}
            Mock Get-HHForensicsDatabaseHead {
                param($Connection, $ForensicsKey, $MigrationPath, $ProviderRoot, $Transaction)

                $competitor = New-HHSqliteConnection `
                    -DatabasePath $script:persistence.DatabasePath `
                    -Mode ReadWrite -ProviderRoot $script:persistence.ProviderRoot
                try {
                    $command = $competitor.CreateCommand()
                    try {
                        $command.CommandTimeout = 1
                        $command.CommandText = @'
UPDATE forensics_state SET projection_digest=zeroblob(32) WHERE singleton_id=1;
'@
                        $null = $command.ExecuteNonQuery()
                    }
                    catch { $script:externalWriterBlocked = $true }
                    finally { $command.Dispose() }
                }
                finally { $competitor.Dispose() }

                & $script:originalGetDatabaseHead `
                    -Connection $Connection -ForensicsKey $ForensicsKey `
                    -MigrationPath $MigrationPath -ProviderRoot $ProviderRoot `
                    -Transaction $Transaction
            }
            $null = Invoke-HHForensicsAnchoredTransaction `
                -Context $script:openContext -MutationId mutation-locked `
                -MutationType Fixture -RoutingKey fixture -PayloadDigest $payload `
                -Action {
                    param($Connection, $Transaction, $Key)
                    $null = $Connection
                    $null = $Transaction
                    $null = $Key
            }
            $script:externalWriterBlocked | Should -BeTrue
            Should -Invoke Get-HHForensicsDatabaseHead -Times 1 -Exactly
            Invoke-HHSqliteScalar -Connection $script:openContext.Connection `
                -Sql 'SELECT generation FROM forensics_state WHERE singleton_id=1;' |
                Should -Be 1
        }

        It 'rejects an opened-then-restored database-path redirection before the first side effect' {
            $target = Join-Path $TestDrive 'redirection-target.db'
            $targetConnection = New-HHSqliteConnection `
                -DatabasePath $target -Mode ReadWriteCreate `
                -ProviderRoot $script:persistence.ProviderRoot
            try {
                $null = Invoke-HHSqliteNonQuery -Connection $targetConnection -Sql @'
CREATE TABLE sentinel(value TEXT NOT NULL);
INSERT INTO sentinel(value) VALUES('unchanged-target');
'@
            }
            finally { $targetConnection.Dispose() }
            $before = [IO.File]::ReadAllBytes($target)
            {
                Open-HHForensicsPersistence -PersistenceContext $script:persistence `
                    -ForensicsKeyProvider $script:keyProvider `
                    -AnchorReader $script:anchorReader -AnchorWriter $script:anchorWriter `
                    -AllowAnchorInitialize -ConnectionFactory {
                        param($DatabasePath, $Mode, $ProviderRoot)
                        $null = $Mode
                        [IO.File]::Delete($DatabasePath)
                        $null = [IO.File]::CreateSymbolicLink($DatabasePath, $target)
                        $redirected = New-HHSqliteConnection -DatabasePath $DatabasePath `
                            -Mode ReadWriteCreate -ProviderRoot $ProviderRoot
                        [IO.File]::Delete($DatabasePath)
                        [IO.File]::WriteAllBytes($DatabasePath, [byte[]]::new(0))
                        $redirected
                    }
            } | Should -Throw -ErrorId 'ForensicsPathRejected*'
            $after = [IO.File]::ReadAllBytes($target)
            $after.Length | Should -Be $before.Length
            [Convert]::ToBase64String($after) |
                Should -BeExactly ([Convert]::ToBase64String($before))
        }
    }
}
