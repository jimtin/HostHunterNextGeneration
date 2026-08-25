$sourceRoot = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
    Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration'
}
else { $env:HH_TEST_SOURCE_ROOT }
$script:dockerProviderModule = Import-Module (
    Join-Path $sourceRoot 'HostHunterNextGeneration.psd1'
) -Force -PassThru

AfterAll {
    Remove-Module HostHunterNextGeneration -Force -ErrorAction SilentlyContinue
}

Describe 'Docker-volume persistence provider' -Tag Unit -Skip:(!$IsLinux) {
    InModuleScope HostHunterNextGeneration {
        BeforeAll {
            function Initialize-HHTestDockerProviderRootSet {
                [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
                    'PSUseShouldProcessForStateChangingFunctions',
                    '',
                    Justification = 'Creates isolated TestDrive fixtures only.'
                )]
                param([Parameter(Mandatory)][string]$Prefix)

                $data = Join-Path $TestDrive "$Prefix-data"
                $secret = Join-Path $TestDrive "$Prefix-secret"
                $anchor = Join-Path $TestDrive "$Prefix-anchor"
                $mode = [IO.UnixFileMode]::UserRead -bor
                    [IO.UnixFileMode]::UserWrite -bor [IO.UnixFileMode]::UserExecute
                foreach ($path in @($data, $secret, $anchor)) {
                    $null = [IO.Directory]::CreateDirectory($path)
                    [IO.File]::SetUnixFileMode($path, $mode)
                }
                return [pscustomobject]@{
                    Data = [IO.Path]::GetFullPath($data)
                    Secret = [IO.Path]::GetFullPath($secret)
                    Anchor = [IO.Path]::GetFullPath($anchor)
                }
            }

            function New-HHTestCoreAnchor {
                [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
                    'PSUseShouldProcessForStateChangingFunctions',
                    '',
                    Justification = 'Creates an in-memory test fixture only.'
                )]
                param([long]$Generation = 0, [byte]$Offset = 0)

                return [pscustomobject]@{
                    DatabaseId = [byte[]](0..15 | ForEach-Object {
                            [byte]($_ + $Offset)
                        })
                    LedgerId = [byte[]](16..31 | ForEach-Object {
                            [byte]($_ + $Offset)
                        })
                    SchemaVersion = 1
                    AuditSequence = $Generation
                    AuditMac = [byte[]](32..63 | ForEach-Object {
                            [byte]($_ + $Offset)
                        })
                    TargetGeneration = $Generation
                    TargetStateMac = [byte[]](64..95 | ForEach-Object {
                            [byte]($_ + $Offset)
                        })
                    SchemaFingerprint = [byte[]](96..127 | ForEach-Object {
                            [byte]($_ + $Offset)
                        })
                    ConfigurationGeneration = $Generation
                    ConfigurationStateMac = [byte[]](128..159 | ForEach-Object {
                            [byte]($_ + $Offset)
                        })
                }
            }

            function New-HHTestDockerForensicsAnchor {
                [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
                    'PSUseShouldProcessForStateChangingFunctions',
                    '',
                    Justification = 'Creates an in-memory test fixture only.'
                )]
                param([long]$Generation = 0, [byte]$Offset = 0)

                return [pscustomobject]@{
                    Schema = 'hosthunter.forensics-anchor/1'
                    Service = 'HostHunterNextGeneration.Forensics.v1'
                    Account = 'ledger-anchor'
                    DatabaseId = [byte[]](0..15 | ForEach-Object {
                            [byte]($_ + $Offset)
                        })
                    SchemaVersion = 1L
                    SchemaFingerprint = [byte[]](16..47 | ForEach-Object {
                            [byte]($_ + $Offset)
                        })
                    Generation = $Generation
                    StateDigest = [byte[]](48..79 | ForEach-Object {
                            [byte]($_ + $Offset)
                        })
                    StateMac = [byte[]](80..111 | ForEach-Object {
                            [byte]($_ + $Offset)
                        })
                    ProjectionDigest = [byte[]](112..143 | ForEach-Object {
                            [byte]($_ + $Offset)
                        })
                    ProjectionMac = [byte[]](144..175 | ForEach-Object {
                            [byte]($_ + $Offset)
                        })
                    AnchorMac = [byte[]](176..207 | ForEach-Object {
                            [byte]($_ + $Offset)
                        })
                }
            }

            function New-HHTestDockerProvider {
                [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
                    'PSUseShouldProcessForStateChangingFunctions',
                    '',
                    Justification = 'Creates isolated TestDrive provider state only.'
                )]
                param([Parameter(Mandatory)][string]$Prefix)

                $roots = Initialize-HHTestDockerProviderRootSet -Prefix $Prefix
                $provider = New-HHDockerVolumePersistenceProvider `
                    -DataRoot $roots.Data -SecretRoot $roots.Secret `
                    -AnchorRoot $roots.Anchor
                return [pscustomobject]@{ Roots = $roots; Provider = $provider }
            }
        }

        BeforeEach {
            $env:HH_COVERAGE_CASE = [Guid]::NewGuid().ToString('N')
            $env:HH_SECRET_PROVIDER = $null
            $env:HH_SECRET_ROOT = $null
            $env:HH_ANCHOR_ROOT = $null
        }

        AfterEach {
            $env:HH_SECRET_PROVIDER = $null
            $env:HH_SECRET_ROOT = $null
            $env:HH_ANCHOR_ROOT = $null
        }

        It 'returns a byte-free versioned callback contract and private domain roots' {
            $fixture = New-HHTestDockerProvider -Prefix 'contract'
            $provider = $fixture.Provider

            $provider.ProviderId | Should -BeExactly 'hosthunter.docker-volume'
            $provider.ProviderVersion | Should -Be 1
            $provider.DataRoot | Should -BeExactly $fixture.Roots.Data
            $provider.SecretRoot | Should -BeExactly $fixture.Roots.Secret
            $provider.AnchorRoot | Should -BeExactly $fixture.Roots.Anchor
            foreach ($name in @(
                    'CoreMasterKeyProvider', 'CoreAnchorReader', 'CoreAnchorWriter',
                    'ForensicsKeyProvider', 'ForensicsAnchorReader',
                    'ForensicsAnchorWriter'
                )) {
                $provider.$name | Should -BeOfType ([scriptblock])
            }
            @($provider.PSObject.Properties.Value | Where-Object { $_ -is [byte[]] }).Count |
                Should -Be 0
            foreach ($path in @(
                    (Join-Path $fixture.Roots.Secret 'core'),
                    (Join-Path $fixture.Roots.Secret 'forensics'),
                    (Join-Path $fixture.Roots.Anchor 'core'),
                    (Join-Path $fixture.Roots.Anchor 'forensics')
                )) {
                [IO.File]::GetUnixFileMode($path) | Should -Be (
                    [IO.UnixFileMode]::UserRead -bor
                    [IO.UnixFileMode]::UserWrite -bor
                    [IO.UnixFileMode]::UserExecute
                )
            }
        }

        It 'creates immutable domain-separated keys with exact private modes and reloads them' {
            $fixture = New-HHTestDockerProvider -Prefix 'keys'
            $context = [pscustomobject]@{ DataRoot = $fixture.Roots.Data }
            $coreFirst = & $fixture.Provider.CoreMasterKeyProvider $context $false
            $coreSecond = & $fixture.Provider.CoreMasterKeyProvider $context $true
            $forensicsFirst = & $fixture.Provider.ForensicsKeyProvider
            $forensicsSecond = & $fixture.Provider.ForensicsKeyProvider
            try {
                $coreFirst.Length | Should -Be 32
                [Security.Cryptography.CryptographicOperations]::FixedTimeEquals(
                    $coreFirst,
                    $coreSecond
                ) | Should -BeTrue
                [Security.Cryptography.CryptographicOperations]::FixedTimeEquals(
                    $forensicsFirst.KeyBytes,
                    $forensicsSecond.KeyBytes
                ) | Should -BeTrue
                [Security.Cryptography.CryptographicOperations]::FixedTimeEquals(
                    $coreFirst,
                    $forensicsFirst.KeyBytes
                ) | Should -BeFalse
                foreach ($path in @(
                        $fixture.Provider.Paths.CoreKey,
                        $fixture.Provider.Paths.ForensicsKey
                    )) {
                    [IO.File]::GetUnixFileMode($path) | Should -Be (
                        [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite
                    )
                    [IO.FileInfo]::new($path).Length | Should -Be 144
                    [IO.FileInfo]::new($path).LinkTarget | Should -BeNullOrEmpty
                }
            }
            finally {
                [Array]::Clear($coreFirst, 0, $coreFirst.Length)
                [Array]::Clear($coreSecond, 0, $coreSecond.Length)
                [Array]::Clear($forensicsFirst.KeyBytes, 0, 32)
                [Array]::Clear($forensicsSecond.KeyBytes, 0, 32)
            }
        }

        It 'round-trips and compare-and-swaps authenticated core anchors' {
            $fixture = New-HHTestDockerProvider -Prefix 'core-anchor'
            $context = [pscustomobject]@{ DataRoot = $fixture.Roots.Data }
            $key = & $fixture.Provider.CoreMasterKeyProvider $context $false
            $initialArtifact = ConvertTo-HHPersistenceAnchorArtifact `
                -Anchor (New-HHTestCoreAnchor) -MasterKey $key
            $advancedArtifact = ConvertTo-HHPersistenceAnchorArtifact `
                -Anchor (New-HHTestCoreAnchor -Generation 1 -Offset 1) -MasterKey $key
            try {
                & $fixture.Provider.CoreAnchorWriter $context $null $initialArtifact $key
                (& $fixture.Provider.CoreAnchorReader $context $key).AuditSequence |
                    Should -Be 0
                & $fixture.Provider.CoreAnchorWriter $context $initialArtifact `
                    $advancedArtifact $key
                (& $fixture.Provider.CoreAnchorReader $context $key).AuditSequence |
                    Should -Be 1
                {
                    & $fixture.Provider.CoreAnchorWriter $context $initialArtifact `
                        $advancedArtifact $key
                } | Should -Throw -ErrorId 'DockerVolumeAnchorCompareFailed*'
                foreach ($path in @(
                        $fixture.Provider.Paths.CoreAnchor,
                        $fixture.Provider.Paths.CoreAnchorLock
                    )) {
                    [IO.File]::GetUnixFileMode($path) | Should -Be (
                        [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite
                    )
                }
            }
            finally {
                [Array]::Clear($key, 0, $key.Length)
                [Array]::Clear($initialArtifact, 0, $initialArtifact.Length)
                [Array]::Clear($advancedArtifact, 0, $advancedArtifact.Length)
            }
        }

        It 'round-trips and compare-and-swaps authenticated forensics anchors' {
            $fixture = New-HHTestDockerProvider -Prefix 'forensics-anchor'
            $context = [pscustomobject]@{ DataRoot = $fixture.Roots.Data }
            $initial = New-HHTestDockerForensicsAnchor
            $advanced = New-HHTestDockerForensicsAnchor -Generation 1 -Offset 1

            & $fixture.Provider.ForensicsAnchorWriter $null $initial $context
            (& $fixture.Provider.ForensicsAnchorReader $context).Generation | Should -Be 0
            & $fixture.Provider.ForensicsAnchorWriter $initial $advanced $context
            (& $fixture.Provider.ForensicsAnchorReader $context).Generation | Should -Be 1
            {
                & $fixture.Provider.ForensicsAnchorWriter $initial $advanced $context
            } | Should -Throw -ErrorId 'DockerVolumeAnchorCompareFailed*'
        }

        It 'fails closed when existing core or forensics state has no key' {
            $fixture = New-HHTestDockerProvider -Prefix 'missing-key'
            $context = [pscustomobject]@{ DataRoot = $fixture.Roots.Data }

            { & $fixture.Provider.CoreMasterKeyProvider $context $true } |
                Should -Throw -ErrorId 'DockerVolumeKeyUnavailable*'
            [IO.File]::WriteAllBytes(
                (Join-Path $fixture.Roots.Data 'forensics.db'),
                [byte[]]::new(0)
            )
            {
                & $fixture.Provider.ForensicsKeyProvider
            } | Should -Throw -ErrorId 'DockerVolumeKeyUnavailable*'
            Test-Path -LiteralPath $fixture.Provider.Paths.CoreKey | Should -BeFalse
            Test-Path -LiteralPath $fixture.Provider.Paths.ForensicsKey | Should -BeFalse
        }

        It 'rejects a different callback data root without creating state' {
            $fixture = New-HHTestDockerProvider -Prefix 'wrong-context'
            $wrong = [pscustomobject]@{
                DataRoot = Join-Path $TestDrive 'some-other-data-root'
            }

            { & $fixture.Provider.CoreMasterKeyProvider $wrong $false } |
                Should -Throw -ErrorId 'DockerVolumeProviderMismatch*'
            {
                & $fixture.Provider.ForensicsAnchorReader $wrong
            } | Should -Throw -ErrorId 'DockerVolumeProviderMismatch*'
            $readerKey = [byte[]](0..31)
            try {
                { & $fixture.Provider.CoreAnchorReader $wrong $readerKey } |
                    Should -Throw -ErrorId 'DockerVolumeProviderMismatch*'
            }
            finally { [Array]::Clear($readerKey, 0, $readerKey.Length) }
            Test-Path -LiteralPath $fixture.Provider.Paths.CoreKey | Should -BeFalse
        }

        It 'rejects roots that are relative, overlapping, missing, linked, or too permissive' {
            $roots = Initialize-HHTestDockerProviderRootSet -Prefix 'bad-roots'
            {
                New-HHDockerVolumePersistenceProvider -DataRoot $roots.Data `
                    -SecretRoot relative -AnchorRoot $roots.Anchor
            } | Should -Throw -ErrorId 'DockerVolumeProviderPathInvalid*'
            {
                New-HHDockerVolumePersistenceProvider -DataRoot $roots.Data `
                    -SecretRoot $roots.Data -AnchorRoot $roots.Anchor
            } | Should -Throw -ErrorId 'DockerVolumeProviderPathInvalid*'
            {
                New-HHDockerVolumePersistenceProvider -DataRoot $roots.Data `
                    -SecretRoot (Join-Path $TestDrive 'missing-secret') `
                    -AnchorRoot $roots.Anchor
            } | Should -Throw -ErrorId 'DockerVolumeProviderPathInvalid*'

            [IO.File]::SetUnixFileMode(
                $roots.Secret,
                [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite -bor
                [IO.UnixFileMode]::UserExecute -bor [IO.UnixFileMode]::GroupRead
            )
            {
                New-HHDockerVolumePersistenceProvider -DataRoot $roots.Data `
                    -SecretRoot $roots.Secret -AnchorRoot $roots.Anchor
            } | Should -Throw -ErrorId 'DockerVolumeProviderPathUnsafe*'

            $linkedRoot = Join-Path $TestDrive 'linked-secret-root'
            [IO.Directory]::CreateSymbolicLink($linkedRoot, $roots.Anchor) | Out-Null
            {
                New-HHDockerVolumePersistenceProvider -DataRoot $roots.Data `
                    -SecretRoot $linkedRoot -AnchorRoot $roots.Anchor
            } | Should -Throw -ErrorId 'DockerVolumeProviderPathUnsafe*'
        }

        It 'rejects key files that are linked, non-regular, or not exactly mode 0600' {
            foreach ($kind in @('mode', 'link', 'dangling-link', 'directory')) {
                $fixture = New-HHTestDockerProvider -Prefix "bad-key-$kind"
                $context = [pscustomobject]@{ DataRoot = $fixture.Roots.Data }
                $key = & $fixture.Provider.CoreMasterKeyProvider $context $false
                [Array]::Clear($key, 0, $key.Length)
                if ($kind -eq 'mode') {
                    [IO.File]::SetUnixFileMode(
                        $fixture.Provider.Paths.CoreKey,
                        [IO.UnixFileMode]::UserRead -bor
                        [IO.UnixFileMode]::UserWrite -bor [IO.UnixFileMode]::GroupRead
                    )
                }
                elseif ($kind -eq 'link') {
                    $outside = Join-Path $TestDrive 'outside-private-key'
                    [IO.File]::Move($fixture.Provider.Paths.CoreKey, $outside)
                    [IO.File]::CreateSymbolicLink(
                        $fixture.Provider.Paths.CoreKey,
                        $outside
                    ) | Out-Null
                }
                elseif ($kind -eq 'dangling-link') {
                    [IO.File]::Delete($fixture.Provider.Paths.CoreKey)
                    [IO.File]::CreateSymbolicLink(
                        $fixture.Provider.Paths.CoreKey,
                        (Join-Path $TestDrive 'missing-link-target')
                    ) | Out-Null
                }
                else {
                    [IO.File]::Delete($fixture.Provider.Paths.CoreKey)
                    [IO.Directory]::CreateDirectory($fixture.Provider.Paths.CoreKey) |
                        Out-Null
                }
                { & $fixture.Provider.CoreMasterKeyProvider $context $true } |
                    Should -Throw -ErrorId 'DockerVolumeProviderFileUnsafe*'
            }
        }

        It 'rejects swapped core and forensics keys by domain binding' {
            $fixture = New-HHTestDockerProvider -Prefix 'swapped-keys'
            $context = [pscustomobject]@{ DataRoot = $fixture.Roots.Data }
            $core = & $fixture.Provider.CoreMasterKeyProvider $context $false
            $forensics = & $fixture.Provider.ForensicsKeyProvider
            [Array]::Clear($core, 0, $core.Length)
            [Array]::Clear($forensics.KeyBytes, 0, 32)
            $coreEnvelope = [IO.File]::ReadAllBytes($fixture.Provider.Paths.CoreKey)
            $forensicsEnvelope = [IO.File]::ReadAllBytes(
                $fixture.Provider.Paths.ForensicsKey
            )
            try {
                [IO.File]::WriteAllBytes(
                    $fixture.Provider.Paths.CoreKey,
                    $forensicsEnvelope
                )
                [IO.File]::WriteAllBytes(
                    $fixture.Provider.Paths.ForensicsKey,
                    $coreEnvelope
                )
                { & $fixture.Provider.CoreMasterKeyProvider $context $true } |
                    Should -Throw -ErrorId 'DockerVolumeProviderMismatch*'
                { & $fixture.Provider.ForensicsKeyProvider } |
                    Should -Throw -ErrorId 'DockerVolumeProviderMismatch*'
            }
            finally {
                [Array]::Clear($coreEnvelope, 0, $coreEnvelope.Length)
                [Array]::Clear($forensicsEnvelope, 0, $forensicsEnvelope.Length)
            }
        }

        It 'rejects provider-version, provider-id, binding, and authentication tampering' {
            foreach ($offset in @(10, 12, 44, 143)) {
                $fixture = New-HHTestDockerProvider -Prefix "tamper-$offset"
                $context = [pscustomobject]@{ DataRoot = $fixture.Roots.Data }
                $key = & $fixture.Provider.CoreMasterKeyProvider $context $false
                [Array]::Clear($key, 0, $key.Length)
                $envelope = [IO.File]::ReadAllBytes($fixture.Provider.Paths.CoreKey)
                try {
                    $envelope[$offset] = $envelope[$offset] -bxor 1
                    [IO.File]::WriteAllBytes($fixture.Provider.Paths.CoreKey, $envelope)
                    { & $fixture.Provider.CoreMasterKeyProvider $context $true } |
                        Should -Throw
                }
                finally { [Array]::Clear($envelope, 0, $envelope.Length) }
            }
        }

        It 'rejects an anchor whose permissions or authenticated bytes changed' {
            foreach ($kind in @('mode', 'tamper')) {
                $fixture = New-HHTestDockerProvider -Prefix "bad-anchor-$kind"
                $context = [pscustomobject]@{ DataRoot = $fixture.Roots.Data }
                $key = & $fixture.Provider.CoreMasterKeyProvider $context $false
                $artifact = ConvertTo-HHPersistenceAnchorArtifact `
                    -Anchor (New-HHTestCoreAnchor) -MasterKey $key
                & $fixture.Provider.CoreAnchorWriter $context $null $artifact $key
                if ($kind -eq 'mode') {
                    [IO.File]::SetUnixFileMode(
                        $fixture.Provider.Paths.CoreAnchor,
                        [IO.UnixFileMode]::UserRead -bor
                        [IO.UnixFileMode]::UserWrite -bor [IO.UnixFileMode]::GroupRead
                    )
                }
                else {
                    $envelope = [IO.File]::ReadAllBytes(
                        $fixture.Provider.Paths.CoreAnchor
                    )
                    $envelope[90] = $envelope[90] -bxor 1
                    [IO.File]::WriteAllBytes(
                        $fixture.Provider.Paths.CoreAnchor,
                        $envelope
                    )
                    [Array]::Clear($envelope, 0, $envelope.Length)
                }
                { & $fixture.Provider.CoreAnchorReader $context $key } | Should -Throw
                [Array]::Clear($key, 0, $key.Length)
                [Array]::Clear($artifact, 0, $artifact.Length)
            }
        }

        It 'binds existing files to their original canonical data root' {
            $fixture = New-HHTestDockerProvider -Prefix 'root-binding'
            $context = [pscustomobject]@{ DataRoot = $fixture.Roots.Data }
            $key = & $fixture.Provider.CoreMasterKeyProvider $context $false
            [Array]::Clear($key, 0, $key.Length)
            $otherData = Join-Path $TestDrive 'root-binding-other-data'
            [IO.Directory]::CreateDirectory($otherData) | Out-Null
            [IO.File]::SetUnixFileMode(
                $otherData,
                [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite -bor
                [IO.UnixFileMode]::UserExecute
            )
            $other = New-HHDockerVolumePersistenceProvider -DataRoot $otherData `
                -SecretRoot $fixture.Roots.Secret -AnchorRoot $fixture.Roots.Anchor
            {
                & $other.CoreMasterKeyProvider (
                    [pscustomobject]@{ DataRoot = $otherData }
                ) $true
            } | Should -Throw -ErrorId 'DockerVolumeProviderMismatch*'
        }

        It 'selects DockerVolume only by its exact name and requires both absolute roots' {
            Get-HHSecretProviderSelection | Should -BeExactly 'PlatformNative'
            foreach ($invalid in @('dockerVolume', 'File', 'PlatformNative')) {
                $env:HH_SECRET_PROVIDER = $invalid
                { Get-HHSecretProviderSelection } |
                    Should -Throw -ErrorId 'DockerVolumeProviderSelectionInvalid*'
            }
            $env:HH_SECRET_PROVIDER = 'DockerVolume'
            { Get-HHDockerVolumePersistenceProviderFromEnvironment -DataRoot $TestDrive } |
                Should -Throw -ErrorId 'DockerVolumeProviderPathInvalid*'
            $roots = Initialize-HHTestDockerProviderRootSet -Prefix 'env-provider'
            $env:HH_SECRET_ROOT = $roots.Secret
            $env:HH_ANCHOR_ROOT = $roots.Anchor
            $provider = Get-HHDockerVolumePersistenceProviderFromEnvironment `
                -DataRoot $roots.Data
            $provider.ProviderId | Should -BeExactly 'hosthunter.docker-volume'
        }

        It 'wires core key and anchor selection without changing native defaults' {
            $roots = Initialize-HHTestDockerProviderRootSet -Prefix 'env-wiring'
            $env:HH_SECRET_PROVIDER = 'DockerVolume'
            $env:HH_SECRET_ROOT = $roots.Secret
            $env:HH_ANCHOR_ROOT = $roots.Anchor
            $context = Get-HHPersistenceContext -DataRoot $roots.Data
            $key = Get-HHMasterKey -DataRoot $roots.Data
            $anchor = New-HHTestCoreAnchor
            try {
                Write-HHPersistenceAnchor -PersistenceContext $context -Anchor $anchor `
                    -MasterKey $key -ExpectedArtifact $null
                (Read-HHPersistenceAnchor -PersistenceContext $context -MasterKey $key).
                    AuditSequence | Should -Be 0
                Test-Path -LiteralPath $context.AnchorPath | Should -BeFalse
                Test-Path -LiteralPath (
                    Join-Path $context.AuditRoot 'audit.key'
                ) | Should -BeFalse
            }
            finally { [Array]::Clear($key, 0, $key.Length) }

            $env:HH_SECRET_PROVIDER = $null
            $nativeRoots = Initialize-HHTestDockerProviderRootSet -Prefix 'native-default'
            $nativeKey = Get-HHMasterKey -DataRoot $nativeRoots.Data
            try {
                Test-Path -LiteralPath (
                    Join-Path $nativeRoots.Data 'audit/audit.key'
                ) | Should -BeTrue
            }
            finally { [Array]::Clear($nativeKey, 0, $nativeKey.Length) }
        }

        It 'rejects platform, filesystem-root, and unselected environment use' {
            $roots = Initialize-HHTestDockerProviderRootSet -Prefix 'guard-roots'
            {
                New-HHDockerVolumePersistenceProvider -DataRoot $roots.Data `
                    -SecretRoot ([IO.Path]::GetPathRoot($roots.Secret)) `
                    -AnchorRoot $roots.Anchor
            } | Should -Throw -ErrorId 'DockerVolumeProviderPathInvalid*'
            {
                Get-HHDockerVolumePersistenceProviderFromEnvironment `
                    -DataRoot $roots.Data
            } | Should -Throw -ErrorId 'DockerVolumeProviderSelectionInvalid*'

            $savedIsLinux = $IsLinux
            Set-Variable -Name IsLinux -Scope Script -Value $false -Force
            try {
                {
                    New-HHDockerVolumePersistenceProvider -DataRoot $roots.Data `
                        -SecretRoot $roots.Secret -AnchorRoot $roots.Anchor
                } | Should -Throw -ErrorId 'DockerVolumeProviderPlatformInvalid*'
            }
            finally {
                Set-Variable -Name IsLinux -Scope Script -Value $savedIsLinux -Force
            }
        }

        It 'returns null from both domain readers before an anchor exists' {
            $fixture = New-HHTestDockerProvider -Prefix 'missing-anchor'
            $context = [pscustomobject]@{ DataRoot = $fixture.Roots.Data }
            $key = & $fixture.Provider.CoreMasterKeyProvider $context $false
            try {
                (& $fixture.Provider.CoreAnchorReader $context $key) |
                    Should -BeNullOrEmpty
                (& $fixture.Provider.ForensicsAnchorReader $context) |
                    Should -BeNullOrEmpty
            }
            finally { [Array]::Clear($key, 0, $key.Length) }
        }

        It 'rejects writer callbacks invoked for a different data root' {
            $fixture = New-HHTestDockerProvider -Prefix 'wrong-writer-root'
            $context = [pscustomobject]@{ DataRoot = $fixture.Roots.Data }
            $wrong = [pscustomobject]@{ DataRoot = Join-Path $TestDrive 'wrong-root' }
            $key = & $fixture.Provider.CoreMasterKeyProvider $context $false
            $coreArtifact = ConvertTo-HHPersistenceAnchorArtifact `
                -Anchor (New-HHTestCoreAnchor) -MasterKey $key
            try {
                {
                    & $fixture.Provider.CoreAnchorWriter $wrong $null $coreArtifact $key
                } | Should -Throw -ErrorId 'DockerVolumeProviderMismatch*'
                {
                    & $fixture.Provider.ForensicsAnchorWriter $null `
                        (New-HHTestDockerForensicsAnchor) $wrong
                } | Should -Throw -ErrorId 'DockerVolumeProviderMismatch*'
            }
            finally {
                [Array]::Clear($key, 0, $key.Length)
                [Array]::Clear($coreArtifact, 0, $coreArtifact.Length)
            }
        }

        It 'rejects malformed envelope inputs before any filesystem mutation' {
            $key = [byte[]](0..31)
            try {
                {
                    New-HHDockerVolumeEnvelope -Kind Key -Domain core `
                        -DataRoot $TestDrive -Payload ([byte[]](1, 2))
                } | Should -Throw -ErrorId 'DockerVolumeProviderArtifactInvalid*'
                {
                    New-HHDockerVolumeEnvelope -Kind Anchor -Domain core `
                        -DataRoot $TestDrive -Payload ([byte[]]::new(196))
                } | Should -Throw -ErrorId 'DockerVolumeProviderArtifactInvalid*'
                {
                    ConvertFrom-HHDockerVolumeEnvelope -Kind Key -Domain core `
                        -DataRoot $TestDrive -Envelope ([byte[]]::new(20)) `
                        -AllowedPayloadLength @(32)
                } | Should -Throw -ErrorId 'DockerVolumeProviderArtifactInvalid*'

                $envelope = New-HHDockerVolumeEnvelope -Kind Anchor -Domain core `
                    -DataRoot $TestDrive -Payload ([byte[]]::new(196)) -MacKey $key
                try {
                    {
                        ConvertFrom-HHDockerVolumeEnvelope -Kind Anchor -Domain core `
                            -DataRoot $TestDrive -Envelope $envelope `
                            -AllowedPayloadLength @(196)
                    } | Should -Throw -ErrorId 'DockerVolumeProviderArtifactInvalid*'
                    $envelope[79] = 195
                    {
                        ConvertFrom-HHDockerVolumeEnvelope -Kind Anchor -Domain core `
                            -DataRoot $TestDrive -Envelope $envelope `
                            -AllowedPayloadLength @(196) -MacKey $key
                    } | Should -Throw -ErrorId 'DockerVolumeProviderArtifactInvalid*'
                }
                finally { [Array]::Clear($envelope, 0, $envelope.Length) }
            }
            finally { [Array]::Clear($key, 0, $key.Length) }
        }

        It 'rejects bounded-length, exclusive-read, lock-mode, and lock-timeout failures' {
            $fixture = New-HHTestDockerProvider -Prefix 'io-failures'
            $context = [pscustomobject]@{ DataRoot = $fixture.Roots.Data }
            [IO.File]::WriteAllBytes(
                $fixture.Provider.Paths.CoreKey,
                [byte[]](1, 2, 3)
            )
            [IO.File]::SetUnixFileMode(
                $fixture.Provider.Paths.CoreKey,
                [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite
            )
            { & $fixture.Provider.CoreMasterKeyProvider $context $true } |
                Should -Throw -ErrorId 'DockerVolumeProviderArtifactInvalid*'
            [IO.File]::Delete($fixture.Provider.Paths.CoreKey)

            $key = & $fixture.Provider.CoreMasterKeyProvider $context $false
            $artifact = ConvertTo-HHPersistenceAnchorArtifact `
                -Anchor (New-HHTestCoreAnchor) -MasterKey $key
            & $fixture.Provider.CoreAnchorWriter $context $null $artifact $key
            $exclusiveAnchor = [IO.File]::Open(
                $fixture.Provider.Paths.CoreAnchor,
                [IO.FileMode]::Open,
                [IO.FileAccess]::ReadWrite,
                [IO.FileShare]::None
            )
            try {
                { & $fixture.Provider.CoreAnchorReader $context $key } |
                    Should -Throw -ErrorId 'DockerVolumeProviderFileUnsafe*'
            }
            finally { $exclusiveAnchor.Dispose() }

            [IO.File]::SetUnixFileMode(
                $fixture.Provider.Paths.CoreAnchorLock,
                [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite -bor
                [IO.UnixFileMode]::GroupRead
            )
            {
                & $fixture.Provider.CoreAnchorWriter $context $artifact $artifact $key
            } | Should -Throw -ErrorId 'DockerVolumeProviderFileUnsafe*'
            [IO.File]::SetUnixFileMode(
                $fixture.Provider.Paths.CoreAnchorLock,
                [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite
            )

            $heldLock = [IO.File]::Open(
                $fixture.Provider.Paths.CoreAnchorLock,
                [IO.FileMode]::Open,
                [IO.FileAccess]::ReadWrite,
                [IO.FileShare]::None
            )
            $savedTimeout = $script:HHDockerVolumeLockTimeoutMilliseconds
            $script:HHDockerVolumeLockTimeoutMilliseconds = 40
            try {
                {
                    & $fixture.Provider.CoreAnchorWriter $context $artifact $artifact $key
                } | Should -Throw -ErrorId 'DockerVolumeProviderBusy*'
            }
            finally {
                $script:HHDockerVolumeLockTimeoutMilliseconds = $savedTimeout
                $heldLock.Dispose()
                [Array]::Clear($key, 0, $key.Length)
                [Array]::Clear($artifact, 0, $artifact.Length)
            }
        }

        It 'rejects invalid direct anchor lengths without creating a lock' {
            $fixture = New-HHTestDockerProvider -Prefix 'invalid-anchor-length'
            $key = [byte[]](0..31)
            try {
                {
                    Write-HHDockerVolumeAnchorPayload `
                        -Path $fixture.Provider.Paths.CoreAnchor `
                        -LockPath $fixture.Provider.Paths.CoreAnchorLock `
                        -Domain core -DataRoot $fixture.Roots.Data `
                        -ExpectedPayload $null -NewPayload ([byte[]]::new(10)) `
                        -MacKey $key
                } | Should -Throw -ErrorId 'DockerVolumeProviderArtifactInvalid*'
                Test-Path -LiteralPath $fixture.Provider.Paths.CoreAnchorLock |
                    Should -BeFalse
            }
            finally { [Array]::Clear($key, 0, $key.Length) }
        }

        It 'fails closed when private-file metadata inspection itself fails' {
            $path = Join-Path $TestDrive 'metadata-inspection.key'
            [IO.File]::WriteAllBytes($path, [byte[]](0..31))
            [IO.File]::SetUnixFileMode(
                $path,
                [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite
            )
            Mock Get-Item { throw 'fixture metadata failure' } -ParameterFilter {
                $LiteralPath -eq $path
            }
            { Test-HHDockerVolumePrivateFile -Path $path } |
                Should -Throw -ErrorId 'DockerVolumeProviderFileUnsafe*'
        }

        It 'reloads the provider declarations without changing the versioned contract' {
            . (Join-Path $script:HHModuleRoot 'Private/DockerVolumePersistence.ps1')
            $script:HHDockerVolumeProviderId |
                Should -BeExactly 'hosthunter.docker-volume'
            $script:HHDockerVolumeProviderVersion | Should -Be 1
        }

        It 'returns null when a forensics anchor disappears after its safe precheck' {
            $fixture = New-HHTestDockerProvider -Prefix 'anchor-disappeared'
            $context = [pscustomobject]@{ DataRoot = $fixture.Roots.Data }
            $providedKey = & $fixture.Provider.ForensicsKeyProvider
            [Array]::Clear($providedKey.KeyBytes, 0, $providedKey.KeyBytes.Length)
            [IO.File]::WriteAllBytes(
                $fixture.Provider.Paths.ForensicsAnchor,
                [byte[]]::new(352)
            )
            [IO.File]::SetUnixFileMode(
                $fixture.Provider.Paths.ForensicsAnchor,
                [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite
            )
            Mock Read-HHDockerVolumeAnchorPayload { return $null }

            (& $fixture.Provider.ForensicsAnchorReader $context) |
                Should -BeNullOrEmpty
        }
    }
}
