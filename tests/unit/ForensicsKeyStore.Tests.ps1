$sourceRoot = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
    Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration'
}
else { $env:HH_TEST_SOURCE_ROOT }
$module = New-Module -Name HostHunterForensicsKeyStoreTest -ArgumentList $sourceRoot -ScriptBlock {
    param($Root)
    $script:HHModuleRoot = $Root
    . (Join-Path $Root 'Private/ForensicsKeyStore.ps1')
}
$module | Import-Module -Force

Describe 'macOS Forensics Keychain provider' -Tag Unit {
    InModuleScope HostHunterForensicsKeyStoreTest {
        BeforeAll {
            function New-HHTestForensicsAnchor {
                [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
                    'PSUseShouldProcessForStateChangingFunctions',
                    '',
                    Justification = 'Builds an in-memory test fixture only.'
                )]
                param([long]$Generation = 0, [byte]$Offset = 0)

                [pscustomobject]@{
                    Schema = 'hosthunter.forensics-anchor/1'
                    Service = 'HostHunterNextGeneration.Forensics.v1'
                    Account = 'ledger-anchor'
                    DatabaseId = [byte[]](0..15 | ForEach-Object { [byte]($_ + $Offset) })
                    SchemaVersion = 1L
                    SchemaFingerprint = [byte[]](16..47 | ForEach-Object { [byte]($_ + $Offset) })
                    Generation = $Generation
                    StateDigest = [byte[]](48..79 | ForEach-Object { [byte]($_ + $Offset) })
                    StateMac = [byte[]](80..111 | ForEach-Object { [byte]($_ + $Offset) })
                    ProjectionDigest = [byte[]](112..143 | ForEach-Object {
                            [byte]($_ + $Offset)
                        })
                    ProjectionMac = [byte[]](144..175 | ForEach-Object {
                            [byte]($_ + $Offset)
                        })
                    AnchorMac = [byte[]](176..207 | ForEach-Object { [byte]($_ + $Offset) })
                }
            }

            function New-HHTestSecurityResult {
                [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
                    'PSUseShouldProcessForStateChangingFunctions',
                    '',
                    Justification = 'Builds an in-memory test fixture only.'
                )]
                param(
                    [int]$ExitCode = 0,
                    [string]$StandardOutput = '"/tmp/login.keychain-db"',
                    [string]$StandardError = ''
                )

                [pscustomobject]@{
                    ExitCode = $ExitCode
                    StandardOutput = $StandardOutput
                    StandardError = $StandardError
                }
            }
        }

        BeforeEach {
            $script:securityInvoker = { New-HHTestSecurityResult }
            $script:workerCalls = [Collections.Generic.List[object]]::new()
        }

        It 'derives a stable lowercase account from canonical data-root bytes' {
            $withSeparator = "$TestDrive$([IO.Path]::DirectorySeparatorChar)"
            $first = Get-HHForensicsKeychainAccount -DataRoot $TestDrive
            $second = Get-HHForensicsKeychainAccount -DataRoot $withSeparator

            $first | Should -Be $second
            $first | Should -Match '^[0-9a-f]{64}$'
            $first | Should -Not -Match ([regex]::Escape($TestDrive))
            Get-HHForensicsKeychainAccount -DataRoot (
                [IO.Path]::GetPathRoot($TestDrive)
            ) | Should -Match '^[0-9a-f]{64}$'
            { Get-HHForensicsKeychainAccount -DataRoot ' ' } | Should -Throw '*must not be empty*'
        }

        It 'round-trips the strict versioned 240-byte anchor artifact' {
            $anchor = New-HHTestForensicsAnchor -Generation 7
            $artifact = ConvertTo-HHForensicsAnchorArtifact -Anchor $anchor
            $actual = ConvertFrom-HHForensicsAnchorArtifact -Artifact $artifact

            $artifact.Length | Should -Be 240
            [Text.Encoding]::ASCII.GetString($artifact, 0, 8) | Should -BeExactly 'HHFANCH1'
            $actual.DatabaseId | Should -Be $anchor.DatabaseId
            $actual.SchemaVersion | Should -Be 1
            $actual.SchemaFingerprint | Should -Be $anchor.SchemaFingerprint
            $actual.Generation | Should -Be 7
            $actual.StateDigest | Should -Be $anchor.StateDigest
            $actual.StateMac | Should -Be $anchor.StateMac
            $actual.ProjectionDigest | Should -Be $anchor.ProjectionDigest
            $actual.ProjectionMac | Should -Be $anchor.ProjectionMac
            $actual.AnchorMac | Should -Be $anchor.AnchorMac
            $actual.Schema | Should -BeExactly 'hosthunter.forensics-anchor/1'
            $actual.Service | Should -BeExactly 'HostHunterNextGeneration.Forensics.v1'
            $actual.Account | Should -BeExactly 'ledger-anchor'
        }

        It 'rejects malformed anchor objects, length, magic, and versions' {
            { ConvertTo-HHForensicsAnchorArtifact -Anchor ([pscustomobject]@{}) } |
                Should -Throw '*incomplete*'
            $badAnchor = New-HHTestForensicsAnchor
            $badAnchor.Generation = -1
            { ConvertTo-HHForensicsAnchorArtifact -Anchor $badAnchor } |
                Should -Throw '*malformed*'
            { ConvertFrom-HHForensicsAnchorArtifact -Artifact ([byte[]]::new(239)) } |
                Should -Throw '*240 bytes*'

            $artifact = ConvertTo-HHForensicsAnchorArtifact -Anchor (New-HHTestForensicsAnchor)
            $artifact[0] = 0
            { ConvertFrom-HHForensicsAnchorArtifact -Artifact $artifact } |
                Should -Throw '*header*'
            $artifact = ConvertTo-HHForensicsAnchorArtifact -Anchor (New-HHTestForensicsAnchor)
            $artifact[8] = 2
            { ConvertFrom-HHForensicsAnchorArtifact -Artifact $artifact } |
                Should -Throw '*version*'
        }

        It 'returns a clone of an existing exact 32-byte key and clears worker output' {
            $workerBytes = [byte[]](1..32)
            $workerInvoker = {
                param($WorkerPath, $PowerShellPath, $Action, $KeychainPath,
                    $Service, $Account, $InputBytes, $TimeoutSeconds)
                $null = @($WorkerPath, $PowerShellPath, $KeychainPath, $Account,
                    $InputBytes, $TimeoutSeconds)
                $Action | Should -BeExactly 'ReadKey'
                $Service | Should -BeExactly 'com.hosthunter.nextgeneration.forensics-key.v1'
                [pscustomobject]@{ ExitCode = 0; OutputBytes = $workerBytes }
            }.GetNewClosure()

            $actual = Get-HHMacOSForensicsKey -DataRoot $TestDrive `
                -SecurityCommandInvoker $script:securityInvoker `
                -KeychainWorkerInvoker $workerInvoker

            $actual | Should -Be ([byte[]](1..32))
            @($workerBytes | Where-Object { $_ -ne 0 }).Count | Should -Be 0
        }

        It 'creates a random missing key, verifies it, and handles a duplicate winner' {
            foreach ($createExit in @(0, 11)) {
                $state = [pscustomobject]@{ ReadCount = 0; Candidate = $null }
                $calls = [Collections.Generic.List[object]]::new()
                $workerInvoker = {
                    param($WorkerPath, $PowerShellPath, $Action, $KeychainPath,
                        $Service, $Account, $InputBytes, $TimeoutSeconds)
                    $null = @($WorkerPath, $PowerShellPath, $KeychainPath, $Service,
                        $Account, $TimeoutSeconds)
                    $calls.Add($Action) | Out-Null
                    if ($Action -eq 'ReadKey') {
                        $state.ReadCount++
                        if ($state.ReadCount -eq 1) {
                            return [pscustomobject]@{
                                ExitCode = 10
                                OutputBytes = [byte[]]::new(0)
                            }
                        }
                        [byte[]]$bytes = if ($createExit -eq 0) {
                            $state.Candidate.Clone()
                        }
                        else { [byte[]](101..132) }
                        return [pscustomobject]@{ ExitCode = 0; OutputBytes = $bytes }
                    }
                    $state.Candidate = [byte[]]$InputBytes.Clone()
                    [pscustomobject]@{
                        ExitCode = $createExit
                        OutputBytes = [byte[]]::new(0)
                    }
                }.GetNewClosure()

                $key = Get-HHMacOSForensicsKey -DataRoot $TestDrive `
                    -SecurityCommandInvoker $script:securityInvoker `
                    -KeychainWorkerInvoker $workerInvoker

                $key.Length | Should -Be 32
                $calls | Should -Be @('ReadKey', 'CreateKey', 'ReadKey')
                $state.Candidate.Length | Should -Be 32
                @($state.Candidate | Where-Object { $_ -ne 0 }).Count | Should -BeGreaterThan 0
            }
        }

        It 'fails closed on malformed key results without including raw diagnostics' {
            foreach ($result in @(
                    [pscustomobject]@{ ExitCode = 0; OutputBytes = [byte[]](1, 2) },
                    [pscustomobject]@{ ExitCode = 12; OutputBytes = [byte[]]::new(0) },
                    [pscustomobject]@{ ExitCode = 'invalid'; OutputBytes = [byte[]]::new(0) },
                    [pscustomobject]@{ ExitCode = 0 }
                )) {
                $workerInvoker = { $result }.GetNewClosure()
                { Get-HHMacOSForensicsKey -DataRoot $TestDrive `
                        -SecurityCommandInvoker $script:securityInvoker `
                        -KeychainWorkerInvoker $workerInvoker } |
                    Should -Throw -ErrorId 'ForensicsKey*'
            }
            $sensitive = 'raw-provider-secret-diagnostic'
            $workerInvoker = { throw $sensitive }.GetNewClosure()
            try {
                $null = Get-HHMacOSForensicsKey -DataRoot $TestDrive `
                    -SecurityCommandInvoker $script:securityInvoker `
                    -KeychainWorkerInvoker $workerInvoker
                throw 'Expected failure was not raised.'
            }
            catch {
                $_.Exception.Message | Should -Not -Match $sensitive
            }
        }

        It 'fails closed when key creation or authoritative readback is not exact' {
            $createOutput = [byte[]](1, 2, 3)
            $createFailure = {
                param($WorkerPath, $PowerShellPath, $Action)
                $null = @($WorkerPath, $PowerShellPath)
                if ($Action -eq 'ReadKey') {
                    return [pscustomobject]@{
                        ExitCode = 10
                        OutputBytes = [byte[]]::new(0)
                    }
                }
                [pscustomobject]@{ ExitCode = 12; OutputBytes = $createOutput }
            }.GetNewClosure()
            { Get-HHMacOSForensicsKey -DataRoot $TestDrive `
                    -SecurityCommandInvoker $script:securityInvoker `
                    -KeychainWorkerInvoker $createFailure } |
                Should -Throw -ErrorId 'ForensicsKeyUnavailable*'
            @($createOutput | Where-Object { $_ -ne 0 }).Count | Should -Be 0

            $readState = [pscustomobject]@{ Count = 0 }
            $missingReadback = {
                param($WorkerPath, $PowerShellPath, $Action)
                $null = @($WorkerPath, $PowerShellPath)
                if ($Action -eq 'ReadKey') {
                    $readState.Count++
                    return [pscustomobject]@{
                        ExitCode = 10
                        OutputBytes = [byte[]]::new(0)
                    }
                }
                [pscustomobject]@{ ExitCode = 0; OutputBytes = [byte[]]::new(0) }
            }.GetNewClosure()
            { Get-HHMacOSForensicsKey -DataRoot $TestDrive `
                    -SecurityCommandInvoker $script:securityInvoker `
                    -KeychainWorkerInvoker $missingReadback } |
                Should -Throw -ErrorId 'ForensicsKeyUnavailable*'
            $readState.Count | Should -Be 2

            $readState = [pscustomobject]@{ Count = 0 }
            $differentKey = [byte[]](101..132)
            $mismatchReadback = {
                param($WorkerPath, $PowerShellPath, $Action)
                $null = @($WorkerPath, $PowerShellPath)
                if ($Action -eq 'ReadKey') {
                    $readState.Count++
                    if ($readState.Count -eq 1) {
                        return [pscustomobject]@{
                            ExitCode = 10
                            OutputBytes = [byte[]]::new(0)
                        }
                    }
                    return [pscustomobject]@{
                        ExitCode = 0
                        OutputBytes = $differentKey
                    }
                }
                [pscustomobject]@{ ExitCode = 0; OutputBytes = [byte[]]::new(0) }
            }.GetNewClosure()
            { Get-HHMacOSForensicsKey -DataRoot $TestDrive `
                    -SecurityCommandInvoker $script:securityInvoker `
                    -KeychainWorkerInvoker $mismatchReadback } |
                Should -Throw -ErrorId 'ForensicsKeyUnavailable*'
            @($differentKey | Where-Object { $_ -ne 0 }).Count | Should -Be 0
        }

        It 'creates only when missing and verifies exact anchor readback' {
            $anchor = New-HHTestForensicsAnchor
            $artifact = ConvertTo-HHForensicsAnchorArtifact -Anchor $anchor
            $calls = $script:workerCalls
            $workerInvoker = {
                param($WorkerPath, $PowerShellPath, $Action, $KeychainPath,
                    $Service, $Account, $InputBytes, $TimeoutSeconds)
                $null = @($WorkerPath, $PowerShellPath, $KeychainPath, $Account, $TimeoutSeconds)
                $calls.Add([pscustomobject]@{
                        Action = $Action
                        Service = $Service
                        InputBytes = if ($null -eq $InputBytes) {
                            $null
                        }
                        else { [byte[]]$InputBytes.Clone() }
                    }) | Out-Null
                if ($Action -eq 'ReadAnchor') {
                    return [pscustomobject]@{
                        ExitCode = 0
                        OutputBytes = [byte[]]$artifact.Clone()
                    }
                }
                [pscustomobject]@{ ExitCode = 0; OutputBytes = [byte[]]::new(0) }
            }.GetNewClosure()

            Write-HHMacOSForensicsAnchor -ExpectedAnchor $null -NewAnchor $anchor `
                -DataRoot $TestDrive -SecurityCommandInvoker $script:securityInvoker `
                -KeychainWorkerInvoker $workerInvoker

            @($calls.Action) | Should -Be @('CreateAnchor', 'ReadAnchor')
            $calls[0].InputBytes | Should -Be $artifact
            $calls[0].Service |
                Should -BeExactly 'com.hosthunter.nextgeneration.forensics-anchor.v1'

            $duplicateInvoker = {
                [pscustomobject]@{ ExitCode = 11; OutputBytes = [byte[]]::new(0) }
            }
            { Write-HHMacOSForensicsAnchor -ExpectedAnchor $null -NewAnchor $anchor `
                    -DataRoot $TestDrive -SecurityCommandInvoker $script:securityInvoker `
                    -KeychainWorkerInvoker $duplicateInvoker } |
                Should -Throw -ErrorId 'ForensicsIntegrityFailed*'
        }

        It 'uses exact expected/current CAS and rejects compare mismatch' {
            $expected = New-HHTestForensicsAnchor
            $next = New-HHTestForensicsAnchor -Generation 1 -Offset 1
            $expectedBytes = ConvertTo-HHForensicsAnchorArtifact -Anchor $expected
            $nextBytes = ConvertTo-HHForensicsAnchorArtifact -Anchor $next
            $captured = [pscustomobject]@{ Input = $null }
            $successInvoker = {
                param($WorkerPath, $PowerShellPath, $Action, $KeychainPath,
                    $Service, $Account, $InputBytes, $TimeoutSeconds)
                $null = @($WorkerPath, $PowerShellPath, $KeychainPath, $Service,
                    $Account, $TimeoutSeconds)
                $Action | Should -BeExactly 'CompareUpdateAnchor'
                $captured.Input = [byte[]]$InputBytes.Clone()
                [pscustomobject]@{
                    ExitCode = 0
                    OutputBytes = [byte[]]$nextBytes.Clone()
                }
            }.GetNewClosure()
            { Write-HHMacOSForensicsAnchor -ExpectedAnchor $expected -NewAnchor $next `
                    -DataRoot $TestDrive -SecurityCommandInvoker $script:securityInvoker `
                    -KeychainWorkerInvoker $successInvoker } | Should -Not -Throw
                    $captured.Input[0..239] | Should -Be $expectedBytes
                    $captured.Input[240..479] | Should -Be $nextBytes

            $mismatchInvoker = {
                [pscustomobject]@{ ExitCode = 16; OutputBytes = [byte[]]::new(0) }
            }
            { Write-HHMacOSForensicsAnchor -ExpectedAnchor $expected -NewAnchor $next `
                    -DataRoot $TestDrive -SecurityCommandInvoker $script:securityInvoker `
                    -KeychainWorkerInvoker $mismatchInvoker } |
                Should -Throw -ErrorId 'ForensicsIntegrityFailed*'
        }

        It 'rejects inexact create and CAS readback outcomes' {
            $initial = New-HHTestForensicsAnchor
            $advanced = New-HHTestForensicsAnchor -Generation 1 -Offset 1
            $badReadback = [byte[]]::new(240)
            $createInvoker = {
                param($WorkerPath, $PowerShellPath, $Action)
                $null = @($WorkerPath, $PowerShellPath)
                if ($Action -eq 'CreateAnchor') {
                    return [pscustomobject]@{
                        ExitCode = 0
                        OutputBytes = [byte[]]::new(0)
                    }
                }
                [pscustomobject]@{ ExitCode = 0; OutputBytes = $badReadback }
            }.GetNewClosure()
            { Write-HHMacOSForensicsAnchor -ExpectedAnchor $null -NewAnchor $initial `
                    -DataRoot $TestDrive -SecurityCommandInvoker $script:securityInvoker `
                    -KeychainWorkerInvoker $createInvoker } |
                Should -Throw -ErrorId 'ForensicsIntegrityFailed*'
            @($badReadback | Where-Object { $_ -ne 0 }).Count | Should -Be 0

            $casOutput = [byte[]](1, 2, 3)
            $casInvoker = {
                [pscustomobject]@{ ExitCode = 12; OutputBytes = $casOutput }
            }.GetNewClosure()
            { Write-HHMacOSForensicsAnchor -ExpectedAnchor $initial -NewAnchor $advanced `
                    -DataRoot $TestDrive -SecurityCommandInvoker $script:securityInvoker `
                    -KeychainWorkerInvoker $casInvoker } |
                Should -Throw -ErrorId 'ForensicsIntegrityFailed*'
            @($casOutput | Where-Object { $_ -ne 0 }).Count | Should -Be 0
        }

        It 'reads missing as null and rejects corrupt anchor bytes' {
            $missingInvoker = {
                [pscustomobject]@{ ExitCode = 10; OutputBytes = [byte[]]::new(0) }
            }
            Read-HHMacOSForensicsAnchor -DataRoot $TestDrive `
                -SecurityCommandInvoker $script:securityInvoker `
                -KeychainWorkerInvoker $missingInvoker | Should -BeNullOrEmpty
            $badInvoker = {
                [pscustomobject]@{ ExitCode = 0; OutputBytes = [byte[]]::new(175) }
            }
            { Read-HHMacOSForensicsAnchor -DataRoot $TestDrive `
                    -SecurityCommandInvoker $script:securityInvoker `
                    -KeychainWorkerInvoker $badInvoker } |
                Should -Throw -ErrorId 'ForensicsIntegrityFailed*'
        }

        It 'returns persistence-compatible callbacks bound to one data root' {
            $providerKey = [byte[]](1..32)
            $providerAnchor = [pscustomobject]@{ Bytes = $null }
            $provider = New-HHMacOSForensicsProvider -DataRoot $TestDrive `
                -SecurityCommandInvoker $script:securityInvoker `
                -KeychainWorkerInvoker { param($WorkerPath, $PowerShellPath, $Action,
                    $KeychainPath, $Service, $Account, $InputBytes)
                    $null = @($WorkerPath, $PowerShellPath, $KeychainPath, $Service, $Account)
                    if ($Action -eq 'ReadKey') {
                        return [pscustomobject]@{
                            ExitCode = 0
                            OutputBytes = [byte[]]$providerKey.Clone()
                        }
                    }
                    if ($Action -eq 'CreateAnchor') {
                        $providerAnchor.Bytes = [byte[]]$InputBytes.Clone()
                        return [pscustomobject]@{
                            ExitCode = 0
                            OutputBytes = [byte[]]::new(0)
                        }
                    }
                    if ($Action -eq 'ReadAnchor' -and $null -ne $providerAnchor.Bytes) {
                        return [pscustomobject]@{
                            ExitCode = 0
                            OutputBytes = [byte[]]$providerAnchor.Bytes.Clone()
                        }
                    }
                    [pscustomobject]@{
                        ExitCode = 10
                        OutputBytes = [byte[]]::new(0)
                    }
                }.GetNewClosure()
            $provider.ForensicsKeyProvider | Should -BeOfType ([scriptblock])
            $provider.AnchorReader | Should -BeOfType ([scriptblock])
            $provider.AnchorWriter | Should -BeOfType ([scriptblock])
            $provider.KeyLabel | Should -BeExactly 'HostHunter Next Generation Forensics Key'
            $provider.AnchorLabel | Should -BeExactly 'HostHunter Next Generation Forensics Anchor'
            $providedKey = & $provider.ForensicsKeyProvider
            $providedKey.Service | Should -BeExactly 'HostHunterNextGeneration.Forensics.v1'
            $providedKey.Account | Should -BeExactly 'ledger-key'
            $providedKey.KeyBytes | Should -Be $providerKey
            & $provider.AnchorReader ([pscustomobject]@{ DataRoot = $TestDrive }) |
                Should -BeNullOrEmpty
            $providerAnchorValue = New-HHTestForensicsAnchor
            { & $provider.AnchorWriter $null $providerAnchorValue `
                    ([pscustomobject]@{ DataRoot = $TestDrive }) } |
                Should -Not -Throw
            { & $provider.AnchorReader ([pscustomobject]@{
                        DataRoot = Join-Path $TestDrive 'different'
                    }) } | Should -Throw -ErrorId 'ForensicsKeychainUnavailable*'
            { & $provider.AnchorWriter $null $providerAnchorValue `
                    ([pscustomobject]@{
                            DataRoot = Join-Path $TestDrive 'different'
                        }) } | Should -Throw -ErrorId 'ForensicsKeychainUnavailable*'
        }

        It 'qualifies create, CAS, readback, and exact two-item cleanup through the seam' {
            $initial = New-HHTestForensicsAnchor
            $advanced = New-HHTestForensicsAnchor -Generation 1 -Offset 1
            $state = @{}
            $actions = [Collections.Generic.List[string]]::new()
            $workerInvoker = {
                param($WorkerPath, $PowerShellPath, $Action, $KeychainPath,
                    $Service, $Account, $InputBytes, $TimeoutSeconds)
                $null = @($WorkerPath, $PowerShellPath, $KeychainPath, $Account, $TimeoutSeconds)
                $actions.Add("$Action|$Service") | Out-Null
                if ($Action -in @('ReadKey', 'ReadAnchor')) {
                    if (-not $state.ContainsKey($Service)) {
                        return [pscustomobject]@{
                            ExitCode = 10
                            OutputBytes = [byte[]]::new(0)
                        }
                    }
                    return [pscustomobject]@{
                        ExitCode = 0
                        OutputBytes = [byte[]]$state[$Service].Clone()
                    }
                }
                if ($Action -in @('CreateKey', 'CreateAnchor')) {
                    if ($state.ContainsKey($Service)) {
                        return [pscustomobject]@{
                            ExitCode = 11
                            OutputBytes = [byte[]]::new(0)
                        }
                    }
                    $state[$Service] = [byte[]]$InputBytes.Clone()
                    return [pscustomobject]@{ ExitCode = 0; OutputBytes = [byte[]]::new(0) }
                }
                if ($Action -eq 'CompareUpdateAnchor') {
                    $expected = [byte[]]$InputBytes[0..239]
                    $replacement = [byte[]]$InputBytes[240..479]
                    if (-not [Security.Cryptography.CryptographicOperations]::FixedTimeEquals(
                            [byte[]]$state[$Service],
                            $expected
                        )) {
                        return [pscustomobject]@{
                            ExitCode = 16
                            OutputBytes = [byte[]]::new(0)
                        }
                    }
                    $state[$Service] = [byte[]]$replacement.Clone()
                    return [pscustomobject]@{
                        ExitCode = 0
                        OutputBytes = [byte[]]$replacement.Clone()
                    }
                }
                $state.Remove($Service)
                [pscustomobject]@{ ExitCode = 0; OutputBytes = [byte[]]::new(0) }
            }.GetNewClosure()

            $qualificationRoot = Join-Path $TestDrive (
                'hosthunter-forensics-keychain-qualification-' +
                [Guid]::NewGuid().ToString('N')
            )
            $receipt = Test-HHMacOSForensicsKeychainLifecycle `
                -DataRoot $qualificationRoot `
                -InitialAnchor $initial -AdvancedAnchor $advanced `
                -SecurityCommandInvoker $script:securityInvoker `
                -KeychainWorkerInvoker $workerInvoker

            $receipt.Status | Should -BeExactly 'Passed'
            $receipt.CleanupComplete | Should -BeTrue
            $receipt.Redacted | Should -BeTrue
            $state.Count | Should -Be 0
            @($actions | Where-Object { $_ -like 'Delete|*' }).Count | Should -Be 2
            { Test-HHMacOSForensicsKeychainLifecycle `
                    -DataRoot $TestDrive -InitialAnchor $initial -AdvancedAnchor $advanced `
                    -SecurityCommandInvoker $script:securityInvoker `
                    -KeychainWorkerInvoker $workerInvoker } |
                Should -Throw '*unique disposable data root*'
        }

        It 'fails closed on lifecycle drift, pre-key failure, and cleanup failure' {
            $initial = New-HHTestForensicsAnchor
            $advanced = New-HHTestForensicsAnchor -Generation 1 -Offset 1
            $unexpected = New-HHTestForensicsAnchor -Generation 2 -Offset 2
            $unexpectedBytes = ConvertTo-HHForensicsAnchorArtifact -Anchor $unexpected
            $lifecycleState = [pscustomobject]@{
                Key = $null
                Anchor = $null
                AnchorReads = 0
            }
            $driftInvoker = {
                param($WorkerPath, $PowerShellPath, $Action, $KeychainPath,
                    $Service, $Account, $InputBytes)
                $null = @($WorkerPath, $PowerShellPath, $KeychainPath, $Service, $Account)
                if ($Action -eq 'ReadKey') {
                    if ($null -eq $lifecycleState.Key) {
                        return [pscustomobject]@{
                            ExitCode = 10
                            OutputBytes = [byte[]]::new(0)
                        }
                    }
                    return [pscustomobject]@{
                        ExitCode = 0
                        OutputBytes = [byte[]]$lifecycleState.Key.Clone()
                    }
                }
                if ($Action -eq 'CreateKey') {
                    $lifecycleState.Key = [byte[]]$InputBytes.Clone()
                    return [pscustomobject]@{
                        ExitCode = 0
                        OutputBytes = [byte[]]::new(0)
                    }
                }
                if ($Action -eq 'CreateAnchor') {
                    $lifecycleState.Anchor = [byte[]]$InputBytes.Clone()
                    return [pscustomobject]@{
                        ExitCode = 0
                        OutputBytes = [byte[]]::new(0)
                    }
                }
                if ($Action -eq 'ReadAnchor') {
                    $lifecycleState.AnchorReads++
                    [byte[]]$bytes = if ($lifecycleState.AnchorReads -eq 1) {
                        [byte[]]$lifecycleState.Anchor.Clone()
                    }
                    else { [byte[]]$unexpectedBytes.Clone() }
                    return [pscustomobject]@{ ExitCode = 0; OutputBytes = $bytes }
                }
                if ($Action -eq 'CompareUpdateAnchor') {
                    $replacement = [byte[]]$InputBytes[240..479]
                    $lifecycleState.Anchor = [byte[]]$replacement.Clone()
                    return [pscustomobject]@{
                        ExitCode = 0
                        OutputBytes = [byte[]]$replacement.Clone()
                    }
                }
                [pscustomobject]@{ ExitCode = 0; OutputBytes = [byte[]]::new(0) }
            }.GetNewClosure()
            $driftRoot = Join-Path $TestDrive (
                'hosthunter-forensics-keychain-qualification-' +
                [Guid]::NewGuid().ToString('N')
            )
            { Test-HHMacOSForensicsKeychainLifecycle -DataRoot $driftRoot `
                    -InitialAnchor $initial -AdvancedAnchor $advanced `
                    -SecurityCommandInvoker $script:securityInvoker `
                    -KeychainWorkerInvoker $driftInvoker } |
                Should -Throw -ErrorId 'ForensicsIntegrityFailed*'

            $preKeyFailureInvoker = {
                param($WorkerPath, $PowerShellPath, $Action)
                $null = @($WorkerPath, $PowerShellPath)
                if ($Action -eq 'Delete') {
                    return [pscustomobject]@{
                        ExitCode = 0
                        OutputBytes = [byte[]]::new(0)
                    }
                }
                [pscustomobject]@{ ExitCode = 12; OutputBytes = [byte[]]::new(0) }
            }
            $preKeyRoot = Join-Path $TestDrive (
                'hosthunter-forensics-keychain-qualification-' +
                [Guid]::NewGuid().ToString('N')
            )
            { Test-HHMacOSForensicsKeychainLifecycle -DataRoot $preKeyRoot `
                    -InitialAnchor $initial -AdvancedAnchor $advanced `
                    -SecurityCommandInvoker $script:securityInvoker `
                    -KeychainWorkerInvoker $preKeyFailureInvoker } |
                Should -Throw -ErrorId 'ForensicsKeyUnavailable*'

            $cleanupFailureInvoker = {
                param($WorkerPath, $PowerShellPath, $Action)
                $null = @($WorkerPath, $PowerShellPath)
                $Action | Should -BeIn @('ReadKey', 'Delete')
                [pscustomobject]@{
                    ExitCode = 12
                    OutputBytes = [byte[]]::new(0)
                }
            }
            $cleanupRoot = Join-Path $TestDrive (
                'hosthunter-forensics-keychain-qualification-' +
                [Guid]::NewGuid().ToString('N')
            )
            { Test-HHMacOSForensicsKeychainLifecycle -DataRoot $cleanupRoot `
                    -InitialAnchor $initial -AdvancedAnchor $advanced `
                    -SecurityCommandInvoker $script:securityInvoker `
                    -KeychainWorkerInvoker $cleanupFailureInvoker } |
                Should -Throw -ErrorId 'ForensicsKeychainUnavailable*'
        }

        It 'validates every framed login-keychain result without leaking diagnostics' {
            (Get-HHForensicsLoginKeychainPath -SecurityCommandInvoker {
                    New-HHTestSecurityResult -StandardOutput "  `"/tmp/login keychain-db`"  `r`n"
                }) | Should -BeExactly '/tmp/login keychain-db'
            (Get-HHForensicsLoginKeychainPath -SecurityCommandInvoker {
                    New-HHTestSecurityResult -StandardOutput "`"/tmp/login.keychain-db`"`n"
                }) | Should -BeExactly '/tmp/login.keychain-db'

            foreach ($invoker in @(
                    { throw 'private diagnostic' },
                    { $null },
                    { [pscustomobject]@{ ExitCode = 'bad'; StandardOutput = ''; StandardError = '' } },
                    { New-HHTestSecurityResult -ExitCode 1 },
                    { New-HHTestSecurityResult -StandardOutput 'relative.keychain-db' },
                    { New-HHTestSecurityResult -StandardOutput '""' },
                    { New-HHTestSecurityResult -StandardOutput (
                            '"/tmp/invalid' + [char]0 + '.keychain-db"'
                        ) }
                )) {
                { Get-HHForensicsLoginKeychainPath -SecurityCommandInvoker $invoker } |
                    Should -Throw -ErrorId 'ForensicsKeychainUnavailable*'
            }
        }

        It 'clears nullable and populated memory streams at the secret boundary' {
            { Clear-HHForensicsMemoryStream -Stream $null } | Should -Not -Throw
            $stream = [IO.MemoryStream]::new()
            try {
                $stream.Write([byte[]](1, 2, 3, 4), 0, 4)
                Clear-HHForensicsMemoryStream -Stream $stream
                $segment = [ArraySegment[byte]]::new([byte[]]::new(0))
                $stream.TryGetBuffer([ref]$segment) | Should -BeTrue
                @($segment.Array[0..3] | Where-Object { $_ -ne 0 }).Count | Should -Be 0
            }
            finally { $stream.Dispose() }

            $backing = [byte[]](1, 2, 3, 4)
            $privateStream = [IO.MemoryStream]::new($backing, 0, 4, $true, $false)
            try {
                { Clear-HHForensicsMemoryStream -Stream $privateStream } |
                    Should -Not -Throw
                $privateSegment = [ArraySegment[byte]]::new([byte[]]::new(0))
                $privateStream.TryGetBuffer([ref]$privateSegment) | Should -BeFalse
            }
            finally {
                [Array]::Clear($backing, 0, $backing.Length)
                $privateStream.Dispose()
            }
        }

        It 'sanitizes malformed worker command envelopes and preserves owned errors' {
            $missingExitCodeBytes = [byte[]](1, 2)
            foreach ($result in @(
                    $null,
                    [pscustomobject]@{ ExitCode = 0 },
                    [pscustomobject]@{ OutputBytes = $missingExitCodeBytes },
                    [pscustomobject]@{ ExitCode = 0; OutputBytes = 'not-bytes' },
                    [pscustomobject]@{ ExitCode = 'bad'; OutputBytes = [byte[]](1, 2) }
                )) {
                $invoker = { $result }.GetNewClosure()
                { Invoke-HHForensicsKeychainCommand -Action ReadKey `
                        -KeychainPath '/tmp/login.keychain-db' `
                        -Service 'com.hosthunter.nextgeneration.forensics-key.v1' `
                        -Account 'account' -KeychainWorkerInvoker $invoker } |
                    Should -Throw -ErrorId 'ForensicsKeychainUnavailable*'
            }
            @($missingExitCodeBytes | Where-Object { $_ -ne 0 }).Count | Should -Be 0
            { Invoke-HHForensicsKeychainCommand -Action ReadKey `
                    -KeychainPath '/tmp/login.keychain-db' `
                    -Service 'com.hosthunter.nextgeneration.forensics-key.v1' `
                    -Account 'account' } |
                Should -Throw -ErrorId 'ForensicsKeychainUnavailable*'
            { Invoke-HHForensicsKeychainCommand -Action ReadKey `
                    -KeychainPath '/tmp/login.keychain-db' `
                    -Service 'com.hosthunter.nextgeneration.forensics-key.v1' `
                    -Account 'account' -KeychainWorkerInvoker {
                        throw (Get-HHForensicsKeyStoreErrorRecord `
                                -ErrorId ForensicsKeychainTimedOut -Message timeout `
                                -Category OperationTimeout)
                    } } | Should -Throw -ErrorId 'ForensicsKeychainTimedOut*'
            { Invoke-HHForensicsKeychainCommand -Action ReadKey `
                    -KeychainPath '/tmp/login.keychain-db' `
                    -Service 'com.hosthunter.nextgeneration.forensics-key.v1' `
                    -Account 'account' -KeychainWorkerInvoker { throw 'secret' } } |
                Should -Throw -ErrorId 'ForensicsKeychainUnavailable*'
        }

        It 'fails closed without injected seams on a non-macOS platform' -Skip:$IsMacOS {
            { Get-HHMacOSForensicsKey -DataRoot $TestDrive } |
                Should -Throw -ErrorId 'ForensicsKeychainUnavailable*'
        }

        It 'kills and reaps the exact bounded child process' {
            $startInfo = [Diagnostics.ProcessStartInfo]::new()
            $startInfo.FileName = (Get-Command pwsh).Source
            $startInfo.UseShellExecute = $false
            foreach ($argument in @(
                    '-NoLogo', '-NoProfile', '-NonInteractive', '-Command',
                    'Start-Sleep -Seconds 30'
                )) {
                $null = $startInfo.ArgumentList.Add($argument)
            }
            $process = [Diagnostics.Process]::new()
            $process.StartInfo = $startInfo
            try {
                $process.Start() | Should -BeTrue
                Stop-HHForensicsKeychainProcess -Process $process
                $process.HasExited | Should -BeTrue
            }
            finally {
                if (-not $process.HasExited) { $process.Kill($true) }
                $process.Dispose()
            }

            $exitedStartInfo = [Diagnostics.ProcessStartInfo]::new()
            $exitedStartInfo.FileName = (Get-Command pwsh).Source
            $exitedStartInfo.UseShellExecute = $false
            foreach ($argument in @(
                    '-NoLogo', '-NoProfile', '-NonInteractive', '-Command', 'exit 0'
                )) {
                $null = $exitedStartInfo.ArgumentList.Add($argument)
            }
            $exited = [Diagnostics.Process]::new()
            $exited.StartInfo = $exitedStartInfo
            try {
                $exited.Start() | Should -BeTrue
                $exited.WaitForExit()
                { Stop-HHForensicsKeychainProcess -Process $exited } |
                    Should -Not -Throw
            }
            finally { $exited.Dispose() }

            $disposed = [Diagnostics.Process]::new()
            $disposed.Dispose()
            { Stop-HHForensicsKeychainProcess -Process $disposed } |
                Should -Throw -ErrorId 'ForensicsKeychainTerminationFailed*'
        }
    }
}

Describe 'native Forensics Keychain worker closure' -Tag Unit {
    BeforeAll {
        $script:forensicsStorePath = Join-Path $PSScriptRoot `
            '../../src/HostHunterNextGeneration/Private/ForensicsKeyStore.ps1'
        $script:forensicsStoreSource = Get-Content `
            -LiteralPath $script:forensicsStorePath -Raw
        $script:forensicsWorkerPath = Join-Path $PSScriptRoot `
            '../../src/HostHunterNextGeneration/Private/Workers/MacOSForensicsKeychainWorker.ps1'
        $script:forensicsWorkerSource = Get-Content `
            -LiteralPath $script:forensicsWorkerPath -Raw
    }

    It 'hard-codes only the two owned services and exact byte bounds' {
        $script:forensicsWorkerSource |
            Should -Match 'com\.hosthunter\.nextgeneration\.forensics-key\.v1'
        $script:forensicsWorkerSource |
            Should -Match 'com\.hosthunter\.nextgeneration\.forensics-anchor\.v1'
        $script:forensicsWorkerSource | Should -Match 'private const int KeyLength = 32;'
        $script:forensicsWorkerSource | Should -Match 'private const int AnchorLength = 240;'
        $script:forensicsWorkerSource |
            Should -Match 'CryptographicOperations\.FixedTimeEquals'
    }

    It 'passes only metadata through argv and raw bytes through standard streams' {
        $script:forensicsWorkerSource | Should -Match 'Console\.OpenStandardInput'
        $script:forensicsWorkerSource | Should -Match 'Console\.OpenStandardOutput'
        $script:forensicsWorkerSource |
            Should -Not -Match 'GetEnvironmentVariable|SetEnvironmentVariable'
        $script:forensicsWorkerSource | Should -Not -Match 'Console\.Write(Line)?\('
        $script:forensicsWorkerSource | Should -Match 'arguments\.Length != 8'
    }

    It 'keeps the parent process bounded and excludes secret bytes from argv' {
        $script:forensicsStoreSource |
            Should -Match '\$process\.WaitForExit\(\$TimeoutSeconds \* 1000\)'
        $script:forensicsStoreSource |
            Should -Match 'Stop-HHForensicsKeychainProcess -Process \$process'
        $argumentBlock = [regex]::Match(
            $script:forensicsStoreSource,
            '(?s)foreach \(\$argument in @\((?<body>.*?)\)\)'
        )
        $argumentBlock.Success | Should -BeTrue
        $argumentBlock.Groups['body'].Value | Should -Not -Match 'InputBytes|KeyBytes'
    }

    It 'returns unsupported-platform without touching Keychain on Linux' -Skip:(!$IsLinux) {
        & (Get-Command pwsh).Source `
            -NoLogo -NoProfile -NonInteractive -File $script:forensicsWorkerPath `
            -Action ReadKey -KeychainPath /tmp/login.keychain-db `
            -Service com.hosthunter.nextgeneration.forensics-key.v1 `
            -Account fixture-account
        $LASTEXITCODE | Should -Be 14
    }
}
