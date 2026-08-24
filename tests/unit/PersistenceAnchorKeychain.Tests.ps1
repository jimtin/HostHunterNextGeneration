BeforeAll {
    $sourceRoot = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
        Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration'
    }
    else { $env:HH_TEST_SOURCE_ROOT }
    . (Join-Path $sourceRoot 'Private/AuditKeyStore.ps1')

    function Get-HHTestAnchorArtifact {
        param([byte]$Offset = 0)

        $bytes = [byte[]]::new(196)
        for ($index = 0; $index -lt $bytes.Length; $index++) {
            $bytes[$index] = [byte](($index + $Offset) % 256)
        }
        return ,$bytes
    }

    function Get-HHTestAnchorWorker {
        param(
            [Parameter(Mandatory)][object]$State,
            [Parameter(Mandatory)]
            [AllowEmptyCollection()]
            [Collections.Generic.List[object]]$Calls
        )

        $workerState = $State
        $callSink = $Calls
        return {
            param(
                $WorkerPath,
                $PowerShellPath,
                $Action,
                $KeychainPath,
                $Service,
                $Account,
                $InputBytes,
                $TimeoutSeconds
            )

            $callSink.Add([pscustomobject]@{
                    WorkerPath = $WorkerPath
                    PowerShellPath = $PowerShellPath
                    Action = $Action
                    KeychainPath = $KeychainPath
                    Service = $Service
                    Account = $Account
                    InputBytes = if ($null -eq $InputBytes) {
                        $null
                    }
                    else { [byte[]]$InputBytes.Clone() }
                    TimeoutSeconds = $TimeoutSeconds
                }) | Out-Null
            switch ($Action) {
                'CreateAnchor' {
                    if ($null -ne $workerState.Artifact) {
                        return [pscustomobject]@{
                            ExitCode = 11
                            OutputBytes = [byte[]]::new(0)
                        }
                    }
                    $workerState.Artifact = [byte[]]$InputBytes.Clone()
                    return [pscustomobject]@{
                        ExitCode = 0
                        OutputBytes = [byte[]]::new(0)
                    }
                }
                'ReadAnchor' {
                    if ($null -eq $workerState.Artifact) {
                        return [pscustomobject]@{
                            ExitCode = 10
                            OutputBytes = [byte[]]::new(0)
                        }
                    }
                    return [pscustomobject]@{
                        ExitCode = 0
                        OutputBytes = [byte[]]$workerState.Artifact.Clone()
                    }
                }
                'CompareUpdateAnchor' {
                    $expected = [byte[]]::new(196)
                    $replacement = [byte[]]::new(196)
                    [Array]::Copy($InputBytes, 0, $expected, 0, 196)
                    [Array]::Copy($InputBytes, 196, $replacement, 0, 196)
                    if ($null -eq $workerState.Artifact -or
                        -not [Security.Cryptography.CryptographicOperations]::FixedTimeEquals(
                            $workerState.Artifact,
                            $expected
                        )) {
                        return [pscustomobject]@{
                            ExitCode = 16
                            OutputBytes = [byte[]]::new(0)
                        }
                    }
                    $workerState.Artifact = [byte[]]$replacement.Clone()
                    return [pscustomobject]@{
                        ExitCode = 0
                        OutputBytes = [byte[]]$workerState.Artifact.Clone()
                    }
                }
                default { throw "Unexpected fake worker action: $Action" }
            }
        }.GetNewClosure()
    }
}

Describe 'macOS persistence-anchor Keychain boundary' -Tag Unit {
    BeforeEach {
        $script:keychainPath = '/tmp/hosthunter-login.keychain-db'
        $script:state = [pscustomobject]@{ Artifact = $null }
        $script:calls = [Collections.Generic.List[object]]::new()
        $script:worker = Get-HHTestAnchorWorker -State $script:state -Calls $script:calls
        $script:security = {
            [pscustomobject]@{
                ExitCode = 0
                StandardOutput = "`"$script:keychainPath`"`n"
                StandardError = ''
            }
        }
    }

    It 'creates only in the separate service and verifies exact readback' {
        $artifact = Get-HHTestAnchorArtifact -Offset 7

        New-HHMacOSPersistenceAnchorItem `
            -DataRoot $TestDrive `
            -Artifact $artifact `
            -SecurityCommandInvoker $script:security `
            -KeychainWorkerInvoker $script:worker

        $script:calls.Action | Should -Be @('CreateAnchor', 'ReadAnchor')
        @($script:calls | Select-Object -ExpandProperty Service -Unique) |
            Should -Be @('com.hosthunter.nextgeneration.database-anchor.v1')
        $script:calls[0].InputBytes.Length | Should -Be 196
        $script:calls[0].TimeoutSeconds | Should -Be 15
        $script:calls[0].Account | Should -Be (Get-HHAuditKeychainAccount -DataRoot $TestDrive)
        ($script:calls[0].WorkerPath, $script:calls[0].PowerShellPath,
            $script:calls[0].Action, $script:calls[0].KeychainPath,
            $script:calls[0].Service, $script:calls[0].Account) -contains
            ([Convert]::ToBase64String($artifact)) | Should -BeFalse
    }

    It 'returns a missing result without manufacturing an anchor' {
        $result = Read-HHMacOSPersistenceAnchorItem `
            -DataRoot $TestDrive `
            -SecurityCommandInvoker $script:security `
            -KeychainWorkerInvoker $script:worker

        $result.Found | Should -BeFalse
        $result.Artifact | Should -BeNullOrEmpty
        $script:calls.Count | Should -Be 1
        $script:calls[0].Action | Should -BeExactly 'ReadAnchor'
    }

    It 'reads an exact 196-byte artifact' {
        $script:state.Artifact = Get-HHTestAnchorArtifact -Offset 11

        $result = Read-HHMacOSPersistenceAnchorItem `
            -DataRoot $TestDrive `
            -SecurityCommandInvoker $script:security `
            -KeychainWorkerInvoker $script:worker

        $result.Found | Should -BeTrue
        [Convert]::ToHexString($result.Artifact) |
            Should -BeExactly ([Convert]::ToHexString($script:state.Artifact))
    }

    It 'atomically compares, updates, and verifies exact readback' {
        $expected = Get-HHTestAnchorArtifact -Offset 19
        $replacement = Get-HHTestAnchorArtifact -Offset 23
        $script:state.Artifact = [byte[]]$expected.Clone()

        Update-HHMacOSPersistenceAnchorItem `
            -DataRoot $TestDrive `
            -ExpectedArtifact $expected `
            -NewArtifact $replacement `
            -SecurityCommandInvoker $script:security `
            -KeychainWorkerInvoker $script:worker

        $script:calls.Count | Should -Be 1
        $script:calls[0].Action | Should -BeExactly 'CompareUpdateAnchor'
        $script:calls[0].InputBytes.Length | Should -Be 392
        [Convert]::ToHexString($script:state.Artifact) |
            Should -BeExactly ([Convert]::ToHexString($replacement))
    }

    It 'fails a stale comparison without changing the authoritative bytes' {
        $authoritative = Get-HHTestAnchorArtifact -Offset 31
        $stale = Get-HHTestAnchorArtifact -Offset 37
        $replacement = Get-HHTestAnchorArtifact -Offset 41
        $script:state.Artifact = [byte[]]$authoritative.Clone()

        {
            Update-HHMacOSPersistenceAnchorItem `
                -DataRoot $TestDrive `
                -ExpectedArtifact $stale `
                -NewArtifact $replacement `
                -SecurityCommandInvoker $script:security `
                -KeychainWorkerInvoker $script:worker
        } | Should -Throw -ErrorId 'AuditIntegrityFailed'
        [Convert]::ToHexString($script:state.Artifact) |
            Should -BeExactly ([Convert]::ToHexString($authoritative))
    }

    It 'rejects wrong-length create and update artifacts before worker access' {
        $valid = Get-HHTestAnchorArtifact
        {
            New-HHMacOSPersistenceAnchorItem `
                -DataRoot $TestDrive `
                -Artifact ([byte[]](1, 2, 3)) `
                -SecurityCommandInvoker $script:security `
                -KeychainWorkerInvoker $script:worker
        } | Should -Throw '*exactly 196 bytes*'
        {
            Update-HHMacOSPersistenceAnchorItem `
                -DataRoot $TestDrive `
                -ExpectedArtifact ([byte[]](1, 2, 3)) `
                -NewArtifact $valid `
                -SecurityCommandInvoker $script:security `
                -KeychainWorkerInvoker $script:worker
        } | Should -Throw '*exactly 196 bytes*'
        $script:calls.Count | Should -Be 0
    }

    It 'rejects duplicate creation without overwriting the item' {
        $authoritative = Get-HHTestAnchorArtifact -Offset 43
        $replacement = Get-HHTestAnchorArtifact -Offset 47
        $script:state.Artifact = [byte[]]$authoritative.Clone()

        {
            New-HHMacOSPersistenceAnchorItem `
                -DataRoot $TestDrive `
                -Artifact $replacement `
                -SecurityCommandInvoker $script:security `
                -KeychainWorkerInvoker $script:worker
        } | Should -Throw -ErrorId 'AuditIntegrityFailed'
        [Convert]::ToHexString($script:state.Artifact) |
            Should -BeExactly ([Convert]::ToHexString($authoritative))
    }

    It 'fails and clears a corrupt anchor read result' {
        $corrupt = [byte[]](1, 2, 3)
        $worker = {
            [pscustomobject]@{ ExitCode = 0; OutputBytes = $corrupt }
        }.GetNewClosure()

        {
            Read-HHMacOSPersistenceAnchorItem `
                -DataRoot $TestDrive `
                -SecurityCommandInvoker $script:security `
                -KeychainWorkerInvoker $worker
        } | Should -Throw -ErrorId 'AuditIntegrityFailed'
        @($corrupt | Where-Object { $_ -ne 0 }).Count | Should -Be 0
    }

    It 'fails a mismatched creation readback' {
        $artifact = Get-HHTestAnchorArtifact -Offset 51
        $wrongReadback = Get-HHTestAnchorArtifact -Offset 53
        $callCount = 0
        $worker = {
            $callCount++
            if ($callCount -eq 1) {
                return [pscustomobject]@{
                    ExitCode = 0
                    OutputBytes = [byte[]]::new(0)
                }
            }
            [pscustomobject]@{
                ExitCode = 0
                OutputBytes = $wrongReadback
            }
        }.GetNewClosure()

        {
            New-HHMacOSPersistenceAnchorItem `
                -DataRoot $TestDrive `
                -Artifact $artifact `
                -SecurityCommandInvoker $script:security `
                -KeychainWorkerInvoker $worker
        } | Should -Throw -ErrorId 'AuditIntegrityFailed'
    }

    It 'fails and clears a mismatched update readback' {
        $expected = Get-HHTestAnchorArtifact -Offset 59
        $replacement = Get-HHTestAnchorArtifact -Offset 61
        $wrongReadback = Get-HHTestAnchorArtifact -Offset 67
        $worker = {
            [pscustomobject]@{ ExitCode = 0; OutputBytes = $wrongReadback }
        }.GetNewClosure()

        {
            Update-HHMacOSPersistenceAnchorItem `
                -DataRoot $TestDrive `
                -ExpectedArtifact $expected `
                -NewArtifact $replacement `
                -SecurityCommandInvoker $script:security `
                -KeychainWorkerInvoker $worker
        } | Should -Throw -ErrorId 'AuditIntegrityFailed'
        @($wrongReadback | Where-Object { $_ -ne 0 }).Count | Should -Be 0
    }

    It 'sanitizes unexpected anchor worker failures' {
        $sensitiveFailure = 'private-anchor-native-error'
        $worker = { throw $sensitiveFailure }.GetNewClosure()
        $caught = $null
        try {
            Read-HHMacOSPersistenceAnchorItem `
                -DataRoot $TestDrive `
                -SecurityCommandInvoker $script:security `
                -KeychainWorkerInvoker $worker
        }
        catch { $caught = $_ }

        $caught.FullyQualifiedErrorId | Should -BeExactly 'AuditKeychainUnavailable'
        $caught.Exception.Message | Should -Not -Match $sensitiveFailure
    }

    It 'rejects malformed native anchor input at the process boundary' {
        foreach ($case in @(
                [pscustomobject]@{ Action = 'CreateAnchor'; Bytes = [byte[]](1, 2, 3) },
                [pscustomobject]@{ Action = 'CompareUpdateAnchor'; Bytes = [byte[]]::new(196) },
                [pscustomobject]@{ Action = 'ReadAnchor'; Bytes = [byte[]]::new(196) }
            )) {
            {
                Invoke-HHMacOSKeychainWorker `
                    -Action $case.Action `
                    -KeychainPath '/tmp/test-login.keychain-db' `
                    -Account 'test-anchor-account' `
                    -Service $script:HHPersistenceAnchorKeychainService `
                    -InputKey $case.Bytes
            } | Should -Throw -ErrorId 'AuditKeychainUnavailable'
        }
    }

    It 'rejects cross-service action confusion before worker access' {
        {
            Invoke-HHMacOSKeychainWorker `
                -Action ReadAnchor `
                -KeychainPath '/tmp/test-login.keychain-db' `
                -Account 'test-anchor-account'
        } | Should -Throw -ErrorId 'AuditKeychainUnavailable'
        {
            Invoke-HHMacOSKeychainWorker `
                -Action Read `
                -KeychainPath '/tmp/test-login.keychain-db' `
                -Account 'test-key-account' `
                -Service $script:HHPersistenceAnchorKeychainService
        } | Should -Throw -ErrorId 'AuditKeychainUnavailable'
    }

    It 'returns finite unsupported-platform status for native anchor reads on Linux' -Skip:(!$IsLinux) {
        $result = Invoke-HHMacOSKeychainWorker `
            -Action ReadAnchor `
            -KeychainPath '/tmp/test-login.keychain-db' `
            -Account 'test-anchor-account' `
            -Service $script:HHPersistenceAnchorKeychainService

        $result.ExitCode | Should -Be 14
        $result.OutputBytes.Length | Should -Be 0
    }

    It 'uses the default bounded worker path for anchor commands on Linux' -Skip:(!$IsLinux) {
        $result = Invoke-HHPersistenceAnchorKeychainWorkerCommand `
            -Action ReadAnchor `
            -KeychainPath '/tmp/test-login.keychain-db' `
            -Account 'test-anchor-account'
        $result.ExitCode | Should -Be 14
        $result.OutputBytes.Length | Should -Be 0
    }

    It 'propagates known finite anchor worker errors and sanitizes malformed results' {
        foreach ($errorId in @(
                'AuditKeychainTimedOut',
                'AuditKeychainTerminationFailed',
                'AuditKeychainUnavailable'
            )) {
            $known = Get-HHAuditKeyStoreErrorRecord `
                -ErrorId $errorId `
                -Message 'sanitized native failure' `
                -Category OperationStopped
            $worker = { throw $known }.GetNewClosure()
            {
                Invoke-HHPersistenceAnchorKeychainWorkerCommand `
                    -Action ReadAnchor `
                    -KeychainPath $script:keychainPath `
                    -Account 'test-anchor-account' `
                    -KeychainWorkerInvoker $worker
            } | Should -Throw -ErrorId $errorId
        }

        $sensitive = Get-HHTestAnchorArtifact -Offset 71
        $malformed = {
            [pscustomobject]@{ OutputBytes = $sensitive }
        }.GetNewClosure()
        {
            Invoke-HHPersistenceAnchorKeychainWorkerCommand `
                -Action ReadAnchor `
                -KeychainPath $script:keychainPath `
                -Account 'test-anchor-account' `
                -KeychainWorkerInvoker $malformed
        } | Should -Throw -ErrorId AuditKeychainUnavailable
        @($sensitive | Where-Object { $_ -ne 0 }).Count | Should -Be 0

        foreach ($bad in @(
                $null,
                [pscustomobject]@{ ExitCode = 0; OutputBytes = 'not-bytes' },
                [pscustomobject]@{ ExitCode = 'not-a-number'; OutputBytes = [byte[]]::new(0) }
            )) {
            $worker = { return $bad }.GetNewClosure()
            {
                Invoke-HHPersistenceAnchorKeychainWorkerCommand `
                    -Action ReadAnchor `
                    -KeychainPath $script:keychainPath `
                    -Account 'test-anchor-account' `
                    -KeychainWorkerInvoker $worker
            } | Should -Throw -ErrorId AuditKeychainUnavailable
        }
    }

    It 'rejects nonempty creation output and nonzero exact-length reads' {
        $artifact = Get-HHTestAnchorArtifact -Offset 73
        $createOutput = Get-HHTestAnchorArtifact -Offset 79
        $createWorker = {
            [pscustomobject]@{ ExitCode = 0; OutputBytes = $createOutput }
        }.GetNewClosure()
        {
            New-HHMacOSPersistenceAnchorItem `
                -DataRoot $TestDrive `
                -Artifact $artifact `
                -SecurityCommandInvoker $script:security `
                -KeychainWorkerInvoker $createWorker
        } | Should -Throw -ErrorId AuditIntegrityFailed
        @($createOutput | Where-Object { $_ -ne 0 }).Count | Should -Be 0

        $readOutput = Get-HHTestAnchorArtifact -Offset 83
        $readWorker = {
            [pscustomobject]@{ ExitCode = 12; OutputBytes = $readOutput }
        }.GetNewClosure()
        {
            Read-HHMacOSPersistenceAnchorItem `
                -DataRoot $TestDrive `
                -SecurityCommandInvoker $script:security `
                -KeychainWorkerInvoker $readWorker
        } | Should -Throw -ErrorId AuditIntegrityFailed
        @($readOutput | Where-Object { $_ -ne 0 }).Count | Should -Be 0
    }

    It 'rejects an invalid replacement length before constructing CAS input' {
        {
            Update-HHMacOSPersistenceAnchorItem `
                -DataRoot $TestDrive `
                -ExpectedArtifact (Get-HHTestAnchorArtifact) `
                -NewArtifact ([byte[]](1, 2, 3)) `
                -SecurityCommandInvoker $script:security `
                -KeychainWorkerInvoker $script:worker
        } | Should -Throw '*exactly 196 bytes*'
        $script:calls.Count | Should -Be 0
    }
}
