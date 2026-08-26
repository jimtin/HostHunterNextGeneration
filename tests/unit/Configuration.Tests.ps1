BeforeAll {
    $sourceRoot = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
        Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration'
    }
    else {
        $env:HH_TEST_SOURCE_ROOT
    }
    $script:HHModuleRoot = $sourceRoot
    . (Join-Path $sourceRoot 'Private/AuditKeyStore.ps1')
    . (Join-Path $sourceRoot 'Private/PersistencePath.ps1')
    . (Join-Path $sourceRoot 'Private/DockerVolumePersistence.ps1')
    . (Join-Path $sourceRoot 'Private/Configuration.ps1')
}

Describe 'HostHunter runtime configuration' -Tag Unit {
    BeforeEach {
        $env:HH_COVERAGE_CASE = [Guid]::NewGuid().ToString('N')
        $env:HH_DATA_ROOT = $null
        $env:XDG_STATE_HOME = $null
        $env:HH_SECRET_PROVIDER = $null
        $env:HH_SECRET_ROOT = $null
        $env:HH_ANCHOR_ROOT = $null
        $script:HHControllerIsMacOS = $false
        $testAuditRoot = Join-Path $TestDrive 'audit'
        [IO.Directory]::CreateDirectory($testAuditRoot) | Out-Null
        $testKeyPath = Join-Path $testAuditRoot 'audit.key'
        if (Test-Path -LiteralPath $testKeyPath) {
            Remove-Item -LiteralPath $testKeyPath -Recurse -Force
        }
        $legacyKeyPath = Join-Path $TestDrive 'audit.key'
        if (Test-Path -LiteralPath $legacyKeyPath) {
            Remove-Item -LiteralPath $legacyKeyPath -Recurse -Force
        }
    }

    It 'uses an explicit data root before environment defaults' {
        Resolve-HHDataRoot -DataRoot $TestDrive | Should -Be ([IO.Path]::GetFullPath($TestDrive))
    }

    It 'uses the HostHunter data-root environment override' {
        $env:HH_DATA_ROOT = Join-Path $TestDrive 'override'
        Resolve-HHDataRoot | Should -Be ([IO.Path]::GetFullPath($env:HH_DATA_ROOT))
    }

    It 'uses XDG state on Linux when supplied' -Skip:(!$IsLinux) {
        $env:XDG_STATE_HOME = Join-Path $TestDrive 'state'
        Resolve-HHDataRoot | Should -Be (Join-Path $env:XDG_STATE_HOME 'hosthunter-next-generation')
    }

    It 'uses the private Linux state default when no override exists' -Skip:(!$IsLinux) {
        Resolve-HHDataRoot |
            Should -Be (Join-Path ([Environment]::GetFolderPath('UserProfile')) '.local/state/hosthunter-next-generation')
    }

    It 'explicitly creates and reloads the non-macOS mode-0600 file key' {
        $first = Get-HHMasterKey -DataRoot $TestDrive
        $second = Get-HHMasterKey -DataRoot $TestDrive
        $first.Length | Should -Be 32
        [Convert]::ToHexString($second) | Should -Be ([Convert]::ToHexString($first))
        if (-not $IsWindows) {
            [IO.File]::GetUnixFileMode($testKeyPath) |
                Should -Be ([IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite)
        }
    }

    It 'sets mode 0600 before writing any non-macOS key bytes' -Skip:$IsWindows {
        $observation = [pscustomobject]@{
            Mode = [IO.UnixFileMode]::None
            Length = -1L
        }
        $observer = {
            param($Path)

            $observation.Mode = [IO.File]::GetUnixFileMode($Path)
            $observation.Length = [IO.FileInfo]::new($Path).Length
        }.GetNewClosure()

        $key = Get-HHFileAuditMasterKey `
            -DataRoot $TestDrive `
            -OpenedFileObserver $observer

        $key.Length | Should -Be 32
        $observation.Mode |
            Should -Be ([IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite)
        $observation.Length | Should -Be 0
    }

    It 'fails closed for an invalid existing non-macOS file key' {
        [IO.File]::WriteAllBytes($testKeyPath, [byte[]](1, 2, 3))
        if (-not $IsWindows) {
            [IO.File]::SetUnixFileMode(
                $testKeyPath,
                [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite
            )
        }
        {
            Get-HHMasterKey -DataRoot $TestDrive
        } | Should -Throw '*Remote activity is blocked*'
    }

    It 'rejects an existing non-macOS key whose mode is not exactly 0600' -Skip:$IsWindows {
        $keyPath = $testKeyPath
        $expected = [byte[]](0..31)
        [IO.File]::WriteAllBytes($keyPath, $expected)
        [IO.File]::SetUnixFileMode(
            $keyPath,
            [IO.UnixFileMode]::UserRead -bor
                [IO.UnixFileMode]::UserWrite -bor
                [IO.UnixFileMode]::GroupRead
        )

        { Get-HHFileAuditMasterKey -DataRoot $TestDrive } |
            Should -Throw -ErrorId 'AuditFileKeyUnsafe'
        [Convert]::ToHexString([IO.File]::ReadAllBytes($keyPath)) |
            Should -Be ([Convert]::ToHexString($expected))
    }

    It 'rejects a symbolic-link non-macOS key without reading its target' -Skip:$IsWindows {
        $outsidePath = Join-Path $TestDrive 'outside-key'
        $keyPath = $testKeyPath
        $expected = [byte[]](32..63)
        [IO.File]::WriteAllBytes($outsidePath, $expected)
        [IO.File]::SetUnixFileMode(
            $outsidePath,
            [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite
        )
        [IO.File]::CreateSymbolicLink($keyPath, $outsidePath) | Out-Null

        { Get-HHFileAuditMasterKey -DataRoot $TestDrive } |
            Should -Throw -ErrorId 'AuditFileKeyUnsafe'
        [Convert]::ToHexString([IO.File]::ReadAllBytes($outsidePath)) |
            Should -Be ([Convert]::ToHexString($expected))
    }

    It 'fails closed when another process boundary exclusively holds the key file' {
        $keyPath = $testKeyPath
        [IO.File]::WriteAllBytes($keyPath, [byte[]](0..31))
        if (-not $IsWindows) {
            [IO.File]::SetUnixFileMode(
                $keyPath,
                [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite
            )
        }
        $exclusiveStream = [IO.File]::Open(
            $keyPath,
            [IO.FileMode]::Open,
            [IO.FileAccess]::ReadWrite,
            [IO.FileShare]::None
        )
        try {
            { Read-HHPrivateAuditKeyFile -Path $keyPath } |
                Should -Throw -ErrorId 'AuditFileKeyUnsafe'
        }
        finally {
            $exclusiveStream.Dispose()
        }
    }

    It 'fails closed when an audit-key path cannot be inspected' {
        { Confirm-HHAuditKeyFileSafety -Path (Join-Path $TestDrive 'missing.key') } |
            Should -Throw -ErrorId 'AuditFileKeyUnsafe'
    }

    It 'uses create-new semantics and never overwrites a private key file' {
        $keyPath = Join-Path $TestDrive 'existing.key'
        $existing = [byte[]](32..63)
        [IO.File]::WriteAllBytes($keyPath, $existing)
        if (-not $IsWindows) {
            [IO.File]::SetUnixFileMode(
                $keyPath,
                [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite
            )
        }

        { Write-HHPrivateAuditKeyFile -Path $keyPath -Key ([byte[]](0..31)) } | Should -Throw
        [Convert]::ToHexString([IO.File]::ReadAllBytes($keyPath)) |
            Should -Be ([Convert]::ToHexString($existing))
    }

    It 'uses a valid concurrent non-macOS file-provider winner' {
        $winner = [byte[]](64..95)
        $winnerPath = $testKeyPath
        $observer = {
            param($TemporaryPath)

            if (-not [string]::IsNullOrWhiteSpace($TemporaryPath)) {
                [IO.File]::WriteAllBytes($winnerPath, $winner)
                if (-not $IsWindows) {
                    [IO.File]::SetUnixFileMode(
                        $winnerPath,
                        [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite
                    )
                }
                throw 'A concurrent writer won the final audit-key path.'
            }
        }.GetNewClosure()

        $actual = Get-HHFileAuditMasterKey `
            -DataRoot $TestDrive `
            -OpenedFileObserver $observer

        [Convert]::ToHexString($actual) | Should -Be ([Convert]::ToHexString($winner))
        @(Get-ChildItem -LiteralPath $testAuditRoot -Filter 'audit.key.*.tmp').Count | Should -Be 0
    }

    It 'cleans its temporary file when the non-macOS key destination cannot be committed' {
        [IO.Directory]::CreateDirectory($testKeyPath) | Out-Null

        {
            Get-HHMasterKey -DataRoot $TestDrive
        } | Should -Throw
        @(Get-ChildItem -LiteralPath $testAuditRoot -Filter 'audit.key.*.tmp').Count | Should -Be 0
    }

    It 'fails without temporary key material when its data root is not writable' -Skip:$IsWindows {
        $lockedRoot = Join-Path $TestDrive 'locked-root'
        [IO.Directory]::CreateDirectory($lockedRoot) | Out-Null
        [IO.File]::SetUnixFileMode(
            $lockedRoot,
            [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserExecute
        )
        try {
            { Get-HHFileAuditMasterKey -DataRoot $lockedRoot } | Should -Throw
            @(Get-ChildItem -LiteralPath $lockedRoot -Force).Count | Should -Be 0
        }
        finally {
            [IO.File]::SetUnixFileMode(
                $lockedRoot,
                [IO.UnixFileMode]::UserRead -bor
                    [IO.UnixFileMode]::UserWrite -bor
                    [IO.UnixFileMode]::UserExecute
            )
        }
    }

    It 'builds all runtime paths under the selected root' {
        $context = Get-HHRuntimeContext -DataRoot $TestDrive
        $context.DataRoot | Should -Be ([IO.Path]::GetFullPath($TestDrive))
        $context.DatabasePath | Should -Be (Join-Path $TestDrive 'hosthunter.db')
        $context.AuditRoot | Should -Be (Join-Path $TestDrive 'audit')
        $context.KnownHostsPath | Should -Be (Join-Path $TestDrive 'known_hosts')
        $context.KeyRoot | Should -Be (Join-Path $TestDrive 'keys')
        $context.OutputRoot | Should -Be (Join-Path $TestDrive 'audit/output')
        $context.RecoveryRoot | Should -Be (Join-Path $TestDrive 'recovery')
    }

    It 'requires an existing non-macOS key without creating temporary material' {
        {
            Get-HHFileAuditMasterKey -DataRoot $TestDrive -RequireExisting
        } | Should -Throw -ErrorId 'AuditKeyUnavailable'
        Test-Path -LiteralPath $testKeyPath | Should -BeFalse
        @(Get-ChildItem -LiteralPath $testAuditRoot -Filter '*.tmp').Count |
            Should -Be 0
    }

    It 'handles a creation failure after its temporary key was independently removed' {
        $observer = {
            param($TemporaryPath)
            [IO.File]::Delete($TemporaryPath)
            throw 'simulated vanished staging key'
        }
        {
            Get-HHFileAuditMasterKey `
                -DataRoot $TestDrive `
                -OpenedFileObserver $observer
        } | Should -Throw '*simulated vanished staging key*'
        Test-Path -LiteralPath $testKeyPath | Should -BeFalse
        @(Get-ChildItem -LiteralPath $testAuditRoot -Filter '*.tmp').Count |
            Should -Be 0
    }
}
