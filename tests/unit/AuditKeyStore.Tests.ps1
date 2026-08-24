BeforeAll {
    $sourceRoot = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
        Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration'
    }
    else {
        $env:HH_TEST_SOURCE_ROOT
    }
    . (Join-Path $sourceRoot 'Private/AuditKeyStore.ps1')

    function Get-HHTestSecurityResult {
        param(
            [int]$ExitCode = 0,
            [AllowEmptyString()][string]$StandardOutput = '',
            [AllowEmptyString()][string]$StandardError = ''
        )

        [pscustomobject]@{
            ExitCode = $ExitCode
            StandardOutput = $StandardOutput
            StandardError = $StandardError
        }
    }

    function Get-HHTestWorkerResult {
        param(
            [object]$ExitCode = 0,
            [AllowNull()][object]$OutputBytes = ([byte[]]::new(0))
        )

        [pscustomobject]@{
            ExitCode = $ExitCode
            OutputBytes = $OutputBytes
        }
    }

    function Get-HHTestSecurityInvoker {
        param(
            [Parameter(Mandatory)][object[]]$Result,
            [Parameter(Mandatory)]
            [AllowEmptyCollection()]
            [System.Collections.Generic.List[object]]$Call
        )

        $queue = [System.Collections.Generic.Queue[object]]::new()
        foreach ($item in $Result) {
            $queue.Enqueue($item)
        }
        $callSink = $Call
        return {
            param($ExecutablePath, $ArgumentList, $TimeoutSeconds)

            $callSink.Add([pscustomobject]@{
                    ExecutablePath = $ExecutablePath
                    ArgumentList = [string[]]$ArgumentList
                    TimeoutSeconds = $TimeoutSeconds
                }) | Out-Null
            if ($queue.Count -eq 0) {
                throw 'The fake macOS security result queue is empty.'
            }
            return $queue.Dequeue()
        }.GetNewClosure()
    }

    function Get-HHTestWorkerInvoker {
        param(
            [Parameter(Mandatory)][object[]]$Result,
            [Parameter(Mandatory)]
            [AllowEmptyCollection()]
            [System.Collections.Generic.List[object]]$Call
        )

        $queue = [System.Collections.Generic.Queue[object]]::new()
        foreach ($item in $Result) {
            $queue.Enqueue($item)
        }
        $callSink = $Call
        return {
            param(
                $WorkerPath,
                $PowerShellPath,
                $Action,
                $KeychainPath,
                $Service,
                $Account,
                $InputKey,
                $TimeoutSeconds
            )

            $inputCopy = if ($null -eq $InputKey) {
                $null
            }
            else {
                [byte[]]$InputKey.Clone()
            }
            $callSink.Add([pscustomobject]@{
                    WorkerPath = $WorkerPath
                    PowerShellPath = $PowerShellPath
                    Action = $Action
                    KeychainPath = $KeychainPath
                    Service = $Service
                    Account = $Account
                    InputKey = $inputCopy
                    TimeoutSeconds = $TimeoutSeconds
                }) | Out-Null
            if ($queue.Count -eq 0) {
                throw 'The fake native worker result queue is empty.'
            }
            return $queue.Dequeue()
        }.GetNewClosure()
    }

    function Get-HHTestAuditKey {
        param([ValidateRange(0, 223)][int]$Offset = 0)

        return ,[byte[]]@(0..31 | ForEach-Object { [byte]($_ + $Offset) })
    }
}

Describe 'Audit Keychain identifiers' -Tag Unit {
    BeforeEach {
        $env:HH_COVERAGE_CASE = [Guid]::NewGuid().ToString('N')
    }

    It 'uses a stable lowercase SHA-256 account without the data-root path' {
        $withSeparator = "$TestDrive$([IO.Path]::DirectorySeparatorChar)"
        $first = Get-HHAuditKeychainAccount -DataRoot $TestDrive
        $second = Get-HHAuditKeychainAccount -DataRoot $withSeparator
        $other = Get-HHAuditKeychainAccount -DataRoot (Join-Path $TestDrive 'other')

        $first | Should -Be $second
        $first | Should -Match '^[0-9a-f]{64}$'
        $first | Should -Not -Be $other
        $first | Should -Not -Match ([Regex]::Escape($TestDrive))
    }

    It 'rejects an empty data root' {
        { Get-HHAuditKeychainAccount -DataRoot ' ' } | Should -Throw '*must not be empty*'
    }

    It 'supports the filesystem root as a canonical account input' {
        Get-HHAuditKeychainAccount -DataRoot ([IO.Path]::GetPathRoot($TestDrive)) |
            Should -Match '^[0-9a-f]{64}$'
    }
}

Describe 'Bounded metadata-only security process' -Tag Unit {
    BeforeEach {
        $env:HH_COVERAGE_CASE = [Guid]::NewGuid().ToString('N')
        $script:testPwshPath = (Get-Command pwsh -ErrorAction Stop).Source
    }

    It 'uses ArgumentList without a shell and captures metadata output' {
        $result = Invoke-HHMacOSSecurityCommand `
            -ExecutablePath '/usr/bin/printf' `
            -ArgumentList @('%s', 'value with spaces')

        $result.ExitCode | Should -Be 0
        $result.StandardOutput | Should -Be 'value with spaces'
        $result.StandardError | Should -BeNullOrEmpty
        (Get-Command Invoke-HHMacOSSecurityCommand).Parameters.ContainsKey('StandardInput') |
            Should -BeFalse
    }

    It 'supports a bounded executable with an empty argument list' {
        (Invoke-HHMacOSSecurityCommand -ExecutablePath '/usr/bin/true' -ArgumentList @()).ExitCode |
            Should -Be 0
    }

    It 'kills, reaps, and fails closed when the process exceeds its bound' {
        $childScriptPath = Join-Path $TestDrive 'timed-security-child.ps1'
        $childPidPath = Join-Path $TestDrive 'timed-security-child.pid'
        $childSource = @'
param([Parameter(Mandatory)][string]$PidPath)
[IO.File]::WriteAllText($PidPath, [string]$PID)
Start-Sleep -Seconds 30
'@
        [IO.File]::WriteAllText($childScriptPath, $childSource, [Text.UTF8Encoding]::new($false))
        $caught = $null
        try {
            Invoke-HHMacOSSecurityCommand `
                -ExecutablePath $script:testPwshPath `
                -ArgumentList @('-NoProfile', '-File', $childScriptPath, '-PidPath', $childPidPath) `
                -TimeoutSeconds 1
        }
        catch {
            $caught = $_
        }

        $caught.FullyQualifiedErrorId | Should -Be 'AuditKeychainTimedOut'
        Test-Path -LiteralPath $childPidPath | Should -BeTrue
        $childId = [int][IO.File]::ReadAllText($childPidPath)
        $childProcess = $null
        try {
            $childProcess = [Diagnostics.Process]::GetProcessById($childId)
        }
        catch [ArgumentException] {
            $childProcess = $null
        }
        ($null -eq $childProcess -or $childProcess.HasExited) | Should -BeTrue
        if ($null -ne $childProcess) {
            $childProcess.Dispose()
        }
    }

    It 'sanitizes an unavailable executable failure' {
        $caught = $null
        try {
            Invoke-HHMacOSSecurityCommand `
                -ExecutablePath '/hosthunter-test/not-present/security' `
                -ArgumentList @('sensitive-test-argument')
        }
        catch {
            $caught = $_
        }

        $caught.FullyQualifiedErrorId | Should -Be 'AuditKeychainUnavailable'
        $caught.Exception.Message | Should -Not -Match 'sensitive-test-argument'
    }

    It 'fails finitely when termination cannot inspect or reap a disposed process boundary' {
        $disposedProcess = [Diagnostics.Process]::new()
        $disposedProcess.Dispose()

        { Invoke-HHChildProcessTermination -Process $disposedProcess } |
            Should -Throw -ErrorId 'AuditKeychainTerminationFailed'
    }

    It 'treats an already exited process as an idempotent termination boundary' {
        $completedProcess = [Diagnostics.Process]::Start('/usr/bin/true')
        $completedProcess.WaitForExit()
        try {
            { Invoke-HHChildProcessTermination -Process $completedProcess } |
                Should -Not -Throw
        }
        finally {
            $completedProcess.Dispose()
        }
    }

    It 'rejects a relative executable instead of allowing PATH resolution' {
        {
            Invoke-HHMacOSSecurityCommand -ExecutablePath 'security' -ArgumentList @('login-keychain')
        } | Should -Throw -ErrorId 'AuditKeychainUnavailable'
    }

    It 'fails closed through the fixed security path when it is absent' -Skip:(!$IsLinux) {
        { Invoke-HHAuditKeychainCommand -ArgumentList @('login-keychain') } |
            Should -Throw -ErrorId 'AuditKeychainUnavailable'
    }
}

Describe 'Native Keychain worker process boundary' -Tag Unit {
    BeforeEach {
        $env:HH_COVERAGE_CASE = [Guid]::NewGuid().ToString('N')
        $script:testPwshPath = (Get-Command pwsh -ErrorAction Stop).Source
        $script:fakeKey = Get-HHTestAuditKey -Offset 16
    }

    It 'passes a 32-byte create key only through raw standard input' {
        $workerPath = Join-Path $TestDrive 'echo-key-worker.ps1'
        $workerSource = @'
param($Action, $KeychainPath, $Service, $Account)
$key = [byte[]]::new(32)
try {
    [Console]::OpenStandardInput().ReadExactly($key, 0, $key.Length)
    $output = [Console]::OpenStandardOutput()
    $output.Write($key, 0, $key.Length)
    $output.Flush()
}
finally {
    [Array]::Clear($key, 0, $key.Length)
}
'@
        [IO.File]::WriteAllText($workerPath, $workerSource, [Text.UTF8Encoding]::new($false))

        $result = Invoke-HHMacOSKeychainWorker `
            -Action Create `
            -KeychainPath '/tmp/test-login.keychain-db' `
            -Account 'test-account' `
            -InputKey $script:fakeKey `
            -WorkerPath $workerPath `
            -PowerShellPath $script:testPwshPath

        $result.ExitCode | Should -Be 0
        [Convert]::ToHexString($result.OutputBytes) |
            Should -Be ([Convert]::ToHexString($script:fakeKey))
        [Text.Encoding]::UTF8.GetString($result.OutputBytes) |
            Should -Not -Be ([Convert]::ToBase64String($script:fakeKey))
    }

    It 'captures a raw 32-byte read result without text conversion' {
        $workerPath = Join-Path $TestDrive 'read-worker.ps1'
        $hex = [Convert]::ToHexString($script:fakeKey)
        $workerSource = @"
param(`$Action, `$KeychainPath, `$Service, `$Account)
`$bytes = [Convert]::FromHexString('$hex')
try {
    `$output = [Console]::OpenStandardOutput()
    `$output.Write(`$bytes, 0, `$bytes.Length)
    `$output.Flush()
}
finally {
    [Array]::Clear(`$bytes, 0, `$bytes.Length)
}
"@
        [IO.File]::WriteAllText($workerPath, $workerSource, [Text.UTF8Encoding]::new($false))

        $result = Invoke-HHMacOSKeychainWorker `
            -Action Read `
            -KeychainPath '/tmp/test-login.keychain-db' `
            -Account 'test-account' `
            -WorkerPath $workerPath `
            -PowerShellPath $script:testPwshPath

        [Convert]::ToHexString($result.OutputBytes) | Should -Be $hex
    }

    It 'discards child output whenever the worker reports failure' {
        $workerPath = Join-Path $TestDrive 'failed-worker.ps1'
        $workerSource = @'
param($Action, $KeychainPath, $Service, $Account)
$output = [Console]::OpenStandardOutput()
$output.Write([byte[]](0..31), 0, 32)
$output.Flush()
exit 12
'@
        [IO.File]::WriteAllText($workerPath, $workerSource, [Text.UTF8Encoding]::new($false))

        $result = Invoke-HHMacOSKeychainWorker `
            -Action Read `
            -KeychainPath '/tmp/test-login.keychain-db' `
            -Account 'test-account' `
            -WorkerPath $workerPath `
            -PowerShellPath $script:testPwshPath

        $result.ExitCode | Should -Be 12
        $result.OutputBytes.Length | Should -Be 0
    }

    It 'rejects and clears worker output beyond the 32-byte protocol bound' {
        $workerPath = Join-Path $TestDrive 'oversized-worker.ps1'
        $workerSource = @'
param($Action, $KeychainPath, $Service, $Account)
$output = [Console]::OpenStandardOutput()
$output.Write([byte[]](0..32), 0, 33)
$output.Flush()
'@
        [IO.File]::WriteAllText($workerPath, $workerSource, [Text.UTF8Encoding]::new($false))

        {
            Invoke-HHMacOSKeychainWorker `
                -Action Read `
                -KeychainPath '/tmp/test-login.keychain-db' `
                -Account 'test-account' `
                -WorkerPath $workerPath `
                -PowerShellPath $script:testPwshPath
        } | Should -Throw -ErrorId 'AuditKeychainUnavailable'
    }

    It 'kills and confirms reaping a timed-out worker' {
        $workerPath = Join-Path $TestDrive 'timed-worker.ps1'
        $pidPath = Join-Path $TestDrive 'timed-worker.pid'
        $workerSource = @'
param($Action, $KeychainPath, $Service, $Account)
[IO.File]::WriteAllText($Account, [string]$PID)
Start-Sleep -Seconds 30
'@
        [IO.File]::WriteAllText($workerPath, $workerSource, [Text.UTF8Encoding]::new($false))
        $caught = $null
        try {
            Invoke-HHMacOSKeychainWorker `
                -Action Read `
                -KeychainPath '/tmp/test-login.keychain-db' `
                -Account $pidPath `
                -WorkerPath $workerPath `
                -PowerShellPath $script:testPwshPath `
                -TimeoutSeconds 1
        }
        catch {
            $caught = $_
        }

        $caught.FullyQualifiedErrorId | Should -Be 'AuditKeychainTimedOut'
        $childId = [int][IO.File]::ReadAllText($pidPath)
        $childProcess = $null
        try {
            $childProcess = [Diagnostics.Process]::GetProcessById($childId)
        }
        catch [ArgumentException] {
            $childProcess = $null
        }
        ($null -eq $childProcess -or $childProcess.HasExited) | Should -BeTrue
        if ($null -ne $childProcess) {
            $childProcess.Dispose()
        }
    }

    It 'rejects absent or relative worker executables' {
        {
            Invoke-HHMacOSKeychainWorker `
                -Action Read `
                -KeychainPath '/tmp/test-login.keychain-db' `
                -Account 'test-account' `
                -WorkerPath 'relative-worker.ps1' `
                -PowerShellPath $script:testPwshPath
        } | Should -Throw -ErrorId 'AuditKeychainUnavailable'
        {
            Invoke-HHMacOSKeychainWorker `
                -Action Read `
                -KeychainPath '/tmp/test-login.keychain-db' `
                -Account 'test-account' `
                -WorkerPath $script:HHMacOSKeychainWorkerPath `
                -PowerShellPath '/missing/pwsh'
        } | Should -Throw -ErrorId 'AuditKeychainUnavailable'
    }

    It 'sanitizes a process-start failure for an existing non-executable pwsh path' -Skip:$IsWindows {
        $nonExecutablePath = Join-Path $TestDrive 'not-pwsh'
        [IO.File]::WriteAllText($nonExecutablePath, 'not an executable')
        [IO.File]::SetUnixFileMode($nonExecutablePath, [IO.UnixFileMode]::UserRead)

        {
            Invoke-HHMacOSKeychainWorker `
                -Action Read `
                -KeychainPath '/tmp/test-login.keychain-db' `
                -Account 'test-account' `
                -PowerShellPath $nonExecutablePath
        } | Should -Throw -ErrorId 'AuditKeychainUnavailable'
        {
            Invoke-HHMacOSKeychainWorker `
                -Action Create `
                -KeychainPath '/tmp/test-login.keychain-db' `
                -Account 'test-account' `
                -InputKey $script:fakeKey `
                -PowerShellPath $nonExecutablePath
        } | Should -Throw -ErrorId 'AuditKeychainUnavailable'
    }

    It 'rejects missing, short, or unexpected create input' {
        foreach ($invalid in @($null, [byte[]](1, 2, 3))) {
            {
                Invoke-HHMacOSKeychainWorker `
                    -Action Create `
                    -KeychainPath '/tmp/test-login.keychain-db' `
                    -Account 'test-account' `
                    -InputKey $invalid
            } | Should -Throw -ErrorId 'AuditKeychainUnavailable'
        }
        {
            Invoke-HHMacOSKeychainWorker `
                -Action Read `
                -KeychainPath '/tmp/test-login.keychain-db' `
                -Account 'test-account' `
                -InputKey $script:fakeKey
        } | Should -Throw -ErrorId 'AuditKeychainUnavailable'
    }

    It 'returns the finite unsupported-platform status on Linux' -Skip:(!$IsLinux) {
        $result = Invoke-HHAuditKeychainWorkerCommand `
            -Action Read `
            -KeychainPath '/tmp/test-login.keychain-db' `
            -Account 'test-account'

        $result.ExitCode | Should -Be 14
        $result.OutputBytes.Length | Should -Be 0
    }

    It 'clears an exposed memory-stream backing buffer' {
        $stream = [IO.MemoryStream]::new()
        $stream.Write($script:fakeKey, 0, $script:fakeKey.Length)
        $segment = [ArraySegment[byte]]::new([byte[]]::new(0))
        $stream.TryGetBuffer([ref]$segment) | Should -BeTrue

        Clear-HHMemoryStreamBuffer -Stream $stream
        @($segment.Array[$segment.Offset..($segment.Offset + $script:fakeKey.Length - 1)] |
                Where-Object { $_ -ne 0 }).Count | Should -Be 0
        { Clear-HHMemoryStreamBuffer -Stream $null } | Should -Not -Throw
        $stream.Dispose()

        $privateStream = [IO.MemoryStream]::new(
            $script:fakeKey,
            0,
            $script:fakeKey.Length,
            $true,
            $false
        )
        { Clear-HHMemoryStreamBuffer -Stream $privateStream } | Should -Not -Throw
        $privateStream.Dispose()
    }
}

Describe 'macOS audit master-key lifecycle' -Tag Unit {
    BeforeEach {
        $env:HH_COVERAGE_CASE = [Guid]::NewGuid().ToString('N')
        $script:keychainPath = '/tmp/hosthunter-login.keychain-db'
        $script:loginResult = Get-HHTestSecurityResult -StandardOutput "`"$script:keychainPath`"`n"
        $script:securityCalls = [System.Collections.Generic.List[object]]::new()
        $script:workerCalls = [System.Collections.Generic.List[object]]::new()
        $script:securityInvoker = Get-HHTestSecurityInvoker `
            -Result @($script:loginResult) `
            -Call $script:securityCalls
    }

    It 'reads an existing raw 32-byte key from the exact login Keychain' {
        $expected = Get-HHTestAuditKey
        $workerInvoker = Get-HHTestWorkerInvoker `
            -Result @((Get-HHTestWorkerResult -OutputBytes $expected)) `
            -Call $script:workerCalls

        $actual = Get-HHMacOSAuditMasterKey `
            -DataRoot $TestDrive `
            -SecurityCommandInvoker $script:securityInvoker `
            -KeychainWorkerInvoker $workerInvoker

        [Convert]::ToHexString($actual) | Should -Be ([Convert]::ToHexString($expected))
        $script:securityCalls.Count | Should -Be 1
        $script:securityCalls[0].ArgumentList | Should -Be @('login-keychain')
        $script:workerCalls.Count | Should -Be 1
        $script:workerCalls[0].Action | Should -Be 'Read'
        $script:workerCalls[0].KeychainPath | Should -Be $script:keychainPath
        $script:workerCalls[0].InputKey | Should -BeNullOrEmpty
        $script:workerCalls[0].TimeoutSeconds | Should -Be 15
    }

    It 'creates and verifies a missing key without using the security CLI for secrets' {
        $state = [pscustomobject]@{ Key = $null; ReadCount = 0 }
        $calls = $script:workerCalls
        $workerInvoker = {
            param(
                $WorkerPath,
                $PowerShellPath,
                $Action,
                $KeychainPath,
                $Service,
                $Account,
                $InputKey,
                $TimeoutSeconds
            )

            $calls.Add([pscustomobject]@{
                    WorkerPath = $WorkerPath
                    PowerShellPath = $PowerShellPath
                    Action = $Action
                    KeychainPath = $KeychainPath
                    Service = $Service
                    Account = $Account
                    InputKey = if ($null -eq $InputKey) { $null } else { [byte[]]$InputKey.Clone() }
                    TimeoutSeconds = $TimeoutSeconds
                }) | Out-Null
            if ($Action -eq 'Read') {
                $state.ReadCount++
                if ($state.ReadCount -eq 1) {
                    return [pscustomobject]@{
                        ExitCode = 10
                        OutputBytes = [byte[]]::new(0)
                    }
                }
                return [pscustomobject]@{
                    ExitCode = 0
                    OutputBytes = [byte[]]$state.Key.Clone()
                }
            }
            $state.Key = [byte[]]$InputKey.Clone()
            return [pscustomobject]@{
                ExitCode = 0
                OutputBytes = [byte[]]::new(0)
            }
        }.GetNewClosure()

        $actual = Get-HHMacOSAuditMasterKey `
            -DataRoot $TestDrive `
            -SecurityCommandInvoker $script:securityInvoker `
            -KeychainWorkerInvoker $workerInvoker

        [Convert]::ToHexString($actual) | Should -Be ([Convert]::ToHexString($state.Key))
        $script:securityCalls.Count | Should -Be 1
        $script:securityCalls[0].ArgumentList | Should -Be @('login-keychain')
        @($script:workerCalls | Where-Object Action -EQ 'Create').Count | Should -Be 1
        $createCall = $script:workerCalls | Where-Object Action -EQ 'Create'
        $createCall.InputKey.Length | Should -Be 32
        $createCall.WorkerPath | Should -Match 'MacOSKeychainWorker\.ps1$'
        Test-Path -LiteralPath $createCall.WorkerPath -PathType Leaf | Should -BeTrue
        $createCall.PowerShellPath | Should -Match 'pwsh$'
        $createCall.Service | Should -Be 'com.hosthunter.nextgeneration.audit-key.v1'
        ($createCall.WorkerPath, $createCall.PowerShellPath, $createCall.Action,
            $createCall.KeychainPath, $createCall.Service, $createCall.Account) -contains
            ([Convert]::ToBase64String($createCall.InputKey)) | Should -BeFalse
        Test-Path -LiteralPath (Join-Path $TestDrive 'audit.key') | Should -BeFalse
    }

    It 'uses a duplicate-item race winner without overwriting it' {
        $winner = Get-HHTestAuditKey -Offset 64
        $workerInvoker = Get-HHTestWorkerInvoker `
            -Result @(
                (Get-HHTestWorkerResult -ExitCode 10),
                (Get-HHTestWorkerResult -ExitCode 11),
                (Get-HHTestWorkerResult -OutputBytes $winner)
            ) `
            -Call $script:workerCalls

        $actual = Get-HHMacOSAuditMasterKey `
            -DataRoot $TestDrive `
            -SecurityCommandInvoker $script:securityInvoker `
            -KeychainWorkerInvoker $workerInvoker

        [Convert]::ToHexString($actual) | Should -Be ([Convert]::ToHexString($winner))
        @($script:workerCalls | Where-Object Action -EQ 'Create').Count | Should -Be 1
    }

    It 'fails if successful creation reads back a different key and clears that copy' {
        $differentKey = Get-HHTestAuditKey -Offset 96
        $workerInvoker = Get-HHTestWorkerInvoker `
            -Result @(
                (Get-HHTestWorkerResult -ExitCode 10),
                (Get-HHTestWorkerResult),
                (Get-HHTestWorkerResult -OutputBytes $differentKey)
            ) `
            -Call $script:workerCalls

        {
            Get-HHMacOSAuditMasterKey `
                -DataRoot $TestDrive `
                -SecurityCommandInvoker $script:securityInvoker `
                -KeychainWorkerInvoker $workerInvoker
        } | Should -Throw -ErrorId 'AuditKeychainWriteFailed'
        @($differentKey | Where-Object { $_ -ne 0 }).Count | Should -Be 0
    }

    It 'fails if creation succeeds but the authoritative reread is missing' {
        $workerInvoker = Get-HHTestWorkerInvoker `
            -Result @(
                (Get-HHTestWorkerResult -ExitCode 10),
                (Get-HHTestWorkerResult),
                (Get-HHTestWorkerResult -ExitCode 10)
            ) `
            -Call $script:workerCalls

        {
            Get-HHMacOSAuditMasterKey `
                -DataRoot $TestDrive `
                -SecurityCommandInvoker $script:securityInvoker `
                -KeychainWorkerInvoker $workerInvoker
        } | Should -Throw -ErrorId 'AuditKeychainWriteFailed'
    }

    It 'fails immediately for a native create error' {
        $workerInvoker = Get-HHTestWorkerInvoker `
            -Result @(
                (Get-HHTestWorkerResult -ExitCode 10),
                (Get-HHTestWorkerResult -ExitCode 12)
            ) `
            -Call $script:workerCalls

        {
            Get-HHMacOSAuditMasterKey `
                -DataRoot $TestDrive `
                -SecurityCommandInvoker $script:securityInvoker `
                -KeychainWorkerInvoker $workerInvoker
        } | Should -Throw -ErrorId 'AuditKeychainWriteFailed'
        @($script:workerCalls | Where-Object Action -EQ 'Read').Count | Should -Be 1
    }

    It 'fails closed and clears a wrong-length worker result' {
        $corrupt = [byte[]](1, 2, 3)
        $workerInvoker = Get-HHTestWorkerInvoker `
            -Result @((Get-HHTestWorkerResult -OutputBytes $corrupt)) `
            -Call $script:workerCalls

        {
            Get-HHMacOSAuditMasterKey `
                -DataRoot $TestDrive `
                -SecurityCommandInvoker $script:securityInvoker `
                -KeychainWorkerInvoker $workerInvoker
        } | Should -Throw -ErrorId 'AuditKeychainUnavailable'
        @($corrupt | Where-Object { $_ -ne 0 }).Count | Should -Be 0
    }

    It 'fails closed for a non-missing native read error' {
        $workerInvoker = Get-HHTestWorkerInvoker `
            -Result @((Get-HHTestWorkerResult -ExitCode 12)) `
            -Call $script:workerCalls

        {
            Get-HHMacOSAuditMasterKey `
                -DataRoot $TestDrive `
                -SecurityCommandInvoker $script:securityInvoker `
                -KeychainWorkerInvoker $workerInvoker
        } | Should -Throw -ErrorId 'AuditKeychainUnavailable'
    }

    It 'propagates finite timeout and termination errors from the worker seam' {
        foreach ($errorId in @('AuditKeychainTimedOut', 'AuditKeychainTerminationFailed')) {
            $securityCalls = [System.Collections.Generic.List[object]]::new()
            $securityInvoker = Get-HHTestSecurityInvoker `
                -Result @($script:loginResult) `
                -Call $securityCalls
            $workerError = Get-HHAuditKeyStoreErrorRecord `
                -ErrorId $errorId `
                -Message 'A sanitized worker boundary failure occurred.' `
                -Category ([System.Management.Automation.ErrorCategory]::OperationStopped)
            $workerInvoker = { throw $workerError }.GetNewClosure()
            {
                Get-HHMacOSAuditMasterKey `
                    -DataRoot $TestDrive `
                    -SecurityCommandInvoker $securityInvoker `
                    -KeychainWorkerInvoker $workerInvoker
            } | Should -Throw -ErrorId $errorId
        }
    }

    It 'sanitizes unexpected worker failures' {
        $sensitiveFailure = 'private-native-provider-error'
        $workerInvoker = { throw $sensitiveFailure }.GetNewClosure()
        $caught = $null
        try {
            Get-HHMacOSAuditMasterKey `
                -DataRoot $TestDrive `
                -SecurityCommandInvoker $script:securityInvoker `
                -KeychainWorkerInvoker $workerInvoker
        }
        catch {
            $caught = $_
        }

        $caught.FullyQualifiedErrorId | Should -Be 'AuditKeychainUnavailable'
        $caught.Exception.Message | Should -Not -Match $sensitiveFailure
    }

    It 'rejects malformed and nonnumeric worker results' {
        foreach ($badResult in @(
                [pscustomobject]@{ ExitCode = 0 },
                (Get-HHTestWorkerResult -ExitCode 'not-a-number'),
                (Get-HHTestWorkerResult -OutputBytes 'not-bytes')
            )) {
            $workerInvoker = Get-HHTestWorkerInvoker `
                -Result @($badResult) `
                -Call $script:workerCalls
            {
                Get-HHMacOSAuditMasterKey `
                    -DataRoot $TestDrive `
                    -SecurityCommandInvoker $script:securityInvoker `
                    -KeychainWorkerInvoker $workerInvoker
            } | Should -Throw -ErrorId 'AuditKeychainUnavailable'
        }
    }

    It 'clears byte output attached to a malformed worker result' {
        $sensitiveBytes = Get-HHTestAuditKey -Offset 128
        $workerInvoker = {
            [pscustomobject]@{ OutputBytes = $sensitiveBytes }
        }.GetNewClosure()

        {
            Invoke-HHAuditKeychainWorkerCommand `
                -Action Read `
                -KeychainPath $script:keychainPath `
                -Account 'test-account' `
                -KeychainWorkerInvoker $workerInvoker
        } | Should -Throw -ErrorId 'AuditKeychainUnavailable'
        @($sensitiveBytes | Where-Object { $_ -ne 0 }).Count | Should -Be 0
    }

    It 'sanitizes a directly injected nonnumeric worker exit code' {
        $workerInvoker = {
            [pscustomobject]@{
                ExitCode = 'not-a-number'
                OutputBytes = [byte[]]::new(0)
            }
        }

        {
            Invoke-HHAuditKeychainWorkerCommand `
                -Action Read `
                -KeychainPath $script:keychainPath `
                -Account 'test-account' `
                -KeychainWorkerInvoker $workerInvoker
        } | Should -Throw -ErrorId 'AuditKeychainUnavailable'
    }

    It 'accepts one safely framed indented login-Keychain path' {
        $invoker = Get-HHTestSecurityInvoker `
            -Result @((Get-HHTestSecurityResult -StandardOutput "  `t`"$script:keychainPath`" `t`r`n")) `
            -Call $script:securityCalls

        Get-HHMacOSLoginKeychainPath -SecurityCommandInvoker $invoker |
            Should -Be $script:keychainPath
        $script:securityCalls[0].ArgumentList | Should -Be @('login-keychain')
        $script:securityCalls[0].ArgumentList | Should -Not -Contain '-d'
    }

    It 'rejects malformed, multiple, relative, and uncanonical login paths' {
        $invalidValues = @(
            'relative-keychain',
            '"relative-keychain"',
            "`"$script:keychainPath`"`n`"/tmp/other.keychain-db`"`n",
            "`"/tmp/invalid$([char]0)keychain`""
        )
        foreach ($invalidValue in $invalidValues) {
            $invoker = Get-HHTestSecurityInvoker `
                -Result @((Get-HHTestSecurityResult -StandardOutput $invalidValue)) `
                -Call $script:securityCalls
            { Get-HHMacOSLoginKeychainPath -SecurityCommandInvoker $invoker } |
                Should -Throw -ErrorId 'AuditKeychainUnavailable'
        }
    }

    It 'rejects failed or malformed security process results without raw diagnostics' {
        $sensitiveError = 'private-login-error'
        $failureInvoker = Get-HHTestSecurityInvoker `
            -Result @((Get-HHTestSecurityResult -ExitCode 1 -StandardError $sensitiveError)) `
            -Call $script:securityCalls
        $caught = $null
        try {
            Get-HHMacOSLoginKeychainPath -SecurityCommandInvoker $failureInvoker
        }
        catch {
            $caught = $_
        }
        $caught.FullyQualifiedErrorId | Should -Be 'AuditKeychainUnavailable'
        $caught.Exception.Message | Should -Not -Match $sensitiveError

        foreach ($badResult in @(
                [pscustomobject]@{ ExitCode = 0 },
                [pscustomobject]@{
                    ExitCode = 'not-a-number'
                    StandardOutput = ''
                    StandardError = ''
                }
            )) {
            $badInvoker = { return $badResult }.GetNewClosure()
            { Get-HHMacOSLoginKeychainPath -SecurityCommandInvoker $badInvoker } |
                Should -Throw -ErrorId 'AuditKeychainUnavailable'
        }
    }
}

Describe 'native Keychain service routing closure' -Tag Unit {
    BeforeEach {
        $env:HH_COVERAGE_CASE = [Guid]::NewGuid().ToString('N')
    }

    It 'permits delete only for the two owned services' -Skip:(!$IsLinux) {
        foreach ($service in @(
                $script:HHAuditKeychainService,
                $script:HHPersistenceAnchorKeychainService
            )) {
            $result = Invoke-HHMacOSKeychainWorker `
                -Action Delete `
                -KeychainPath '/tmp/test-login.keychain-db' `
                -Account 'test-account' `
                -Service $service
            $result.ExitCode | Should -Be 14
            $result.OutputBytes.Length | Should -Be 0
        }

        {
            Invoke-HHMacOSKeychainWorker `
                -Action Delete `
                -KeychainPath '/tmp/test-login.keychain-db' `
                -Account 'test-account' `
                -Service 'com.example.unowned'
        } | Should -Throw -ErrorId AuditKeychainUnavailable
    }
}
