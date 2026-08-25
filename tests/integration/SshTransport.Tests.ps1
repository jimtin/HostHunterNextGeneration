BeforeAll {
    $sourceRoot = Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration'
    . (Join-Path $sourceRoot 'Private/TargetModel.ps1')
    . (Join-Path $sourceRoot 'Private/SshTransport.ps1')

    function New-SshIntegrationTarget {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
            'PSUseShouldProcessForStateChangingFunctions',
            '',
            Justification = 'This test helper only constructs an in-memory target value.'
        )]
        [CmdletBinding()]
        param(
            [string] $Name = 'ssh-integration',
            [string] $Fingerprint = $script:fixtureFingerprint,
            [string] $UserName = $script:fixtureUserName
        )

        New-HHTargetRecord `
            -Name $Name `
            -Transport SSH `
            -HostName $env:HH_SSH_HOST `
            -Port ([int] $env:HH_SSH_PORT) `
            -UserName $UserName `
            -Authentication Password `
            -HostKeyFingerprint $Fingerprint `
            -IsActive $true `
            -LastValidatedAtUtc ([DateTimeOffset]::Parse('2026-08-23T00:00:00Z')) `
            -LastValidatedPowerShellVersion '7.6.5'
    }

    foreach ($requiredName in @(
            'HH_ARTIFACT_ROOT',
            'HH_SSH_HOST',
            'HH_SSH_PORT',
            'HH_SSH_RUNTIME_DIR'
        )) {
        if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($requiredName))) {
            throw "SSH integration requires $requiredName."
        }
    }

    $script:savedSshEnvironment = @{}
    foreach ($environmentName in @(
            'DISPLAY',
            'HH_SSH_PASSWORD_FILE',
            'SSH_ASKPASS',
            'SSH_ASKPASS_REQUIRE'
        )) {
        $script:savedSshEnvironment[$environmentName] = [Environment]::GetEnvironmentVariable(
            $environmentName,
            'Process'
        )
    }

    $script:integrationDirectory = Join-Path (
        Join-Path $env:HH_ARTIFACT_ROOT (
            '.ssh-transport-integration-{0}' -f [Guid]::NewGuid().ToString('N')
        )
    ) 'Library/Application Support/HostHunterNextGeneration'
    [IO.Directory]::CreateDirectory($script:integrationDirectory) | Out-Null
    & chmod 0700 -- $script:integrationDirectory
    if ($LASTEXITCODE -ne 0) {
        throw 'Unable to secure the SSH integration directory.'
    }

    $script:knownHostsPath = Join-Path $script:integrationDirectory 'known_hosts'
    $scannedKeys = @(& ssh-keyscan `
            -T 5 `
            -p ([int] $env:HH_SSH_PORT) `
            -t ed25519 `
            -- $env:HH_SSH_HOST 2>$null)
    if ($LASTEXITCODE -ne 0 -or $scannedKeys.Count -lt 1) {
        throw 'Unable to scan the disposable SSH fixture host key.'
    }
    [IO.File]::WriteAllLines(
        $script:knownHostsPath,
        [string[]] $scannedKeys,
        [Text.UTF8Encoding]::new($false)
    )
    & chmod 0600 -- $script:knownHostsPath
    if ($LASTEXITCODE -ne 0) {
        throw 'Unable to secure the integration known_hosts file.'
    }

    $runtimeDirectory = $env:HH_SSH_RUNTIME_DIR
    $script:fixtureFingerprint = [IO.File]::ReadAllText(
        (Join-Path $runtimeDirectory 'hostkey.sha256')
    ).Trim()
    $script:fixtureUserName = [IO.File]::ReadAllText(
        (Join-Path $runtimeDirectory 'username')
    ).Trim()
    if ($script:fixtureFingerprint -notmatch '^SHA256:[A-Za-z0-9+/]+$' -or
        $script:fixtureUserName -cne 'hhfixture') {
        throw 'The disposable SSH fixture metadata is invalid.'
    }

    $askpassPath = Join-Path $PSScriptRoot '../fixtures/ssh/fixture-askpass.sh'
    if (-not [IO.File]::Exists($askpassPath)) {
        throw 'The test-only SSH askpass helper is missing.'
    }
    [Environment]::SetEnvironmentVariable('DISPLAY', 'hosthunter-fixture', 'Process')
    [Environment]::SetEnvironmentVariable(
        'HH_SSH_PASSWORD_FILE',
        (Join-Path $runtimeDirectory 'password'),
        'Process'
    )
    [Environment]::SetEnvironmentVariable('SSH_ASKPASS', $askpassPath, 'Process')
    [Environment]::SetEnvironmentVariable('SSH_ASKPASS_REQUIRE', 'force', 'Process')
}

AfterAll {
    foreach ($entry in $script:savedSshEnvironment.GetEnumerator()) {
        [Environment]::SetEnvironmentVariable($entry.Key, $entry.Value, 'Process')
    }
    if ([IO.Directory]::Exists($script:integrationDirectory)) {
        [IO.Directory]::Delete($script:integrationDirectory, $true)
    }
}

Describe 'real PowerShell-over-SSH transport' -Tag Integration {
    It 'opens and runs a password-authenticated command with a macOS-style known-hosts path' {
        $script:knownHostsPath | Should -Match 'Library/Application Support/HostHunterNextGeneration'

        $result = Invoke-HHSshTransport `
            -Target (New-SshIntegrationTarget) `
            -KnownHostsPath $script:knownHostsPath `
            -RemoteScriptBlock { 'macos-default-data-root-password-proof' }

        $result.Succeeded | Should -BeTrue
        @(
            $result.StreamEvents |
                Where-Object { $_.Phase -ceq 'Command' -and $_.Stream -ceq 'Output' } |
                ForEach-Object Value
        ) | Should -Be @('macos-default-data-root-password-proof')
    }

    It 'rejects a wrong strict host-key pin with a macOS-style known-hosts path' {
        $result = Invoke-HHSshTransport `
            -Target (New-SshIntegrationTarget -Fingerprint ('SHA256:' + ('A' * 43))) `
            -KnownHostsPath $script:knownHostsPath `
            -RemoteScriptBlock { 'must-not-run' }

        $result.Succeeded | Should -BeFalse
        $result.FailureKind | Should -BeExactly TrustFailure
        @($result.StreamEvents | Where-Object Phase -eq Command).Count | Should -Be 0
    }

    It 'proves PowerShell 7.6.5 and captures every stream after a non-terminating error' {
        $result = Invoke-HHSshTransport `
            -Target (New-SshIntegrationTarget) `
            -KnownHostsPath $script:knownHostsPath `
            -RemoteScriptBlock {
                'before'
                Write-Error 'non-terminating' -ErrorAction Continue
                Write-Warning 'after-warning'
                Write-Verbose 'after-verbose' -Verbose
                Write-Debug 'after-debug' -Debug
                Write-Information 'after-information'
                'after'
            }

        $result.Succeeded | Should -BeTrue
        $result.RemotePowerShellVersion | Should -BeExactly '7.6.5'
        $result.RemoteIdentity.PSEdition | Should -BeExactly 'Core'
        $result.RemoteIdentity.ProcessPath | Should -Match '[/\\]pwsh$'
        @($result.StreamEvents | Where-Object Phase -eq Command | ForEach-Object Stream) |
            Should -Be @('Output', 'Error', 'Warning', 'Verbose', 'Debug', 'Information', 'Output')
        @($result.StreamEvents | Where-Object Phase -eq Command | ForEach-Object {
                [string] $_.Value
            }) | Should -Be @(
            'before',
            'non-terminating',
            'after-warning',
            'after-verbose',
            'after-debug',
            'after-information',
            'after'
        )
        @($result.StreamEvents | Where-Object Phase -eq Command | ForEach-Object RemoteSequence) |
            Should -Be @(0, 1, 2, 3, 4, 5, 6)
    }

    It 'distinguishes a terminating remote error and never captures the unreachable output' {
        $result = Invoke-HHSshTransport `
            -Target (New-SshIntegrationTarget) `
            -KnownHostsPath $script:knownHostsPath `
            -RemoteScriptBlock {
                'before'
                throw 'terminal'
                'unreachable'
            }

        $result.Succeeded | Should -BeFalse
        $result.FailureKind | Should -BeExactly 'RemoteCommandFailure'
        @($result.StreamEvents | Where-Object IsTerminating).Count | Should -Be 1
        @($result.StreamEvents | ForEach-Object { [string] $_.Value }) -join "`n" |
            Should -Not -Match 'unreachable'
    }

    It 'stops a streaming remote pipeline when the per-target plaintext cap is exceeded' {
        $stopwatch = [Diagnostics.Stopwatch]::StartNew()
        $result = Invoke-HHSshTransport `
            -Target (New-SshIntegrationTarget) `
            -KnownHostsPath $script:knownHostsPath `
            -MaxOutputBytes 12000 `
            -RemoteScriptBlock {
                1..100000 | ForEach-Object {
                    'x' * 1024
                    Start-Sleep -Milliseconds 1
                }
            }
        $stopwatch.Stop()

        $result.Succeeded | Should -BeFalse
        $result.FailureKind | Should -BeExactly 'OutputLimitExceeded'
        $result.OutputBytes | Should -BeLessOrEqual 12000
        @($result.StreamEvents | Where-Object Phase -eq Command).Count | Should -BeLessThan 100000
        $stopwatch.Elapsed | Should -BeLessThan ([TimeSpan]::FromSeconds(10))
    }

    It 'fails closed when native remoting omits password-rejection detail from its exception' {
        $savedPasswordFile = $env:HH_SSH_PASSWORD_FILE
        try {
            $env:HH_SSH_PASSWORD_FILE = Join-Path $script:integrationDirectory 'missing-password'
            $result = Invoke-HHSshTransport `
                -Target (New-SshIntegrationTarget) `
                -KnownHostsPath $script:knownHostsPath `
                -ConnectionTimeoutSeconds 5
        }
        finally {
            $env:HH_SSH_PASSWORD_FILE = $savedPasswordFile
        }

        $result.Succeeded | Should -BeFalse
        $result.FailureKind | Should -BeExactly 'TransportFailure'
        $result.ExceptionType | Should -BeExactly (
            'System.Management.Automation.Remoting.PSRemotingTransportException'
        )
    }

    It 'bounds wrong-user authentication and produces an accountability-safe event by default' {
        $stopwatch = [Diagnostics.Stopwatch]::StartNew()
        $result = Invoke-HHSshTransport `
            -Target (New-SshIntegrationTarget -UserName 'hhfixture-invalid') `
            -KnownHostsPath $script:knownHostsPath
        $stopwatch.Stop()

        $result.Succeeded | Should -BeFalse
        $result.FailureKind | Should -BeExactly 'TransportFailure'
        $result.ExceptionType | Should -BeExactly (
            'System.Management.Automation.Remoting.PSRemotingTransportException'
        )
        $result.StreamEvents[-1].Value | Should -BeOfType ([string])
        $jsonStopwatch = [Diagnostics.Stopwatch]::StartNew()
        $json = @($result.StreamEvents | ForEach-Object {
                $_ | ConvertTo-Json -Depth 20 -Compress
            }) -join "`n"
        $jsonStopwatch.Stop()

        $json.Length | Should -BeLessThan 16384
        $stopwatch.Elapsed | Should -BeLessThan ([TimeSpan]::FromSeconds(30))
        $jsonStopwatch.Elapsed | Should -BeLessThan ([TimeSpan]::FromSeconds(2))
    }

    It 'uses one multi-session Invoke-Command and attributes every stream to the correct result' {
        $contexts = [ordered]@{}
        try {
            foreach ($name in @('alpha', 'beta')) {
                $contexts[$name] = Open-HHSshSession `
                    -Target (New-SshIntegrationTarget -Name $name) `
                    -KnownHostsPath $script:knownHostsPath
            }
            $result = Invoke-HHSshSessionFanOut `
                -SessionContextByName $contexts `
                -ScriptBlock {
                    param($prefix, $number)
                    "$prefix-$number-before"
                    Write-Error 'non-terminating' -ErrorAction Continue
                    Write-Warning 'later'
                    "$prefix-$number-after"
                } `
                -ArgumentList @('value', 42) `
                -ThrottleLimit 2

            foreach ($name in @('alpha', 'beta')) {
                $result[$name].Succeeded | Should -BeTrue
                @($result[$name].StreamEvents | Where-Object Phase -eq Command |
                        ForEach-Object Stream) | Should -Be @('Output', 'Error', 'Warning', 'Output')
                @($result[$name].StreamEvents | Where-Object Phase -eq Command |
                        ForEach-Object { [string] $_.Value }) |
                    Should -Be @('value-42-before', 'non-terminating', 'later', 'value-42-after')
            }
            $contexts.alpha.Session.InstanceId | Should -Not -Be $contexts.beta.Session.InstanceId
        }
        finally {
            foreach ($context in $contexts.Values) {
                Close-HHSshSession -Session $context.Session
            }
        }
    }

    It 'stops the shared fan-out pipeline when one target exceeds its independent cap' {
        $contexts = [ordered]@{}
        try {
            foreach ($name in @('alpha-limit', 'beta-limit')) {
                $contexts[$name] = Open-HHSshSession `
                    -Target (New-SshIntegrationTarget -Name $name) `
                    -KnownHostsPath $script:knownHostsPath
            }
            $result = Invoke-HHSshSessionFanOut `
                -SessionContextByName $contexts `
                -ScriptBlock { 1..10000 | ForEach-Object { 'x' * 512 } } `
                -ThrottleLimit 2 `
                -MaxOutputBytes 9000

            @($result.Values | Where-Object FailureKind -eq OutputLimitExceeded).Count |
                Should -Be 1
            @($result.Values | Where-Object FailureKind -eq TransportFailure).Count |
                Should -Be 1
            foreach ($targetResult in $result.Values) {
                $targetResult.OutputBytes | Should -BeLessOrEqual 9000
            }
        }
        finally {
            foreach ($context in $contexts.Values) {
                Close-HHSshSession -Session $context.Session
            }
        }
    }
}
