BeforeAll {
    $sourceRoot = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
        Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration'
    }
    else {
        $env:HH_TEST_SOURCE_ROOT
    }
    . (Join-Path $sourceRoot 'Private/TargetModel.ps1')
    . (Join-Path $sourceRoot 'Private/RemoteOperationManifest.ps1')
    . (Join-Path $sourceRoot 'Private/SshTransport.ps1')
    . (Join-Path $sourceRoot 'Private/SshKeyBootstrap.ps1')

    $script:runtimeDirectory = $env:HH_SSH_RUNTIME_DIR
    $script:targetHost = $env:HH_SSH_HOST
    $script:targetPort = if ([string]::IsNullOrWhiteSpace($env:HH_SSH_PORT)) {
        22
    }
    else {
        [int] $env:HH_SSH_PORT
    }
    if ([string]::IsNullOrWhiteSpace($script:runtimeDirectory) -or
        [string]::IsNullOrWhiteSpace($script:targetHost)) {
        throw 'The SSH bootstrap integration fixture environment is not configured.'
    }

    $script:userName = [IO.File]::ReadAllText(
        (Join-Path $script:runtimeDirectory 'username')
    ).Trim()
    $script:trustedFingerprint = [IO.File]::ReadAllText(
        (Join-Path $script:runtimeDirectory 'hostkey.sha256')
    ).Trim()
    $script:authorizedKeysPath = '/home/hhfixture/.ssh/authorized_keys'

    $script:environmentNames = @(
        'DISPLAY',
        'HH_SSH_PASSWORD_FILE',
        'SSH_ASKPASS',
        'SSH_ASKPASS_REQUIRE'
    )
    $script:savedEnvironment = @{}
    foreach ($environmentName in $script:environmentNames) {
        $script:savedEnvironment[$environmentName] = [Environment]::GetEnvironmentVariable(
            $environmentName,
            'Process'
        )
    }
    $env:DISPLAY = 'hosthunter-bootstrap-integration'
    $env:HH_SSH_PASSWORD_FILE = Join-Path $script:runtimeDirectory 'password'
    $env:SSH_ASKPASS = (Resolve-Path (
            Join-Path $PSScriptRoot '../fixtures/ssh/fixture-askpass.sh'
        )).Path
    $env:SSH_ASKPASS_REQUIRE = 'force'

    function New-HHBootstrapFixtureTarget {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
            'PSUseShouldProcessForStateChangingFunctions',
            '',
            Justification = 'This test helper constructs an in-memory target only.'
        )]
        param([Parameter(Mandatory)][string] $Fingerprint)

        New-HHTargetRecord `
            -Name 'ssh-bootstrap-fixture' `
            -Transport SSH `
            -HostName $script:targetHost `
            -Port $script:targetPort `
            -UserName $script:userName `
            -Authentication Password `
            -HostKeyFingerprint $Fingerprint `
            -KeyPath $null `
            -IsActive $true `
            -LastValidatedAtUtc '2026-08-23T00:00:00.0000000Z' `
            -LastValidatedPowerShellVersion '7.6.5'
    }

    function Open-HHBootstrapFixturePasswordContext {
        $plan = New-HHSshTransportPlan `
            -Target $script:fixtureTarget `
            -KnownHostsPath $script:knownHostsPath `
            -ConnectionTimeoutSeconds 10
        Open-HHSshValidatedSession -Plan $plan -MaxOutputBytes 1048576
    }

    function Set-HHBootstrapFixtureAuthorizedKeyFile {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
            'PSUseShouldProcessForStateChangingFunctions',
            '',
            Justification = 'This mutates only the disposable integration fixture under explicit test control.'
        )]
        param([AllowEmptyCollection()][string[]] $Lines = @())

        $context = $null
        try {
            $context = Open-HHBootstrapFixturePasswordContext
            $serializedLines = [Management.Automation.PSSerializer]::Serialize(
                [string[]] $Lines,
                5
            )
            Invoke-Command -Session $context.Session -ScriptBlock {
                param($SerializedLines, $AuthorizedKeysPath)
                $authorizedKeysDirectory = Split-Path -Parent $AuthorizedKeysPath
                [IO.Directory]::CreateDirectory($authorizedKeysDirectory) | Out-Null
                $linesToWrite = [Management.Automation.PSSerializer]::Deserialize($SerializedLines)
                [IO.File]::WriteAllLines(
                    $AuthorizedKeysPath,
                    [string[]] $linesToWrite,
                    [Text.UTF8Encoding]::new($false)
                )
                & chmod 0700 -- $authorizedKeysDirectory
                if ($LASTEXITCODE -ne 0) {
                    throw 'Unable to secure the fixture SSH directory.'
                }
                & chmod 0600 -- $AuthorizedKeysPath
                if ($LASTEXITCODE -ne 0) {
                    throw 'Unable to secure the fixture authorized_keys file.'
                }
            } -ArgumentList $serializedLines, $script:authorizedKeysPath -ErrorAction Stop
        }
        finally {
            if ($null -ne $context) {
                Close-HHSshSession -Session $context.Session
            }
        }
    }

    function Get-HHBootstrapFixtureAuthorizedKeysState {
        $context = $null
        try {
            $context = Open-HHBootstrapFixturePasswordContext
            $state = Invoke-Command -Session $context.Session -ScriptBlock {
                param($AuthorizedKeysPath)
                [pscustomobject]@{
                    Lines = [string[]] [IO.File]::ReadAllLines($AuthorizedKeysPath)
                    FileMode = [string] (& stat --format '%a' -- $AuthorizedKeysPath)
                    DirectoryMode = [string] (& stat --format '%a' -- (Split-Path -Parent $AuthorizedKeysPath))
                }
            } -ArgumentList $script:authorizedKeysPath -ErrorAction Stop
            return $state
        }
        finally {
            if ($null -ne $context) {
                Close-HHSshSession -Session $context.Session
            }
        }
    }
}

AfterAll {
    foreach ($environmentName in $script:environmentNames) {
        [Environment]::SetEnvironmentVariable(
            $environmentName,
            $script:savedEnvironment[$environmentName],
            'Process'
        )
    }
}

Describe 'SSH key bootstrap against the disposable PowerShell-over-SSH fixture' -Tag Integration {
    BeforeEach {
        $env:HH_COVERAGE_CASE = [Guid]::NewGuid().ToString('N')
        $script:fixtureTarget = $null
        $script:knownHostsPath = Join-Path $TestDrive "$($env:HH_COVERAGE_CASE)-known_hosts"
        $scannedHostKeys = @(
            & ssh-keyscan `
                -T 5 `
                -p $script:targetPort `
                -t ed25519 `
                -- $script:targetHost 2>$null
        )
        $LASTEXITCODE | Should -Be 0
        $scannedHostKeys.Count | Should -BeGreaterThan 0
        [IO.File]::WriteAllLines(
            $script:knownHostsPath,
            [string[]] $scannedHostKeys,
            [Text.UTF8Encoding]::new($false)
        )
        [IO.File]::SetUnixFileMode(
            $script:knownHostsPath,
            [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite
        )
        $scannedFingerprints = @(
            foreach ($line in $scannedHostKeys) {
                $parts = @($line.Trim() -split '\s+')
                if ($parts.Count -ge 3) {
                    Get-HHSshPublicKeyFingerprint -PublicKeyLine "$($parts[1]) $($parts[2])"
                }
            }
        ) | Sort-Object -Unique
        $scannedFingerprints | Should -Be @($script:trustedFingerprint)
        $script:fixtureTarget = New-HHBootstrapFixtureTarget -Fingerprint $script:trustedFingerprint
        Set-HHBootstrapFixtureAuthorizedKeyFile
    }

    AfterEach {
        if ($null -ne $script:fixtureTarget -and
            -not [string]::IsNullOrWhiteSpace($script:knownHostsPath)) {
            Set-HHBootstrapFixtureAuthorizedKeyFile
        }
    }

    It 'installs one exact marker, proves PublicKey authentication, and remains idempotent' {
        $keyPath = Join-Path $TestDrive "$($env:HH_COVERAGE_CASE)-id_ed25519"
        & ssh-keygen -q -t ed25519 -N '' -f $keyPath -C hosthunter-bootstrap-integration
        $LASTEXITCODE | Should -Be 0

        $first = Invoke-HHSshKeyBootstrap `
            -Target $script:fixtureTarget `
            -KnownHostsPath $script:knownHostsPath `
            -KeyPath $keyPath `
            -UseExistingKey `
            -ConnectionTimeoutSeconds 10 `
            -Confirm:$false
        $second = Invoke-HHSshKeyBootstrap `
            -Target $script:fixtureTarget `
            -KnownHostsPath $script:knownHostsPath `
            -KeyPath $keyPath `
            -UseExistingKey `
            -ConnectionTimeoutSeconds 10 `
            -Confirm:$false

        $firstDiagnostic = 'failureKind={0}; exceptionType={1}; eventErrors={2}' -f @(
            $first.FailureKind,
            $first.ExceptionType,
            (@(
                    $first.StreamEvents |
                        Where-Object Stream -eq 'Error' |
                        ForEach-Object {
                            if ($null -ne $_.Value.PSObject.Properties['FullyQualifiedErrorId']) {
                                [string] $_.Value.FullyQualifiedErrorId
                            }
                            else {
                                [string] $_.TypeName
                            }
                        }
                ) -join ',')
        )
        $first.Succeeded | Should -BeTrue -Because $firstDiagnostic
        $first.Installed | Should -BeTrue
        $first.ProfileTransition.Authentication | Should -Be 'PublicKey'
        $second.Succeeded | Should -BeTrue
        $second.Installed | Should -BeFalse
        $second.ProfileTransition.Authentication | Should -Be 'PublicKey'

        $material = Get-HHSshBootstrapPublicKey -KeyPath $keyPath
        $state = Get-HHBootstrapFixtureAuthorizedKeysState
        @($state.Lines | Where-Object { $_ -ceq $material.ExactLine }).Count | Should -Be 1
        $state.FileMode | Should -Be '600'
        $state.DirectoryMode | Should -Be '700'

        $savedPasswordPath = $env:HH_SSH_PASSWORD_FILE
        $env:HH_SSH_PASSWORD_FILE = '/tmp/hosthunter-deliberately-absent-password'
        try {
            $keyOnlyInvocation = Invoke-HHSshTransport `
                -Target $first.ProfileTransition `
                -KnownHostsPath $script:knownHostsPath `
                -RemoteScriptBlock { [Environment]::UserName } `
                -ConnectionTimeoutSeconds 10
        }
        finally {
            $env:HH_SSH_PASSWORD_FILE = $savedPasswordPath
        }
        $keyOnlyInvocation.Succeeded | Should -BeTrue
        @(
            $keyOnlyInvocation.StreamEvents |
                Where-Object { $_.Phase -ceq 'Command' -and $_.Stream -ceq 'Output' } |
                ForEach-Object Value
        ) | Should -Be @($script:userName)
    }

    It 'rolls back only its added marker when the separate key-only proof is rejected' {
        $selectedKeyPath = Join-Path $TestDrive "$($env:HH_COVERAGE_CASE)-selected"
        $mismatchKeyPath = Join-Path $TestDrive "$($env:HH_COVERAGE_CASE)-mismatch"
        $unrelatedKeyPath = Join-Path $TestDrive "$($env:HH_COVERAGE_CASE)-unrelated"
        foreach ($path in @($selectedKeyPath, $mismatchKeyPath, $unrelatedKeyPath)) {
            & ssh-keygen -q -t ed25519 -N '' -f $path -C "integration-$([IO.Path]::GetFileName($path))"
            $LASTEXITCODE | Should -Be 0
        }
        $script:mismatchPublicLine = [IO.File]::ReadAllText("$mismatchKeyPath.pub").Trim()
        $unrelatedLine = [IO.File]::ReadAllText("$unrelatedKeyPath.pub").Trim()
        Set-HHBootstrapFixtureAuthorizedKeyFile -Lines @($unrelatedLine)

        $result = Invoke-HHSshKeyBootstrap `
            -Target $script:fixtureTarget `
            -KnownHostsPath $script:knownHostsPath `
            -KeyPath $selectedKeyPath `
            -UseExistingKey `
            -PublicKeyReader { $script:mismatchPublicLine } `
            -ConnectionTimeoutSeconds 10 `
            -Confirm:$false

        $failureDiagnostic = 'rollbackAttempted={0}; rollbackSucceeded={1}; exceptionType={2}; events={3}; eventErrors={4}' -f @(
            $result.RollbackAttempted,
            $result.RollbackSucceeded,
            $result.ExceptionType,
            @($result.StreamEvents).Count,
            (@(
                    $result.StreamEvents |
                        Where-Object Stream -eq 'Error' |
                        ForEach-Object {
                            if ($null -ne $_.Value.PSObject.Properties['FullyQualifiedErrorId']) {
                                [string] $_.Value.FullyQualifiedErrorId
                            }
                            else {
                                [string] $_.TypeName
                            }
                        }
                ) -join ',')
        )
        $result.Succeeded | Should -BeFalse
        $result.FailureKind | Should -Be 'AuthenticationFailure' -Because $failureDiagnostic
        $result.ProfileTransition | Should -BeNullOrEmpty
        $result.Installed | Should -BeTrue
        $result.RollbackAttempted | Should -BeTrue
        $result.RollbackSucceeded | Should -BeTrue
        $result.LocalKeyRemovedOnFailure | Should -BeFalse
        Test-Path -LiteralPath $selectedKeyPath | Should -BeTrue
        Test-Path -LiteralPath "$selectedKeyPath.pub" | Should -BeTrue

        $state = Get-HHBootstrapFixtureAuthorizedKeysState
        @($state.Lines) | Should -Be @($unrelatedLine)
        $state.FileMode | Should -Be '600'
    }
}
