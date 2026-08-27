BeforeAll {
    $sourceRoot = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
        Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration'
    }
    else {
        $env:HH_TEST_SOURCE_ROOT
    }
    . (Join-Path $sourceRoot 'Private/Configuration.ps1')
    . (Join-Path $sourceRoot 'Private/SshTrust.ps1')
    $script:keyBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('host-key-material'))
    $script:fingerprint = Get-HHSshKeyFingerprint -PublicKeyBase64 $script:keyBase64
    $script:scanLine = "example.test ssh-ed25519 $script:keyBase64"
}

Describe 'SSH host trust' -Tag Unit {
    BeforeEach {
        $env:HH_COVERAGE_CASE = [Guid]::NewGuid().ToString('N')
        $script:knownHosts = Join-Path $TestDrive "$($env:HH_COVERAGE_CASE)-known_hosts"
    }

    It 'calculates an OpenSSH SHA256 fingerprint' {
        $script:fingerprint | Should -Match '^SHA256:[A-Za-z0-9+/]{43}$'
    }

    It 'rejects invalid base64 host-key data' {
        { Get-HHSshKeyFingerprint -PublicKeyBase64 '%' } | Should -Throw '*not valid base64*'
    }

    It 'rejects invalid hosts and incomplete fingerprints before scanning' {
        { Register-HHSshHostTrust -HostName 'bad host' -Port 22 `
                -ExpectedFingerprint $script:fingerprint -KnownHostsPath $script:knownHosts `
                -KeyScanner { throw 'must not run' } } | Should -Throw '*invalid*'
        { Register-HHSshHostTrust -HostName 'example.test' -Port 22 `
                -ExpectedFingerprint 'SHA256:short' -KnownHostsPath $script:knownHosts `
                -KeyScanner { throw 'must not run' } } | Should -Throw '*complete OpenSSH*'
    }

    It 'rejects discovery that does not contain the expected key' {
        $other = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('different'))
        { Register-HHSshHostTrust -HostName 'example.test' -Port 22 `
                -ExpectedFingerprint $script:fingerprint -KnownHostsPath $script:knownHosts `
                -KeyScanner { "# comment`nmalformed`nexample.test ssh-ed25519 $other" } } |
            Should -Throw '*No discovered SSH host key matched*'
    }

    It 'writes a newly verified key and then treats it idempotently' {
        $first = Register-HHSshHostTrust -HostName 'example.test' -Port 22 `
            -ExpectedFingerprint $script:fingerprint -KnownHostsPath $script:knownHosts `
            -KeyScanner { $script:scanLine } -Confirm:$false
        $second = Register-HHSshHostTrust -HostName 'example.test' -Port 22 `
            -ExpectedFingerprint $script:fingerprint -KnownHostsPath $script:knownHosts `
            -KeyScanner { $script:scanLine } -Confirm:$false
        $first | Should -Be $script:scanLine
        $second | Should -Be $script:scanLine
        @(Get-Content -LiteralPath $script:knownHosts).Count | Should -Be 1
    }

    It 'selects Ed25519 deterministically and announces automatic first-use trust' {
        $ecdsaKey = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('ecdsa-material'))
        Mock Write-Host
        $trusted = Register-HHSshHostTrust -HostName 'example.test' -Port 22 `
            -KnownHostsPath $script:knownHosts -PassThru -Confirm:$false `
            -KeyScanner {
                "example.test ecdsa-sha2-nistp256 $ecdsaKey`n$script:scanLine"
            }

        $trusted.Algorithm | Should -BeExactly ssh-ed25519
        $trusted.Fingerprint | Should -BeExactly $script:fingerprint
        $trusted.NewlyTrusted | Should -BeTrue
        Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter {
            $Object -ceq "Accepting public key ssh-ed25519 $script:fingerprint"
        }
        Get-Content -LiteralPath $script:knownHosts | Should -BeExactly $script:scanLine
    }

    It 'reuses a matching pinned identity without announcing acceptance again' {
        [IO.File]::WriteAllText($script:knownHosts, "$script:scanLine`n")
        Mock Write-Host
        $trusted = Register-HHSshHostTrust -HostName 'example.test' -Port 22 `
            -KnownHostsPath $script:knownHosts -PassThru `
            -KeyScanner { $script:scanLine }

        $trusted.NewlyTrusted | Should -BeFalse
        $trusted.Fingerprint | Should -BeExactly $script:fingerprint
        Should -Invoke Write-Host -Times 0 -Exactly
    }

    It 'preserves separate records when adding a second host to a one-line file' {
        Register-HHSshHostTrust -HostName 'example.test' -Port 22 `
            -ExpectedFingerprint $script:fingerprint -KnownHostsPath $script:knownHosts `
            -KeyScanner { $script:scanLine } -Confirm:$false | Out-Null
        $secondLine = "second.example.test ssh-ed25519 $script:keyBase64"
        Register-HHSshHostTrust -HostName 'second.example.test' -Port 22 `
            -ExpectedFingerprint $script:fingerprint -KnownHostsPath $script:knownHosts `
            -KeyScanner { $secondLine } -Confirm:$false | Out-Null

        $lines = @(Get-Content -LiteralPath $script:knownHosts)
        $lines.Count | Should -Be 2
        $lines | Should -Contain $script:scanLine
        $lines | Should -Contain $secondLine
    }

    It 'does not persist a key under WhatIf' {
        Mock Write-Host
        Register-HHSshHostTrust -HostName 'example.test' -Port 22 `
            -ExpectedFingerprint $script:fingerprint -KnownHostsPath $script:knownHosts `
            -KeyScanner { $script:scanLine } -WhatIf | Should -Be $script:scanLine
        Test-Path -LiteralPath $script:knownHosts | Should -BeFalse
        Should -Invoke Write-Host -Times 0 -Exactly
    }

    It 'rejects a changed key for an already tracked host token' {
        $other = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('different'))
        [IO.File]::WriteAllText($script:knownHosts, "example.test ssh-ed25519 $other`n")
        { Register-HHSshHostTrust -HostName 'example.test' -Port 22 `
                -ExpectedFingerprint $script:fingerprint -KnownHostsPath $script:knownHosts `
                -KeyScanner { $script:scanLine } -Confirm:$false } |
            Should -Throw '*has changed*Credentials were not sent*'
    }

    It 'captures stdout from a successful native process with arguments' {
        $result = Invoke-HHNativeProcess -FileName '/usr/bin/printf' `
            -ArgumentList @('%s:%s', 'alpha', 'beta') -TimeoutSeconds 2

        $result.ExitCode | Should -Be 0
        $result.StandardOutput | Should -BeExactly 'alpha:beta'
        $result.StandardError | Should -BeExactly ''
    }

    It 'runs a successful native process with an empty argument list' {
        $result = Invoke-HHNativeProcess -FileName '/usr/bin/true' `
            -ArgumentList @() -TimeoutSeconds 2

        $result.ExitCode | Should -Be 0
        $result.StandardOutput | Should -BeExactly ''
        $result.StandardError | Should -BeExactly ''
    }

    It 'writes sensitive helper input only through redirected standard input' {
        $inputBytes = [Text.Encoding]::UTF8.GetBytes('stdin-fixture')
        try {
            $result = Invoke-HHNativeProcess -FileName '/bin/cat' `
                -ArgumentList @() -StandardInputBytes $inputBytes -TimeoutSeconds 2
            $result.ExitCode | Should -Be 0
            $result.StandardOutput | Should -BeExactly 'stdin-fixture'
        }
        finally { [Array]::Clear($inputBytes, 0, $inputBytes.Length) }
    }

    It 'terminates a native process when its bounded timeout expires' {
        {
            Invoke-HHNativeProcess -FileName '/bin/sh' `
                -ArgumentList @('-c', 'while :; do :; done') -TimeoutSeconds 0
        } | Should -Throw "*'/bin/sh' exceeded the 0 second timeout*"
    }

    It 'uses the native key scanner when no scanner override is supplied' {
        Mock Invoke-HHNativeProcess {
            [pscustomobject]@{
                ExitCode = 0
                StandardOutput = $script:scanLine
                StandardError = ''
            }
        }

        $trusted = Register-HHSshHostTrust -HostName 'example.test' -Port 2222 `
            -ExpectedFingerprint $script:fingerprint -KnownHostsPath $script:knownHosts `
            -TimeoutSeconds 7 -Confirm:$false

        $trusted | Should -BeExactly $script:scanLine
        Should -Invoke Invoke-HHNativeProcess -Exactly 1 -ParameterFilter {
            $FileName -eq 'ssh-keyscan' -and
            $ArgumentList.Count -eq 5 -and
            $ArgumentList[0] -eq '-p' -and
            $ArgumentList[1] -eq '2222' -and
            $ArgumentList[2] -eq '-T' -and
            $ArgumentList[3] -eq '7' -and
            $ArgumentList[4] -eq 'example.test' -and
            $TimeoutSeconds -eq 9
        }
    }

    It 'accepts valid native scanner output when the scanner also reports an error' {
        Mock Invoke-HHNativeProcess {
            [pscustomobject]@{
                ExitCode = 1
                StandardOutput = $script:scanLine
                StandardError = 'one address did not respond'
            }
        }

        Register-HHSshHostTrust -HostName 'example.test' -Port 22 `
            -ExpectedFingerprint $script:fingerprint -KnownHostsPath $script:knownHosts `
            -Confirm:$false | Should -BeExactly $script:scanLine
    }

    It 'surfaces a native scanner error when no host keys were returned' {
        Mock Invoke-HHNativeProcess {
            [pscustomobject]@{
                ExitCode = 1
                StandardOutput = "`n"
                StandardError = '  scanner unavailable  '
            }
        }

        {
            Register-HHSshHostTrust -HostName 'example.test' -Port 22 `
                -ExpectedFingerprint $script:fingerprint -KnownHostsPath $script:knownHosts
        } | Should -Throw (
            "*Unable to retrieve an SSH host key from 'example.test:22'.*" +
            '*OpenSSH Server (sshd)*port 22*scanner unavailable*'
        )
    }

    It 'explains an empty scanner failure without exposing a blank internal error' {
        Mock Invoke-HHNativeProcess {
            [pscustomobject]@{
                ExitCode = 1
                StandardOutput = ''
                StandardError = ''
            }
        }

        {
            Register-HHSshHostTrust -HostName 'unreachable.test' -Port 2222 `
                -ExpectedFingerprint $script:fingerprint -KnownHostsPath $script:knownHosts
        } | Should -Throw (
            "*Unable to retrieve an SSH host key from 'unreachable.test:2222'.*" +
            '*OpenSSH Server (sshd)*port 2222*firewall*'
        )
    }

    It 'removes the temporary known-hosts file when permission hardening fails' {
        $script:temporaryAttempt = $null
        Mock Protect-HHPrivateFileMode {
            param($Path)
            $script:temporaryAttempt = $Path
            throw 'mode hardening failed'
        }

        {
            Register-HHSshHostTrust -HostName 'example.test' -Port 22 `
                -ExpectedFingerprint $script:fingerprint -KnownHostsPath $script:knownHosts `
                -KeyScanner { $script:scanLine } -Confirm:$false
        } | Should -Throw '*mode hardening failed*'

        $script:temporaryAttempt | Should -Not -BeNullOrEmpty
        Test-Path -LiteralPath $script:temporaryAttempt | Should -BeFalse
        Test-Path -LiteralPath $script:knownHosts | Should -BeFalse
    }
}
