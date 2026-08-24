BeforeAll {
    $sourceRoot = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
        Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration'
    }
    else {
        $env:HH_TEST_SOURCE_ROOT
    }
    . (Join-Path $sourceRoot 'Private/TargetModel.ps1')
    . (Join-Path $sourceRoot 'Private/SshTransport.ps1')
    . (Join-Path $sourceRoot 'Private/WinRmTransport.ps1')
    . (Join-Path $sourceRoot 'Private/RemoteOperations.ps1')
}

Describe 'remote operation dispatch' -Tag Unit {
    BeforeEach {
        $env:HH_COVERAGE_CASE = [Guid]::NewGuid().ToString('N')
        $key = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('host-key'))
        $digest = [Security.Cryptography.SHA256]::HashData([Convert]::FromBase64String($key))
        $script:fingerprint = "SHA256:$([Convert]::ToBase64String($digest).TrimEnd('='))"
        $script:knownHosts = Join-Path $TestDrive "$($env:HH_COVERAGE_CASE)-known_hosts"
        [IO.File]::WriteAllText($script:knownHosts, "example.test ssh-ed25519 $key`n")
        $script:runtime = [pscustomobject]@{ KnownHostsPath = $script:knownHosts }
        $script:target = New-HHTargetRecord -Name alpha -Transport SSH `
            -HostName example.test -Port 22 -UserName operator -Authentication Password `
            -HostKeyFingerprint $script:fingerprint -KeyPath $null -IsActive $true `
            -LastValidatedAtUtc ([DateTimeOffset]::UtcNow) `
            -LastValidatedPowerShellVersion '7.6.5'
    }

    It 'dispatches an SSH identity probe through injected session seams' {
        $result = Invoke-HHTargetProbe -Target $script:target -RuntimeContext $script:runtime `
            -SshSessionFactory { param($plan) $plan } `
            -SshRemoteInvoker {
                param($session, $scriptBlock, $arguments)
                $null = $session, $scriptBlock, $arguments
                [pscustomobject]@{
                    Marker = 'HostHunter.PowerShellIdentity.v1'
                    PSEdition = 'Core'
                    PowerShellVersion = '7.6.5'
                    ProcessPath = '/usr/bin/pwsh'
                    UserName = 'operator'
                    MachineName = 'fixture'
                }
            } `
            -SshSessionRemover { param($session) $null = $session }
        $result.Succeeded | Should -BeTrue
    }

    It 'dispatches a Windows PowerShell 5.1 probe through the explicit bridge seam' {
        $target = New-HHTargetRecord -Name compat -Transport SSH `
            -HostName example.test -Port 22 -UserName operator -Authentication Password `
            -PowerShellRuntime WindowsPowerShell51 `
            -HostKeyFingerprint $script:fingerprint -KeyPath $null -IsActive $true `
            -LastValidatedAtUtc ([DateTimeOffset]::UtcNow) `
            -LastValidatedPowerShellVersion '5.1.26100.1'
        $result = Invoke-HHTargetProbe -Target $target -RuntimeContext $script:runtime `
            -SshSessionFactory { [pscustomobject]@{ InstanceId = [Guid]::NewGuid() } } `
            -SshRemoteInvoker {
                [pscustomobject]@{
                    Marker = 'HostHunter.PowerShellIdentity.v1'
                    PSEdition = 'Core'
                    PowerShellVersion = '7.6.5'
                    ProcessPath = '/usr/bin/pwsh'
                    UserName = 'operator'
                    MachineName = 'fixture'
                }
            } `
            -SshBridgeInvoker {
                [pscustomobject]@{
                    Marker = 'HostHunter.StreamEnvelope.v1'
                    Kind = 'Stream'
                    Sequence = 0
                    Stream = 'Output'
                    TypeName = 'System.Management.Automation.PSCustomObject'
                    IsTerminating = $false
                    Value = [pscustomobject]@{
                        Marker = 'HostHunter.PowerShellIdentity.v1'
                        PSEdition = 'Desktop'
                        PowerShellVersion = '5.1.26100.1'
                        ProcessPath = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
                        UserName = 'operator'
                        MachineName = 'fixture'
                    }
                }
                [pscustomobject]@{
                    Marker = 'HostHunter.StreamEnvelope.v1'
                    Kind = 'Completion'
                    Sequence = 1
                    Terminated = $false
                    DispatchState = 'Completed'
                    OutcomeStatus = 'Succeeded'
                    FailureKind = $null
                }
            } `
            -SshSessionRemover {}

        $result.Succeeded | Should -BeTrue
        $result.RemotePSEdition | Should -BeExactly 'Desktop'
        $result.RemotePowerShellVersion | Should -BeExactly '5.1.26100.1'
        $result.ExecutionMode | Should -BeExactly 'WindowsPowerShellCompatibility'
    }

    It 'rejects WinRM even on a Windows controller while qualification is deferred' {
        $winTarget = [pscustomobject]@{ Transport = 'WinRM'; Name = 'win' }
        {
            Invoke-HHTargetProbe -Target $winTarget -RuntimeContext $script:runtime `
                -IsWindowsController $true
        } | Should -Throw '*qualification is blocked*'
    }

    It 'rejects unsupported transports and failed validation results' {
        { Invoke-HHTargetProbe -Target @{ Transport = 'Other' } -RuntimeContext $script:runtime } |
            Should -Throw '*Unsupported target transport*'
        { Test-HHTransportResult -Result @{ Succeeded = $false; FailureKind = 'TrustFailure' } } |
            Should -Throw '*TrustFailure*'
        Test-HHTransportResult -Result @{ Succeeded = $true } | Should -Not -BeNullOrEmpty
    }
}
