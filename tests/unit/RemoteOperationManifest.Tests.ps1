BeforeAll {
    $sourceRoot = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
        Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration'
    }
    else {
        $env:HH_TEST_SOURCE_ROOT
    }
    . (Join-Path $sourceRoot 'Private/SshTransport.ps1')
    . (Join-Path $sourceRoot 'Private/RemoteOperationManifest.ps1')
}

Describe 'remote operation audit manifests' -Tag Unit {
    BeforeEach {
        $env:HH_COVERAGE_CASE = [Guid]::NewGuid().ToString('N')
    }

    It 'retains exact script text and deterministic non-secret arguments' {
        $scriptText = "param(`$Value) Write-Output `$Value"
        $arguments = @('alpha', 22, $true)

        $entry = Get-HHRemoteOperationManifestEntry `
            -Phase Command `
            -PowerShellRuntime PowerShell7 `
            -ScriptText $scriptText `
            -ArgumentList $arguments

        $entry.Phase | Should -BeExactly 'Command'
        $entry.PowerShellRuntime | Should -BeExactly 'PowerShell7'
        $entry.ScriptText | Should -BeExactly $scriptText
        $entry.SerializedArguments | Should -BeExactly (
            [Management.Automation.PSSerializer]::Serialize([object[]] $arguments, 20)
        )
        $entry.Conditional | Should -BeFalse
    }

    It 'marks conditional operations without changing their exact content' {
        $entry = Get-HHRemoteOperationManifestEntry `
            -Phase BootstrapRollback `
            -PowerShellRuntime PowerShell7 `
            -ScriptText 'rollback-script' `
            -ArgumentList @('public-key-line') `
            -Conditional $true

        $entry.Conditional | Should -BeTrue
        [Management.Automation.PSSerializer]::Deserialize($entry.SerializedArguments) |
            Should -Be @('public-key-line')
    }

    It 'uses the exact identity probe script and empty argument serialization' {
        $entry = Get-HHSshIdentityRemoteOperationManifest `
            -PowerShellRuntime PowerShell7 `
            -Phase OuterIdentity

        $entry.ScriptText | Should -BeExactly ((Get-HHSshIdentityProbeScriptBlock).ToString())
        @([Management.Automation.PSSerializer]::Deserialize($entry.SerializedArguments)).Count |
            Should -Be 0
    }

    It 'supports both PowerShell 7 identity phases without rewriting the script' {
        $expectedScript = (Get-HHSshIdentityProbeScriptBlock).ToString()
        foreach ($case in @(
                @{ Runtime = 'PowerShell7'; Phase = 'OuterIdentity' }
                @{ Runtime = 'PowerShell7'; Phase = 'BootstrapKeyOnlyOuterIdentity' }
            )) {
            $entry = Get-HHSshIdentityRemoteOperationManifest `
                -PowerShellRuntime $case.Runtime `
                -Phase $case.Phase
            $entry.ScriptText | Should -BeExactly $expectedScript
            $entry.PowerShellRuntime | Should -BeExactly $case.Runtime
            $entry.Phase | Should -BeExactly $case.Phase
        }
    }

    It 'rejects blank script text and unsupported manifest fields' {
        {
            Get-HHRemoteOperationManifestEntry `
                -Phase Command `
                -PowerShellRuntime PowerShell7 `
                -ScriptText '   '
        } | Should -Throw '*must not be blank*'
        {
            Get-HHRemoteOperationManifestEntry `
                -Phase Unknown `
                -PowerShellRuntime PowerShell7 `
                -ScriptText 'Get-Date'
        } | Should -Throw
        {
            Get-HHRemoteOperationManifestEntry `
                -Phase Command `
                -PowerShellRuntime PowerShell6 `
                -ScriptText 'Get-Date'
        } | Should -Throw
    }

    It 'describes exact host discovery and direct identity before validation' {
        $target = [pscustomobject]@{
            HostName = 'server.example.test'
            Port = 2222
            PowerShellRuntime = 'PowerShell7'
        }

        $operations = @(Get-HHTargetValidationRemoteOperationManifest `
                -Target $target `
                -IncludeHostTrustDiscovery `
                -HostTrustTimeoutSeconds 17)

        $operations.Count | Should -Be 2
        $operations[0].Phase | Should -BeExactly 'HostTrustDiscovery'
        $operations[0].ScriptText | Should -BeExactly 'ssh-keyscan'
        [Management.Automation.PSSerializer]::Deserialize(
            $operations[0].SerializedArguments
        ) | Should -Be @('-p', '2222', '-T', '17', 'server.example.test')
        $operations[1].Phase | Should -BeExactly 'OuterIdentity'
        $operations[1].PowerShellRuntime | Should -BeExactly 'PowerShell7'
    }

    It 'rejects target manifests without explicit supported runtime metadata' {
        foreach ($runtime in @($null, '', 'PowerShell6')) {
            $target = [pscustomobject]@{ PowerShellRuntime = $runtime }
            { Get-HHTargetValidationRemoteOperationManifest -Target $target } |
                Should -Throw '*explicit supported PowerShell runtime*'
        }
        { Get-HHTargetValidationRemoteOperationManifest -Target ([pscustomobject]@{}) } |
            Should -Throw '*explicit supported PowerShell runtime*'
    }

}
