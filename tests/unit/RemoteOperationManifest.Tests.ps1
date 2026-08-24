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
            -PowerShellRuntime WindowsPowerShell51 `
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

    It 'supports every identity phase and requested runtime without rewriting the script' {
        $expectedScript = (Get-HHSshIdentityProbeScriptBlock).ToString()
        foreach ($case in @(
                @{ Runtime = 'PowerShell7'; Phase = 'OuterIdentity' }
                @{ Runtime = 'WindowsPowerShell51'; Phase = 'RuntimeIdentity' }
                @{ Runtime = 'PowerShell7'; Phase = 'BootstrapKeyOnlyOuterIdentity' }
                @{ Runtime = 'WindowsPowerShell51'; Phase = 'BootstrapKeyOnlyRuntimeIdentity' }
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

    It 'includes both identity probes and the exact candidate invocation for 5.1' {
        $target = [pscustomobject]@{ PowerShellRuntime = 'WindowsPowerShell51' }
        $scriptBlock = { param($CommandText) & ([scriptblock]::Create($CommandText)) }
        $operations = @(Get-HHCommandRemoteOperationManifest `
                -Target $target `
                -ScriptBlock $scriptBlock `
                -ArgumentList @('Get-Date'))

        $operations.Phase | Should -Be @('OuterIdentity', 'RuntimeIdentity', 'Command')
        $operations.PowerShellRuntime |
            Should -Be @('PowerShell7', 'WindowsPowerShell51', 'WindowsPowerShell51')
        $operations[-1].ScriptText | Should -BeExactly $scriptBlock.ToString()
        [Management.Automation.PSSerializer]::Deserialize(
            $operations[-1].SerializedArguments
        ) | Should -Be @('Get-Date')
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

    It 'matches the exact logical script and serialized arguments sent by transport' {
        $candidate = { param($Value) Write-Output $Value }
        $candidateArguments = @('exact-value')
        $entry = Get-HHRemoteOperationManifestEntry `
            -Phase Command `
            -PowerShellRuntime WindowsPowerShell51 `
            -ScriptText $candidate.ToString() `
            -ArgumentList $candidateArguments
        $script:wireArguments = $null

        $events = @(Invoke-HHSshRemoteCapture `
                -Session ([pscustomobject]@{}) `
                -ScriptBlock $candidate `
                -ArgumentList $candidateArguments `
                -Phase Command `
                -PowerShellRuntime WindowsPowerShell51 `
                -BridgeInvoker {
                    param($session, $wrapper, $argumentList)
                    $null = $session, $wrapper
                    $script:wireArguments = @($argumentList)
                    [pscustomobject]@{
                        Marker = 'HostHunter.StreamEnvelope.v1'
                        Kind = 'Stream'
                        Sequence = 0
                        Stream = 'Output'
                        TypeName = 'System.String'
                        IsTerminating = $false
                        Value = 'exact-value'
                    }
                    [pscustomobject]@{
                        Marker = 'HostHunter.StreamEnvelope.v1'
                        Kind = 'Completion'
                        Sequence = 1
                        Terminated = $false
                        FailureKind = $null
                        DispatchState = 'Completed'
                        OutcomeStatus = 'Succeeded'
                    }
                })

        $events.Count | Should -Be 1
        $script:wireArguments[0] | Should -BeExactly $entry.ScriptText
        $script:wireArguments[1] | Should -BeExactly $entry.SerializedArguments
    }
}
