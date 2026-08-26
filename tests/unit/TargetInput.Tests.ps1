BeforeAll {
    $sourceRoot = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
        Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration'
    }
    else {
        $env:HH_TEST_SOURCE_ROOT
    }
    . (Join-Path $sourceRoot 'Private/TargetModel.ps1')
    . (Join-Path $sourceRoot 'Private/TargetInput.ps1')
}

Describe 'target input conversion' -Tag Unit {
    BeforeEach {
        $env:HH_COVERAGE_CASE = [Guid]::NewGuid().ToString('N')
        $script:fingerprint = "SHA256:$('A' * 43)"
        $script:proposal = [pscustomobject]@{
            Name = 'alpha'
            Transport = 'SSH'
            HostName = 'example.test'
            Port = 22
            UserName = 'operator'
            Authentication = 'Password'
            HostKeyFingerprint = $script:fingerprint
        }
    }

        It 'selects a corresponding value from a complete property array' {
            Get-HHInputValue -Value @('first', 'second') -Index 1 -ExpectedCount 2 -Name Example |
                Should -BeExactly second
        }

        It 'broadcasts a single input value and rejects an incomplete array' {
            Get-HHInputValue -Value @('shared') -Index 1 -ExpectedCount 2 -Name Example |
                Should -BeExactly shared
            { Get-HHInputValue -Value @('one', 'two', 'three') -Index 0 -ExpectedCount 2 -Name Example } |
                Should -Throw "*Parameter 'Example' must contain either one value or 2 values*"
        }

        It 'rejects each secret-bearing input property before target construction' {
            foreach ($propertyName in @('Password', 'Credential', 'Secret', 'Token')) {
                $candidate = $script:proposal.PSObject.Copy()
                Add-Member -InputObject $candidate -NotePropertyName $propertyName -NotePropertyValue hidden
                { ConvertTo-HHProposedTarget -InputObject $candidate } |
                    Should -Throw "*cannot contain '$propertyName'*"
            }
        }

        It 'reports every required property when it is absent' {
            foreach ($propertyName in @('Name', 'HostName', 'Port', 'UserName', 'Authentication')) {
                $candidate = [ordered]@{}
                foreach ($property in $script:proposal.PSObject.Properties) {
                    if ($property.Name -ne $propertyName) {
                        $candidate[$property.Name] = $property.Value
                    }
                }
                { ConvertTo-HHProposedTarget -InputObject ([pscustomobject]$candidate) } |
                    Should -Throw "*missing '$propertyName'*"
            }
        }

        It 'accepts optional SSH fingerprint and key-path fields when present' {
            $keyPath = Join-Path $TestDrive 'id_ed25519'
            [IO.File]::WriteAllText($keyPath, 'test-only-key')
            $candidate = $script:proposal.PSObject.Copy()
            $candidate.Authentication = 'PublicKey'
            Add-Member -InputObject $candidate -NotePropertyName KeyPath -NotePropertyValue $keyPath

            $target = ConvertTo-HHProposedTarget -InputObject $candidate
            $target.HostKeyFingerprint | Should -BeExactly $script:fingerprint
            $target.KeyPath | Should -BeExactly ([IO.Path]::GetFullPath($keyPath))
            $target.PowerShellRuntime | Should -BeExactly 'PowerShell7'
            $target.LastValidatedPSEdition | Should -BeExactly 'Core'
            $target.LastValidatedExecutionMode | Should -BeExactly 'Direct'
        }

        It 'treats absent SSH-only optional properties as null' {
            $candidate = [pscustomobject]@{
                Name = 'unpinned-proposal'
                Transport = 'SSH'
                HostName = 'example.test'
                Port = 22
                UserName = 'operator'
                Authentication = 'Password'
            }

            $target = ConvertTo-HHProposedTarget -InputObject $candidate

            $target.HostKeyFingerprint | Should -BeNullOrEmpty
            $target.KeyPath | Should -BeNullOrEmpty
            $target.PowerShellRuntime | Should -BeExactly 'PowerShell7'
        }

        It 'rejects an explicit Windows PowerShell 5.1 compatibility proposal' {
            $candidate = $script:proposal.PSObject.Copy()
            Add-Member `
                -InputObject $candidate `
                -NotePropertyName PowerShellRuntime `
                -NotePropertyValue WindowsPowerShell51

            { ConvertTo-HHProposedTarget -InputObject $candidate } |
                Should -Throw '*Only PowerShell7 target creation is supported*'
        }

        It 'rejects WinRM proposals while first-release qualification is deferred' {
            $candidate = [pscustomobject]@{
                Name = 'windows'
                Transport = 'WinRM'
                HostName = 'windows.example.test'
                Port = 5985
                UserName = 'DOMAIN\operator'
                Authentication = 'Kerberos'
            }

            { ConvertTo-HHProposedTarget -InputObject $candidate } |
                Should -Throw '*Only SSH target creation is supported*'
        }

        It 'persists only observed runtime fields from a successful probe result' {
            $target = ConvertTo-HHProposedTarget -InputObject $script:proposal
            $result = [pscustomobject]@{
                ValidatedAtUtc = '2026-08-24T01:02:03Z'
                RemotePSEdition = 'Core'
                RemotePowerShellVersion = '7.6.5'
                ExecutionMode = 'Direct'
            }

            $validated = ConvertTo-HHValidatedProbeTarget -Target $target -TransportResult $result

            $validated.LastValidatedAtUtc | Should -BeExactly '2026-08-24T01:02:03.0000000Z'
            $validated.LastValidatedPSEdition | Should -BeExactly 'Core'
            $validated.LastValidatedPowerShellVersion | Should -BeExactly '7.6.5'
            $validated.LastValidatedExecutionMode | Should -BeExactly 'Direct'
        }

        It 'fails closed when any observed runtime field is absent or empty' {
            $target = ConvertTo-HHProposedTarget -InputObject $script:proposal
            $complete = [ordered]@{
                ValidatedAtUtc = '2026-08-24T01:02:03Z'
                RemotePSEdition = 'Core'
                RemotePowerShellVersion = '7.6.5'
                ExecutionMode = 'Direct'
            }
            foreach ($propertyName in $complete.Keys) {
                $missing = [ordered]@{}
                foreach ($entryName in $complete.Keys) {
                    if ($entryName -cne $propertyName) {
                        $missing[$entryName] = $complete[$entryName]
                    }
                }
                {
                    ConvertTo-HHValidatedProbeTarget `
                        -Target $target `
                        -TransportResult ([pscustomobject] $missing)
                } | Should -Throw "*missing observed runtime field '$propertyName'*"
            }

            $empty = [pscustomobject] $complete
            $empty.RemotePSEdition = ' '
            { ConvertTo-HHValidatedProbeTarget -Target $target -TransportResult $empty } |
                Should -Throw "*missing observed runtime field 'RemotePSEdition'*"
        }

        It 'rejects an observed runtime that does not match the requested profile' {
            $target = ConvertTo-HHProposedTarget -InputObject $script:proposal
            $result = [pscustomobject]@{
                ValidatedAtUtc = '2026-08-24T01:02:03Z'
                RemotePSEdition = 'Desktop'
                RemotePowerShellVersion = '5.1.26100.9168'
                ExecutionMode = 'WindowsPowerShellCompatibility'
            }

            { ConvertTo-HHValidatedProbeTarget -Target $target -TransportResult $result } |
                Should -Throw '*PowerShell7 targets require*'
        }
}
