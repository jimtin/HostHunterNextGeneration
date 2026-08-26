$sourceRoot = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
    Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration'
}
else { $env:HH_TEST_SOURCE_ROOT }
Import-Module (Join-Path $sourceRoot 'HostHunterNextGeneration.psd1') -Force

Describe 'managed-host engine contract' -Tag Unit {
    BeforeAll {
        $script:engineSourceRoot = if (
            [string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)
        ) {
            Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration'
        }
        else { $env:HH_TEST_SOURCE_ROOT }
        $script:engineRepoRoot = [IO.Path]::GetFullPath(
            (Join-Path $PSScriptRoot '../..')
        )
        $script:engineGuardPath = Join-Path $script:engineRepoRoot 'scripts/static/Test-HHManagedHostBoundary.ps1'
    }

    It 'accepts the five closed operation values and rejects every other value' {
        InModuleScope HostHunterNextGeneration {
            $command = Get-Command Invoke-HHManagedHostOperation
            $attribute = @($command.Parameters.Operation.Attributes | Where-Object {
                    $_ -is [Management.Automation.ValidateSetAttribute]
                })
            $attribute.Count | Should -Be 1
            @($attribute[0].ValidValues | Sort-Object) | Should -Be @(
                'EnableSshKeyAuthentication',
                'InvokeCommand',
                'SetWindowsProcessAuditPolicy',
                'TestTarget',
                'ValidateTarget'
            )
            {
                Invoke-HHManagedHostOperation -Operation NotAnOperation -Arguments @{}
            } | Should -Throw
        }
    }

    It 'keeps the engine private and exports exactly eleven cmdlets' {
        $exported = @(Get-Command -Module HostHunterNextGeneration |
                Select-Object -ExpandProperty Name | Sort-Object)
        $exported | Should -Be @(
            'Enable-HHSshKeyAuthentication',
            'Get-HHAuditOutput',
            'Get-HHAuditRecord',
            'Get-HHEscalationPreference',
            'Get-HHTarget',
            'Invoke-HHCommand',
            'Remove-HHTarget',
            'Set-HHEscalationPreference',
            'Set-HHTarget',
            'Set-HHWindowsProcessAuditPolicy',
            'Test-HHTarget'
        )
        Get-Command Invoke-HHManagedHostOperation -ErrorAction SilentlyContinue |
            Should -BeNullOrEmpty
    }

    It 'routes all five public cmdlets through the sole boundary' {
        $result = & $script:engineGuardPath -ModuleRoot $script:engineSourceRoot
        $result.Succeeded | Should -BeTrue
        $result.ManagedHostCmdletCount | Should -Be 5
        @($result.Operations) | Should -Be @(
            'ValidateTarget',
            'TestTarget',
            'InvokeCommand',
            'EnableSshKeyAuthentication',
            'SetWindowsProcessAuditPolicy'
        )
    }

    It 'delegates Set-HHTarget once as ValidateTarget' {
        InModuleScope HostHunterNextGeneration {
            Mock Invoke-HHManagedHostOperation { 'delegated' }
            Set-HHTarget -Name alpha -HostName host.example -UserName operator |
                Should -BeExactly delegated
            Should -Invoke Invoke-HHManagedHostOperation -Times 1 -Exactly -ParameterFilter {
                $Operation -ceq 'ValidateTarget' -and
                $Arguments.Name -ceq 'alpha' -and
                $Arguments.HostName -ceq 'host.example'
            }
        }
    }

    It 'collects piped target objects before crossing the boundary once' {
        InModuleScope HostHunterNextGeneration {
            Mock Invoke-HHManagedHostOperation { $Arguments.InputObject.Count }
            @(
                [pscustomobject]@{ Name = 'alpha' },
                [pscustomobject]@{ Name = 'beta' }
            ) | Set-HHTarget | Should -Be 2
            Should -Invoke Invoke-HHManagedHostOperation -Times 1 -Exactly -ParameterFilter {
                $Operation -ceq 'ValidateTarget' -and
                $Arguments.InputObject.Count -eq 2
            }
        }
    }

    It 'delegates Test-HHTarget once as TestTarget' {
        InModuleScope HostHunterNextGeneration {
            Mock Invoke-HHManagedHostOperation { 'delegated' }
            Test-HHTarget -Name alpha | Should -BeExactly delegated
            Should -Invoke Invoke-HHManagedHostOperation -Times 1 -Exactly -ParameterFilter {
                $Operation -ceq 'TestTarget' -and $Arguments.Name -ceq 'alpha'
            }
        }
    }

    It 'delegates Invoke-HHCommand once as InvokeCommand' {
        InModuleScope HostHunterNextGeneration {
            Mock Invoke-HHManagedHostOperation { 'delegated' }
            Invoke-HHCommand -Command "'ok'" -Target alpha |
                Should -BeExactly delegated
            Should -Invoke Invoke-HHManagedHostOperation -Times 1 -Exactly -ParameterFilter {
                $Operation -ceq 'InvokeCommand' -and
                $Arguments.Command -ceq "'ok'" -and
                $Arguments.Target -ceq 'alpha'
            }
        }
    }

    It 'delegates Enable-HHSshKeyAuthentication once with its semantic label' {
        InModuleScope HostHunterNextGeneration {
            Mock Invoke-HHManagedHostOperation { 'delegated' }
            Enable-HHSshKeyAuthentication -Name alpha -Confirm:$false |
                Should -BeExactly delegated
            Should -Invoke Invoke-HHManagedHostOperation -Times 1 -Exactly -ParameterFilter {
                $Operation -ceq 'EnableSshKeyAuthentication' -and
                $Arguments.Name -ceq 'alpha'
            }
        }
    }

    It 'delegates Set-HHWindowsProcessAuditPolicy once with its semantic label' {
        InModuleScope HostHunterNextGeneration {
            Mock Invoke-HHManagedHostOperation { 'delegated' }
            Set-HHWindowsProcessAuditPolicy -State Enabled -Target alpha -Confirm:$false |
                Should -BeExactly delegated
            Should -Invoke Invoke-HHManagedHostOperation -Times 1 -Exactly -ParameterFilter {
                $Operation -ceq 'SetWindowsProcessAuditPolicy' -and
                $Arguments.State -ceq 'Enabled' -and
                $Arguments.Target -ceq 'alpha'
            }
        }
    }

    It 'fails closed when a public cmdlet contains a direct transport call' {
        $fixtureRoot = Join-Path $TestDrive 'module'
        $fixturePublic = Join-Path $fixtureRoot 'Public'
        $fixturePrivate = Join-Path $fixtureRoot 'Private'
        [IO.Directory]::CreateDirectory($fixturePublic) | Out-Null
        [IO.Directory]::CreateDirectory($fixturePrivate) | Out-Null
        Copy-Item -LiteralPath (
            Join-Path $script:engineSourceRoot 'Private/ManagedHostOperation.ps1'
        ) -Destination $fixturePrivate
        foreach ($file in Get-ChildItem -LiteralPath (
                Join-Path $script:engineSourceRoot 'Public'
            ) -Filter '*.ps1') {
            Copy-Item -LiteralPath $file.FullName -Destination $fixturePublic
        }
        Add-Content -LiteralPath (Join-Path $fixturePublic 'Invoke-HHCommand.ps1') -Value (
            [Environment]::NewLine + 'Open-HHSshSession'
        )

        { & $script:engineGuardPath -ModuleRoot $fixtureRoot } |
            Should -Throw '*forbidden boundary bypass*'
    }
}
