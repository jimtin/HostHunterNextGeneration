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
        $exported = @(Get-Command -Module HostHunterNextGeneration -CommandType Function |
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
        (Get-Command Get-HHTargets -Module HostHunterNextGeneration `
                -CommandType Alias).Definition | Should -BeExactly Get-HHTarget
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

    It 'dispatches every closed operation to exactly its owned implementation' {
        InModuleScope HostHunterNextGeneration {
            Mock Invoke-HHManagedHostValidateTargetOperation { 'validate' }
            Mock Invoke-HHManagedHostTestTargetOperation { 'test' }
            Mock Invoke-HHManagedHostInvokeCommandOperation { 'command' }
            Mock Invoke-HHManagedHostEnableSshKeyAuthenticationOperation { 'key' }
            Mock Invoke-HHManagedHostSetWindowsProcessAuditPolicyOperation { 'policy' }

            Invoke-HHManagedHostOperation -Operation ValidateTarget -Arguments @{
                Name = 'alpha'
                HostName = 'alpha.example'
                UserName = 'operator'
                WhatIf = $true
            } | Should -BeExactly validate
            Invoke-HHManagedHostOperation -Operation TestTarget -Arguments @{} |
                Should -BeExactly test
            Invoke-HHManagedHostOperation -Operation InvokeCommand -Arguments @{
                Command = "'ok'"
            } | Should -BeExactly command
            Invoke-HHManagedHostOperation -Operation EnableSshKeyAuthentication -Arguments @{
                Name = 'alpha'
                WhatIf = $true
            } | Should -BeExactly key
            Invoke-HHManagedHostOperation -Operation SetWindowsProcessAuditPolicy -Arguments @{
                State = 'Enabled'
                WhatIf = $true
            } | Should -BeExactly policy

            Should -Invoke Invoke-HHManagedHostValidateTargetOperation -Times 1 -Exactly
            Should -Invoke Invoke-HHManagedHostTestTargetOperation -Times 1 -Exactly
            Should -Invoke Invoke-HHManagedHostInvokeCommandOperation -Times 1 -Exactly
            Should -Invoke Invoke-HHManagedHostEnableSshKeyAuthenticationOperation -Times 1 -Exactly
            Should -Invoke Invoke-HHManagedHostSetWindowsProcessAuditPolicyOperation -Times 1 -Exactly
        }
    }

    It 'accepts current managed targets and rejects historical profiles' {
        InModuleScope HostHunterNextGeneration {
            { Assert-HHManagedTargetSupported -Target @(
                    [pscustomobject]@{
                        Name = 'current'
                        Transport = 'SSH'
                        PowerShellRuntime = 'PowerShell7'
                    }
                ) } | Should -Not -Throw
            {
                Assert-HHManagedTargetSupported -Target @(
                    [pscustomobject]@{
                        Name = 'legacy-transport'
                        Transport = 'WinRM'
                        PowerShellRuntime = 'PowerShell7'
                    }
                )
            } | Should -Throw '*historical transport or runtime profile*'
            {
                Assert-HHManagedTargetSupported -Target @(
                    [pscustomobject]@{
                        Name = 'legacy-runtime'
                        Transport = 'SSH'
                        PowerShellRuntime = 'WindowsPowerShell51'
                    }
                )
            } | Should -Throw '*historical transport or runtime profile*'
        }
    }

    It 'returns deterministic no-database behavior without opening persistence or a host' {
        InModuleScope HostHunterNextGeneration {
            $missingDatabase = Join-Path $TestDrive 'missing/hosthunter.sqlite3'
            Mock Get-HHRuntimeContext {
                [pscustomobject]@{
                    DatabasePath = $missingDatabase
                    KeyRoot = (Join-Path $TestDrive 'keys')
                }
            }
            Mock Open-HHAuthenticatedPersistence { throw 'must not open persistence' }
            Mock Invoke-HHSshTransport { throw 'must not contact a host' }

            @(Invoke-HHManagedHostTestTargetOperation).Count | Should -Be 0
            { Invoke-HHManagedHostTestTargetOperation -Name alpha } |
                Should -Throw '*Unknown target(s): alpha*'
            { Invoke-HHManagedHostCommandCoordinator -Command "'ok'" } |
                Should -Throw '*No active HostHunter targets*'
            { Invoke-HHManagedHostEnableSshKeyAuthenticationOperation -Name alpha -Confirm:$false } |
                Should -Throw "*Unknown target 'alpha'*"
            $preference = Get-HHManagedHostEscalationPreference
            $preference.Method | Should -BeExactly WindowsTokenPrivilege
            $preference.Scope | Should -BeExactly Global
            $preference.Source | Should -BeExactly BuiltIn
            $preference.IsPersisted | Should -BeFalse

            Should -Invoke Open-HHAuthenticatedPersistence -Times 0 -Exactly
            Should -Invoke Invoke-HHSshTransport -Times 0 -Exactly
        }
    }

    It 'rejects invalid command and Windows policy requests before dispatch' {
        InModuleScope HostHunterNextGeneration {
            Mock Invoke-HHManagedHostCommandCoordinator { 'dispatched' }

            { Invoke-HHManagedHostInvokeCommandOperation -Command 'if (' } |
                Should -Throw '*not valid PowerShell*'
            Invoke-HHManagedHostInvokeCommandOperation -Command "'valid'" |
                Should -BeExactly dispatched

            {
                Invoke-HHManagedHostSetWindowsProcessAuditPolicyOperation `
                    -State Enabled `
                    -Subcategory ProcessTermination `
                    -CommandLineLogging Enabled `
                    -Confirm:$false
            } | Should -Throw '*only when ProcessCreation is selected*'
            {
                Invoke-HHManagedHostSetWindowsProcessAuditPolicyOperation `
                    -State Disabled `
                    -CommandLineLogging Enabled `
                    -Confirm:$false
            } | Should -Throw '*cannot be enabled while ProcessCreation auditing is disabled*'
            {
                Invoke-HHManagedHostSetWindowsProcessAuditPolicyOperation `
                    -State Enabled `
                    -EscalationMethod WindowsTokenPrivilege `
                    -Confirm:$false
            } | Should -Throw '*requires -Escalate*'

            Should -Invoke Invoke-HHManagedHostCommandCoordinator -Times 1 -Exactly
        }
    }

    It 'coordinates default and custom remote commands through one audited fan-out' {
        InModuleScope HostHunterNextGeneration {
            $databasePath = Join-Path $TestDrive 'coordinator/hosthunter.sqlite3'
            [IO.Directory]::CreateDirectory((Split-Path -Parent $databasePath)) | Out-Null
            [IO.File]::WriteAllBytes($databasePath, [byte[]](1))
            $selectedFixture = [pscustomobject]@{
                Name = 'alpha'
                Transport = 'SSH'
                PowerShellRuntime = 'PowerShell7'
                IsActive = $true
                HostKeyFingerprint = 'SHA256:' + ('A' * 43)
            }
            $context = [pscustomobject]@{
                Connection = [pscustomobject]@{}
                MasterKey = [byte[]]::new(32)
                Anchor = [pscustomobject]@{}
            }
            $intent = [pscustomobject]@{
                BatchId = [Guid]::Parse('11111111-1111-1111-1111-111111111111')
                InvocationId = [Guid]::Parse('22222222-2222-2222-2222-222222222222')
                RemoteOperations = @([pscustomobject]@{ Ordinal = 0 }, [pscustomobject]@{ Ordinal = 1 })
            }
            $session = [pscustomobject]@{
                Session = [pscustomobject]@{ Id = 1 }
                IdentityEvents = @()
                Identity = [pscustomobject]@{ Marker = 'HostHunter.PowerShellIdentity.v1' }
                ValidatedAtUtc = '2026-08-26T00:00:00Z'
                RemotePowerShellVersion = '7.6.5'
                RemotePSEdition = 'Core'
                ExecutionMode = 'Direct'
                HostKeyFingerprint = $selectedFixture.HostKeyFingerprint
            }
            $commandResult = [pscustomobject]@{
                Succeeded = $true
                FailureKind = $null
                StreamEvents = @()
                OutputBytes = 0L
                ExceptionType = $null
                DispatchState = 'Completed'
                OutcomeStatus = 'Succeeded'
            }

            Mock Get-HHRuntimeContext {
                [pscustomobject]@{ DatabasePath = $databasePath; KnownHostsPath = '/fixture/known_hosts' }
            }
            Mock Open-HHAuthenticatedPersistence { $context }
            Mock Read-HHTargetRepositorySnapshot {
                [pscustomobject]@{ Targets = @($selectedFixture) }
            }
            Mock Get-HHCommandRemoteOperationManifest { $intent.RemoteOperations }
            Mock Register-HHAuthenticatedAuditBatch { @($intent) }
            Mock Start-HHAuthenticatedAuditCapacityReservation { [pscustomobject]@{ Id = 1 } }
            Mock Open-HHAuthenticatedAuditArtifactWriter { [pscustomobject]@{ State = 'Open' } }
            Mock Arm-HHAuthenticatedRemoteOperation { }
            Mock Open-HHSshSession { $session }
            Mock Write-HHAuditArtifactV2Event { }
            Mock Invoke-HHSshSessionFanOut { @{ alpha = $commandResult } }
            Mock Close-HHSshSession { }
            Mock Complete-HHAuthenticatedTransportAudit { }
            Mock Abort-HHAuditArtifactV2Writer { }
            Mock Remove-HHPersistenceCapacityReservation { }
            Mock Close-HHAuthenticatedPersistence { }

            $default = @(Invoke-HHManagedHostCommandCoordinator -Command "'default'")
            $default.Count | Should -Be 1
            $default[0].Target | Should -BeExactly alpha
            $default[0].Succeeded | Should -BeTrue
            $default[0].SessionRemovalFailure | Should -BeFalse

            $manifestFactory = {
                param($SelectedTarget, $ScriptBlock, $ArgumentList)
                $null = $SelectedTarget, $ScriptBlock, $ArgumentList
                @([pscustomobject]@{ Ordinal = 0 }, [pscustomobject]@{ Ordinal = 1 })
            }
            $augmenter = {
                param($SelectedTarget, $TransportResult, $CommandResult)
                $null = $SelectedTarget, $CommandResult
                $TransportResult | Add-Member -NotePropertyName PolicyOutcome `
                    -NotePropertyValue ([pscustomobject]@{ Succeeded = $true })
                $TransportResult
            }
            $custom = @(Invoke-HHManagedHostCommandCoordinator `
                    -Command 'custom-policy' `
                    -Target alpha `
                    -RemoteScriptBlock { param($Value) $Value } `
                    -RemoteArgumentList @('value') `
                    -RemoteOperationManifestFactory $manifestFactory `
                    -TransportResultAugmenter $augmenter `
                    -Operation SetWindowsProcessAuditPolicy)
            $custom.Count | Should -Be 1
            $custom[0].PolicyOutcome.Succeeded | Should -BeTrue

            Should -Invoke Invoke-HHSshSessionFanOut -Times 2 -Exactly
            Should -Invoke Complete-HHAuthenticatedTransportAudit -Times 2 -Exactly
            Should -Invoke Close-HHAuthenticatedPersistence -Times 2 -Exactly
        }
    }

    It 'preserves complete runtime-mismatch evidence and downgrades incomplete evidence' {
        InModuleScope HostHunterNextGeneration {
            $databasePath = Join-Path $TestDrive 'mismatch/hosthunter.sqlite3'
            [IO.Directory]::CreateDirectory((Split-Path -Parent $databasePath)) | Out-Null
            [IO.File]::WriteAllBytes($databasePath, [byte[]](1))
            $targets = @(
                [pscustomobject]@{
                    Name = 'complete'; Transport = 'SSH'; PowerShellRuntime = 'PowerShell7'
                    IsActive = $true; HostKeyFingerprint = 'SHA256:' + ('A' * 43)
                },
                [pscustomobject]@{
                    Name = 'incomplete'; Transport = 'SSH'; PowerShellRuntime = 'PowerShell7'
                    IsActive = $true; HostKeyFingerprint = 'SHA256:' + ('B' * 43)
                }
            )
            $context = [pscustomobject]@{
                Connection = [pscustomobject]@{}
                MasterKey = [byte[]]::new(32)
                Anchor = [pscustomobject]@{}
            }
            Mock Get-HHRuntimeContext {
                [pscustomobject]@{ DatabasePath = $databasePath; KnownHostsPath = '/fixture/known_hosts' }
            }
            Mock Open-HHAuthenticatedPersistence { $context }
            Mock Read-HHTargetRepositorySnapshot { [pscustomobject]@{ Targets = $targets } }
            Mock Get-HHCommandRemoteOperationManifest {
                @([pscustomobject]@{ Ordinal = 0 }, [pscustomobject]@{ Ordinal = 1 })
            }
            Mock Register-HHAuthenticatedAuditBatch {
                @($Request | ForEach-Object {
                        [pscustomobject]@{
                            BatchId = [Guid]::Parse('33333333-3333-3333-3333-333333333333')
                            InvocationId = [Guid]::NewGuid()
                            RemoteOperations = @(
                                [pscustomobject]@{ Ordinal = 0 },
                                [pscustomobject]@{ Ordinal = 1 }
                            )
                        }
                    })
            }
            Mock Start-HHAuthenticatedAuditCapacityReservation { [pscustomobject]@{ Id = 1 } }
            Mock Open-HHAuthenticatedAuditArtifactWriter { [pscustomobject]@{ State = 'Open' } }
            Mock Arm-HHAuthenticatedRemoteOperation { }
            Mock Open-HHSshSession {
                $failure = New-HHSshClassifiedException `
                    -FailureKind RuntimeMismatch `
                    -Message "runtime mismatch for $($Target.Name)"
                if ($Target.Name -ceq 'complete') {
                    $failure.Data['HHObservedIdentity'] = [pscustomobject]@{ Marker = 'identity' }
                    $failure.Data['HHObservedRemotePowerShellVersion'] = '5.1.26100.1'
                    $failure.Data['HHObservedRemotePSEdition'] = 'Desktop'
                    $failure.Data['HHObservedExecutionMode'] = 'Compatibility'
                    $failure.Data['HHObservedValidatedAtUtc'] = '2026-08-26T00:00:00Z'
                    $failure.Data['HHObservedHostKeyFingerprint'] = $Target.HostKeyFingerprint
                    $failure.Data['HHDispatchState'] = 'NotDispatched'
                    $failure.Data['HHOutcomeStatus'] = 'Failed'
                    $failure.Data['HHStreamEvents'] = @(
                        New-HHSshStreamEvent -Sequence 0 -Phase Identity -InputObject 'observed'
                    )
                }
                throw $failure
            }
            Mock Write-HHAuditArtifactV2Event { }
            Mock Complete-HHAuthenticatedTransportAudit { }
            Mock Abort-HHAuditArtifactV2Writer { }
            Mock Remove-HHPersistenceCapacityReservation { }
            Mock Close-HHAuthenticatedPersistence { }
            Mock Invoke-HHSshSessionFanOut { throw 'fan-out must not run without a session' }

            $result = @(Invoke-HHManagedHostCommandCoordinator -Command "'probe'")
            $result.Count | Should -Be 2
            ($result | Where-Object Target -CEQ complete).FailureKind |
                Should -BeExactly RuntimeMismatch
            ($result | Where-Object Target -CEQ complete).RemotePowerShellVersion |
                Should -BeExactly '5.1.26100.1'
            ($result | Where-Object Target -CEQ incomplete).FailureKind |
                Should -BeExactly TransportFailure
            ($result | Where-Object Target -CEQ incomplete).RemotePowerShellVersion |
                Should -BeNullOrEmpty
            Should -Invoke Invoke-HHSshSessionFanOut -Times 0 -Exactly
        }
    }
}
