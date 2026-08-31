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

    It 'accepts the eleven closed operation values and rejects every other value' {
        InModuleScope HostHunterNextGeneration {
            $command = Get-Command Invoke-HHManagedHostOperation
            $attribute = @($command.Parameters.Operation.Attributes | Where-Object {
                    $_ -is [Management.Automation.ValidateSetAttribute]
                })
            $attribute.Count | Should -Be 1
            @($attribute[0].ValidValues | Sort-Object) | Should -Be @(
                'EnableSshKeyAuthentication',
                'GetAuthenticationEvents',
                'GetHostDetails',
                'GetProcessAccessToken',
                'GetProcessEndEvents',
                'GetProcessStartEvents',
                'GetUserEffectiveRights',
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

    It 'keeps the engine private and exports exactly the manifest command surface' {
        $manifest = Import-PowerShellDataFile -LiteralPath (
            Join-Path $script:engineSourceRoot 'HostHunterNextGeneration.psd1'
        )
        $declared = @($manifest.FunctionsToExport | Sort-Object -Unique)
        $exported = @(Get-Command -Module HostHunterNextGeneration -CommandType Function |
                Select-Object -ExpandProperty Name | Sort-Object)
        $exported | Should -Be $declared
        (Get-Command Get-HHTargets -Module HostHunterNextGeneration `
                -CommandType Alias).Definition | Should -BeExactly Get-HHTarget
        Get-Command Invoke-HHManagedHostOperation -ErrorAction SilentlyContinue |
            Should -BeNullOrEmpty
    }

    It 'routes all eleven public cmdlets through the sole boundary' {
        $result = & $script:engineGuardPath -ModuleRoot $script:engineSourceRoot
        $result.Succeeded | Should -BeTrue
        $result.ManagedHostCmdletCount | Should -Be 11
        @($result.Operations) | Should -Be @(
            'ValidateTarget',
            'TestTarget',
            'InvokeCommand',
            'GetHostDetails',
            'GetProcessStartEvents',
            'GetProcessEndEvents',
            'GetAuthenticationEvents',
            'GetProcessAccessToken',
            'GetUserEffectiveRights',
            'EnableSshKeyAuthentication',
            'SetWindowsProcessAuditPolicy'
        )
    }

    It 'rejects invalid CIM collection input before crossing the boundary' {
        InModuleScope HostHunterNextGeneration {
            Mock Invoke-HHManagedHostOperation { throw 'must not reach engine' }
            {
                Get-TargetProcessAccessToken -ProcessName 'C:\Tools\pwsh.exe'
            } | Should -Throw '*exact process basename*'
            {
                Get-TargetUserEffectiveRights -Identity '   '
            } | Should -Throw '*cannot be blank*'
            {
                Get-TargetAuthenticationEvents `
                    -Since '2026-08-29T02:00:00Z' -Until '2026-08-29T01:00:00Z'
            } | Should -Throw '*greater than or equal*'
            Should -Invoke Invoke-HHManagedHostOperation -Times 0 -Exactly
        }
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

    It 'delegates Get-TargetProcessEndEvents once with its bounded arguments' {
        InModuleScope HostHunterNextGeneration {
            Mock Invoke-HHManagedHostOperation { 'delegated' }
            Get-TargetProcessEndEvents -Name alpha -First 25 |
                Should -BeExactly delegated
            Should -Invoke Invoke-HHManagedHostOperation -Times 1 -Exactly -ParameterFilter {
                $Operation -ceq 'GetProcessEndEvents' -and
                $Arguments.Name -ceq 'alpha' -and $Arguments.First -eq 25
            }
        }
    }

    It 'delegates the complete CIM public surface with operator filters intact' {
        InModuleScope HostHunterNextGeneration {
            Mock Invoke-HHManagedHostOperation { $Operation }
            $since = [DateTimeOffset]'2026-08-31T00:00:00Z'
            $until = [DateTimeOffset]'2026-08-31T01:00:00Z'

            Get-TargetProcessStartEvents -Name alpha -Since $since -Until $until `
                -First 20 -ThrottleLimit 2 -Reason reason -CaseId case |
                Should -BeExactly GetProcessStartEvents
            Get-TargetAuthenticationEvents -Name alpha -Since $since -Until $until `
                -First 21 -ThrottleLimit 3 |
                Should -BeExactly GetAuthenticationEvents
            Get-TargetProcessAccessToken -Name alpha -ProcessId 10 -ThrottleLimit 4 |
                Should -BeExactly GetProcessAccessToken
            Get-TargetProcessAccessToken -Name alpha -ProcessName pwsh.exe |
                Should -BeExactly GetProcessAccessToken
            Get-TargetUserEffectiveRights -Name alpha -Identity 'LAB\alice' |
                Should -BeExactly GetUserEffectiveRights

            Should -Invoke Invoke-HHManagedHostOperation -Times 5 -Exactly
            Should -Invoke Invoke-HHManagedHostOperation -Times 1 -Exactly -ParameterFilter {
                $Operation -ceq 'GetProcessStartEvents' -and
                $Arguments.Since -eq $since -and $Arguments.Until -eq $until -and
                $Arguments.First -eq 20 -and $Arguments.ThrottleLimit -eq 2
            }
            Should -Invoke Invoke-HHManagedHostOperation -Times 1 -Exactly -ParameterFilter {
                $Operation -ceq 'GetProcessAccessToken' -and
                $Arguments.ProcessName -ceq 'pwsh.exe'
            }
            Should -Invoke Invoke-HHManagedHostOperation -Times 1 -Exactly -ParameterFilter {
                $Operation -ceq 'GetUserEffectiveRights' -and
                $Arguments.Identity -ceq 'LAB\alice'
            }
        }
    }

    It 'collects 4689 through the shared bounded Security-event operation and end cursor' {
        InModuleScope HostHunterNextGeneration {
            Mock Get-HHForensicCollectionContext {
                [pscustomobject]@{
                    Runtime=[pscustomobject]@{}
                    Targets=@([pscustomobject]@{Name='alpha';HostName='alpha.example'})
                    MissionId=[Guid]::NewGuid();PublishingEnabled=$false
                    AgentId=[Guid]::NewGuid();AgentVersion='0.7.0'
                }
            }
            Mock Assert-HHForensicVisualizerCapability {}
            Mock Get-HHForensicCursorPosition {
                [pscustomobject]@{
                    Since=[DateTimeOffset]'2026-08-31T00:00:00Z'
                    AfterRecordId=400L
                }
            }
            Mock Get-HHWindowsSecurityEventsRemoteScriptBlock { { 'remote' } }
            Mock Invoke-HHForensicRemoteCollection {
                [pscustomobject]@{
                    Succeeded=$true
                    ForensicRaw=[pscustomobject]@{
                        ObservedAtUtc=[DateTimeOffset]'2026-08-31T00:01:00Z'
                        Records=@([pscustomobject]@{
                                EventId=4689;Version=0;RecordId=401L
                                TimeCreated=[DateTimeOffset]'2026-08-31T00:00:30Z'
                                Data=[ordered]@{}
                            })
                    }
                }
            }
            Mock Save-HHForensicTransportResult { $Cursor.SourceName }

            Invoke-HHManagedHostGetProcessEndEventsOperation -Name alpha -First 25 |
                Should -BeExactly windows.security.process-end
            Should -Invoke Invoke-HHForensicRemoteCollection -Times 1 -Exactly -ParameterFilter {
                $Operation -ceq 'GetProcessEndEvents' -and $RemoteArgumentList.Count -eq 2 -and
                $RemoteArgumentList[0] -match 'EventID=4689' -and
                $RemoteArgumentList[0] -match 'EventRecordID>400' -and
                $RemoteArgumentList[1] -eq 25
            }
            Should -Invoke Save-HHForensicTransportResult -Times 1 -Exactly -ParameterFilter {
                $Cursor.SourceName -ceq 'windows.security.process-end' -and
                $Cursor.RecordId -ceq '401'
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
            Mock Invoke-HHManagedHostGetProcessStartEventsOperation { 'process-start' }
            Mock Invoke-HHManagedHostGetProcessEndEventsOperation { 'process-end' }
            Mock Invoke-HHManagedHostGetAuthenticationEventsOperation { 'authentication' }
            Mock Invoke-HHManagedHostGetProcessAccessTokenOperation { 'process-token' }
            Mock Invoke-HHManagedHostGetUserEffectiveRightsOperation { 'effective-rights' }

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
            Invoke-HHManagedHostOperation -Operation GetProcessEndEvents -Arguments @{} |
                Should -BeExactly process-end
            Invoke-HHManagedHostOperation -Operation GetProcessStartEvents -Arguments @{} |
                Should -BeExactly process-start
            Invoke-HHManagedHostOperation -Operation GetAuthenticationEvents -Arguments @{} |
                Should -BeExactly authentication
            Invoke-HHManagedHostOperation -Operation GetProcessAccessToken -Arguments @{
                ProcessId = @(10)
            } | Should -BeExactly process-token
            Invoke-HHManagedHostOperation -Operation GetUserEffectiveRights -Arguments @{} |
                Should -BeExactly effective-rights

            Should -Invoke Invoke-HHManagedHostValidateTargetOperation -Times 1 -Exactly
            Should -Invoke Invoke-HHManagedHostTestTargetOperation -Times 1 -Exactly
            Should -Invoke Invoke-HHManagedHostInvokeCommandOperation -Times 1 -Exactly
            Should -Invoke Invoke-HHManagedHostEnableSshKeyAuthenticationOperation -Times 1 -Exactly
            Should -Invoke Invoke-HHManagedHostSetWindowsProcessAuditPolicyOperation -Times 1 -Exactly
            Should -Invoke Invoke-HHManagedHostGetProcessStartEventsOperation -Times 1 -Exactly
            Should -Invoke Invoke-HHManagedHostGetProcessEndEventsOperation -Times 1 -Exactly
            Should -Invoke Invoke-HHManagedHostGetAuthenticationEventsOperation -Times 1 -Exactly
            Should -Invoke Invoke-HHManagedHostGetProcessAccessTokenOperation -Times 1 -Exactly
            Should -Invoke Invoke-HHManagedHostGetUserEffectiveRightsOperation -Times 1 -Exactly
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

    It 'proves an existing public key once without bootstrapping or changing the profile' {
        InModuleScope HostHunterNextGeneration {
            $databasePath = Join-Path $TestDrive 'key-proof/hosthunter.sqlite3'
            [IO.Directory]::CreateDirectory((Split-Path -Parent $databasePath)) |
                Out-Null
            [IO.File]::WriteAllBytes($databasePath, [byte[]](1))
            $savedTarget = [pscustomobject]@{
                Name = 'alpha'
                Transport = 'SSH'
                Authentication = 'PublicKey'
                PowerShellRuntime = 'PowerShell7'
                KeyPath = '/var/lib/hosthunter-data/keys/hosthunter_ed25519'
            }
            Mock Get-HHRuntimeContext {
                [pscustomobject]@{ DatabasePath=$databasePath; KeyRoot=$TestDrive }
            }
            Mock Open-HHAuthenticatedPersistence {
                [pscustomobject]@{
                    Connection = [pscustomobject]@{}
                    MasterKey = [byte[]](0..31)
                    Anchor = [pscustomobject]@{}
                }
            }
            Mock Close-HHAuthenticatedPersistence {}
            Mock Read-HHTargetRepositorySnapshot {
                [pscustomobject]@{ Targets=@($savedTarget) }
            }
            Mock Invoke-HHManagedHostCommandCoordinator {
                [pscustomobject]@{
                    Succeeded = $true
                    StreamEvents = @([pscustomobject]@{
                            Phase = 'Command'
                            Value = [pscustomobject]@{
                                Marker = 'HostHunter.ExistingSshKeyProof.v1'
                                Succeeded = $true
                            }
                        })
                }
            }
            Mock Prepare-HHSshKeyBootstrapOperation {
                throw 'must not bootstrap an existing public key'
            }

            $result = Invoke-HHManagedHostEnableSshKeyAuthenticationOperation `
                -Name alpha -Confirm:$false

            $result | Should -Be $savedTarget
            Should -Invoke Invoke-HHManagedHostCommandCoordinator -Times 1 `
                -Exactly -ParameterFilter {
                $Operation -ceq 'EnableSshKeyAuthentication' -and
                @($Target).Count -eq 1 -and $Target[0] -ceq 'alpha'
            }
            Should -Invoke Prepare-HHSshKeyBootstrapOperation -Times 0 -Exactly
        }
    }

    It 'fails an existing public-key proof when the fixed marker is absent' {
        InModuleScope HostHunterNextGeneration {
            $databasePath = Join-Path $TestDrive 'key-proof-failure/hosthunter.sqlite3'
            [IO.Directory]::CreateDirectory((Split-Path -Parent $databasePath)) |
                Out-Null
            [IO.File]::WriteAllBytes($databasePath, [byte[]](1))
            Mock Get-HHRuntimeContext {
                [pscustomobject]@{ DatabasePath=$databasePath; KeyRoot=$TestDrive }
            }
            Mock Open-HHAuthenticatedPersistence {
                [pscustomobject]@{
                    Connection = [pscustomobject]@{}
                    MasterKey = [byte[]](0..31)
                    Anchor = [pscustomobject]@{}
                }
            }
            Mock Close-HHAuthenticatedPersistence {}
            Mock Read-HHTargetRepositorySnapshot {
                [pscustomobject]@{ Targets=@([pscustomobject]@{
                            Name = 'alpha'
                            Transport = 'SSH'
                            Authentication = 'PublicKey'
                            PowerShellRuntime = 'PowerShell7'
                            KeyPath = '/keys/id_ed25519'
                        }) }
            }
            Mock Invoke-HHManagedHostCommandCoordinator {
                [pscustomobject]@{ Succeeded=$true; StreamEvents=@() }
            }

            {
                Invoke-HHManagedHostEnableSshKeyAuthenticationOperation `
                    -Name alpha -Confirm:$false
            } | Should -Throw '*could not prove its existing SSH key authentication*'
            Should -Invoke Invoke-HHManagedHostCommandCoordinator -Times 1 -Exactly
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

    It 'returns finite host details without persistence while visualization is paused' {
        InModuleScope HostHunterNextGeneration {
            $raw = [pscustomobject]@{
                ObservedAtUtc='2026-08-29T00:00:00Z';Hostname='alpha';Platform='linux'
            }
            $failure = [pscustomobject]@{
                Target='beta';Succeeded=$false;FailureKind='TransportFailure'
            }
            Mock Get-HHCurrentMissionId { $null }
            Mock Get-HHHostDetailsRemoteScriptBlock { { [pscustomobject]@{} } }
            Mock Invoke-HHManagedHostCommandCoordinator {
                @(
                    [pscustomobject]@{
                        Target='alpha';Succeeded=$true;HostDetailsRaw=$raw
                    },
                    $failure
                )
            }
            Mock Get-HHRuntimeContext { throw 'paused collection must not persist' }

            $result = @(Invoke-HHManagedHostGetHostDetailsOperation `
                    -Name alpha,beta -ThrottleLimit 2 -Reason inventory -CaseId case-1)

            $result | Should -HaveCount 2
            $result[0].Hostname | Should -BeExactly alpha
            $result[0].VisualizerDelivered | Should -BeFalse
            $result[0].VisualizerPublishingState | Should -BeExactly Paused
            $result[1] | Should -Be $failure
            Should -Invoke Invoke-HHManagedHostCommandCoordinator -Times 1 -Exactly `
                -ParameterFilter {
                    $Operation -ceq 'GetHostDetails' -and
                    @($Target) -join ',' -ceq 'alpha,beta' -and
                    $ThrottleLimit -eq 2 -and $Reason -ceq 'inventory' -and
                    $CaseId -ceq 'case-1'
                }
            Should -Not -Invoke Get-HHRuntimeContext
        }
    }

    It 'authenticates stores delivers and records an active-mission host observation once' {
        InModuleScope HostHunterNextGeneration {
            $missionId = [Guid]::NewGuid()
            $batchId = [Guid]::NewGuid().ToByteArray()
            $invocationId = [Guid]::NewGuid().ToByteArray()
            $raw = [pscustomobject]@{
                ObservedAtUtc='2026-08-29T00:00:00Z';Hostname='alpha';Platform='linux'
                NativeIdentityDigest=('b' * 64)
            }
            $transport = [pscustomobject]@{
                Target='alpha';Succeeded=$true;HostDetailsRaw=$raw
                BatchId=$batchId;InvocationId=$invocationId
            }
            $runtime = [pscustomobject]@{DatabasePath='/data/hosthunter.sqlite3'}
            $writer = [pscustomobject]@{
                MasterKey=[byte[]](0..31)
                Anchor=[pscustomobject]@{DatabaseId=[Guid]::NewGuid().ToByteArray()}
                VisualizerSnapshot=[pscustomobject]@{Generation=1}
            }
            $payload = [pscustomobject]@{
                host=[pscustomobject]@{hostname='alpha'}
            }
            $payloadBytes = [Text.UTF8Encoding]::new($false).GetBytes('{"host":{"hostname":"alpha"}}')
            $script:transactionCount = 0
            Mock Get-HHCurrentMissionId { $missionId }
            Mock Get-HHHostDetailsRemoteScriptBlock { { [pscustomobject]@{} } }
            Mock Invoke-HHManagedHostCommandCoordinator { @($transport) }
            Mock Get-HHRuntimeContext { $runtime }
            Mock Open-HHAuthenticatedPersistence {
                [pscustomobject]@{Connection=[pscustomobject]@{};MasterKey=$writer.MasterKey}
            }
            Mock Close-HHAuthenticatedPersistence {}
            Mock Invoke-HHAnchoredPersistenceTransaction {
                $script:transactionCount++
                & $Action ([pscustomobject]@{}) ([pscustomobject]@{}) $writer $ArgumentList
            }
            Mock Read-HHTargetRepositorySnapshot {
                [pscustomobject]@{Targets=@([pscustomobject]@{
                            Name='alpha';HostName='alpha.example';Port=22
                        })}
            }
            Mock Resolve-HHVisualizerEndpointIdentity {
                [pscustomobject]@{
                    EndpointId=('hh_' + ('a' * 52));Strategy='platform_instance_hmac_sha256'
                    TargetNameKey='ALPHA'
                }
            }
            Mock ConvertTo-HHHostDetailsPayload { $payload }
            Mock Assert-HHHostDetailsPayloadSchema { $true }
            Mock Add-HHVisualizerHostObservation {
                [pscustomobject]@{PayloadBytes=$payloadBytes}
            }
            Mock Send-HHVisualizerObservation {
                [pscustomobject]@{Delivered=$true;StatusCode=201}
            }
            Mock Set-HHVisualizerDeliveryResult {}

            $result = @(Invoke-HHManagedHostGetHostDetailsOperation `
                    -Name alpha -ProducerSender { throw 'sender is passed through, not invoked directly' })

            $result | Should -HaveCount 1
            $result[0].host.hostname | Should -BeExactly alpha
            $result[0].VisualizerDelivered | Should -BeTrue
            $script:transactionCount | Should -Be 2
            Should -Invoke Open-HHAuthenticatedPersistence -Times 2 -Exactly
            Should -Invoke Close-HHAuthenticatedPersistence -Times 2 -Exactly
            Should -Invoke Add-HHVisualizerHostObservation -Times 1 -Exactly
            Should -Invoke Send-HHVisualizerObservation -Times 1 -Exactly `
                -ParameterFilter {
                    $MissionId -eq $missionId -and
                    [Text.Encoding]::UTF8.GetString($PayloadBytes) -match 'hostname'
                }
            Should -Invoke Set-HHVisualizerDeliveryResult -Times 1 -Exactly `
                -ParameterFilter {
                    $Kind -ceq 'Observation' -and $Delivered -and $StatusCode -eq 201
                }
        }
    }
}
