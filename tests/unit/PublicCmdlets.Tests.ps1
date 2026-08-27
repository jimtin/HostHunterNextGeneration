$sourceRoot = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
    Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration'
}
else { $env:HH_TEST_SOURCE_ROOT }
Import-Module (Join-Path $sourceRoot 'HostHunterNextGeneration.psd1') -Force

Describe 'HostHunter SQLite public cmdlets' -Tag Unit {
    InModuleScope HostHunterNextGeneration {
        BeforeEach {
            $script:testRoot = Join-Path $TestDrive ([Guid]::NewGuid().ToString('N'))
            [IO.Directory]::CreateDirectory($script:testRoot) | Out-Null
            $script:runtime = Get-HHPersistenceContext -DataRoot $script:testRoot
            [IO.File]::WriteAllBytes($script:runtime.DatabasePath, [byte[]]@(1))
            $script:fingerprint = "SHA256:$('A' * 43)"
            $script:target = New-HHTargetRecord -Name alpha -Transport SSH `
                -HostName example.test -Port 22 -UserName operator `
                -Authentication Password -PowerShellRuntime PowerShell7 `
                -HostKeyFingerprint $script:fingerprint -KeyPath $null -IsActive $true `
                -LastValidatedAtUtc '2026-08-24T00:00:00Z' `
                -LastValidatedPSEdition Core -LastValidatedPowerShellVersion 7.6.5 `
                -LastValidatedExecutionMode Direct
            $script:savedTargets = @($script:target)
            $script:context = [pscustomobject]@{
                PersistenceContext = $script:runtime
                Connection = 'connection'
                MasterKey = [byte[]](0..31)
                Anchor = [pscustomobject]@{ Artifact = [byte[]]::new(196) }
                TargetSnapshot = [pscustomobject]@{ Generation = 0L; Targets = @() }
                WriterLock = 'writer'
            }
            $script:transportResult = [pscustomobject]@{
                Succeeded = $true
                FailureKind = $null
                ValidatedAtUtc = '2026-08-24T01:00:00Z'
                RemotePSEdition = 'Core'
                RemotePowerShellVersion = '7.6.5'
                ExecutionMode = 'Direct'
                RemoteIdentity = @{ UserName = 'operator'; MachineName = 'fixture-node' }
                HostKeyFingerprint = $script:fingerprint
                StreamEvents = @()
                OutputBytes = 0L
                ExceptionType = $null
                DispatchState = 'Completed'
                OutcomeStatus = 'Succeeded'
                SessionRemovalFailure = $false
            }
            $script:events = [Collections.Generic.List[string]]::new()
            $script:completedTransportResults = [Collections.Generic.List[object]]::new()
            $script:intentCounter = 0
            Mock Get-HHRuntimeContext { $script:runtime }
            Mock Open-HHAuthenticatedPersistence { $script:context }
            Mock Close-HHAuthenticatedPersistence
            Mock Read-HHTargetRepositorySnapshot {
                param($Name)
                $targets = if ($null -eq $Name) {
                    @($script:savedTargets)
                }
                else {
                    @($script:savedTargets | Where-Object { $_.Name -iin @($Name) })
                }
                [pscustomobject]@{ Generation = 0L; Targets = $targets }
            }
            Mock Register-HHAuthenticatedAuditBatch {
                param($Request)
                $script:events.Add('intent')
                @(
                    foreach ($item in $Request) {
                        $script:intentCounter++
                        [pscustomobject]@{
                            BatchId = 'b' * 32
                            InvocationId = ('{0:x32}' -f $script:intentCounter)
                            ArtifactId = ('{0:x32}' -f ($script:intentCounter + 100))
                            RemoteOperations = [object[]]$item.RemoteOperations
                        }
                    }
                )
            }
            Mock Start-HHAuthenticatedAuditCapacityReservation {
                [pscustomobject]@{ ReservationId = 'unit-capacity'; Paths = @() }
            }
            Mock Remove-HHPersistenceCapacityReservation
            Mock Open-HHAuthenticatedAuditArtifactWriter {
                [pscustomobject]@{ State = 'Completed' }
            }
            Mock Write-HHAuditArtifactV2Event
            Mock Abort-HHAuditArtifactV2Writer
            Mock Arm-HHAuthenticatedRemoteOperation {
                param($Ordinal)
                $script:events.Add("arm:$(@($Ordinal) -join ',')")
            }
            Mock Complete-HHAuthenticatedTransportAudit {
                param($TransportResult)
                $script:events.Add('terminal')
                $script:completedTransportResults.Add($TransportResult)
            }
            Mock Complete-HHAuthenticatedUnstartedAuditIntent { $script:events.Add('cancel') }
            Mock Invoke-HHAnchoredPersistenceTransaction {
                param($ArgumentList)
                $inputData = $ArgumentList[0]
                if ($null -ne $inputData.PSObject.Properties['Target']) {
                    return [pscustomobject]@{
                        CurrentTargets = [object[]]$inputData.Target
                        Committed = $true
                    }
                }
                if ($null -ne $inputData.PSObject.Properties['Transition']) {
                    $expectedTarget = if ($null -ne $inputData.PSObject.Properties['Expected']) {
                        $inputData.Expected
                    }
                    else { $inputData.ExpectedTarget }
                    return [pscustomobject]@{
                        PreviousTarget = $expectedTarget
                        CurrentTarget = $inputData.Transition
                        Committed = $true
                    }
                }
                [pscustomobject]@{ CurrentTargets = @(); Committed = $true }
            }
            Mock Register-HHSshHostTrust {
                param($ExpectedFingerprint)
                $script:events.Add('trust')
                [pscustomobject]@{
                    Fingerprint = if ([string]::IsNullOrWhiteSpace($ExpectedFingerprint)) {
                        $script:fingerprint
                    }
                    else { $ExpectedFingerprint }
                    Algorithm = 'ssh-ed25519'
                    NewlyTrusted = $true
                }
            }
            Mock Invoke-HHTargetProbe { $script:events.Add('probe'); $script:transportResult }
            Mock Test-HHTransportResult { $script:transportResult }
            Mock Request-HHSshKeyOnboardingChoice { $false }
            Mock Request-HHPasswordStorageConsent { $true }
            Mock Get-HHClientCredentialBytes {
                [Text.Encoding]::UTF8.GetBytes('unit-password')
            }
            Mock Prepare-HHSshKeyBootstrapOperation { throw 'unexpected bootstrap preparation' }
            Mock Invoke-HHSshKeyBootstrap { throw 'unexpected bootstrap execution' }
        }

        It 'previews target creation without persistence or network activity' {
            Set-HHTarget -Name alpha -HostName example.test -UserName operator `
                -HostKeyFingerprint $script:fingerprint -WhatIf
            Should -Not -Invoke Open-HHAuthenticatedPersistence
            Should -Not -Invoke Register-HHSshHostTrust
        }

        It 'previews object-form target creation and exposes a scalar interactive parameter set' {
            $proposal = [pscustomobject]@{
                Name = 'object-alpha'; Transport = 'SSH'; HostName = 'object.test'
                Port = 22; UserName = 'operator'; Authentication = 'Password'
                HostKeyFingerprint = $script:fingerprint
            }
            { Set-HHTarget -InputObject @($proposal) -WhatIf } | Should -Not -Throw
            $command = Get-Command Set-HHTarget
            $command.Parameters.Name.ParameterType | Should -Be ([string])
            $command.Parameters.HostName.ParameterType | Should -Be ([string])
            $command.Parameters.UserName.ParameterType | Should -Be ([string])
            @($command.Parameters.Name.Attributes | Where-Object {
                    $_ -is [Management.Automation.ParameterAttribute]
                }).Mandatory | Should -Not -Contain $true
            Should -Not -Invoke Open-HHAuthenticatedPersistence
        }

        It 'discovers trust, derives the remote computer name, and saves additively by default' {
            $result = @(Set-HHTarget -HostName example.test -UserName operator -Confirm:$false)

            $result | Should -HaveCount 1
            $result[0].Name | Should -BeExactly fixture-node
            $result[0].HostKeyFingerprint | Should -BeExactly $script:fingerprint
            Should -Invoke Register-HHSshHostTrust -Times 1 -ParameterFilter {
                [string]::IsNullOrWhiteSpace([string]$ExpectedFingerprint) -and $PassThru
            }
            Should -Invoke Invoke-HHAnchoredPersistenceTransaction -Times 1 -ParameterFilter {
                [bool]$ArgumentList[0].Add
            }
        }

        It 'seals intent and arms trust and identity before saving a validated target' {
            $result = @(Set-HHTarget -Name alpha -HostName example.test -UserName operator `
                    -HostKeyFingerprint $script:fingerprint -Confirm:$false)
            $result.Count | Should -Be 1
            $result[0].Name | Should -BeExactly alpha
            $script:events | Should -Be @('intent', 'arm:0', 'trust', 'arm:1', 'probe', 'terminal')
            Should -Invoke Invoke-HHAnchoredPersistenceTransaction -Times 1
        }

        It 'uses the recommended key path without persisting a password' {
            Mock Request-HHSshKeyOnboardingChoice { $true }
            Mock Invoke-HHManagedHostEnableSshKeyAuthenticationOperation {
                New-HHTargetRecord -Name fixture-node -Transport SSH `
                    -HostName example.test -Port 22 -UserName operator `
                    -Authentication PublicKey -CredentialStorage None `
                    -PowerShellRuntime PowerShell7 `
                    -HostKeyFingerprint $script:fingerprint `
                    -KeyPath /keys/hosthunter_ed25519 -IsActive $true `
                    -LastValidatedAtUtc '2026-08-24T01:00:00Z' `
                    -LastValidatedPSEdition Core `
                    -LastValidatedPowerShellVersion 7.6.5 `
                    -LastValidatedExecutionMode Direct
            }

            $result = Set-HHTarget -HostName example.test -UserName operator `
                -HostKeyFingerprint $script:fingerprint -Confirm:$false

            $result.Authentication | Should -BeExactly PublicKey
            $result.CredentialStorage | Should -BeExactly None
            Should -Invoke Request-HHPasswordStorageConsent -Times 0 -Exactly
            Should -Invoke Invoke-HHManagedHostEnableSshKeyAuthenticationOperation `
                -Times 1 -Exactly
        }

        It 'offers warned password fallback only after a definite key failure' {
            Mock Request-HHSshKeyOnboardingChoice { $true }
            Mock Invoke-HHManagedHostEnableSshKeyAuthenticationOperation {
                throw 'definite key setup failure'
            }
            Mock Save-HHOnboardingPasswordFallback {
                ConvertTo-HHEncryptedPasswordTarget -Target $Target
            }
            Mock Remove-HHIncompleteOnboardingTarget {}

            $result = Set-HHTarget -HostName example.test -UserName operator `
                -HostKeyFingerprint $script:fingerprint -Confirm:$false

            $result.Authentication | Should -BeExactly Password
            $result.CredentialStorage | Should -BeExactly Encrypted
            Should -Invoke Request-HHPasswordStorageConsent -Times 1 -Exactly
            Should -Invoke Save-HHOnboardingPasswordFallback -Times 1 -Exactly
            Should -Invoke Remove-HHIncompleteOnboardingTarget -Times 0 -Exactly
        }

        It 'returns the singular target receipt after saving a password fallback' {
            $result = Save-HHOnboardingPasswordFallback -Runtime $script:runtime `
                -Target $script:target `
                -PasswordBytes ([Text.Encoding]::UTF8.GetBytes('unit-password'))

            $result.Name | Should -BeExactly $script:target.Name
            $result.CredentialStorage | Should -BeExactly Encrypted
            Should -Invoke Invoke-HHAnchoredPersistenceTransaction -Times 1 -Exactly
            Should -Invoke Close-HHAuthenticatedPersistence -Times 1 -Exactly
        }

        It 'persists nothing when warned password storage is declined' {
            Mock Request-HHSshKeyOnboardingChoice { $false }
            Mock Request-HHPasswordStorageConsent { $false }

            { Set-HHTarget -HostName example.test -UserName operator `
                    -HostKeyFingerprint $script:fingerprint -Confirm:$false } |
                Should -Throw '*Password storage was declined*no target was saved*'
            Should -Invoke Open-HHAuthenticatedPersistence -Times 0 -Exactly
            Should -Invoke Get-HHClientCredentialBytes -Times 0 -Exactly
        }

        It 'never falls back or retries after an uncertain key outcome' {
            Mock Request-HHSshKeyOnboardingChoice { $true }
            Mock Invoke-HHManagedHostEnableSshKeyAuthenticationOperation {
                $failure = [InvalidOperationException]::new('uncertain key setup')
                $failure.Data['HHOutcomeStatus'] = 'Unknown'
                throw $failure
            }
            Mock Remove-HHIncompleteOnboardingTarget {}
            Mock Save-HHOnboardingPasswordFallback { throw 'must not save' }

            { Set-HHTarget -HostName example.test -UserName operator `
                    -HostKeyFingerprint $script:fingerprint -Confirm:$false } |
                Should -Throw '*uncertain state*did not save a password or retry*'
            Should -Invoke Remove-HHIncompleteOnboardingTarget -Times 1 -Exactly
            Should -Invoke Request-HHPasswordStorageConsent -Times 0 -Exactly
            Should -Invoke Save-HHOnboardingPasswordFallback -Times 0 -Exactly
            Should -Invoke Invoke-HHManagedHostEnableSshKeyAuthenticationOperation `
                -Times 1 -Exactly
        }

        It 'preserves Add and explicit public-key fields in the committed target' {
            $result = @(Set-HHTarget -Name alpha -HostName example.test -UserName operator `
                    -Authentication PublicKey -KeyPath /keys/id_ed25519 -Add `
                    -HostKeyFingerprint $script:fingerprint -Confirm:$false)
            $result[0].Authentication | Should -BeExactly PublicKey
            $result[0].KeyPath | Should -BeExactly /keys/id_ed25519
            Should -Invoke Invoke-HHAnchoredPersistenceTransaction -ParameterFilter {
                [bool]$ArgumentList[0].Add
            } -Times 1
        }

        It 'records a finite trust terminal and never probes or mutates after trust refusal' {
            Mock Register-HHSshHostTrust { throw 'known_hosts fingerprint mismatch' }
            {
                Set-HHTarget -Name alpha -HostName example.test -UserName operator `
                    -HostKeyFingerprint $script:fingerprint -Confirm:$false
            } | Should -Throw '*known_hosts fingerprint mismatch*'
            Should -Invoke Complete-HHAuthenticatedTransportAudit -Times 1
            Should -Not -Invoke Invoke-HHTargetProbe
            Should -Not -Invoke Invoke-HHAnchoredPersistenceTransaction -ParameterFilter {
                $null -ne $ArgumentList[0].PSObject.Properties['Target']
            }
        }

        It 'rejects removed transport parameters before persistence' {
            {
                Set-HHTarget -Name windows -HostName windows.test -UserName operator `
                    -Transport WinRM -Authentication Password -Confirm:$false
            } | Should -Throw '*parameter*Transport*'
            Should -Not -Invoke Open-HHAuthenticatedPersistence
        }

        It 'lists authenticated targets and returns no state for an absent root' {
            @(Get-HHTarget -Name alpha).Name | Should -Be alpha
            @(Get-HHTarget).Name | Should -Be alpha
            [IO.Directory]::Delete($script:testRoot, $true)
            $information = @()
            @(Get-HHTarget -InformationVariable information).Count | Should -Be 0
            [string]$information[-1] | Should -BeExactly 'No currently set'
            @($information[-1].Tags) | Should -Contain PSHOST
        }

        It 'returns no state for a mounted empty data root without opening persistence' {
            [IO.File]::Delete($script:runtime.DatabasePath)
            [IO.Directory]::Exists($script:runtime.DataRoot) | Should -BeTrue
            $information = @()
            @(Get-HHTargets -InformationVariable information).Count | Should -Be 0
            [string]$information[-1] | Should -BeExactly 'No currently set'
            @($information[-1].Tags) | Should -Contain PSHOST
            [IO.File]::Exists($script:runtime.DatabasePath) | Should -BeFalse
            Should -Not -Invoke Open-HHAuthenticatedPersistence
        }

        It 'falls back to read-only display rows when the authenticated key is unavailable' {
            $errorRecord = [Management.Automation.ErrorRecord]::new(
                [InvalidOperationException]::new('key unavailable'),
                'AuditKeyUnavailable',
                [Management.Automation.ErrorCategory]::ResourceUnavailable,
                $script:runtime.DataRoot
            )
            Mock Open-HHAuthenticatedPersistence { throw $errorRecord }
            $readOnlyConnection = [pscustomobject]@{ DataSource = $script:runtime.DatabasePath }
            $readOnlyConnection | Add-Member ScriptMethod Dispose { }
            Mock New-HHSqliteConnection { $readOnlyConnection }
            Mock Test-HHSqliteDatabaseSchema { [pscustomobject]@{ SchemaVersion = 1 } }
            Mock Read-HHTargetRepositoryDisplaySnapshot {
                [pscustomobject]@{ Targets = @($script:target) }
            }
            $warning = $null
            $result = @(Get-HHTarget -Name alpha -WarningVariable warning)
            $result.Name | Should -BeExactly alpha
            [string]$warning | Should -Match 'cannot be authenticated'
            Should -Invoke New-HHSqliteConnection -Times 1 -ParameterFilter {
                $Mode -ceq 'ReadOnly'
            }
            Should -Invoke Read-HHTargetRepositoryDisplaySnapshot -Times 1 `
                -ParameterFilter { $Name -contains 'alpha' }

            $result = @(Get-HHTarget -WarningAction SilentlyContinue)
            $result.Name | Should -BeExactly alpha
            Should -Invoke Read-HHTargetRepositoryDisplaySnapshot -Times 1 `
                -ParameterFilter { $null -eq $Name }
        }

        It 'does not downgrade non-key authentication failures to display-only rows' {
            $errorRecord = [Management.Automation.ErrorRecord]::new(
                [Security.SecurityException]::new('state tampered'),
                'AuditIntegrityFailed',
                [Management.Automation.ErrorCategory]::SecurityError,
                $script:runtime.DataRoot
            )
            Mock Open-HHAuthenticatedPersistence { throw $errorRecord }
            Mock Read-HHTargetRepositoryDisplaySnapshot {
                throw 'Display fallback must not run for integrity failures.'
            }
            { Get-HHTarget } | Should -Throw -ErrorId 'AuditIntegrityFailed*'
            Should -Not -Invoke Read-HHTargetRepositoryDisplaySnapshot
        }

        It 'previews removal without initialization and commits approved removal once' {
            Remove-HHTarget -Name alpha -WhatIf
            Should -Not -Invoke Open-HHAuthenticatedPersistence
            @(Remove-HHTarget -Name alpha -Confirm:$false).Count | Should -Be 0
            Should -Invoke Invoke-HHAnchoredPersistenceTransaction -Times 1
        }

        It 'rejects more than eight piped removal names and an absent database' {
            $nine = 1..9 | ForEach-Object { [pscustomobject]@{ Name = "target$_" } }
            { $nine | Remove-HHTarget -Confirm:$false } | Should -Throw '*No more than eight*'
            Should -Not -Invoke Open-HHAuthenticatedPersistence

            [IO.File]::Delete($script:runtime.DatabasePath)
            { Remove-HHTarget -Name alpha -Confirm:$false } | Should -Throw '*unknown target*'
            Should -Not -Invoke Open-HHAuthenticatedPersistence
        }

        It 'forwards approved removal through the anchored repository transaction' {
            Mock Remove-HHTargetRepository {
                [pscustomobject]@{ CurrentTargets = @($script:target) }
            }
            Mock Invoke-HHAnchoredPersistenceTransaction {
                param($Context, $ArgumentList, $Action)
                & $Action 'connection' 'transaction' $Context $ArgumentList
            }
            $result = @(Remove-HHTarget -Name beta -Confirm:$false)
            $result.Name | Should -BeExactly alpha
            Should -Invoke Remove-HHTargetRepository -Times 1 -ParameterFilter {
                $Connection -ceq 'connection' -and $Transaction -ceq 'transaction' -and
                $Name -contains 'beta' -and $MutationId.Length -eq 16
            }
        }

        It 'returns empty Test state and rejects a requested missing target without audit' {
            $script:savedTargets = @()
            @(Test-HHTarget).Count | Should -Be 0
            { Test-HHTarget -Name missing } | Should -Throw '*Unknown target*'
            Should -Not -Invoke Register-HHAuthenticatedAuditBatch
        }

        It 'returns empty or unknown target state before persistence when the database is absent' {
            [IO.File]::Delete($script:runtime.DatabasePath)
            @(Test-HHTarget).Count | Should -Be 0
            { Test-HHTarget -Name alpha } | Should -Throw '*Unknown target*'
            Should -Not -Invoke Open-HHAuthenticatedPersistence
        }

        It 'seals and arms every Test identity operation before probing' {
            $result = Test-HHTarget -Name alpha
            $result.Succeeded | Should -BeTrue
            $result.PowerShellRuntime | Should -BeExactly PowerShell7
            $script:events | Should -Be @('intent', 'arm:0', 'probe', 'terminal')
        }

        It 'rejects malformed command text before touching persistence' {
            { Invoke-HHCommand -Command 'if (' } | Should -Throw '*not valid PowerShell*'
            Should -Not -Invoke Open-HHAuthenticatedPersistence
        }

        It 'arms identity before session open and command before fan-out' {
            Mock Open-HHSshSession {
                $script:events.Add('open')
                [pscustomobject]@{
                    Session = 'session'; IdentityEvents = @(); ValidatedAtUtc = '2026-08-24T01:00:00Z'
                    RemotePowerShellVersion = '7.6.5'; RemotePSEdition = 'Core'
                    ExecutionMode = 'Direct'; Identity = @{ UserName = 'operator' }
                    HostKeyFingerprint = $script:fingerprint
                }
            }
            Mock Invoke-HHSshSessionFanOut {
                $script:events.Add('fanout')
                [ordered]@{ alpha = [pscustomobject]@{
                        Succeeded = $true; FailureKind = $null; StreamEvents = @()
                        OutputBytes = 0L; ExceptionType = $null
                        DispatchState = 'Completed'; OutcomeStatus = 'Succeeded'
                    } }
            }
            Mock Close-HHSshSession { $script:events.Add('close') }
            $result = Invoke-HHCommand -Command '6 * 7' -Target alpha
            $result.Succeeded | Should -BeTrue
            $script:events | Should -Be @(
                'intent', 'arm:0', 'open', 'arm:1', 'fanout', 'close', 'terminal'
            )
            Should -Invoke Start-HHAuthenticatedAuditCapacityReservation -Times 1
            Should -Invoke Open-HHAuthenticatedAuditArtifactWriter -Times 1
            Should -Invoke Invoke-HHSshSessionFanOut -ParameterFilter {
                $null -ne $EventObserver
            } -Times 1
            Should -Invoke Complete-HHAuthenticatedTransportAudit -ParameterFilter {
                $null -ne $ArtifactWriter
            } -Times 1
            Should -Invoke Remove-HHPersistenceCapacityReservation -Times 1
        }

        It 'streams identity and command events into the reserved artifact writer' {
            $identityEvent = [pscustomobject]@{ Sequence = 0; Phase = 'Identity'; Value = 'identity' }
            $commandEvent = [pscustomobject]@{ Sequence = 1; Phase = 'Command'; Value = 42 }
            Mock Open-HHSshSession {
                [pscustomobject]@{
                    Session = 'session'; IdentityEvents = @($identityEvent)
                    ValidatedAtUtc = '2026-08-24T01:00:00Z'; RemotePowerShellVersion = '7.6.5'
                    RemotePSEdition = 'Core'; ExecutionMode = 'Direct'
                    Identity = @{ UserName = 'operator' }; HostKeyFingerprint = $script:fingerprint
                }
            }
            Mock Invoke-HHSshSessionFanOut {
                param($ScriptBlock, $EventObserver)
                $script:remoteClosureResult = & $ScriptBlock -CommandText '6 * 7'
                & $EventObserver alpha $commandEvent
                [ordered]@{ alpha = [pscustomobject]@{
                        Succeeded = $true; FailureKind = $null; StreamEvents = @($commandEvent)
                        OutputBytes = 2L; ExceptionType = $null
                        DispatchState = 'Completed'; OutcomeStatus = 'Succeeded'
                    } }
            }
            Mock Close-HHSshSession
            $result = Invoke-HHCommand -Command '6 * 7' -Target alpha
            $result.Succeeded | Should -BeTrue
            $script:remoteClosureResult | Should -Be 42
            Should -Invoke Write-HHAuditArtifactV2Event -Times 1 -ParameterFilter {
                $EventRecord -eq $identityEvent
            }
            Should -Invoke Write-HHAuditArtifactV2Event -Times 1 -ParameterFilter {
                $EventRecord -eq $commandEvent
            }
        }

        It 'records a classified open failure without retrying' {
            Mock Open-HHSshSession { throw [TimeoutException]::new('timeout') }
            Mock Get-HHSshFailureKind { 'Timeout' }
            $result = Invoke-HHCommand -Command 'Get-Date' -Target alpha
            $result.Succeeded | Should -BeFalse
            $result.FailureKind | Should -BeExactly Timeout
            Should -Invoke Open-HHSshSession -Times 1
            Should -Invoke Complete-HHAuthenticatedTransportAudit -Times 1
        }

        It 'gives one Set-HHTarget recovery action when a saved password is rejected' {
            $script:target.CredentialStorage = 'Encrypted'
            $script:savedTargets = @($script:target)
            Mock Initialize-HHStoredTargetCredential {}
            Mock Open-HHSshSession { throw 'password rejected' }
            Mock Get-HHSshFailureKind { 'AuthenticationFailure' }

            $result = Invoke-HHCommand -Command 'Get-Date' -Target alpha

            $result.Succeeded | Should -BeFalse
            $result.RecoveryAction | Should -BeExactly `
                "Run Set-HHTarget for 'alpha' to replace its saved password."
            Should -Invoke Open-HHSshSession -Times 1 -Exactly
        }

        It 'retains and resequences transport evidence captured before session-open failure' {
            $captured = [pscustomobject]@{
                Sequence = 99; Phase = 'Identity'; Value = 'partial'; SerializedByteCount = 7L
            }
            Mock Open-HHSshSession {
                $exception = [IO.IOException]::new('open failed after evidence')
                $exception.Data['HHStreamEvents'] = @($captured)
                throw $exception
            }
            Mock Get-HHSshFailureKind { 'TransportFailure' }
            $result = Invoke-HHCommand -Command 'Get-Date' -Target alpha
            $result.StreamEvents.Count | Should -Be 2
            $result.StreamEvents[0] | Should -Be $captured
            $result.StreamEvents[0].Sequence | Should -Be 0
            $result.StreamEvents[1].Phase | Should -BeExactly Transport
        }

        It 'fails before persistence when the database is absent' {
            [IO.File]::Delete($script:runtime.DatabasePath)
            { Invoke-HHCommand -Command 'Get-Date' } |
                Should -Throw '*No active HostHunter targets are available*'
            Should -Not -Invoke Open-HHAuthenticatedPersistence
            Should -Not -Invoke Close-HHAuthenticatedPersistence
        }

        It 'closes authenticated persistence for selection and registration faults' {
            $script:savedTargets = @()
            { Invoke-HHCommand -Command 'Get-Date' } |
                Should -Throw '*No active HostHunter targets are available*'
            Should -Invoke Close-HHAuthenticatedPersistence -Times 1

            $script:savedTargets = @($script:target)
            { Invoke-HHCommand -Command 'Get-Date' -Target missing } |
                Should -Throw '*Unknown target*'
            Should -Invoke Close-HHAuthenticatedPersistence -Times 2

            Mock Register-HHAuthenticatedAuditBatch { throw 'registration fault' }
            { Invoke-HHCommand -Command 'Get-Date' -Target alpha } |
                Should -Throw '*registration fault*'
            Should -Invoke Close-HHAuthenticatedPersistence -Times 3
        }

        It 'preserves a capacity reservation fault and closes without releasing an absent receipt' {
            Mock Start-HHAuthenticatedAuditCapacityReservation {
                throw [IO.IOException]::new('capacity unavailable')
            }
            { Invoke-HHCommand -Command 'Get-Date' -Target alpha } |
                Should -Throw '*capacity unavailable*'
            Should -Invoke Register-HHAuthenticatedAuditBatch -Times 1
            Should -Invoke Start-HHAuthenticatedAuditCapacityReservation -Times 1
            Should -Not -Invoke Remove-HHPersistenceCapacityReservation
            Should -Invoke Close-HHAuthenticatedPersistence -Times 1
        }

        It 'rejects a selected historical transport and releases persistence' {
            $script:target.Transport = 'WinRM'
            { Invoke-HHCommand -Command 'Get-Date' -Target alpha } |
                Should -Throw '*historical transport or runtime profile*'
            Should -Invoke Close-HHAuthenticatedPersistence -Times 1
            Should -Not -Invoke Register-HHAuthenticatedAuditBatch
        }

        It 'fails closed when an open mismatch lacks complete attributable evidence' {
            Mock Get-HHSshFailureKind { 'RuntimeMismatch' }
            Mock Open-HHSshSession {
                $exception = [InvalidOperationException]::new('runtime mismatch')
                $exception.Data['HHObservedRemotePowerShellVersion'] = '5.1.26100.1'
                throw $exception
            }
            $result = Invoke-HHCommand -Command 'Get-Date' -Target alpha
            $result.FailureKind | Should -BeExactly TransportFailure
            $result.RemotePowerShellVersion | Should -BeNullOrEmpty
            $result.DispatchState | Should -BeExactly NotDispatched
            $script:completedTransportResults[0].FailureKind |
                Should -BeExactly TransportFailure
            $script:completedTransportResults[0].RemoteIdentity | Should -BeNullOrEmpty
            Should -Invoke Close-HHAuthenticatedPersistence -Times 1
        }

        It 'preserves complete mismatch attribution and uncertain dispatch from open failure data' {
            Mock Get-HHSshFailureKind { 'RuntimeMismatch' }
            Mock Open-HHSshSession {
                $exception = [InvalidOperationException]::new('runtime mismatch')
                $exception.Data['HHObservedIdentity'] = [pscustomobject]@{
                    Marker = 'HostHunter.PowerShellIdentity.v1'
                    PSEdition = 'Desktop'
                    PowerShellVersion = '5.1.26100.1'
                    ProcessPath = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
                    UserName = 'operator'
                    MachineName = 'fixture'
                }
                $exception.Data['HHObservedRemotePowerShellVersion'] = '5.1.26100.1'
                $exception.Data['HHObservedRemotePSEdition'] = 'Desktop'
                $exception.Data['HHObservedExecutionMode'] = 'WindowsPowerShellCompatibility'
                $exception.Data['HHObservedValidatedAtUtc'] = '2026-08-24T01:00:00Z'
                $exception.Data['HHObservedHostKeyFingerprint'] = $script:fingerprint
                $exception.Data['HHDispatchState'] = 'DispatchUncertain'
                $exception.Data['HHOutcomeStatus'] = 'Unknown'
                throw $exception
            }
            $result = Invoke-HHCommand -Command 'Get-Date' -Target alpha
            $result.FailureKind | Should -BeExactly RuntimeMismatch
            $result.DispatchState | Should -BeExactly DispatchUncertain
            $result.OutcomeStatus | Should -BeExactly Unknown
            $result.RemotePSEdition | Should -BeExactly Desktop
            $result.HostKeyFingerprint | Should -BeExactly $script:fingerprint
            $script:completedTransportResults[0].RemoteIdentity.PSEdition |
                Should -BeExactly Desktop
        }

        It 'turns session cleanup failure into a terminal failed result and retains command events' {
            $commandEvent = [pscustomobject]@{ Sequence = 0; Phase = 'Command'; Stream = 'Output' }
            Mock Open-HHSshSession {
                [pscustomobject]@{
                    Session = 'session'; IdentityEvents = @(); ValidatedAtUtc = '2026-08-24T01:00:00Z'
                    RemotePowerShellVersion = '7.6.5'; RemotePSEdition = 'Core'
                    ExecutionMode = 'Direct'; Identity = @{ UserName = 'operator' }
                    HostKeyFingerprint = $script:fingerprint
                }
            }
            Mock Invoke-HHSshSessionFanOut {
                [ordered]@{ alpha = [pscustomobject]@{
                        Succeeded = $true; FailureKind = $null; StreamEvents = @($commandEvent)
                        OutputBytes = 0L; ExceptionType = $null
                        DispatchState = 'Completed'; OutcomeStatus = 'Succeeded'
                    } }
            }
            Mock Close-HHSshSession { throw [InvalidOperationException]::new('cleanup failed') }
            $result = Invoke-HHCommand -Command 'Get-Date' -Target alpha
            $result.Succeeded | Should -BeFalse
            $result.FailureKind | Should -BeExactly TransportFailure
            $result.SessionRemovalFailure | Should -BeTrue
            $result.StreamEvents.Count | Should -Be 2
            $result.StreamEvents[0] | Should -Be $commandEvent
            $script:completedTransportResults[0].SessionRemovalFailure | Should -BeTrue
            $script:completedTransportResults[0].ExceptionType |
                Should -BeExactly System.InvalidOperationException
        }

        It 'fails closed for incomplete command mismatch evidence after dispatch' {
            Mock Open-HHSshSession {
                [pscustomobject]@{
                    Session = 'session'; IdentityEvents = @(); ValidatedAtUtc = '2026-08-24T01:00:00Z'
                    RemotePowerShellVersion = '7.6.5'; RemotePSEdition = 'Core'
                    ExecutionMode = 'Direct'; Identity = @{ UserName = 'operator' }
                    HostKeyFingerprint = $script:fingerprint
                }
            }
            Mock Invoke-HHSshSessionFanOut {
                [ordered]@{ alpha = [pscustomobject]@{
                        Succeeded = $false; FailureKind = 'RuntimeMismatch'; StreamEvents = @()
                        OutputBytes = 0L; ExceptionType = 'System.InvalidOperationException'
                        DispatchState = 'Dispatched'; OutcomeStatus = 'Failed'
                        RemoteIdentity = $null; RemotePowerShellVersion = $null
                        RemotePSEdition = $null; ExecutionMode = $null; ValidatedAtUtc = $null
                    } }
            }
            Mock Close-HHSshSession
            $result = Invoke-HHCommand -Command 'Get-Date' -Target alpha
            $result.FailureKind | Should -BeExactly TransportFailure
            $result.OutcomeStatus | Should -BeExactly Unknown
            $result.RemotePowerShellVersion | Should -BeExactly 7.6.5
            $script:completedTransportResults[0].FailureKind |
                Should -BeExactly TransportFailure
        }

        It 'maps an incomplete non-dispatched command mismatch to a failed outcome' {
            Mock Open-HHSshSession {
                [pscustomobject]@{
                    Session = 'session'; IdentityEvents = @(); ValidatedAtUtc = '2026-08-24T01:00:00Z'
                    RemotePowerShellVersion = '7.6.5'; RemotePSEdition = 'Core'
                    ExecutionMode = 'Direct'; Identity = @{ UserName = 'operator' }
                    HostKeyFingerprint = $script:fingerprint
                }
            }
            Mock Invoke-HHSshSessionFanOut {
                [ordered]@{ alpha = [pscustomobject]@{
                        Succeeded = $false; FailureKind = 'RuntimeMismatch'; StreamEvents = @()
                        OutputBytes = 0L; ExceptionType = 'System.InvalidOperationException'
                        DispatchState = 'NotDispatched'; OutcomeStatus = 'Unknown'
                        RemoteIdentity = $null; RemotePowerShellVersion = $null
                        RemotePSEdition = $null; ExecutionMode = $null; ValidatedAtUtc = $null
                    } }
            }
            Mock Close-HHSshSession
            $result = Invoke-HHCommand -Command 'Get-Date' -Target alpha
            $result.FailureKind | Should -BeExactly TransportFailure
            $result.OutcomeStatus | Should -BeExactly Failed
        }

        It 'uses complete command mismatch evidence and falls back to session trust evidence' {
            $identity = [pscustomobject]@{
                Marker = 'HostHunter.PowerShellIdentity.v1'
                PSEdition = 'Desktop'
                PowerShellVersion = '5.1.26100.1'
                ProcessPath = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
                UserName = 'operator'
                MachineName = 'fixture'
            }
            Mock Open-HHSshSession {
                [pscustomobject]@{
                    Session = 'session'; IdentityEvents = @(); ValidatedAtUtc = '2026-08-24T01:00:00Z'
                    RemotePowerShellVersion = '7.6.5'; RemotePSEdition = 'Core'
                    ExecutionMode = 'Direct'; Identity = @{ UserName = 'operator' }
                    HostKeyFingerprint = $script:fingerprint
                }
            }
            Mock Invoke-HHSshSessionFanOut {
                [ordered]@{ alpha = [pscustomobject]@{
                        Succeeded = $false; FailureKind = 'RuntimeMismatch'; StreamEvents = @()
                        OutputBytes = 0L; ExceptionType = 'System.InvalidOperationException'
                        DispatchState = 'Completed'; OutcomeStatus = 'Failed'
                        RemoteIdentity = $identity; RemotePowerShellVersion = '5.1.26100.1'
                        RemotePSEdition = 'Desktop'
                        ExecutionMode = 'WindowsPowerShellCompatibility'
                        ValidatedAtUtc = '2026-08-24T01:01:00Z'
                    } }
            }
            Mock Close-HHSshSession
            $result = Invoke-HHCommand -Command 'Get-Date' -Target alpha
            $result.FailureKind | Should -BeExactly RuntimeMismatch
            $result.RemotePowerShellVersion | Should -BeExactly 5.1.26100.1
            $result.RemotePSEdition | Should -BeExactly Desktop
            $result.HostKeyFingerprint | Should -BeExactly $script:fingerprint
            $script:completedTransportResults[0].RemoteIdentity | Should -Be $identity
        }

        It 'cancels later unarmed Set intents when an earlier target fails validation' {
            Mock Invoke-HHTargetProbe { throw 'first target probe failed' }
            $targets = @(
                [pscustomobject]@{ Name = 'alpha'; HostName = 'alpha.test'; Port = 22
                    UserName = 'operator'; Authentication = 'Password'
                    HostKeyFingerprint = $script:fingerprint }
                [pscustomobject]@{ Name = 'beta'; HostName = 'beta.test'; Port = 22
                    UserName = 'operator'; Authentication = 'Password'
                    HostKeyFingerprint = $script:fingerprint }
            )
            {
                Set-HHTarget -InputObject $targets -Confirm:$false
            } | Should -Throw '*first target probe failed*'
            Should -Invoke Complete-HHAuthenticatedUnstartedAuditIntent -Times 1 `
                -ParameterFilter { $Intent.InvocationId -ceq ('{0:x32}' -f 2) }
            Should -Invoke Close-HHAuthenticatedPersistence -Times 1
            Should -Invoke Remove-HHPersistenceCapacityReservation -Times 1
        }

        It 'preserves the primary Set failure when recording a later cancellation also fails' {
            Mock Invoke-HHTargetProbe { throw 'first target probe failed' }
            Mock Complete-HHAuthenticatedUnstartedAuditIntent {
                throw 'cancellation persistence failed'
            }

            $targets = @(
                [pscustomobject]@{ Name = 'alpha'; HostName = 'alpha.test'; Port = 22
                    UserName = 'operator'; Authentication = 'Password'
                    HostKeyFingerprint = $script:fingerprint }
                [pscustomobject]@{ Name = 'beta'; HostName = 'beta.test'; Port = 22
                    UserName = 'operator'; Authentication = 'Password'
                    HostKeyFingerprint = $script:fingerprint }
            )
            {
                Set-HHTarget -InputObject $targets -Confirm:$false
            } | Should -Throw '*first target probe failed*'
            Should -Invoke Complete-HHAuthenticatedUnstartedAuditIntent -Times 1
            Should -Invoke Close-HHAuthenticatedPersistence -Times 1
        }

        It 'previews SSH key bootstrap without preparation or remote activity' {
            Mock New-HHSshKeyBootstrapPlan { [pscustomobject]@{ Planned = $true } }
            $result = Enable-HHSshKeyAuthentication -Name alpha -WhatIf
            $result.Planned | Should -BeTrue
            Should -Not -Invoke Prepare-HHSshKeyBootstrapOperation
        }

        It 'rejects bootstrap before mutation for an absent unknown or non-password target' {
            [IO.File]::Delete($script:runtime.DatabasePath)
            { Enable-HHSshKeyAuthentication -Name alpha -Confirm:$false } |
                Should -Throw "*Unknown target 'alpha'*"
            Should -Not -Invoke Open-HHAuthenticatedPersistence

            [IO.File]::WriteAllBytes($script:runtime.DatabasePath, [byte[]]@(1))
            $script:savedTargets = @()
            { Enable-HHSshKeyAuthentication -Name alpha -Confirm:$false } |
                Should -Throw "*Unknown target 'alpha'*"

            $keyPath = Join-Path $TestDrive 'already-keyed'
            [IO.File]::WriteAllText($keyPath, 'test-key')
            $script:savedTargets = @(New-HHTargetRecord -Name alpha -Transport SSH `
                    -HostName example.test -Port 22 -UserName operator `
                    -Authentication PublicKey -PowerShellRuntime PowerShell7 `
                    -HostKeyFingerprint $script:fingerprint -KeyPath $keyPath -IsActive $true `
                    -LastValidatedAtUtc '2026-08-24T00:00:00Z' `
                    -LastValidatedPSEdition Core -LastValidatedPowerShellVersion 7.6.5 `
                    -LastValidatedExecutionMode Direct)
            { Enable-HHSshKeyAuthentication -Name alpha -Confirm:$false } |
                Should -Throw '*must use SSH password authentication*'
        }

        It 'previews bootstrap with an explicit normalized key path' {
            Mock New-HHSshKeyBootstrapPlan {
                [pscustomobject]@{ KeyPath = $KeyPath }
            }
            $relative = Join-Path $TestDrive 'explicit-key'

            $result = Enable-HHSshKeyAuthentication -Name alpha `
                -KeyPath $relative -WhatIf

            $result.KeyPath | Should -BeExactly ([IO.Path]::GetFullPath($relative))
        }

        It 'arms bootstrap phases and commits the profile through target CAS' {
            $operations = @(
                Get-HHRemoteOperationManifestEntry -Phase OuterIdentity `
                    -PowerShellRuntime PowerShell7 -ScriptText identity
                Get-HHRemoteOperationManifestEntry -Phase BootstrapInstall `
                    -PowerShellRuntime PowerShell7 -ScriptText install
                Get-HHRemoteOperationManifestEntry -Phase BootstrapKeyOnlyOuterIdentity `
                    -PowerShellRuntime PowerShell7 -ScriptText keyidentity
                Get-HHRemoteOperationManifestEntry -Phase BootstrapRollback `
                    -PowerShellRuntime PowerShell7 -ScriptText rollback -Conditional $true
            )
            $prepared = [pscustomobject]@{
                Plan = [pscustomobject]@{ KeyAction = 'Generate' }
                RemoteOperations = $operations
                LocalGenerationOccurred = $true
            }
            Mock Prepare-HHSshKeyBootstrapOperation { $prepared }
            Mock Invoke-HHSshKeyBootstrap {
                param($OperationArmer, $ProfileTransitionCommitter)
                & $OperationArmer @('OuterIdentity')
                & $OperationArmer @('BootstrapInstall')
                & $OperationArmer @('BootstrapKeyOnlyOuterIdentity')
                $transition = New-HHTargetRecord -Name alpha -Transport SSH `
                    -HostName example.test -Port 22 -UserName operator `
                    -Authentication PublicKey -PowerShellRuntime PowerShell7 `
                    -HostKeyFingerprint $script:fingerprint -KeyPath /keys/id_ed25519 `
                    -IsActive $true -LastValidatedAtUtc '2026-08-24T02:00:00Z' `
                    -LastValidatedPSEdition Core -LastValidatedPowerShellVersion 7.6.5 `
                    -LastValidatedExecutionMode Direct
                $receipt = & $ProfileTransitionCommitter $transition $script:target $prepared
                [pscustomobject]@{
                    Succeeded = $true; FailureKind = $null; DispatchState = 'Completed'
                    OutcomeStatus = 'Succeeded'; ProfileTransition = $transition
                    Installed = $true; RollbackAttempted = $false; RollbackSucceeded = $null
                    ReconciliationRequired = $false; CommitState = if ($receipt.Committed) {
                        'Committed'
                    }
                    else { 'Failed' }
                    StreamEvents = @(); OutputBytes = 0L; ExceptionType = $null
                    RemotePowerShellVersion = '7.6.5'; RemotePSEdition = 'Core'
                    ExecutionMode = 'Direct'; RemoteIdentity = @{ UserName = 'operator' }
                    HostKeyFingerprint = $script:fingerprint; ValidatedAtUtc = '2026-08-24T02:00:00Z'
                    SessionRemovalFailure = $false
                }
            }
            $result = Enable-HHSshKeyAuthentication -Name alpha -Confirm:$false
            $result.Authentication | Should -BeExactly PublicKey
            Should -Invoke Arm-HHAuthenticatedRemoteOperation -Times 3
            Should -Invoke Invoke-HHAnchoredPersistenceTransaction -Times 1
            Should -Invoke Complete-HHAuthenticatedTransportAudit -Times 1
        }

        It 'removes prepared local material when durable intent registration fails' {
            Mock Prepare-HHSshKeyBootstrapOperation {
                [pscustomobject]@{
                    Plan = [pscustomobject]@{ KeyAction = 'Generate' }
                    RemoteOperations = @(
                        Get-HHRemoteOperationManifestEntry -Phase OuterIdentity `
                            -PowerShellRuntime PowerShell7 -ScriptText identity
                    )
                    LocalGenerationOccurred = $true
                }
            }
            Mock Register-HHAuthenticatedAuditBatch { throw 'intent persistence failed' }
            Mock Undo-HHSshKeyBootstrapPreparation {
                [pscustomobject]@{ Attempted = $true; Removed = $true; FailureType = $null }
            }
            { Enable-HHSshKeyAuthentication -Name alpha -Confirm:$false } |
                Should -Throw '*intent persistence failed*'
            Should -Invoke Undo-HHSshKeyBootstrapPreparation -Times 1
            Should -Not -Invoke Invoke-HHSshKeyBootstrap
        }

        It 'preserves local key cleanup failure evidence on an intent registration fault' {
            Mock Prepare-HHSshKeyBootstrapOperation {
                [pscustomobject]@{
                    Plan = [pscustomobject]@{ KeyAction = 'Generate' }
                    RemoteOperations = @(
                        Get-HHRemoteOperationManifestEntry -Phase OuterIdentity `
                            -PowerShellRuntime PowerShell7 -ScriptText identity
                    )
                    LocalGenerationOccurred = $true
                }
            }
            Mock Register-HHAuthenticatedAuditBatch { throw 'intent persistence failed' }
            Mock Undo-HHSshKeyBootstrapPreparation {
                [pscustomobject]@{
                    Attempted = $true; Removed = $false; FailureType = 'PermissionDenied'
                }
            }
            $caught = $null
            try { Enable-HHSshKeyAuthentication -Name alpha -Confirm:$false }
            catch { $caught = $_ }

            $caught.Exception.Message | Should -BeExactly 'intent persistence failed'
            $caught.Exception.Data['HHLocalKeyCleanupFailureType'] |
                Should -BeExactly PermissionDenied
        }
    }
}
