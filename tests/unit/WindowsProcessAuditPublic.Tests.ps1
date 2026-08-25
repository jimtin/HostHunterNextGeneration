$sourceRoot = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
    Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration'
}
else { $env:HH_TEST_SOURCE_ROOT }
Import-Module (Join-Path $sourceRoot 'HostHunterNextGeneration.psd1') -Force

Describe 'Windows process-audit public contract' -Tag Unit {
    InModuleScope HostHunterNextGeneration {
        BeforeEach {
            $script:testRoot = Join-Path $TestDrive ([Guid]::NewGuid().ToString('N'))
            $script:runtime = Get-HHPersistenceContext -DataRoot $script:testRoot
            Mock Get-HHRuntimeContext { $script:runtime }
            Mock Open-HHAuthenticatedPersistence { throw 'unexpected persistence open' }
        }

        It 'returns the sole built-in preference without creating persistence' {
            $preference = Get-HHEscalationPreference
            $preference.Method | Should -BeExactly WindowsTokenPrivilege
            $preference.Scope | Should -BeExactly Global
            $preference.Source | Should -BeExactly BuiltIn
            $preference.IsPersisted | Should -BeFalse
            Test-Path -LiteralPath $script:testRoot | Should -BeFalse
            Should -Not -Invoke Open-HHAuthenticatedPersistence
        }

        It 'previews a preference change without initializing persistence' {
            Set-HHEscalationPreference -Method WindowsTokenPrivilege -WhatIf
            Test-Path -LiteralPath $script:testRoot | Should -BeFalse
            Should -Not -Invoke Open-HHAuthenticatedPersistence
        }

        It 'reads and writes persisted preferences while always closing the context' {
            $context = [pscustomobject]@{ Marker = 'context' }
            [IO.Directory]::CreateDirectory($script:testRoot) | Out-Null
            [IO.File]::WriteAllBytes($script:runtime.DatabasePath, [byte[]](1))
            Mock Open-HHAuthenticatedPersistence { $context }
            Mock Get-HHAuthenticatedEscalationPreference {
                [pscustomobject]@{ Method = 'WindowsTokenPrivilege'; Source = 'Persisted' }
            }
            Mock Set-HHAuthenticatedEscalationPreference {
                [pscustomobject]@{ Method = $Method; Committed = $true }
            }
            Mock Close-HHAuthenticatedPersistence { }

            (Get-HHEscalationPreference).Source | Should -BeExactly Persisted
            (Set-HHEscalationPreference -Method WindowsTokenPrivilege -Confirm:$false).Committed |
                Should -BeTrue
            Should -Invoke Open-HHAuthenticatedPersistence -Times 2 -Exactly
            Should -Invoke Close-HHAuthenticatedPersistence -Times 2 -Exactly
        }

        It 'closes persisted preference contexts when a repository operation fails' {
            [IO.Directory]::CreateDirectory($script:testRoot) | Out-Null
            [IO.File]::WriteAllBytes($script:runtime.DatabasePath, [byte[]](1))
            Mock Open-HHAuthenticatedPersistence { [pscustomobject]@{ Marker = 'context' } }
            Mock Get-HHAuthenticatedEscalationPreference { throw 'read failed' }
            Mock Set-HHAuthenticatedEscalationPreference { throw 'write failed' }
            Mock Close-HHAuthenticatedPersistence { }

            { Get-HHEscalationPreference } | Should -Throw '*read failed*'
            { Set-HHEscalationPreference -Method WindowsTokenPrivilege -Confirm:$false } |
                Should -Throw '*write failed*'
            Should -Invoke Close-HHAuthenticatedPersistence -Times 2 -Exactly
        }

        It 'rejects invalid command-line policy combinations before persistence' {
            {
                Set-HHWindowsProcessAuditPolicy -State Enabled `
                    -Subcategory ProcessTermination `
                    -CommandLineLogging Enabled -Confirm:$false
            } | Should -Throw '*only when ProcessCreation is selected*'
            {
                Set-HHWindowsProcessAuditPolicy -State Disabled `
                    -CommandLineLogging Enabled -Confirm:$false
            } | Should -Throw '*cannot be enabled*'
            {
                Set-HHWindowsProcessAuditPolicy -State Enabled `
                    -EscalationMethod WindowsTokenPrivilege -Confirm:$false
            } | Should -Throw '*requires -Escalate*'
            {
                Set-HHWindowsProcessAuditPolicy -State Enabled `
                    -Subcategory ProcessCreation, ProcessCreation -Confirm:$false
            } | Should -Throw '*duplicate*'
            {
                Set-HHWindowsProcessAuditPolicy -State Enabled `
                    -Subcategory ProcessTermination `
                    -CommandLineLogging Disabled -Confirm:$false
            } | Should -Throw '*only when ProcessCreation is selected*'
            Should -Not -Invoke Open-HHAuthenticatedPersistence
        }

        It 'warns once when command-line logging is enabled and continues WhatIf' {
            $records = @(
                Set-HHWindowsProcessAuditPolicy -State Enabled `
                    -CommandLineLogging Enabled -Target alpha, beta `
                    -Escalate -WhatIf 3>&1
            )
            $warnings = @($records | Where-Object { $_ -is [Management.Automation.WarningRecord] })
            $warnings.Count | Should -Be 1
            [string]$warnings[0] | Should -Match 'plaintext'
            [string]$warnings[0] | Should -Match 'Execution will continue'
            Should -Not -Invoke Open-HHAuthenticatedPersistence
        }

        It 'does not warn for unchanged disabled or not-configured command-line state' {
            foreach ($commandLineState in @('Unchanged', 'Disabled', 'NotConfigured')) {
                $records = @(
                    Set-HHWindowsProcessAuditPolicy -State Enabled `
                        -CommandLineLogging $commandLineState -WhatIf 3>&1
                )
                @($records | Where-Object {
                        $_ -is [Management.Automation.WarningRecord]
                    }).Count | Should -Be 0
            }
            Should -Not -Invoke Open-HHAuthenticatedPersistence
        }

        It 'forwards explicit target and escalation method to the shared coordinator' {
            Mock Invoke-HHRemoteCommandCoordinator {
                [pscustomobject]@{
                    Operation = $Operation
                    Target = @($Target)
                    Request = $RemoteArgumentList[0]
                }
            }
            $result = Set-HHWindowsProcessAuditPolicy -State Enabled `
                -Subcategory ProcessCreation, ProcessTermination `
                -CommandLineLogging Disabled -Target alpha, beta `
                -Escalate -EscalationMethod WindowsTokenPrivilege -Confirm:$false
            $result.Operation | Should -BeExactly SetWindowsProcessAuditPolicy
            $result.Target | Should -Be @('alpha', 'beta')
            $result.Request.Escalate | Should -BeTrue
            $result.Request.EscalationMethod | Should -BeExactly WindowsTokenPrivilege
            $result.Request.Subcategory | Should -Be @(
                'ProcessCreation', 'ProcessTermination'
            )
        }

        It 'resolves the saved method only when escalation has no explicit override' {
            Mock Get-HHEscalationPreference {
                [pscustomobject]@{ Method = 'WindowsTokenPrivilege' }
            }
            Mock Invoke-HHRemoteCommandCoordinator {
                $RemoteArgumentList[0]
            }
            $escalated = Set-HHWindowsProcessAuditPolicy -State Enabled `
                -Escalate -Confirm:$false
            $current = Set-HHWindowsProcessAuditPolicy -State Disabled -Confirm:$false
            $escalated.EscalationMethod | Should -BeExactly WindowsTokenPrivilege
            $current.EscalationMethod | Should -BeExactly CurrentToken
            Should -Invoke Get-HHEscalationPreference -Times 1 -Exactly
        }

        It 'fails closed when a persisted escalation method is unsupported' {
            Mock Get-HHEscalationPreference { [pscustomobject]@{ Method = 'UnknownMethod' } }
            Mock Invoke-HHRemoteCommandCoordinator { throw 'must not dispatch' }

            {
                Set-HHWindowsProcessAuditPolicy -State Enabled -Escalate -Confirm:$false
            } | Should -Throw '*unsupported*'
            Should -Not -Invoke Invoke-HHRemoteCommandCoordinator
        }

        It 'maps a finite remote policy failure into the aggregate transport result' {
            Mock Invoke-HHRemoteCommandCoordinator {
                $outcome = New-HHWindowsProcessAuditResult `
                    -AuditBefore ([ordered]@{}) -AuditDesired ([ordered]@{}) `
                    -AuditAfter $null -CommandLineBefore Unknown `
                    -CommandLineDesired Unchanged -CommandLineAfter $null `
                    -Succeeded $false -Changed $false `
                    -CompensationStatus NotRequired -ConflictDetected $false `
                    -ReconciliationRequired $false -EscalationRequested $false `
                    -PrivilegeResult $null -FailureKind PolicyQueryFailed `
                    -FailureMessage unavailable
                $commandResult = [pscustomobject]@{
                    StreamEvents = @([pscustomobject]@{ Value = $outcome })
                    DispatchState = 'Completed'
                }
                $transport = [pscustomobject]@{
                    Succeeded = $true; FailureKind = $null
                    DispatchState = 'Completed'; OutcomeStatus = 'Succeeded'
                    ExceptionType = $null
                }
                & $TransportResultAugmenter $null $transport $commandResult
            }
            $result = Set-HHWindowsProcessAuditPolicy -State Enabled -Confirm:$false
            $result.Succeeded | Should -BeFalse
            $result.FailureKind | Should -BeExactly RemoteCommandFailure
            $result.OutcomeStatus | Should -BeExactly Failed
            $result.PolicyOutcome.FailureKind | Should -BeExactly PolicyQueryFailed
        }

        It 'preserves successful and pre-completion transport results' {
            Mock Invoke-HHRemoteCommandCoordinator {
                $successfulOutcome = New-HHWindowsProcessAuditResult `
                    -AuditBefore ([ordered]@{ ProcessCreation = 4 }) `
                    -AuditDesired ([ordered]@{ ProcessCreation = 1 }) `
                    -AuditAfter ([ordered]@{ ProcessCreation = 1 }) `
                    -CommandLineBefore Disabled -CommandLineDesired Disabled `
                    -CommandLineAfter Disabled -Succeeded $true -Changed $true `
                    -CompensationStatus NotRequired -ConflictDetected $false `
                    -ReconciliationRequired $false -EscalationRequested $false `
                    -PrivilegeResult $null -FailureKind $null -FailureMessage $null
                $successfulCommand = [pscustomobject]@{
                    StreamEvents = @([pscustomobject]@{ Value = $successfulOutcome })
                    DispatchState = 'Completed'
                }
                $successfulTransport = [pscustomobject]@{
                    Succeeded = $true; FailureKind = $null
                    DispatchState = 'Completed'; OutcomeStatus = 'Succeeded'
                    ExceptionType = $null
                }
                $first = & $TransportResultAugmenter $null $successfulTransport $successfulCommand

                $incompleteCommand = [pscustomobject]@{
                    StreamEvents = @([pscustomobject]@{ Value = 'partial output' })
                    DispatchState = 'DispatchUncertain'
                }
                $incompleteTransport = [pscustomobject]@{
                    Succeeded = $false; FailureKind = 'TransportFailure'
                    DispatchState = 'DispatchUncertain'; OutcomeStatus = 'Unknown'
                    ExceptionType = 'TransportFailure'
                }
                $second = & $TransportResultAugmenter $null $incompleteTransport $incompleteCommand
                @($first, $second)
            }

            $results = @(Set-HHWindowsProcessAuditPolicy -State Enabled -Confirm:$false)
            $results.Count | Should -Be 2
            $results[0].PolicyOutcome.Succeeded | Should -BeTrue
            $results[0].Succeeded | Should -BeTrue
            $results[1].PSObject.Properties['PolicyOutcome'] | Should -BeNullOrEmpty
            $results[1].OutcomeStatus | Should -BeExactly Unknown
        }

        It 'uses a finite generic exception type when the policy failure kind is blank' {
            Mock Invoke-HHRemoteCommandCoordinator {
                $outcome = New-HHWindowsProcessAuditResult `
                    -AuditBefore ([ordered]@{}) -AuditDesired ([ordered]@{}) `
                    -AuditAfter $null -CommandLineBefore Unknown `
                    -CommandLineDesired Unchanged -CommandLineAfter $null `
                    -Succeeded $false -Changed $false `
                    -CompensationStatus NotRequired -ConflictDetected $false `
                    -ReconciliationRequired $false -EscalationRequested $false `
                    -PrivilegeResult $null -FailureKind $null -FailureMessage unavailable
                $commandResult = [pscustomobject]@{
                    StreamEvents = @([pscustomobject]@{ Value = $outcome })
                    DispatchState = 'Completed'
                }
                $transport = [pscustomobject]@{
                    Succeeded = $true; FailureKind = $null
                    DispatchState = 'Completed'; OutcomeStatus = 'Succeeded'
                    ExceptionType = $null
                }
                & $TransportResultAugmenter $null $transport $commandResult
            }

            $result = Set-HHWindowsProcessAuditPolicy -State Enabled -Confirm:$false
            $result.ExceptionType | Should -BeExactly HostHunter.WindowsProcessAuditPolicyFailure
        }
    }
}
