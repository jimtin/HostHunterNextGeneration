$sourceRoot = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
    Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration'
}
else { $env:HH_TEST_SOURCE_ROOT }
Import-Module (Join-Path $sourceRoot 'HostHunterNextGeneration.psd1') -Force

Describe 'transport accountability validation' -Tag Unit {
    InModuleScope HostHunterNextGeneration {
        BeforeEach {
            $script:fingerprint = "SHA256:$('A' * 43)"
            $script:intent = [pscustomobject]@{
                IntentRecord = [pscustomobject]@{ payload = [pscustomobject]@{
                        operation = 'InvokeCommand'
                        requestedPowerShellRuntime = 'PowerShell7'
                        expectedHostKeyFingerprint = $script:fingerprint
                    } }
            }
            $script:result = [pscustomobject]@{
                Succeeded = $true
                FailureKind = $null
                DispatchState = 'Completed'
                OutcomeStatus = 'Succeeded'
                RemotePowerShellVersion = '7.6.5'
                RemotePSEdition = 'Core'
                ExecutionMode = 'Direct'
                HostKeyFingerprint = $script:fingerprint
                StreamEvents = [Collections.Generic.List[object]]@()
                OutputBytes = 0L
                ExceptionType = $null
                RemoteIdentity = [pscustomobject]@{
                    Marker = 'HostHunter.PowerShellIdentity.v1'
                    PSEdition = 'Core'
                    PowerShellVersion = '7.6.5'
                    ProcessPath = '/opt/microsoft/powershell/7/pwsh'
                    UserName = 'operator'
                    MachineName = 'fixture'
                }
                ValidatedAtUtc = '2026-08-24T00:00:00Z'
                SessionRemovalFailure = $false
            }
        }

        It 'reads requested runtime and trust only from the authenticated intent payload' {
            $metadata = Get-HHAuditIntentTransportContext -Intent $script:intent
            $metadata.Operation | Should -BeExactly InvokeCommand
            $metadata.RequestedPowerShellRuntime | Should -BeExactly PowerShell7
            $metadata.ExpectedHostKeyFingerprint | Should -BeExactly $script:fingerprint
            $script:intent | Add-Member RequestedPowerShellRuntime WindowsPowerShell51
            { Get-HHAuditIntentTransportContext -Intent $script:intent } |
                Should -Throw '*contradicts the persisted intent payload*'
        }

        It 'accepts a complete successful PowerShell 7 result' {
            $validated = Assert-HHTransportAuditResult -TransportResult $script:result `
                -IntentMetadata (Get-HHAuditIntentTransportContext $script:intent)
            $validated.Succeeded | Should -BeTrue
            $validated.ValidatedAtUtc | Should -Match '^2026-08-24T00:00:00'
        }

        It 'requires and retains a correlated process audit policy outcome' {
            $script:intent.IntentRecord.payload.operation = 'SetWindowsProcessAuditPolicy'
            $script:result | Add-Member PolicyOutcome ([pscustomobject][ordered]@{
                    Marker = 'HostHunter.WindowsProcessAuditPolicyResult.v1'
                    Succeeded = $true
                    FailureKind = $null
                    FailureMessage = $null
                    AuditBefore = [pscustomobject]@{ ProcessCreation = 0 }
                    AuditDesired = [pscustomobject]@{ ProcessCreation = 1 }
                    AuditAfter = [pscustomobject]@{ ProcessCreation = 1 }
                    CommandLineBefore = 'NotConfigured'
                    CommandLineDesired = 'Enabled'
                    CommandLineAfter = 'Enabled'
                    Changed = $true
                    CompensationStatus = 'NotRequired'
                    ConflictDetected = $false
                    ReconciliationRequired = $false
                    EscalationRequested = $true
                    EscalationMethod = 'WindowsTokenPrivilege'
                    RequiredPrivilege = 'SeSecurityPrivilege'
                    PrivilegeActivated = $true
                    PrivilegeChanged = $true
                    PrivilegeRestored = $true
                })
            $validated = Assert-HHTransportAuditResult -TransportResult $script:result `
                -IntentMetadata (Get-HHAuditIntentTransportContext $script:intent)
            $validated.HasPolicyOutcome | Should -BeTrue
            $validated.PolicyOutcome.CommandLineAfter | Should -BeExactly Enabled
        }

        It 'rejects a completed process audit operation without its policy outcome' {
            $script:intent.IntentRecord.payload.operation = 'SetWindowsProcessAuditPolicy'
            { Assert-HHTransportAuditResult -TransportResult $script:result `
                    -IntentMetadata (Get-HHAuditIntentTransportContext $script:intent) } |
                Should -Throw '*requires a policy outcome*'
        }

        It 'rejects contradictory or misplaced process audit policy outcomes' {
            $outcome = [pscustomobject][ordered]@{
                Marker = 'HostHunter.WindowsProcessAuditPolicyResult.v1'
                Succeeded = $false
                FailureKind = 'PolicyMutationFailed'
                FailureMessage = 'failure'
                AuditBefore = [pscustomobject]@{ ProcessCreation = 0 }
                AuditDesired = [pscustomobject]@{ ProcessCreation = 1 }
                AuditAfter = [pscustomobject]@{ ProcessCreation = 0 }
                CommandLineBefore = 'Unchanged'
                CommandLineDesired = 'Unchanged'
                CommandLineAfter = 'Unchanged'
                Changed = $false
                CompensationStatus = 'NotRequired'
                ConflictDetected = $false
                ReconciliationRequired = $false
                EscalationRequested = $false
                EscalationMethod = $null
                RequiredPrivilege = 'SeSecurityPrivilege'
                PrivilegeActivated = $false
                PrivilegeChanged = $false
                PrivilegeRestored = $null
            }
            $script:result | Add-Member PolicyOutcome $outcome
            { Assert-HHTransportAuditResult -TransportResult $script:result `
                    -IntentMetadata (Get-HHAuditIntentTransportContext $script:intent) } |
                Should -Throw '*matching operation*'
            $script:intent.IntentRecord.payload.operation = 'SetWindowsProcessAuditPolicy'
            { Assert-HHTransportAuditResult -TransportResult $script:result `
                    -IntentMetadata (Get-HHAuditIntentTransportContext $script:intent) } |
                Should -Throw '*contradicts*'
        }

        It 'validates every finite process audit policy outcome invariant' {
            $script:intent.IntentRecord.payload.operation = 'SetWindowsProcessAuditPolicy'
            $metadata = Get-HHAuditIntentTransportContext $script:intent
            (Get-HHTransportAuditPolicyOutcome -TransportResult $script:result `
                    -IntentMetadata $metadata -DispatchState NotDispatched).HasOutcome |
                Should -BeFalse
            $valid = [pscustomobject][ordered]@{
                Marker = 'HostHunter.WindowsProcessAuditPolicyResult.v1'
                Succeeded = $true; FailureKind = $null; FailureMessage = $null
                AuditBefore = [pscustomobject]@{}; AuditDesired = [pscustomobject]@{}
                AuditAfter = [pscustomobject]@{}
                CommandLineBefore = 'Disabled'; CommandLineDesired = 'Disabled'
                CommandLineAfter = 'Disabled'; Changed = $false
                CompensationStatus = 'NotRequired'; ConflictDetected = $false
                ReconciliationRequired = $false; EscalationRequested = $false
                EscalationMethod = $null; RequiredPrivilege = 'SeSecurityPrivilege'
                PrivilegeActivated = $false; PrivilegeChanged = $false
                PrivilegeRestored = $null
            }
            foreach ($mutation in @(
                    { param($o) $o.Changed = 'false' },
                    { param($o) $o.PrivilegeRestored = 'true' },
                    { param($o) $o.RequiredPrivilege = 'SeDebugPrivilege' },
                    { param($o) $o.EscalationRequested = $true; $o.EscalationMethod = 'Other' },
                    { param($o) $o.EscalationMethod = 'WindowsTokenPrivilege' },
                    { param($o) $o.ReconciliationRequired = $true }
                )) {
                $candidate = $valid.PSObject.Copy()
                & $mutation $candidate
                $transport = $script:result.PSObject.Copy()
                $transport | Add-Member PolicyOutcome $candidate
                { Get-HHTransportAuditPolicyOutcome -TransportResult $transport `
                        -IntentMetadata $metadata -DispatchState Completed } |
                    Should -Throw
            }
            $valid.EscalationRequested = $true
            $valid.EscalationMethod = 'WindowsTokenPrivilege'
            $transport = $script:result.PSObject.Copy()
            $transport | Add-Member PolicyOutcome $valid
            (Get-HHTransportAuditPolicyOutcome -TransportResult $transport `
                    -IntentMetadata $metadata -DispatchState Completed).HasOutcome |
                Should -BeTrue
        }

        It 'accepts a complete successful Windows PowerShell 5.1 result' {
            $script:intent.IntentRecord.payload.requestedPowerShellRuntime = 'WindowsPowerShell51'
            $script:result.RemotePowerShellVersion = '5.1.26100.9168'
            $script:result.RemotePSEdition = 'Desktop'
            $script:result.ExecutionMode = 'WindowsPowerShellCompatibility'
            $script:result.RemoteIdentity.PSEdition = 'Desktop'
            $script:result.RemoteIdentity.PowerShellVersion = '5.1.26100.9168'
            $script:result.RemoteIdentity.ProcessPath = `
                'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
            {
                Assert-HHTransportAuditResult -TransportResult $script:result `
                    -IntentMetadata (Get-HHAuditIntentTransportContext $script:intent)
            } | Should -Not -Throw
        }

        It 'requires every result field and finite stream collection' {
            $script:result.PSObject.Properties.Remove('DispatchState')
            { Assert-HHTransportAuditResult -TransportResult $script:result `
                    -IntentMetadata (Get-HHAuditIntentTransportContext $script:intent) } |
                Should -Throw "*DispatchState*"
        }

        It 'rejects success with a failure kind or cleanup failure' {
            $script:result.FailureKind = 'TransportFailure'
            { Assert-HHTransportAuditResult -TransportResult $script:result `
                    -IntentMetadata (Get-HHAuditIntentTransportContext $script:intent) } |
                Should -Throw '*cannot contain FailureKind*'
            $script:result.FailureKind = $null
            $script:result.SessionRemovalFailure = $true
            { Assert-HHTransportAuditResult -TransportResult $script:result `
                    -IntentMetadata (Get-HHAuditIntentTransportContext $script:intent) } |
                Should -Throw '*cleanup failure cannot be successful*'
        }

        It 'accepts an evidence-free pre-dispatch authentication failure' {
            $script:result.Succeeded = $false
            $script:result.FailureKind = 'AuthenticationFailure'
            $script:result.DispatchState = 'NotDispatched'
            $script:result.OutcomeStatus = 'Failed'
            $script:result.ExceptionType = 'System.Exception'
            foreach ($name in @(
                    'RemotePowerShellVersion', 'RemotePSEdition', 'ExecutionMode',
                    'HostKeyFingerprint', 'RemoteIdentity', 'ValidatedAtUtc'
                )) { $script:result.$name = $null }
            {
                Assert-HHTransportAuditResult -TransportResult $script:result `
                    -IntentMetadata (Get-HHAuditIntentTransportContext $script:intent)
            } | Should -Not -Throw
        }

        It 'rejects partial identity and expected-fingerprint substitution before identity' {
            $script:result.Succeeded = $false
            $script:result.FailureKind = 'TransportFailure'
            $script:result.DispatchState = 'NotDispatched'
            $script:result.OutcomeStatus = 'Failed'
            $script:result.ExceptionType = 'System.Exception'
            $script:result.RemoteIdentity = $null
            { Assert-HHTransportAuditResult -TransportResult $script:result `
                    -IntentMetadata (Get-HHAuditIntentTransportContext $script:intent) } |
                Should -Throw '*entirely present or entirely null*'
            foreach ($name in @(
                    'RemotePowerShellVersion', 'RemotePSEdition', 'ExecutionMode',
                    'RemoteIdentity', 'ValidatedAtUtc'
                )) { $script:result.$name = $null }
            { Assert-HHTransportAuditResult -TransportResult $script:result `
                    -IntentMetadata (Get-HHAuditIntentTransportContext $script:intent) } |
                Should -Throw '*fingerprint must be null*'
        }

        It 'requires attributable evidence for RuntimeMismatch' {
            $script:result.Succeeded = $false
            $script:result.FailureKind = 'RuntimeMismatch'
            $script:result.DispatchState = 'NotDispatched'
            $script:result.OutcomeStatus = 'Failed'
            $script:result.ExceptionType = 'System.Exception'
            foreach ($name in @(
                    'RemotePowerShellVersion', 'RemotePSEdition', 'ExecutionMode',
                    'HostKeyFingerprint', 'RemoteIdentity', 'ValidatedAtUtc'
                )) { $script:result.$name = $null }
            { Assert-HHTransportAuditResult -TransportResult $script:result `
                    -IntentMetadata (Get-HHAuditIntentTransportContext $script:intent) } |
                Should -Throw '*RuntimeMismatch requires complete observed runtime evidence*'
        }

        It 'accepts a proven unsupported requested-runtime identity as RuntimeMismatch' {
            $script:result.Succeeded = $false
            $script:result.FailureKind = 'RuntimeMismatch'
            $script:result.DispatchState = 'NotDispatched'
            $script:result.OutcomeStatus = 'Failed'
            $script:result.ExceptionType = 'System.Exception'
            $script:result.RemotePowerShellVersion = '6.2.0'
            $script:result.RemoteIdentity.PowerShellVersion = '6.2.0'
            {
                Assert-HHTransportAuditResult -TransportResult $script:result `
                    -IntentMetadata (Get-HHAuditIntentTransportContext $script:intent)
            } | Should -Not -Throw
        }

        It 'rejects contradictory runtime mapping and host identity' {
            $script:result.RemotePSEdition = 'Desktop'
            { Assert-HHTransportAuditResult -TransportResult $script:result `
                    -IntentMetadata (Get-HHAuditIntentTransportContext $script:intent) } |
                Should -Throw '*supported runtime mapping*'
            $script:result.RemotePSEdition = 'Core'
            $script:result.HostKeyFingerprint = "SHA256:$('B' * 43)"
            { Assert-HHTransportAuditResult -TransportResult $script:result `
                    -IntentMetadata (Get-HHAuditIntentTransportContext $script:intent) } |
                Should -Throw '*contradicts the intent*'
        }

        It 'requires bootstrap success to include a committed reconciled transition' {
            $script:intent.IntentRecord.payload.operation = 'EnableSshKeyAuthentication'
            $script:result | Add-Member -NotePropertyMembers ([ordered]@{
                    Installed = $true
                    RollbackAttempted = $false
                    RollbackSucceeded = $null
                    ReconciliationRequired = $false
                    CommitState = 'Committed'
                })
            { Assert-HHTransportAuditResult -TransportResult $script:result `
                    -IntentMetadata (Get-HHAuditIntentTransportContext $script:intent) } |
                Should -Not -Throw
            $script:result.CommitState = 'Unknown'
            { Assert-HHTransportAuditResult -TransportResult $script:result `
                    -IntentMetadata (Get-HHAuditIntentTransportContext $script:intent) } |
                Should -Throw '*Unknown bootstrap commit state*'
        }

        It 'accepts only a proven compensated completed bootstrap mismatch' {
            $script:intent.IntentRecord.payload.operation = 'EnableSshKeyAuthentication'
            $script:result.Succeeded = $false
            $script:result.FailureKind = 'RuntimeMismatch'
            $script:result.DispatchState = 'Completed'
            $script:result.OutcomeStatus = 'Failed'
            $script:result.ExceptionType = 'System.Exception'
            $script:result.RemotePowerShellVersion = '6.2.0'
            $script:result.RemoteIdentity.PowerShellVersion = '6.2.0'
            $script:result | Add-Member -NotePropertyMembers ([ordered]@{
                    Installed = $true
                    RollbackAttempted = $true
                    RollbackSucceeded = $true
                    ReconciliationRequired = $false
                    CommitState = 'NotRequested'
                })
            { Assert-HHTransportAuditResult -TransportResult $script:result `
                    -IntentMetadata (Get-HHAuditIntentTransportContext $script:intent) } |
                Should -Not -Throw
            $script:result.RollbackSucceeded = $false
            { Assert-HHTransportAuditResult -TransportResult $script:result `
                    -IntentMetadata (Get-HHAuditIntentTransportContext $script:intent) } |
                Should -Throw '*compensated or non-mutating*'
        }

        It 'reads exact properties from dictionaries and objects and rejects absent required state' {
            $dictionary = [ordered]@{ Exact = 42 }
            (Get-HHAuditObjectPropertyState -InputObject $dictionary -Name Exact `
                    -Context dictionary).Value | Should -Be 42
            (Get-HHAuditObjectPropertyState -InputObject ([pscustomobject]@{ Exact = 43 }) `
                    -Name Exact -Context object).Value | Should -Be 43
            (Get-HHAuditObjectPropertyState -InputObject $dictionary -Name Optional `
                    -Context dictionary -Optional).Exists | Should -BeFalse
            { Get-HHAuditObjectPropertyState -InputObject $null -Name Exact -Context sample } |
                Should -Throw '*sample cannot be null*'
            { Get-HHAuditObjectPropertyState -InputObject $dictionary -Name exact `
                    -Context dictionary } | Should -Throw "*property 'exact' is required*"
        }

        It 'canonicalizes exact remote operation manifests and rejects bounded shape violations' {
            $entry = [ordered]@{
                Phase = 'Command'
                PowerShellRuntime = 'PowerShell7'
                ScriptText = 'Get-Date'
                SerializedArguments = '[]'
                Conditional = $false
            }
            $canonical = ConvertTo-HHCanonicalRemoteOperationManifest -RemoteOperations @($entry)
            $canonical.Count | Should -Be 1
            $canonical[0].Phase | Should -BeExactly Command

            { ConvertTo-HHCanonicalRemoteOperationManifest -RemoteOperations @() } |
                Should -Throw '*At least one exact remote operation*'
            { ConvertTo-HHCanonicalRemoteOperationManifest -RemoteOperations @(0..64 | ForEach-Object {
                        [ordered]@{
                            Phase = 'Command'; PowerShellRuntime = 'PowerShell7'
                            ScriptText = 'Get-Date'; SerializedArguments = '[]'; Conditional = $false
                        }
                    }) } | Should -Throw '*more than 64*'
            foreach ($mutation in @(
                    { param($item) $item.Remove('Phase') },
                    { param($item) $item.Extra = 'unexpected' }
                )) {
                $invalid = [ordered]@{} + $entry
                & $mutation $invalid
                { ConvertTo-HHCanonicalRemoteOperationManifest -RemoteOperations @($invalid) } |
                    Should -Throw '*must contain exactly*'
            }
        }

        It 'rejects every invalid remote operation field class' {
            $cases = @(
                @{ Name = 'Phase'; Value = 'Unknown'; Expected = '*Phase is unsupported*' },
                @{ Name = 'PowerShellRuntime'; Value = 'PowerShell6'; Expected = '*PowerShellRuntime is unsupported*' },
                @{ Name = 'ScriptText'; Value = ' '; Expected = '*ScriptText must be a nonempty string*' },
                @{ Name = 'SerializedArguments'; Value = $null; Expected = '*SerializedArguments must be a nonempty string*' },
                @{ Name = 'Conditional'; Value = 'false'; Expected = '*Conditional must be Boolean*' }
            )
            foreach ($case in $cases) {
                $entry = [ordered]@{
                    Phase = 'Command'; PowerShellRuntime = 'PowerShell7'
                    ScriptText = 'Get-Date'; SerializedArguments = '[]'; Conditional = $false
                }
                $entry[$case.Name] = $case.Value
                { ConvertTo-HHCanonicalRemoteOperationManifest -RemoteOperations @($entry) } |
                    Should -Throw $case.Expected
            }
        }

        It 'rejects invalid persisted intent runtime trust and operation metadata' {
            $script:intent.IntentRecord.payload.requestedPowerShellRuntime = 'PowerShell6'
            { Get-HHAuditIntentTransportContext -Intent $script:intent } |
                Should -Throw '*requested PowerShell runtime is invalid*'
            $script:intent.IntentRecord.payload.requestedPowerShellRuntime = 'PowerShell7'
            $script:intent.IntentRecord.payload.expectedHostKeyFingerprint = 'SHA256:short'
            { Get-HHAuditIntentTransportContext -Intent $script:intent } |
                Should -Throw '*expected SSH host fingerprint is invalid*'
            $script:intent.IntentRecord.payload.expectedHostKeyFingerprint = $script:fingerprint
            $script:intent.IntentRecord.payload.operation = ' '
            { Get-HHAuditIntentTransportContext -Intent $script:intent } |
                Should -Throw '*operation is invalid*'
        }

        It 'rejects partial and contradictory bootstrap outcome state' {
            $script:intent.IntentRecord.payload.operation = 'EnableSshKeyAuthentication'
            $script:result | Add-Member Installed $true
            { Assert-HHTransportAuditResult -TransportResult $script:result `
                    -IntentMetadata (Get-HHAuditIntentTransportContext $script:intent) } |
                Should -Throw '*requires all properties*'

            $script:result.PSObject.Properties.Remove('Installed')
            $script:result | Add-Member -NotePropertyMembers ([ordered]@{
                    Installed = $null
                    RollbackAttempted = $false
                    RollbackSucceeded = $null
                    ReconciliationRequired = $false
                    CommitState = 'NotRequested'
                })
            $invalidCases = @(
                @{ Name = 'Installed'; Value = 'yes'; Expected = "*'Installed' must be Boolean or null*" },
                @{ Name = 'RollbackAttempted'; Value = 'no'; Expected = "*'RollbackAttempted' must be Boolean*" },
                @{ Name = 'RollbackSucceeded'; Value = 'yes'; Expected = "*'RollbackSucceeded' must be Boolean or null*" },
                @{ Name = 'ReconciliationRequired'; Value = 'no'; Expected = "*'ReconciliationRequired' must be Boolean*" },
                @{ Name = 'CommitState'; Value = 'Pending'; Expected = "*'CommitState' is unsupported*" }
            )
            foreach ($case in $invalidCases) {
                $original = $script:result.($case.Name)
                $script:result.($case.Name) = $case.Value
                { Assert-HHTransportAuditResult -TransportResult $script:result `
                        -IntentMetadata (Get-HHAuditIntentTransportContext $script:intent) } |
                    Should -Throw $case.Expected
                $script:result.($case.Name) = $original
            }
            $script:result.RollbackSucceeded = $true
            { Assert-HHTransportAuditResult -TransportResult $script:result `
                    -IntentMetadata (Get-HHAuditIntentTransportContext $script:intent) } |
                Should -Throw '*without a rollback attempt*'
            $script:result.RollbackSucceeded = $null
            $script:result.CommitState = 'Unknown'
            { Assert-HHTransportAuditResult -TransportResult $script:result `
                    -IntentMetadata (Get-HHAuditIntentTransportContext $script:intent) } |
                Should -Throw '*requires reconciliation*'
        }

        It 'rejects invalid result status, failure, stream, byte and exception metadata' {
            $cases = @(
                @{ Name = 'Succeeded'; Value = 'true'; Expected = "*'Succeeded' must be Boolean*" },
                @{ Name = 'DispatchState'; Value = 'Queued'; Expected = '*unsupported dispatch state*' },
                @{ Name = 'OutcomeStatus'; Value = 'Pending'; Expected = '*unsupported outcome status*' },
                @{ Name = 'StreamEvents'; Value = 'not-a-list'; Expected = "*'StreamEvents' must be a finite list*" },
                @{ Name = 'OutputBytes'; Value = 1.5; Expected = "*'OutputBytes' must be an integer*" }
            )
            foreach ($case in $cases) {
                $original = $script:result.($case.Name)
                $script:result.($case.Name) = $case.Value
                { Assert-HHTransportAuditResult -TransportResult $script:result `
                        -IntentMetadata (Get-HHAuditIntentTransportContext $script:intent) } |
                    Should -Throw $case.Expected
                $script:result.($case.Name) = $original
            }
            $script:result.StreamEvents = [Collections.Generic.List[object]]@($null)
            { Assert-HHTransportAuditResult -TransportResult $script:result `
                    -IntentMetadata (Get-HHAuditIntentTransportContext $script:intent) } |
                Should -Throw '*cannot contain null entries*'
            $script:result.StreamEvents = [Collections.Generic.List[object]]@()
            $script:result.OutputBytes = -1L
            { Assert-HHTransportAuditResult -TransportResult $script:result `
                    -IntentMetadata (Get-HHAuditIntentTransportContext $script:intent) } |
                Should -Throw '*cannot be negative*'
            $script:result.OutputBytes = 0L
            $script:result.Succeeded = $false
            $script:result.FailureKind = 'TransportFailure'
            $script:result.OutcomeStatus = 'Failed'
            $script:result.ExceptionType = ' '
            { Assert-HHTransportAuditResult -TransportResult $script:result `
                    -IntentMetadata (Get-HHAuditIntentTransportContext $script:intent) } |
                Should -Throw '*requires a nonempty ExceptionType*'
        }

        It 'enforces finite failure dispatch and aggregate outcome combinations' {
            $cases = @(
                @{ Failure = 'Unsupported'; Dispatch = 'NotDispatched'; Outcome = 'Failed'; Expected = '*supported nonempty FailureKind*' },
                @{ Failure = 'TransportFailure'; Dispatch = 'NotDispatched'; Outcome = 'Succeeded'; Expected = '*cannot have a Succeeded outcome*' },
                @{ Failure = 'Timeout'; Dispatch = 'NotDispatched'; Outcome = 'Unknown'; Expected = '*dispatch and outcome metadata is inconsistent*' },
                @{ Failure = 'RemoteCommandFailure'; Dispatch = 'Completed'; Outcome = 'Unknown'; Expected = '*Only timeout or transport failures*' },
                @{ Failure = 'Timeout'; Dispatch = 'Completed'; Outcome = 'Unknown'; Expected = '*Only a transport failure can have*' },
                @{ Failure = 'AuthenticationFailure'; Dispatch = 'Dispatched'; Outcome = 'Failed'; Expected = '*must fail before dispatch*' },
                @{ Failure = 'RuntimeMismatch'; Dispatch = 'Dispatched'; Outcome = 'Failed'; Expected = '*must fail before dispatch*' },
                @{ Failure = 'RemoteCommandFailure'; Dispatch = 'Dispatched'; Outcome = 'Failed'; Expected = '*requires a completed failed outcome*' },
                @{ Failure = 'OutputLimitExceeded'; Dispatch = 'Completed'; Outcome = 'Failed'; Expected = '*metadata is inconsistent*' }
            )
            foreach ($case in $cases) {
                $script:result.Succeeded = $false
                $script:result.FailureKind = $case.Failure
                $script:result.DispatchState = $case.Dispatch
                $script:result.OutcomeStatus = $case.Outcome
                $script:result.ExceptionType = 'System.Exception'
                { Assert-HHTransportAuditResult -TransportResult $script:result `
                        -IntentMetadata (Get-HHAuditIntentTransportContext $script:intent) } |
                    Should -Throw $case.Expected
            }
        }

        It 'rejects malformed observed runtime evidence and remote identity' {
            $script:result.RemotePowerShellVersion = 'not-a-version'
            { Assert-HHTransportAuditResult -TransportResult $script:result `
                    -IntentMetadata (Get-HHAuditIntentTransportContext $script:intent) } |
                Should -Throw '*RemotePowerShellVersion is invalid*'
            $script:result.RemotePowerShellVersion = '7.6.5'
            $script:result.ValidatedAtUtc = 'not-a-time'
            { Assert-HHTransportAuditResult -TransportResult $script:result `
                    -IntentMetadata (Get-HHAuditIntentTransportContext $script:intent) } |
                Should -Throw "*'ValidatedAtUtc' is invalid*"
            $script:result.ValidatedAtUtc = '2026-08-24T00:00:00Z'
            $script:result.RemoteIdentity.ProcessPath = '/usr/bin/powershell'
            { Assert-HHTransportAuditResult -TransportResult $script:result `
                    -IntentMetadata (Get-HHAuditIntentTransportContext $script:intent) } |
                Should -Throw '*process contradicts*'
            $script:result.RemoteIdentity.ProcessPath = '/usr/bin/pwsh'
            $script:result.RemoteIdentity.Marker = 'wrong'
            { Assert-HHTransportAuditResult -TransportResult $script:result `
                    -IntentMetadata (Get-HHAuditIntentTransportContext $script:intent) } |
                Should -Throw '*RemoteIdentity contradicts*'
            $script:result.RemoteIdentity.Marker = 'HostHunter.PowerShellIdentity.v1'
            $script:result.RemoteIdentity.UserName = ' '
            { Assert-HHTransportAuditResult -TransportResult $script:result `
                    -IntentMetadata (Get-HHAuditIntentTransportContext $script:intent) } |
                Should -Throw "*'UserName' must be a nonempty string*"
        }

        It 'covers successful, cleanup, and bootstrap aggregate contradictions' {
            $script:result.OutcomeStatus = 'Failed'
            { Assert-HHTransportAuditResult -TransportResult $script:result `
                    -IntentMetadata (Get-HHAuditIntentTransportContext $script:intent) } |
                Should -Throw '*Successful transport result dispatch and outcome metadata is inconsistent*'
            $script:result.OutcomeStatus = 'Succeeded'
            $script:result.ExceptionType = 'System.Exception'
            { Assert-HHTransportAuditResult -TransportResult $script:result `
                    -IntentMetadata (Get-HHAuditIntentTransportContext $script:intent) } |
                Should -Throw '*successful transport result cannot contain ExceptionType*'
            $script:result.ExceptionType = $null
            $script:result.SessionRemovalFailure = 'yes'
            { Assert-HHTransportAuditResult -TransportResult $script:result `
                    -IntentMetadata (Get-HHAuditIntentTransportContext $script:intent) } |
                Should -Throw '*SessionRemovalFailure*Boolean*'

            $script:result.SessionRemovalFailure = $false
            $script:intent.IntentRecord.payload.operation = 'EnableSshKeyAuthentication'
            $script:result | Add-Member -NotePropertyMembers ([ordered]@{
                    Installed = $true
                    RollbackAttempted = $false
                    RollbackSucceeded = $null
                    ReconciliationRequired = $true
                    CommitState = 'Committed'
                })
            { Assert-HHTransportAuditResult -TransportResult $script:result `
                    -IntentMetadata (Get-HHAuditIntentTransportContext $script:intent) } |
                Should -Throw '*committed, reconciled*'
            $script:result.Succeeded = $false
            $script:result.FailureKind = 'TransportFailure'
            $script:result.DispatchState = 'Dispatched'
            $script:result.OutcomeStatus = 'Failed'
            $script:result.ExceptionType = 'System.Exception'
            $script:result.CommitState = 'Unknown'
            { Assert-HHTransportAuditResult -TransportResult $script:result `
                    -IntentMetadata (Get-HHAuditIntentTransportContext $script:intent) } |
                Should -Throw '*Unknown bootstrap commit state requires an Unknown aggregate outcome*'
        }

        It 'accepts finite valid failure dispatch combinations' {
            $script:result.Succeeded = $false
            $script:result.ExceptionType = 'System.Exception'
            foreach ($case in @(
                    @{ Failure = 'RemoteCommandFailure'; Dispatch = 'Completed' },
                    @{ Failure = 'OutputLimitExceeded'; Dispatch = 'Dispatched' }
                )) {
                $script:result.FailureKind = $case.Failure
                $script:result.DispatchState = $case.Dispatch
                $script:result.OutcomeStatus = 'Failed'
                { Assert-HHTransportAuditResult -TransportResult $script:result `
                        -IntentMetadata (Get-HHAuditIntentTransportContext $script:intent) } |
                    Should -Not -Throw
            }
        }

        It 'rejects blank runtime fields and absent identity after dispatch or cleanup failure' {
            $script:result.RemotePowerShellVersion = ' '
            { Assert-HHTransportAuditResult -TransportResult $script:result `
                    -IntentMetadata (Get-HHAuditIntentTransportContext $script:intent) } |
                Should -Throw '*runtime string metadata*'
            $script:result.RemotePowerShellVersion = '7.6.5'
            $script:result.ValidatedAtUtc = ' '
            { Assert-HHTransportAuditResult -TransportResult $script:result `
                    -IntentMetadata (Get-HHAuditIntentTransportContext $script:intent) } |
                Should -Throw '*ValidatedAtUtc*blank*'

            foreach ($name in @(
                    'RemotePowerShellVersion', 'RemotePSEdition', 'ExecutionMode',
                    'RemoteIdentity', 'ValidatedAtUtc'
                )) { $script:result.$name = $null }
            $script:result.HostKeyFingerprint = $null
            $script:result.Succeeded = $false
            $script:result.FailureKind = 'TransportFailure'
            $script:result.OutcomeStatus = 'Unknown'
            $script:result.DispatchState = 'Dispatched'
            $script:result.ExceptionType = 'System.Exception'
            { Assert-HHTransportAuditResult -TransportResult $script:result `
                    -IntentMetadata (Get-HHAuditIntentTransportContext $script:intent) } |
                Should -Throw '*requires complete observed runtime metadata*'
        }

        It 'rejects attributable runtime mismatch and request contradictions' {
            $script:result.Succeeded = $false
            $script:result.FailureKind = 'RuntimeMismatch'
            $script:result.DispatchState = 'NotDispatched'
            $script:result.OutcomeStatus = 'Failed'
            $script:result.ExceptionType = 'System.Exception'
            $script:result.RemotePSEdition = 'Preview'
            $script:result.RemoteIdentity.PSEdition = 'Preview'
            { Assert-HHTransportAuditResult -TransportResult $script:result `
                    -IntentMetadata (Get-HHAuditIntentTransportContext $script:intent) } |
                Should -Throw '*not finite or attributable*'

            $script:result.RemotePSEdition = 'Core'
            $script:result.RemoteIdentity.PSEdition = 'Core'
            { Assert-HHTransportAuditResult -TransportResult $script:result `
                    -IntentMetadata (Get-HHAuditIntentTransportContext $script:intent) } |
                Should -Throw '*cannot report an identity satisfying the requested runtime*'

            $script:result.Succeeded = $true
            $script:result.FailureKind = $null
            $script:result.OutcomeStatus = 'Succeeded'
            $script:result.ExceptionType = $null
            $script:intent.IntentRecord.payload.requestedPowerShellRuntime = 'WindowsPowerShell51'
            { Assert-HHTransportAuditResult -TransportResult $script:result `
                    -IntentMetadata (Get-HHAuditIntentTransportContext $script:intent) } |
                Should -Throw '*contradicts the requested runtime*'
        }

        It 'rejects unsupported remote identity editions and returns absent optional cleanup' {
            $script:result.RemoteIdentity.PSEdition = 'Preview'
            { Assert-HHAuditRemoteIdentity -Identity $script:result.RemoteIdentity `
                    -RemotePSEdition Preview -PowerShellVersion '7.6.5' } |
                Should -Throw '*unsupported PowerShell edition*'
            $script:result.RemoteIdentity.PSEdition = 'Core'
            $script:result.PSObject.Properties.Remove('SessionRemovalFailure')
            $validated = Assert-HHTransportAuditResult -TransportResult $script:result `
                -IntentMetadata (Get-HHAuditIntentTransportContext $script:intent)
            $validated.SessionRemovalFailure | Should -BeNullOrEmpty
            $validated.HasSessionRemovalFailure | Should -BeFalse
        }
    }
}
