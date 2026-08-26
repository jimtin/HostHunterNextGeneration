BeforeAll {
    $sourceRoot = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
        Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration'
    }
    else { $env:HH_TEST_SOURCE_ROOT }
    $script:auditPath = Join-Path $sourceRoot 'Private/WindowsProcessAuditPolicy.ps1'
    . (Join-Path $sourceRoot 'Private/PrivilegeEscalation.ps1')
    . $script:auditPath
}

Describe 'Windows process audit policy desired state' -Tag Unit {
    It 'uses the documented process audit subcategories and no command-line tools' {
        $source = Get-Content -LiteralPath $script:auditPath -Raw
        $source | Should -Match '0CCE922B-69AE-11D9-BED3-505054503030'
        $source | Should -Match '0CCE922C-69AE-11D9-BED3-505054503030'
        $source | Should -Match 'AuditQuerySystemPolicy'
        $source | Should -Match 'AuditSetSystemPolicy'
        @([regex]::Matches(
                $source,
                '\[return:\s*MarshalAs\(UnmanagedType\.U1\)\]\s*' +
                'private static extern bool Audit(?:Query|Set)SystemPolicy'
            )).Count | Should -Be 2
        $source | Should -Not -Match '(?i)\bauditpol(?:\.exe)?\b'
        $source | Should -Not -Match '(?i)\breg\.exe\b|\bgpupdate(?:\.exe)?\b'
    }

    It 'compiles the PowerShell 5.1-compatible audit native type' {
        { Initialize-HHWindowsAuditNativeType } | Should -Not -Throw
        { Initialize-HHWindowsAuditNativeType } | Should -Not -Throw
        ('HostHunter.Native.WindowsAuditPolicy' -as [type]) | Should -Not -BeNullOrEmpty
    }

    It 'refuses every native audit and registry boundary away from Windows' -Skip:(
        [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
    ) {
        { Get-HHWindowsProcessAuditFlagMap -Subcategory ProcessCreation } |
            Should -Throw '*require*Windows*'
        { Set-HHWindowsProcessAuditFlagMap -Flags ([ordered]@{ ProcessCreation = 1 }) } |
            Should -Throw '*require*Windows*'
        { Get-HHWindowsCommandLineAuditState } | Should -Throw '*require*Windows*'
        { Get-HHWindowsCommandLineAuditSnapshot } | Should -Throw '*require*Windows*'
        { Test-HHWindowsCommandLineAuditWriteAccess } | Should -Throw '*require*Windows*'
        { Set-HHWindowsCommandLineAuditState -State Disabled } |
            Should -Throw '*require*Windows*'
        {
            Restore-HHWindowsCommandLineAuditSnapshot -Snapshot ([pscustomobject]@{
                    Exists = $false
                })
        } | Should -Throw '*require*Windows*'
    }

    It 'preserves failure auditing while changing successful auditing' -TestCases @(
        @{ Current = 0; State = 'Enabled'; Expected = 1 }
        @{ Current = 2; State = 'Enabled'; Expected = 3 }
        @{ Current = 3; State = 'Disabled'; Expected = 2 }
        @{ Current = 1; State = 'Disabled'; Expected = 4 }
        @{ Current = 4; State = 'Enabled'; Expected = 1 }
    ) {
        param($Current, $State, $Expected)
        ConvertTo-HHDesiredAuditFlag -Current $Current -State $State |
            Should -Be $Expected
    }

    It 'compares complete audit flag maps' {
        Test-HHAuditFlagMapsEqual -Left ([ordered]@{}) -Right ([ordered]@{}) |
            Should -BeTrue
        Test-HHAuditFlagMapsEqual -Left ([ordered]@{ A = 1; B = 2 }) `
            -Right ([ordered]@{ A = 1; B = 2 }) | Should -BeTrue
        Test-HHAuditFlagMapsEqual -Left ([ordered]@{ A = 1 }) `
            -Right ([ordered]@{ A = 1; B = 2 }) | Should -BeFalse
        Test-HHAuditFlagMapsEqual -Left ([ordered]@{ A = 1 }) `
            -Right ([ordered]@{ A = 2 }) | Should -BeFalse
        Test-HHAuditFlagMapsEqual -Left ([ordered]@{ A = 1 }) `
            -Right ([ordered]@{ B = 1 }) | Should -BeFalse
        Test-HHAuditFlagMapsEqual -Left ([ordered]@{ A = 0 }) `
            -Right ([ordered]@{ A = 4 }) | Should -BeTrue
    }

    It 'normalizes finite command-line projections and rejects malformed input' {
        ConvertTo-HHCommandLineAuditState -Value 'Enabled' |
            Should -BeExactly 'Enabled'
        ConvertTo-HHCommandLineAuditState -Value ([pscustomobject]@{ State = 'Disabled' }) |
            Should -BeExactly 'Disabled'
        { ConvertTo-HHCommandLineAuditState -Value ([pscustomobject]@{ Value = 1 }) } |
            Should -Throw '*projection is invalid*'
    }

    It 'validates command-line enablement against process creation auditing' {
        {
            New-HHWindowsProcessAuditPolicyRequest `
                -Subcategory ProcessTermination -State Enabled `
                -CommandLineLogging Enabled
        } | Should -Throw '*only with enabled ProcessCreation*'
        {
            Invoke-HHWindowsProcessAuditPolicyChange `
                -Subcategory ProcessTermination -State Enabled `
                -CommandLineLogging Enabled
        } | Should -Throw '*only with enabled ProcessCreation*'
        {
            New-HHWindowsProcessAuditPolicyRequest `
                -Subcategory ProcessCreation -State Disabled `
                -CommandLineLogging Enabled
        } | Should -Throw '*only with enabled ProcessCreation*'
    }

    It 'creates a stable, deduplicated request contract' {
        $request = New-HHWindowsProcessAuditPolicyRequest `
            -Subcategory ProcessCreation, ProcessCreation, ProcessTermination `
            -State Enabled -CommandLineLogging Disabled -EscalationRequested $true `
            -EscalationMethod WindowsTokenPrivilege

        $request.Marker | Should -BeExactly 'HostHunter.WindowsProcessAuditPolicyRequest.v1'
        $request.Subcategory | Should -Be @('ProcessCreation', 'ProcessTermination')
        $request.EscalationMethod | Should -BeExactly 'WindowsTokenPrivilege'
        $request.Escalate | Should -BeTrue
    }

    It 'requires the finite escalation method to match the escalation request' {
        {
            New-HHWindowsProcessAuditPolicyRequest -Subcategory ProcessCreation `
                -State Enabled -EscalationRequested $true -EscalationMethod CurrentToken
        } | Should -Throw '*must match*'
        {
            Invoke-HHWindowsProcessAuditPolicyChange -Subcategory ProcessCreation `
                -State Enabled -Escalate -EscalationMethod CurrentToken
        } | Should -Throw '*must match*'
    }

    It 'returns an idempotent verified outcome without a write preflight' {
        $script:preflightCalls = 0
        $result = Invoke-HHWindowsProcessAuditPolicyChange `
            -Subcategory ProcessCreation -State Enabled `
            -AuditQuery { [ordered]@{ ProcessCreation = 1 } } `
            -AuditSet { throw 'unexpected audit write' } `
            -CommandLineQuery { 'Disabled' } `
            -CommandLineSet { throw 'unexpected registry write' } `
            -RegistryPreflight { $script:preflightCalls++ }

        $result.Succeeded | Should -BeTrue
        $result.Changed | Should -BeFalse
        $result.CompensationStatus | Should -BeExactly 'NotRequired'
        $result.AuditAfter.ProcessCreation | Should -Be 1
        $script:preflightCalls | Should -Be 0
    }

    It 'returns a finite failure when registry preflight fails before any mutation' {
        $script:writes = 0
        $result = Invoke-HHWindowsProcessAuditPolicyChange `
            -Subcategory ProcessCreation -State Enabled -CommandLineLogging Enabled `
            -AuditQuery { [ordered]@{ ProcessCreation = 4 } } `
            -AuditSet { $script:writes++ } `
            -CommandLineQuery { 'Disabled' } `
            -CommandLineSet { $script:writes++ } `
            -RegistryPreflight { throw 'registry write denied' }

        $result.Succeeded | Should -BeFalse
        $result.Changed | Should -BeFalse
        $result.CompensationStatus | Should -BeExactly NotRequired
        $result.FailureKind | Should -BeExactly PolicyMutationFailed
        $script:writes | Should -Be 0
    }

    It 'supports independently changing only command-line policy' {
        $script:commandState = 'Enabled'
        $result = Invoke-HHWindowsProcessAuditPolicyChange `
            -Subcategory ProcessCreation -State Enabled -CommandLineLogging Disabled `
            -AuditQuery { [ordered]@{ ProcessCreation = 1 } } `
            -AuditSet { throw 'audit must remain unchanged' } `
            -CommandLineQuery { $script:commandState } `
            -CommandLineSet { param($Value) $script:commandState = $Value } `
            -RegistryPreflight { $true }

        $result.Succeeded | Should -BeTrue
        $result.Changed | Should -BeTrue
        $result.CommandLineAfter | Should -BeExactly Disabled
        $result.AuditAfter.ProcessCreation | Should -Be 1
    }

    It 'supports independently changing only the audit subcategory' {
        $script:auditState = [uint32]4
        $result = Invoke-HHWindowsProcessAuditPolicyChange `
            -Subcategory ProcessCreation -State Enabled -CommandLineLogging Unchanged `
            -AuditQuery { [ordered]@{ ProcessCreation = $script:auditState } } `
            -AuditSet { param($Flags) $script:auditState = [uint32]$Flags.ProcessCreation } `
            -CommandLineQuery { 'Disabled' } `
            -CommandLineSet { throw 'command line must remain unchanged' }

        $result.Succeeded | Should -BeTrue
        $result.Changed | Should -BeTrue
        $result.AuditAfter.ProcessCreation | Should -Be 1
        $result.CommandLineAfter | Should -BeExactly Disabled
    }

    It 'accepts the native zero projection after setting AUDIT_NONE' {
        $script:auditState = [uint32]1
        $result = Invoke-HHWindowsProcessAuditPolicyChange `
            -Subcategory ProcessCreation -State Disabled -CommandLineLogging Unchanged `
            -AuditQuery { [ordered]@{ ProcessCreation = $script:auditState } } `
            -AuditSet { param($Flags) $null = $Flags; $script:auditState = [uint32]0 } `
            -CommandLineQuery { 'Enabled' } `
            -CommandLineSet { throw 'command line must remain unchanged' }

        $result.Succeeded | Should -BeTrue
        $result.Changed | Should -BeTrue
        $result.AuditDesired.ProcessCreation | Should -Be 4
        $result.AuditAfter.ProcessCreation | Should -Be 0
        $result.CommandLineAfter | Should -BeExactly Enabled
    }

    It 'detects command-line verification drift and restores the exact snapshot' {
        $snapshot = [pscustomobject]@{ State = 'Enabled'; Exists = $true; Value = 1; Kind = 'DWord' }
        $script:commandReads = 0
        $script:restored = $false
        $result = Invoke-HHWindowsProcessAuditPolicyChange `
            -Subcategory ProcessCreation -State Enabled -CommandLineLogging Disabled `
            -AuditQuery { [ordered]@{ ProcessCreation = 1 } } `
            -AuditSet { throw 'audit must remain unchanged' } `
            -CommandLineQuery {
                $script:commandReads++
                if ($script:commandReads -eq 1) { return $snapshot }
                if ($script:commandReads -le 3) { return 'Enabled' }
                return 'Disabled'
            } `
            -CommandLineSet { } `
            -CommandLineRestore { $script:restored = $true } `
            -RegistryPreflight { $true }

        $result.Succeeded | Should -BeFalse
        $result.CompensationStatus | Should -BeExactly SkippedConflict
        $result.ConflictDetected | Should -BeTrue
        $script:restored | Should -BeFalse
    }

    It 'detects an audit verification failure and restores the written audit state' {
        $script:auditReads = 0
        $script:auditWrites = [Collections.Generic.List[uint32]]::new()
        $result = Invoke-HHWindowsProcessAuditPolicyChange `
            -Subcategory ProcessCreation -State Enabled `
            -AuditQuery {
                $script:auditReads++
                if ($script:auditReads -eq 1) { return [ordered]@{ ProcessCreation = 4 } }
                if ($script:auditReads -eq 2) { return [ordered]@{ ProcessCreation = 4 } }
                if ($script:auditReads -eq 3) { return [ordered]@{ ProcessCreation = 2 } }
                return [ordered]@{ ProcessCreation = 4 }
            } `
            -AuditSet { param($Flags) $script:auditWrites.Add([uint32]$Flags.ProcessCreation) } `
            -CommandLineQuery { 'Disabled' } `
            -CommandLineSet { throw 'command line must remain unchanged' }

        $result.Succeeded | Should -BeFalse
        $result.CompensationStatus | Should -BeExactly SkippedConflict
        $result.ConflictDetected | Should -BeTrue
        $script:auditWrites | Should -Be @(1)
    }

    It 'detects enabled command-line verification failure and restores both changes' {
        $script:auditState = [uint32]4
        $script:commandReads = 0
        $script:commandState = 'Disabled'
        $result = Invoke-HHWindowsProcessAuditPolicyChange `
            -Subcategory ProcessCreation -State Enabled -CommandLineLogging Enabled `
            -AuditQuery { [ordered]@{ ProcessCreation = $script:auditState } } `
            -AuditSet { param($Flags) $script:auditState = [uint32]$Flags.ProcessCreation } `
            -CommandLineQuery {
                $script:commandReads++
                if ($script:commandReads -le 2) { return 'Disabled' }
                return $script:commandState
            } `
            -CommandLineSet { param($Value) $script:commandState = $Value } `
            -CommandLineRestore { param($Snapshot) $script:commandState = $Snapshot } `
            -RegistryPreflight { $true }

        $result.Succeeded | Should -BeFalse
        $result.CompensationStatus | Should -BeExactly Succeeded
        $result.AuditAfter.ProcessCreation | Should -Be 4
        $result.CommandLineAfter | Should -BeExactly Disabled
    }

    It 'returns a non-mutating failure when the first audit write fails' {
        $result = Invoke-HHWindowsProcessAuditPolicyChange `
            -Subcategory ProcessCreation -State Enabled `
            -AuditQuery { [ordered]@{ ProcessCreation = 4 } } `
            -AuditSet { throw 'audit write denied' } `
            -CommandLineQuery { 'Disabled' }

        $result.Succeeded | Should -BeFalse
        $result.Changed | Should -BeFalse
        $result.CompensationStatus | Should -BeExactly NotRequired
        $result.FailureMessage | Should -BeExactly 'audit write denied'
    }

    It 'fails finitely through the default native escalation boundary off Windows' -Skip:$IsWindows {
        $result = Invoke-HHWindowsProcessAuditPolicyChange `
            -Subcategory ProcessCreation -State Enabled -Escalate

        $result.Succeeded | Should -BeFalse
        $result.FailureKind | Should -BeExactly PrivilegeOrOperationFailed
        $result.PrivilegeActivated | Should -BeFalse
    }

    It 'enables audit before command-line capture and verifies both writes' {
        $script:auditState = [ordered]@{ ProcessCreation = [uint32]4 }
        $script:commandState = 'Disabled'
        $script:events = [Collections.Generic.List[string]]::new()
        $result = Invoke-HHWindowsProcessAuditPolicyChange `
            -Subcategory ProcessCreation -State Enabled -CommandLineLogging Enabled `
            -AuditQuery { [ordered]@{ ProcessCreation = $script:auditState.ProcessCreation } } `
            -AuditSet {
                param($Flags)
                $script:events.Add('audit')
                $script:auditState.ProcessCreation = [uint32]$Flags.ProcessCreation
            } `
            -CommandLineQuery { $script:commandState } `
            -CommandLineSet {
                param($Value)
                $script:events.Add('command')
                $script:commandState = $Value
            } `
            -RegistryPreflight { $script:events.Add('preflight'); $true }

        $result.Succeeded | Should -BeTrue
        $result.Changed | Should -BeTrue
        $result.AuditBefore.ProcessCreation | Should -Be 4
        $result.AuditAfter.ProcessCreation | Should -Be 1
        $result.CommandLineAfter | Should -BeExactly 'Enabled'
        $script:events | Should -Be @('preflight', 'audit', 'command')
    }

    It 'applies privacy-reducing command-line changes before audit changes' {
        $script:auditState = [ordered]@{ ProcessCreation = [uint32]1 }
        $script:commandState = 'Enabled'
        $script:events = [Collections.Generic.List[string]]::new()
        $result = Invoke-HHWindowsProcessAuditPolicyChange `
            -Subcategory ProcessCreation -State Disabled -CommandLineLogging Disabled `
            -AuditQuery { [ordered]@{ ProcessCreation = $script:auditState.ProcessCreation } } `
            -AuditSet {
                param($Flags)
                $script:events.Add('audit')
                $script:auditState.ProcessCreation = [uint32]$Flags.ProcessCreation
            } `
            -CommandLineQuery { $script:commandState } `
            -CommandLineSet {
                param($Value)
                $script:events.Add('command')
                $script:commandState = $Value
            } `
            -RegistryPreflight { $true }

        $result.Succeeded | Should -BeTrue
        $script:events | Should -Be @('command', 'audit')
        $result.AuditAfter.ProcessCreation | Should -Be 4
    }

    It 'compensates a verified audit write when command-line enablement fails' {
        $script:auditState = [ordered]@{ ProcessCreation = [uint32]4 }
        $script:commandState = 'Disabled'
        $script:auditWrites = 0
        $result = Invoke-HHWindowsProcessAuditPolicyChange `
            -Subcategory ProcessCreation -State Enabled -CommandLineLogging Enabled `
            -AuditQuery { [ordered]@{ ProcessCreation = $script:auditState.ProcessCreation } } `
            -AuditSet {
                param($Flags)
                $script:auditWrites++
                $script:auditState.ProcessCreation = [uint32]$Flags.ProcessCreation
            } `
            -CommandLineQuery { $script:commandState } `
            -CommandLineSet { throw 'registry denied' } `
            -RegistryPreflight { $true }

        $result.Succeeded | Should -BeFalse
        $result.CompensationStatus | Should -BeExactly 'Succeeded'
        $result.ReconciliationRequired | Should -BeFalse
        $result.AuditAfter.ProcessCreation | Should -Be 4
        $script:auditWrites | Should -Be 2
    }

    It 'restores the exact command-line snapshot when a later audit verification fails' {
        $script:auditReads = 0
        $script:commandState = 'Enabled'
        $script:restoredSnapshot = $null
        $snapshot = [pscustomobject]@{
            State = 'Enabled'
            Exists = $true
            Value = 7
            Kind = 'DWord'
        }
        $result = Invoke-HHWindowsProcessAuditPolicyChange `
            -Subcategory ProcessCreation -State Disabled -CommandLineLogging Disabled `
            -AuditQuery {
                $script:auditReads++
                if ($script:auditReads -eq 1) {
                    return [ordered]@{ ProcessCreation = [uint32]1 }
                }
                return [ordered]@{ ProcessCreation = [uint32]1 }
            } `
            -AuditSet { } `
            -CommandLineQuery {
                if ($script:commandState -ceq 'Enabled') { return $snapshot }
                return $script:commandState
            } `
            -CommandLineSet { param($Value) $script:commandState = $Value } `
            -CommandLineRestore {
                param($Original)
                $script:restoredSnapshot = $Original
                $script:commandState = $Original.State
            } `
            -RegistryPreflight { $true }

        $result.Succeeded | Should -BeFalse
        $result.CompensationStatus | Should -BeExactly 'SkippedConflict'
        $script:restoredSnapshot | Should -Be $snapshot
        $script:restoredSnapshot.Value | Should -Be 7
        $result.CommandLineAfter | Should -BeExactly 'Enabled'
    }

    It 'reports failed compensation and unavailable final projections' {
        $script:auditReads = 0
        $script:commandReads = 0
        $script:auditState = [uint32]4
        $script:commandState = 'Disabled'
        $result = Invoke-HHWindowsProcessAuditPolicyChange `
            -Subcategory ProcessCreation -State Enabled -CommandLineLogging Enabled `
            -AuditQuery {
                $script:auditReads++
                if ($script:auditReads -ge 4) { throw 'audit query unavailable' }
                [ordered]@{ ProcessCreation = $script:auditState }
            } `
            -AuditSet {
                param($Flags)
                if ([uint32]$Flags.ProcessCreation -eq 4) { throw 'rollback denied' }
                $script:auditState = [uint32]$Flags.ProcessCreation
            } `
            -CommandLineQuery {
                $script:commandReads++
                if ($script:commandReads -ge 2) { throw 'registry query unavailable' }
                $script:commandState
            } `
            -CommandLineSet { throw 'registry denied' } `
            -RegistryPreflight { $true }

        $result.Succeeded | Should -BeFalse
        $result.CompensationStatus | Should -BeExactly 'Failed'
        $result.ReconciliationRequired | Should -BeTrue
        $result.AuditAfter | Should -BeNullOrEmpty
        $result.CommandLineAfter | Should -BeNullOrEmpty
    }

    It 'does not overwrite a concurrent audit policy change during compensation' {
        $script:auditReads = 0
        $script:auditState = [uint32]4
        $script:commandState = 'Disabled'
        $script:auditWrites = 0
        $result = Invoke-HHWindowsProcessAuditPolicyChange `
            -Subcategory ProcessCreation -State Enabled -CommandLineLogging Enabled `
            -AuditQuery {
                $script:auditReads++
                if ($script:auditReads -ge 3) { $script:auditState = [uint32]2 }
                [ordered]@{ ProcessCreation = $script:auditState }
            } `
            -AuditSet {
                param($Flags)
                $script:auditWrites++
                $script:auditState = [uint32]$Flags.ProcessCreation
            } `
            -CommandLineQuery { $script:commandState } `
            -CommandLineSet { throw 'registry denied' } `
            -RegistryPreflight { $true }

        $result.Succeeded | Should -BeFalse
        $result.CompensationStatus | Should -BeExactly 'SkippedConflict'
        $result.ConflictDetected | Should -BeTrue
        $result.ReconciliationRequired | Should -BeTrue
        $script:auditWrites | Should -Be 1
    }

    It 'activates and restores SeSecurityPrivilege when escalation is requested' {
        $script:scopeEvents = [Collections.Generic.List[string]]::new()
        $result = Invoke-HHWindowsProcessAuditPolicyChange `
            -Subcategory ProcessCreation -State Enabled -Escalate `
            -AuditQuery { [ordered]@{ ProcessCreation = 1 } } `
            -AuditSet { throw 'unexpected' } `
            -CommandLineQuery { 'Disabled' } `
            -CommandLineSet { throw 'unexpected' } `
            -RegistryPreflight { $true } `
            -PrivilegeEnter {
                param($Name)
                $script:scopeEvents.Add("enter:$Name")
                [pscustomobject]@{ Changed = $true }
            } `
            -PrivilegeExit { $script:scopeEvents.Add('exit') }

        $result.Succeeded | Should -BeTrue
        $result.PrivilegeActivated | Should -BeTrue
        $result.PrivilegeChanged | Should -BeTrue
        $result.PrivilegeRestored | Should -BeTrue
        $script:scopeEvents | Should -Be @('enter:SeSecurityPrivilege', 'exit')
    }

    It 'turns a privilege restoration failure into reconciliation-required failure' {
        $result = Invoke-HHWindowsProcessAuditPolicyChange `
            -Subcategory ProcessCreation -State Enabled -Escalate `
            -AuditQuery { [ordered]@{ ProcessCreation = 1 } } `
            -AuditSet { throw 'unexpected' } `
            -CommandLineQuery { 'Disabled' } `
            -CommandLineSet { throw 'unexpected' } `
            -RegistryPreflight { $true } `
            -PrivilegeEnter { [pscustomobject]@{ Changed = $false } } `
            -PrivilegeExit { throw 'restore failed' }

        $result.Succeeded | Should -BeFalse
        $result.FailureKind | Should -BeExactly 'PrivilegeRestoreFailed'
        $result.PrivilegeRestored | Should -BeFalse
        $result.ReconciliationRequired | Should -BeTrue
    }

    It 'returns a finite failure when privilege activation is unavailable' {
        $result = Invoke-HHWindowsProcessAuditPolicyChange `
            -Subcategory ProcessCreation -State Enabled -Escalate `
            -PrivilegeEnter { throw 'SeSecurityPrivilege is absent' } `
            -PrivilegeExit { throw 'must not run' }

        $result.Succeeded | Should -BeFalse
        $result.FailureKind | Should -BeExactly 'PrivilegeOrOperationFailed'
        $result.FailureMessage | Should -BeExactly 'SeSecurityPrivilege is absent'
        $result.PrivilegeActivated | Should -BeFalse
        $result.PrivilegeRestored | Should -BeFalse
    }

    It 'builds a self-contained remote script with a finite request entry point' {
        $remote = Get-HHWindowsProcessAuditPolicyScriptBlock
        $text = $remote.ToString()
        $text | Should -Match 'HostHunter.WindowsProcessAuditPolicyRequest.v1'
        $text | Should -Match 'function Invoke-HHWindowsProcessAuditPolicyChange'
        $text | Should -Match 'function Invoke-HHWindowsPrivilegeScope'
        $text | Should -Match 'Set-StrictMode -Version Latest'
    }

    It 'returns a finite policy outcome when the native query boundary fails' -Skip:$IsWindows {
        $request = New-HHWindowsProcessAuditPolicyRequest `
            -Subcategory ProcessCreation -State Enabled
        $result = & (Get-HHWindowsProcessAuditPolicyScriptBlock) $request
        $result.Marker | Should -BeExactly 'HostHunter.WindowsProcessAuditPolicyResult.v1'
        $result.Succeeded | Should -BeFalse
        $result.FailureKind | Should -BeExactly PolicyQueryFailed
        $result.Changed | Should -BeFalse
    }

    It 'extracts exactly one structurally valid outcome from stream events' {
        $outcome = New-HHWindowsProcessAuditResult `
            -AuditBefore ([ordered]@{ ProcessCreation = 4 }) `
            -AuditDesired ([ordered]@{ ProcessCreation = 1 }) `
            -AuditAfter ([ordered]@{ ProcessCreation = 1 }) `
            -CommandLineBefore Disabled -CommandLineDesired Disabled `
            -CommandLineAfter Disabled -Succeeded $true -Changed $true `
            -CompensationStatus NotRequired -ConflictDetected $false `
            -ReconciliationRequired $false -EscalationRequested $false `
            -PrivilegeResult $null -FailureKind $null -FailureMessage $null
        $events = @(
            [pscustomobject]@{ Value = 'ordinary output' },
            [pscustomobject]@{ Value = $outcome }
        )

        Test-HHWindowsProcessAuditPolicyOutcome -Outcome $outcome | Should -BeTrue
        Test-HHWindowsProcessAuditPolicyOutcome -Outcome ([pscustomobject]@{
                Marker = 'wrong'
            }) | Should -BeFalse
        $missing = $outcome.PSObject.Copy()
        $missing.PSObject.Properties.Remove('AuditAfter')
        Test-HHWindowsProcessAuditPolicyOutcome -Outcome $missing | Should -BeFalse
        $invalidStatus = $outcome.PSObject.Copy()
        $invalidStatus.CompensationStatus = 'Unknown'
        Test-HHWindowsProcessAuditPolicyOutcome -Outcome $invalidStatus | Should -BeFalse
        Get-HHWindowsProcessAuditPolicyOutcomeFromStreamEvents -StreamEvents $events |
            Should -Be $outcome
        {
            Get-HHWindowsProcessAuditPolicyOutcomeFromStreamEvents `
                -StreamEvents @($events[1], $events[1])
        } | Should -Throw '*exactly one valid*'
        Get-HHWindowsProcessAuditPolicyOutcomeFromStreamEvents `
            -StreamEvents @([pscustomobject]@{ Value = 'no result' }) -Required $false |
            Should -BeNullOrEmpty
    }
}
