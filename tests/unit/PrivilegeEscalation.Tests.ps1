BeforeAll {
    $sourceRoot = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
        Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration'
    }
    else { $env:HH_TEST_SOURCE_ROOT }
    $script:privilegePath = Join-Path $sourceRoot 'Private/PrivilegeEscalation.ps1'
    . $script:privilegePath
}

Describe 'Windows token privilege scope' -Tag Unit {
    It 'contains an exact existing-token activation boundary and ERROR_NOT_ALL_ASSIGNED check' {
        $source = Get-Content -LiteralPath $script:privilegePath -Raw
        $source | Should -Match 'AdjustTokenPrivileges'
        $source | Should -Match 'ErrorNotAllAssigned\s*=\s*1300'
        $source | Should -Match 'PreviousState'
        $source | Should -Not -Match '(?i)runas|Start-Process|sudo|credential'
    }

    It 'compiles the PowerShell 5.1-compatible native type without invoking Windows' {
        { Initialize-HHWindowsPrivilegeNativeType } | Should -Not -Throw
        ('HostHunter.Native.WindowsTokenPrivileges' -as [type]) | Should -Not -BeNullOrEmpty
    }

    It 'refuses native token operations away from Windows' -Skip:(
        [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
    ) {
        { Enter-HHWindowsTokenPrivilege -PrivilegeName SeSecurityPrivilege } |
            Should -Throw '*requires Windows*'
        { Exit-HHWindowsTokenPrivilege -Scope ([pscustomobject]@{}) } |
            Should -Throw '*requires Windows*'
    }

    It 'enters, executes, and restores one declared privilege' {
        $script:scopeEvents = [Collections.Generic.List[string]]::new()
        $result = Invoke-HHWindowsPrivilegeScope `
            -Method WindowsTokenPrivilege `
            -PrivilegeName SeSecurityPrivilege `
            -PrivilegeEnter {
                param($Name)
                $script:scopeEvents.Add("enter:$Name")
                [pscustomobject]@{ Changed = $true }
            } `
            -Operation {
                $script:scopeEvents.Add('operation')
                'completed'
            } `
            -PrivilegeExit {
                param($Scope)
                $script:scopeEvents.Add("exit:$($Scope.Changed)")
            }

        $result.Marker | Should -BeExactly 'HostHunter.PrivilegeScope.v1'
        $result.OperationSucceeded | Should -BeTrue
        $result.OperationResult | Should -BeExactly 'completed'
        $result.Changed | Should -BeTrue
        $result.Restored | Should -BeTrue
        $script:scopeEvents | Should -Be @(
            'enter:SeSecurityPrivilege', 'operation', 'exit:True'
        )
    }

    It 'restores the scope when the protected operation fails' {
        $script:restoreCalled = $false
        $result = Invoke-HHWindowsPrivilegeScope `
            -Method WindowsTokenPrivilege `
            -PrivilegeName SeSecurityPrivilege `
            -PrivilegeEnter { [pscustomobject]@{ Changed = $false } } `
            -Operation { throw 'operation failed' } `
            -PrivilegeExit { $script:restoreCalled = $true }

        $script:restoreCalled | Should -BeTrue
        $result.OperationSucceeded | Should -BeFalse
        $result.FailureKind | Should -BeExactly 'PrivilegeOrOperationFailed'
        $result.FailureMessage | Should -BeExactly 'operation failed'
        $result.Restored | Should -BeTrue
    }

    It 'does not call restore when privilege activation fails' {
        $script:restoreCalled = $false
        $result = Invoke-HHWindowsPrivilegeScope `
            -Method WindowsTokenPrivilege `
            -PrivilegeName SeSecurityPrivilege `
            -PrivilegeEnter { throw 'privilege absent' } `
            -Operation { throw 'must not execute' } `
            -PrivilegeExit { $script:restoreCalled = $true }

        $script:restoreCalled | Should -BeFalse
        $result.Entered | Should -BeFalse
        $result.Restored | Should -BeFalse
        $result.FailureMessage | Should -BeExactly 'privilege absent'
    }

    It 'reports a restoration failure after successful work' {
        $result = Invoke-HHWindowsPrivilegeScope `
            -Method WindowsTokenPrivilege `
            -PrivilegeName SeSecurityPrivilege `
            -PrivilegeEnter { [pscustomobject]@{ Changed = $true } } `
            -Operation { 'done' } `
            -PrivilegeExit { throw 'restore failed' }

        $result.OperationSucceeded | Should -BeFalse
        $result.FailureKind | Should -BeExactly 'PrivilegeRestoreFailed'
        $result.FailureMessage | Should -BeExactly 'restore failed'
        $result.Restored | Should -BeFalse
    }
}
