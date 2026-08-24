$sourceRoot = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
    Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration'
}
else { $env:HH_TEST_SOURCE_ROOT }
Import-Module (Join-Path $sourceRoot 'HostHunterNextGeneration.psd1') -Force

Describe 'persistence path and lock safety' -Tag Unit {
    InModuleScope HostHunterNextGeneration {
        It 'rejects filesystem roots, missing roots, and linked persistence roots' -Skip:$IsWindows {
            { Assert-HHPersistencePathSafety -DataRoot ([IO.Path]::GetPathRoot($TestDrive)) } |
                Should -Throw -ErrorId 'PersistencePathUnsafe*'
            { Assert-HHPersistencePathSafety -DataRoot (Join-Path $TestDrive 'missing') } |
                Should -Throw -ErrorId 'PersistencePathUnsafe*'
            { Assert-HHPersistencePathSafety -DataRoot (Join-Path $TestDrive 'missing') -AllowMissingRoot } |
                Should -Not -Throw

            $real = Join-Path $TestDrive 'real-root'
            $linked = Join-Path $TestDrive 'linked-root'
            [IO.Directory]::CreateDirectory($real) | Out-Null
            [IO.Directory]::CreateSymbolicLink($linked, $real) | Out-Null
            { Assert-HHPersistencePathSafety -DataRoot $linked } |
                Should -Throw -ErrorId 'PersistencePathUnsafe*'
        }

        It 'creates a private mode-0700 persistence root and accepts absent legacy state' -Skip:$IsWindows {
            $context = Get-HHPersistenceContext -DataRoot (Join-Path $TestDrive 'fresh-state')
            Assert-HHLegacyPersistenceAbsent -PersistenceContext $context
            Initialize-HHPersistenceRoot -PersistenceContext $context
            [IO.File]::GetUnixFileMode($context.DataRoot) | Should -Be (
                [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite -bor
                    [IO.UnixFileMode]::UserExecute
            )
            Assert-HHLegacyPersistenceAbsent -PersistenceContext $context
        }

        It 'accepts only the exact private Windows directory ACL projection' {
            $userSid = 'S-1-5-21-1000'
            $inheritance = [long](
                [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
                    [Security.AccessControl.InheritanceFlags]::ObjectInherit
            )
            $projection = [pscustomobject]@{
                OwnerSid = $userSid
                AccessRulesProtected = $true
                Rules = @(
                    foreach ($sid in @($userSid, 'S-1-5-18', 'S-1-5-32-544')) {
                        [pscustomobject]@{
                            IdentitySid = $sid
                            AccessControlType = 'Allow'
                            FileSystemRights = [long][Security.AccessControl.FileSystemRights]::FullControl
                            InheritanceFlags = $inheritance
                            PropagationFlags = 0L
                            IsInherited = $false
                        }
                    }
                )
            }

            {
                Assert-HHWindowsPrivateAclProjection -Projection $projection `
                    -CurrentUserSid $userSid -Directory
            } | Should -Not -Throw
        }

        It 'rejects inherited or additional Windows persistence principals' {
            $userSid = 'S-1-5-21-1000'
            $rules = @(
                foreach ($sid in @(
                        $userSid,
                        'S-1-5-18',
                        'S-1-5-32-544',
                        'S-1-1-0'
                    )) {
                    [pscustomobject]@{
                        IdentitySid = $sid
                        AccessControlType = 'Allow'
                        FileSystemRights = [long][Security.AccessControl.FileSystemRights]::FullControl
                        InheritanceFlags = 0L
                        PropagationFlags = 0L
                        IsInherited = $false
                    }
                }
            )
            $projection = [pscustomobject]@{
                OwnerSid = $userSid
                AccessRulesProtected = $true
                Rules = $rules
            }

            {
                Assert-HHWindowsPrivateAclProjection -Projection $projection `
                    -CurrentUserSid $userSid
            } | Should -Throw -ErrorId 'PersistenceAclUnsafe*'
            $projection.Rules = @($rules | Select-Object -First 3)
            $projection.Rules[0].IsInherited = $true
            {
                Assert-HHWindowsPrivateAclProjection -Projection $projection `
                    -CurrentUserSid $userSid
            } | Should -Throw -ErrorId 'PersistenceAclUnsafe*'
        }

        It 'rejects incomplete or empty Windows ACL projections and accepts the exact file form' {
            $userSid = 'S-1-5-21-1000'
            {
                Assert-HHWindowsPrivateAclProjection `
                    -Projection ([pscustomobject]@{ OwnerSid = $userSid }) `
                    -CurrentUserSid $userSid
            } | Should -Throw -ErrorId 'PersistenceAclUnsafe*'
            {
                Assert-HHWindowsPrivateAclProjection -Projection ([pscustomobject]@{
                        OwnerSid = $userSid
                        AccessRulesProtected = $true
                        Rules = @()
                    }) -CurrentUserSid $userSid
            } | Should -Throw -ErrorId 'PersistenceAclUnsafe*'

            $fileProjection = [pscustomobject]@{
                OwnerSid = $userSid
                AccessRulesProtected = $true
                Rules = @(
                    foreach ($sid in @($userSid, 'S-1-5-18', 'S-1-5-32-544')) {
                        [pscustomobject]@{
                            IdentitySid = $sid
                            AccessControlType = 'Allow'
                            FileSystemRights = [long][Security.AccessControl.FileSystemRights]::FullControl
                            InheritanceFlags = 0L
                            PropagationFlags = 0L
                            IsInherited = $false
                        }
                    }
                )
            }
            {
                Assert-HHWindowsPrivateAclProjection -Projection $fileProjection `
                    -CurrentUserSid $userSid
            } | Should -Not -Throw
        }

        It 'keeps every Windows ACL entry point inert or unavailable off Windows' -Skip:$IsWindows {
            { Get-HHWindowsCurrentUserSid } | Should -Throw -ExceptionType PlatformNotSupportedException
            { Get-HHWindowsPrivateAclProjection -Path $TestDrive -Directory } |
                Should -Throw -ExceptionType PlatformNotSupportedException
            { Assert-HHWindowsPrivatePathAcl -Path $TestDrive -Directory } |
                Should -Not -Throw
            { Protect-HHWindowsPrivatePathAcl -Path $TestDrive -Directory } |
                Should -Not -Throw
        }

        It 'projects Windows directory and file ACLs through the isolated native boundary' -Skip:$IsWindows {
            $userSid = 'S-1-5-21-1000'
            $rules = @(
                [pscustomobject]@{
                    IdentityReference = [pscustomobject]@{ Value = $userSid }
                    AccessControlType = 'Allow'
                    FileSystemRights = [Security.AccessControl.FileSystemRights]::FullControl
                    InheritanceFlags = [Security.AccessControl.InheritanceFlags]::None
                    PropagationFlags = [Security.AccessControl.PropagationFlags]::None
                    IsInherited = $false
                }
            )
            $acl = [pscustomobject]@{ AreAccessRulesProtected = $true; Rules = $rules }
            $acl | Add-Member ScriptMethod GetOwner { param($Type) $null = $Type; [pscustomobject]@{ Value = 'S-1-5-21-1000' } }
            $acl | Add-Member ScriptMethod GetAccessRules {
                param($IncludeExplicit, $IncludeInherited, $Type)
                $null = $IncludeExplicit, $IncludeInherited, $Type
                return $this.Rules
            }
            Mock Get-HHWindowsNativeFileSystemAcl { $acl }
            Set-Variable -Name IsWindows -Scope Script -Value $true -Force
            try {
                (Get-HHWindowsPrivateAclProjection -Path $TestDrive -Directory).Rules.Count |
                    Should -Be 1
                $filePath = Join-Path $TestDrive 'acl.file'
                [IO.File]::WriteAllText($filePath, 'safe')
                $acl.Rules = @()
                (Get-HHWindowsPrivateAclProjection -Path $filePath).Rules.Count |
                    Should -Be 0
            }
            finally {
                Set-Variable -Name IsWindows -Scope Script -Value $false -Force
            }
        }

        It 'applies and revalidates exact Windows directory and file ACL decisions' -Skip:$IsWindows {
            $userSid = 'S-1-5-21-1000'
            $state = [pscustomobject]@{
                Owner = $null
                Protected = $false
                Rules = [Collections.Generic.List[object]]::new()
            }
            $state | Add-Member ScriptMethod SetOwner { param($Owner) $this.Owner = $Owner }
            $state | Add-Member ScriptMethod SetAccessRuleProtection {
                param($Protected, $PreserveInheritance)
                $null = $PreserveInheritance
                $this.Protected = $Protected
            }
            $state | Add-Member ScriptMethod AddAccessRule {
                param($Rule)
                $this.Rules.Add($Rule)
                return $true
            }
            Mock Get-HHWindowsNativeCurrentUserSid { $userSid }
            Mock Get-HHWindowsNativeSecurityIdentifier { param($Sid) [pscustomobject]@{ Value = $Sid } }
            Mock Get-HHWindowsNativeDirectorySecurity { $state }
            Mock Get-HHWindowsNativeFileSecurity { $state }
            Mock Get-HHWindowsNativeAccessRule {
                param($Identity, $Inheritance)
                [pscustomobject]@{ Identity = $Identity; Inheritance = $Inheritance }
            }
            Mock Set-HHWindowsNativeDirectoryAcl {}
            Mock Set-HHWindowsNativeFileAcl {}
            Mock Get-HHWindowsPrivateAclProjection {
                [pscustomobject]@{ OwnerSid = $userSid; AccessRulesProtected = $true; Rules = @() }
            }
            Mock Assert-HHWindowsPrivateAclProjection {}
            Set-Variable -Name IsWindows -Scope Script -Value $true -Force
            try {
                Protect-HHWindowsPrivatePathAcl -Path $TestDrive -Directory
                $filePath = Join-Path $TestDrive 'private.file'
                Protect-HHWindowsPrivatePathAcl -Path $filePath
                Assert-HHWindowsPrivatePathAcl -Path $TestDrive -Directory
            }
            finally {
                Set-Variable -Name IsWindows -Scope Script -Value $false -Force
            }

            $state.Protected | Should -BeTrue
            $state.Rules.Count | Should -Be 6
            Should -Invoke Set-HHWindowsNativeDirectoryAcl -Times 1 -Exactly
            Should -Invoke Set-HHWindowsNativeFileAcl -Times 1 -Exactly
            Should -Invoke Assert-HHWindowsPrivateAclProjection -Times 3 -Exactly
        }

        It 'protects a new Windows persistence root and validates an existing root' -Skip:$IsWindows {
            Mock Protect-HHWindowsPrivatePathAcl {}
            Mock Assert-HHWindowsPrivatePathAcl {}
            $newContext = Get-HHPersistenceContext -DataRoot (Join-Path $TestDrive 'new-windows-root')
            $existingContext = Get-HHPersistenceContext `
                -DataRoot (Join-Path $TestDrive 'existing-windows-root')
            [IO.Directory]::CreateDirectory($existingContext.DataRoot) | Out-Null
            Set-Variable -Name IsWindows -Scope Script -Value $true -Force
            try {
                Initialize-HHPersistenceRoot -PersistenceContext $newContext
                Initialize-HHPersistenceRoot -PersistenceContext $existingContext
            }
            finally {
                Set-Variable -Name IsWindows -Scope Script -Value $false -Force
            }
            Should -Invoke Protect-HHWindowsPrivatePathAcl -Times 1 -Exactly
            Should -Invoke Assert-HHWindowsPrivatePathAcl -Times 1 -Exactly
        }

        It 'uses injected lock clock and delay providers and returns a stable busy error' {
            $path = Join-Path $TestDrive 'contended.lock'
            $first = Enter-HHPersistenceFileLock -Path $path -FailureId PersistenceBusy
            $clockState = [pscustomobject]@{ Calls = 0 }
            $clock = {
                $clockState.Calls++
                if ($clockState.Calls -eq 1) { [DateTimeOffset]'2026-08-24T00:00:00Z' }
                else { [DateTimeOffset]'2026-08-24T00:00:01Z' }
            }.GetNewClosure()
            $delay = { param($Milliseconds) $null = $Milliseconds }
            try {
                {
                    Enter-HHPersistenceFileLock -Path $path -FailureId PersistenceBusy `
                        -TimeoutMilliseconds 1 -Clock $clock -Delay $delay
                } | Should -Throw -ErrorId 'PersistenceBusy*'
                $clockState.Calls | Should -BeGreaterOrEqual 2
            }
            finally { Exit-HHPersistenceFileLock -LockContext $first }
        }

        It 'rejects a linked persistence lock before opening its target' -Skip:$IsWindows {
            $target = Join-Path $TestDrive 'real.lock'
            $link = Join-Path $TestDrive 'linked.lock'
            [IO.File]::WriteAllText($target, 'preserve')
            [IO.File]::CreateSymbolicLink($link, $target) | Out-Null
            { Enter-HHPersistenceFileLock -Path $link -FailureId OperationBusy } |
                Should -Throw -ErrorId 'PersistencePathUnsafe*'
            [IO.File]::ReadAllText($target) | Should -BeExactly 'preserve'
            Exit-HHPersistenceFileLock -LockContext $null
        }
    }
}
