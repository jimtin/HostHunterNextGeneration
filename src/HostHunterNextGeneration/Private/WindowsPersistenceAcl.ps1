Set-StrictMode -Version Latest

function Get-HHWindowsNativeCurrentUserSid {
    [CmdletBinding()]
    param()

    return [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
}

function Get-HHWindowsNativeFileSystemAcl {
    [CmdletBinding()]
    param([Parameter(Mandatory)][IO.FileSystemInfo]$Item)

    return [IO.FileSystemAclExtensions]::GetAccessControl($Item)
}

function Get-HHWindowsNativeSecurityIdentifier {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Sid)

    return [Security.Principal.SecurityIdentifier]::new($Sid)
}

function Get-HHWindowsNativeDirectorySecurity {
    [CmdletBinding()]
    param()

    return [Security.AccessControl.DirectorySecurity]::new()
}

function Get-HHWindowsNativeFileSecurity {
    [CmdletBinding()]
    param()

    return [Security.AccessControl.FileSecurity]::new()
}

function Get-HHWindowsNativeAccessRule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Identity,
        [Parameter(Mandatory)][Security.AccessControl.InheritanceFlags]$Inheritance
    )

    return [Security.AccessControl.FileSystemAccessRule]::new(
        $Identity,
        [Security.AccessControl.FileSystemRights]::FullControl,
        $Inheritance,
        [Security.AccessControl.PropagationFlags]::None,
        [Security.AccessControl.AccessControlType]::Allow
    )
}

function Set-HHWindowsNativeDirectoryAcl {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Native boundary for an already authorized private ACL mutation.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Acl
    )

    [IO.FileSystemAclExtensions]::SetAccessControl([IO.DirectoryInfo]::new($Path), $Acl)
}

function Set-HHWindowsNativeFileAcl {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Native boundary for an already authorized private ACL mutation.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Acl
    )

    [IO.FileSystemAclExtensions]::SetAccessControl([IO.FileInfo]::new($Path), $Acl)
}

function Get-HHWindowsCurrentUserSid {
    [CmdletBinding()]
    param()

    if (-not $IsWindows) {
        throw [PlatformNotSupportedException]::new(
            'Windows persistence ACL operations require Windows.'
        )
    }
    return Get-HHWindowsNativeCurrentUserSid
}

function Assert-HHWindowsPrivateAclProjection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Projection,
        [Parameter(Mandatory)][string]$CurrentUserSid,
        [switch]$Directory
    )

    foreach ($propertyName in @('OwnerSid', 'AccessRulesProtected', 'Rules')) {
        if ($null -eq $Projection.PSObject.Properties[$propertyName]) {
            Stop-HHPersistenceOperation `
                -ErrorId 'PersistenceAclUnsafe' `
                -Message 'The Windows persistence ACL could not be verified.' `
                -Category ([Management.Automation.ErrorCategory]::SecurityError) `
                -TargetObject $null
        }
    }
    $allowedSids = @($CurrentUserSid, 'S-1-5-18', 'S-1-5-32-544')
    $rules = @($Projection.Rules)
    $requiredInheritance = if ($Directory) {
        [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
            [Security.AccessControl.InheritanceFlags]::ObjectInherit
    }
    else {
        [Security.AccessControl.InheritanceFlags]::None
    }
    $seenSids = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal
    )
    $valid = [string]$Projection.OwnerSid -ceq $CurrentUserSid -and
        [bool]$Projection.AccessRulesProtected -and
        $rules.Count -eq $allowedSids.Count
    foreach ($rule in $rules) {
        $valid = $valid -and
            [string]$rule.IdentitySid -cin $allowedSids -and
            [string]$rule.AccessControlType -ceq 'Allow' -and
            [long]$rule.FileSystemRights -eq
                [long][Security.AccessControl.FileSystemRights]::FullControl -and
            [long]$rule.InheritanceFlags -eq [long]$requiredInheritance -and
            [long]$rule.PropagationFlags -eq
                [long][Security.AccessControl.PropagationFlags]::None -and
            -not [bool]$rule.IsInherited
        if ($null -ne $rule -and
            $null -ne $rule.PSObject.Properties['IdentitySid']) {
            $null = $seenSids.Add([string]$rule.IdentitySid)
        }
    }
    foreach ($requiredSid in $allowedSids) {
        $valid = $valid -and $seenSids.Contains($requiredSid)
    }
    if (-not $valid) {
        Stop-HHPersistenceOperation `
            -ErrorId 'PersistenceAclUnsafe' `
            -Message ('The Windows persistence path must grant full control only to ' +
                'the current user, SYSTEM, and local Administrators.') `
            -Category ([Management.Automation.ErrorCategory]::SecurityError) `
            -TargetObject $null
    }
}

function Get-HHWindowsPrivateAclProjection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$Directory
    )

    if (-not $IsWindows) {
        throw [PlatformNotSupportedException]::new(
            'Windows persistence ACL operations require Windows.'
        )
    }
    $item = if ($Directory) {
        [IO.DirectoryInfo]::new($Path)
    }
    else {
        [IO.FileInfo]::new($Path)
    }
    $acl = Get-HHWindowsNativeFileSystemAcl -Item $item
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    $rules = @(
        foreach ($rule in $acl.GetAccessRules(
                $true,
                $true,
                [Security.Principal.SecurityIdentifier]
            )) {
            [pscustomobject]@{
                IdentitySid = $rule.IdentityReference.Value
                AccessControlType = [string]$rule.AccessControlType
                FileSystemRights = [long]$rule.FileSystemRights
                InheritanceFlags = [long]$rule.InheritanceFlags
                PropagationFlags = [long]$rule.PropagationFlags
                IsInherited = [bool]$rule.IsInherited
            }
        }
    )
    return [pscustomobject]@{
        OwnerSid = $owner
        AccessRulesProtected = [bool]$acl.AreAccessRulesProtected
        Rules = $rules
    }
}

function Assert-HHWindowsPrivatePathAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$Directory
    )

    if (-not $IsWindows) { return }
    $projection = Get-HHWindowsPrivateAclProjection -Path $Path -Directory:$Directory
    Assert-HHWindowsPrivateAclProjection -Projection $projection `
        -CurrentUserSid (Get-HHWindowsCurrentUserSid) -Directory:$Directory
}

function Protect-HHWindowsPrivatePathAcl {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Private ACL hardening is part of an already authorized persistence initialization.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$Directory
    )

    if (-not $IsWindows) { return }
    $currentUserSid = Get-HHWindowsNativeSecurityIdentifier `
        -Sid (Get-HHWindowsCurrentUserSid)
    $acl = if ($Directory) {
        Get-HHWindowsNativeDirectorySecurity
    }
    else {
        Get-HHWindowsNativeFileSecurity
    }
    $acl.SetOwner($currentUserSid)
    $acl.SetAccessRuleProtection($true, $false)
    $inheritance = if ($Directory) {
        [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
            [Security.AccessControl.InheritanceFlags]::ObjectInherit
    }
    else {
        [Security.AccessControl.InheritanceFlags]::None
    }
    foreach ($sidText in @(
            $currentUserSid.Value,
            'S-1-5-18',
            'S-1-5-32-544'
        )) {
        $rule = Get-HHWindowsNativeAccessRule `
            -Identity (Get-HHWindowsNativeSecurityIdentifier -Sid $sidText) `
            -Inheritance $inheritance
        $null = $acl.AddAccessRule($rule)
    }
    if ($Directory) {
        Set-HHWindowsNativeDirectoryAcl -Path $Path -Acl $acl
    }
    else {
        Set-HHWindowsNativeFileAcl -Path $Path -Acl $acl
    }
    Assert-HHWindowsPrivatePathAcl -Path $Path -Directory:$Directory
}
