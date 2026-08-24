Set-StrictMode -Version Latest

function Get-HHPersistenceContext {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$DataRoot)

    $root = [System.IO.Path]::GetFullPath($DataRoot)
    [pscustomobject][ordered]@{
        DataRoot = $root
        DatabasePath = Join-Path $root 'hosthunter.db'
        WriterLockPath = Join-Path $root 'hosthunter.db.writer.lock'
        OperationLockPath = Join-Path $root 'hosthunter.operation.lock'
        AuditRoot = Join-Path $root 'audit'
        AnchorPath = Join-Path $root 'audit/anchor.bin'
        OutputRoot = Join-Path $root 'audit/output'
        RecoveryRoot = Join-Path $root 'recovery'
        KnownHostsPath = Join-Path $root 'known_hosts'
        KeyRoot = Join-Path $root 'keys'
        MigrationPath = Join-Path $script:HHModuleRoot 'Private/Migrations/0001_initial_sqlite.sql'
    }
}

function Test-HHPersistencePathContained {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$Candidate
    )

    $fullRoot = [System.IO.Path]::GetFullPath($Root)
    $fullCandidate = [System.IO.Path]::GetFullPath($Candidate)
    $relative = [System.IO.Path]::GetRelativePath($fullRoot, $fullCandidate)
    return $relative -ne '..' -and
        -not $relative.StartsWith("..$([System.IO.Path]::DirectorySeparatorChar)") -and
        -not [System.IO.Path]::IsPathRooted($relative)
}

function Assert-HHPersistencePathSafety {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DataRoot,
        [switch]$AllowMissingRoot
    )

    $root = [System.IO.Path]::GetFullPath($DataRoot)
    if ($root -eq [System.IO.Path]::GetPathRoot($root)) {
        Stop-HHPersistenceOperation `
            -ErrorId 'PersistencePathUnsafe' `
            -Message 'A filesystem root cannot be used as the HostHunter data root.' `
            -Category ([System.Management.Automation.ErrorCategory]::SecurityError) `
            -TargetObject $root
    }
    if (-not [System.IO.Directory]::Exists($root)) {
        if ($AllowMissingRoot) { return }
        Stop-HHPersistenceOperation `
            -ErrorId 'PersistencePathUnsafe' `
            -Message 'The HostHunter data root does not exist.' `
            -Category ([System.Management.Automation.ErrorCategory]::ObjectNotFound) `
            -TargetObject $root
    }

    $current = [System.IO.DirectoryInfo]::new($root)
    while ($null -ne $current) {
        if (($current.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
            $null -ne $current.LinkTarget) {
            Stop-HHPersistenceOperation `
                -ErrorId 'PersistencePathUnsafe' `
                -Message 'The HostHunter data root cannot traverse a symbolic link or reparse point.' `
                -Category ([System.Management.Automation.ErrorCategory]::SecurityError) `
                -TargetObject $current.FullName
        }
        $current = $current.Parent
    }
}

function Initialize-HHPersistenceRoot {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$PersistenceContext)

    $rootExisted = [System.IO.Directory]::Exists($PersistenceContext.DataRoot)
    Assert-HHPersistencePathSafety -DataRoot $PersistenceContext.DataRoot -AllowMissingRoot
    [System.IO.Directory]::CreateDirectory($PersistenceContext.DataRoot) | Out-Null
    if ($IsWindows) {
        if ($rootExisted) {
            Assert-HHWindowsPrivatePathAcl `
                -Path $PersistenceContext.DataRoot -Directory
        }
        else {
            Protect-HHWindowsPrivatePathAcl `
                -Path $PersistenceContext.DataRoot -Directory
        }
    }
    else {
        [System.IO.File]::SetUnixFileMode(
            $PersistenceContext.DataRoot,
            [System.IO.UnixFileMode]::UserRead -bor
                [System.IO.UnixFileMode]::UserWrite -bor
                [System.IO.UnixFileMode]::UserExecute
        )
    }
    Assert-HHPersistencePathSafety -DataRoot $PersistenceContext.DataRoot
}

function Assert-HHLegacyPersistenceAbsent {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$PersistenceContext)

    if (-not [System.IO.Directory]::Exists($PersistenceContext.DataRoot)) {
        return
    }
    $legacyPaths = @(
        (Join-Path $PersistenceContext.DataRoot 'targets.json')
        (Join-Path $PersistenceContext.DataRoot 'targets.json.lock')
        (Join-Path $PersistenceContext.DataRoot 'audit/ledger.jsonl')
        (Join-Path $PersistenceContext.DataRoot 'audit/ledger.head.json')
    )
    $legacyPaths += Join-Path $PersistenceContext.DataRoot 'audit.key'
    $found = @($legacyPaths | Where-Object { Test-Path -LiteralPath $_ })
    if ($found.Count -gt 0) {
        Stop-HHPersistenceOperation `
            -ErrorId 'LegacyPersistenceMigrationRequired' `
            -Message 'Legacy HostHunter persistence was found and preserved. Automatic import is not supported.' `
            -Category ([System.Management.Automation.ErrorCategory]::InvalidData) `
            -TargetObject $found[0]
    }
}
