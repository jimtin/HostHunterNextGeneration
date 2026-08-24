Set-StrictMode -Version Latest

$script:HHControllerIsMacOS = $IsMacOS

function Resolve-HHDataRoot {
    [CmdletBinding()]
    param([string]$DataRoot)

    if (-not [string]::IsNullOrWhiteSpace($DataRoot)) {
        return [System.IO.Path]::GetFullPath($DataRoot)
    }
    if (-not [string]::IsNullOrWhiteSpace($env:HH_DATA_ROOT)) {
        return [System.IO.Path]::GetFullPath($env:HH_DATA_ROOT)
    }
    if ($IsWindows) {
        return Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'HostHunterNextGeneration'
    }
    if ($IsMacOS) {
        return Join-Path ([Environment]::GetFolderPath('UserProfile')) 'Library/Application Support/HostHunterNextGeneration'
    }
    if (-not [string]::IsNullOrWhiteSpace($env:XDG_STATE_HOME)) {
        return Join-Path $env:XDG_STATE_HOME 'hosthunter-next-generation'
    }
    return Join-Path ([Environment]::GetFolderPath('UserProfile')) '.local/state/hosthunter-next-generation'
}

function Protect-HHPrivateFileMode {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if ($IsWindows) {
        Protect-HHWindowsPrivatePathAcl -Path $Path
    }
    else {
        [System.IO.File]::SetUnixFileMode(
            $Path,
            [System.IO.UnixFileMode]::UserRead -bor [System.IO.UnixFileMode]::UserWrite
        )
    }
}

function Confirm-HHAuditKeyFileSafety {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    try {
        $attributes = [System.IO.File]::GetAttributes($Path)
    }
    catch {
        throw (Get-HHAuditKeyStoreErrorRecord `
                -ErrorId 'AuditFileKeyUnsafe' `
                -Message 'The audit key file cannot be safely inspected. Remote activity is blocked.' `
                -Category ([System.Management.Automation.ErrorCategory]::SecurityError))
    }
    if (($attributes -band [System.IO.FileAttributes]::Directory) -ne 0 -or
        ($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw (Get-HHAuditKeyStoreErrorRecord `
                -ErrorId 'AuditFileKeyUnsafe' `
                -Message 'The audit key path must be a regular private file. Remote activity is blocked.' `
                -Category ([System.Management.Automation.ErrorCategory]::SecurityError))
    }
    if ($IsWindows) {
        Assert-HHWindowsPrivatePathAcl -Path $Path
    }
    else {
        $requiredMode = [System.IO.UnixFileMode]::UserRead -bor [System.IO.UnixFileMode]::UserWrite
        try {
            $actualMode = [System.IO.File]::GetUnixFileMode($Path)
        }
        catch {
            throw (Get-HHAuditKeyStoreErrorRecord `
                    -ErrorId 'AuditFileKeyUnsafe' `
                    -Message 'The audit key permissions cannot be inspected. Remote activity is blocked.' `
                    -Category ([System.Management.Automation.ErrorCategory]::SecurityError))
        }
        if ($actualMode -ne $requiredMode) {
            throw (Get-HHAuditKeyStoreErrorRecord `
                    -ErrorId 'AuditFileKeyUnsafe' `
                    -Message 'The audit key file must have mode 0600. Remote activity is blocked.' `
                    -Category ([System.Management.Automation.ErrorCategory]::SecurityError))
        }
    }
}

function Read-HHPrivateAuditKeyFile {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    Confirm-HHAuditKeyFileSafety -Path $Path
    $stream = $null
    $key = $null
    try {
        $stream = [System.IO.File]::Open(
            $Path,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::None
        )
        Confirm-HHAuditKeyFileSafety -Path $Path
        if ($stream.Length -ne 32) {
            throw (Get-HHAuditKeyStoreErrorRecord `
                    -ErrorId 'AuditFileKeyCorrupt' `
                    -Message 'The audit key file is invalid. Remote activity is blocked.' `
                    -Category ([System.Management.Automation.ErrorCategory]::InvalidData))
        }
        $key = [byte[]]::new(32)
        $stream.ReadExactly($key, 0, $key.Length)
    }
    catch {
        if ($null -ne $key) {
            [Array]::Clear($key, 0, $key.Length)
        }
        $knownErrorId = ($_.FullyQualifiedErrorId -split ',', 2)[0]
        if ($knownErrorId -in @('AuditFileKeyCorrupt', 'AuditFileKeyUnsafe')) {
            throw
        }
        throw (Get-HHAuditKeyStoreErrorRecord `
                -ErrorId 'AuditFileKeyUnsafe' `
                -Message 'The audit key file cannot be safely read. Remote activity is blocked.' `
                -Category ([System.Management.Automation.ErrorCategory]::SecurityError))
    }
    finally {
        if ($null -ne $stream) {
            $stream.Dispose()
        }
    }
    return ,$key
}

function Write-HHPrivateAuditKeyFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][byte[]]$Key,
        [scriptblock]$OpenedFileObserver
    )

    $options = [System.IO.FileStreamOptions]::new()
    $options.Mode = [System.IO.FileMode]::CreateNew
    $options.Access = [System.IO.FileAccess]::Write
    $options.Share = [System.IO.FileShare]::None
    $options.Options = [System.IO.FileOptions]::WriteThrough
    if (-not $IsWindows) {
        $options.UnixCreateMode = [System.IO.UnixFileMode]::UserRead -bor
            [System.IO.UnixFileMode]::UserWrite
    }

    $stream = $null
    try {
        $stream = [System.IO.File]::Open($Path, $options)
        if ($null -ne $OpenedFileObserver) {
            & $OpenedFileObserver $Path
        }
        $stream.Write($Key, 0, $Key.Length)
        $stream.Flush($true)
    }
    finally {
        if ($null -ne $stream) {
            $stream.Dispose()
        }
    }
    Confirm-HHAuditKeyFileSafety -Path $Path
}

function Get-HHFileAuditMasterKey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DataRoot,
        [scriptblock]$OpenedFileObserver,
        [switch]$RequireExisting
    )

    if ($script:HHControllerIsMacOS) {
        throw (Get-HHAuditKeyStoreErrorRecord `
                -ErrorId 'AuditKeyPlaintextDowngradeBlocked' `
                -Message 'The plaintext audit-key provider is disabled on macOS. Remote activity is blocked.' `
                -Category ([System.Management.Automation.ErrorCategory]::SecurityError))
    }

    $auditRoot = Join-Path $DataRoot 'audit'
    $keyPath = Join-Path $auditRoot 'audit.key'
    $auditRootExisted = [System.IO.Directory]::Exists($auditRoot)
    [System.IO.Directory]::CreateDirectory($auditRoot) | Out-Null
    if ($IsWindows) {
        if ($auditRootExisted) {
            Assert-HHWindowsPrivatePathAcl -Path $auditRoot -Directory
        }
        else {
            Protect-HHWindowsPrivatePathAcl -Path $auditRoot -Directory
        }
    }
    if (Test-Path -LiteralPath $keyPath -PathType Leaf) {
        return Read-HHPrivateAuditKeyFile -Path $keyPath
    }
    if ($RequireExisting) {
        throw (Get-HHAuditKeyStoreErrorRecord `
                -ErrorId 'AuditKeyUnavailable' `
                -Message 'The existing HostHunter database has no matching audit key. Remote activity is blocked.' `
                -Category ([System.Management.Automation.ErrorCategory]::ResourceUnavailable))
    }

    $key = [byte[]]::new(32)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($key)
    $temporaryPath = "$keyPath.$([Guid]::NewGuid().ToString('N')).tmp"
    try {
        Write-HHPrivateAuditKeyFile `
            -Path $temporaryPath `
            -Key $key `
            -OpenedFileObserver $OpenedFileObserver
        [System.IO.File]::Move($temporaryPath, $keyPath, $false)
        if ($IsWindows) {
            Protect-HHWindowsPrivatePathAcl -Path $keyPath
        }
        Confirm-HHAuditKeyFileSafety -Path $keyPath
    }
    catch {
        if (Test-Path -LiteralPath $temporaryPath) {
            Remove-Item -LiteralPath $temporaryPath -Force
        }
        if (Test-Path -LiteralPath $keyPath -PathType Leaf) {
            [Array]::Clear($key, 0, $key.Length)
            return Read-HHPrivateAuditKeyFile -Path $keyPath
        }
        [Array]::Clear($key, 0, $key.Length)
        throw
    }
    return ,$key
}

function Confirm-HHLegacyAuditKeyAbsent {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$DataRoot)

    if (Test-Path -LiteralPath (Join-Path $DataRoot 'audit.key')) {
        throw (Get-HHAuditKeyStoreErrorRecord `
                -ErrorId 'LegacyAuditKeyMigrationRequired' `
                -Message ('A legacy audit key file exists under the selected data root. ' +
                    'It was preserved; complete a verified migration before remote activity.') `
                -Category ([System.Management.Automation.ErrorCategory]::SecurityError))
    }
}

function Get-HHMasterKey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DataRoot,
        [scriptblock]$SecurityCommandInvoker,
        [scriptblock]$KeychainWorkerInvoker,
        [switch]$RequireExisting
    )

    if (-not $script:HHControllerIsMacOS) {
        return Get-HHFileAuditMasterKey -DataRoot $DataRoot -RequireExisting:$RequireExisting
    }

    Confirm-HHLegacyAuditKeyAbsent -DataRoot $DataRoot
    if ($RequireExisting) {
        $account = Get-HHAuditKeychainAccount -DataRoot $DataRoot
        $keychainPath = Get-HHMacOSLoginKeychainPath `
            -SecurityCommandInvoker $SecurityCommandInvoker
        $storedItem = Read-HHMacOSAuditKeychainItem `
            -Account $account `
            -KeychainPath $keychainPath `
            -KeychainWorkerInvoker $KeychainWorkerInvoker
        if (-not $storedItem.Found) {
            throw (Get-HHAuditKeyStoreErrorRecord `
                    -ErrorId 'AuditKeyUnavailable' `
                    -Message 'The existing HostHunter database has no matching Keychain key. Remote activity is blocked.' `
                    -Category ([System.Management.Automation.ErrorCategory]::ResourceUnavailable))
        }
        return ,([byte[]]$storedItem.Key)
    }
    $key = Get-HHMacOSAuditMasterKey `
        -DataRoot $DataRoot `
        -SecurityCommandInvoker $SecurityCommandInvoker `
        -KeychainWorkerInvoker $KeychainWorkerInvoker
    try {
        Confirm-HHLegacyAuditKeyAbsent -DataRoot $DataRoot
    }
    catch {
        [Array]::Clear($key, 0, $key.Length)
        throw
    }
    return ,$key
}

function Get-HHRuntimeContext {
    [CmdletBinding()]
    param([string]$DataRoot)

    $root = Resolve-HHDataRoot -DataRoot $DataRoot
    return Get-HHPersistenceContext -DataRoot $root
}
