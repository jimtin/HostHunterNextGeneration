Set-StrictMode -Version Latest

$script:HHSqliteProviderInitialized = $false
$script:HHSqliteProviderRootOverride = $null
$script:HHSqliteExpectedProviderVersion = [version]'10.0.11.0'
$script:HHSqliteExpectedNativeVersion = '3.53.4'

function Resolve-HHSqliteControllerRid {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [string]$OperatingSystem,
        [string]$Architecture,
        [string]$RuntimeIdentifier
    )

    $os = if ($PSBoundParameters.ContainsKey('OperatingSystem')) {
        $OperatingSystem
    }
    elseif ($IsWindows) { 'Windows' }
    elseif ($IsMacOS) { 'macOS' }
    elseif ($IsLinux) { 'Linux' }
    else { 'Unknown' }

    $architectureName = if ($PSBoundParameters.ContainsKey('Architecture')) {
        $Architecture
    }
    else {
        [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()
    }
    $runtime = if ($PSBoundParameters.ContainsKey('RuntimeIdentifier')) {
        $RuntimeIdentifier
    }
    else {
        [System.Runtime.InteropServices.RuntimeInformation]::RuntimeIdentifier
    }
    if ($os -ceq 'Linux' -and $runtime -match 'musl') {
        Stop-HHPersistenceOperation `
            -ErrorId 'PersistenceRuntimeUnsupported' `
            -Message 'HostHunter SQLite persistence does not support musl Linux in this release.' `
            -Category ([System.Management.Automation.ErrorCategory]::NotImplemented) `
            -TargetObject $runtime
    }

    $rid = switch -CaseSensitive ("$os|$architectureName") {
        'macOS|Arm64' { 'osx-arm64'; break }
        'Linux|Arm64' { 'linux-arm64'; break }
        'Linux|X64' { 'linux-x64'; break }
        'Windows|X64' { 'win-x64'; break }
        default { $null }
    }
    if ($null -eq $rid) {
        Stop-HHPersistenceOperation `
            -ErrorId 'PersistenceRuntimeUnsupported' `
            -Message 'This controller operating system and architecture are not qualified for HostHunter SQLite persistence.' `
            -Category ([System.Management.Automation.ErrorCategory]::NotImplemented) `
            -TargetObject "$os/$architectureName"
    }
    return $rid
}

function Resolve-HHSqliteProviderRoot {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [string]$ProviderRoot,
        [string]$ControllerRid
    )

    $rid = if ([string]::IsNullOrWhiteSpace($ControllerRid)) {
        Resolve-HHSqliteControllerRid
    }
    else { $ControllerRid }
    $baseRoot = if (-not [string]::IsNullOrWhiteSpace($ProviderRoot)) {
        [System.IO.Path]::GetFullPath($ProviderRoot)
    }
    elseif (-not [string]::IsNullOrWhiteSpace($script:HHSqliteProviderRootOverride)) {
        [System.IO.Path]::GetFullPath($script:HHSqliteProviderRootOverride)
    }
    elseif (-not [string]::IsNullOrWhiteSpace($env:HH_SQLITE_PROVIDER_ROOT)) {
        [System.IO.Path]::GetFullPath($env:HH_SQLITE_PROVIDER_ROOT)
    }
    else {
        [System.IO.Path]::GetFullPath((Join-Path $script:HHModuleRoot 'lib'))
    }
    $candidate = [System.IO.Path]::GetFullPath((Join-Path $baseRoot $rid))
    $relative = [System.IO.Path]::GetRelativePath($baseRoot, $candidate)
    if ($relative -eq '..' -or $relative.StartsWith("..$([System.IO.Path]::DirectorySeparatorChar)")) {
        Stop-HHPersistenceOperation `
            -ErrorId 'PersistenceRuntimeUnsupported' `
            -Message 'The SQLite provider path escapes its packaged root.' `
            -Category ([System.Management.Automation.ErrorCategory]::SecurityError) `
            -TargetObject $candidate
    }
    return $candidate
}

function Get-HHSqliteProviderAssetName {
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)][string]$ControllerRid)

    $nativeName = if ($ControllerRid -ceq 'win-x64') {
        'e_sqlite3.dll'
    }
    elseif ($ControllerRid -ceq 'osx-arm64') {
        'libe_sqlite3.dylib'
    }
    else {
        'libe_sqlite3.so'
    }
    @(
        'SQLitePCLRaw.core.dll'
        'SQLitePCLRaw.provider.e_sqlite3.dll'
        'SQLitePCLRaw.batteries_v2.dll'
        'Microsoft.Data.Sqlite.dll'
        $nativeName
    )
}

function Initialize-HHSqliteProvider {
    [CmdletBinding()]
    param(
        [string]$ProviderRoot,
        [scriptblock]$AssemblyLoader,
        [scriptblock]$BatteriesInitializer
    )

    if ($script:HHSqliteProviderInitialized) {
        return
    }
    $rid = Resolve-HHSqliteControllerRid
    $ridRoot = Resolve-HHSqliteProviderRoot -ProviderRoot $ProviderRoot -ControllerRid $rid
    $assets = Get-HHSqliteProviderAssetName -ControllerRid $rid
    foreach ($asset in $assets) {
        $assetPath = Join-Path $ridRoot $asset
        if (-not [System.IO.File]::Exists($assetPath)) {
            Stop-HHPersistenceOperation `
                -ErrorId 'PersistenceRuntimeUnsupported' `
                -Message "A required packaged SQLite asset is missing: $asset." `
                -Category ([System.Management.Automation.ErrorCategory]::ResourceUnavailable) `
                -TargetObject $assetPath
        }
    }

    if ($null -eq $AssemblyLoader) {
        $AssemblyLoader = { param($Path) [System.Reflection.Assembly]::LoadFrom($Path) }
    }
    foreach ($managedAsset in @($assets | Where-Object { $_.EndsWith('.dll') -and $_ -ne 'e_sqlite3.dll' })) {
        $null = & $AssemblyLoader (Join-Path $ridRoot $managedAsset)
    }
    if ($null -eq $BatteriesInitializer) {
        [SQLitePCL.Batteries_V2]::Init()
    }
    else {
        & $BatteriesInitializer
    }

    $providerVersion = [Microsoft.Data.Sqlite.SqliteConnection].Assembly.GetName().Version
    if ($providerVersion -ne $script:HHSqliteExpectedProviderVersion) {
        Stop-HHPersistenceOperation `
            -ErrorId 'PersistenceRuntimeUnsupported' `
            -Message 'The loaded Microsoft.Data.Sqlite provider version is not the locked version.' `
            -Category ([System.Management.Automation.ErrorCategory]::SecurityError) `
            -TargetObject $providerVersion
    }
    $script:HHSqliteProviderInitialized = $true
}
