[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$SourceRoot,

    [Parameter(Mandatory)]
    [string]$ArtifactRoot,

    [Parameter(Mandatory)]
    [string]$ProviderRoot,

    [Parameter(Mandatory)]
    [string]$MetadataRoot,

    [Parameter(Mandatory)]
    [string]$DurabilityHelperRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$source = (Resolve-Path -LiteralPath $SourceRoot).Path
$artifact = [System.IO.Path]::GetFullPath($ArtifactRoot)
$provider = (Resolve-Path -LiteralPath $ProviderRoot).Path
$metadata = (Resolve-Path -LiteralPath $MetadataRoot).Path
$durabilityHelper = (Resolve-Path -LiteralPath `
        (Join-Path $DurabilityHelperRoot 'HostHunter.Persistence.Durability.dll')).Path
$sourceManifestPath = Join-Path $source 'HostHunterNextGeneration.psd1'
$sourceManifest = Test-ModuleManifest -Path $sourceManifestPath -ErrorAction Stop
$expectedModuleVersion = $sourceManifest.Version.ToString()
$expectedPrerelease = [string]$sourceManifest.PrivateData.PSData.Prerelease
$expectedPackageVersion = if ([string]::IsNullOrWhiteSpace($expectedPrerelease)) {
    $expectedModuleVersion
}
else { "$expectedModuleVersion-$expectedPrerelease" }
$packageRoot = Join-Path $artifact "HostHunterNextGeneration/$expectedPackageVersion"
if (Test-Path -LiteralPath $packageRoot) {
    Remove-Item -LiteralPath $packageRoot -Recurse -Force
}
[System.IO.Directory]::CreateDirectory($packageRoot) | Out-Null
Copy-Item -Path (Join-Path $source '*') -Destination $packageRoot -Recurse -Force

$interopRoot = Join-Path $packageRoot 'Private/Interop'
[System.IO.Directory]::CreateDirectory($interopRoot) | Out-Null
$packagedDurabilityHelper = Join-Path $interopRoot 'HostHunter.Persistence.Durability.dll'
Copy-Item -LiteralPath $durabilityHelper -Destination $packagedDurabilityHelper
$durabilityAssembly = [Reflection.AssemblyName]::GetAssemblyName($packagedDurabilityHelper)
if ($durabilityAssembly.Name -cne 'HostHunter.Persistence.Durability' -or
    $durabilityAssembly.Version.ToString() -cne '0.1.0.0') {
    throw "Unexpected durable publication helper identity '$($durabilityAssembly.FullName)'."
}

$managedAssets = @(
    'Microsoft.Data.Sqlite.dll'
    'SQLitePCLRaw.batteries_v2.dll'
    'SQLitePCLRaw.core.dll'
    'SQLitePCLRaw.provider.e_sqlite3.dll'
)
$nativeAssets = [ordered]@{
    'linux-arm64' = 'libe_sqlite3.so'
    'linux-x64'   = 'libe_sqlite3.so'
}

foreach ($rid in $nativeAssets.Keys) {
    $sourceRidRoot = Join-Path $provider "lib/$rid"
    $destinationRidRoot = Join-Path $packageRoot "lib/$rid"
    [System.IO.Directory]::CreateDirectory($destinationRidRoot) | Out-Null

    $expectedAssets = @($managedAssets + $nativeAssets[$rid])
    $actualAssets = @(
        Get-ChildItem -LiteralPath $sourceRidRoot -File |
            Select-Object -ExpandProperty Name |
            Sort-Object
    )
    if (($actualAssets -join "`n") -cne (($expectedAssets | Sort-Object) -join "`n")) {
        throw "Unexpected locked provider inventory for RID '$rid'."
    }
    foreach ($assetName in $expectedAssets) {
        Copy-Item -LiteralPath (Join-Path $sourceRidRoot $assetName) `
            -Destination (Join-Path $destinationRidRoot $assetName)
    }
}

$metadataFiles = @(
    'packages.lock.json'
    'THIRD-PARTY-NOTICES.md'
    'sqlite-dependencies.cdx.json'
)
$dependencyMetadataRoot = Join-Path $packageRoot 'dependencies/sqlite'
[System.IO.Directory]::CreateDirectory($dependencyMetadataRoot) | Out-Null
foreach ($metadataFile in $metadataFiles) {
    Copy-Item -LiteralPath (Join-Path $metadata $metadataFile) `
        -Destination (Join-Path $dependencyMetadataRoot $metadataFile)
}
Copy-Item -LiteralPath (Join-Path $provider 'asset-sha256.txt') `
    -Destination (Join-Path $dependencyMetadataRoot 'asset-sha256.txt')

$manifestPath = Join-Path $packageRoot 'HostHunterNextGeneration.psd1'
$manifest = Test-ModuleManifest -Path $manifestPath -ErrorAction Stop
if ($manifest.Version.ToString() -ne $expectedModuleVersion) {
    throw "Unexpected packaged module version '$($manifest.Version)'."
}
$packagedPrerelease = [string]$manifest.PrivateData.PSData.Prerelease
if ($packagedPrerelease -cne $expectedPrerelease) {
    throw "Unexpected packaged prerelease label '$packagedPrerelease'."
}

Import-Module $manifestPath -Force -ErrorAction Stop
$expected = @(
    'Enable-HHSshKeyAuthentication'
    'Get-HHAuditOutput'
    'Get-HHAuditRecord'
    'Get-HHEscalationPreference'
    'Get-HHTarget'
    'Invoke-HHCommand'
    'Remove-HHTarget'
    'Set-HHEscalationPreference'
    'Set-HHTarget'
    'Set-HHWindowsProcessAuditPolicy'
    'Test-HHTarget'
)
$actual = @(Get-Command -Module HostHunterNextGeneration -CommandType Function |
        Select-Object -ExpandProperty Name | Sort-Object)
if (($actual -join "`n") -cne ($expected -join "`n")) {
    throw "Exported command drift. Expected $($expected -join ', '); got $($actual -join ', ')."
}

foreach ($commandName in $expected) {
    $help = Get-Help $commandName -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($help.Name)) {
        throw "Help could not be loaded for '$commandName'."
    }
}

$loadedSqliteAssemblies = @(
    [AppDomain]::CurrentDomain.GetAssemblies() |
        Where-Object { $_.GetName().Name -in @('Microsoft.Data.Sqlite', 'SQLitePCLRaw.core') }
)
if ($loadedSqliteAssemblies.Count -ne 0) {
    throw 'Module import or help eagerly loaded the SQLite provider.'
}

$lock = Get-Content -LiteralPath `
    (Join-Path $dependencyMetadataRoot 'packages.lock.json') -Raw |
    ConvertFrom-Json -Depth 20
$lockedDependencies = @(
    $lock.dependencies.'net8.0'.PSObject.Properties.Name | Sort-Object
)
$expectedDependencies = @(
    'Microsoft.Data.Sqlite.Core'
    'SQLite'
    'SQLitePCLRaw.bundle_e_sqlite3'
    'SQLitePCLRaw.config.e_sqlite3'
    'SQLitePCLRaw.core'
    'SQLitePCLRaw.provider.e_sqlite3'
) | Sort-Object
if (($lockedDependencies -join "`n") -cne ($expectedDependencies -join "`n")) {
    throw 'Locked SQLite package graph drifted from the approved six-package graph.'
}

$assetHashes = [ordered]@{}
foreach ($rid in $nativeAssets.Keys) {
    $assetHashes[$rid] = [ordered]@{}
    foreach ($asset in @(Get-ChildItem -LiteralPath (Join-Path $packageRoot "lib/$rid") -File |
            Sort-Object Name)) {
        $assetHashes[$rid][$asset.Name] = `
            (Get-FileHash -LiteralPath $asset.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}

$receipt = [ordered]@{
    status = 'passed'
    moduleVersion = $expectedPackageVersion
    packagePath = $packageRoot
    exports = $actual
    provider = [ordered]@{
        targetFramework = 'net8.0'
        managedProviderVersion = '10.0.11'
        sqlitePclRawVersion = '3.0.5'
        nativeSqliteVersion = '3.53.4'
        runtimeIdentifiers = @($nativeAssets.Keys)
        assetSha256 = $assetHashes
    }
    durabilityHelper = [ordered]@{
        targetFramework = 'net8.0'
        assemblyName = $durabilityAssembly.Name
        assemblyVersion = $durabilityAssembly.Version.ToString()
        relativePath = 'Private/Interop/HostHunter.Persistence.Durability.dll'
        sha256 = (Get-FileHash -LiteralPath $packagedDurabilityHelper -Algorithm SHA256).Hash.ToLowerInvariant()
        thirdPartyPackages = 0
    }
}
$receiptPath = Join-Path $artifact 'module-package.json'
$receipt | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $receiptPath -Encoding utf8NoBOM
$manifestPath | Set-Content -LiteralPath (Join-Path $artifact 'module-path.txt') `
    -Encoding utf8NoBOM -NoNewline
$receipt
