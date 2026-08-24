[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$SourceRoot,

    [Parameter(Mandatory)]
    [string]$OutputRoot,

    [Parameter(Mandatory)]
    [string]$ManifestPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$resolvedSource = (Resolve-Path -LiteralPath $SourceRoot).Path
$resolvedOutput = [System.IO.Path]::GetFullPath($OutputRoot)
if ($resolvedOutput.StartsWith($resolvedSource, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'The instrumented output must be outside the production source tree.'
}

[System.IO.Directory]::CreateDirectory($resolvedOutput) | Out-Null
$sourceFiles = @(Get-ChildItem -LiteralPath $resolvedSource -Recurse -File)
if (@($sourceFiles | Where-Object { $_.Extension -in @('.ps1', '.psm1') }).Count -eq 0) {
    throw 'No instrumentable PowerShell source files were found.'
}

$manifests = [System.Collections.Generic.List[object]]::new()
foreach ($sourceFile in $sourceFiles) {
    $relativePath = [System.IO.Path]::GetRelativePath($resolvedSource, $sourceFile.FullName)
    $destination = Join-Path $resolvedOutput $relativePath
    [System.IO.Directory]::CreateDirectory((Split-Path -Parent $destination)) | Out-Null

    if ($sourceFile.Extension -in @('.ps1', '.psm1')) {
        $fileManifest = "$destination.branch-manifest.json"
        & (Join-Path $PSScriptRoot 'Instrument-HHBranches.ps1') `
            -Path $sourceFile.FullName `
            -OutputPath $destination `
            -ManifestPath $fileManifest
        $manifests.Add((Get-Content -LiteralPath $fileManifest -Raw | ConvertFrom-Json))
        Remove-Item -LiteralPath $fileManifest -Force
    }
    else {
        Copy-Item -LiteralPath $sourceFile.FullName -Destination $destination -Force
    }
}

$sourceHashes = @($manifests | ForEach-Object sourceSha256 | Sort-Object)
$aggregateHashBytes = [System.Text.Encoding]::UTF8.GetBytes(($sourceHashes -join "`n"))
$aggregateHash = [Convert]::ToHexString(
    [System.Security.Cryptography.SHA256]::HashData($aggregateHashBytes)
).ToLowerInvariant()
$branches = @($manifests | ForEach-Object { @($_.branches) })
$aggregate = [ordered]@{
    schemaVersion = 2
    source = $resolvedSource
    sourceSha256 = $aggregateHash
    branchCount = $branches.Count
    outcomeCount = @($branches | ForEach-Object { @($_.outcomes) }).Count
    branches = $branches
}

$manifestDirectory = Split-Path -Parent $ManifestPath
if ($manifestDirectory) {
    [System.IO.Directory]::CreateDirectory($manifestDirectory) | Out-Null
}
$aggregate | ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $ManifestPath -Encoding utf8NoBOM

[pscustomobject]@{
    SourceRoot = $resolvedSource
    OutputRoot = $resolvedOutput
    Files = $sourceFiles.Count
    Branches = $aggregate.branchCount
    Outcomes = $aggregate.outcomeCount
    Manifest = [System.IO.Path]::GetFullPath($ManifestPath)
}
