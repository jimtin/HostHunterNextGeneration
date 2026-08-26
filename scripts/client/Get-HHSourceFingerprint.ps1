[CmdletBinding()]
param([Parameter(Mandatory)][string]$RepoRoot)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$resolvedRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$scopes = @(
    '.dockerignore', 'Dockerfile.runtime', 'compose.runtime.yml',
    'src/HostHunterNextGeneration', 'eng/durability', 'eng/sqlite',
    'scripts/build', 'scripts/runtime'
)
$relativeFiles = @(& git -C $resolvedRoot ls-files --cached --others `
        --exclude-standard -- @scopes | Sort-Object -Unique)
if ($LASTEXITCODE -ne 0 -or $relativeFiles.Count -eq 0) {
    throw 'Unable to inventory HostHunter runtime source files.'
}
$builder = [Text.StringBuilder]::new()
foreach ($relativePath in $relativeFiles) {
    $fullPath = Join-Path $resolvedRoot $relativePath
    if (-not [IO.File]::Exists($fullPath)) { continue }
    $hash = (Get-FileHash -LiteralPath $fullPath -Algorithm SHA256).Hash.ToLowerInvariant()
    [void]$builder.Append($relativePath.Replace('\', '/')).Append("`0").Append($hash).Append("`n")
}
$bytes = [Text.Encoding]::UTF8.GetBytes($builder.ToString())
[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
