[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path,
    [string]$VisualizerRepoRoot,
    [string]$UserHome = $HOME,
    [string]$ProfilePath = $PROFILE.CurrentUserAllHosts,
    [switch]$SkipProfile
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path -LiteralPath $RepoRoot).Path
$visualizerRepo = $null
if (-not [string]::IsNullOrWhiteSpace($VisualizerRepoRoot)) {
    $visualizerRepo = (Resolve-Path -LiteralPath $VisualizerRepoRoot).Path
    foreach ($relativePath in @('scripts/up.sh','scripts/down.sh','scripts/bootstrap-secrets.sh','compose.yaml')) {
        if (-not [IO.File]::Exists((Join-Path $visualizerRepo $relativePath))) {
            throw "The visualizer repository is missing '$relativePath'."
        }
    }
}
$source = Join-Path $repo 'client/HostHunter.Client'
$manifest = Import-PowerShellDataFile (Join-Path $source 'HostHunter.Client.psd1')
$version = [string]$manifest.ModuleVersion
$moduleRoot = Join-Path $UserHome ".local/share/powershell/Modules/HostHunter.Client/$version"
$configurationRoot = if (-not [string]::IsNullOrWhiteSpace($env:XDG_CONFIG_HOME)) {
    $env:XDG_CONFIG_HOME
} else { Join-Path $UserHome '.config' }
$configurationPath = Join-Path $configurationRoot 'hosthunter/client.json'

if (-not $PSCmdlet.ShouldProcess($moduleRoot, 'Install HostHunter.Client')) { return }
[IO.Directory]::CreateDirectory($moduleRoot) | Out-Null
Copy-Item -LiteralPath (Join-Path $source 'HostHunter.Client.psd1') -Destination $moduleRoot -Force
Copy-Item -LiteralPath (Join-Path $source 'HostHunter.Client.psm1') -Destination $moduleRoot -Force
$privateSource = Join-Path $source 'Private'
$privateDestination = Join-Path $moduleRoot 'Private'
if ([IO.Directory]::Exists($privateSource)) {
    [IO.Directory]::CreateDirectory($privateDestination) | Out-Null
    Copy-Item -Path (Join-Path $privateSource '*') -Destination $privateDestination `
        -Recurse -Force
}
[IO.Directory]::CreateDirectory((Split-Path -Parent $configurationPath)) | Out-Null
[IO.File]::WriteAllText(
    $configurationPath,
    ([ordered]@{
            schema = 'HostHunter.ClientConfiguration.v2'
            repoRoot = $repo
            visualizerRepoRoot = $visualizerRepo
            visualizerUrl = 'http://127.0.0.1:4310'
        } |
        ConvertTo-Json -Compress),
    [Text.UTF8Encoding]::new($false)
)
if (-not $IsWindows) {
    [IO.File]::SetUnixFileMode(
        $configurationPath,
        [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite
    )
}

if ($null -ne $visualizerRepo) {
    $bootstrap = Join-Path $visualizerRepo 'scripts/bootstrap-secrets.sh'
    $bootstrapOutput = @(& /usr/bin/env bash $bootstrap 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "Visualizer credential bootstrap failed: $([string]::Join([Environment]::NewLine, $bootstrapOutput))"
    }
}

if (-not $SkipProfile) {
    $profilePath = $ProfilePath
    [IO.Directory]::CreateDirectory((Split-Path -Parent $profilePath)) | Out-Null
    $begin = '# HostHunter.Client auto-import begin'
    $end = '# HostHunter.Client auto-import end'
    $existing = if ([IO.File]::Exists($profilePath)) {
        [IO.File]::ReadAllText($profilePath)
    } else { '' }
    $sourceManifest = Join-Path $source 'HostHunter.Client.psd1'
    $quotedSourceManifest = "'" + $sourceManifest.Replace("'", "''") + "'"
    $block = @(
        $begin
        "Import-Module $quotedSourceManifest -Force -ErrorAction Stop"
        $end
        ''
    ) -join "`n"
    $markedBlockPattern = '(?ms)^' + [regex]::Escape($begin) +
        '.*?^' + [regex]::Escape($end) + '\r?\n?'
    if ($existing -match [regex]::Escape($begin)) {
        $existing = [regex]::new($markedBlockPattern).Replace($existing, $block, 1)
        [IO.File]::WriteAllText($profilePath, $existing, [Text.UTF8Encoding]::new($false))
    }
    else {
        if ($existing.Length -gt 0 -and -not $existing.EndsWith("`n")) { $existing += "`n" }
        [IO.File]::WriteAllText($profilePath, "$existing$block", [Text.UTF8Encoding]::new($false))
    }
}

[pscustomobject]@{
    ModulePath = $moduleRoot
    ConfigurationPath = $configurationPath
    VisualizerRepoRoot = $visualizerRepo
    ProfilePath = if ($SkipProfile) { $null } else { $ProfilePath }
}
