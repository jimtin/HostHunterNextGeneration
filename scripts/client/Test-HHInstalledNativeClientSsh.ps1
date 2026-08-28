[CmdletBinding()]
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path,
    [ValidateRange(30, 900)][int]$TimeoutSeconds = 300
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path -LiteralPath $RepoRoot).Path
$installer = Join-Path $repo 'scripts/client/Install-HHClient.ps1'
$journey = Join-Path $repo 'scripts/client/Test-HHNativeClientSsh.ps1'
$temporaryHome = Join-Path ([IO.Path]::GetTempPath()) (
    'hosthunter-installed-client-' + [Guid]::NewGuid().ToString('N')
)
$configurationRoot = Join-Path $temporaryHome '.config'
$profilePath = Join-Path $configurationRoot 'powershell/profile.ps1'
$previousConfigurationRoot = $env:XDG_CONFIG_HOME
$previousRuntimeProject = $env:HH_RUNTIME_PROJECT
$runtimeProject = 'hosthunter-native-runtime-' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
$fixtureProject = 'hosthunter-native-fixture-' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
$composeFile = Join-Path $repo 'compose.test.yml'
$runtimeScript = Join-Path $repo 'scripts/runtime/hosthunter.sh'
$testHelpers = Join-Path $repo 'scripts/client/NativeClientTestHelpers.ps1'
. $testHelpers
$dockerConfigurationRoot = if (-not [string]::IsNullOrWhiteSpace($env:DOCKER_CONFIG)) {
    $env:DOCKER_CONFIG
}
else { Join-Path $HOME '.docker' }

try {
    & docker compose --project-name $fixtureProject -f $composeFile up --detach --wait ssh-target
    if ($LASTEXITCODE -ne 0) { throw 'The disposable native-client SSH fixture failed to start.' }
    [IO.Directory]::CreateDirectory($temporaryHome) | Out-Null
    $env:XDG_CONFIG_HOME = $configurationRoot
    $null = & $installer -RepoRoot $repo -UserHome $temporaryHome `
        -ProfilePath $profilePath -Confirm:$false
    if (-not [IO.File]::Exists($profilePath)) {
        throw 'The HostHunter client installer did not create the PowerShell profile entry.'
    }

    $escapedJourney = $journey.Replace("'", "''")
    $escapedRepo = $repo.Replace("'", "''")
    $escapedHelpers = $testHelpers.Replace("'", "''")
    $workerCommand = @"
. '$escapedHelpers'
`$journeyParameters = @{
    RepoRoot = '$escapedRepo'
    RequireProfileLoadedClient = `$true
    RuntimeProject = '$runtimeProject'
    FixtureProject = '$fixtureProject'
}
`$items = @(& '$escapedJourney' @journeyParameters)
`$result = Select-HHNativeClientTerminalResult -InputObject `$items
'HH_NATIVE_CLIENT_RESULT=' + (`$result | ConvertTo-Json -Compress -Depth 8)
"@
    $encodedCommand = [Convert]::ToBase64String(
        [Text.Encoding]::Unicode.GetBytes($workerCommand)
    )
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = 'pwsh'
    foreach ($argument in @('-NoLogo', '-EncodedCommand', $encodedCommand)) {
        [void]$startInfo.ArgumentList.Add($argument)
    }
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.Environment['HOME'] = $temporaryHome
    $startInfo.Environment['XDG_CONFIG_HOME'] = $configurationRoot
    $startInfo.Environment['HH_CLIENT_REPO_ROOT'] = $repo
    $startInfo.Environment['HH_RUNTIME_PROJECT'] = $runtimeProject
    $startInfo.Environment['DOCKER_CONFIG'] = $dockerConfigurationRoot
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    if (-not $process.Start()) {
        throw 'Unable to start the fresh PowerShell profile qualification process.'
    }
    try {
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            $process.Kill($true)
            throw "The installed-client macOS journey exceeded $TimeoutSeconds seconds."
        }
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) {
            $failure = Format-HHNativeClientFailure -StandardError $stderr `
                -StandardOutput $stdout
            throw "The installed-client macOS journey failed. $failure".Trim()
        }
    }
    finally { $process.Dispose() }

    $resultLine = @($stdout -split "`r?`n" | Where-Object {
            $_.StartsWith('HH_NATIVE_CLIENT_RESULT=', [StringComparison]::Ordinal)
        }) | Select-Object -Last 1
    if ([string]::IsNullOrWhiteSpace($resultLine)) {
        throw 'The installed-client macOS journey did not emit its terminal result.'
    }
    $result = $resultLine.Substring('HH_NATIVE_CLIENT_RESULT='.Length) |
        ConvertFrom-Json -Depth 8
    if ($result.Status -cne 'passed' -or
        $result.ClientLoad -cne 'fresh-process-installed-profile' -or
        [int]$result.InvokedUniqueCommandCount -ne 12) {
        throw 'The installed-client macOS journey returned an invalid terminal result.'
    }
    $result
}
finally {
    $env:XDG_CONFIG_HOME = $previousConfigurationRoot
    $previousErrorAction = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $env:HH_RUNTIME_PROJECT = $runtimeProject
    & /usr/bin/env bash $runtimeScript destroy --confirm-project $runtimeProject --destroy-volumes | Out-Null
    & docker compose --project-name $fixtureProject -f $composeFile down --volumes --remove-orphans | Out-Null
    $env:HH_RUNTIME_PROJECT = $previousRuntimeProject
    $ErrorActionPreference = $previousErrorAction
    if ([IO.Directory]::Exists($temporaryHome)) {
        [IO.Directory]::Delete($temporaryHome, $true)
    }
}
