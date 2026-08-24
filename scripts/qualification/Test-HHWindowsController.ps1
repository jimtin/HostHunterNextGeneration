[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$CandidateSha,
    [Parameter(Mandatory)][string]$PackageArchivePath,
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9._-]+$')][string]$SshHost,
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9._-]+$')][string]$UserName,
    [Parameter(Mandatory)]
    [ValidatePattern('^SHA256:[A-Za-z0-9+/]{43}$')]
    [string]$HostKeyFingerprint,
    [ValidateRange(1, 65535)][int]$Port = 22,
    [string]$ReceiptPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $IsMacOS) {
    throw 'The Windows qualification must run from the qualified macOS HostHunter controller.'
}
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '../..')).Path
$archive = (Resolve-Path -LiteralPath $PackageArchivePath).Path
$candidateReceiptPath = Join-Path $repoRoot ".artifacts/release/$CandidateSha/receipt.json"
if (-not [IO.File]::Exists($candidateReceiptPath)) {
    throw 'The exact-candidate receipt is missing.'
}
$candidateReceipt = Get-Content -LiteralPath $candidateReceiptPath -Raw | ConvertFrom-Json
$packageSha256 = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
if ($candidateReceipt.status -cne 'passed' -or
    $candidateReceipt.candidateSha -cne $CandidateSha -or
    $candidateReceipt.packageArchiveSha256 -cne $packageSha256) {
    throw 'The package archive is not bound to the successful exact-candidate receipt.'
}
$head = (& git -C $repoRoot rev-parse HEAD).Trim()
$status = @(& git -C $repoRoot status --porcelain=v1 --untracked-files=all)
if ($LASTEXITCODE -ne 0 -or $head -cne $CandidateSha -or $status.Count -ne 0) {
    throw 'Windows qualification requires the clean exact candidate at repository HEAD.'
}

if ([string]::IsNullOrWhiteSpace($ReceiptPath)) {
    $ReceiptPath = Join-Path $repoRoot ".artifacts/qualification/windows/$CandidateSha/receipt.json"
}
$receipt = [IO.Path]::GetFullPath($ReceiptPath)
$startedAt = [DateTimeOffset]::UtcNow
$dataRoot = Join-Path ([IO.Path]::GetTempPath()) (
    'hosthunter-windows-qualification-' + [Guid]::NewGuid().ToString('N')
)
$extractRoot = Join-Path ([IO.Path]::GetTempPath()) (
    'hosthunter-windows-package-' + [Guid]::NewGuid().ToString('N')
)
$remoteArchiveName = 'HostHunterNextGeneration-' + [Guid]::NewGuid().ToString('N') + '.tar.gz'
$module = $null
$keychainAccount = $null
$keychainPath = $null
$exactInstalledKeyLine = $null
$remoteKeyRemoved = $false
$cleanupComplete = $false
$nativeProof = $null
$directResult = $null
$compatibilityResult = $null
$mixedResult = @()
$keyResult = $null

function Invoke-HHInteractiveNativeProcess {
    param(
        [Parameter(Mandatory)][string]$FileName,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$ArgumentList,
        [switch]$CaptureOutput,
        [ValidateRange(1, 1800)][int]$TimeoutSeconds = 300
    )

    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FileName
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = [bool]$CaptureOutput
    $startInfo.RedirectStandardError = $false
    foreach ($argument in $ArgumentList) {
        $null = $startInfo.ArgumentList.Add($argument)
    }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    if (-not $process.Start()) {
        throw "The native qualification process '$FileName' did not start."
    }
    try {
        $outputTask = if ($CaptureOutput) {
            $process.StandardOutput.ReadToEndAsync()
        }
        else { $null }
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            $process.Kill($true)
            $process.WaitForExit()
            throw "The native qualification process '$FileName' timed out."
        }
        $output = if ($null -ne $outputTask) { $outputTask.GetAwaiter().GetResult() } else { '' }
        if ($process.ExitCode -ne 0) {
            throw "The native qualification process '$FileName' failed with exit code $($process.ExitCode)."
        }
        return $output
    }
    finally { $process.Dispose() }
}

function Invoke-HHQualificationSecurityDelete {
    param(
        [Parameter(Mandatory)][string]$Service,
        [Parameter(Mandatory)][string]$Account,
        [Parameter(Mandatory)][string]$LoginKeychain
    )

    $null = Invoke-HHInteractiveNativeProcess -FileName '/usr/bin/security' `
        -ArgumentList @(
            'delete-generic-password', '-s', $Service, '-a', $Account, $LoginKeychain
        ) -CaptureOutput -TimeoutSeconds 15
}

function Get-HHRemoteWindowsBootstrapScript {
    param(
        [Parameter(Mandatory)][string]$ArchiveName,
        [Parameter(Mandatory)][string]$ExpectedSha256
    )

    $scriptText = @'
$ErrorActionPreference = 'Stop'
$archivePath = Join-Path $HOME '__ARCHIVE_NAME__'
$stageRoot = Join-Path $env:TEMP ('hosthunter-package-' + [Guid]::NewGuid().ToString('N'))
$dataRoot = Join-Path $env:TEMP ('hosthunter-data-' + [Guid]::NewGuid().ToString('N'))
$module = $null
try {
    $actualHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -cne '__ARCHIVE_SHA256__') { throw 'Remote package hash mismatch.' }
    [IO.Directory]::CreateDirectory($stageRoot) | Out-Null
    & tar -xzf $archivePath -C $stageRoot
    if ($LASTEXITCODE -ne 0) { throw 'Remote package extraction failed.' }
    $manifest = Get-ChildItem -LiteralPath $stageRoot -Recurse `
        -Filter HostHunterNextGeneration.psd1 -File | Select-Object -First 1
    if ($null -eq $manifest) { throw 'Remote module manifest is missing.' }
    $env:HH_DATA_ROOT = $dataRoot
    $module = Import-Module $manifest.FullName -Force -PassThru
    $proof = & $module {
        $runtime = Get-HHRuntimeContext
        $context = Open-HHAuthenticatedPersistence `
            -PersistenceContext $runtime -AllowAnchorAdvance
        try {
            $sqliteVersion = [string](Invoke-HHSqliteScalar `
                    -Connection $context.Connection -Sql 'SELECT sqlite_version();')
        }
        finally { Close-HHAuthenticatedPersistence -Context $context }
        $paths = @(
            @{ Path = $runtime.DataRoot; Directory = $true },
            @{ Path = $runtime.DatabasePath; Directory = $false },
            @{ Path = (Join-Path $runtime.AuditRoot 'audit.key'); Directory = $false },
            @{ Path = $runtime.AnchorPath; Directory = $false }
        )
        foreach ($item in $paths) {
            Assert-HHWindowsPrivatePathAcl `
                -Path $item.Path -Directory:$item.Directory
            if ((Get-Item -LiteralPath $item.Path -Force).Attributes -band `
                [IO.FileAttributes]::ReparsePoint) {
                throw 'A Windows persistence path is a reparse point.'
            }
        }
        $publishRoot = Join-Path $runtime.DataRoot 'durability-proof'
        [IO.Directory]::CreateDirectory($publishRoot) | Out-Null
        $source = Join-Path $publishRoot 'source.tmp'
        $destination = Join-Path $publishRoot 'destination.bin'
        [IO.File]::WriteAllText($source, 'durable-windows-proof')
        Publish-HHDurableFile -SourcePath $source -DestinationPath $destination
        if ([IO.File]::Exists($source) -or
            [IO.File]::ReadAllText($destination) -cne 'durable-windows-proof') {
            throw 'Native Windows durable publication proof failed.'
        }
        [pscustomobject]@{
            SQLiteVersion = $sqliteVersion
            PowerShellVersion = $PSVersionTable.PSVersion.ToString()
            PSEdition = $PSVersionTable.PSEdition
            PathAclCount = $paths.Count
            DurablePublish = $true
        }
    }
    $proof | ConvertTo-Json -Compress
}
finally {
    if ($null -ne $module) { Remove-Module $module -Force -ErrorAction SilentlyContinue }
    Remove-Item -LiteralPath $dataRoot -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $stageRoot -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $archivePath -Force -ErrorAction SilentlyContinue
}
'@
    return $scriptText.Replace('__ARCHIVE_NAME__', $ArchiveName).
        Replace('__ARCHIVE_SHA256__', $ExpectedSha256)
}

function Assert-HHRuntimeResult {
    param(
        [Parameter(Mandatory)][object]$Result,
        [Parameter(Mandatory)][ValidateSet('PowerShell7', 'WindowsPowerShell51')]
        [string]$Runtime
    )

    if (-not $Result.Succeeded -or $Result.DispatchState -cne 'Completed' -or
        $Result.OutcomeStatus -cne 'Succeeded') {
        throw "The $Runtime qualification command did not complete successfully."
    }
    if ($Runtime -ceq 'PowerShell7') {
        if ($Result.RemotePSEdition -cne 'Core' -or $Result.ExecutionMode -cne 'Direct' -or
            [version]$Result.RemotePowerShellVersion -lt [version]'7.0') {
            throw 'The direct PowerShell 7 identity is invalid.'
        }
    }
    elseif ($Result.RemotePSEdition -cne 'Desktop' -or
        $Result.ExecutionMode -cne 'WindowsPowerShellCompatibility' -or
        [version]$Result.RemotePowerShellVersion -lt [version]'5.1' -or
        [version]$Result.RemotePowerShellVersion -ge [version]'5.2') {
        throw 'The Windows PowerShell 5.1 compatibility identity is invalid.'
    }
    $streams = @($Result.StreamEvents.Stream | Sort-Object -Unique)
    foreach ($requiredStream in @('Output', 'Error', 'Warning', 'Verbose', 'Debug', 'Information')) {
        if ($streams -cnotcontains $requiredStream) {
            throw "The $Runtime result is missing the $requiredStream stream."
        }
    }
}

try {
    [IO.Directory]::CreateDirectory($extractRoot) | Out-Null
    & tar -xzf $archive -C $extractRoot
    if ($LASTEXITCODE -ne 0) { throw 'Candidate package extraction failed.' }
    $manifest = Get-ChildItem -LiteralPath $extractRoot -Recurse `
        -Filter HostHunterNextGeneration.psd1 -File | Select-Object -First 1
    if ($null -eq $manifest) { throw 'Candidate module manifest is missing.' }
    $env:HH_DATA_ROOT = $dataRoot
    $module = Import-Module $manifest.FullName -Force -PassThru
    $identity = & $module {
        param($QualificationDataRoot)
        [pscustomobject]@{
            Account = Get-HHAuditKeychainAccount -DataRoot $QualificationDataRoot
            KeychainPath = Get-HHMacOSLoginKeychainPath
        }
    } $dataRoot
    $keychainAccount = [string]$identity.Account
    $keychainPath = [string]$identity.KeychainPath

    $null = Invoke-HHInteractiveNativeProcess -FileName 'scp' -ArgumentList @(
        '-P', [string]$Port, $archive, "${UserName}@${SshHost}:$remoteArchiveName"
    ) -TimeoutSeconds 300
    $remoteScript = Get-HHRemoteWindowsBootstrapScript `
        -ArchiveName $remoteArchiveName -ExpectedSha256 $packageSha256
    $encodedRemoteScript = [Convert]::ToBase64String(
        [Text.Encoding]::Unicode.GetBytes($remoteScript)
    )
    $remoteOutput = Invoke-HHInteractiveNativeProcess -FileName 'ssh' -ArgumentList @(
        '-p', [string]$Port, "${UserName}@${SshHost}",
        'pwsh', '-NoLogo', '-NoProfile', '-EncodedCommand', $encodedRemoteScript
    ) -CaptureOutput -TimeoutSeconds 300
    $nativeProofLine = @($remoteOutput -split "`r?`n" | Where-Object {
            -not [string]::IsNullOrWhiteSpace($_)
        })[-1]
    $nativeProof = $nativeProofLine | ConvertFrom-Json
    if ($nativeProof.PSEdition -cne 'Core' -or
        [version]$nativeProof.PowerShellVersion -lt [version]'7.4' -or
        $nativeProof.SQLiteVersion -cne '3.53.4' -or
        [int]$nativeProof.PathAclCount -ne 4 -or
        -not [bool]$nativeProof.DurablePublish) {
        throw 'The native Windows package, provider, ACL, or durability proof failed.'
    }

    $null = Set-HHTarget -Name windows-ps7 -HostName $SshHost -Port $Port `
        -UserName $UserName -Authentication Password -PowerShellRuntime PowerShell7 `
        -HostKeyFingerprint $HostKeyFingerprint -Confirm:$false
    $null = Set-HHTarget -Name windows-ps51 -HostName $SshHost -Port $Port `
        -UserName $UserName -Authentication Password `
        -PowerShellRuntime WindowsPowerShell51 `
        -HostKeyFingerprint $HostKeyFingerprint -Add -Confirm:$false

    $streamCommand = @'
Write-Output 'output'
Write-Warning 'warning'
Write-Verbose 'verbose' -Verbose
Write-Debug 'debug' -Debug
Write-Information 'information' -InformationAction Continue
Write-Error 'error' -ErrorAction Continue
'@
    $directResult = Invoke-HHCommand -Command $streamCommand -Target windows-ps7
    $compatibilityResult = Invoke-HHCommand -Command $streamCommand -Target windows-ps51
    Assert-HHRuntimeResult -Result $directResult -Runtime PowerShell7
    Assert-HHRuntimeResult -Result $compatibilityResult -Runtime WindowsPowerShell51
    $mixedResult = @(Invoke-HHCommand -Command $streamCommand `
            -Target windows-ps7, windows-ps51 -ThrottleLimit 2)
    if ($mixedResult.Count -ne 2 -or
        @(Compare-Object `
                -ReferenceObject @('windows-ps51', 'windows-ps7') `
                -DifferenceObject @($mixedResult.Target | Sort-Object) `
                -CaseSensitive).Count -ne 0) {
        throw 'The mixed-runtime qualification did not preserve both target identities.'
    }
    foreach ($result in $mixedResult) {
        Assert-HHRuntimeResult -Result $result -Runtime $result.PowerShellRuntime
    }

    $transition = Enable-HHSshKeyAuthentication `
        -Name windows-ps7 -Confirm:$false
    if ($transition.Authentication -cne 'PublicKey') {
        throw 'The password-to-key transition did not commit a public-key profile.'
    }
    $keyMaterial = & $module {
        param($KeyPath)
        Get-HHSshBootstrapPublicKey -KeyPath $KeyPath
    } $transition.KeyPath
    $exactInstalledKeyLine = [string]$keyMaterial.ExactLine
    $keyResult = Invoke-HHCommand -Command "'key-proof'" -Target windows-ps7
    if (-not $keyResult.Succeeded) { throw 'The committed key profile could not execute.' }

    $passwordOutput = Invoke-HHInteractiveNativeProcess -FileName 'ssh' -ArgumentList @(
        '-o', 'PubkeyAuthentication=no', '-o', 'PreferredAuthentications=password',
        '-p', [string]$Port, "${UserName}@${SshHost}",
        'pwsh', '-NoLogo', '-NoProfile', '-Command', "'HH_PASSWORD_AUTH_STILL_ENABLED'"
    ) -CaptureOutput -TimeoutSeconds 120
    if ($passwordOutput.Trim() -cne 'HH_PASSWORD_AUTH_STILL_ENABLED') {
        throw 'Password authentication was not independently proven after key installation.'
    }

    $rollbackText = & $module {
        (Get-HHSshAuthorizedKeyRollbackScriptBlock).ToString()
    }
    $escapedLine = $exactInstalledKeyLine.Replace("'", "''")
    $cleanupCommand = "& { $rollbackText } -ExactLine '$escapedLine'"
    $cleanupResult = Invoke-HHCommand -Command $cleanupCommand -Target windows-ps7
    $rollbackReceipt = @($cleanupResult.StreamEvents | Where-Object {
            $_.Stream -ceq 'Output' -and
            $null -ne $_.Value.PSObject.Properties['Operation'] -and
            $_.Value.Operation -ceq 'HostHunterAuthorizedKeyRollback.v1'
        })
    $remoteKeyRemoved = $cleanupResult.Succeeded -and
        $rollbackReceipt.Count -eq 1 -and
        [bool]$rollbackReceipt[0].Value.Removed -and
        -not [bool]$rollbackReceipt[0].Value.PresentAfter
    if (-not $remoteKeyRemoved) {
        throw 'The exact HostHunter qualification key was not removed remotely.'
    }

    $null = Remove-HHTarget -Name windows-ps7, windows-ps51 -Confirm:$false
}
finally {
    if ($remoteKeyRemoved -and
        -not [string]::IsNullOrWhiteSpace($keychainAccount) -and
        -not [string]::IsNullOrWhiteSpace($keychainPath)) {
        Invoke-HHQualificationSecurityDelete `
            -Service 'com.hosthunter.nextgeneration.audit-master-key' `
            -Account $keychainAccount -LoginKeychain $keychainPath
        Invoke-HHQualificationSecurityDelete `
            -Service 'com.hosthunter.nextgeneration.database-anchor.v1' `
            -Account $keychainAccount -LoginKeychain $keychainPath
        Remove-Item -LiteralPath $dataRoot -Recurse -Force -ErrorAction Stop
        $cleanupComplete = $true
    }
    if ($null -ne $module) {
        Remove-Module $module -Force -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $extractRoot -Recurse -Force -ErrorAction SilentlyContinue
    $env:HH_DATA_ROOT = $null
}

if (-not $cleanupComplete) {
    throw 'Windows qualification cleanup was not proven; local recovery state was preserved.'
}
[IO.Directory]::CreateDirectory((Split-Path -Parent $receipt)) | Out-Null
[ordered]@{
    status = 'passed'
    candidateSha = $CandidateSha
    packageArchiveSha256 = $packageSha256
    controllerPlatform = 'macOS'
    targetPlatform = 'Windows'
    targetPowerShellVersion = [string]$nativeProof.PowerShellVersion
    sqliteVersion = [string]$nativeProof.SQLiteVersion
    privateAclPathsVerified = [int]$nativeProof.PathAclCount
    durablePublicationVerified = [bool]$nativeProof.DurablePublish
    directRuntime = [string]$directResult.PowerShellRuntime
    directEdition = [string]$directResult.RemotePSEdition
    directExecutionMode = [string]$directResult.ExecutionMode
    compatibilityRuntime = [string]$compatibilityResult.PowerShellRuntime
    compatibilityEdition = [string]$compatibilityResult.RemotePSEdition
    compatibilityExecutionMode = [string]$compatibilityResult.ExecutionMode
    mixedTargetCount = $mixedResult.Count
    keyTransitionSucceeded = [bool]$keyResult.Succeeded
    passwordAuthenticationPreserved = $true
    remoteQualificationKeyRemoved = $remoteKeyRemoved
    cleanupComplete = $cleanupComplete
    redacted = $true
    startedAtUtc = $startedAt.ToString('O')
    finishedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $receipt -Encoding utf8NoBOM

Write-Output "Native Windows qualification passed: $receipt"
