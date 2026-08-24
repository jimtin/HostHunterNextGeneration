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
$canonicalTempRoot = (& /bin/realpath ([IO.Path]::GetTempPath())).Trim()
if ([string]::IsNullOrWhiteSpace($canonicalTempRoot) -or
    -not [IO.Directory]::Exists($canonicalTempRoot)) {
    throw 'The Windows qualification temporary root could not be canonicalized.'
}
$dataRoot = Join-Path $canonicalTempRoot (
    'hosthunter-windows-qualification-' + [Guid]::NewGuid().ToString('N')
)
$extractRoot = Join-Path $canonicalTempRoot (
    'hosthunter-windows-package-' + [Guid]::NewGuid().ToString('N')
)
$remoteArchiveName = 'HostHunterNextGeneration-' + [Guid]::NewGuid().ToString('N') + '.tar.gz'
$module = $null
$keychainAccount = $null
$keychainPath = $null
$auditService = $null
$anchorService = $null
$exactInstalledKeyLine = $null
$remoteKeyRemoved = $false
$cleanupComplete = $false
$nativeProof = $null
$directResult = $null
$compatibilityResult = $null
$mixedResult = @()
$keyResult = $null
$transition = $null
$sshAgentStarted = $false
$sshAgentKeyAdded = $false
$sshAgentIdentityRemoved = $false
$sshAgentStopped = $false
$originalSshAuthSock = [Environment]::GetEnvironmentVariable('SSH_AUTH_SOCK', 'Process')
$originalSshAgentPid = [Environment]::GetEnvironmentVariable('SSH_AGENT_PID', 'Process')

function Write-HHQualificationPhase {
    param(
        [Parameter(Mandatory)]
        [ValidateSet(
            'NativePackage',
            'TargetValidation',
            'DirectPowerShell7',
            'DirectWindowsPowerShell51',
            'MixedRuntime',
            'SshKeyBootstrap',
            'AgentKeyProof',
            'PasswordRecovery',
            'Cleanup'
        )]
        [string]$Phase,

        [Parameter(Mandatory)]
        [ValidateSet('Started', 'Passed')]
        [string]$Status
    )

    Write-Output "HH_QUALIFICATION_PHASE|$Phase|$Status"
}

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

function Test-HHQualificationSecurityItem {
    param(
        [Parameter(Mandatory)][string]$Service,
        [Parameter(Mandatory)][string]$Account,
        [Parameter(Mandatory)][string]$LoginKeychain
    )

    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = '/usr/bin/security'
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in @(
            'find-generic-password', '-s', $Service, '-a', $Account, $LoginKeychain
        )) {
        $null = $startInfo.ArgumentList.Add($argument)
    }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    if (-not $process.Start()) {
        throw 'The exact Keychain verification process did not start.'
    }
    try {
        if (-not $process.WaitForExit(15000)) {
            $process.Kill($true)
            $process.WaitForExit()
            throw 'The exact Keychain verification process timed out.'
        }
        $null = $process.StandardOutput.ReadToEnd()
        $null = $process.StandardError.ReadToEnd()
        if ($process.ExitCode -eq 0) { return $true }
        if ($process.ExitCode -eq 44) { return $false }
        throw 'The exact Keychain item could not be verified safely.'
    }
    finally { $process.Dispose() }
}

function Invoke-HHQualificationSshAgentStart {
    $agentOutput = Invoke-HHInteractiveNativeProcess -FileName '/usr/bin/ssh-agent' `
        -ArgumentList @('-s') -CaptureOutput -TimeoutSeconds 15
    $socketMatch = [regex]::Match(
        $agentOutput,
        '(?m)^SSH_AUTH_SOCK=(?<Value>[^;\r\n]+);'
    )
    $pidMatch = [regex]::Match(
        $agentOutput,
        '(?m)^SSH_AGENT_PID=(?<Value>[0-9]+);'
    )
    if (-not $socketMatch.Success -or -not $pidMatch.Success) {
        throw 'The run-scoped SSH agent did not publish a valid process contract.'
    }

    [pscustomobject]@{
        Socket = $socketMatch.Groups['Value'].Value
        ProcessId = $pidMatch.Groups['Value'].Value
    }
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
    if ($null -ne $module) {
        Remove-Module $module -Force -Confirm:$false -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $dataRoot -Recurse -Force -Confirm:$false `
        -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $stageRoot -Recurse -Force -Confirm:$false `
        -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $archivePath -Force -Confirm:$false `
        -ErrorAction SilentlyContinue
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
    Write-HHQualificationPhase -Phase NativePackage -Status Started
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
            AuditService = $script:HHAuditKeychainService
            AnchorService = $script:HHPersistenceAnchorKeychainService
        }
    } $dataRoot
    $keychainAccount = [string]$identity.Account
    $keychainPath = [string]$identity.KeychainPath
    $auditService = [string]$identity.AuditService
    $anchorService = [string]$identity.AnchorService

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
    Write-HHQualificationPhase -Phase NativePackage -Status Passed

    Write-HHQualificationPhase -Phase TargetValidation -Status Started
    $null = Set-HHTarget -Name windows-ps7 -HostName $SshHost -Port $Port `
        -UserName $UserName -Authentication Password -PowerShellRuntime PowerShell7 `
        -HostKeyFingerprint $HostKeyFingerprint -Confirm:$false
    $null = Set-HHTarget -Name windows-ps51 -HostName $SshHost -Port $Port `
        -UserName $UserName -Authentication Password `
        -PowerShellRuntime WindowsPowerShell51 `
        -HostKeyFingerprint $HostKeyFingerprint -Add -Confirm:$false
    Write-HHQualificationPhase -Phase TargetValidation -Status Passed

    $streamCommand = @'
Write-Output 'output'
Write-Warning 'warning'
Write-Verbose 'verbose' -Verbose
& {
    $DebugPreference = 'Continue'
    Write-Debug 'debug'
}
Write-Information 'information' -InformationAction Continue
Write-Error 'error' -ErrorAction Continue
'@
    Write-HHQualificationPhase -Phase DirectPowerShell7 -Status Started
    $directResult = Invoke-HHCommand -Command $streamCommand -Target windows-ps7
    Assert-HHRuntimeResult -Result $directResult -Runtime PowerShell7
    Write-HHQualificationPhase -Phase DirectPowerShell7 -Status Passed

    Write-HHQualificationPhase -Phase DirectWindowsPowerShell51 -Status Started
    $compatibilityResult = Invoke-HHCommand -Command $streamCommand -Target windows-ps51
    Assert-HHRuntimeResult -Result $compatibilityResult -Runtime WindowsPowerShell51
    Write-HHQualificationPhase -Phase DirectWindowsPowerShell51 -Status Passed

    Write-HHQualificationPhase -Phase MixedRuntime -Status Started
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
    Write-HHQualificationPhase -Phase MixedRuntime -Status Passed

    Write-HHQualificationPhase -Phase SshKeyBootstrap -Status Started
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
    Write-HHQualificationPhase -Phase SshKeyBootstrap -Status Passed

    Write-HHQualificationPhase -Phase AgentKeyProof -Status Started
    $sshAgent = Invoke-HHQualificationSshAgentStart
    $env:SSH_AUTH_SOCK = $sshAgent.Socket
    $env:SSH_AGENT_PID = $sshAgent.ProcessId
    $sshAgentStarted = $true
    $null = Invoke-HHInteractiveNativeProcess -FileName '/usr/bin/ssh-add' `
        -ArgumentList @($transition.KeyPath) -CaptureOutput -TimeoutSeconds 120
    $sshAgentKeyAdded = $true
    $agentPublicKeys = Invoke-HHInteractiveNativeProcess -FileName '/usr/bin/ssh-add' `
        -ArgumentList @('-L') -CaptureOutput -TimeoutSeconds 15
    $expectedPublicKey = (@($exactInstalledKeyLine -split '\s+')[0..1] -join ' ')
    $matchingAgentKeys = @($agentPublicKeys -split "`r?`n" | Where-Object {
            $_ -ceq $expectedPublicKey -or $_.StartsWith("$expectedPublicKey ")
        })
    if ($matchingAgentKeys.Count -ne 1) {
        throw 'The exact qualification identity was not loaded into the run-scoped SSH agent.'
    }
    $keyResult = Invoke-HHCommand -Command "'key-proof'" -Target windows-ps7
    if (-not $keyResult.Succeeded) { throw 'The committed key profile could not execute.' }
    Write-HHQualificationPhase -Phase AgentKeyProof -Status Passed

    Write-HHQualificationPhase -Phase PasswordRecovery -Status Started
    $passwordOutput = Invoke-HHInteractiveNativeProcess -FileName 'ssh' -ArgumentList @(
        '-o', 'PubkeyAuthentication=no', '-o', 'PreferredAuthentications=password',
        '-p', [string]$Port, "${UserName}@${SshHost}",
        'pwsh', '-NoLogo', '-NoProfile', '-NonInteractive', '-Command',
        'Write-Output HH_PASSWORD_AUTH_STILL_ENABLED; exit 0'
    ) -CaptureOutput -TimeoutSeconds 120
    if ($passwordOutput.Trim() -cne 'HH_PASSWORD_AUTH_STILL_ENABLED') {
        throw 'Password authentication was not independently proven after key installation.'
    }
    Write-HHQualificationPhase -Phase PasswordRecovery -Status Passed

    Write-HHQualificationPhase -Phase Cleanup -Status Started
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
    if ($sshAgentStarted) {
        try {
            if ($sshAgentKeyAdded -and $null -ne $transition) {
                $null = Invoke-HHInteractiveNativeProcess -FileName '/usr/bin/ssh-add' `
                    -ArgumentList @('-d', [string]$transition.KeyPath) `
                    -CaptureOutput -TimeoutSeconds 15
                $sshAgentIdentityRemoved = $true
            }
        }
        finally {
            try {
                $null = Invoke-HHInteractiveNativeProcess `
                    -FileName '/usr/bin/ssh-agent' -ArgumentList @('-k') `
                    -CaptureOutput -TimeoutSeconds 15
                $sshAgentStopped = $true
            }
            finally {
                $env:SSH_AUTH_SOCK = $originalSshAuthSock
                $env:SSH_AGENT_PID = $originalSshAgentPid
            }
        }
    }
    if ($remoteKeyRemoved -and
        -not [string]::IsNullOrWhiteSpace($keychainAccount) -and
        -not [string]::IsNullOrWhiteSpace($keychainPath) -and
        -not [string]::IsNullOrWhiteSpace($auditService) -and
        -not [string]::IsNullOrWhiteSpace($anchorService)) {
        $keychainItems = @(
            [pscustomobject]@{ Service = $auditService; Account = $keychainAccount },
            [pscustomobject]@{ Service = $anchorService; Account = $keychainAccount }
        )
        foreach ($item in $keychainItems) {
            if (-not (Test-HHQualificationSecurityItem `
                        -Service $item.Service -Account $item.Account `
                        -LoginKeychain $keychainPath)) {
                throw 'An exact Keychain item expected from qualification was not present for cleanup.'
            }
            Invoke-HHQualificationSecurityDelete `
                -Service $item.Service -Account $item.Account `
                -LoginKeychain $keychainPath
        }
        foreach ($item in $keychainItems) {
            if (Test-HHQualificationSecurityItem `
                    -Service $item.Service -Account $item.Account `
                    -LoginKeychain $keychainPath) {
                throw 'An exact Keychain item remained after qualification cleanup.'
            }
        }
        Remove-Item -LiteralPath $dataRoot -Recurse -Force -Confirm:$false `
            -ErrorAction Stop
        $cleanupComplete = $true
    }
    if ($null -ne $module) {
        Remove-Module $module -Force -Confirm:$false -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $extractRoot -Recurse -Force -Confirm:$false `
        -ErrorAction SilentlyContinue
    $env:HH_DATA_ROOT = $null
}

if (-not $cleanupComplete) {
    throw 'Windows qualification cleanup was not proven; local recovery state was preserved.'
}
if (-not $sshAgentIdentityRemoved -or -not $sshAgentStopped) {
    throw 'The run-scoped SSH agent cleanup was not proven.'
}
Write-HHQualificationPhase -Phase Cleanup -Status Passed
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
    runScopedSshAgentVerified = $sshAgentStarted -and $sshAgentKeyAdded -and
        [bool]$keyResult.Succeeded
    runScopedSshAgentIdentityRemoved = $sshAgentIdentityRemoved
    runScopedSshAgentStopped = $sshAgentStopped
    passwordAuthenticationPreserved = $true
    remoteQualificationKeyRemoved = $remoteKeyRemoved
    cleanupComplete = $cleanupComplete
    redacted = $true
    startedAtUtc = $startedAt.ToString('O')
    finishedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $receipt -Encoding utf8NoBOM

Write-Output "Native Windows qualification passed: $receipt"
