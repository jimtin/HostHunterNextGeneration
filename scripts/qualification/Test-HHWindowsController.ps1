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
    [string]$ReceiptPath,
    [ValidateSet('Auto', 'MacOSKeychain', 'LinuxDockerVolume')]
    [string]$ControllerMode = 'Auto',
    [string]$CandidateReceiptPath,
    [string]$ModuleManifestPath,
    [ValidateScript({
            [string]::IsNullOrWhiteSpace($_) -or $_ -cmatch '^sha256:[a-f0-9]{64}$'
        })]
    [string]$ControllerImageId,
    [ValidatePattern('^[a-z0-9][a-z0-9_-]{2,63}$')]
    [string]$ControllerVolumeProject
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$resolvedControllerMode = if ($ControllerMode -ceq 'Auto') {
    if ($IsMacOS) { 'MacOSKeychain' }
    elseif ($IsLinux) { 'LinuxDockerVolume' }
    else { throw 'The Windows qualification controller platform is unsupported.' }
}
else { $ControllerMode }
if ($resolvedControllerMode -ceq 'MacOSKeychain' -and -not $IsMacOS) {
    throw 'The MacOSKeychain qualification mode requires macOS.'
}
if ($resolvedControllerMode -ceq 'LinuxDockerVolume' -and -not $IsLinux) {
    throw 'The LinuxDockerVolume qualification mode requires Linux.'
}

$repoRoot = $null
if ($resolvedControllerMode -ceq 'MacOSKeychain') {
    $repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '../..')).Path
    if ([string]::IsNullOrWhiteSpace($CandidateReceiptPath)) {
        $CandidateReceiptPath = Join-Path $repoRoot ".artifacts/release/$CandidateSha/receipt.json"
    }
}
elseif ([string]::IsNullOrWhiteSpace($CandidateReceiptPath)) {
    throw 'LinuxDockerVolume qualification requires the exact candidate receipt path.'
}
$archive = (Resolve-Path -LiteralPath $PackageArchivePath).Path
$candidateReceiptFile = (Resolve-Path -LiteralPath $CandidateReceiptPath).Path
if (-not [IO.File]::Exists($candidateReceiptFile)) {
    throw 'The exact-candidate receipt is missing.'
}
$candidateReceipt = Get-Content -LiteralPath $candidateReceiptFile -Raw | ConvertFrom-Json
$packageSha256 = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
if ($candidateReceipt.status -cne 'passed' -or
    $candidateReceipt.candidateSha -cne $CandidateSha -or
    $candidateReceipt.packageArchiveSha256 -cne $packageSha256 -or
    [string]$candidateReceipt.packageInventorySha256 -cnotmatch '^[a-f0-9]{64}$') {
    throw 'The package archive is not bound to the successful exact-candidate receipt.'
}
$expectedPackageInventorySha256 = [string]$candidateReceipt.packageInventorySha256
if ($resolvedControllerMode -ceq 'MacOSKeychain') {
    $head = (& git -C $repoRoot rev-parse HEAD).Trim()
    $status = @(& git -C $repoRoot status --porcelain=v1 --untracked-files=all)
    if ($LASTEXITCODE -ne 0 -or $head -cne $CandidateSha -or $status.Count -ne 0) {
        throw 'Windows qualification requires the clean exact candidate at repository HEAD.'
    }
}
else {
    if ([string]::IsNullOrWhiteSpace($ControllerImageId) -or
        [string]::IsNullOrWhiteSpace($ControllerVolumeProject)) {
        throw 'Docker qualification requires the exact controller image and volume project.'
    }
    if ($env:HH_SECRET_PROVIDER -cne 'DockerVolume' -or
        [string]::IsNullOrWhiteSpace($env:HH_DATA_ROOT) -or
        [string]::IsNullOrWhiteSpace($env:HH_SECRET_ROOT) -or
        [string]::IsNullOrWhiteSpace($env:HH_ANCHOR_ROOT) -or
        [string]::IsNullOrWhiteSpace($env:HH_SSH_ROOT) -or
        [string]::IsNullOrWhiteSpace($env:HH_EVIDENCE_ROOT) -or
        $env:HH_QUALIFICATION_VOLUME_COUNT -cne '6') {
        throw 'The DockerVolume controller environment is incomplete.'
    }
    if ([string]::IsNullOrWhiteSpace($ModuleManifestPath)) {
        $ModuleManifestPath = $env:HH_RUNTIME_MODULE_PATH
    }
}

if ([string]::IsNullOrWhiteSpace($ReceiptPath)) {
    if ($resolvedControllerMode -ceq 'LinuxDockerVolume') {
        throw 'LinuxDockerVolume qualification requires an explicit receipt path.'
    }
    $ReceiptPath = Join-Path $repoRoot ".artifacts/qualification/windows/$CandidateSha/receipt.json"
}
$receipt = [IO.Path]::GetFullPath($ReceiptPath)
$startedAt = [DateTimeOffset]::UtcNow
$canonicalTempRoot = (& /bin/realpath ([IO.Path]::GetTempPath())).Trim()
if ([string]::IsNullOrWhiteSpace($canonicalTempRoot) -or
    -not [IO.Directory]::Exists($canonicalTempRoot)) {
    throw 'The Windows qualification temporary root could not be canonicalized.'
}
$qualificationRoot = $null
$extractRoot = $null
$dataRoot = if ($resolvedControllerMode -ceq 'MacOSKeychain') {
    $qualificationRoot = Join-Path $canonicalTempRoot (
        'hosthunter-windows-qualification-' + [Guid]::NewGuid().ToString('N')
    )
    $extractRoot = Join-Path $canonicalTempRoot (
        'hosthunter-windows-package-' + [Guid]::NewGuid().ToString('N')
    )
    Join-Path $qualificationRoot 'Library/Application Support/HostHunterNextGeneration'
}
else { [IO.Path]::GetFullPath($env:HH_DATA_ROOT) }
$remoteArchiveName = 'HostHunterNextGeneration-' + [Guid]::NewGuid().ToString('N') + '.tar.gz'
$module = $null
$keychainAccount = $null
$keychainPath = $null
$auditService = $null
$anchorService = $null
$controllerPackageInventorySha256 = $null
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
$processAuditPowerShell7Verified = $false
$processAuditWindowsPowerShell51Verified = $false
$commandLineEnabledEventVerified = $false
$commandLineDisabledEventVerified = $false
$escalationPreferenceVerified = $false
$processAuditPolicyRestored = $false
$spaceContainingDataRootVerified = $false
$restartPersistenceVerified = $false
$processAuditRestoreRequired = $false
$processAuditBeforeFlag = $null
$commandLineBeforeState = $null
$originalSshAuthSock = [Environment]::GetEnvironmentVariable('SSH_AUTH_SOCK', 'Process')
$originalSshAgentPid = [Environment]::GetEnvironmentVariable('SSH_AGENT_PID', 'Process')
$originalDataRoot = [Environment]::GetEnvironmentVariable('HH_DATA_ROOT', 'Process')

function Write-HHQualificationPhase {
    param(
        [Parameter(Mandatory)]
        [ValidateSet(
            'NativePackage',
            'TargetValidation',
            'RestartPersistence',
            'DirectPowerShell7',
            'DirectWindowsPowerShell51',
            'MixedRuntime',
            'WindowsProcessAuditPolicy',
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

function Get-HHQualificationPackageInventorySha256 {
    param([Parameter(Mandatory)][string]$ModuleRoot)

    $canonicalRoot = (Resolve-Path -LiteralPath $ModuleRoot).Path
    $inventory = [Collections.Generic.SortedDictionary[string, string]]::new(
        [StringComparer]::Ordinal
    )
    foreach ($file in @(Get-ChildItem -LiteralPath $canonicalRoot -File -Recurse)) {
        $relativePath = [IO.Path]::GetRelativePath(
            $canonicalRoot,
            $file.FullName
        ).Replace('\', '/')
        $fileSha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).
            Hash.ToLowerInvariant()
        $inventory.Add($relativePath, "$fileSha256  ./$relativePath")
    }
    if ($inventory.Count -eq 0) {
        throw 'The packaged controller module inventory is empty.'
    }
    $inventoryBytes = [Text.Encoding]::UTF8.GetBytes(
        (@($inventory.Values) -join "`n") + "`n"
    )
    try {
        $inventoryHash = [Security.Cryptography.SHA256]::HashData($inventoryBytes)
        return [Convert]::ToHexString($inventoryHash).ToLowerInvariant()
    }
    finally { [Array]::Clear($inventoryBytes, 0, $inventoryBytes.Length) }
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

function Assert-HHWindowsProcessAuditPolicyResult {
    param(
        [Parameter(Mandatory)][object]$Result,
        [Parameter(Mandatory)][string]$Runtime
    )

    if (-not $Result.Succeeded -or
        $Result.DispatchState -cne 'Completed' -or
        $Result.OutcomeStatus -cne 'Succeeded' -or
        $null -eq $Result.PolicyOutcome -or
        -not [bool]$Result.PolicyOutcome.Succeeded -or
        [string]$Result.PolicyOutcome.RequiredPrivilege -cne 'SeSecurityPrivilege' -or
        -not [bool]$Result.PolicyOutcome.PrivilegeActivated -or
        -not [bool]$Result.PolicyOutcome.PrivilegeRestored -or
        [bool]$Result.PolicyOutcome.ReconciliationRequired) {
        throw "The $Runtime Windows process-audit policy qualification failed."
    }
}

function Invoke-HHWindowsProcessAuditEventProbe {
    param(
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][bool]$ExpectCommandLine
    )

    $marker = 'HHPA' + [Guid]::NewGuid().ToString('N')
    $probe = @'
$marker = '__MARKER__'
$startedAt = [DateTime]::UtcNow.AddSeconds(-5)
$creatorProcessId = $PID
$startInfo = [Diagnostics.ProcessStartInfo]::new()
$startInfo.FileName = Join-Path $env:SystemRoot 'System32\cmd.exe'
$startInfo.UseShellExecute = $false
$startInfo.CreateNoWindow = $true
$startInfo.Arguments = '/d /c echo ' + $marker + '>NUL'
$process = [Diagnostics.Process]::new()
$process.StartInfo = $startInfo
if (-not $process.Start()) { throw 'The process-audit marker process did not start.' }
try {
    if (-not $process.WaitForExit(15000)) {
        $process.Kill()
        throw 'The process-audit marker process did not exit in time.'
    }
    $markerProcessId = $process.Id
}
finally { $process.Dispose() }

$matched = $null
$deadline = [DateTime]::UtcNow.AddSeconds(30)
do {
    $events = @(Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            Id = 4688
            StartTime = $startedAt
        } -MaxEvents 256 -ErrorAction Stop)
    foreach ($eventRecord in $events) {
        $eventXml = [xml]$eventRecord.ToXml()
        $fields = @{}
        foreach ($field in @($eventXml.Event.EventData.Data)) {
            $fields[[string]$field.Name] = [string]$field.'#text'
        }
        $eventProcessId = [string]$fields['NewProcessId']
        $eventCreatorProcessId = [string]$fields['ProcessId']
        if ($eventProcessId -match '^0x[0-9a-fA-F]+$' -and
            $eventCreatorProcessId -match '^0x[0-9a-fA-F]+$' -and
            [Convert]::ToInt64($eventProcessId.Substring(2), 16) -eq $markerProcessId -and
            [Convert]::ToInt64($eventCreatorProcessId.Substring(2), 16) -eq
                $creatorProcessId) {
            $matched = $fields
            break
        }
    }
    if ($null -eq $matched) { Start-Sleep -Milliseconds 250 }
} while ($null -eq $matched -and [DateTime]::UtcNow -lt $deadline)

if ($null -eq $matched) { throw 'The expected Security event 4688 was not observed.' }
$commandLine = [string]$matched['CommandLine']
[pscustomobject]@{
    Marker = 'HostHunter.WindowsProcessAuditEventProbe.v1'
    EventFound = $true
    CommandLinePresent = -not [string]::IsNullOrWhiteSpace($commandLine)
    MarkerPresent = $commandLine.Contains($marker)
}
'@.Replace('__MARKER__', $marker)

    $result = Invoke-HHCommand -Command $probe -Target $Target
    if (-not $result.Succeeded) {
        throw "The process-audit event probe failed on $Target."
    }
    $probeReceipts = @($result.StreamEvents | Where-Object {
            $_.Stream -ceq 'Output' -and
            $null -ne $_.Value.PSObject.Properties['Marker'] -and
            $_.Value.Marker -ceq 'HostHunter.WindowsProcessAuditEventProbe.v1'
        })
    if ($probeReceipts.Count -ne 1 -or
        -not [bool]$probeReceipts[0].Value.EventFound -or
        [bool]$probeReceipts[0].Value.CommandLinePresent -ne $ExpectCommandLine -or
        [bool]$probeReceipts[0].Value.MarkerPresent -ne $ExpectCommandLine) {
        throw "Security event 4688 command-line behavior was incorrect on $Target."
    }
    return $true
}

try {
    Write-HHQualificationPhase -Phase NativePackage -Status Started
    if ($resolvedControllerMode -ceq 'MacOSKeychain') {
        [IO.Directory]::CreateDirectory($extractRoot) | Out-Null
        & tar -xzf $archive -C $extractRoot
        if ($LASTEXITCODE -ne 0) { throw 'Candidate package extraction failed.' }
        $manifest = Get-ChildItem -LiteralPath $extractRoot -Recurse `
            -Filter HostHunterNextGeneration.psd1 -File | Select-Object -First 1
        if ($null -eq $manifest) { throw 'Candidate module manifest is missing.' }
    }
    else {
        $manifest = Get-Item -LiteralPath $ModuleManifestPath -ErrorAction Stop
        if ($manifest.Name -cne 'HostHunterNextGeneration.psd1') {
            throw 'The stable controller module manifest is invalid.'
        }
        $controllerPackageInventorySha256 =
            Get-HHQualificationPackageInventorySha256 -ModuleRoot $manifest.DirectoryName
        if ($controllerPackageInventorySha256 -cne $expectedPackageInventorySha256) {
            throw 'The controller image module is not the exact candidate package.'
        }
    }
    $env:HH_DATA_ROOT = $dataRoot
    $module = Import-Module $manifest.FullName -Force -PassThru
    if ($resolvedControllerMode -ceq 'MacOSKeychain') {
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
    }

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

    Write-HHQualificationPhase -Phase RestartPersistence -Status Started
    Remove-Module $module -Force -Confirm:$false
    $module = Import-Module $manifest.FullName -Force -PassThru
    $reloadedTargets = @(Get-HHTarget | Sort-Object Name)
    if ($reloadedTargets.Count -ne 2 -or
        @(Compare-Object -CaseSensitive `
                -ReferenceObject @('windows-ps51', 'windows-ps7') `
                -DifferenceObject @($reloadedTargets.Name)).Count -ne 0 -or
        @($reloadedTargets | Where-Object Authentication -cne 'Password').Count -ne 0) {
        throw 'The controller persistence root did not retain both password targets across restart.'
    }
    $restartPersistenceVerified = $true
    Write-HHQualificationPhase -Phase RestartPersistence -Status Passed

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

    Write-HHQualificationPhase -Phase WindowsProcessAuditPolicy -Status Started
    $null = Set-HHEscalationPreference -Method WindowsTokenPrivilege -Confirm:$false
    $savedEscalation = Get-HHEscalationPreference
    $escalationPreferenceVerified =
        $savedEscalation.Method -ceq 'WindowsTokenPrivilege' -and
        [bool]$savedEscalation.IsPersisted
    if (-not $escalationPreferenceVerified) {
        throw 'The authenticated escalation preference was not persisted.'
    }

    $policyPowerShell7 = Set-HHWindowsProcessAuditPolicy -State Enabled `
        -Subcategory ProcessCreation -CommandLineLogging Enabled `
        -Target windows-ps7 -Escalate -Confirm:$false
    Assert-HHWindowsProcessAuditPolicyResult `
        -Result $policyPowerShell7 -Runtime PowerShell7
    $processAuditBeforeFlag =
        [uint32]$policyPowerShell7.PolicyOutcome.AuditBefore.ProcessCreation
    $commandLineBeforeState =
        [string]$policyPowerShell7.PolicyOutcome.CommandLineBefore
    if ($processAuditBeforeFlag -notin @([uint32]1, [uint32]2, [uint32]3, [uint32]4) -or
        $commandLineBeforeState -notin @('Enabled', 'Disabled', 'NotConfigured')) {
        throw 'The starting Windows process-audit policy cannot be restored exactly.'
    }
    $processAuditRestoreRequired = $true
    $processAuditPowerShell7Verified = $true
    $commandLineEnabledEventVerified = Invoke-HHWindowsProcessAuditEventProbe `
        -Target windows-ps7 -ExpectCommandLine $true

    $policyWindowsPowerShell51 = Set-HHWindowsProcessAuditPolicy -State Enabled `
        -Subcategory ProcessCreation -CommandLineLogging Enabled `
        -Target windows-ps51 -Escalate `
        -EscalationMethod WindowsTokenPrivilege -Confirm:$false
    Assert-HHWindowsProcessAuditPolicyResult `
        -Result $policyWindowsPowerShell51 -Runtime WindowsPowerShell51
    $processAuditWindowsPowerShell51Verified = $true

    $policyCommandLineDisabled = Set-HHWindowsProcessAuditPolicy -State Enabled `
        -Subcategory ProcessCreation -CommandLineLogging Disabled `
        -Target windows-ps51 -Escalate -Confirm:$false
    Assert-HHWindowsProcessAuditPolicyResult `
        -Result $policyCommandLineDisabled -Runtime WindowsPowerShell51
    $commandLineDisabledEventVerified = Invoke-HHWindowsProcessAuditEventProbe `
        -Target windows-ps51 -ExpectCommandLine $false
    Write-HHQualificationPhase -Phase WindowsProcessAuditPolicy -Status Passed

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
    if ($resolvedControllerMode -ceq 'MacOSKeychain') {
        if ($dataRoot -notmatch 'Library/Application Support/HostHunterNextGeneration') {
            throw 'The Windows qualification did not use the required macOS-style data root.'
        }
        $spaceContainingDataRootVerified = $true
    }
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

}
finally {
    if ($processAuditRestoreRequired -and
        $null -ne $processAuditBeforeFlag -and
        -not [string]::IsNullOrWhiteSpace($commandLineBeforeState) -and
        $null -ne $module) {
        $restoreAuditState = if (($processAuditBeforeFlag -band [uint32]1) -ne 0) {
            'Enabled'
        }
        else { 'Disabled' }
        $restoreResult = Set-HHWindowsProcessAuditPolicy -State $restoreAuditState `
            -Subcategory ProcessCreation -CommandLineLogging $commandLineBeforeState `
            -Target windows-ps51 -Escalate `
            -EscalationMethod WindowsTokenPrivilege -Confirm:$false
        Assert-HHWindowsProcessAuditPolicyResult `
            -Result $restoreResult -Runtime WindowsPowerShell51
        $processAuditPolicyRestored =
            [uint32]$restoreResult.PolicyOutcome.AuditAfter.ProcessCreation -eq
                $processAuditBeforeFlag -and
            [string]$restoreResult.PolicyOutcome.CommandLineAfter -ceq
                $commandLineBeforeState
        if (-not $processAuditPolicyRestored) {
            throw 'The starting Windows process-audit policy was not restored exactly.'
        }
        $processAuditRestoreRequired = $false
    }
    if ($remoteKeyRemoved) {
        $null = Remove-HHTarget -Name windows-ps7, windows-ps51 -Confirm:$false
    }
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
        Remove-Item -LiteralPath $qualificationRoot -Recurse -Force -Confirm:$false `
            -ErrorAction Stop
        $cleanupComplete = $true
    }
    elseif ($resolvedControllerMode -ceq 'LinuxDockerVolume' -and $remoteKeyRemoved) {
        $cleanupComplete = $true
    }
    if ($null -ne $module) {
        Remove-Module $module -Force -Confirm:$false -ErrorAction SilentlyContinue
    }
    if (-not [string]::IsNullOrWhiteSpace($extractRoot)) {
        Remove-Item -LiteralPath $extractRoot -Recurse -Force -Confirm:$false `
            -ErrorAction SilentlyContinue
    }
    $env:HH_DATA_ROOT = $originalDataRoot
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
    status = if ($resolvedControllerMode -ceq 'LinuxDockerVolume') {
        'controller-passed'
    }
    else { 'passed' }
    candidateSha = $CandidateSha
    packageArchiveSha256 = $packageSha256
    packageInventorySha256 = $expectedPackageInventorySha256
    controllerMode = $resolvedControllerMode
    controllerPlatform = if ($resolvedControllerMode -ceq 'LinuxDockerVolume') {
        'Linux'
    }
    else { 'macOS' }
    controllerImageId = if ($resolvedControllerMode -ceq 'LinuxDockerVolume') {
        $ControllerImageId
    }
    else { $null }
    controllerVolumeProject = if ($resolvedControllerMode -ceq 'LinuxDockerVolume') {
        $ControllerVolumeProject
    }
    else { $null }
    controllerVolumeCount = if ($resolvedControllerMode -ceq 'LinuxDockerVolume') { 6 }
        else { 0 }
    controllerVolumeCleanupComplete =
        $resolvedControllerMode -cne 'LinuxDockerVolume'
    stablePackagedModuleVerified =
        $resolvedControllerMode -cne 'LinuxDockerVolume' -or
        $controllerPackageInventorySha256 -ceq $expectedPackageInventorySha256
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
    processAuditPowerShell7Verified = $processAuditPowerShell7Verified
    processAuditWindowsPowerShell51Verified = $processAuditWindowsPowerShell51Verified
    commandLineEnabledEventVerified = $commandLineEnabledEventVerified
    commandLineDisabledEventVerified = $commandLineDisabledEventVerified
    escalationPreferenceVerified = $escalationPreferenceVerified
    processAuditPolicyRestored = $processAuditPolicyRestored
    keyTransitionSucceeded = [bool]$keyResult.Succeeded
    restartPersistenceVerified = $restartPersistenceVerified
    spaceContainingDataRootVerified = $spaceContainingDataRootVerified
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
