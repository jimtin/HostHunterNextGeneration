[CmdletBinding()]
param(
    [string]$TargetHost = $env:HH_SSH_HOST,
    [int]$Port = $(if ($env:HH_SSH_PORT) { [int]$env:HH_SSH_PORT } else { 22 }),
    [string]$RuntimeDirectory = $(
        if ($env:HH_SSH_RUNTIME_DIR) { $env:HH_SSH_RUNTIME_DIR } else { '/run/hosthunter-ssh' }
    ),
    [string]$ArtifactRoot = $(
        if ($env:HH_ARTIFACT_ROOT) { $env:HH_ARTIFACT_ROOT } else { '/artifacts' }
    )
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-Condition {
    param(
        [Parameter(Mandatory)]
        [bool]$Condition,

        [Parameter(Mandatory)]
        [string]$Message
    )

    if (-not $Condition) {
        throw $Message
    }
}

function Get-PathMode {
    param(
        [Parameter(Mandatory)]
        [string]$LiteralPath
    )

    $item = Get-Item -LiteralPath $LiteralPath -Force
    Assert-Condition -Condition ($null -eq $item.LinkType) -Message "A fixture path is a symbolic link: $LiteralPath"

    $metadata = & /usr/bin/stat --format '%a:%u:%g' -- $LiteralPath
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to inspect fixture metadata: $LiteralPath"
    }

    return [string]$metadata
}

function Write-ContractArtifact {
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Result,

        [Parameter(Mandatory)]
        [string]$Destination
    )

    $destinationDirectory = Split-Path -Parent $Destination
    [System.IO.Directory]::CreateDirectory($destinationDirectory) | Out-Null
    $temporaryPath = "$Destination.tmp.$PID"
    $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
    $json = $Result | ConvertTo-Json -Depth 6
    [System.IO.File]::WriteAllText($temporaryPath, "$json`n", $utf8NoBom)
    Move-Item -LiteralPath $temporaryPath -Destination $Destination -Force
}

if ([string]::IsNullOrWhiteSpace($TargetHost)) {
    throw 'HH_SSH_HOST or -TargetHost is required.'
}
if ($Port -lt 1 -or $Port -gt 65535) {
    throw 'The SSH port must be between 1 and 65535.'
}

$artifactPath = Join-Path $ArtifactRoot 'integration/ssh-fixture-contract.json'
$result = [ordered]@{
    schemaVersion = 1
    status = 'failed'
    completedAtUtc = $null
    transport = 'PowerShell-over-SSH'
    target = [ordered]@{
        host = $TargetHost
        port = $Port
        username = $null
    }
    runtimeMetadataVerified = $false
    hostKeyVerified = $false
    passwordAuthenticationVerified = $false
    remote = $null
    helperSafety = $null
    failurePhase = 'initialization'
    failureType = $null
    failureLine = $null
}

$phase = 'initialization'
$session = $null
$temporaryDirectory = $null
$failure = $null
$environmentNames = @(
    'DISPLAY',
    'HH_SSH_PASSWORD_FILE',
    'SSH_ASKPASS',
    'SSH_ASKPASS_REQUIRE'
)
$savedEnvironment = @{}
foreach ($environmentName in $environmentNames) {
    $savedEnvironment[$environmentName] = [Environment]::GetEnvironmentVariable($environmentName, 'Process')
}

try {
    $phase = 'toolchain-validation'
    foreach ($commandName in @('chmod', 'ssh-keygen', 'ssh-keyscan', 'stat')) {
        Assert-Condition -Condition ($null -ne (Get-Command $commandName -CommandType Application -ErrorAction SilentlyContinue)) `
            -Message "Required fixture command is missing: $commandName"
    }
    Assert-Condition -Condition ($PSVersionTable.PSVersion.ToString() -eq '7.6.5') `
        -Message 'The fixture contract must run under PowerShell 7.6.5.'

    $phase = 'runtime-metadata-validation'
    $passwordPath = Join-Path $RuntimeDirectory 'password'
    $usernamePath = Join-Path $RuntimeDirectory 'username'
    $fingerprintPath = Join-Path $RuntimeDirectory 'hostkey.sha256'
    $readyPath = Join-Path $RuntimeDirectory 'ready'

    $expectedMetadata = [ordered]@{
        $RuntimeDirectory = '750:0:10002'
        $passwordPath = '640:0:10002'
        $usernamePath = '644:0:0'
        $fingerprintPath = '644:0:0'
        $readyPath = '644:0:0'
    }
    foreach ($entry in $expectedMetadata.GetEnumerator()) {
        Assert-Condition -Condition ((Get-PathMode -LiteralPath $entry.Key) -eq $entry.Value) `
            -Message "Unexpected fixture ownership or mode: $($entry.Key)"
    }

    $supplementaryGroups = @(& /usr/bin/id --groups)
    Assert-Condition -Condition ($LASTEXITCODE -eq 0) -Message 'Unable to inspect test-container groups.'
    Assert-Condition -Condition (($supplementaryGroups -join ' ') -split '\s+' -contains '10002') `
        -Message 'The test container is missing fixture secret group 10002.'

    $username = [System.IO.File]::ReadAllText($usernamePath).Trim()
    Assert-Condition -Condition ($username -eq 'hhfixture') -Message 'The runtime fixture username is invalid.'
    $password = [System.IO.File]::ReadAllText($passwordPath).Trim()
    Assert-Condition -Condition ($password -cmatch '^[0-9a-f]{64}$') `
        -Message 'The runtime fixture password does not have the generated-secret format.'
    $password = $null
    $expectedFingerprint = [System.IO.File]::ReadAllText($fingerprintPath).Trim()
    Assert-Condition -Condition ($expectedFingerprint -match '^SHA256:[A-Za-z0-9+/]+$') `
        -Message 'The runtime fixture host-key fingerprint is invalid.'
    Assert-Condition -Condition ([System.IO.File]::ReadAllText($readyPath).Trim() -eq 'ready') `
        -Message 'The fixture readiness marker is invalid.'
    $result.target.username = $username
    $result.runtimeMetadataVerified = $true

    $phase = 'ephemeral-client-setup'
    [System.IO.Directory]::CreateDirectory($ArtifactRoot) | Out-Null
    $temporaryDirectory = Join-Path `
        $ArtifactRoot `
        ".ssh-contract-runtime-$PID-$([guid]::NewGuid().ToString('N'))"
    [System.IO.Directory]::CreateDirectory($temporaryDirectory) | Out-Null
    & /usr/bin/chmod 0700 $temporaryDirectory
    Assert-Condition -Condition ($LASTEXITCODE -eq 0) -Message 'Unable to secure the fixture client directory.'

    $askpassSource = Join-Path $PSScriptRoot 'fixture-askpass.sh'
    $askpassPath = Join-Path $temporaryDirectory 'askpass'
    Copy-Item -LiteralPath $askpassSource -Destination $askpassPath
    & /usr/bin/chmod 0500 $askpassPath
    Assert-Condition -Condition ($LASTEXITCODE -eq 0) -Message 'Unable to secure the fixture askpass helper.'

    $phase = 'host-key-validation'
    $knownHostsPath = Join-Path $temporaryDirectory 'known_hosts'
    $scannedHostKeys = @(& /usr/bin/ssh-keyscan -T 5 -p $Port -t ed25519 -- $TargetHost 2>$null)
    Assert-Condition -Condition ($LASTEXITCODE -eq 0 -and $scannedHostKeys.Count -gt 0) `
        -Message 'Unable to retrieve the fixture SSH host key.'
    $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllLines($knownHostsPath, [string[]]$scannedHostKeys, $utf8NoBom)
    & /usr/bin/chmod 0600 $knownHostsPath
    Assert-Condition -Condition ($LASTEXITCODE -eq 0) -Message 'Unable to secure the known-hosts file.'

    $fingerprintOutput = @(& /usr/bin/ssh-keygen -l -E sha256 -f $knownHostsPath)
    Assert-Condition -Condition ($LASTEXITCODE -eq 0 -and $fingerprintOutput.Count -gt 0) `
        -Message 'Unable to fingerprint the scanned fixture host key.'
    $scannedFingerprints = @(
        @(
            foreach ($fingerprintLine in $fingerprintOutput) {
                if ($fingerprintLine -match '(SHA256:[A-Za-z0-9+/]+)') {
                    $Matches[1]
                }
            }
        ) | Sort-Object -Unique
    )
    Assert-Condition -Condition ($scannedFingerprints.Count -eq 1) `
        -Message 'The fixture returned an unexpected host-key set.'
    Assert-Condition -Condition ($scannedFingerprints[0] -ceq $expectedFingerprint) `
        -Message 'The scanned fixture host key does not match the trusted runtime fingerprint.'
    $result.hostKeyVerified = $true

    $phase = 'password-authentication'
    [Environment]::SetEnvironmentVariable('DISPLAY', 'hosthunter-fixture', 'Process')
    [Environment]::SetEnvironmentVariable('HH_SSH_PASSWORD_FILE', $passwordPath, 'Process')
    [Environment]::SetEnvironmentVariable('SSH_ASKPASS', $askpassPath, 'Process')
    [Environment]::SetEnvironmentVariable('SSH_ASKPASS_REQUIRE', 'force', 'Process')
    $sshOptions = @{
        NumberOfPasswordPrompts = '1'
        PasswordAuthentication = 'yes'
        PreferredAuthentications = 'password'
        PubkeyAuthentication = 'no'
        StrictHostKeyChecking = 'yes'
        UserKnownHostsFile = $knownHostsPath
    }
    $session = New-PSSession `
        -HostName $TargetHost `
        -Port $Port `
        -UserName $username `
        -Options $sshOptions

    $phase = 'remote-powershell-validation'
    $remoteProbe = Invoke-Command -Session $session -ScriptBlock {
        $authorizedKeysPath = '/home/hhfixture/.ssh/authorized_keys'
        $beforeHash = (Get-FileHash -LiteralPath $authorizedKeysPath -Algorithm SHA256).Hash

        & /usr/local/bin/hh-ssh-reset-authorized-keys 2>$null
        $resetExitCode = $LASTEXITCODE
        & /usr/local/bin/hh-ssh-rotate-host-key 2>$null
        $rotateExitCode = $LASTEXITCODE

        $afterHash = (Get-FileHash -LiteralPath $authorizedKeysPath -Algorithm SHA256).Hash
        $resetMode = & /usr/bin/stat --format '%a:%u:%g' -- /usr/local/bin/hh-ssh-reset-authorized-keys
        $rotateMode = & /usr/bin/stat --format '%a:%u:%g' -- /usr/local/bin/hh-ssh-rotate-host-key

        [pscustomobject]@{
            Marker = 'HostHunterFixtureContract'
            PowerShellVersion = $PSVersionTable.PSVersion.ToString()
            User = [Environment]::UserName
            ResetHelperMode = [string]$resetMode
            ResetUnprivilegedExitCode = $resetExitCode
            RotateHelperMode = [string]$rotateMode
            RotateUnprivilegedExitCode = $rotateExitCode
            AuthorizedKeysUnchanged = $beforeHash -ceq $afterHash
        }
    }

    Assert-Condition -Condition ($remoteProbe.Marker -ceq 'HostHunterFixtureContract') `
        -Message 'The remote PowerShell marker is invalid.'
    Assert-Condition -Condition ($remoteProbe.PowerShellVersion -eq '7.6.5') `
        -Message 'The remote fixture is not running PowerShell 7.6.5.'
    Assert-Condition -Condition ($remoteProbe.User -ceq $username) `
        -Message 'The remote fixture user is invalid.'
    Assert-Condition -Condition ($remoteProbe.ResetHelperMode -ceq '755:0:0') `
        -Message 'The authorized-keys reset helper metadata is invalid.'
    Assert-Condition -Condition ($remoteProbe.RotateHelperMode -ceq '755:0:0') `
        -Message 'The host-key rotation helper metadata is invalid.'
    Assert-Condition -Condition ($remoteProbe.ResetUnprivilegedExitCode -eq 77) `
        -Message 'The reset helper did not reject an unprivileged caller.'
    Assert-Condition -Condition ($remoteProbe.RotateUnprivilegedExitCode -eq 77) `
        -Message 'The rotation helper did not reject an unprivileged caller.'
    Assert-Condition -Condition ([bool]$remoteProbe.AuthorizedKeysUnchanged) `
        -Message 'An unprivileged helper invocation changed authorized_keys.'

    $result.passwordAuthenticationVerified = $true
    $result.remote = [ordered]@{
        marker = $remoteProbe.Marker
        powerShellVersion = $remoteProbe.PowerShellVersion
        user = $remoteProbe.User
    }
    $result.helperSafety = [ordered]@{
        resetHelperMode = $remoteProbe.ResetHelperMode
        resetRejectedUnprivilegedCaller = $true
        rotateHelperMode = $remoteProbe.RotateHelperMode
        rotateRejectedUnprivilegedCaller = $true
        authorizedKeysUnchanged = $true
    }
    $result.status = 'passed'
    $result.failurePhase = $null
}
catch {
    $failure = $_
    $result.failurePhase = $phase
    $result.failureType = $_.Exception.GetType().FullName
    $result.failureLine = $_.InvocationInfo.ScriptLineNumber
}
finally {
    if ($null -ne $session) {
        Remove-PSSession -Session $session -ErrorAction SilentlyContinue
    }
    foreach ($environmentName in $environmentNames) {
        [Environment]::SetEnvironmentVariable(
            $environmentName,
            $savedEnvironment[$environmentName],
            'Process'
        )
    }
    if ($null -ne $temporaryDirectory -and [System.IO.Directory]::Exists($temporaryDirectory)) {
        [System.IO.Directory]::Delete($temporaryDirectory, $true)
    }
    $result.completedAtUtc = [DateTimeOffset]::UtcNow.ToString('o')
    Write-ContractArtifact -Result $result -Destination $artifactPath
}

if ($null -ne $failure) {
    throw "SSH fixture contract failed during phase '$phase' ($($failure.Exception.GetType().FullName))."
}

Write-Output "SSH fixture contract passed; non-secret artifact: $artifactPath"
