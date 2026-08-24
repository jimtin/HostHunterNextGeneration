Set-StrictMode -Version Latest

function Get-HHSshKeyFingerprint {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$PublicKeyBase64)

    try {
        $keyBytes = [Convert]::FromBase64String($PublicKeyBase64)
    }
    catch {
        throw "SSH host key data is not valid base64: $($_.Exception.Message)"
    }
    $digest = [System.Security.Cryptography.SHA256]::HashData($keyBytes)
    "SHA256:$([Convert]::ToBase64String($digest).TrimEnd('='))"
}

function Invoke-HHNativeProcess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FileName,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$ArgumentList,
        [int]$TimeoutSeconds = 15
    )

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FileName
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in $ArgumentList) {
        $startInfo.ArgumentList.Add($argument)
    }
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) {
            throw "Failed to start '$FileName'."
        }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            $process.Kill($true)
            throw "'$FileName' exceeded the $TimeoutSeconds second timeout."
        }
        [pscustomobject]@{
            ExitCode = $process.ExitCode
            StandardOutput = $stdoutTask.GetAwaiter().GetResult()
            StandardError = $stderrTask.GetAwaiter().GetResult()
        }
    }
    finally {
        $process.Dispose()
    }
}

function Register-HHSshHostTrust {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$HostName,
        [Parameter(Mandatory)][ValidateRange(1, 65535)][int]$Port,
        [Parameter(Mandatory)][string]$ExpectedFingerprint,
        [Parameter(Mandatory)][string]$KnownHostsPath,
        [int]$TimeoutSeconds = 15,
        [scriptblock]$KeyScanner
    )

    if ([Uri]::CheckHostName($HostName) -eq [UriHostNameType]::Unknown) {
        throw "SSH host name '$HostName' is invalid."
    }
    if ($ExpectedFingerprint -notmatch '^SHA256:[A-Za-z0-9+/]{43}$') {
        throw 'ExpectedFingerprint must be a complete OpenSSH SHA256 host-key fingerprint.'
    }

    $scanOutput = if ($null -ne $KeyScanner) {
        & $KeyScanner $HostName $Port $TimeoutSeconds
    }
    else {
        $result = Invoke-HHNativeProcess -FileName 'ssh-keyscan' -ArgumentList @(
            '-p', [string]$Port, '-T', [string]$TimeoutSeconds, $HostName
        ) -TimeoutSeconds ($TimeoutSeconds + 2)
        if ($result.ExitCode -ne 0 -and [string]::IsNullOrWhiteSpace($result.StandardOutput)) {
            throw "SSH host-key discovery failed: $($result.StandardError.Trim())"
        }
        $result.StandardOutput
    }

    $matchingLine = $null
    foreach ($line in @($scanOutput -split "`r?`n")) {
        if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('#')) {
            continue
        }
        $parts = $line -split '\s+'
        if ($parts.Count -lt 3) {
            continue
        }
        if ((Get-HHSshKeyFingerprint -PublicKeyBase64 $parts[2]) -ceq $ExpectedFingerprint) {
            $matchingLine = "$($parts[0]) $($parts[1]) $($parts[2])"
            break
        }
    }
    if ($null -eq $matchingLine) {
        throw "No discovered SSH host key matched '$ExpectedFingerprint'."
    }

    $existingLines = if (Test-Path -LiteralPath $KnownHostsPath) {
        @(Get-Content -LiteralPath $KnownHostsPath)
    }
    else {
        @()
    }
    if ($matchingLine -cin $existingLines) {
        return $matchingLine
    }
    $matchingHostToken = ($matchingLine -split '\s+', 2)[0]
    $changedIdentity = @($existingLines | Where-Object {
            -not [string]::IsNullOrWhiteSpace($_) -and
            ($_ -split '\s+', 2)[0] -ceq $matchingHostToken
        })
    if ($changedIdentity.Count -gt 0) {
        throw "The saved SSH identity for '$HostName`:$Port' differs from the expected fingerprint."
    }
    if (-not $PSCmdlet.ShouldProcess("$HostName`:$Port", 'Trust the verified SSH host key')) {
        return $matchingLine
    }

    $directory = Split-Path -Parent $KnownHostsPath
    [System.IO.Directory]::CreateDirectory($directory) | Out-Null
    $updatedLines = @(@($existingLines) + @($matchingLine) | Sort-Object -Unique)
    $temporaryPath = "$KnownHostsPath.$([Guid]::NewGuid().ToString('N')).tmp"
    try {
        [System.IO.File]::WriteAllLines($temporaryPath, $updatedLines, [Text.UTF8Encoding]::new($false))
        Protect-HHPrivateFileMode -Path $temporaryPath
        [System.IO.File]::Move($temporaryPath, $KnownHostsPath, $true)
    }
    finally {
        if (Test-Path -LiteralPath $temporaryPath) {
            Remove-Item -LiteralPath $temporaryPath -Force
        }
    }
    $matchingLine
}
