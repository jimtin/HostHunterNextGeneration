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
        [AllowNull()][byte[]]$StandardInputBytes,
        [int]$TimeoutSeconds = 15
    )

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FileName
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.RedirectStandardInput = $null -ne $StandardInputBytes
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
        if ($null -ne $StandardInputBytes) {
            $process.StandardInput.BaseStream.Write($StandardInputBytes, 0, $StandardInputBytes.Length)
            $process.StandardInput.Close()
        }
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
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSAvoidUsingWriteHost',
        '',
        Justification = 'Announces the accepted fingerprint on the capturable host information stream.'
    )]
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$HostName,
        [Parameter(Mandatory)][ValidateRange(1, 65535)][int]$Port,
        [AllowNull()][string]$ExpectedFingerprint,
        [Parameter(Mandatory)][string]$KnownHostsPath,
        [int]$TimeoutSeconds = 15,
        [scriptblock]$KeyScanner,
        [switch]$PassThru
    )

    if ([Uri]::CheckHostName($HostName) -eq [UriHostNameType]::Unknown) {
        throw "SSH host name '$HostName' is invalid."
    }
    if (-not [string]::IsNullOrWhiteSpace($ExpectedFingerprint) -and
        $ExpectedFingerprint -notmatch '^SHA256:[A-Za-z0-9+/]{43}$') {
        throw 'ExpectedFingerprint must be a complete OpenSSH SHA256 host-key fingerprint.'
    }

    $algorithmRank = @{
        'ssh-ed25519' = 0
        'ecdsa-sha2-nistp256' = 1
        'ecdsa-sha2-nistp384' = 2
        'ecdsa-sha2-nistp521' = 3
        'ssh-rsa' = 4
    }
    $existingLines = if (Test-Path -LiteralPath $KnownHostsPath) {
        @(Get-Content -LiteralPath $KnownHostsPath)
    }
    else {
        @()
    }
    if (-not [string]::IsNullOrWhiteSpace($ExpectedFingerprint)) {
        $expectedHostToken = if ($Port -eq 22) { $HostName } else { "[$HostName]:$Port" }
        $matchingPinned = @(
            foreach ($line in $existingLines) {
                $parts = $line -split '\s+'
                if ($parts.Count -lt 3 -or $parts[0] -cne $expectedHostToken -or
                    -not $algorithmRank.ContainsKey($parts[1])) {
                    continue
                }
                try { $fingerprint = Get-HHSshKeyFingerprint -PublicKeyBase64 $parts[2] }
                catch { continue }
                if ($fingerprint -cne $ExpectedFingerprint) { continue }
                [pscustomobject][ordered]@{
                    Line = "$($parts[0]) $($parts[1]) $($parts[2])"
                    Algorithm = $parts[1]
                    Fingerprint = $fingerprint
                    Rank = [int]$algorithmRank[$parts[1]]
                }
            }
        )
        if ($matchingPinned.Count -gt 0) {
            $selectedPinned = @($matchingPinned | Sort-Object Rank, Line)[0]
            $pinnedResult = [pscustomobject][ordered]@{
                Line = [string]$selectedPinned.Line
                Algorithm = [string]$selectedPinned.Algorithm
                Fingerprint = [string]$selectedPinned.Fingerprint
                NewlyTrusted = $false
            }
            if ($PassThru) { return $pinnedResult }
            return $pinnedResult.Line
        }
    }

    $scanOutput = if ($null -ne $KeyScanner) {
        & $KeyScanner $HostName $Port $TimeoutSeconds
    }
    else {
        $result = Invoke-HHNativeProcess -FileName 'ssh-keyscan' -ArgumentList @(
            '-p', [string]$Port, '-T', [string]$TimeoutSeconds, $HostName
        ) -TimeoutSeconds ($TimeoutSeconds + 2)
        if ([string]::IsNullOrWhiteSpace($result.StandardOutput)) {
            $message = @(
                "Unable to retrieve an SSH host key from '$HostName`:$Port'."
                "Confirm the host name or IP address, that OpenSSH Server (sshd) is running,"
                "and that port $Port is reachable through the firewall."
            ) -join ' '
            $scannerDetail = $result.StandardError.Trim()
            if (-not [string]::IsNullOrWhiteSpace($scannerDetail)) {
                $message += " ssh-keyscan reported: $scannerDetail"
            }
            $exception = [InvalidOperationException]::new($message)
            $exception.Data['HHFailureKind'] = 'TransportFailure'
            throw $exception
        }
        $result.StandardOutput
    }

    $candidates = [Collections.Generic.List[object]]::new()
    foreach ($line in @($scanOutput -split "`r?`n")) {
        if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('#')) {
            continue
        }
        $parts = $line -split '\s+'
        if ($parts.Count -lt 3) {
            continue
        }
        if (-not $algorithmRank.ContainsKey($parts[1])) { continue }
        $fingerprint = Get-HHSshKeyFingerprint -PublicKeyBase64 $parts[2]
        $candidates.Add([pscustomobject][ordered]@{
                HostToken = $parts[0]
                Algorithm = $parts[1]
                Fingerprint = $fingerprint
                Line = "$($parts[0]) $($parts[1]) $($parts[2])"
                Rank = [int]$algorithmRank[$parts[1]]
            })
    }
    if ($candidates.Count -eq 0) {
        throw 'SSH host-key discovery returned no supported host keys.'
    }
    $selected = if ([string]::IsNullOrWhiteSpace($ExpectedFingerprint)) {
        $matchingPinned = @($candidates | Where-Object { $_.Line -cin $existingLines })
        if ($matchingPinned.Count -gt 0) {
            @($matchingPinned | Sort-Object Rank, Fingerprint, Line)[0]
        }
        else {
            @($candidates | Sort-Object Rank, Fingerprint, Line)[0]
        }
    }
    else {
        @($candidates | Where-Object Fingerprint -CEQ $ExpectedFingerprint |
                Sort-Object Rank, Line | Select-Object -First 1)
    }
    if ($null -eq $selected) {
        throw "No discovered SSH host key matched '$ExpectedFingerprint'."
    }
    $matchingLine = [string]$selected.Line

    if ($matchingLine -cin $existingLines) {
        $result = [pscustomobject][ordered]@{
            Line = $matchingLine
            Algorithm = [string]$selected.Algorithm
            Fingerprint = [string]$selected.Fingerprint
            NewlyTrusted = $false
        }
        if ($PassThru) { return $result }
        return $matchingLine
    }
    $matchingHostToken = ($matchingLine -split '\s+', 2)[0]
    $changedIdentity = @($existingLines | Where-Object {
            -not [string]::IsNullOrWhiteSpace($_) -and
            ($_ -split '\s+', 2)[0] -ceq $matchingHostToken
        })
    if ($changedIdentity.Count -gt 0) {
        throw "The saved SSH identity for '$HostName`:$Port' has changed. Credentials were not sent."
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
    Write-Host "Accepting public key $($selected.Algorithm) $($selected.Fingerprint)"
    $result = [pscustomobject][ordered]@{
        Line = $matchingLine
        Algorithm = [string]$selected.Algorithm
        Fingerprint = [string]$selected.Fingerprint
        NewlyTrusted = $true
    }
    if ($PassThru) { return $result }
    $matchingLine
}
