Set-StrictMode -Version Latest

$script:HHDockerVolumeProviderId = 'hosthunter.docker-volume'
$script:HHDockerVolumeProviderVersion = 1
$script:HHDockerVolumeEnvelopeHeaderLength = 80
$script:HHDockerVolumeEnvelopeAuthenticatorLength = 32
$script:HHDockerVolumeKeyLength = 32
$script:HHDockerVolumeCoreAnchorLengths = @(196, 236)
$script:HHDockerVolumeForensicsAnchorLength = 240
$script:HHDockerVolumeLockTimeoutMilliseconds = 10000

function New-HHDockerVolumeProviderErrorRecord {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Builds an in-memory error record only.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ErrorId,
        [Parameter(Mandatory)][string]$Message,
        [Parameter(Mandatory)][Management.Automation.ErrorCategory]$Category,
        [AllowNull()][Exception]$InnerException
    )

    $exception = [InvalidOperationException]::new($Message, $InnerException)
    return [Management.Automation.ErrorRecord]::new(
        $exception,
        $ErrorId,
        $Category,
        $null
    )
}

function Stop-HHDockerVolumeProviderOperation {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Throws a terminating provider error and does not mutate state.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ErrorId,
        [Parameter(Mandatory)][string]$Message,
        [Parameter(Mandatory)][Management.Automation.ErrorCategory]$Category,
        [AllowNull()][Exception]$InnerException
    )

    $PSCmdlet.ThrowTerminatingError((New-HHDockerVolumeProviderErrorRecord `
            -ErrorId $ErrorId -Message $Message -Category $Category `
            -InnerException $InnerException))
}

function Get-HHSecretProviderSelection {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    if ([string]::IsNullOrWhiteSpace($env:HH_SECRET_PROVIDER)) {
        return 'PlatformNative'
    }
    if ([string]$env:HH_SECRET_PROVIDER -cne 'DockerVolume') {
        Stop-HHDockerVolumeProviderOperation `
            -ErrorId DockerVolumeProviderSelectionInvalid `
            -Message ('HH_SECRET_PROVIDER must be unset for the platform-native provider or ' +
                'set exactly to DockerVolume.') `
            -Category SecurityError
    }
    return 'DockerVolume'
}

function Get-HHDockerVolumeCanonicalPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name
    )

    if ([string]::IsNullOrWhiteSpace($Path) -or -not [IO.Path]::IsPathRooted($Path)) {
        Stop-HHDockerVolumeProviderOperation `
            -ErrorId DockerVolumeProviderPathInvalid `
            -Message "$Name must be an absolute non-empty path." `
            -Category InvalidArgument
    }
    $canonical = [IO.Path]::GetFullPath($Path)
    if ($canonical -ceq [IO.Path]::GetPathRoot($canonical)) {
        Stop-HHDockerVolumeProviderOperation `
            -ErrorId DockerVolumeProviderPathInvalid `
            -Message "$Name cannot be a filesystem root." `
            -Category SecurityError
    }
    return $canonical
}

function Test-HHDockerVolumePathOverlap {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][string]$First,
        [Parameter(Mandatory)][string]$Second
    )

    $firstToSecond = [IO.Path]::GetRelativePath($First, $Second)
    $secondToFirst = [IO.Path]::GetRelativePath($Second, $First)
    $separator = [IO.Path]::DirectorySeparatorChar
    $secondIsWithinFirst = $firstToSecond -eq '.' -or
        ($firstToSecond -ne '..' -and
            -not $firstToSecond.StartsWith("..$separator", [StringComparison]::Ordinal) -and
            -not [IO.Path]::IsPathRooted($firstToSecond))
    $firstIsWithinSecond = $secondToFirst -eq '.' -or
        ($secondToFirst -ne '..' -and
            -not $secondToFirst.StartsWith("..$separator", [StringComparison]::Ordinal) -and
            -not [IO.Path]::IsPathRooted($secondToFirst))
    return $secondIsWithinFirst -or $firstIsWithinSecond
}

function Assert-HHDockerVolumeDirectory {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not $IsLinux -or -not [IO.Directory]::Exists($Path)) {
        Stop-HHDockerVolumeProviderOperation `
            -ErrorId DockerVolumeProviderPathInvalid `
            -Message 'A required Docker-volume directory is unavailable.' `
            -Category ObjectNotFound
    }
    $current = [IO.DirectoryInfo]::new($Path)
    while ($null -ne $current) {
        if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            $null -ne $current.LinkTarget) {
            Stop-HHDockerVolumeProviderOperation `
                -ErrorId DockerVolumeProviderPathUnsafe `
                -Message 'Docker-volume provider paths cannot traverse links.' `
                -Category SecurityError
        }
        $current = $current.Parent
    }
    $requiredMode = [IO.UnixFileMode]::UserRead -bor
        [IO.UnixFileMode]::UserWrite -bor [IO.UnixFileMode]::UserExecute
    try {
        $actualMode = [IO.File]::GetUnixFileMode($Path)
    }
    catch {
        Stop-HHDockerVolumeProviderOperation `
            -ErrorId DockerVolumeProviderPathUnsafe `
            -Message 'Docker-volume directory permissions cannot be verified.' `
            -Category SecurityError -InnerException $_.Exception
    }
    if ($actualMode -ne $requiredMode) {
        Stop-HHDockerVolumeProviderOperation `
            -ErrorId DockerVolumeProviderPathUnsafe `
            -Message 'Docker-volume provider directories must have mode 0700.' `
            -Category SecurityError
    }
}

function Initialize-HHDockerVolumeDomainDirectory {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Creates an explicitly selected provider-private domain directory.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][ValidateSet('core', 'forensics')][string]$Domain
    )

    Assert-HHDockerVolumeDirectory -Path $Root
    $path = [IO.Path]::GetFullPath((Join-Path $Root $Domain))
    if (-not [IO.Directory]::Exists($path)) {
        try {
            $mode = [IO.UnixFileMode]::UserRead -bor
                [IO.UnixFileMode]::UserWrite -bor [IO.UnixFileMode]::UserExecute
            $null = [IO.Directory]::CreateDirectory($path, $mode)
        }
        catch {
            Stop-HHDockerVolumeProviderOperation `
                -ErrorId DockerVolumeProviderPathUnsafe `
                -Message 'A Docker-volume provider domain directory could not be created privately.' `
                -Category SecurityError -InnerException $_.Exception
        }
    }
    Assert-HHDockerVolumeDirectory -Path $path
    return $path
}

function Test-HHDockerVolumePrivateFile {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][string]$Path)

    $info = [IO.FileInfo]::new($Path)
    if (-not [IO.File]::Exists($Path)) {
        if ($null -ne $info.LinkTarget) {
            Stop-HHDockerVolumeProviderOperation `
                -ErrorId DockerVolumeProviderFileUnsafe `
                -Message 'Docker-volume provider files must not be links.' `
                -Category SecurityError
        }
        if ([IO.Directory]::Exists($Path)) {
            Stop-HHDockerVolumeProviderOperation `
                -ErrorId DockerVolumeProviderFileUnsafe `
                -Message 'A Docker-volume provider file path is a directory.' `
                -Category SecurityError
        }
        return $false
    }
    if ($null -ne $info.LinkTarget -or
        (($info.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        Stop-HHDockerVolumeProviderOperation `
            -ErrorId DockerVolumeProviderFileUnsafe `
            -Message 'Docker-volume provider files must not be links.' `
            -Category SecurityError
    }
    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if ([string]$item.UnixMode -notmatch '^-' -or
            $item.UnixFileMode -ne (
                [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite
            )) {
            Stop-HHDockerVolumeProviderOperation `
                -ErrorId DockerVolumeProviderFileUnsafe `
                -Message 'Docker-volume provider files must be regular files with mode 0600.' `
                -Category SecurityError
        }
    }
    catch {
        if (($_.FullyQualifiedErrorId -split ',', 2)[0] -eq
            'DockerVolumeProviderFileUnsafe') {
            throw
        }
        Stop-HHDockerVolumeProviderOperation `
            -ErrorId DockerVolumeProviderFileUnsafe `
            -Message 'A Docker-volume provider file cannot be safely inspected.' `
            -Category SecurityError -InnerException $_.Exception
    }
    return $true
}

function Read-HHDockerVolumePrivateFile {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][int]$MinimumLength,
        [Parameter(Mandatory)][int]$MaximumLength
    )

    if (-not (Test-HHDockerVolumePrivateFile -Path $Path)) {
        return $null
    }
    $stream = $null
    $bytes = $null
    try {
        $stream = [IO.File]::Open(
            $Path,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read
        )
        if (-not (Test-HHDockerVolumePrivateFile -Path $Path) -or
            $stream.Length -lt $MinimumLength -or $stream.Length -gt $MaximumLength) {
            Stop-HHDockerVolumeProviderOperation `
                -ErrorId DockerVolumeProviderArtifactInvalid `
                -Message 'A Docker-volume provider artifact has an invalid bounded length.' `
                -Category InvalidData
        }
        $bytes = [byte[]]::new([int]$stream.Length)
        $stream.ReadExactly($bytes, 0, $bytes.Length)
        Write-Output -InputObject $bytes -NoEnumerate
        $bytes = $null
    }
    catch {
        if ($null -ne $bytes) { [Array]::Clear($bytes, 0, $bytes.Length) }
        $knownId = ($_.FullyQualifiedErrorId -split ',', 2)[0]
        if ($knownId -in @(
                'DockerVolumeProviderFileUnsafe',
                'DockerVolumeProviderArtifactInvalid'
            )) {
            throw
        }
        Stop-HHDockerVolumeProviderOperation `
            -ErrorId DockerVolumeProviderFileUnsafe `
            -Message 'A Docker-volume provider artifact could not be read safely.' `
            -Category SecurityError -InnerException $_.Exception
    }
    finally {
        if ($null -ne $stream) { $stream.Dispose() }
    }
}

function Write-HHDockerVolumePrivateFileCreateNew {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Performs an atomic provider-private create-new operation.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes
    )

    $options = [IO.FileStreamOptions]::new()
    $options.Mode = [IO.FileMode]::CreateNew
    $options.Access = [IO.FileAccess]::Write
    $options.Share = [IO.FileShare]::None
    $options.Options = [IO.FileOptions]::WriteThrough
    $options.UnixCreateMode = [IO.UnixFileMode]::UserRead -bor
        [IO.UnixFileMode]::UserWrite
    $stream = $null
    try {
        $stream = [IO.File]::Open($Path, $options)
        if (-not (Test-HHDockerVolumePrivateFile -Path $Path)) {
            Stop-HHDockerVolumeProviderOperation `
                -ErrorId DockerVolumeProviderFileUnsafe `
                -Message 'A Docker-volume provider file was not created privately.' `
                -Category SecurityError
        }
        $stream.Write($Bytes, 0, $Bytes.Length)
        $stream.Flush($true)
    }
    finally {
        if ($null -ne $stream) { $stream.Dispose() }
    }
    $null = Test-HHDockerVolumePrivateFile -Path $Path
}

function Set-HHDockerVolumeUInt32BigEndian {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Mutates only the caller-owned in-memory byte buffer.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][byte[]]$Buffer,
        [Parameter(Mandatory)][int]$Offset,
        [Parameter(Mandatory)][uint32]$Value
    )

    for ($index = 0; $index -lt 4; $index++) {
        $Buffer[$Offset + $index] = [byte](($Value -shr ((3 - $index) * 8)) -band 0xff)
    }
}

function Get-HHDockerVolumeUInt32BigEndian {
    [CmdletBinding()]
    [OutputType([uint32])]
    param(
        [Parameter(Mandatory)][byte[]]$Buffer,
        [Parameter(Mandatory)][int]$Offset
    )

    [uint32]$value = 0
    for ($index = 0; $index -lt 4; $index++) {
        $value = ($value -shl 8) -bor [uint32]$Buffer[$Offset + $index]
    }
    return $value
}

function Get-HHDockerVolumeBindingHash {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param([Parameter(Mandatory)][string]$Value)

    $textBytes = [Text.Encoding]::UTF8.GetBytes(
        $Value.Normalize([Text.NormalizationForm]::FormC)
    )
    try {
        $digest = [Security.Cryptography.SHA256]::HashData($textBytes)
        Write-Output -InputObject $digest -NoEnumerate
    }
    finally { [Array]::Clear($textBytes, 0, $textBytes.Length) }
}

function New-HHDockerVolumeEnvelope {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Builds an in-memory binary envelope only.'
    )]
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)][ValidateSet('Key', 'Anchor')][string]$Kind,
        [Parameter(Mandatory)][ValidateSet('core', 'forensics')][string]$Domain,
        [Parameter(Mandatory)][string]$DataRoot,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Payload,
        [AllowNull()][byte[]]$MacKey
    )

    if ($Kind -eq 'Key' -and $Payload.Length -ne $script:HHDockerVolumeKeyLength) {
        Stop-HHDockerVolumeProviderOperation `
            -ErrorId DockerVolumeProviderArtifactInvalid `
            -Message 'A Docker-volume key payload must contain exactly 32 bytes.' `
            -Category InvalidData
    }
    if ($Kind -eq 'Anchor' -and ($null -eq $MacKey -or $MacKey.Length -ne 32)) {
        Stop-HHDockerVolumeProviderOperation `
            -ErrorId DockerVolumeProviderArtifactInvalid `
            -Message 'A Docker-volume anchor envelope requires its domain key.' `
            -Category SecurityError
    }
    $bodyLength = $script:HHDockerVolumeEnvelopeHeaderLength + $Payload.Length
    $envelope = [byte[]]::new(
        $bodyLength + $script:HHDockerVolumeEnvelopeAuthenticatorLength
    )
    $magic = [Text.Encoding]::ASCII.GetBytes(
        $(if ($Kind -eq 'Key') { 'HHDKEY01' } else { 'HHDANC01' })
    )
    $providerHash = $null
    $rootHash = $null
    $body = $null
    $authenticator = $null
    try {
        [Array]::Copy($magic, 0, $envelope, 0, 8)
        $envelope[8] = 1
        $envelope[9] = if ($Domain -eq 'core') { 1 } else { 2 }
        $envelope[10] = [byte]$script:HHDockerVolumeProviderVersion
        $envelope[11] = 0
        $providerHash = Get-HHDockerVolumeBindingHash `
            -Value $script:HHDockerVolumeProviderId
        $rootHash = Get-HHDockerVolumeBindingHash -Value $DataRoot
        [Array]::Copy($providerHash, 0, $envelope, 12, 32)
        [Array]::Copy($rootHash, 0, $envelope, 44, 32)
        Set-HHDockerVolumeUInt32BigEndian -Buffer $envelope -Offset 76 `
            -Value ([uint32]$Payload.Length)
        [Array]::Copy($Payload, 0, $envelope, 80, $Payload.Length)
        $body = [byte[]]::new($bodyLength)
        [Array]::Copy($envelope, 0, $body, 0, $bodyLength)
        if ($Kind -eq 'Key') {
            $authenticator = [Security.Cryptography.SHA256]::HashData($body)
        }
        else {
            $hmac = [Security.Cryptography.HMACSHA256]::new($MacKey)
            try { $authenticator = $hmac.ComputeHash($body) }
            finally { $hmac.Dispose() }
        }
        [Array]::Copy($authenticator, 0, $envelope, $bodyLength, 32)
        Write-Output -InputObject $envelope -NoEnumerate
        $envelope = $null
    }
    finally {
        [Array]::Clear($magic, 0, $magic.Length)
        if ($null -ne $providerHash) { [Array]::Clear($providerHash, 0, 32) }
        if ($null -ne $rootHash) { [Array]::Clear($rootHash, 0, 32) }
        if ($null -ne $body) { [Array]::Clear($body, 0, $body.Length) }
        if ($null -ne $authenticator) { [Array]::Clear($authenticator, 0, 32) }
        if ($null -ne $envelope) { [Array]::Clear($envelope, 0, $envelope.Length) }
    }
}

function ConvertFrom-HHDockerVolumeEnvelope {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)][ValidateSet('Key', 'Anchor')][string]$Kind,
        [Parameter(Mandatory)][ValidateSet('core', 'forensics')][string]$Domain,
        [Parameter(Mandatory)][string]$DataRoot,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Envelope,
        [Parameter(Mandatory)][int[]]$AllowedPayloadLength,
        [AllowNull()][byte[]]$MacKey
    )

    $minimumLength = $script:HHDockerVolumeEnvelopeHeaderLength +
        $script:HHDockerVolumeEnvelopeAuthenticatorLength
    if ($Envelope.Length -lt $minimumLength) {
        Stop-HHDockerVolumeProviderOperation `
            -ErrorId DockerVolumeProviderArtifactInvalid `
            -Message 'A Docker-volume provider artifact is truncated.' `
            -Category InvalidData
    }
    $expectedMagic = if ($Kind -eq 'Key') { 'HHDKEY01' } else { 'HHDANC01' }
    $actualMagic = [Text.Encoding]::ASCII.GetString($Envelope, 0, 8)
    $expectedDomain = if ($Domain -eq 'core') { 1 } else { 2 }
    $providerHash = Get-HHDockerVolumeBindingHash -Value $script:HHDockerVolumeProviderId
    $rootHash = Get-HHDockerVolumeBindingHash -Value $DataRoot
    try {
        $storedProviderHash = [byte[]]::new(32)
        $storedRootHash = [byte[]]::new(32)
        try {
            [Array]::Copy($Envelope, 12, $storedProviderHash, 0, 32)
            [Array]::Copy($Envelope, 44, $storedRootHash, 0, 32)
            if ($actualMagic -cne $expectedMagic -or $Envelope[8] -ne 1 -or
                $Envelope[9] -ne $expectedDomain -or
                $Envelope[10] -ne $script:HHDockerVolumeProviderVersion -or
                $Envelope[11] -ne 0 -or
                -not [Security.Cryptography.CryptographicOperations]::FixedTimeEquals(
                    $storedProviderHash,
                    $providerHash
                ) -or
                -not [Security.Cryptography.CryptographicOperations]::FixedTimeEquals(
                    $storedRootHash,
                    $rootHash
                )) {
                Stop-HHDockerVolumeProviderOperation `
                    -ErrorId DockerVolumeProviderMismatch `
                    -Message ('A Docker-volume artifact belongs to a different provider, ' +
                        'version, domain, or data root.') `
                    -Category SecurityError
            }
        }
        finally {
            [Array]::Clear($storedProviderHash, 0, 32)
            [Array]::Clear($storedRootHash, 0, 32)
        }

        $payloadLength = [int](Get-HHDockerVolumeUInt32BigEndian `
                -Buffer $Envelope -Offset 76)
        $bodyLength = $script:HHDockerVolumeEnvelopeHeaderLength + $payloadLength
        if ($payloadLength -notin $AllowedPayloadLength -or
            $Envelope.Length -ne ($bodyLength + 32)) {
            Stop-HHDockerVolumeProviderOperation `
                -ErrorId DockerVolumeProviderArtifactInvalid `
                -Message 'A Docker-volume provider artifact has an invalid payload length.' `
                -Category InvalidData
        }
        if ($Kind -eq 'Anchor' -and ($null -eq $MacKey -or $MacKey.Length -ne 32)) {
            Stop-HHDockerVolumeProviderOperation `
                -ErrorId DockerVolumeProviderArtifactInvalid `
                -Message 'A Docker-volume anchor cannot be verified without its domain key.' `
                -Category SecurityError
        }
        $body = [byte[]]::new($bodyLength)
        $storedAuthenticator = [byte[]]::new(32)
        $expectedAuthenticator = $null
        try {
            [Array]::Copy($Envelope, 0, $body, 0, $bodyLength)
            [Array]::Copy($Envelope, $bodyLength, $storedAuthenticator, 0, 32)
            if ($Kind -eq 'Key') {
                $expectedAuthenticator = [Security.Cryptography.SHA256]::HashData($body)
            }
            else {
                $hmac = [Security.Cryptography.HMACSHA256]::new($MacKey)
                try { $expectedAuthenticator = $hmac.ComputeHash($body) }
                finally { $hmac.Dispose() }
            }
            if (-not [Security.Cryptography.CryptographicOperations]::FixedTimeEquals(
                    $storedAuthenticator,
                    $expectedAuthenticator
                )) {
                Stop-HHDockerVolumeProviderOperation `
                    -ErrorId DockerVolumeProviderArtifactInvalid `
                    -Message 'A Docker-volume provider artifact failed authentication.' `
                    -Category SecurityError
            }
            $payload = [byte[]]::new($payloadLength)
            [Array]::Copy($Envelope, 80, $payload, 0, $payloadLength)
            Write-Output -InputObject $payload -NoEnumerate
        }
        finally {
            [Array]::Clear($body, 0, $body.Length)
            [Array]::Clear($storedAuthenticator, 0, 32)
            if ($null -ne $expectedAuthenticator) {
                [Array]::Clear($expectedAuthenticator, 0, 32)
            }
        }
    }
    finally {
        [Array]::Clear($providerHash, 0, 32)
        [Array]::Clear($rootHash, 0, 32)
    }
}

function Get-HHDockerVolumeDomainKey {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][ValidateSet('core', 'forensics')][string]$Domain,
        [Parameter(Mandatory)][string]$DataRoot,
        [switch]$RequireExisting
    )

    $minimum = $script:HHDockerVolumeEnvelopeHeaderLength + 32 + 32
    $existing = Read-HHDockerVolumePrivateFile `
        -Path $Path -MinimumLength $minimum -MaximumLength $minimum
    if ($null -ne $existing) {
        try {
            return ConvertFrom-HHDockerVolumeEnvelope -Kind Key -Domain $Domain `
                -DataRoot $DataRoot -Envelope $existing -AllowedPayloadLength @(32)
        }
        finally { [Array]::Clear($existing, 0, $existing.Length) }
    }
    if ($RequireExisting) {
        Stop-HHDockerVolumeProviderOperation `
            -ErrorId DockerVolumeKeyUnavailable `
            -Message 'Existing HostHunter state has no matching Docker-volume key.' `
            -Category ResourceUnavailable
    }

    $candidate = [byte[]]::new(32)
    [Security.Cryptography.RandomNumberGenerator]::Fill($candidate)
    $envelope = $null
    $temporaryPath = "$Path.$([Guid]::NewGuid().ToString('N')).tmp"
    try {
        $envelope = New-HHDockerVolumeEnvelope -Kind Key -Domain $Domain `
            -DataRoot $DataRoot -Payload $candidate
        Write-HHDockerVolumePrivateFileCreateNew -Path $temporaryPath -Bytes $envelope
        try {
            [IO.File]::Move($temporaryPath, $Path, $false)
        }
        catch {
            if (Test-Path -LiteralPath $temporaryPath) {
                [IO.File]::Delete($temporaryPath)
            }
            $winner = Read-HHDockerVolumePrivateFile `
                -Path $Path -MinimumLength $minimum -MaximumLength $minimum
            if ($null -eq $winner) {
                Stop-HHDockerVolumeProviderOperation `
                    -ErrorId DockerVolumeProviderArtifactInvalid `
                    -Message 'The Docker-volume key could not be created atomically.' `
                    -Category WriteError -InnerException $_.Exception
            }
            try {
                $winnerKey = ConvertFrom-HHDockerVolumeEnvelope -Kind Key `
                    -Domain $Domain -DataRoot $DataRoot -Envelope $winner `
                    -AllowedPayloadLength @(32)
                Write-Output -InputObject $winnerKey -NoEnumerate
                return
            }
            finally { [Array]::Clear($winner, 0, $winner.Length) }
        }
        $readback = Read-HHDockerVolumePrivateFile `
            -Path $Path -MinimumLength $minimum -MaximumLength $minimum
        try {
            $storedKey = ConvertFrom-HHDockerVolumeEnvelope -Kind Key `
                -Domain $Domain -DataRoot $DataRoot -Envelope $readback `
                -AllowedPayloadLength @(32)
            try {
                if (-not [Security.Cryptography.CryptographicOperations]::FixedTimeEquals(
                        $candidate,
                        $storedKey
                    )) {
                    Stop-HHDockerVolumeProviderOperation `
                        -ErrorId DockerVolumeProviderArtifactInvalid `
                        -Message 'The new Docker-volume key failed exact readback.' `
                        -Category WriteError
                }
                $result = [byte[]]$storedKey.Clone()
                Write-Output -InputObject $result -NoEnumerate
            }
            finally { [Array]::Clear($storedKey, 0, $storedKey.Length) }
        }
        finally { [Array]::Clear($readback, 0, $readback.Length) }
    }
    finally {
        if (Test-Path -LiteralPath $temporaryPath) {
            [IO.File]::Delete($temporaryPath)
        }
        [Array]::Clear($candidate, 0, $candidate.Length)
        if ($null -ne $envelope) { [Array]::Clear($envelope, 0, $envelope.Length) }
    }
}

function Enter-HHDockerVolumeAnchorLock {
    [CmdletBinding()]
    [OutputType([IO.FileStream])]
    param([Parameter(Mandatory)][string]$Path)

    $deadline = [DateTime]::UtcNow.AddMilliseconds(
        $script:HHDockerVolumeLockTimeoutMilliseconds
    )
    while ($true) {
        $null = Test-HHDockerVolumePrivateFile -Path $Path
        $options = [IO.FileStreamOptions]::new()
        $options.Mode = [IO.FileMode]::OpenOrCreate
        $options.Access = [IO.FileAccess]::ReadWrite
        $options.Share = [IO.FileShare]::None
        $options.Options = [IO.FileOptions]::WriteThrough
        $options.UnixCreateMode = [IO.UnixFileMode]::UserRead -bor
            [IO.UnixFileMode]::UserWrite
        try {
            $stream = [IO.File]::Open($Path, $options)
            if (-not (Test-HHDockerVolumePrivateFile -Path $Path)) {
                $stream.Dispose()
                Stop-HHDockerVolumeProviderOperation `
                    -ErrorId DockerVolumeProviderFileUnsafe `
                    -Message 'The Docker-volume anchor lock is unsafe.' `
                    -Category SecurityError
            }
            return $stream
        }
        catch [IO.IOException] {
            if ([DateTime]::UtcNow -ge $deadline) {
                Stop-HHDockerVolumeProviderOperation `
                    -ErrorId DockerVolumeProviderBusy `
                    -Message 'The Docker-volume anchor lock timed out.' `
                    -Category ResourceBusy -InnerException $_.Exception
            }
            Start-Sleep -Milliseconds 20
        }
    }
}

function Read-HHDockerVolumeAnchorPayload {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][ValidateSet('core', 'forensics')][string]$Domain,
        [Parameter(Mandatory)][string]$DataRoot,
        [Parameter(Mandatory)][byte[]]$MacKey
    )

    $allowed = if ($Domain -eq 'core') {
        [int[]]$script:HHDockerVolumeCoreAnchorLengths
    }
    else { [int[]]@($script:HHDockerVolumeForensicsAnchorLength) }
    $minimum = $script:HHDockerVolumeEnvelopeHeaderLength +
        ($allowed | Measure-Object -Minimum).Minimum + 32
    $maximum = $script:HHDockerVolumeEnvelopeHeaderLength +
        ($allowed | Measure-Object -Maximum).Maximum + 32
    $envelope = Read-HHDockerVolumePrivateFile `
        -Path $Path -MinimumLength $minimum -MaximumLength $maximum
    if ($null -eq $envelope) { return $null }
    try {
        return ConvertFrom-HHDockerVolumeEnvelope -Kind Anchor -Domain $Domain `
            -DataRoot $DataRoot -Envelope $envelope -AllowedPayloadLength $allowed `
            -MacKey $MacKey
    }
    finally { [Array]::Clear($envelope, 0, $envelope.Length) }
}

function Write-HHDockerVolumeAnchorPayload {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Implements the provider compare-and-swap contract.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$LockPath,
        [Parameter(Mandatory)][ValidateSet('core', 'forensics')][string]$Domain,
        [Parameter(Mandatory)][string]$DataRoot,
        [AllowNull()][byte[]]$ExpectedPayload,
        [Parameter(Mandatory)][byte[]]$NewPayload,
        [Parameter(Mandatory)][byte[]]$MacKey
    )

    $allowed = if ($Domain -eq 'core') {
        [int[]]$script:HHDockerVolumeCoreAnchorLengths
    }
    else { [int[]]@($script:HHDockerVolumeForensicsAnchorLength) }
    if ($NewPayload.Length -notin $allowed -or
        ($null -ne $ExpectedPayload -and $ExpectedPayload.Length -notin $allowed)) {
        Stop-HHDockerVolumeProviderOperation `
            -ErrorId DockerVolumeProviderArtifactInvalid `
            -Message 'A Docker-volume anchor has an invalid domain payload length.' `
            -Category InvalidData
    }
    $lock = Enter-HHDockerVolumeAnchorLock -Path $LockPath
    $current = $null
    $envelope = $null
    $temporaryPath = "$Path.$([Guid]::NewGuid().ToString('N')).tmp"
    try {
        $current = Read-HHDockerVolumeAnchorPayload -Path $Path -Domain $Domain `
            -DataRoot $DataRoot -MacKey $MacKey
        $isExpectedMatch = if ($null -eq $ExpectedPayload) {
            $null -eq $current
        }
        else {
            $null -ne $current -and
                [Security.Cryptography.CryptographicOperations]::FixedTimeEquals(
                    $ExpectedPayload,
                    $current
                )
        }
        if (-not $isExpectedMatch) {
            Stop-HHDockerVolumeProviderOperation `
                -ErrorId DockerVolumeAnchorCompareFailed `
                -Message 'The Docker-volume anchor changed concurrently or regressed.' `
                -Category SecurityError
        }
        $envelope = New-HHDockerVolumeEnvelope -Kind Anchor -Domain $Domain `
            -DataRoot $DataRoot -Payload $NewPayload -MacKey $MacKey
        Write-HHDockerVolumePrivateFileCreateNew -Path $temporaryPath -Bytes $envelope
        [IO.File]::Move($temporaryPath, $Path, $true)
        $readback = Read-HHDockerVolumeAnchorPayload -Path $Path -Domain $Domain `
            -DataRoot $DataRoot -MacKey $MacKey
        try {
            if ($null -eq $readback -or
                -not [Security.Cryptography.CryptographicOperations]::FixedTimeEquals(
                    $NewPayload,
                    $readback
                )) {
                Stop-HHDockerVolumeProviderOperation `
                    -ErrorId DockerVolumeProviderArtifactInvalid `
                    -Message 'The Docker-volume anchor failed exact readback.' `
                    -Category WriteError
            }
        }
        finally {
            if ($null -ne $readback) { [Array]::Clear($readback, 0, $readback.Length) }
        }
    }
    finally {
        if (Test-Path -LiteralPath $temporaryPath) { [IO.File]::Delete($temporaryPath) }
        if ($null -ne $current) { [Array]::Clear($current, 0, $current.Length) }
        if ($null -ne $envelope) { [Array]::Clear($envelope, 0, $envelope.Length) }
        $lock.Dispose()
    }
}

function New-HHDockerVolumePersistenceProvider {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Initializes private provider domain directories and returns callbacks.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DataRoot,
        [Parameter(Mandatory)][string]$SecretRoot,
        [Parameter(Mandatory)][string]$AnchorRoot
    )

    if (-not $IsLinux) {
        Stop-HHDockerVolumeProviderOperation `
            -ErrorId DockerVolumeProviderPlatformInvalid `
            -Message 'The DockerVolume provider is supported only inside the Linux runtime.' `
            -Category NotImplemented
    }
    $canonicalDataRoot = Get-HHDockerVolumeCanonicalPath -Path $DataRoot -Name DataRoot
    $canonicalSecretRoot = Get-HHDockerVolumeCanonicalPath `
        -Path $SecretRoot -Name HH_SECRET_ROOT
    $canonicalAnchorRoot = Get-HHDockerVolumeCanonicalPath `
        -Path $AnchorRoot -Name HH_ANCHOR_ROOT
    if ((Test-HHDockerVolumePathOverlap $canonicalDataRoot $canonicalSecretRoot) -or
        (Test-HHDockerVolumePathOverlap $canonicalDataRoot $canonicalAnchorRoot) -or
        (Test-HHDockerVolumePathOverlap $canonicalSecretRoot $canonicalAnchorRoot)) {
        Stop-HHDockerVolumeProviderOperation `
            -ErrorId DockerVolumeProviderPathInvalid `
            -Message 'Data, key, and anchor roots must be independent directory trees.' `
            -Category SecurityError
    }
    Assert-HHDockerVolumeDirectory -Path $canonicalSecretRoot
    Assert-HHDockerVolumeDirectory -Path $canonicalAnchorRoot
    $coreSecretRoot = Initialize-HHDockerVolumeDomainDirectory `
        -Root $canonicalSecretRoot -Domain core
    $forensicsSecretRoot = Initialize-HHDockerVolumeDomainDirectory `
        -Root $canonicalSecretRoot -Domain forensics
    $coreAnchorRoot = Initialize-HHDockerVolumeDomainDirectory `
        -Root $canonicalAnchorRoot -Domain core
    $forensicsAnchorRoot = Initialize-HHDockerVolumeDomainDirectory `
        -Root $canonicalAnchorRoot -Domain forensics

    $paths = [pscustomobject][ordered]@{
        CoreKey = Join-Path $coreSecretRoot 'master.key'
        CoreAnchor = Join-Path $coreAnchorRoot 'anchor.bin'
        CoreAnchorLock = Join-Path $coreAnchorRoot 'anchor.lock'
        ForensicsKey = Join-Path $forensicsSecretRoot 'master.key'
        ForensicsAnchor = Join-Path $forensicsAnchorRoot 'anchor.bin'
        ForensicsAnchorLock = Join-Path $forensicsAnchorRoot 'anchor.lock'
    }
    $providerModule = $ExecutionContext.SessionState.Module
    if ($null -eq $providerModule) {
        Stop-HHDockerVolumeProviderOperation `
            -ErrorId DockerVolumeProviderModuleUnavailable `
            -Message 'The DockerVolume provider requires module scope.' `
            -Category ResourceUnavailable
    }

    $coreKeyProvider = {
        param($PersistenceContext, $RequireExisting)
        & $providerModule {
            param($BoundDataRoot, $ProviderPaths, $Context, $ExistingRequired)
            if ([IO.Path]::GetFullPath([string]$Context.DataRoot) -cne $BoundDataRoot) {
                Stop-HHDockerVolumeProviderOperation `
                    -ErrorId DockerVolumeProviderMismatch `
                    -Message 'The DockerVolume provider was invoked for a different data root.' `
                    -Category SecurityError
            }
            $mustExist = [bool]$ExistingRequired -or
                (Test-HHDockerVolumePrivateFile -Path $ProviderPaths.CoreAnchor)
            Get-HHDockerVolumeDomainKey -Path $ProviderPaths.CoreKey -Domain core `
                -DataRoot $BoundDataRoot -RequireExisting:$mustExist
        } $canonicalDataRoot $paths $PersistenceContext $RequireExisting
    }.GetNewClosure()
    $coreAnchorReader = {
        param($PersistenceContext, $MasterKey)
        & $providerModule {
            param($BoundDataRoot, $ProviderPaths, $Context, $Key)
            if ([IO.Path]::GetFullPath([string]$Context.DataRoot) -cne $BoundDataRoot) {
                Stop-HHDockerVolumeProviderOperation `
                    -ErrorId DockerVolumeProviderMismatch `
                    -Message 'The DockerVolume provider was invoked for a different data root.' `
                    -Category SecurityError
            }
            $payload = Read-HHDockerVolumeAnchorPayload -Path $ProviderPaths.CoreAnchor `
                -Domain core -DataRoot $BoundDataRoot -MacKey $Key
            if ($null -eq $payload) { return $null }
            try {
                ConvertFrom-HHPersistenceAnchorArtifact -Artifact $payload -MasterKey $Key
            }
            finally { [Array]::Clear($payload, 0, $payload.Length) }
        } $canonicalDataRoot $paths $PersistenceContext $MasterKey
    }.GetNewClosure()
    $coreAnchorWriter = {
        param($PersistenceContext, $ExpectedArtifact, $NewArtifact, $MasterKey)
        & $providerModule {
            param($BoundDataRoot, $ProviderPaths, $Context, $Expected, $New, $Key)
            if ([IO.Path]::GetFullPath([string]$Context.DataRoot) -cne $BoundDataRoot) {
                Stop-HHDockerVolumeProviderOperation `
                    -ErrorId DockerVolumeProviderMismatch `
                    -Message 'The DockerVolume provider was invoked for a different data root.' `
                    -Category SecurityError
            }
            Write-HHDockerVolumeAnchorPayload -Path $ProviderPaths.CoreAnchor `
                -LockPath $ProviderPaths.CoreAnchorLock -Domain core `
                -DataRoot $BoundDataRoot -ExpectedPayload $Expected -NewPayload $New `
                -MacKey $Key
        } $canonicalDataRoot $paths $PersistenceContext $ExpectedArtifact `
            $NewArtifact $MasterKey
    }.GetNewClosure()
    $forensicsKeyProvider = {
        & $providerModule {
            param($BoundDataRoot, $ProviderPaths)
            $mustExist = [IO.File]::Exists((Join-Path $BoundDataRoot 'forensics.db')) -or
                (Test-HHDockerVolumePrivateFile -Path $ProviderPaths.ForensicsAnchor)
            $key = Get-HHDockerVolumeDomainKey -Path $ProviderPaths.ForensicsKey `
                -Domain forensics -DataRoot $BoundDataRoot -RequireExisting:$mustExist
            [pscustomobject]@{
                Service = 'HostHunterNextGeneration.Forensics.v1'
                Account = 'ledger-key'
                KeyBytes = $key
            }
        } $canonicalDataRoot $paths
    }.GetNewClosure()
    $forensicsAnchorReader = {
        param($PersistenceContext)
        & $providerModule {
            param($BoundDataRoot, $ProviderPaths, $Context)
            if ([IO.Path]::GetFullPath([string]$Context.DataRoot) -cne $BoundDataRoot) {
                Stop-HHDockerVolumeProviderOperation `
                    -ErrorId DockerVolumeProviderMismatch `
                    -Message 'The DockerVolume provider was invoked for a different data root.' `
                    -Category SecurityError
            }
            if (-not (Test-HHDockerVolumePrivateFile `
                        -Path $ProviderPaths.ForensicsAnchor)) {
                return $null
            }
            $key = Get-HHDockerVolumeDomainKey -Path $ProviderPaths.ForensicsKey `
                -Domain forensics -DataRoot $BoundDataRoot `
                -RequireExisting
            try {
                $payload = Read-HHDockerVolumeAnchorPayload `
                    -Path $ProviderPaths.ForensicsAnchor -Domain forensics `
                    -DataRoot $BoundDataRoot -MacKey $key
                if ($null -eq $payload) { return $null }
                try { ConvertFrom-HHForensicsAnchorArtifact -Artifact $payload }
                finally { [Array]::Clear($payload, 0, $payload.Length) }
            }
            finally { [Array]::Clear($key, 0, $key.Length) }
        } $canonicalDataRoot $paths $PersistenceContext
    }.GetNewClosure()
    $forensicsAnchorWriter = {
        param($ExpectedAnchor, $NewAnchor, $PersistenceContext)
        & $providerModule {
            param($BoundDataRoot, $ProviderPaths, $Expected, $New, $Context)
            if ([IO.Path]::GetFullPath([string]$Context.DataRoot) -cne $BoundDataRoot) {
                Stop-HHDockerVolumeProviderOperation `
                    -ErrorId DockerVolumeProviderMismatch `
                    -Message 'The DockerVolume provider was invoked for a different data root.' `
                    -Category SecurityError
            }
            $mustExist = [IO.File]::Exists((Join-Path $BoundDataRoot 'forensics.db')) -or
                (Test-HHDockerVolumePrivateFile -Path $ProviderPaths.ForensicsAnchor)
            $key = Get-HHDockerVolumeDomainKey -Path $ProviderPaths.ForensicsKey `
                -Domain forensics -DataRoot $BoundDataRoot `
                -RequireExisting:$mustExist
            $newArtifact = $null
            $expectedArtifact = $null
            try {
                $newArtifact = ConvertTo-HHForensicsAnchorArtifact -Anchor $New
                if ($null -ne $Expected) {
                    $expectedArtifact = ConvertTo-HHForensicsAnchorArtifact -Anchor $Expected
                }
                Write-HHDockerVolumeAnchorPayload `
                    -Path $ProviderPaths.ForensicsAnchor `
                    -LockPath $ProviderPaths.ForensicsAnchorLock -Domain forensics `
                    -DataRoot $BoundDataRoot -ExpectedPayload $expectedArtifact `
                    -NewPayload $newArtifact -MacKey $key
            }
            finally {
                [Array]::Clear($key, 0, $key.Length)
                if ($null -ne $newArtifact) {
                    [Array]::Clear($newArtifact, 0, $newArtifact.Length)
                }
                if ($null -ne $expectedArtifact) {
                    [Array]::Clear($expectedArtifact, 0, $expectedArtifact.Length)
                }
            }
        } $canonicalDataRoot $paths $ExpectedAnchor $NewAnchor $PersistenceContext
    }.GetNewClosure()

    return [pscustomobject][ordered]@{
        ProviderId = $script:HHDockerVolumeProviderId
        ProviderVersion = $script:HHDockerVolumeProviderVersion
        DataRoot = $canonicalDataRoot
        SecretRoot = $canonicalSecretRoot
        AnchorRoot = $canonicalAnchorRoot
        Paths = $paths
        CoreMasterKeyProvider = $coreKeyProvider
        CoreAnchorReader = $coreAnchorReader
        CoreAnchorWriter = $coreAnchorWriter
        ForensicsKeyProvider = $forensicsKeyProvider
        ForensicsAnchorReader = $forensicsAnchorReader
        ForensicsAnchorWriter = $forensicsAnchorWriter
    }
}

function Get-HHDockerVolumePersistenceProviderFromEnvironment {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$DataRoot)

    if ((Get-HHSecretProviderSelection) -cne 'DockerVolume') {
        Stop-HHDockerVolumeProviderOperation `
            -ErrorId DockerVolumeProviderSelectionInvalid `
            -Message 'The DockerVolume provider was not explicitly selected.' `
            -Category SecurityError
    }
    if ([string]::IsNullOrWhiteSpace($env:HH_SECRET_ROOT) -or
        [string]::IsNullOrWhiteSpace($env:HH_ANCHOR_ROOT)) {
        Stop-HHDockerVolumeProviderOperation `
            -ErrorId DockerVolumeProviderPathInvalid `
            -Message 'DockerVolume requires absolute HH_SECRET_ROOT and HH_ANCHOR_ROOT paths.' `
            -Category InvalidArgument
    }
    return New-HHDockerVolumePersistenceProvider -DataRoot $DataRoot `
        -SecretRoot $env:HH_SECRET_ROOT -AnchorRoot $env:HH_ANCHOR_ROOT
}
