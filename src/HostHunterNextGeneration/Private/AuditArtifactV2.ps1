Set-StrictMode -Version Latest

if (-not (Get-Command -Name Stop-HHPersistenceOperation -CommandType Function -ErrorAction SilentlyContinue)) {
    . (Join-Path $PSScriptRoot 'PersistenceErrors.ps1')
}
if (-not (Get-Command -Name Assert-HHAuditMasterKey -CommandType Function -ErrorAction SilentlyContinue)) {
    . (Join-Path $PSScriptRoot 'AuditKeyValidation.ps1')
}
if (-not (Get-Command -Name Protect-HHPersistenceValue -CommandType Function -ErrorAction SilentlyContinue)) {
    . (Join-Path $PSScriptRoot 'PersistenceCrypto.ps1')
}
if (-not (Get-Command -Name Publish-HHDurableFile -CommandType Function -ErrorAction SilentlyContinue)) {
    . (Join-Path $PSScriptRoot 'DurableFilePublisher.ps1')
}

$script:HHAuditArtifactV2MaximumPlaintextBytes = 100L * 1024L * 1024L
$script:HHAuditArtifactV2DefaultChunkBytes = 1024 * 1024
$script:HHAuditArtifactV2HeaderLength = 80
$script:HHAuditArtifactV2HeaderMagic = [Text.Encoding]::ASCII.GetBytes('HHOUTV02')
$script:HHAuditArtifactV2FooterMagic = [Text.Encoding]::ASCII.GetBytes('HHFOOT02')
$script:HHAuditArtifactV2ChunkMagic = [Text.Encoding]::ASCII.GetBytes('CHN2')

function Test-HHAuditArtifactV2ExceptionType {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][AllowNull()][object]$ErrorObject,
        [Parameter(Mandatory)][type]$ExceptionType
    )

    $exception = if ($ErrorObject -is [Management.Automation.ErrorRecord]) {
        $ErrorObject.Exception
    }
    elseif ($ErrorObject -is [Exception]) { $ErrorObject }
    else { $null }
    $visited = [Collections.Generic.HashSet[Exception]]::new()
    while ($null -ne $exception -and $visited.Add($exception)) {
        if ($ExceptionType.IsAssignableFrom($exception.GetType())) { return $true }
        $exception = $exception.InnerException
    }
    return $false
}

function Get-HHAuditArtifactV2DurableFailureState {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][AllowNull()][object]$ErrorObject)

    $exception = if ($ErrorObject -is [Management.Automation.ErrorRecord]) {
        $ErrorObject.Exception
    }
    elseif ($ErrorObject -is [Exception]) { $ErrorObject }
    else { $null }
    $visited = [Collections.Generic.HashSet[Exception]]::new()
    while ($null -ne $exception -and $visited.Add($exception)) {
        $property = $exception.GetType().GetProperty('FailureState')
        if ($null -ne $property) {
            return [string]$property.GetValue($exception)
        }
        $exception = $exception.InnerException
    }
    return $null
}

function Stop-HHAuditArtifactV2Operation {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Throws a terminating error and does not mutate external state.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ErrorId,
        [Parameter(Mandatory)][string]$Message,
        [Parameter(Mandatory)][Management.Automation.ErrorCategory]$Category,
        [AllowNull()][object]$TargetObject,
        [AllowNull()][Exception]$InnerException
    )

    Stop-HHPersistenceOperation @PSBoundParameters
}

function Assert-HHAuditArtifactV2Identity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Identity,
        [Parameter(Mandatory)][string]$Name
    )

    if ($Identity.Length -ne 16) {
        throw [ArgumentException]::new("$Name must contain exactly 16 bytes.", $Name)
    }
}

function ConvertTo-HHAuditArtifactV2UInt32 {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param([Parameter(Mandatory)][ValidateRange(0, [uint32]::MaxValue)][long]$Value)

    $bytes = [BitConverter]::GetBytes([uint32]$Value)
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($bytes) }
    Write-Output -InputObject $bytes -NoEnumerate
}

function ConvertTo-HHAuditArtifactV2UInt64 {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param([Parameter(Mandatory)][ValidateRange(0, [long]::MaxValue)][long]$Value)

    $bytes = [BitConverter]::GetBytes([uint64]$Value)
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($bytes) }
    Write-Output -InputObject $bytes -NoEnumerate
}

function ConvertFrom-HHAuditArtifactV2UInt32 {
    [CmdletBinding()]
    [OutputType([long])]
    param(
        [Parameter(Mandatory)][byte[]]$Bytes,
        [Parameter(Mandatory)][int]$Offset
    )

    $value = [byte[]]::new(4)
    [Array]::Copy($Bytes, $Offset, $value, 0, 4)
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($value) }
    return [long][BitConverter]::ToUInt32($value, 0)
}

function ConvertFrom-HHAuditArtifactV2UInt64 {
    [CmdletBinding()]
    [OutputType([long])]
    param(
        [Parameter(Mandatory)][byte[]]$Bytes,
        [Parameter(Mandatory)][int]$Offset
    )

    $value = [byte[]]::new(8)
    [Array]::Copy($Bytes, $Offset, $value, 0, 8)
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($value) }
    $unsigned = [BitConverter]::ToUInt64($value, 0)
    if ($unsigned -gt [long]::MaxValue) {
        Stop-HHAuditArtifactV2Operation -ErrorId AuditIntegrityFailed `
            -Message 'An audit artifact contains an out-of-range integer.' `
            -Category InvalidData -TargetObject $null
    }
    return [long]$unsigned
}

function Join-HHAuditArtifactV2Buffer {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Part)

    [long]$length = 0
    foreach ($item in $Part) { $length += ([byte[]]$item).Length }
    if ($length -gt [int]::MaxValue) { throw 'The artifact metadata buffer is too large.' }
    $result = [byte[]]::new([int]$length)
    $offset = 0
    foreach ($item in $Part) {
        $bytes = [byte[]]$item
        [Array]::Copy($bytes, 0, $result, $offset, $bytes.Length)
        $offset += $bytes.Length
    }
    Write-Output -InputObject $result -NoEnumerate
}

function Compress-HHAuditArtifactV2Chunk {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param([Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes)

    $output = [IO.MemoryStream]::new()
    try {
        $gzip = [IO.Compression.GZipStream]::new($output, [IO.Compression.CompressionLevel]::Optimal, $true)
        try { $gzip.Write($Bytes, 0, $Bytes.Length) } finally { $gzip.Dispose() }
        $result = $output.ToArray()
        Write-Output -InputObject $result -NoEnumerate
    }
    finally { $output.Dispose() }
}

function Expand-HHAuditArtifactV2Chunk {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes,
        [Parameter(Mandatory)][ValidateRange(0, [int]::MaxValue)][int]$ExpectedLength
    )

    $inputStream = [IO.MemoryStream]::new($Bytes, $false)
    $output = [IO.MemoryStream]::new()
    try {
        $gzip = [IO.Compression.GZipStream]::new($inputStream, [IO.Compression.CompressionMode]::Decompress)
        try {
            $buffer = [byte[]]::new(8192)
            try {
                while (($read = $gzip.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    if ($output.Length + $read -gt $ExpectedLength) {
                        Stop-HHAuditArtifactV2Operation -ErrorId AuditIntegrityFailed `
                            -Message 'An audit artifact chunk expands beyond its authenticated length.' `
                            -Category InvalidData -TargetObject $null
                    }
                    $output.Write($buffer, 0, $read)
                }
            }
            finally { [Array]::Clear($buffer, 0, $buffer.Length) }
        }
        catch [Management.Automation.ActionPreferenceStopException] { throw }
        catch {
            Stop-HHAuditArtifactV2Operation -ErrorId AuditIntegrityFailed `
                -Message 'An audit artifact chunk contains invalid compressed data.' `
                -Category InvalidData -TargetObject $null -InnerException $_.Exception
        }
        finally { $gzip.Dispose() }
        if ($output.Length -ne $ExpectedLength) {
            Stop-HHAuditArtifactV2Operation -ErrorId AuditIntegrityFailed `
                -Message 'An audit artifact chunk does not match its authenticated length.' `
                -Category InvalidData -TargetObject $null
        }
        $result = $output.ToArray()
        Write-Output -InputObject $result -NoEnumerate
    }
    finally {
        $output.Dispose()
        $inputStream.Dispose()
    }
}

function Get-HHAuditArtifactV2Header {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)][byte[]]$DatabaseId,
        [Parameter(Mandatory)][byte[]]$LedgerId,
        [Parameter(Mandatory)][byte[]]$InvocationId,
        [Parameter(Mandatory)][byte[]]$ArtifactId,
        [Parameter(Mandatory)][ValidateRange(4096, 4194304)][int]$ChunkSize
    )

    foreach ($identity in @(
            @{ Value = $DatabaseId; Name = 'DatabaseId' },
            @{ Value = $LedgerId; Name = 'LedgerId' },
            @{ Value = $InvocationId; Name = 'InvocationId' },
            @{ Value = $ArtifactId; Name = 'ArtifactId' }
        )) {
        Assert-HHAuditArtifactV2Identity -Identity $identity.Value -Name $identity.Name
    }
    $flags = [byte[]](2, 1, 1, 0)
    return Join-HHAuditArtifactV2Buffer -Part @(
        $script:HHAuditArtifactV2HeaderMagic,
        $flags,
        (ConvertTo-HHAuditArtifactV2UInt32 -Value $ChunkSize),
        $DatabaseId,
        $LedgerId,
        $InvocationId,
        $ArtifactId
    )
}

function Get-HHAuditArtifactV2EventFrame {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param([Parameter(Mandatory)][object]$EventRecord)

    $required = @('Sequence', 'RemoteSequence', 'ObservedAtUtc', 'Phase', 'Stream',
        'TypeName', 'SerializedByteCount', 'IsTerminating', 'Value')
    foreach ($name in $required) {
        if ($null -eq $EventRecord.PSObject.Properties[$name]) {
            throw [ArgumentException]::new("Audit stream event property '$name' is required.")
        }
    }
    if ([long]$EventRecord.Sequence -lt 0 -or [long]$EventRecord.SerializedByteCount -lt 0 -or
        $EventRecord.IsTerminating -isnot [bool]) {
        throw [ArgumentException]::new('Audit stream event counters and flags are invalid.')
    }
    $timestamp = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParse([string]$EventRecord.ObservedAtUtc, [ref]$timestamp)) {
        throw [ArgumentException]::new('Audit stream event timestamp is invalid.')
    }
    $serializedValue = [Management.Automation.PSSerializer]::Serialize($EventRecord.Value, 20)
    $frame = [ordered]@{
        Sequence = [long]$EventRecord.Sequence
        RemoteSequence = if ($null -eq $EventRecord.RemoteSequence) { $null } else { [long]$EventRecord.RemoteSequence }
        ObservedAtUtc = $timestamp.ToUniversalTime().ToString('o')
        Phase = [string]$EventRecord.Phase
        Stream = [string]$EventRecord.Stream
        TypeName = [string]$EventRecord.TypeName
        SerializedByteCount = [long]$EventRecord.SerializedByteCount
        IsTerminating = [bool]$EventRecord.IsTerminating
        SerializedValue = $serializedValue
    }
    $json = $frame | ConvertTo-Json -Depth 8 -Compress -WarningAction Stop -ErrorAction Stop
    $bytes = [Text.UTF8Encoding]::new($false, $true).GetBytes($json + "`n")
    Write-Output -InputObject $bytes -NoEnumerate
}

function Set-HHAuditArtifactV2PrivateMode {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Internal hardening for an already authorized artifact path.')]
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [switch]$Directory)

    if ($IsWindows) { return }
    $mode = if ($Directory) {
        [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite -bor [IO.UnixFileMode]::UserExecute
    }
    else { [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite }
    [IO.File]::SetUnixFileMode($Path, $mode)
}

function Open-HHAuditArtifactV2Writer {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'The caller owns ShouldProcess and has already authorized the audited operation.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DataRoot,
        [Parameter(Mandatory)][string]$OutputRoot,
        [Parameter(Mandatory)][string]$RecoveryRoot,
        [Parameter(Mandatory)][byte[]]$DatabaseId,
        [Parameter(Mandatory)][byte[]]$LedgerId,
        [Parameter(Mandatory)][byte[]]$InvocationId,
        [Parameter(Mandatory)][byte[]]$ArtifactId,
        [Parameter(Mandatory)][byte[]]$MasterKey,
        [ValidateRange(4096, 4194304)][int]$ChunkSize = $script:HHAuditArtifactV2DefaultChunkBytes
    )

    Assert-HHAuditMasterKey -MasterKey $MasterKey
    $root = [IO.Path]::GetFullPath($DataRoot)
    $output = [IO.Path]::GetFullPath($OutputRoot)
    $recovery = [IO.Path]::GetFullPath($RecoveryRoot)
    foreach ($candidate in @($output, $recovery)) {
        $relative = [IO.Path]::GetRelativePath($root, $candidate)
        if ($relative -eq '..' -or $relative.StartsWith("..$([IO.Path]::DirectorySeparatorChar)") -or
            [IO.Path]::IsPathRooted($relative)) {
            Stop-HHAuditArtifactV2Operation -ErrorId PersistencePathUnsafe `
                -Message 'The audit artifact directory must remain inside the data root.' `
                -Category SecurityError -TargetObject $candidate
        }
    }
    foreach ($directory in @($output, $recovery)) {
        [IO.Directory]::CreateDirectory($directory) | Out-Null
        $info = [IO.DirectoryInfo]::new($directory)
        if (($info.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $null -ne $info.LinkTarget) {
            Stop-HHAuditArtifactV2Operation -ErrorId PersistencePathUnsafe `
                -Message 'The audit artifact directory cannot be a link or reparse point.' `
                -Category SecurityError -TargetObject $directory
        }
        Set-HHAuditArtifactV2PrivateMode -Path $directory -Directory
    }

    $header = Get-HHAuditArtifactV2Header -DatabaseId $DatabaseId -LedgerId $LedgerId `
        -InvocationId $InvocationId -ArtifactId $ArtifactId -ChunkSize $ChunkSize
    $invocationText = [Convert]::ToHexString($InvocationId).ToLowerInvariant()
    $artifactText = [Convert]::ToHexString($ArtifactId).ToLowerInvariant()
    $finalPath = Join-Path $output "$invocationText.hhout"
    $temporaryPath = Join-Path $output ".$invocationText.$artifactText.tmp"
    if ([IO.File]::Exists($finalPath)) {
        Stop-HHAuditArtifactV2Operation -ErrorId AuditIntegrityFailed `
            -Message 'An audit artifact already exists for this invocation.' `
            -Category ResourceExists -TargetObject $finalPath
    }
    try {
        $stream = [IO.FileStream]::new($temporaryPath, [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write, [IO.FileShare]::None, 65536, [IO.FileOptions]::WriteThrough)
        Set-HHAuditArtifactV2PrivateMode -Path $temporaryPath
        $stream.Write($header, 0, $header.Length)
    }
    catch {
        if ([IO.File]::Exists($temporaryPath)) { [IO.File]::Delete($temporaryPath) }
        throw
    }
    $writer = [pscustomobject][ordered]@{
        State = 'Open'
        Stream = $stream
        TemporaryPath = $temporaryPath
        FinalPath = $finalPath
        RecoveryRoot = $recovery
        Header = $header
        HeaderHash = Get-HHPersistenceHash -Bytes $header
        DatabaseId = [byte[]]$DatabaseId.Clone()
        LedgerId = [byte[]]$LedgerId.Clone()
        InvocationId = [byte[]]$InvocationId.Clone()
        ArtifactId = [byte[]]$ArtifactId.Clone()
        MasterKey = [byte[]]$MasterKey.Clone()
        ChunkSize = $ChunkSize
        ChunkCount = [long]0
        EventCount = [long]0
        PlaintextTotal = [long]0
        CiphertextTotal = [long]0
        PreviousTag = [byte[]]::new(16)
        Digest = [Security.Cryptography.IncrementalHash]::CreateHash([Security.Cryptography.HashAlgorithmName]::SHA256)
        PublishedPath = $null
        QuarantinePath = $null
    }
    $writer.PSObject.TypeNames.Insert(0, 'HostHunter.AuditArtifactV2Writer')
    return $writer
}

function Write-HHAuditArtifactV2Chunk {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'This is an internal write on an already authorized artifact writer.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Writer,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Plaintext
    )

    $compressed = Compress-HHAuditArtifactV2Chunk -Bytes $Plaintext
    $sequenceBytes = ConvertTo-HHAuditArtifactV2UInt64 -Value $Writer.ChunkCount
    $plainLengthBytes = ConvertTo-HHAuditArtifactV2UInt32 -Value $Plaintext.Length
    $compressedLengthBytes = ConvertTo-HHAuditArtifactV2UInt32 -Value $compressed.Length
    $aad = Join-HHAuditArtifactV2Buffer -Part @(
        [Text.Encoding]::ASCII.GetBytes('HostHunterNextGeneration/hhout/chunk/v2'),
        $Writer.HeaderHash, $sequenceBytes, $Writer.PreviousTag, $plainLengthBytes, $compressedLengthBytes
    )
    $envelope = Protect-HHPersistenceValue -Plaintext $compressed -MasterKey $Writer.MasterKey -AssociatedData $aad
    $envelopeLengthBytes = ConvertTo-HHAuditArtifactV2UInt32 -Value $envelope.Length
    try {
        foreach ($bytes in @($script:HHAuditArtifactV2ChunkMagic, $sequenceBytes,
                $plainLengthBytes, $envelopeLengthBytes, $envelope)) {
            $Writer.Stream.Write($bytes, 0, $bytes.Length)
        }
    }
    catch {
        if (Test-HHAuditArtifactV2ExceptionType -ErrorObject $_ -ExceptionType ([IO.IOException])) {
            Stop-HHAuditArtifactV2Operation -ErrorId PersistenceStorageFull `
                -Message 'The audit artifact chunk could not be written durably.' `
                -Category WriteError -TargetObject $Writer.TemporaryPath -InnerException $_.Exception
        }
        throw
    }
    [Array]::Copy($envelope, 16, $Writer.PreviousTag, 0, 16)
    $Writer.ChunkCount++
    $Writer.CiphertextTotal += $envelope.Length
}

function Write-HHAuditArtifactV2Event {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'This is an internal write on an already authorized artifact writer.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Writer,
        [Parameter(Mandatory)][object]$EventRecord
    )

    if ($Writer.State -cne 'Open') { throw 'The audit artifact writer is not open.' }
    if ([long]$EventRecord.Sequence -ne $Writer.EventCount) {
        throw [ArgumentException]::new('Audit stream event sequence is not contiguous.')
    }
    $frame = Get-HHAuditArtifactV2EventFrame -EventRecord $EventRecord
    if ($Writer.PlaintextTotal + $frame.Length -gt $script:HHAuditArtifactV2MaximumPlaintextBytes) {
        Stop-HHAuditArtifactV2Operation -ErrorId PersistenceCapacityInsufficient `
            -Message 'The audit artifact exceeds the 100 MiB canonical-event limit.' `
            -Category LimitsExceeded -TargetObject $Writer.FinalPath
    }
    $Writer.Digest.AppendData($frame)
    $offset = 0
    while ($offset -lt $frame.Length) {
        $length = [Math]::Min($Writer.ChunkSize, $frame.Length - $offset)
        $chunk = [byte[]]::new($length)
        [Array]::Copy($frame, $offset, $chunk, 0, $length)
        try { Write-HHAuditArtifactV2Chunk -Writer $Writer -Plaintext $chunk }
        finally { [Array]::Clear($chunk, 0, $chunk.Length) }
        $offset += $length
    }
    $Writer.PlaintextTotal += $frame.Length
    $Writer.EventCount++
    try { $Writer.Stream.Flush($true) }
    catch {
        if (Test-HHAuditArtifactV2ExceptionType -ErrorObject $_ -ExceptionType ([IO.IOException])) {
            Stop-HHAuditArtifactV2Operation -ErrorId PersistenceStorageFull `
                -Message 'The audit artifact event could not be flushed durably.' `
                -Category WriteError -TargetObject $Writer.TemporaryPath -InnerException $_.Exception
        }
        throw
    }
}

function Complete-HHAuditArtifactV2Writer {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'This finalizes an already authorized artifact writer.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Writer,
        [scriptblock]$DurablePublisher
    )

    if ($Writer.State -cne 'Open') { throw 'The audit artifact writer is not open.' }
    $digest = $Writer.Digest.GetHashAndReset()
    $footerFields = Join-HHAuditArtifactV2Buffer -Part @(
        $script:HHAuditArtifactV2FooterMagic,
        (ConvertTo-HHAuditArtifactV2UInt64 -Value $Writer.ChunkCount),
        (ConvertTo-HHAuditArtifactV2UInt64 -Value $Writer.EventCount),
        (ConvertTo-HHAuditArtifactV2UInt64 -Value $Writer.PlaintextTotal),
        (ConvertTo-HHAuditArtifactV2UInt64 -Value $Writer.CiphertextTotal),
        $digest
    )
    $aad = Join-HHAuditArtifactV2Buffer -Part @(
        [Text.Encoding]::ASCII.GetBytes('HostHunterNextGeneration/hhout/footer/v2'),
        $Writer.HeaderHash, $Writer.PreviousTag, $footerFields
    )
    $footerEnvelope = Protect-HHPersistenceValue -Plaintext ([byte[]]::new(0)) `
        -MasterKey $Writer.MasterKey -AssociatedData $aad
    try {
        $Writer.Stream.Write($footerFields, 0, $footerFields.Length)
        $lengthBytes = ConvertTo-HHAuditArtifactV2UInt32 -Value $footerEnvelope.Length
        $Writer.Stream.Write($lengthBytes, 0, $lengthBytes.Length)
        $Writer.Stream.Write($footerEnvelope, 0, $footerEnvelope.Length)
        $Writer.Stream.Flush($true)
        $Writer.Stream.Dispose()
        $Writer.Stream = $null
        if ($null -eq $DurablePublisher) {
            Publish-HHDurableFile -SourcePath $Writer.TemporaryPath -DestinationPath $Writer.FinalPath
        }
        else {
            & $DurablePublisher $Writer.TemporaryPath $Writer.FinalPath
        }
        $Writer.PublishedPath = $Writer.FinalPath
        $Writer.State = 'Completed'
        $info = [IO.FileInfo]::new($Writer.FinalPath)
        $hash = [Convert]::FromHexString((Get-FileHash -LiteralPath $Writer.FinalPath -Algorithm SHA256).Hash)
        return [pscustomobject][ordered]@{
            Path = $Writer.FinalPath
            RelativeFileName = $info.Name
            Bytes = $info.Length
            CiphertextSha256 = $hash
            FormatVersion = 2
            ChunkCount = $Writer.ChunkCount
            StreamEventCount = $Writer.EventCount
            PlaintextBytes = $Writer.PlaintextTotal
        }
    }
    catch {
        $publicationFailure = $_
        if ($null -ne $Writer.Stream) { $Writer.Stream.Dispose(); $Writer.Stream = $null }
        $durableFailureState = Get-HHAuditArtifactV2DurableFailureState -ErrorObject $publicationFailure
        $Writer.State = if ($durableFailureState -ceq 'PostRenamePossiblyCommitted') {
            'PublicationUnknown'
        }
        else { 'Faulted' }
        if ($durableFailureState -ceq 'Collision') {
            Stop-HHAuditArtifactV2Operation -ErrorId AuditIntegrityFailed `
                -Message 'An audit artifact already exists for this invocation.' `
                -Category ResourceExists -TargetObject $Writer.FinalPath `
                -InnerException $publicationFailure.Exception
        }
        if (Test-HHAuditArtifactV2ExceptionType -ErrorObject $publicationFailure `
                -ExceptionType ([IO.IOException])) {
            Stop-HHAuditArtifactV2Operation -ErrorId PersistenceStorageFull `
                -Message 'The audit artifact could not be durably published.' `
                -Category WriteError -TargetObject $Writer.FinalPath `
                -InnerException $publicationFailure.Exception
        }
        throw $publicationFailure
    }
    finally {
        $Writer.Digest.Dispose()
        [Array]::Clear($Writer.MasterKey, 0, $Writer.MasterKey.Length)
    }
}

function Abort-HHAuditArtifactV2Writer {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '',
        Justification = 'Abort is the explicit API contract for quarantining an incomplete writer.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'This quarantines an incomplete artifact created by an already authorized operation.')]
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Writer)

    if ($Writer.State -cnotin @('Open', 'Faulted', 'PublicationUnknown')) {
        return $Writer.QuarantinePath
    }
    if ($null -ne $Writer.Stream) { $Writer.Stream.Dispose(); $Writer.Stream = $null }
    $Writer.Digest.Dispose()
    [Array]::Clear($Writer.MasterKey, 0, $Writer.MasterKey.Length)
    if ([IO.File]::Exists($Writer.TemporaryPath)) {
        $name = '{0}.{1}.partial' -f @(
            [Convert]::ToHexString($Writer.InvocationId).ToLowerInvariant(),
            [Guid]::NewGuid().ToString('N')
        )
        $quarantine = Join-Path $Writer.RecoveryRoot $name
        [IO.File]::Move($Writer.TemporaryPath, $quarantine, $false)
        Set-HHAuditArtifactV2PrivateMode -Path $quarantine
        $Writer.QuarantinePath = $quarantine
    }
    $Writer.State = 'Aborted'
    return $Writer.QuarantinePath
}

function Read-HHAuditArtifactV2Exact {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param([Parameter(Mandatory)][IO.Stream]$Stream, [Parameter(Mandatory)][int]$Length)

    $bytes = [byte[]]::new($Length)
    $offset = 0
    while ($offset -lt $Length) {
        $read = $Stream.Read($bytes, $offset, $Length - $offset)
        if ($read -le 0) {
            Stop-HHAuditArtifactV2Operation -ErrorId AuditIntegrityFailed `
                -Message 'The audit artifact is truncated.' -Category InvalidData -TargetObject $null
        }
        $offset += $read
    }
    Write-Output -InputObject $bytes -NoEnumerate
}

function ConvertFrom-HHAuditArtifactV2Frame {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][byte[]]$Bytes,
        [ValidateRange(0, [long]::MaxValue)][long]$ExpectedSequence = 0,
        [switch]$Emit
    )

    try {
        $json = [Text.UTF8Encoding]::new($false, $true).GetString($Bytes)
        $jsonDocument = [Text.Json.JsonDocument]::Parse($json)
        try {
            $timestampElement = $jsonDocument.RootElement.GetProperty('ObservedAtUtc')
            if ($timestampElement.ValueKind -ne [Text.Json.JsonValueKind]::String) {
                throw 'Invalid frame timestamp.'
            }
            $timestampText = $timestampElement.GetString()
        }
        finally { $jsonDocument.Dispose() }
        $frame = $json | ConvertFrom-Json -Depth 10 -NoEnumerate -ErrorAction Stop
        $expected = @('Sequence', 'RemoteSequence', 'ObservedAtUtc', 'Phase', 'Stream', 'TypeName',
            'SerializedByteCount', 'IsTerminating', 'SerializedValue')
        $actual = @($frame.PSObject.Properties.Name)
        if (@($expected | Where-Object { $_ -cnotin $actual }).Count -gt 0 -or
            @($actual | Where-Object { $_ -cnotin $expected }).Count -gt 0) { throw 'Unexpected frame shape.' }
        if ([long]$frame.Sequence -ne $ExpectedSequence -or [long]$frame.SerializedByteCount -lt 0 -or
            $frame.IsTerminating -isnot [bool]) { throw 'Invalid frame values.' }
        $timestamp = [DateTimeOffset]::MinValue
        if (-not [DateTimeOffset]::TryParse(
                $timestampText,
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::RoundtripKind,
                [ref]$timestamp
            )) {
            throw 'Invalid frame timestamp.'
        }
        $value = [Management.Automation.PSSerializer]::Deserialize([string]$frame.SerializedValue)
        if ($Emit) {
            $auditEvent = [pscustomobject][ordered]@{
                Sequence = [long]$frame.Sequence
                RemoteSequence = if ($null -eq $frame.RemoteSequence) { $null } else { [long]$frame.RemoteSequence }
                ObservedAtUtc = $timestamp.ToUniversalTime().ToString('o')
                Phase = [string]$frame.Phase
                Stream = [string]$frame.Stream
                TypeName = [string]$frame.TypeName
                SerializedByteCount = [long]$frame.SerializedByteCount
                IsTerminating = [bool]$frame.IsTerminating
                SerializedValue = [string]$frame.SerializedValue
                Value = $value
            }
            $auditEvent.PSObject.TypeNames.Insert(0, 'HostHunter.AuditStreamEvent')
            Write-Output $auditEvent
        }
    }
    catch [Management.Automation.ActionPreferenceStopException] { throw }
    catch {
        Stop-HHAuditArtifactV2Operation -ErrorId AuditIntegrityFailed `
            -Message 'The audit artifact contains an invalid canonical event frame.' `
            -Category InvalidData -TargetObject $null -InnerException $_.Exception
    }
}

function Read-HHAuditArtifactV2Pass {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][IO.Stream]$Stream,
        [Parameter(Mandatory)][byte[]]$MasterKey,
        [Parameter(Mandatory)][byte[]]$ExpectedHeader,
        [switch]$Emit
    )

    $Stream.Position = 0
    $header = Read-HHAuditArtifactV2Exact -Stream $Stream -Length $script:HHAuditArtifactV2HeaderLength
    if (-not (Test-HHPersistenceBytesEqual -Left $header -Right $ExpectedHeader)) {
        Stop-HHAuditArtifactV2Operation -ErrorId AuditIntegrityFailed `
            -Message 'The audit artifact identity header does not match the requested invocation.' `
            -Category SecurityError -TargetObject $null
    }
    $headerHash = Get-HHPersistenceHash -Bytes $header
    $chunkSize = ConvertFrom-HHAuditArtifactV2UInt32 -Bytes $header -Offset 12
    $previousTag = [byte[]]::new(16)
    $digest = [Security.Cryptography.IncrementalHash]::CreateHash([Security.Cryptography.HashAlgorithmName]::SHA256)
    $line = [IO.MemoryStream]::new()
    [long]$chunkCount = 0
    [long]$eventCount = 0
    [long]$plaintextTotal = 0
    [long]$ciphertextTotal = 0
    try {
        while ($true) {
            $marker = Read-HHAuditArtifactV2Exact -Stream $Stream -Length 4
            if ([Text.Encoding]::ASCII.GetString($marker) -ceq 'HHFO') {
                $footerRest = Read-HHAuditArtifactV2Exact -Stream $Stream -Length 68
                $footerFields = Join-HHAuditArtifactV2Buffer -Part @($marker, $footerRest)
                if ([Text.Encoding]::ASCII.GetString($footerFields, 0, 8) -cne 'HHFOOT02') {
                    Stop-HHAuditArtifactV2Operation -ErrorId AuditIntegrityFailed `
                        -Message 'The audit artifact footer marker is invalid.' -Category InvalidData -TargetObject $null
                }
                $declaredChunks = ConvertFrom-HHAuditArtifactV2UInt64 -Bytes $footerFields -Offset 8
                $declaredEvents = ConvertFrom-HHAuditArtifactV2UInt64 -Bytes $footerFields -Offset 16
                $declaredPlaintext = ConvertFrom-HHAuditArtifactV2UInt64 -Bytes $footerFields -Offset 24
                $declaredCiphertext = ConvertFrom-HHAuditArtifactV2UInt64 -Bytes $footerFields -Offset 32
                $declaredDigest = [byte[]]::new(32)
                [Array]::Copy($footerFields, 40, $declaredDigest, 0, 32)
                $envelopeLengthBytes = Read-HHAuditArtifactV2Exact -Stream $Stream -Length 4
                $envelopeLength = ConvertFrom-HHAuditArtifactV2UInt32 -Bytes $envelopeLengthBytes -Offset 0
                if ($envelopeLength -lt 32 -or $envelopeLength -gt 4096) { throw 'Invalid footer envelope length.' }
                $envelope = Read-HHAuditArtifactV2Exact -Stream $Stream -Length ([int]$envelopeLength)
                $aad = Join-HHAuditArtifactV2Buffer -Part @(
                    [Text.Encoding]::ASCII.GetBytes('HostHunterNextGeneration/hhout/footer/v2'),
                    $headerHash, $previousTag, $footerFields
                )
                $footerPlaintext = Unprotect-HHPersistenceValue -Envelope $envelope `
                    -MasterKey $MasterKey -AssociatedData $aad
                if ($footerPlaintext.Length -ne 0 -or $Stream.Position -ne $Stream.Length -or $line.Length -ne 0) {
                    throw 'The audit artifact footer or final frame is invalid.'
                }
                $actualDigest = $digest.GetHashAndReset()
                if ($declaredChunks -ne $chunkCount -or $declaredEvents -ne $eventCount -or
                    $declaredPlaintext -ne $plaintextTotal -or $declaredCiphertext -ne $ciphertextTotal -or
                    -not (Test-HHPersistenceBytesEqual -Left $declaredDigest -Right $actualDigest)) {
                    throw 'The audit artifact footer totals do not match its contents.'
                }
                return [pscustomobject]@{ ChunkCount = $chunkCount; EventCount = $eventCount; PlaintextBytes = $plaintextTotal }
            }
            if ([Text.Encoding]::ASCII.GetString($marker) -cne 'CHN2') { throw 'Invalid chunk marker.' }
            $metadata = Read-HHAuditArtifactV2Exact -Stream $Stream -Length 16
            $sequence = ConvertFrom-HHAuditArtifactV2UInt64 -Bytes $metadata -Offset 0
            $plainLength = ConvertFrom-HHAuditArtifactV2UInt32 -Bytes $metadata -Offset 8
            $envelopeLength = ConvertFrom-HHAuditArtifactV2UInt32 -Bytes $metadata -Offset 12
            if ($sequence -ne $chunkCount -or $plainLength -gt $chunkSize -or
                $envelopeLength -lt 32 -or $envelopeLength -gt ($chunkSize + 65536)) { throw 'Invalid chunk metadata.' }
            $envelope = Read-HHAuditArtifactV2Exact -Stream $Stream -Length ([int]$envelopeLength)
            $sequenceBytes = ConvertTo-HHAuditArtifactV2UInt64 -Value $sequence
            $plainLengthBytes = ConvertTo-HHAuditArtifactV2UInt32 -Value $plainLength
            $compressedLength = $envelope.Length - 32
            $compressedLengthBytes = ConvertTo-HHAuditArtifactV2UInt32 -Value $compressedLength
            $aad = Join-HHAuditArtifactV2Buffer -Part @(
                [Text.Encoding]::ASCII.GetBytes('HostHunterNextGeneration/hhout/chunk/v2'),
                $headerHash, $sequenceBytes, $previousTag, $plainLengthBytes, $compressedLengthBytes
            )
            $compressed = Unprotect-HHPersistenceValue -Envelope $envelope -MasterKey $MasterKey -AssociatedData $aad
            $plaintext = Expand-HHAuditArtifactV2Chunk -Bytes $compressed -ExpectedLength ([int]$plainLength)
            $digest.AppendData($plaintext)
            foreach ($value in $plaintext) {
                if ($value -eq 10) {
                    $frameBytes = $line.ToArray()
                    ConvertFrom-HHAuditArtifactV2Frame -Bytes $frameBytes `
                        -ExpectedSequence $eventCount -Emit:$Emit
                    $eventCount++
                    $line.SetLength(0)
                }
                else { $line.WriteByte($value) }
            }
            [Array]::Copy($envelope, 16, $previousTag, 0, 16)
            $chunkCount++
            $plaintextTotal += $plainLength
            $ciphertextTotal += $envelopeLength
            if ($plaintextTotal -gt $script:HHAuditArtifactV2MaximumPlaintextBytes) { throw 'Plaintext limit exceeded.' }
        }
    }
    catch [Management.Automation.ActionPreferenceStopException] { throw }
    catch {
        Stop-HHAuditArtifactV2Operation -ErrorId AuditIntegrityFailed `
            -Message 'The audit artifact failed complete verification.' -Category SecurityError `
            -TargetObject $null -InnerException $_.Exception
    }
    finally {
        $line.Dispose()
        $digest.Dispose()
    }
}

function Read-HHAuditArtifactV2 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$DataRoot,
        [Parameter(Mandatory)][byte[]]$DatabaseId,
        [Parameter(Mandatory)][byte[]]$LedgerId,
        [Parameter(Mandatory)][byte[]]$InvocationId,
        [Parameter(Mandatory)][byte[]]$ArtifactId,
        [Parameter(Mandatory)][byte[]]$MasterKey,
        [ValidateRange(4096, 4194304)][int]$ChunkSize = $script:HHAuditArtifactV2DefaultChunkBytes,
        [AllowNull()][byte[]]$ExpectedCiphertextSha256,
        [ValidateRange(0, [long]::MaxValue)][long]$ExpectedLength = 0
    )

    Assert-HHAuditMasterKey -MasterKey $MasterKey
    if (-not [IO.File]::Exists($Path)) {
        Stop-HHAuditArtifactV2Operation -ErrorId AuditOutputUnavailable `
            -Message 'The requested audit output artifact is unavailable.' `
            -Category ObjectNotFound -TargetObject $Path
    }
    $fullPath = [IO.Path]::GetFullPath($Path)
    if (-not [string]::IsNullOrWhiteSpace($DataRoot)) {
        $fullRoot = [IO.Path]::GetFullPath($DataRoot)
        $relative = [IO.Path]::GetRelativePath($fullRoot, $fullPath)
        if ($relative -eq '..' -or $relative.StartsWith("..$([IO.Path]::DirectorySeparatorChar)") -or
            [IO.Path]::IsPathRooted($relative)) {
            Stop-HHAuditArtifactV2Operation -ErrorId PersistencePathUnsafe `
                -Message 'The audit artifact path must remain inside the data root.' `
                -Category SecurityError -TargetObject $fullPath
        }
    }
    $fileInfo = [IO.FileInfo]::new($fullPath)
    if (($fileInfo.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $null -ne $fileInfo.LinkTarget) {
        Stop-HHAuditArtifactV2Operation -ErrorId PersistencePathUnsafe `
            -Message 'The audit artifact cannot be a link or reparse point.' `
            -Category SecurityError -TargetObject $fullPath
    }
    $expectedHeader = Get-HHAuditArtifactV2Header -DatabaseId $DatabaseId -LedgerId $LedgerId `
        -InvocationId $InvocationId -ArtifactId $ArtifactId -ChunkSize $ChunkSize
    $stream = [IO.FileStream]::new($fullPath, [IO.FileMode]::Open,
        [IO.FileAccess]::Read, [IO.FileShare]::Read, 65536, [IO.FileOptions]::SequentialScan)
    try {
        if ($ExpectedLength -gt 0 -and $stream.Length -ne $ExpectedLength) {
            Stop-HHAuditArtifactV2Operation -ErrorId AuditIntegrityFailed `
                -Message 'The audit artifact length does not match database metadata.' `
                -Category SecurityError -TargetObject $Path
        }
        if ($null -ne $ExpectedCiphertextSha256) {
            if ($ExpectedCiphertextSha256.Length -ne 32) { throw [ArgumentException]::new('ExpectedCiphertextSha256 must contain 32 bytes.') }
            $actualHash = [Security.Cryptography.SHA256]::HashData($stream)
            if (-not (Test-HHPersistenceBytesEqual -Left $actualHash -Right $ExpectedCiphertextSha256)) {
                Stop-HHAuditArtifactV2Operation -ErrorId AuditIntegrityFailed `
                    -Message 'The audit artifact hash does not match database metadata.' `
                    -Category SecurityError -TargetObject $Path
            }
        }
        Read-HHAuditArtifactV2Pass -Stream $stream -MasterKey $MasterKey `
            -ExpectedHeader $expectedHeader | Out-Null
        Read-HHAuditArtifactV2Pass -Stream $stream -MasterKey $MasterKey `
            -ExpectedHeader $expectedHeader -Emit | Where-Object {
                $_.PSObject.TypeNames -contains 'HostHunter.AuditStreamEvent'
            }
    }
    finally { $stream.Dispose() }
}

function Test-HHAuditArtifactV2 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$DataRoot,
        [Parameter(Mandatory)][byte[]]$DatabaseId,
        [Parameter(Mandatory)][byte[]]$LedgerId,
        [Parameter(Mandatory)][byte[]]$InvocationId,
        [Parameter(Mandatory)][byte[]]$ArtifactId,
        [Parameter(Mandatory)][byte[]]$MasterKey,
        [ValidateRange(4096, 4194304)][int]$ChunkSize = $script:HHAuditArtifactV2DefaultChunkBytes
    )

    Assert-HHAuditMasterKey -MasterKey $MasterKey
    $fullPath = [IO.Path]::GetFullPath($Path)
    if (-not [IO.File]::Exists($fullPath)) { return $false }
    if (-not [string]::IsNullOrWhiteSpace($DataRoot)) {
        $fullRoot = [IO.Path]::GetFullPath($DataRoot)
        $relative = [IO.Path]::GetRelativePath($fullRoot, $fullPath)
        if ($relative -eq '..' -or
            $relative.StartsWith("..$([IO.Path]::DirectorySeparatorChar)") -or
            [IO.Path]::IsPathRooted($relative)) { return $false }
    }
    $fileInfo = [IO.FileInfo]::new($fullPath)
    if (($fileInfo.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $null -ne $fileInfo.LinkTarget) { return $false }
    $expectedHeader = Get-HHAuditArtifactV2Header -DatabaseId $DatabaseId `
        -LedgerId $LedgerId -InvocationId $InvocationId -ArtifactId $ArtifactId `
        -ChunkSize $ChunkSize
    $stream = [IO.FileStream]::new($fullPath, [IO.FileMode]::Open,
        [IO.FileAccess]::Read, [IO.FileShare]::Read, 65536, [IO.FileOptions]::SequentialScan)
    try {
        Read-HHAuditArtifactV2Pass -Stream $stream -MasterKey $MasterKey `
            -ExpectedHeader $expectedHeader | Out-Null
        return $true
    }
    catch { return $false }
    finally { $stream.Dispose() }
}
