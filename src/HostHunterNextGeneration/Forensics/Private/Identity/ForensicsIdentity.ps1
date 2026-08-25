Set-StrictMode -Version Latest

function ConvertTo-HHForensicsCanonicalString {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return ''
    }
    if ($Value -is [DateTime]) {
        return $Value.ToUniversalTime().ToString('o', [Globalization.CultureInfo]::InvariantCulture)
    }
    if ($Value -is [DateTimeOffset]) {
        return $Value.ToUniversalTime().ToString('o', [Globalization.CultureInfo]::InvariantCulture)
    }
    if ($Value -is [IFormattable]) {
        return $Value.ToString($null, [Globalization.CultureInfo]::InvariantCulture)
    }
    return [string]$Value
}

function Get-HHForensicsLengthFramedSha256 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [AllowNull()]
        [object[]]$Value
    )

    $stream = [IO.MemoryStream]::new()
    try {
        foreach ($item in $Value) {
            $bytes = [Text.Encoding]::UTF8.GetBytes(
                (ConvertTo-HHForensicsCanonicalString -Value $item)
            )
            if ($bytes.LongLength -gt [uint32]::MaxValue) {
                throw [ArgumentOutOfRangeException]::new(
                    'Value',
                    'A deterministic identity field exceeds the four-byte frame limit.'
                )
            }
            $length = [uint32]$bytes.Length
            $prefix = [byte[]]@(
                [byte](($length -shr 24) -band 0xff),
                [byte](($length -shr 16) -band 0xff),
                [byte](($length -shr 8) -band 0xff),
                [byte]($length -band 0xff)
            )
            $stream.Write($prefix, 0, $prefix.Length)
            $stream.Write($bytes, 0, $bytes.Length)
        }

        $hasher = [Security.Cryptography.SHA256]::Create()
        try {
            $hash = $hasher.ComputeHash($stream.ToArray())
        }
        finally {
            $hasher.Dispose()
        }
        return ([BitConverter]::ToString($hash)).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $stream.Dispose()
    }
}

function Get-HHForensicsEventId {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$HostId,
        [Parameter(Mandatory)][string]$Provider,
        [Parameter(Mandatory)][string]$Channel,
        [Parameter(Mandatory)][string]$EventCode,
        [Parameter(Mandatory)][string]$EventRecordId,
        [Parameter(Mandatory)][string]$Timestamp,
        [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$SourceIdentity,
        [Parameter(Mandatory)][ValidateRange(1, [long]::MaxValue)][long]$SourceOrdinal
    )

    return Get-HHForensicsLengthFramedSha256 -Value @(
        'hosthunter.event.v1',
        $HostId,
        $Provider,
        $Channel,
        $EventCode,
        $EventRecordId,
        $Timestamp,
        $SourceIdentity,
        $SourceOrdinal
    )
}

function Get-HHForensicsSecurityProcessEntityId {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$HostId,
        [Parameter(Mandatory)][uint64]$ProcessId,
        [Parameter(Mandatory)][string]$Timestamp,
        [Parameter(Mandatory)][string]$EventRecordId
    )

    return Get-HHForensicsLengthFramedSha256 -Value @(
        'hosthunter.security-4688.process.v1',
        $HostId,
        $ProcessId,
        $Timestamp,
        $EventRecordId
    )
}
