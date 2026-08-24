Set-StrictMode -Version Latest

$script:HHPersistenceArtifactReservationBytes = 128L * 1024L * 1024L
$script:HHPersistenceRecoveryMarginBytes = 64L * 1024L * 1024L

function New-HHPersistenceCapacityReservation {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Private pre-dispatch safety primitive called after the public authorization boundary.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$PersistenceContext,
        [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{32}$')][string]$BatchId,
        [Parameter(Mandatory)][ValidateRange(1, 8)][int]$InvocationCount,
        [ValidateRange(4096, [long]::MaxValue)]
        [long]$ArtifactBytes = $script:HHPersistenceArtifactReservationBytes,
        [ValidateRange(4096, [long]::MaxValue)]
        [long]$RecoveryMarginBytes = $script:HHPersistenceRecoveryMarginBytes,
        [ValidateRange(4096, 4194304)][int]$BlockBytes = 1048576,
        [scriptblock]$BlockWriter
    )

    [decimal]$requiredDecimal = ([decimal]$ArtifactBytes * $InvocationCount) + $RecoveryMarginBytes
    if ($requiredDecimal -gt [long]::MaxValue) {
        throw [ArgumentOutOfRangeException]::new('InvocationCount', 'Capacity reservation is too large.')
    }
    [long]$requiredBytes = $requiredDecimal
    [IO.Directory]::CreateDirectory($PersistenceContext.RecoveryRoot) | Out-Null
    $path = Join-Path $PersistenceContext.RecoveryRoot ".$BatchId.capacity.reserve"
    $stream = $null
    $created = $false
    $buffer = [byte[]]::new([Math]::Min([long]$BlockBytes, $requiredBytes))
    try {
        [Security.Cryptography.RandomNumberGenerator]::Fill($buffer)
        $stream = [IO.FileStream]::new(
            $path,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None,
            65536,
            [IO.FileOptions]::WriteThrough
        )
        $created = $true
        if (-not $IsWindows) {
            [IO.File]::SetUnixFileMode(
                $path,
                [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite
            )
        }
        [long]$remaining = $requiredBytes
        while ($remaining -gt 0) {
            $length = [int][Math]::Min([long]$buffer.Length, $remaining)
            if ($null -eq $BlockWriter) {
                $stream.Write($buffer, 0, $length)
            }
            else {
                & $BlockWriter $stream $buffer $length
            }
            $remaining -= $length
        }
        $stream.Flush($true)
        $stream.Dispose()
        $stream = $null
        $actualLength = [IO.FileInfo]::new($path).Length
        if ($actualLength -ne $requiredBytes) {
            throw "Capacity reservation length mismatch ($actualLength of $requiredBytes bytes)."
        }
        $receipt = [pscustomobject][ordered]@{
            Path = $path
            BatchId = $BatchId
            InvocationCount = $InvocationCount
            ReservedBytes = $requiredBytes
            Released = $false
        }
        $receipt.PSObject.TypeNames.Insert(0, 'HostHunter.PersistenceCapacityReservation')
        return $receipt
    }
    catch {
        if ($null -ne $stream) { $stream.Dispose() }
        if ($created -and [IO.File]::Exists($path)) { [IO.File]::Delete($path) }
        Stop-HHPersistenceOperation -ErrorId PersistenceCapacityInsufficient `
            -Message 'HostHunter could not reserve durable output and recovery capacity before dispatch.' `
            -Category ResourceUnavailable -TargetObject $path -InnerException $_.Exception
    }
    finally {
        [Array]::Clear($buffer, 0, $buffer.Length)
    }
}

function Remove-HHPersistenceCapacityReservation {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Private finalization primitive for an owned reservation file.'
    )]
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Reservation)

    if ($Reservation.Released) { return }
    if ([IO.File]::Exists([string]$Reservation.Path)) {
        [IO.File]::Delete([string]$Reservation.Path)
    }
    $Reservation.Released = $true
}
