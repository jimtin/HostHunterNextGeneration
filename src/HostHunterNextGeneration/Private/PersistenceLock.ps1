Set-StrictMode -Version Latest

function Enter-HHPersistenceFileLock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [ValidateRange(1, 60000)][int]$TimeoutMilliseconds = 5000,
        [Parameter(Mandatory)][ValidateSet('PersistenceBusy', 'OperationBusy')][string]$FailureId,
        [scriptblock]$Clock,
        [scriptblock]$Delay
    )

    $clockProvider = if ($null -eq $Clock) {
        { [DateTimeOffset]::UtcNow }
    }
    else { $Clock }
    $delayProvider = if ($null -eq $Delay) {
        { param($Milliseconds) Start-Sleep -Milliseconds $Milliseconds }
    }
    else { $Delay }
    $started = & $clockProvider
    $options = [System.IO.FileStreamOptions]::new()
    $options.Mode = [System.IO.FileMode]::OpenOrCreate
    $options.Access = [System.IO.FileAccess]::ReadWrite
    $options.Share = [System.IO.FileShare]::None
    $options.Options = [System.IO.FileOptions]::WriteThrough
    if (-not $IsWindows) {
        $options.UnixCreateMode = [System.IO.UnixFileMode]::UserRead -bor
            [System.IO.UnixFileMode]::UserWrite
    }

    while ($true) {
        try {
            if (Test-Path -LiteralPath $Path) {
                $attributes = [System.IO.File]::GetAttributes($Path)
                if (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                    Stop-HHPersistenceOperation `
                        -ErrorId 'PersistencePathUnsafe' `
                        -Message 'A persistence lock path cannot be a reparse point.' `
                        -Category ([System.Management.Automation.ErrorCategory]::SecurityError) `
                        -TargetObject $Path
                }
            }
            $stream = [System.IO.File]::Open($Path, $options)
            $attributes = [System.IO.File]::GetAttributes($Path)
            if (($attributes -band [System.IO.FileAttributes]::Directory) -ne 0 -or
                ($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                $stream.Dispose()
                Stop-HHPersistenceOperation `
                    -ErrorId 'PersistencePathUnsafe' `
                    -Message 'A persistence lock must be an owner-private regular file.' `
                    -Category ([System.Management.Automation.ErrorCategory]::SecurityError) `
                    -TargetObject $Path
            }
            if (-not $IsWindows) {
                [System.IO.File]::SetUnixFileMode(
                    $Path,
                    [System.IO.UnixFileMode]::UserRead -bor [System.IO.UnixFileMode]::UserWrite
                )
            }
            return [pscustomobject]@{ Path = $Path; Stream = $stream; AcquiredAtUtc = & $clockProvider }
        }
        catch [System.IO.IOException] {
            $elapsed = (& $clockProvider) - $started
            if ($elapsed.TotalMilliseconds -ge $TimeoutMilliseconds) {
                Stop-HHPersistenceOperation `
                    -ErrorId $FailureId `
                    -Message 'HostHunter persistence is busy in another process.' `
                    -Category ([System.Management.Automation.ErrorCategory]::ResourceBusy) `
                    -TargetObject $Path `
                    -InnerException $_.Exception
            }
            & $delayProvider 25
        }
    }
}

function Exit-HHPersistenceFileLock {
    [CmdletBinding()]
    param([AllowNull()][object]$LockContext)

    if ($null -ne $LockContext -and $null -ne $LockContext.Stream) {
        $LockContext.Stream.Dispose()
    }
}
