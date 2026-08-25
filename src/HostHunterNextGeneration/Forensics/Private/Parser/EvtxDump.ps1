Set-StrictMode -Version Latest

$script:HHEvtxDumpVersion = '0.12.2'
$script:HHEvtxDumpPins = @{
    'linux-arm64' = '50fcb8d316351c7a2c9f6d610ae3f9932b8f6c0ecf87f1e3756630963e263a96'
    'linux-x64' = 'c33c111c9832cff5b91dfca6fece51d603181a42dfb56f0ed0a25669f2600df9'
    'osx-arm64' = '6dd3a5b09ed73d55a3ad76548e99be587ea4258ee89424c8bfcacc18bc8c7e5b'
    'osx-x64' = '60f2a775832fa2433f981ffae83a053420b523641eba1af804d2601e5866f208'
}

function Get-HHForensicsRuntimeIdentifier {
    [CmdletBinding()]
    param()

    $architecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    $suffix = switch ($architecture) {
        'Arm64' { 'arm64' }
        'X64' { 'x64' }
        default {
            throw [PlatformNotSupportedException]::new(
                "evtx_dump is not packaged for architecture '$architecture'."
            )
        }
    }
    if ([Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
            [Runtime.InteropServices.OSPlatform]::OSX
        )) { return "osx-$suffix" }
    if ([Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
            [Runtime.InteropServices.OSPlatform]::Linux
        )) { return "linux-$suffix" }
    throw [PlatformNotSupportedException]::new(
        'The packaged evtx_dump runner supports macOS and Linux only.'
    )
}

function Get-HHForensicsEvtxDumpPin {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('linux-arm64', 'linux-x64', 'osx-arm64', 'osx-x64')]
        [string]$RuntimeIdentifier
    )

    return [pscustomobject]@{
        Name = 'evtx_dump'
        Version = $script:HHEvtxDumpVersion
        RuntimeIdentifier = $RuntimeIdentifier
        RelativePath = "tools/evtx_dump/$RuntimeIdentifier/evtx_dump"
        Sha256 = $script:HHEvtxDumpPins[$RuntimeIdentifier]
    }
}

function Get-HHForensicsParserIsolationProfile {
    [CmdletBinding()]
    param([switch]$MacOSSandbox)

    if ($MacOSSandbox) {
        return [pscustomobject]@{
            Marker = 'HostHunter.Forensics.ParserIsolation.v1'
            Name = 'MacOSSandboxExec'
            ProcessTreeTermination = $true
            CpuLimit = $true
            MemoryLimit = $true
            NetworkIsolation = $true
            FileSystemIsolation = $true
            ProcessForkDenied = $true
            ReleaseQualified = $true
            QualificationRequirement = $null
        }
    }

    return [pscustomobject]@{
        Marker = 'HostHunter.Forensics.ParserIsolation.v1'
        Name = 'PowerShellProcessTree'
        ProcessTreeTermination = $true
        CpuLimit = $false
        MemoryLimit = $false
        NetworkIsolation = $false
        FileSystemIsolation = $false
        ProcessForkDenied = $false
        ReleaseQualified = $false
        QualificationRequirement = 'Use a separately qualified OS sandbox launcher for CPU, memory, and network isolation.'
    }
}

function Get-HHForensicsMacOSSandboxProfile {
    [CmdletBinding()]
    param()

    return @'
(version 1)
(allow default)
(deny network*)
(deny file-write*)
(deny process-fork)
(deny mach-lookup)
(deny file-read*
    (subpath "/Users")
    (subpath "/Volumes")
    (subpath "/Applications")
    (subpath "/Library")
    (subpath "/opt")
    (subpath "/usr/local")
    (subpath "/private/etc")
    (subpath "/private/var")
    (subpath "/usr/bin")
    (subpath "/bin")
    (subpath "/sbin")
    (subpath "/usr/sbin"))
'@
}

function Get-HHForensicsParserLaunchPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Executable,
        [Parameter(Mandatory)][string[]]$ArgumentList,
        [Nullable[bool]]$MacOSPlatformOverride,
        [string]$SandboxExecutable = '/usr/bin/sandbox-exec'
    )

    $useMacOSSandbox = if ($null -ne $MacOSPlatformOverride) {
        [bool]$MacOSPlatformOverride
    }
    else {
        [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
            [Runtime.InteropServices.OSPlatform]::OSX
        )
    }
    if (-not $useMacOSSandbox) {
        return [pscustomobject]@{
            Executable = $Executable
            ArgumentList = [string[]]$ArgumentList
            IsolationProfile = Get-HHForensicsParserIsolationProfile
        }
    }

    $sandboxPath = Assert-HHForensicsNoFollowPath -Path $SandboxExecutable
    $sandboxItem = Get-Item -LiteralPath $sandboxPath -Force
    if ($sandboxItem.PSIsContainer) {
        throw [IO.InvalidDataException]::new(
            'The macOS parser sandbox executable is not a regular file.'
        )
    }
    $arguments = [Collections.Generic.List[string]]::new()
    $arguments.Add('-p')
    $arguments.Add((Get-HHForensicsMacOSSandboxProfile))
    $arguments.Add($Executable)
    foreach ($argument in $ArgumentList) { $arguments.Add($argument) }
    return [pscustomobject]@{
        Executable = $sandboxPath
        ArgumentList = [string[]]$arguments.ToArray()
        IsolationProfile = Get-HHForensicsParserIsolationProfile -MacOSSandbox
    }
}

function Assert-HHForensicsNoFollowPath {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $fullPath = [IO.Path]::GetFullPath($Path)
    $root = [IO.Path]::GetPathRoot($fullPath)
    $relative = $fullPath.Substring($root.Length)
    $current = $root
    foreach ($part in $relative.Split(
            @([IO.Path]::DirectorySeparatorChar),
            [StringSplitOptions]::RemoveEmptyEntries
        )) {
        $current = Join-Path $current $part
        if (-not (Test-Path -LiteralPath $current)) {
            throw [IO.FileNotFoundException]::new('A protected path component does not exist.', $current)
        }
        $attributes = [IO.File]::GetAttributes($current)
        if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw [Security.SecurityException]::new(
                "Symbolic links and reparse points are forbidden: $current"
            )
        }
    }
    return $fullPath
}

function Get-HHForensicsFileIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$ExpectedSha256
    )

    $fullPath = Assert-HHForensicsNoFollowPath -Path $Path
    $item = Get-Item -LiteralPath $fullPath -Force
    if ($item.PSIsContainer) {
        throw [IO.InvalidDataException]::new('The protected path must be a regular file.')
    }
    $stream = [IO.FileStream]::new(
        $fullPath,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    try {
        $hasher = [Security.Cryptography.SHA256]::Create()
        try { $digest = $hasher.ComputeHash($stream) }
        finally { $hasher.Dispose() }
    }
    finally { $stream.Dispose() }
    $sha256 = ([BitConverter]::ToString($digest)).Replace('-', '').ToLowerInvariant()
    if (-not [string]::IsNullOrWhiteSpace($ExpectedSha256) -and
        $sha256 -cne $ExpectedSha256.ToLowerInvariant()) {
        throw [Security.SecurityException]::new(
            "The protected file SHA-256 digest does not match the approved identity. Expected $($ExpectedSha256.ToLowerInvariant()); got $sha256."
        )
    }
    $item = Get-Item -LiteralPath $fullPath -Force
    return [pscustomobject]@{
        Marker = 'HostHunter.Forensics.FileIdentity.v1'
        Path = $fullPath
        Length = [long]$item.Length
        CreationTimeUtcTicks = [long]$item.CreationTimeUtc.Ticks
        LastWriteTimeUtcTicks = [long]$item.LastWriteTimeUtc.Ticks
        Sha256 = $sha256
    }
}

function Assert-HHForensicsFileIdentity {
    [CmdletBinding()]
    param([Parameter(Mandatory)][psobject]$Identity)

    if ($Identity.Marker -cne 'HostHunter.Forensics.FileIdentity.v1') {
        throw [IO.InvalidDataException]::new('The protected file identity is malformed.')
    }
    $current = Get-HHForensicsFileIdentity -Path $Identity.Path -ExpectedSha256 $Identity.Sha256
    foreach ($field in @('Path', 'Length', 'CreationTimeUtcTicks', 'LastWriteTimeUtcTicks', 'Sha256')) {
        if ([string]$current.$field -cne [string]$Identity.$field) {
            throw [Security.SecurityException]::new(
                "The protected file identity changed: $($Identity.Path)"
            )
        }
    }
    return $current
}

function Resolve-HHForensicsEvtxParser {
    [CmdletBinding()]
    param(
        [string]$Path = $env:HH_EVTX_DUMP_PATH,
        [ValidateSet('linux-arm64', 'linux-x64', 'osx-arm64', 'osx-x64')]
        [string]$RuntimeIdentifier,
        [ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ExpectedSha256,
        [scriptblock]$VersionInvoker = {
            param($Executable)
            & $Executable '--version' 2>&1
            if ($LASTEXITCODE -ne 0) {
                throw "evtx_dump --version exited with code $LASTEXITCODE."
            }
        }
    )

    if ([string]::IsNullOrWhiteSpace($RuntimeIdentifier)) {
        $RuntimeIdentifier = Get-HHForensicsRuntimeIdentifier
    }
    $pin = Get-HHForensicsEvtxDumpPin -RuntimeIdentifier $RuntimeIdentifier
    if ([string]::IsNullOrWhiteSpace($Path)) {
        $moduleRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../..'))
        $Path = Join-Path $moduleRoot $pin.RelativePath
    }
    if ([string]::IsNullOrWhiteSpace($ExpectedSha256)) {
        $ExpectedSha256 = $pin.Sha256
    }
    $identity = Get-HHForensicsFileIdentity -Path $Path -ExpectedSha256 $ExpectedSha256
    $versionText = [string](& $VersionInvoker $identity.Path)
    [void](Assert-HHForensicsFileIdentity -Identity $identity)
    $escapedVersion = [regex]::Escape($script:HHEvtxDumpVersion)
    if ($versionText -notmatch "(?<![0-9.])$escapedVersion(?![0-9.])") {
        throw [IO.InvalidDataException]::new(
            "The evtx_dump executable did not report required version $($script:HHEvtxDumpVersion)."
        )
    }
    return [pscustomobject]@{
        Marker = 'HostHunter.Forensics.Parser.v2'
        Name = 'evtx_dump'
        Version = $script:HHEvtxDumpVersion
        Path = $identity.Path
        Sha256 = $identity.Sha256
        RuntimeIdentifier = $RuntimeIdentifier
        FileIdentity = $identity
    }
}

function Protect-HHForensicsOwnerOnlyUnixMode {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Mode
    )

    if ([Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
            [Runtime.InteropServices.OSPlatform]::Windows
        )) { return }
    $modeType = [type]::GetType('System.IO.UnixFileMode, System.Private.CoreLib', $false)
    if ($null -eq $modeType) {
        throw [PlatformNotSupportedException]::new(
            'This runtime cannot enforce owner-only Unix staging permissions.'
        )
    }
    $method = [IO.File].GetMethod(
        'SetUnixFileMode',
        ([Reflection.BindingFlags]::Public -bor [Reflection.BindingFlags]::Static),
        $null,
        [type[]]@([string], $modeType),
        $null
    )
    if ($null -eq $method) {
        throw [PlatformNotSupportedException]::new(
            'This runtime cannot enforce owner-only Unix staging permissions.'
        )
    }
    $modeValue = [Enum]::Parse($modeType, $Mode)
    [void]$method.Invoke($null, @($Path, $modeValue))
}

function Initialize-HHForensicsPrivateStagingDirectory {
    [CmdletBinding()]
    param([string]$RootPath)

    $temporaryRoot = if (-not [string]::IsNullOrWhiteSpace($RootPath)) {
        Assert-HHForensicsNoFollowPath -Path $RootPath
    }
    elseif ([Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
            [Runtime.InteropServices.OSPlatform]::OSX
        )) {
        '/private/tmp'
    }
    else {
        [IO.Path]::GetTempPath()
    }
    $path = Join-Path $temporaryRoot (
        'hosthunter-forensics-' + [Guid]::NewGuid().ToString('N')
    )
    [IO.Directory]::CreateDirectory($path) | Out-Null
    Protect-HHForensicsOwnerOnlyUnixMode -Path $path -Mode 'UserRead, UserWrite, UserExecute'
    return $path
}

function Copy-HHForensicsFileToPrivateStage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][psobject]$SourceIdentity,
        [Parameter(Mandatory)][string]$DestinationPath,
        [switch]$Executable
    )

    $source = [IO.FileStream]::new(
        $SourceIdentity.Path,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    $destination = [IO.FileStream]::new(
        $DestinationPath,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None
    )
    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        $buffer = [byte[]]::new(81920)
        $length = 0L
        while (($read = $source.Read($buffer, 0, $buffer.Length)) -gt 0) {
            [void]$hasher.TransformBlock($buffer, 0, $read, $null, 0)
            $destination.Write($buffer, 0, $read)
            $length += $read
        }
        [void]$hasher.TransformFinalBlock([byte[]]@(), 0, 0)
        $hashBytes = [byte[]]$hasher.Hash.Clone()
        $destination.Flush($true)
    }
    finally {
        $hasher.Dispose()
        $destination.Dispose()
        $source.Dispose()
    }
    $digest = ([BitConverter]::ToString($hashBytes)).Replace('-', '').ToLowerInvariant()
    if ($digest -cne $SourceIdentity.Sha256 -or $length -ne $SourceIdentity.Length) {
        throw [Security.SecurityException]::new(
            'A protected source file changed while it was copied into private staging.'
        )
    }
    $mode = if ($Executable) { 'UserRead, UserWrite, UserExecute' } else { 'UserRead, UserWrite' }
    Protect-HHForensicsOwnerOnlyUnixMode -Path $DestinationPath -Mode $mode
    return Get-HHForensicsFileIdentity -Path $DestinationPath -ExpectedSha256 $digest
}

function ConvertFrom-HHForensicsJsonLine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][byte[]]$Bytes,
        [Parameter(Mandatory)][ValidateRange(1, [int]::MaxValue)][long]$SourceOrdinal,
        [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$SourceIdentity,
        [ValidateRange(1, 128)][int]$MaximumJsonDepth = 64,
        [ValidateRange(1, 16777216)][int]$MaximumStringBytes = 1048576
    )

    Initialize-HHForensicsStrictJsonValidator
    try {
        $original = [HostHunter.Forensics.StrictJsonValidator]::Validate(
            $Bytes,
            $MaximumJsonDepth,
            $MaximumStringBytes
        )
        $data = $original | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw [IO.InvalidDataException]::new(
            "Parser JSONL observation $SourceOrdinal is not strict JSON: $($_.Exception.Message)",
            $_.Exception
        )
    }
    $eventRoot = $data.PSObject.Properties['Event']
    if ($null -eq $eventRoot -or $null -eq $eventRoot.Value -or
        $eventRoot.Value -is [string] -or $eventRoot.Value -is [ValueType]) {
        throw [IO.InvalidDataException]::new(
            "Parser JSONL observation $SourceOrdinal does not contain an Event object."
        )
    }
    $hasher = [Security.Cryptography.SHA256]::Create()
    try { $hash = $hasher.ComputeHash($Bytes) }
    finally { $hasher.Dispose() }
    return [pscustomobject]@{
        Marker = 'HostHunter.Forensics.JsonlRecord.v2'
        SourceOrdinal = $SourceOrdinal
        SourceIdentity = $SourceIdentity
        Original = $original
        OriginalSha256 = ([BitConverter]::ToString($hash)).Replace('-', '').ToLowerInvariant()
        Data = $data
    }
}

function Read-HHForensicsJsonlRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][IO.Stream]$Stream,
        [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$SourceIdentity,
        [ValidateRange(1, 67108864)][int]$MaximumLineBytes = 4194304,
        [ValidateRange(1, 2147483647)][long]$MaximumTotalBytes = 536870912,
        [ValidateRange(1, 128)][int]$MaximumJsonDepth = 64,
        [ValidateRange(1, 16777216)][int]$MaximumStringBytes = 1048576
    )

    $line = [IO.MemoryStream]::new()
    $buffer = [byte[]]::new(8192)
    $total = 0L
    $ordinal = 0L
    try {
        while (($read = $Stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $total += $read
            if ($total -gt $MaximumTotalBytes) {
                throw [IO.InvalidDataException]::new('Parser JSONL exceeds the configured total byte limit.')
            }
            for ($index = 0; $index -lt $read; $index++) {
                $value = $buffer[$index]
                if ($value -eq 10) {
                    $ordinal++
                    $bytes = $line.ToArray()
                    $line.SetLength(0)
                    if ($bytes.Length -gt 0 -and $bytes[$bytes.Length - 1] -eq 13) {
                        if ($bytes.Length -eq 1) { $bytes = [byte[]]@() }
                        else { $bytes = $bytes[0..($bytes.Length - 2)] }
                    }
                    if ($bytes.Length -eq 0) { continue }
                    ConvertFrom-HHForensicsJsonLine -Bytes $bytes -SourceOrdinal $ordinal `
                        -SourceIdentity $SourceIdentity -MaximumJsonDepth $MaximumJsonDepth `
                        -MaximumStringBytes $MaximumStringBytes
                    continue
                }
                if ($line.Length -ge $MaximumLineBytes) {
                    throw [IO.InvalidDataException]::new(
                        'Parser JSONL line exceeds the configured byte limit.'
                    )
                }
                $line.WriteByte($value)
            }
        }
        if ($line.Length -gt 0) {
            $ordinal++
            ConvertFrom-HHForensicsJsonLine -Bytes $line.ToArray() `
                -SourceOrdinal $ordinal -SourceIdentity $SourceIdentity `
                -MaximumJsonDepth $MaximumJsonDepth -MaximumStringBytes $MaximumStringBytes
        }
    }
    finally { $line.Dispose() }
}

function Invoke-HHForensicsParserTreeTermination {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][Diagnostics.Process]$Process,
        [ValidateRange(1, 30)][int]$ReapTimeoutSeconds = 5
    )

    if ($Process.HasExited) { return }
    $treeKill = $Process.GetType().GetMethod('Kill', [type[]]@([bool]))
    if ($null -eq $treeKill) {
        throw [PlatformNotSupportedException]::new(
            'This runtime cannot terminate the complete parser process tree.'
        )
    }
    [void]$treeKill.Invoke($Process, @($true))
    if (-not $Process.WaitForExit($ReapTimeoutSeconds * 1000)) {
        throw [TimeoutException]::new(
            'The parser process tree could not be reaped within the bounded timeout.'
        )
    }
}

function Assert-HHForensicsParserResourceBound {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][Diagnostics.Process]$Process,
        [Parameter(Mandatory)][ValidateRange(1, 4294967296)][long]$MaximumWorkingSetBytes,
        [Parameter(Mandatory)][ValidateRange(1, 3600)][int]$MaximumCpuSeconds,
        [ValidateRange(1, 30)][int]$ReapTimeoutSeconds = 5
    )

    if ($Process.HasExited) { return }
    $Process.Refresh()
    $limitName = $null
    $cpuTime = $Process.TotalProcessorTime
    if ([long]$Process.WorkingSet64 -gt $MaximumWorkingSetBytes) {
        $limitName = 'working-set'
    }
    elseif ($null -ne $cpuTime -and
        ([TimeSpan]$cpuTime).TotalSeconds -gt $MaximumCpuSeconds) {
        $limitName = 'CPU-time'
    }
    if ($null -eq $limitName) { return }

    Invoke-HHForensicsParserTreeTermination -Process $Process `
        -ReapTimeoutSeconds $ReapTimeoutSeconds
    throw [IO.InvalidDataException]::new(
        "ForensicsParserResourceLimitExceeded: the parser exceeded its $limitName limit."
    )
}

function Invoke-HHForensicsBoundedRecordConsumer {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][scriptblock]$RecordConsumer,
        [Parameter(Mandatory)][object]$Record,
        [Parameter(Mandatory)][Diagnostics.Process]$Process,
        [Parameter(Mandatory)][Diagnostics.Stopwatch]$Stopwatch,
        [Parameter(Mandatory)][ValidateRange(1, 3600)][int]$TimeoutSeconds,
        [Parameter(Mandatory)][ValidateRange(1, 4294967296)]
        [long]$MaximumWorkingSetBytes,
        [Parameter(Mandatory)][ValidateRange(1, 3600)][int]$MaximumCpuSeconds,
        [ValidateRange(1, 30)][int]$ReapTimeoutSeconds = 5
    )

    $consumerPowerShell = [PowerShell]::Create()
    $consumerAsync = $null
    $consumerCompleted = $false
    try {
        [void]$consumerPowerShell.AddScript(
            'param($Consumer,$Record) & $Consumer $Record'
        ).AddArgument($RecordConsumer).AddArgument($Record)
        $consumerAsync = $consumerPowerShell.BeginInvoke()
        while (-not $consumerAsync.IsCompleted) {
            Assert-HHForensicsParserResourceBound -Process $Process `
                -MaximumWorkingSetBytes $MaximumWorkingSetBytes `
                -MaximumCpuSeconds $MaximumCpuSeconds `
                -ReapTimeoutSeconds $ReapTimeoutSeconds
            if ($Stopwatch.Elapsed.TotalSeconds -ge $TimeoutSeconds) {
                Invoke-HHForensicsParserTreeTermination -Process $Process `
                    -ReapTimeoutSeconds $ReapTimeoutSeconds
                try {
                    $stopAsync = $consumerPowerShell.BeginStop($null, $null)
                    if ($stopAsync.AsyncWaitHandle.WaitOne($ReapTimeoutSeconds * 1000)) {
                        try { $consumerPowerShell.EndStop($stopAsync) }
                        catch [System.Management.Automation.PipelineStoppedException] {
                            Write-Debug 'The timed-out record consumer stopped as requested.'
                        }
                        $consumerCompleted = $true
                    }
                }
                catch { Write-Debug 'The timed-out record consumer could not be stopped.' }
                return $false
            }
            Start-Sleep -Milliseconds 10
        }
        $consumerOutput = $consumerPowerShell.EndInvoke($consumerAsync)
        $consumerCompleted = $true
        if ($consumerPowerShell.HadErrors) {
            throw $consumerPowerShell.Streams.Error[0]
        }
        if ($consumerOutput.Count -gt 0) {
            Write-Debug 'The bounded parser record consumer emitted ignored output.'
        }
        return $true
    }
    finally {
        if ($consumerCompleted -or $null -eq $consumerAsync) {
            $consumerPowerShell.Dispose()
        }
    }
}

function Invoke-HHForensicsNativeParserProcess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Executable,
        [Parameter(Mandatory)][string[]]$ArgumentList,
        [Parameter(Mandatory)][psobject]$ParserIdentity,
        [Parameter(Mandatory)][psobject]$EvidenceIdentity,
        [Parameter(Mandatory)][scriptblock]$RecordConsumer,
        [Parameter(Mandatory)][ValidateRange(1, 3600)][int]$TimeoutSeconds,
        [ValidateRange(1, 30)][int]$ReapTimeoutSeconds = 5,
        [ValidateRange(1, 67108864)][int]$MaximumLineBytes = 4194304,
        [ValidateRange(1, 2147483647)][long]$MaximumOutputBytes = 536870912,
        [ValidateRange(1, 1048576)][int]$MaximumStderrBytes = 16384,
        [ValidateRange(1, 128)][int]$MaximumJsonDepth = 64,
        [ValidateRange(1, 16777216)][int]$MaximumStringBytes = 1048576,
        [ValidateRange(1, 4294967296)][long]$MaximumWorkingSetBytes = 536870912,
        [ValidateRange(1, 3600)][int]$MaximumCpuSeconds = 120,
        [scriptblock]$LaunchPlanner = ${function:Get-HHForensicsParserLaunchPlan}
    )

    [void](Assert-HHForensicsFileIdentity -Identity $ParserIdentity)
    [void](Assert-HHForensicsFileIdentity -Identity $EvidenceIdentity)
    $launchPlan = & $LaunchPlanner -Executable $Executable -ArgumentList $ArgumentList
    $launchProperties = if ($null -eq $launchPlan) { @() } else {
        @($launchPlan.PSObject.Properties | ForEach-Object Name)
    }
    if ($null -eq $launchPlan -or
        'Executable' -notin $launchProperties -or
        'ArgumentList' -notin $launchProperties -or
        'IsolationProfile' -notin $launchProperties -or
        [string]::IsNullOrWhiteSpace([string]$launchPlan.Executable) -or
        $null -eq $launchPlan.ArgumentList -or $null -eq $launchPlan.IsolationProfile) {
        throw [IO.InvalidDataException]::new(
            'The parser isolation launcher returned an invalid launch plan.'
        )
    }
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = [string]$launchPlan.Executable
    if ($null -eq $startInfo.PSObject.Properties['ArgumentList']) {
        throw [PlatformNotSupportedException]::new(
            'The controller runtime does not support discrete native ArgumentList entries.'
        )
    }
    foreach ($argument in $launchPlan.ArgumentList) {
        [void]$startInfo.ArgumentList.Add([string]$argument)
    }
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true

    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $stderr = [IO.MemoryStream]::new()
    $line = [IO.MemoryStream]::new()
    $stopwatch = [Diagnostics.Stopwatch]::StartNew()
    $records = 0L
    $outputBytes = 0L
    $stderrTruncated = $false
    $processStarted = $false
    try {
        if (-not $process.Start()) {
            throw [InvalidOperationException]::new('The evtx_dump process did not start.')
        }
        $processStarted = $true
        $stdoutBuffer = [byte[]]::new(8192)
        $stderrBuffer = [byte[]]::new(4096)
        $stdoutTask = $process.StandardOutput.BaseStream.ReadAsync(
            $stdoutBuffer, 0, $stdoutBuffer.Length
        )
        $stderrTask = $process.StandardError.BaseStream.ReadAsync(
            $stderrBuffer, 0, $stderrBuffer.Length
        )
        $stdoutEnded = $false
        $stderrEnded = $false

        while (-not $stdoutEnded -or -not $stderrEnded) {
            Assert-HHForensicsParserResourceBound -Process $process `
                -MaximumWorkingSetBytes $MaximumWorkingSetBytes `
                -MaximumCpuSeconds $MaximumCpuSeconds `
                -ReapTimeoutSeconds $ReapTimeoutSeconds
            if ($stopwatch.Elapsed.TotalSeconds -ge $TimeoutSeconds) {
                Invoke-HHForensicsParserTreeTermination -Process $process `
                    -ReapTimeoutSeconds $ReapTimeoutSeconds
                return [pscustomobject]@{
                    ExitCode = $null
                    TimedOut = $true
                    Records = $records
                    OutputBytes = $outputBytes
                    Stderr = ''
                    StderrTruncated = $stderrTruncated
                    IsolationProfile = $launchPlan.IsolationProfile
                }
            }
            $progress = $false
            if (-not $stdoutEnded -and $stdoutTask.IsCompleted) {
                $read = $stdoutTask.GetAwaiter().GetResult()
                if ($read -eq 0) { $stdoutEnded = $true }
                else {
                    $outputBytes += $read
                    if ($outputBytes -gt $MaximumOutputBytes) {
                        throw [IO.InvalidDataException]::new(
                            'Parser JSONL exceeds the configured total byte limit.'
                        )
                    }
                    for ($index = 0; $index -lt $read; $index++) {
                        $value = $stdoutBuffer[$index]
                        if ($value -eq 10) {
                            $records++
                            $bytes = $line.ToArray()
                            $line.SetLength(0)
                            if ($bytes.Length -gt 0 -and $bytes[$bytes.Length - 1] -eq 13) {
                                if ($bytes.Length -eq 1) { $bytes = [byte[]]@() }
                                else { $bytes = $bytes[0..($bytes.Length - 2)] }
                            }
                            if ($bytes.Length -gt 0) {
                                $record = ConvertFrom-HHForensicsJsonLine -Bytes $bytes `
                                    -SourceOrdinal $records -SourceIdentity $EvidenceIdentity.Sha256 `
                                    -MaximumJsonDepth $MaximumJsonDepth `
                                    -MaximumStringBytes $MaximumStringBytes
                                if (-not (Invoke-HHForensicsBoundedRecordConsumer `
                                        -RecordConsumer $RecordConsumer -Record $record `
                                        -Process $process -Stopwatch $stopwatch `
                                        -TimeoutSeconds $TimeoutSeconds `
                                        -MaximumWorkingSetBytes $MaximumWorkingSetBytes `
                                        -MaximumCpuSeconds $MaximumCpuSeconds `
                                        -ReapTimeoutSeconds $ReapTimeoutSeconds)) {
                                    return [pscustomobject]@{
                                        ExitCode = $null; TimedOut = $true
                                        Records = $records; OutputBytes = $outputBytes
                                        Stderr = ''; StderrTruncated = $stderrTruncated
                                        IsolationProfile = $launchPlan.IsolationProfile
                                    }
                                }
                            }
                            continue
                        }
                        if ($line.Length -ge $MaximumLineBytes) {
                            throw [IO.InvalidDataException]::new(
                                'Parser JSONL line exceeds the configured byte limit.'
                            )
                        }
                        $line.WriteByte($value)
                    }
                    $stdoutTask = $process.StandardOutput.BaseStream.ReadAsync(
                        $stdoutBuffer, 0, $stdoutBuffer.Length
                    )
                }
                $progress = $true
            }
            if (-not $stderrEnded -and $stderrTask.IsCompleted) {
                $read = $stderrTask.GetAwaiter().GetResult()
                if ($read -eq 0) { $stderrEnded = $true }
                else {
                    $remaining = [Math]::Max(0, $MaximumStderrBytes - $stderr.Length)
                    $accepted = [Math]::Min($remaining, $read)
                    if ($accepted -gt 0) { $stderr.Write($stderrBuffer, 0, $accepted) }
                    if ($accepted -lt $read) { $stderrTruncated = $true }
                    $stderrTask = $process.StandardError.BaseStream.ReadAsync(
                        $stderrBuffer, 0, $stderrBuffer.Length
                    )
                }
                $progress = $true
            }
            if (-not $progress) { Start-Sleep -Milliseconds 10 }
        }

        if ($line.Length -gt 0) {
            $records++
            $record = ConvertFrom-HHForensicsJsonLine -Bytes $line.ToArray() `
                -SourceOrdinal $records -SourceIdentity $EvidenceIdentity.Sha256 `
                -MaximumJsonDepth $MaximumJsonDepth -MaximumStringBytes $MaximumStringBytes
            if (-not (Invoke-HHForensicsBoundedRecordConsumer `
                    -RecordConsumer $RecordConsumer -Record $record `
                    -Process $process -Stopwatch $stopwatch `
                    -TimeoutSeconds $TimeoutSeconds `
                    -MaximumWorkingSetBytes $MaximumWorkingSetBytes `
                    -MaximumCpuSeconds $MaximumCpuSeconds `
                    -ReapTimeoutSeconds $ReapTimeoutSeconds)) {
                return [pscustomobject]@{
                    ExitCode = $null; TimedOut = $true
                    Records = $records; OutputBytes = $outputBytes
                    Stderr = ''; StderrTruncated = $stderrTruncated
                    IsolationProfile = $launchPlan.IsolationProfile
                }
            }
        }
        while (-not $process.HasExited) {
            Assert-HHForensicsParserResourceBound -Process $process `
                -MaximumWorkingSetBytes $MaximumWorkingSetBytes `
                -MaximumCpuSeconds $MaximumCpuSeconds `
                -ReapTimeoutSeconds $ReapTimeoutSeconds
            if ($stopwatch.Elapsed.TotalSeconds -ge $TimeoutSeconds) {
                Invoke-HHForensicsParserTreeTermination -Process $process `
                    -ReapTimeoutSeconds $ReapTimeoutSeconds
                return [pscustomobject]@{
                    ExitCode = $null
                    TimedOut = $true
                    Records = $records
                    OutputBytes = $outputBytes
                    Stderr = ''
                    StderrTruncated = $stderrTruncated
                    IsolationProfile = $launchPlan.IsolationProfile
                }
            }
            Start-Sleep -Milliseconds 10
        }
        [void](Assert-HHForensicsFileIdentity -Identity $ParserIdentity)
        [void](Assert-HHForensicsFileIdentity -Identity $EvidenceIdentity)
        $stderrText = [Text.UTF8Encoding]::new($false, $false).GetString($stderr.ToArray())
        return [pscustomobject]@{
            ExitCode = $process.ExitCode
            TimedOut = $false
            Records = $records
            OutputBytes = $outputBytes
            Stderr = $stderrText
            StderrTruncated = $stderrTruncated
            IsolationProfile = $launchPlan.IsolationProfile
        }
    }
    catch {
        if ($processStarted -and -not $process.HasExited) {
            Invoke-HHForensicsParserTreeTermination -Process $process `
                -ReapTimeoutSeconds $ReapTimeoutSeconds
        }
        throw
    }
    finally {
        if ($null -ne $stopwatch) { $stopwatch.Stop() }
        if ($null -ne $line) { $line.Dispose() }
        if ($null -ne $stderr) { $stderr.Dispose() }
        if ($null -ne $process) { $process.Dispose() }
    }
}

function Invoke-HHForensicsEvtxParser {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$EvidencePath,
        [Parameter(Mandatory)][ValidatePattern('^[a-fA-F0-9]{64}$')]
        [string]$ExpectedEvidenceSha256,
        [Parameter(Mandatory)][psobject]$Parser,
        [Parameter(Mandatory)][scriptblock]$RecordConsumer,
        [ValidateRange(1, 3600)][int]$TimeoutSeconds = 120,
        [ValidateRange(1, 1073741824)][long]$MaximumEvidenceBytes = 268435456,
        [ValidateRange(1, 2147483647)][long]$MaximumOutputBytes = 536870912,
        [ValidateRange(1, 67108864)][int]$MaximumLineBytes = 4194304,
        [ValidateRange(1, 1048576)][int]$MaximumStderrBytes = 16384,
        [ValidateRange(1, 128)][int]$MaximumJsonDepth = 64,
        [ValidateRange(1, 16777216)][int]$MaximumStringBytes = 1048576,
        [string]$StagingRoot,
        [scriptblock]$ProcessInvoker = ${function:Invoke-HHForensicsNativeParserProcess}
    )

    if ($Parser.Marker -cne 'HostHunter.Forensics.Parser.v2' -or
        $Parser.Name -cne 'evtx_dump' -or $Parser.Version -cne $script:HHEvtxDumpVersion) {
        throw [IO.InvalidDataException]::new(
            'The parser descriptor is not an approved evtx_dump 0.12.2 descriptor.'
        )
    }
    [void](Assert-HHForensicsFileIdentity -Identity $Parser.FileIdentity)
    $originalEvidenceIdentity = Get-HHForensicsFileIdentity -Path $EvidencePath `
        -ExpectedSha256 $ExpectedEvidenceSha256
    if ($originalEvidenceIdentity.Length -gt $MaximumEvidenceBytes) {
        throw [IO.InvalidDataException]::new(
            'The EVTX evidence file exceeds the configured parser input limit.'
        )
    }
    $stagingRoot = Initialize-HHForensicsPrivateStagingDirectory -RootPath $StagingRoot
    try {
        $stagedParser = Copy-HHForensicsFileToPrivateStage `
            -SourceIdentity $Parser.FileIdentity `
            -DestinationPath (Join-Path $stagingRoot 'evtx_dump') -Executable
        $stagedEvidence = Copy-HHForensicsFileToPrivateStage `
            -SourceIdentity $originalEvidenceIdentity `
            -DestinationPath (Join-Path $stagingRoot 'evidence.evtx')
        $result = & $ProcessInvoker -Executable $stagedParser.Path `
            -ArgumentList @('-t', '1', '-o', 'jsonl', $stagedEvidence.Path) `
            -ParserIdentity $stagedParser -EvidenceIdentity $stagedEvidence `
            -RecordConsumer $RecordConsumer -TimeoutSeconds $TimeoutSeconds `
            -MaximumLineBytes $MaximumLineBytes -MaximumOutputBytes $MaximumOutputBytes `
            -MaximumStderrBytes $MaximumStderrBytes -MaximumJsonDepth $MaximumJsonDepth `
            -MaximumStringBytes $MaximumStringBytes
    }
    finally {
        foreach ($name in @('evtx_dump', 'evidence.evtx')) {
            $stagedPath = Join-Path $stagingRoot $name
            if ([IO.File]::Exists($stagedPath)) { [IO.File]::Delete($stagedPath) }
        }
        if ([IO.Directory]::Exists($stagingRoot)) { [IO.Directory]::Delete($stagingRoot, $false) }
    }
    if ($null -eq $result -or $null -eq $result.PSObject.Properties['TimedOut']) {
        throw [IO.InvalidDataException]::new(
            'The parser process returned an invalid bounded-execution result.'
        )
    }
    [void](Assert-HHForensicsFileIdentity -Identity $Parser.FileIdentity)
    [void](Assert-HHForensicsFileIdentity -Identity $originalEvidenceIdentity)
    if ($result.TimedOut) {
        throw [TimeoutException]::new('evtx_dump exceeded the bounded execution timeout.')
    }
    if ([int]$result.ExitCode -ne 0) {
        $suffix = if ($result.StderrTruncated) { ' [stderr truncated]' } else { '' }
        throw [IO.InvalidDataException]::new(
            "evtx_dump failed with exit code $($result.ExitCode): $(([string]$result.Stderr).Trim())$suffix"
        )
    }
    return [pscustomobject]@{
        Marker = 'HostHunter.Forensics.ParserResult.v2'
        ParserName = $Parser.Name
        ParserVersion = $Parser.Version
        EvidenceIdentity = $originalEvidenceIdentity
        Records = [long]$result.Records
        OutputBytes = [long]$result.OutputBytes
        IsolationProfile = $result.IsolationProfile
        PlaintextOutputArtifact = $false
    }
}
