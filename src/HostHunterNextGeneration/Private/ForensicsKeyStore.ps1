Set-StrictMode -Version Latest

$script:HHForensicsKeychainService = 'com.hosthunter.nextgeneration.forensics-key.v1'
$script:HHForensicsAnchorKeychainService = 'com.hosthunter.nextgeneration.forensics-anchor.v1'
$script:HHForensicsKeychainKeyLabel = 'HostHunter Next Generation Forensics Key'
$script:HHForensicsKeychainAnchorLabel = 'HostHunter Next Generation Forensics Anchor'
$script:HHForensicsCredentialService = 'HostHunterNextGeneration.Forensics.v1'
$script:HHForensicsKeyAccount = 'ledger-key'
$script:HHForensicsAnchorAccount = 'ledger-anchor'
$script:HHForensicsAnchorArtifactLength = 240
$script:HHForensicsAnchorMagic = [Text.Encoding]::ASCII.GetBytes('HHFANCH1')
$script:HHMacOSForensicsWorkerPath = Join-Path $PSScriptRoot `
    'Workers/MacOSForensicsKeychainWorker.ps1'
$script:HHForensicsPowerShellPath = Join-Path $PSHOME 'pwsh'

function Get-HHForensicsKeyStoreErrorRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ErrorId,
        [Parameter(Mandatory)][string]$Message,
        [Parameter(Mandatory)][Management.Automation.ErrorCategory]$Category
    )

    $exception = [InvalidOperationException]::new($Message)
    [Management.Automation.ErrorRecord]::new($exception, $ErrorId, $Category, $null)
}

function Get-HHForensicsKeychainAccount {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$DataRoot)

    if ([string]::IsNullOrWhiteSpace($DataRoot)) {
        throw [ArgumentException]::new('DataRoot must not be empty.', 'DataRoot')
    }
    $canonicalRoot = [IO.Path]::GetFullPath($DataRoot)
    $pathRoot = [IO.Path]::GetPathRoot($canonicalRoot)
    if ($canonicalRoot.Length -gt $pathRoot.Length) {
        $canonicalRoot = $canonicalRoot.TrimEnd([char[]]@(
                [IO.Path]::DirectorySeparatorChar,
                [IO.Path]::AltDirectorySeparatorChar
            ))
    }
    $canonicalRoot = $canonicalRoot.Normalize([Text.NormalizationForm]::FormC)
    $pathBytes = [Text.Encoding]::UTF8.GetBytes($canonicalRoot)
    try {
        $digest = [Security.Cryptography.SHA256]::HashData($pathBytes)
        try { return [Convert]::ToHexString($digest).ToLowerInvariant() }
        finally { [Array]::Clear($digest, 0, $digest.Length) }
    }
    finally { [Array]::Clear($pathBytes, 0, $pathBytes.Length) }
}

function Stop-HHForensicsKeychainProcess {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Terminates only the supplied timed-out child process.'
    )]
    [CmdletBinding()]
    param([Parameter(Mandatory)][Diagnostics.Process]$Process)

    try {
        if (-not $Process.HasExited) { $Process.Kill($true) }
    }
    catch { Write-Debug 'The bounded Forensics Keychain worker required a second reap check.' }
    try {
        if ($Process.WaitForExit(2000)) { return }
    }
    catch { Write-Debug 'The bounded Forensics Keychain worker state could not be inspected.' }
    throw (Get-HHForensicsKeyStoreErrorRecord `
            -ErrorId ForensicsKeychainTerminationFailed `
            -Message 'The macOS Forensics Keychain worker could not be confirmed terminated.' `
            -Category OperationStopped)
}

function Clear-HHForensicsMemoryStream {
    [CmdletBinding()]
    param([AllowNull()][IO.MemoryStream]$Stream)

    if ($null -eq $Stream) { return }
    $segment = [ArraySegment[byte]]::new([byte[]]::new(0))
    if ($Stream.TryGetBuffer([ref]$segment) -and $null -ne $segment.Array) {
        [Array]::Clear($segment.Array, $segment.Offset, $segment.Count)
    }
}

function Get-HHForensicsLoginKeychainPath {
    [CmdletBinding()]
    param([scriptblock]$SecurityCommandInvoker)

    if (-not $IsMacOS -and $null -eq $SecurityCommandInvoker) {
        throw (Get-HHForensicsKeyStoreErrorRecord `
                -ErrorId ForensicsKeychainUnavailable `
                -Message 'The macOS Forensics Keychain provider is unavailable on this platform.' `
                -Category ResourceUnavailable)
    }
    try {
        $result = if ($null -eq $SecurityCommandInvoker) {
            Invoke-HHMacOSSecurityCommand `
                -ArgumentList @('login-keychain') -TimeoutSeconds 15 `
                -ExecutablePath '/usr/bin/security'
        }
        else { & $SecurityCommandInvoker '/usr/bin/security' @('login-keychain') 15 }
    }
    catch {
        throw (Get-HHForensicsKeyStoreErrorRecord `
                -ErrorId ForensicsKeychainUnavailable `
                -Message 'The macOS login Keychain could not be resolved for Forensics.' `
                -Category ResourceUnavailable)
    }
    if ($null -eq $result -or $null -eq $result.PSObject.Properties['ExitCode'] -or
        $null -eq $result.PSObject.Properties['StandardOutput'] -or
        $null -eq $result.PSObject.Properties['StandardError']) {
        throw (Get-HHForensicsKeyStoreErrorRecord `
                -ErrorId ForensicsKeychainUnavailable `
                -Message 'The macOS login Keychain returned an invalid result.' `
                -Category InvalidResult)
    }
    try { $exitCode = [int]$result.ExitCode }
    catch {
        throw (Get-HHForensicsKeyStoreErrorRecord `
                -ErrorId ForensicsKeychainUnavailable `
                -Message 'The macOS login Keychain returned an invalid result.' `
                -Category InvalidResult)
    }
    if ($exitCode -ne 0) {
        throw (Get-HHForensicsKeyStoreErrorRecord `
                -ErrorId ForensicsKeychainUnavailable `
                -Message 'The macOS login Keychain is unavailable for Forensics.' `
                -Category ResourceUnavailable)
    }
    $framedPath = [string]$result.StandardOutput
    if ($framedPath.EndsWith("`r`n", [StringComparison]::Ordinal)) {
        $framedPath = $framedPath.Substring(0, $framedPath.Length - 2)
    }
    elseif ($framedPath.EndsWith("`n", [StringComparison]::Ordinal)) {
        $framedPath = $framedPath.Substring(0, $framedPath.Length - 1)
    }
    $match = [regex]::Match($framedPath, '^[ \t]*"([^"\r\n]+)"[ \t]*$')
    if (-not $match.Success -or -not [IO.Path]::IsPathRooted($match.Groups[1].Value)) {
        throw (Get-HHForensicsKeyStoreErrorRecord `
                -ErrorId ForensicsKeychainUnavailable `
                -Message 'The macOS login Keychain path is invalid for Forensics.' `
                -Category InvalidData)
    }
    try { return [IO.Path]::GetFullPath($match.Groups[1].Value) }
    catch {
        throw (Get-HHForensicsKeyStoreErrorRecord `
                -ErrorId ForensicsKeychainUnavailable `
                -Message 'The macOS login Keychain path is invalid for Forensics.' `
                -Category InvalidData)
    }
}

function Invoke-HHMacOSForensicsKeychainWorker {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('CreateKey', 'ReadKey', 'CreateAnchor', 'ReadAnchor',
            'CompareUpdateAnchor', 'Delete')]
        [string]$Action,
        [Parameter(Mandatory)][string]$KeychainPath,
        [Parameter(Mandatory)][string]$Service,
        [Parameter(Mandatory)][string]$Account,
        [AllowNull()][byte[]]$InputBytes,
        [ValidateRange(1, 60)][int]$TimeoutSeconds = 15,
        [string]$WorkerPath = $script:HHMacOSForensicsWorkerPath,
        [string]$PowerShellPath = $script:HHForensicsPowerShellPath
    )

    if (-not $IsMacOS) {
        throw (Get-HHForensicsKeyStoreErrorRecord `
                -ErrorId ForensicsKeychainUnavailable `
                -Message 'The native Forensics Keychain worker is unavailable on this platform.' `
                -Category ResourceUnavailable)
    }
    $expectedInputLength = switch ($Action) {
        'CreateKey' { 32 }
        'CreateAnchor' { $script:HHForensicsAnchorArtifactLength }
        'CompareUpdateAnchor' { $script:HHForensicsAnchorArtifactLength * 2 }
        default { 0 }
    }
    $serviceAllowed = if ($Action -in @('CreateKey', 'ReadKey')) {
        $Service -ceq $script:HHForensicsKeychainService
    }
    elseif ($Action -in @('CreateAnchor', 'ReadAnchor', 'CompareUpdateAnchor')) {
        $Service -ceq $script:HHForensicsAnchorKeychainService
    }
    elseif ($Action -eq 'Delete') {
        $Service -in @(
            $script:HHForensicsKeychainService,
            $script:HHForensicsAnchorKeychainService
        )
    }
    else { $false }
    if (-not $serviceAllowed -or
        ($expectedInputLength -eq 0 -and $null -ne $InputBytes) -or
        ($expectedInputLength -gt 0 -and
            ($null -eq $InputBytes -or $InputBytes.Length -ne $expectedInputLength)) -or
        -not [IO.Path]::IsPathRooted($KeychainPath) -or
        -not [IO.Path]::IsPathRooted($WorkerPath) -or
        -not [IO.File]::Exists($WorkerPath) -or
        -not [IO.Path]::IsPathRooted($PowerShellPath) -or
        -not [IO.File]::Exists($PowerShellPath)) {
        throw (Get-HHForensicsKeyStoreErrorRecord `
                -ErrorId ForensicsKeychainUnavailable `
                -Message 'The native Forensics Keychain worker input is invalid.' `
                -Category InvalidData)
    }

    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $PowerShellPath
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.RedirectStandardInput = $expectedInputLength -gt 0
    foreach ($argument in @(
            '-NoLogo', '-NoProfile', '-NonInteractive', '-File', $WorkerPath,
            '-Action', $Action, '-KeychainPath', $KeychainPath,
            '-Service', $Service, '-Account', $Account
        )) {
        $null = $startInfo.ArgumentList.Add($argument)
    }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $stdout = [IO.MemoryStream]::new()
    $stderr = [IO.MemoryStream]::new()
    $outputBytes = $null
    try {
        try { $started = $process.Start() }
        catch {
            throw (Get-HHForensicsKeyStoreErrorRecord `
                    -ErrorId ForensicsKeychainUnavailable `
                    -Message 'The native Forensics Keychain worker could not start.' `
                    -Category ResourceUnavailable)
        }
        if (-not $started) {
            throw (Get-HHForensicsKeyStoreErrorRecord `
                    -ErrorId ForensicsKeychainUnavailable `
                    -Message 'The native Forensics Keychain worker could not start.' `
                    -Category ResourceUnavailable)
        }
        $stdoutTask = $process.StandardOutput.BaseStream.CopyToAsync($stdout)
        $stderrTask = $process.StandardError.BaseStream.CopyToAsync($stderr)
        if ($expectedInputLength -gt 0) {
            try {
                $process.StandardInput.BaseStream.Write($InputBytes, 0, $InputBytes.Length)
                $process.StandardInput.BaseStream.Flush()
                $process.StandardInput.Close()
            }
            catch {
                if (-not $process.HasExited) {
                    Stop-HHForensicsKeychainProcess -Process $process
                }
                throw (Get-HHForensicsKeyStoreErrorRecord `
                        -ErrorId ForensicsKeychainUnavailable `
                        -Message 'The native Forensics Keychain input channel failed.' `
                        -Category ResourceUnavailable)
            }
        }
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            Stop-HHForensicsKeychainProcess -Process $process
            throw (Get-HHForensicsKeyStoreErrorRecord `
                    -ErrorId ForensicsKeychainTimedOut `
                    -Message 'The native Forensics Keychain worker timed out.' `
                    -Category OperationTimeout)
        }
        try {
            $null = $stdoutTask.GetAwaiter().GetResult()
            $null = $stderrTask.GetAwaiter().GetResult()
            $outputBytes = $stdout.ToArray()
        }
        catch {
            throw (Get-HHForensicsKeyStoreErrorRecord `
                    -ErrorId ForensicsKeychainUnavailable `
                    -Message 'The native Forensics Keychain worker output could not be read.' `
                    -Category ReadError)
        }
        $maximumOutput = if ($Action -eq 'ReadKey') {
            32
        }
        elseif ($Action -in @('ReadAnchor', 'CompareUpdateAnchor')) {
            $script:HHForensicsAnchorArtifactLength
        }
        else { 0 }
        if ($outputBytes.Length -gt $maximumOutput) {
            throw (Get-HHForensicsKeyStoreErrorRecord `
                    -ErrorId ForensicsKeychainUnavailable `
                    -Message 'The native Forensics Keychain worker output exceeded its bound.' `
                    -Category LimitsExceeded)
        }
        if ($process.ExitCode -ne 0 -and $outputBytes.Length -gt 0) {
            [Array]::Clear($outputBytes, 0, $outputBytes.Length)
            $outputBytes = [byte[]]::new(0)
        }
        [pscustomobject]@{ ExitCode = $process.ExitCode; OutputBytes = $outputBytes }
        $outputBytes = $null
    }
    finally {
        if ($null -ne $outputBytes) { [Array]::Clear($outputBytes, 0, $outputBytes.Length) }
        if ($startInfo.RedirectStandardInput) {
            try { $process.StandardInput.Close() }
            catch { Write-Debug 'The Forensics Keychain input stream was already closed.' }
        }
        Clear-HHForensicsMemoryStream -Stream $stdout
        Clear-HHForensicsMemoryStream -Stream $stderr
        $stdout.Dispose()
        $stderr.Dispose()
        $process.Dispose()
    }
}

function Invoke-HHForensicsKeychainCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('CreateKey', 'ReadKey', 'CreateAnchor', 'ReadAnchor',
            'CompareUpdateAnchor', 'Delete')]
        [string]$Action,
        [Parameter(Mandatory)][string]$KeychainPath,
        [Parameter(Mandatory)][string]$Service,
        [Parameter(Mandatory)][string]$Account,
        [AllowNull()][byte[]]$InputBytes,
        [scriptblock]$KeychainWorkerInvoker
    )

    try {
        $result = if ($null -eq $KeychainWorkerInvoker) {
            Invoke-HHMacOSForensicsKeychainWorker `
                -Action $Action -KeychainPath $KeychainPath -Service $Service `
                -Account $Account -InputBytes $InputBytes -TimeoutSeconds 15
        }
        else {
            & $KeychainWorkerInvoker `
                $script:HHMacOSForensicsWorkerPath `
                $script:HHForensicsPowerShellPath $Action $KeychainPath $Service `
                $Account $InputBytes 15
        }
    }
    catch {
        $errorId = ($_.FullyQualifiedErrorId -split ',', 2)[0]
        if ($errorId -in @(
                'ForensicsKeychainUnavailable', 'ForensicsKeychainTimedOut',
                'ForensicsKeychainTerminationFailed'
            )) { throw }
        throw (Get-HHForensicsKeyStoreErrorRecord `
                -ErrorId ForensicsKeychainUnavailable `
                -Message 'The native Forensics Keychain worker failed.' `
                -Category ResourceUnavailable)
    }
    if ($null -eq $result -or $null -eq $result.PSObject.Properties['ExitCode'] -or
        $null -eq $result.PSObject.Properties['OutputBytes'] -or
        $result.OutputBytes -isnot [byte[]]) {
        if ($null -ne $result -and $result.PSObject.Properties['OutputBytes'] -and
            $result.OutputBytes -is [byte[]]) {
            [Array]::Clear($result.OutputBytes, 0, $result.OutputBytes.Length)
        }
        throw (Get-HHForensicsKeyStoreErrorRecord `
                -ErrorId ForensicsKeychainUnavailable `
                -Message 'The native Forensics Keychain worker returned an invalid result.' `
                -Category InvalidResult)
    }
    try { $exitCode = [int]$result.ExitCode }
    catch {
        [Array]::Clear($result.OutputBytes, 0, $result.OutputBytes.Length)
        throw (Get-HHForensicsKeyStoreErrorRecord `
                -ErrorId ForensicsKeychainUnavailable `
                -Message 'The native Forensics Keychain worker returned an invalid result.' `
                -Category InvalidResult)
    }
    [pscustomobject]@{ ExitCode = $exitCode; OutputBytes = [byte[]]$result.OutputBytes }
}

function Get-HHMacOSForensicsKey {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)][string]$DataRoot,
        [scriptblock]$SecurityCommandInvoker,
        [scriptblock]$KeychainWorkerInvoker
    )

    $account = Get-HHForensicsKeychainAccount -DataRoot $DataRoot
    $keychainPath = Get-HHForensicsLoginKeychainPath `
        -SecurityCommandInvoker $SecurityCommandInvoker
    $read = Invoke-HHForensicsKeychainCommand `
        -Action ReadKey -KeychainPath $keychainPath `
        -Service $script:HHForensicsKeychainService -Account $account `
        -KeychainWorkerInvoker $KeychainWorkerInvoker
    if ($read.ExitCode -eq 0 -and $read.OutputBytes.Length -eq 32) {
        $copy = [byte[]]$read.OutputBytes.Clone()
        [Array]::Clear($read.OutputBytes, 0, $read.OutputBytes.Length)
        Write-Output -InputObject $copy -NoEnumerate
        return
    }
    if ($read.ExitCode -ne 10 -or $read.OutputBytes.Length -ne 0) {
        [Array]::Clear($read.OutputBytes, 0, $read.OutputBytes.Length)
        throw (Get-HHForensicsKeyStoreErrorRecord `
                -ErrorId ForensicsKeyUnavailable `
                -Message 'The independent macOS Forensics key could not be read.' `
                -Category SecurityError)
    }

    $candidate = [byte[]]::new(32)
    [Security.Cryptography.RandomNumberGenerator]::Fill($candidate)
    $authoritative = $null
    try {
        $create = Invoke-HHForensicsKeychainCommand `
            -Action CreateKey -KeychainPath $keychainPath `
            -Service $script:HHForensicsKeychainService -Account $account `
            -InputBytes $candidate -KeychainWorkerInvoker $KeychainWorkerInvoker
        if ($create.ExitCode -notin @(0, 11) -or $create.OutputBytes.Length -ne 0) {
            [Array]::Clear($create.OutputBytes, 0, $create.OutputBytes.Length)
            throw (Get-HHForensicsKeyStoreErrorRecord `
                    -ErrorId ForensicsKeyUnavailable `
                    -Message 'The independent macOS Forensics key could not be created.' `
                    -Category SecurityError)
        }
        $verify = Invoke-HHForensicsKeychainCommand `
            -Action ReadKey -KeychainPath $keychainPath `
            -Service $script:HHForensicsKeychainService -Account $account `
            -KeychainWorkerInvoker $KeychainWorkerInvoker
        $authoritative = $verify.OutputBytes
        if ($verify.ExitCode -ne 0 -or $authoritative.Length -ne 32 -or
            ($create.ExitCode -eq 0 -and
                -not [Security.Cryptography.CryptographicOperations]::FixedTimeEquals(
                    $candidate,
                    $authoritative
                ))) {
            throw (Get-HHForensicsKeyStoreErrorRecord `
                    -ErrorId ForensicsKeyUnavailable `
                    -Message 'The independent macOS Forensics key failed exact readback.' `
                    -Category SecurityError)
        }
        $copy = [byte[]]$authoritative.Clone()
        Write-Output -InputObject $copy -NoEnumerate
    }
    finally {
        [Array]::Clear($candidate, 0, $candidate.Length)
        if ($null -ne $authoritative) {
            [Array]::Clear($authoritative, 0, $authoritative.Length)
        }
    }
}

function ConvertTo-HHForensicsAnchorArtifact {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param([Parameter(Mandatory)][object]$Anchor)

    foreach ($name in @(
            'Schema', 'Service', 'Account', 'DatabaseId', 'SchemaVersion',
            'SchemaFingerprint', 'Generation', 'StateDigest', 'StateMac',
            'ProjectionDigest', 'ProjectionMac', 'AnchorMac'
        )) {
        if ($null -eq $Anchor.PSObject.Properties[$name]) {
            throw [ArgumentException]::new('The Forensics anchor is incomplete.', 'Anchor')
        }
    }
    if ([string]$Anchor.Schema -cne 'hosthunter.forensics-anchor/1' -or
        [string]$Anchor.Service -cne $script:HHForensicsCredentialService -or
        [string]$Anchor.Account -cne $script:HHForensicsAnchorAccount -or
        ([byte[]]$Anchor.DatabaseId).Length -ne 16 -or
        ([byte[]]$Anchor.SchemaFingerprint).Length -ne 32 -or
        ([byte[]]$Anchor.StateDigest).Length -ne 32 -or
        ([byte[]]$Anchor.StateMac).Length -ne 32 -or
        ([byte[]]$Anchor.ProjectionDigest).Length -ne 32 -or
        ([byte[]]$Anchor.ProjectionMac).Length -ne 32 -or
        ([byte[]]$Anchor.AnchorMac).Length -ne 32 -or
        [long]$Anchor.SchemaVersion -ne 1 -or [long]$Anchor.Generation -lt 0) {
        throw [ArgumentException]::new('The Forensics anchor is malformed.', 'Anchor')
    }
    $artifact = [byte[]]::new($script:HHForensicsAnchorArtifactLength)
    [Array]::Copy($script:HHForensicsAnchorMagic, 0, $artifact, 0, 8)
    $artifactVersion = [BitConverter]::GetBytes([long]1)
    $schemaVersion = [BitConverter]::GetBytes([long]$Anchor.SchemaVersion)
    $generation = [BitConverter]::GetBytes([long]$Anchor.Generation)
    if (-not [BitConverter]::IsLittleEndian) {
        [Array]::Reverse($artifactVersion)
        [Array]::Reverse($schemaVersion)
        [Array]::Reverse($generation)
    }
    try {
        [Array]::Copy($artifactVersion, 0, $artifact, 8, 8)
        [Array]::Copy([byte[]]$Anchor.DatabaseId, 0, $artifact, 16, 16)
        [Array]::Copy($schemaVersion, 0, $artifact, 32, 8)
        [Array]::Copy([byte[]]$Anchor.SchemaFingerprint, 0, $artifact, 40, 32)
        [Array]::Copy($generation, 0, $artifact, 72, 8)
        [Array]::Copy([byte[]]$Anchor.StateDigest, 0, $artifact, 80, 32)
        [Array]::Copy([byte[]]$Anchor.StateMac, 0, $artifact, 112, 32)
        [Array]::Copy([byte[]]$Anchor.ProjectionDigest, 0, $artifact, 144, 32)
        [Array]::Copy([byte[]]$Anchor.ProjectionMac, 0, $artifact, 176, 32)
        [Array]::Copy([byte[]]$Anchor.AnchorMac, 0, $artifact, 208, 32)
        Write-Output -InputObject $artifact -NoEnumerate
    }
    finally {
        [Array]::Clear($artifactVersion, 0, $artifactVersion.Length)
        [Array]::Clear($schemaVersion, 0, $schemaVersion.Length)
        [Array]::Clear($generation, 0, $generation.Length)
    }
}

function ConvertFrom-HHForensicsAnchorArtifact {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Artifact)

    if ($Artifact.Length -ne $script:HHForensicsAnchorArtifactLength) {
        throw [ArgumentException]::new('The Forensics anchor artifact must be exactly 240 bytes.', 'Artifact')
    }
    $magic = [byte[]]$Artifact[0..7]
    try {
        if (-not [Security.Cryptography.CryptographicOperations]::FixedTimeEquals(
                $magic,
                $script:HHForensicsAnchorMagic
            )) {
            throw [ArgumentException]::new('The Forensics anchor artifact header is invalid.', 'Artifact')
        }
    }
    finally { [Array]::Clear($magic, 0, $magic.Length) }
    $artifactVersionBytes = [byte[]]$Artifact[8..15]
    $schemaVersionBytes = [byte[]]$Artifact[32..39]
    $generationBytes = [byte[]]$Artifact[72..79]
    if (-not [BitConverter]::IsLittleEndian) {
        [Array]::Reverse($artifactVersionBytes)
        [Array]::Reverse($schemaVersionBytes)
        [Array]::Reverse($generationBytes)
    }
    try {
        $artifactVersion = [BitConverter]::ToInt64($artifactVersionBytes, 0)
        $schemaVersion = [BitConverter]::ToInt64($schemaVersionBytes, 0)
        $generation = [BitConverter]::ToInt64($generationBytes, 0)
        if ($artifactVersion -ne 1 -or $schemaVersion -ne 1 -or $generation -lt 0) {
            throw [ArgumentException]::new('The Forensics anchor artifact version is invalid.', 'Artifact')
        }
        [pscustomobject]@{
            Schema = 'hosthunter.forensics-anchor/1'
            Service = $script:HHForensicsCredentialService
            Account = $script:HHForensicsAnchorAccount
            DatabaseId = [byte[]]$Artifact[16..31]
            SchemaVersion = $schemaVersion
            SchemaFingerprint = [byte[]]$Artifact[40..71]
            Generation = $generation
            StateDigest = [byte[]]$Artifact[80..111]
            StateMac = [byte[]]$Artifact[112..143]
            ProjectionDigest = [byte[]]$Artifact[144..175]
            ProjectionMac = [byte[]]$Artifact[176..207]
            AnchorMac = [byte[]]$Artifact[208..239]
        }
    }
    finally {
        [Array]::Clear($artifactVersionBytes, 0, $artifactVersionBytes.Length)
        [Array]::Clear($schemaVersionBytes, 0, $schemaVersionBytes.Length)
        [Array]::Clear($generationBytes, 0, $generationBytes.Length)
    }
}

function Read-HHMacOSForensicsAnchor {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DataRoot,
        [scriptblock]$SecurityCommandInvoker,
        [scriptblock]$KeychainWorkerInvoker
    )

    $account = Get-HHForensicsKeychainAccount -DataRoot $DataRoot
    $keychainPath = Get-HHForensicsLoginKeychainPath `
        -SecurityCommandInvoker $SecurityCommandInvoker
    $result = Invoke-HHForensicsKeychainCommand `
        -Action ReadAnchor -KeychainPath $keychainPath `
        -Service $script:HHForensicsAnchorKeychainService -Account $account `
        -KeychainWorkerInvoker $KeychainWorkerInvoker
    if ($result.ExitCode -eq 10 -and $result.OutputBytes.Length -eq 0) { return $null }
    try {
        if ($result.ExitCode -ne 0 -or
            $result.OutputBytes.Length -ne $script:HHForensicsAnchorArtifactLength) {
            throw (Get-HHForensicsKeyStoreErrorRecord `
                    -ErrorId ForensicsIntegrityFailed `
                    -Message 'The macOS Forensics anchor could not be read exactly.' `
                    -Category SecurityError)
        }
        return ConvertFrom-HHForensicsAnchorArtifact -Artifact $result.OutputBytes
    }
    finally { [Array]::Clear($result.OutputBytes, 0, $result.OutputBytes.Length) }
}

function Write-HHMacOSForensicsAnchor {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Private CAS primitive used behind the persistence mutation boundary.'
    )]
    [CmdletBinding()]
    param(
        [AllowNull()][object]$ExpectedAnchor,
        [Parameter(Mandatory)][object]$NewAnchor,
        [Parameter(Mandatory)][string]$DataRoot,
        [scriptblock]$SecurityCommandInvoker,
        [scriptblock]$KeychainWorkerInvoker
    )

    $account = Get-HHForensicsKeychainAccount -DataRoot $DataRoot
    $keychainPath = Get-HHForensicsLoginKeychainPath `
        -SecurityCommandInvoker $SecurityCommandInvoker
    $newArtifact = ConvertTo-HHForensicsAnchorArtifact -Anchor $NewAnchor
    $expectedArtifact = $null
    $inputBytes = $null
    $readback = $null
    try {
        if ($null -eq $ExpectedAnchor) {
            $result = Invoke-HHForensicsKeychainCommand `
                -Action CreateAnchor -KeychainPath $keychainPath `
                -Service $script:HHForensicsAnchorKeychainService -Account $account `
                -InputBytes $newArtifact -KeychainWorkerInvoker $KeychainWorkerInvoker
            if ($result.ExitCode -ne 0 -or $result.OutputBytes.Length -ne 0) {
                [Array]::Clear($result.OutputBytes, 0, $result.OutputBytes.Length)
                throw (Get-HHForensicsKeyStoreErrorRecord `
                        -ErrorId ForensicsIntegrityFailed `
                        -Message 'The macOS Forensics anchor could not be created exclusively.' `
                        -Category SecurityError)
            }
            $verify = Invoke-HHForensicsKeychainCommand `
                -Action ReadAnchor -KeychainPath $keychainPath `
                -Service $script:HHForensicsAnchorKeychainService -Account $account `
                -KeychainWorkerInvoker $KeychainWorkerInvoker
            $readback = $verify.OutputBytes
            if ($verify.ExitCode -ne 0 -or $readback.Length -ne $newArtifact.Length -or
                -not [Security.Cryptography.CryptographicOperations]::FixedTimeEquals(
                    $newArtifact,
                    $readback
                )) {
                throw (Get-HHForensicsKeyStoreErrorRecord `
                        -ErrorId ForensicsIntegrityFailed `
                        -Message 'The macOS Forensics anchor failed exact readback.' `
                        -Category SecurityError)
            }
            return
        }

        $expectedArtifact = ConvertTo-HHForensicsAnchorArtifact -Anchor $ExpectedAnchor
        $inputBytes = [byte[]]::new($script:HHForensicsAnchorArtifactLength * 2)
        [Array]::Copy($expectedArtifact, 0, $inputBytes, 0, $expectedArtifact.Length)
        [Array]::Copy($newArtifact, 0, $inputBytes, $expectedArtifact.Length, $newArtifact.Length)
        $result = Invoke-HHForensicsKeychainCommand `
            -Action CompareUpdateAnchor -KeychainPath $keychainPath `
            -Service $script:HHForensicsAnchorKeychainService -Account $account `
            -InputBytes $inputBytes -KeychainWorkerInvoker $KeychainWorkerInvoker
        $readback = $result.OutputBytes
        if ($result.ExitCode -eq 16) {
            throw (Get-HHForensicsKeyStoreErrorRecord `
                    -ErrorId ForensicsIntegrityFailed `
                    -Message 'The macOS Forensics anchor changed concurrently.' `
                    -Category SecurityError)
        }
        if ($result.ExitCode -ne 0 -or $readback.Length -ne $newArtifact.Length -or
            -not [Security.Cryptography.CryptographicOperations]::FixedTimeEquals(
                $newArtifact,
                $readback
            )) {
            throw (Get-HHForensicsKeyStoreErrorRecord `
                    -ErrorId ForensicsIntegrityFailed `
                    -Message 'The macOS Forensics anchor CAS failed exact readback.' `
                    -Category SecurityError)
        }
    }
    finally {
        [Array]::Clear($newArtifact, 0, $newArtifact.Length)
        if ($null -ne $expectedArtifact) {
            [Array]::Clear($expectedArtifact, 0, $expectedArtifact.Length)
        }
        if ($null -ne $inputBytes) { [Array]::Clear($inputBytes, 0, $inputBytes.Length) }
        if ($null -ne $readback) { [Array]::Clear($readback, 0, $readback.Length) }
    }
}

function New-HHMacOSForensicsProvider {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Constructs in-memory provider callbacks without touching Keychain.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DataRoot,
        [scriptblock]$SecurityCommandInvoker,
        [scriptblock]$KeychainWorkerInvoker
    )

    $canonicalRoot = [IO.Path]::GetFullPath($DataRoot)
    $providerSecurityInvoker = $SecurityCommandInvoker
    $providerWorkerInvoker = $KeychainWorkerInvoker
    $providerService = $script:HHForensicsCredentialService
    $providerKeyAccount = $script:HHForensicsKeyAccount
    $providerModule = $ExecutionContext.SessionState.Module
    if ($null -eq $providerModule) {
        throw (Get-HHForensicsKeyStoreErrorRecord `
                -ErrorId ForensicsKeychainUnavailable `
                -Message 'The Forensics Keychain provider requires module scope.' `
                -Category SecurityError)
    }
    $keyProvider = {
        & $providerModule {
            param($Root, $SecurityInvoker, $WorkerInvoker, $Service, $Account)
            $keyBytes = Get-HHMacOSForensicsKey -DataRoot $Root `
                -SecurityCommandInvoker $SecurityInvoker `
                -KeychainWorkerInvoker $WorkerInvoker
            [pscustomobject]@{
                Service = $Service
                Account = $Account
                KeyBytes = $keyBytes
            }
        } $canonicalRoot $providerSecurityInvoker $providerWorkerInvoker `
            $providerService $providerKeyAccount
    }.GetNewClosure()
    $anchorReader = {
        param($PersistenceContext)
        & $providerModule {
            param($Root, $Context, $SecurityInvoker, $WorkerInvoker)
            if ([IO.Path]::GetFullPath([string]$Context.DataRoot) -cne $Root) {
                throw (Get-HHForensicsKeyStoreErrorRecord `
                        -ErrorId ForensicsKeychainUnavailable `
                        -Message 'The Forensics provider was invoked for a different data root.' `
                        -Category SecurityError)
            }
            Read-HHMacOSForensicsAnchor -DataRoot $Root `
                -SecurityCommandInvoker $SecurityInvoker `
                -KeychainWorkerInvoker $WorkerInvoker
        } $canonicalRoot $PersistenceContext $providerSecurityInvoker $providerWorkerInvoker
    }.GetNewClosure()
    $anchorWriter = {
        param($ExpectedAnchor, $NewAnchor, $PersistenceContext)
        & $providerModule {
            param($Root, $Expected, $New, $Context, $SecurityInvoker, $WorkerInvoker)
            if ([IO.Path]::GetFullPath([string]$Context.DataRoot) -cne $Root) {
                throw (Get-HHForensicsKeyStoreErrorRecord `
                        -ErrorId ForensicsKeychainUnavailable `
                        -Message 'The Forensics provider was invoked for a different data root.' `
                        -Category SecurityError)
            }
            Write-HHMacOSForensicsAnchor `
                -ExpectedAnchor $Expected -NewAnchor $New -DataRoot $Root `
                -SecurityCommandInvoker $SecurityInvoker `
                -KeychainWorkerInvoker $WorkerInvoker
        } $canonicalRoot $ExpectedAnchor $NewAnchor $PersistenceContext `
            $providerSecurityInvoker $providerWorkerInvoker
    }.GetNewClosure()
    [pscustomobject]@{
        ForensicsKeyProvider = $keyProvider
        AnchorReader = $anchorReader
        AnchorWriter = $anchorWriter
        KeyLabel = $script:HHForensicsKeychainKeyLabel
        AnchorLabel = $script:HHForensicsKeychainAnchorLabel
    }
}

function Test-HHMacOSForensicsKeychainLifecycle {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Explicit disposable native qualification helper with exact cleanup.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DataRoot,
        [Parameter(Mandatory)][object]$InitialAnchor,
        [Parameter(Mandatory)][object]$AdvancedAnchor,
        [scriptblock]$SecurityCommandInvoker,
        [scriptblock]$KeychainWorkerInvoker
    )

    $canonicalRoot = [IO.Path]::GetFullPath($DataRoot)
    $leaf = [IO.Path]::GetFileName($canonicalRoot.TrimEnd([char[]]@(
                [IO.Path]::DirectorySeparatorChar,
                [IO.Path]::AltDirectorySeparatorChar
            )))
    if ($leaf -cnotmatch '^hosthunter-forensics-keychain-qualification-[a-f0-9]{32}$') {
        throw [ArgumentException]::new(
            'Native Forensics Keychain qualification requires a unique disposable data root.',
            'DataRoot'
        )
    }
    $account = Get-HHForensicsKeychainAccount -DataRoot $DataRoot
    $keychainPath = Get-HHForensicsLoginKeychainPath `
        -SecurityCommandInvoker $SecurityCommandInvoker
    $key = $null
    $cleanupComplete = $false
    try {
        $key = Get-HHMacOSForensicsKey -DataRoot $DataRoot `
            -SecurityCommandInvoker $SecurityCommandInvoker `
            -KeychainWorkerInvoker $KeychainWorkerInvoker
        Write-HHMacOSForensicsAnchor -ExpectedAnchor $null -NewAnchor $InitialAnchor `
            -DataRoot $DataRoot -SecurityCommandInvoker $SecurityCommandInvoker `
            -KeychainWorkerInvoker $KeychainWorkerInvoker
        Write-HHMacOSForensicsAnchor -ExpectedAnchor $InitialAnchor -NewAnchor $AdvancedAnchor `
            -DataRoot $DataRoot -SecurityCommandInvoker $SecurityCommandInvoker `
            -KeychainWorkerInvoker $KeychainWorkerInvoker
        $actual = Read-HHMacOSForensicsAnchor -DataRoot $DataRoot `
            -SecurityCommandInvoker $SecurityCommandInvoker `
            -KeychainWorkerInvoker $KeychainWorkerInvoker
        $expectedBytes = ConvertTo-HHForensicsAnchorArtifact -Anchor $AdvancedAnchor
        $actualBytes = ConvertTo-HHForensicsAnchorArtifact -Anchor $actual
        try {
            if (-not [Security.Cryptography.CryptographicOperations]::FixedTimeEquals(
                    $expectedBytes,
                    $actualBytes
                )) {
                throw (Get-HHForensicsKeyStoreErrorRecord `
                        -ErrorId ForensicsIntegrityFailed `
                        -Message 'The disposable Forensics Keychain lifecycle did not advance exactly.' `
                        -Category SecurityError)
            }
        }
        finally {
            [Array]::Clear($expectedBytes, 0, $expectedBytes.Length)
            [Array]::Clear($actualBytes, 0, $actualBytes.Length)
        }
    }
    finally {
        if ($null -ne $key) { [Array]::Clear($key, 0, $key.Length) }
        $deleted = 0
        foreach ($service in @(
                $script:HHForensicsAnchorKeychainService,
                $script:HHForensicsKeychainService
            )) {
            $result = Invoke-HHForensicsKeychainCommand `
                -Action Delete -KeychainPath $keychainPath -Service $service `
                -Account $account -KeychainWorkerInvoker $KeychainWorkerInvoker
            if ($result.ExitCode -ne 0 -or $result.OutputBytes.Length -ne 0) {
                [Array]::Clear($result.OutputBytes, 0, $result.OutputBytes.Length)
                throw (Get-HHForensicsKeyStoreErrorRecord `
                        -ErrorId ForensicsKeychainUnavailable `
                        -Message 'The disposable Forensics Keychain lifecycle cleanup failed.' `
                        -Category SecurityError)
            }
            $deleted++
        }
        $cleanupComplete = $deleted -eq 2
    }
    [pscustomobject]@{
        Status = 'Passed'
        KeyLength = 32
        AnchorArtifactLength = $script:HHForensicsAnchorArtifactLength
        CleanupComplete = $cleanupComplete
        Redacted = $true
    }
}
