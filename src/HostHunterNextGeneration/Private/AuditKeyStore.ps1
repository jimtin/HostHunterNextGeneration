Set-StrictMode -Version Latest

$script:HHAuditKeychainService = 'com.hosthunter.nextgeneration.audit-key.v1'
$script:HHPersistenceAnchorKeychainService = 'com.hosthunter.nextgeneration.database-anchor.v1'
$script:HHPersistenceAnchorV1ArtifactLength = 196
$script:HHPersistenceAnchorArtifactLength = 236
$script:HHMacOSSecurityPath = '/usr/bin/security'
$script:HHMacOSKeychainWorkerPath = Join-Path $PSScriptRoot 'Workers/MacOSKeychainWorker.ps1'
$script:HHPowerShellExecutablePath = Join-Path $PSHOME 'pwsh'

function Get-HHAuditKeyStoreErrorRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ErrorId,
        [Parameter(Mandatory)][string]$Message,
        [Parameter(Mandatory)][System.Management.Automation.ErrorCategory]$Category
    )

    $exception = [System.InvalidOperationException]::new($Message)
    [System.Management.Automation.ErrorRecord]::new($exception, $ErrorId, $Category, $null)
}

function Get-HHAuditKeychainAccount {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$DataRoot)

    if ([string]::IsNullOrWhiteSpace($DataRoot)) {
        throw [System.ArgumentException]::new('DataRoot must not be empty.', 'DataRoot')
    }

    $canonicalRoot = [System.IO.Path]::GetFullPath($DataRoot)
    $pathRoot = [System.IO.Path]::GetPathRoot($canonicalRoot)
    if ($canonicalRoot.Length -gt $pathRoot.Length) {
        $separators = [char[]]@(
            [System.IO.Path]::DirectorySeparatorChar,
            [System.IO.Path]::AltDirectorySeparatorChar
        )
        $canonicalRoot = $canonicalRoot.TrimEnd($separators)
    }
    $canonicalRoot = $canonicalRoot.Normalize([System.Text.NormalizationForm]::FormC)

    $pathBytes = [System.Text.Encoding]::UTF8.GetBytes($canonicalRoot)
    $account = $null
    try {
        $digest = [System.Security.Cryptography.SHA256]::HashData($pathBytes)
        try {
            $account = [Convert]::ToHexString($digest).ToLowerInvariant()
        }
        finally {
            [Array]::Clear($digest, 0, $digest.Length)
        }
    }
    finally {
        [Array]::Clear($pathBytes, 0, $pathBytes.Length)
    }
    return $account
}

function Clear-HHMemoryStreamBuffer {
    [CmdletBinding()]
    param([AllowNull()][System.IO.MemoryStream]$Stream)

    if ($null -eq $Stream) {
        return
    }

    $segment = [ArraySegment[byte]]::new([byte[]]::new(0))
    if ($Stream.TryGetBuffer([ref]$segment) -and $null -ne $segment.Array) {
        [Array]::Clear($segment.Array, $segment.Offset, $segment.Count)
    }
}

function Invoke-HHChildProcessTermination {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Diagnostics.Process]$Process)

    try {
        if (-not $Process.HasExited) {
            $Process.Kill($true)
        }
    }
    catch {
        Write-Debug 'The timed-out child process could not be killed on the first attempt.'
    }

    try {
        if ($Process.WaitForExit(2000)) {
            return
        }
    }
    catch {
        Write-Debug 'The timed-out child process termination state could not be read.'
    }

    throw (Get-HHAuditKeyStoreErrorRecord `
            -ErrorId 'AuditKeychainTerminationFailed' `
            -Message ('The timed-out macOS Keychain process could not be confirmed terminated. ' +
                'Remote activity is blocked.') `
            -Category ([System.Management.Automation.ErrorCategory]::OperationStopped))
}

function Invoke-HHMacOSSecurityCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$ArgumentList,
        [ValidateRange(1, 60)][int]$TimeoutSeconds = 15,
        [string]$ExecutablePath = '/usr/bin/security'
    )

    if (-not [System.IO.Path]::IsPathRooted($ExecutablePath)) {
        throw (Get-HHAuditKeyStoreErrorRecord `
                -ErrorId 'AuditKeychainUnavailable' `
                -Message 'The macOS Keychain command is unavailable. Remote activity is blocked.' `
                -Category ([System.Management.Automation.ErrorCategory]::ResourceUnavailable))
    }

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $ExecutablePath
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.RedirectStandardInput = $false
    foreach ($argument in $ArgumentList) {
        $startInfo.ArgumentList.Add($argument)
    }

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        try {
            $started = $process.Start()
        }
        catch {
            throw (Get-HHAuditKeyStoreErrorRecord `
                    -ErrorId 'AuditKeychainUnavailable' `
                    -Message 'The macOS Keychain command is unavailable. Remote activity is blocked.' `
                    -Category ([System.Management.Automation.ErrorCategory]::ResourceUnavailable))
        }
        if (-not $started) {
            throw (Get-HHAuditKeyStoreErrorRecord `
                    -ErrorId 'AuditKeychainUnavailable' `
                    -Message 'The macOS Keychain command is unavailable. Remote activity is blocked.' `
                    -Category ([System.Management.Automation.ErrorCategory]::ResourceUnavailable))
        }

        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            Invoke-HHChildProcessTermination -Process $process
            throw (Get-HHAuditKeyStoreErrorRecord `
                    -ErrorId 'AuditKeychainTimedOut' `
                    -Message 'The macOS Keychain command timed out. Remote activity is blocked.' `
                    -Category ([System.Management.Automation.ErrorCategory]::OperationTimeout))
        }

        try {
            $standardOutput = $stdoutTask.GetAwaiter().GetResult()
            $standardError = $stderrTask.GetAwaiter().GetResult()
        }
        catch {
            throw (Get-HHAuditKeyStoreErrorRecord `
                    -ErrorId 'AuditKeychainUnavailable' `
                    -Message 'The macOS Keychain command output could not be read. Remote activity is blocked.' `
                    -Category ([System.Management.Automation.ErrorCategory]::ReadError))
        }

        [pscustomobject]@{
            ExitCode = $process.ExitCode
            StandardOutput = $standardOutput
            StandardError = $standardError
        }
    }
    finally {
        $process.Dispose()
    }
}

function Invoke-HHAuditKeychainCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$ArgumentList,
        [scriptblock]$SecurityCommandInvoker
    )

    try {
        $result = if ($null -eq $SecurityCommandInvoker) {
            Invoke-HHMacOSSecurityCommand `
                -ArgumentList $ArgumentList `
                -TimeoutSeconds 15 `
                -ExecutablePath $script:HHMacOSSecurityPath
        }
        else {
            & $SecurityCommandInvoker `
                $script:HHMacOSSecurityPath `
                ([string[]]$ArgumentList) `
                15
        }
    }
    catch {
        $knownErrorId = ($_.FullyQualifiedErrorId -split ',', 2)[0]
        if ($knownErrorId -in @(
                'AuditKeychainTerminationFailed',
                'AuditKeychainTimedOut',
                'AuditKeychainUnavailable'
            )) {
            throw
        }
        throw (Get-HHAuditKeyStoreErrorRecord `
                -ErrorId 'AuditKeychainUnavailable' `
                -Message 'The macOS Keychain command failed. Remote activity is blocked.' `
                -Category ([System.Management.Automation.ErrorCategory]::ResourceUnavailable))
    }

    if ($null -eq $result -or
        $null -eq $result.PSObject.Properties['ExitCode'] -or
        $null -eq $result.PSObject.Properties['StandardOutput'] -or
        $null -eq $result.PSObject.Properties['StandardError']) {
        throw (Get-HHAuditKeyStoreErrorRecord `
                -ErrorId 'AuditKeychainUnavailable' `
                -Message 'The macOS Keychain command returned an invalid result. Remote activity is blocked.' `
                -Category ([System.Management.Automation.ErrorCategory]::InvalidResult))
    }

    try {
        $exitCode = [int]$result.ExitCode
    }
    catch {
        throw (Get-HHAuditKeyStoreErrorRecord `
                -ErrorId 'AuditKeychainUnavailable' `
                -Message 'The macOS Keychain command returned an invalid result. Remote activity is blocked.' `
                -Category ([System.Management.Automation.ErrorCategory]::InvalidResult))
    }

    [pscustomobject]@{
        ExitCode = $exitCode
        StandardOutput = [string]$result.StandardOutput
        StandardError = [string]$result.StandardError
    }
}

function Get-HHMacOSLoginKeychainPath {
    [CmdletBinding()]
    param([scriptblock]$SecurityCommandInvoker)

    $result = Invoke-HHAuditKeychainCommand `
        -ArgumentList @('login-keychain') `
        -SecurityCommandInvoker $SecurityCommandInvoker
    if ($result.ExitCode -ne 0) {
        throw (Get-HHAuditKeyStoreErrorRecord `
                -ErrorId 'AuditKeychainUnavailable' `
                -Message 'The macOS login Keychain is unavailable. Remote activity is blocked.' `
                -Category ([System.Management.Automation.ErrorCategory]::ResourceUnavailable))
    }

    $framedPath = $result.StandardOutput
    if ($framedPath.EndsWith("`r`n", [System.StringComparison]::Ordinal)) {
        $framedPath = $framedPath.Substring(0, $framedPath.Length - 2)
    }
    elseif ($framedPath.EndsWith("`n", [System.StringComparison]::Ordinal)) {
        $framedPath = $framedPath.Substring(0, $framedPath.Length - 1)
    }
    $pathMatch = [System.Text.RegularExpressions.Regex]::Match(
        $framedPath,
        '^[ \t]*"([^"\r\n]+)"[ \t]*$',
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
    if (-not $pathMatch.Success) {
        throw (Get-HHAuditKeyStoreErrorRecord `
                -ErrorId 'AuditKeychainUnavailable' `
                -Message 'The macOS login Keychain path is invalid. Remote activity is blocked.' `
                -Category ([System.Management.Automation.ErrorCategory]::InvalidData))
    }
    $keychainPath = $pathMatch.Groups[1].Value
    if (-not [System.IO.Path]::IsPathRooted($keychainPath)) {
        throw (Get-HHAuditKeyStoreErrorRecord `
                -ErrorId 'AuditKeychainUnavailable' `
                -Message 'The macOS login Keychain path is invalid. Remote activity is blocked.' `
                -Category ([System.Management.Automation.ErrorCategory]::InvalidData))
    }

    try {
        return [System.IO.Path]::GetFullPath($keychainPath)
    }
    catch {
        throw (Get-HHAuditKeyStoreErrorRecord `
                -ErrorId 'AuditKeychainUnavailable' `
                -Message 'The macOS login Keychain path is invalid. Remote activity is blocked.' `
                -Category ([System.Management.Automation.ErrorCategory]::InvalidData))
    }
}

function Invoke-HHMacOSKeychainWorker {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Create', 'Read', 'Delete', 'CreateAnchor', 'ReadAnchor', 'CompareUpdateAnchor')]
        [string]$Action,
        [Parameter(Mandatory)][string]$KeychainPath,
        [Parameter(Mandatory)][string]$Account,
        [AllowNull()][byte[]]$InputKey = $null,
        [string]$Service = $script:HHAuditKeychainService,
        [ValidateRange(1, 60)][int]$TimeoutSeconds = 15,
        [string]$WorkerPath = $script:HHMacOSKeychainWorkerPath,
        [string]$PowerShellPath = $script:HHPowerShellExecutablePath
    )

    if (-not [System.IO.Path]::IsPathRooted($WorkerPath) -or
        -not [System.IO.File]::Exists($WorkerPath) -or
        -not [System.IO.Path]::IsPathRooted($PowerShellPath) -or
        -not [System.IO.File]::Exists($PowerShellPath)) {
        throw (Get-HHAuditKeyStoreErrorRecord `
                -ErrorId 'AuditKeychainUnavailable' `
                -Message 'The native macOS Keychain worker is unavailable. Remote activity is blocked.' `
                -Category ([System.Management.Automation.ErrorCategory]::ResourceUnavailable))
    }
    $expectedInputLength = switch ($Action) {
        'Create' { 32 }
        'CreateAnchor' { $script:HHPersistenceAnchorArtifactLength }
        'CompareUpdateAnchor' {
            if ($null -eq $InputKey -or
                $InputKey.Length -notin @(
                    ($script:HHPersistenceAnchorV1ArtifactLength +
                        $script:HHPersistenceAnchorArtifactLength),
                    ($script:HHPersistenceAnchorArtifactLength * 2)
                )) {
                -1
            }
            else { $InputKey.Length }
        }
        default { 0 }
    }
    $anchorActions = @('CreateAnchor', 'ReadAnchor', 'CompareUpdateAnchor')
    $serviceMatchesAction = if ($Action -in $anchorActions) {
        $Service -ceq $script:HHPersistenceAnchorKeychainService
    }
    elseif ($Action -eq 'Delete') {
        $Service -in @(
            $script:HHAuditKeychainService,
            $script:HHPersistenceAnchorKeychainService
        )
    }
    else { $Service -ceq $script:HHAuditKeychainService }
    if ($expectedInputLength -lt 0 -or
        ($expectedInputLength -eq 0 -and $null -ne $InputKey) -or
        ($expectedInputLength -gt 0 -and
            ($null -eq $InputKey -or $InputKey.Length -ne $expectedInputLength)) -or
        [string]::IsNullOrWhiteSpace($Service) -or
        -not $serviceMatchesAction) {
        throw (Get-HHAuditKeyStoreErrorRecord `
                -ErrorId 'AuditKeychainUnavailable' `
                -Message 'The native macOS Keychain worker input is invalid. Remote activity is blocked.' `
                -Category ([System.Management.Automation.ErrorCategory]::InvalidData))
    }

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $PowerShellPath
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.RedirectStandardInput = $expectedInputLength -gt 0
    foreach ($argument in @(
            '-NoLogo',
            '-NoProfile',
            '-NonInteractive',
            '-File', $WorkerPath,
            '-Action', $Action,
            '-KeychainPath', $KeychainPath,
            '-Service', $Service,
            '-Account', $Account
        )) {
        $startInfo.ArgumentList.Add($argument)
    }

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $outputStream = [System.IO.MemoryStream]::new()
    $errorStream = [System.IO.MemoryStream]::new()
    $outputBytes = $null
    try {
        try {
            $started = $process.Start()
        }
        catch {
            throw (Get-HHAuditKeyStoreErrorRecord `
                    -ErrorId 'AuditKeychainUnavailable' `
                    -Message 'The native macOS Keychain worker could not start. Remote activity is blocked.' `
                    -Category ([System.Management.Automation.ErrorCategory]::ResourceUnavailable))
        }
        if (-not $started) {
            throw (Get-HHAuditKeyStoreErrorRecord `
                    -ErrorId 'AuditKeychainUnavailable' `
                    -Message 'The native macOS Keychain worker could not start. Remote activity is blocked.' `
                    -Category ([System.Management.Automation.ErrorCategory]::ResourceUnavailable))
        }

        $stdoutTask = $process.StandardOutput.BaseStream.CopyToAsync($outputStream)
        $stderrTask = $process.StandardError.BaseStream.CopyToAsync($errorStream)
        if ($expectedInputLength -gt 0) {
            try {
                $process.StandardInput.BaseStream.Write($InputKey, 0, $InputKey.Length)
                $process.StandardInput.BaseStream.Flush()
                $process.StandardInput.Close()
            }
            catch {
                if (-not $process.HasExited) {
                    Invoke-HHChildProcessTermination -Process $process
                }
                throw (Get-HHAuditKeyStoreErrorRecord `
                        -ErrorId 'AuditKeychainUnavailable' `
                        -Message 'The native macOS Keychain input channel failed. Remote activity is blocked.' `
                        -Category ([System.Management.Automation.ErrorCategory]::ResourceUnavailable))
            }
        }

        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            Invoke-HHChildProcessTermination -Process $process
            throw (Get-HHAuditKeyStoreErrorRecord `
                    -ErrorId 'AuditKeychainTimedOut' `
                    -Message 'The native macOS Keychain worker timed out. Remote activity is blocked.' `
                    -Category ([System.Management.Automation.ErrorCategory]::OperationTimeout))
        }
        try {
            $null = $stdoutTask.GetAwaiter().GetResult()
            $null = $stderrTask.GetAwaiter().GetResult()
            $outputBytes = $outputStream.ToArray()
        }
        catch {
            throw (Get-HHAuditKeyStoreErrorRecord `
                    -ErrorId 'AuditKeychainUnavailable' `
                    -Message 'The native macOS Keychain worker output could not be read. Remote activity is blocked.' `
                    -Category ([System.Management.Automation.ErrorCategory]::ReadError))
        }

        $maximumOutputLength = if ($Action -in @('ReadAnchor', 'CompareUpdateAnchor')) {
            $script:HHPersistenceAnchorArtifactLength
        }
        else { 32 }
        if ($outputBytes.Length -gt $maximumOutputLength) {
            throw (Get-HHAuditKeyStoreErrorRecord `
                    -ErrorId 'AuditKeychainUnavailable' `
                    -Message 'The native macOS Keychain worker output exceeded its bound. Remote activity is blocked.' `
                    -Category ([System.Management.Automation.ErrorCategory]::LimitsExceeded))
        }
        if ($process.ExitCode -ne 0 -and $outputBytes.Length -gt 0) {
            [Array]::Clear($outputBytes, 0, $outputBytes.Length)
            $outputBytes = [byte[]]::new(0)
        }
        [pscustomobject]@{
            ExitCode = $process.ExitCode
            OutputBytes = $outputBytes
        }
        $outputBytes = $null
    }
    finally {
        if ($null -ne $outputBytes) {
            [Array]::Clear($outputBytes, 0, $outputBytes.Length)
        }
        if ($startInfo.RedirectStandardInput) {
            try {
                $process.StandardInput.Close()
            }
            catch {
                Write-Debug 'The native macOS Keychain worker input stream was already closed.'
            }
        }
        Clear-HHMemoryStreamBuffer -Stream $outputStream
        Clear-HHMemoryStreamBuffer -Stream $errorStream
        $outputStream.Dispose()
        $errorStream.Dispose()
        $process.Dispose()
    }
}

function Invoke-HHAuditKeychainWorkerCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('Create', 'Read', 'Delete')][string]$Action,
        [Parameter(Mandatory)][string]$KeychainPath,
        [Parameter(Mandatory)][string]$Account,
        [AllowNull()][byte[]]$InputKey = $null,
        [scriptblock]$KeychainWorkerInvoker
    )

    try {
        $result = if ($null -eq $KeychainWorkerInvoker) {
            Invoke-HHMacOSKeychainWorker `
                -Action $Action `
                -KeychainPath $KeychainPath `
                -Account $Account `
                -InputKey $InputKey `
                -TimeoutSeconds 15
        }
        else {
            & $KeychainWorkerInvoker `
                $script:HHMacOSKeychainWorkerPath `
                $script:HHPowerShellExecutablePath `
                $Action `
                $KeychainPath `
                $script:HHAuditKeychainService `
                $Account `
                $InputKey `
                15
        }
    }
    catch {
        $knownErrorId = ($_.FullyQualifiedErrorId -split ',', 2)[0]
        if ($knownErrorId -in @(
                'AuditKeychainTerminationFailed',
                'AuditKeychainTimedOut',
                'AuditKeychainUnavailable'
            )) {
            throw
        }
        throw (Get-HHAuditKeyStoreErrorRecord `
                -ErrorId 'AuditKeychainUnavailable' `
                -Message 'The native macOS Keychain worker failed. Remote activity is blocked.' `
                -Category ([System.Management.Automation.ErrorCategory]::ResourceUnavailable))
    }

    if ($null -eq $result -or
        $null -eq $result.PSObject.Properties['ExitCode'] -or
        $null -eq $result.PSObject.Properties['OutputBytes'] -or
        $result.OutputBytes -isnot [byte[]]) {
        if ($null -ne $result -and $result.PSObject.Properties['OutputBytes'] -and
            $result.OutputBytes -is [byte[]]) {
            [Array]::Clear($result.OutputBytes, 0, $result.OutputBytes.Length)
        }
        throw (Get-HHAuditKeyStoreErrorRecord `
                -ErrorId 'AuditKeychainUnavailable' `
                -Message 'The native macOS Keychain worker returned an invalid result. Remote activity is blocked.' `
                -Category ([System.Management.Automation.ErrorCategory]::InvalidResult))
    }

    try {
        $exitCode = [int]$result.ExitCode
    }
    catch {
        [Array]::Clear($result.OutputBytes, 0, $result.OutputBytes.Length)
        throw (Get-HHAuditKeyStoreErrorRecord `
                -ErrorId 'AuditKeychainUnavailable' `
                -Message 'The native macOS Keychain worker returned an invalid result. Remote activity is blocked.' `
                -Category ([System.Management.Automation.ErrorCategory]::InvalidResult))
    }

    [pscustomobject]@{
        ExitCode = $exitCode
        OutputBytes = [byte[]]$result.OutputBytes
    }
}

function Read-HHMacOSAuditKeychainItem {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Account,
        [Parameter(Mandatory)][string]$KeychainPath,
        [scriptblock]$KeychainWorkerInvoker
    )

    $result = Invoke-HHAuditKeychainWorkerCommand `
        -Action 'Read' `
        -Account $Account `
        -KeychainPath $KeychainPath `
        -KeychainWorkerInvoker $KeychainWorkerInvoker
    if ($result.ExitCode -eq 10) {
        return [pscustomobject]@{
            Found = $false
            Key = $null
        }
    }
    if ($result.ExitCode -ne 0 -or $result.OutputBytes.Length -ne 32) {
        [Array]::Clear($result.OutputBytes, 0, $result.OutputBytes.Length)
        throw (Get-HHAuditKeyStoreErrorRecord `
                -ErrorId 'AuditKeychainUnavailable' `
                -Message 'The macOS Keychain audit key could not be read. Remote activity is blocked.' `
                -Category ([System.Management.Automation.ErrorCategory]::ResourceUnavailable))
    }

    [pscustomobject]@{
        Found = $true
        Key = [byte[]]$result.OutputBytes
    }
}

function Get-HHMacOSAuditMasterKey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DataRoot,
        [scriptblock]$SecurityCommandInvoker,
        [scriptblock]$KeychainWorkerInvoker
    )

    $account = Get-HHAuditKeychainAccount -DataRoot $DataRoot
    $keychainPath = Get-HHMacOSLoginKeychainPath -SecurityCommandInvoker $SecurityCommandInvoker
    $storedItem = Read-HHMacOSAuditKeychainItem `
        -Account $account `
        -KeychainPath $keychainPath `
        -KeychainWorkerInvoker $KeychainWorkerInvoker
    if ($storedItem.Found) {
        return ,([byte[]]$storedItem.Key)
    }

    $candidate = [byte[]]::new(32)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($candidate)
    $masterKey = $null
    $authoritativeKey = $null
    try {
        $addResult = Invoke-HHAuditKeychainWorkerCommand `
            -Action 'Create' `
            -Account $account `
            -KeychainPath $keychainPath `
            -InputKey $candidate `
            -KeychainWorkerInvoker $KeychainWorkerInvoker
        if ($addResult.ExitCode -notin @(0, 11) -or $addResult.OutputBytes.Length -ne 0) {
            [Array]::Clear($addResult.OutputBytes, 0, $addResult.OutputBytes.Length)
            throw (Get-HHAuditKeyStoreErrorRecord `
                    -ErrorId 'AuditKeychainWriteFailed' `
                    -Message 'The macOS Keychain audit key could not be created. Remote activity is blocked.' `
                    -Category ([System.Management.Automation.ErrorCategory]::WriteError))
        }

        $authoritativeItem = Read-HHMacOSAuditKeychainItem `
            -Account $account `
            -KeychainPath $keychainPath `
            -KeychainWorkerInvoker $KeychainWorkerInvoker
        if (-not $authoritativeItem.Found) {
            throw (Get-HHAuditKeyStoreErrorRecord `
                    -ErrorId 'AuditKeychainWriteFailed' `
                    -Message 'The macOS Keychain audit key could not be created. Remote activity is blocked.' `
                    -Category ([System.Management.Automation.ErrorCategory]::WriteError))
        }
        $authoritativeKey = [byte[]]$authoritativeItem.Key

        if ($addResult.ExitCode -eq 0 -and
            -not [System.Security.Cryptography.CryptographicOperations]::FixedTimeEquals(
                $candidate,
                $authoritativeKey
            )) {
            throw (Get-HHAuditKeyStoreErrorRecord `
                    -ErrorId 'AuditKeychainWriteFailed' `
                    -Message 'The macOS Keychain audit key verification failed. Remote activity is blocked.' `
                    -Category ([System.Management.Automation.ErrorCategory]::SecurityError))
        }

        $masterKey = $authoritativeKey
        $authoritativeKey = $null
    }
    finally {
        [Array]::Clear($candidate, 0, $candidate.Length)
        if ($null -ne $authoritativeKey) {
            [Array]::Clear($authoritativeKey, 0, $authoritativeKey.Length)
        }
    }
    return ,$masterKey
}

function Invoke-HHPersistenceAnchorKeychainWorkerCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('CreateAnchor', 'ReadAnchor', 'CompareUpdateAnchor')]
        [string]$Action,
        [Parameter(Mandatory)][string]$KeychainPath,
        [Parameter(Mandatory)][string]$Account,
        [AllowNull()][byte[]]$InputBytes,
        [scriptblock]$KeychainWorkerInvoker
    )

    try {
        $result = if ($null -eq $KeychainWorkerInvoker) {
            Invoke-HHMacOSKeychainWorker `
                -Action $Action `
                -KeychainPath $KeychainPath `
                -Account $Account `
                -InputKey $InputBytes `
                -Service $script:HHPersistenceAnchorKeychainService `
                -TimeoutSeconds 15
        }
        else {
            & $KeychainWorkerInvoker `
                $script:HHMacOSKeychainWorkerPath `
                $script:HHPowerShellExecutablePath `
                $Action `
                $KeychainPath `
                $script:HHPersistenceAnchorKeychainService `
                $Account `
                $InputBytes `
                15
        }
    }
    catch {
        $knownErrorId = ($_.FullyQualifiedErrorId -split ',', 2)[0]
        if ($knownErrorId -in @(
                'AuditKeychainTerminationFailed',
                'AuditKeychainTimedOut',
                'AuditKeychainUnavailable'
            )) {
            throw
        }
        throw (Get-HHAuditKeyStoreErrorRecord `
                -ErrorId 'AuditKeychainUnavailable' `
                -Message 'The macOS persistence-anchor worker failed. Remote activity is blocked.' `
                -Category ([System.Management.Automation.ErrorCategory]::ResourceUnavailable))
    }

    if ($null -eq $result -or
        $null -eq $result.PSObject.Properties['ExitCode'] -or
        $null -eq $result.PSObject.Properties['OutputBytes'] -or
        $result.OutputBytes -isnot [byte[]]) {
        if ($null -ne $result -and $result.PSObject.Properties['OutputBytes'] -and
            $result.OutputBytes -is [byte[]]) {
            [Array]::Clear($result.OutputBytes, 0, $result.OutputBytes.Length)
        }
        throw (Get-HHAuditKeyStoreErrorRecord `
                -ErrorId 'AuditKeychainUnavailable' `
                -Message 'The macOS persistence-anchor worker returned an invalid result. Remote activity is blocked.' `
                -Category ([System.Management.Automation.ErrorCategory]::InvalidResult))
    }
    try {
        $exitCode = [int]$result.ExitCode
    }
    catch {
        [Array]::Clear($result.OutputBytes, 0, $result.OutputBytes.Length)
        throw (Get-HHAuditKeyStoreErrorRecord `
                -ErrorId 'AuditKeychainUnavailable' `
                -Message 'The macOS persistence-anchor worker returned an invalid result. Remote activity is blocked.' `
                -Category ([System.Management.Automation.ErrorCategory]::InvalidResult))
    }
    [pscustomobject]@{
        ExitCode = $exitCode
        OutputBytes = $result.OutputBytes
    }
}

function Read-HHMacOSPersistenceAnchorItem {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DataRoot,
        [scriptblock]$SecurityCommandInvoker,
        [scriptblock]$KeychainWorkerInvoker
    )

    $account = Get-HHAuditKeychainAccount -DataRoot $DataRoot
    $keychainPath = Get-HHMacOSLoginKeychainPath `
        -SecurityCommandInvoker $SecurityCommandInvoker
    $result = Invoke-HHPersistenceAnchorKeychainWorkerCommand `
        -Action ReadAnchor `
        -Account $account `
        -KeychainPath $keychainPath `
        -KeychainWorkerInvoker $KeychainWorkerInvoker
    if ($result.ExitCode -eq 10) {
        return [pscustomobject]@{ Found = $false; Artifact = $null }
    }
    if ($result.ExitCode -ne 0 -or
        $result.OutputBytes.Length -notin @(
            $script:HHPersistenceAnchorV1ArtifactLength,
            $script:HHPersistenceAnchorArtifactLength
        )) {
        [Array]::Clear($result.OutputBytes, 0, $result.OutputBytes.Length)
        throw (Get-HHAuditKeyStoreErrorRecord `
                -ErrorId 'AuditIntegrityFailed' `
                -Message 'The macOS persistence anchor could not be read exactly. Remote activity is blocked.' `
                -Category ([System.Management.Automation.ErrorCategory]::SecurityError))
    }
    [pscustomobject]@{
        Found = $true
        Artifact = [byte[]]$result.OutputBytes
    }
}

function New-HHMacOSPersistenceAnchorItem {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Private persistence primitive invoked only after the public ShouldProcess boundary.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DataRoot,
        [Parameter(Mandatory)][byte[]]$Artifact,
        [scriptblock]$SecurityCommandInvoker,
        [scriptblock]$KeychainWorkerInvoker
    )

    if ($Artifact.Length -ne $script:HHPersistenceAnchorArtifactLength) {
        throw [System.ArgumentException]::new('Persistence anchor must be exactly 236 bytes.', 'Artifact')
    }
    $account = Get-HHAuditKeychainAccount -DataRoot $DataRoot
    $keychainPath = Get-HHMacOSLoginKeychainPath `
        -SecurityCommandInvoker $SecurityCommandInvoker
    $createResult = Invoke-HHPersistenceAnchorKeychainWorkerCommand `
        -Action CreateAnchor `
        -Account $account `
        -KeychainPath $keychainPath `
        -InputBytes $Artifact `
        -KeychainWorkerInvoker $KeychainWorkerInvoker
    if ($createResult.ExitCode -ne 0 -or $createResult.OutputBytes.Length -ne 0) {
        [Array]::Clear($createResult.OutputBytes, 0, $createResult.OutputBytes.Length)
        throw (Get-HHAuditKeyStoreErrorRecord `
                -ErrorId 'AuditIntegrityFailed' `
                -Message 'The macOS persistence anchor could not be created exclusively. Remote activity is blocked.' `
                -Category ([System.Management.Automation.ErrorCategory]::SecurityError))
    }

    $readResult = Invoke-HHPersistenceAnchorKeychainWorkerCommand `
        -Action ReadAnchor `
        -Account $account `
        -KeychainPath $keychainPath `
        -KeychainWorkerInvoker $KeychainWorkerInvoker
    $readback = $readResult.OutputBytes
    try {
        if ($readResult.ExitCode -ne 0 -or
            $readback.Length -ne $script:HHPersistenceAnchorArtifactLength -or
            -not [System.Security.Cryptography.CryptographicOperations]::FixedTimeEquals(
                $Artifact,
                $readback
            )) {
            throw (Get-HHAuditKeyStoreErrorRecord `
                    -ErrorId 'AuditIntegrityFailed' `
                    -Message 'The macOS persistence anchor failed exact readback. Remote activity is blocked.' `
                    -Category ([System.Management.Automation.ErrorCategory]::SecurityError))
        }
    }
    finally {
        [Array]::Clear($readback, 0, $readback.Length)
    }
}

function Update-HHMacOSPersistenceAnchorItem {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Private persistence primitive invoked only after the public ShouldProcess boundary.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DataRoot,
        [Parameter(Mandatory)][byte[]]$ExpectedArtifact,
        [Parameter(Mandatory)][byte[]]$NewArtifact,
        [scriptblock]$SecurityCommandInvoker,
        [scriptblock]$KeychainWorkerInvoker
    )

    if ($ExpectedArtifact.Length -notin @(
            $script:HHPersistenceAnchorV1ArtifactLength,
            $script:HHPersistenceAnchorArtifactLength
        ) -or
        $NewArtifact.Length -ne $script:HHPersistenceAnchorArtifactLength) {
        throw [System.ArgumentException]::new(
            'The expected persistence anchor must be 196 or 236 bytes and the replacement must be 236 bytes.',
            'ExpectedArtifact'
        )
    }
    $inputBytes = [byte[]]::new($ExpectedArtifact.Length + $NewArtifact.Length)
    try {
        [Array]::Copy($ExpectedArtifact, 0, $inputBytes, 0, $ExpectedArtifact.Length)
        [Array]::Copy(
            $NewArtifact,
            0,
            $inputBytes,
            $ExpectedArtifact.Length,
            $NewArtifact.Length
        )
        $account = Get-HHAuditKeychainAccount -DataRoot $DataRoot
        $keychainPath = Get-HHMacOSLoginKeychainPath `
            -SecurityCommandInvoker $SecurityCommandInvoker
        $result = Invoke-HHPersistenceAnchorKeychainWorkerCommand `
            -Action CompareUpdateAnchor `
            -Account $account `
            -KeychainPath $keychainPath `
            -InputBytes $inputBytes `
            -KeychainWorkerInvoker $KeychainWorkerInvoker
        $readback = $result.OutputBytes
        try {
            if ($result.ExitCode -eq 16) {
                throw (Get-HHAuditKeyStoreErrorRecord `
                        -ErrorId 'AuditIntegrityFailed' `
                        -Message 'The macOS persistence anchor changed concurrently or regressed.' `
                        -Category ([System.Management.Automation.ErrorCategory]::SecurityError))
            }
            if ($result.ExitCode -ne 0 -or
                $readback.Length -ne $script:HHPersistenceAnchorArtifactLength -or
                -not [System.Security.Cryptography.CryptographicOperations]::FixedTimeEquals(
                    $NewArtifact,
                    $readback
                )) {
                throw (Get-HHAuditKeyStoreErrorRecord `
                        -ErrorId 'AuditIntegrityFailed' `
                        -Message 'The macOS persistence anchor update failed exact readback.' `
                        -Category ([System.Management.Automation.ErrorCategory]::SecurityError))
            }
        }
        finally {
            [Array]::Clear($readback, 0, $readback.Length)
        }
    }
    finally {
        [Array]::Clear($inputBytes, 0, $inputBytes.Length)
    }
}
