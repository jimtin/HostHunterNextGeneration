Set-StrictMode -Version Latest

function Get-HHCmdletVerifierManifestCommand {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ModulePath)

    $manifestPath = [IO.Path]::GetFullPath($ModulePath)
    $manifest = Import-PowerShellDataFile -LiteralPath $manifestPath
    $declared = @($manifest.FunctionsToExport)
    $commands = @($declared | Sort-Object -Unique)
    if ($commands.Count -eq 0 -or $declared.Count -ne $commands.Count) {
        throw 'The packaged manifest command list is empty or ambiguous.'
    }
    foreach ($command in $commands) {
        if ([string]$command -cnotmatch '^[A-Za-z][A-Za-z0-9]*-[A-Za-z][A-Za-z0-9]*$') {
            throw "The packaged manifest contains invalid command name '$command'."
        }
    }
    $commands
}

function Invoke-HHCmdletVerifierPreflight {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ModulePath,
        [Parameter(Mandatory)][string[]]$OrderedJourney,
        [Parameter(Mandatory)][string]$DataRoot,
        [Parameter(Mandatory)][string]$RuntimeDirectory,
        [Parameter(Mandatory)][string]$ReceiptPath
    )

    $resolvedModulePath = [IO.Path]::GetFullPath($ModulePath)
    $resolvedDataRoot = [IO.Path]::GetFullPath($DataRoot)
    $resolvedRuntimeDirectory = [IO.Path]::GetFullPath($RuntimeDirectory)
    $resolvedReceiptPath = [IO.Path]::GetFullPath($ReceiptPath)
    $expectedCommands = @(Get-HHCmdletVerifierManifestCommand `
            -ModulePath $resolvedModulePath)
    if (@(Compare-Object -ReferenceObject $expectedCommands `
                -DifferenceObject @($OrderedJourney | Sort-Object -Unique)).Count -ne 0 -or
        @($OrderedJourney).Count -ne $expectedCommands.Count) {
        throw 'The ordered journey does not match the packaged manifest command surface.'
    }

    foreach ($directory in @($resolvedDataRoot, $resolvedRuntimeDirectory)) {
        if (-not [IO.Directory]::Exists($directory) -or
            $null -ne ([IO.DirectoryInfo]::new($directory)).LinkTarget) {
            throw "Verifier preflight requires mounted non-symlink directory '$directory'."
        }
    }

    $receiptDirectory = [IO.Path]::GetDirectoryName($resolvedReceiptPath)
    [IO.Directory]::CreateDirectory($receiptDirectory) | Out-Null
    $writeProbe = Join-Path $receiptDirectory ('.write-probe-' + [Guid]::NewGuid().ToString('N'))
    $probeStream = $null
    try {
        $probeStream = [IO.File]::Open(
            $writeProbe,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None
        )
        $probeStream.WriteByte(1)
        $probeStream.Flush($true)
    }
    catch {
        throw "Verifier receipt directory is not writable: $($_.Exception.Message)"
    }
    finally {
        if ($null -ne $probeStream) { $probeStream.Dispose() }
        if ([IO.File]::Exists($writeProbe)) { [IO.File]::Delete($writeProbe) }
    }

    $usernamePath = Join-Path $resolvedRuntimeDirectory 'username'
    $fingerprintPath = Join-Path $resolvedRuntimeDirectory 'hostkey.sha256'
    $passwordPath = Join-Path $resolvedRuntimeDirectory 'password'
    $userName = [IO.File]::ReadAllText($usernamePath).Trim()
    $fingerprint = [IO.File]::ReadAllText($fingerprintPath).Trim()
    if ($userName -cnotmatch '^[A-Za-z_][A-Za-z0-9_.-]{0,63}$') {
        throw 'The SSH fixture username is invalid.'
    }
    if ($fingerprint -cnotmatch '^SHA256:[A-Za-z0-9+/]{43}$') {
        throw 'The SSH fixture fingerprint is invalid.'
    }
    $passwordStream = $null
    try {
        $passwordStream = [IO.File]::Open(
            $passwordPath,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read
        )
        if ($passwordStream.Length -le 0) { throw 'The SSH fixture password is empty.' }
    }
    catch {
        throw "The SSH fixture credential is not readable: $($_.Exception.Message)"
    }
    finally {
        if ($null -ne $passwordStream) { $passwordStream.Dispose() }
    }

    $moduleRoot = Split-Path -Parent $resolvedModulePath
    $migrationRoot = Join-Path $moduleRoot 'Private/Migrations'
    $migrationFiles = @(Get-ChildItem -LiteralPath $migrationRoot -File -Filter '*.sql' |
            Sort-Object Name)
    if ($migrationFiles.Count -eq 0) {
        throw 'The packaged module contains no SQLite migrations.'
    }
    for ($index = 0; $index -lt $migrationFiles.Count; $index++) {
        $expectedPrefix = '{0:D4}_' -f ($index + 1)
        if (-not $migrationFiles[$index].Name.StartsWith(
                $expectedPrefix,
                [StringComparison]::Ordinal
            )) {
            throw 'The packaged SQLite migration sequence is not contiguous.'
        }
    }

    Import-Module $resolvedModulePath -Force -ErrorAction Stop
    $actualCommands = @(Get-Command -Module HostHunterNextGeneration -CommandType Function |
            Sort-Object Name | ForEach-Object Name)
    if (@(Compare-Object -ReferenceObject $expectedCommands `
                -DifferenceObject $actualCommands).Count -ne 0) {
        throw 'Imported framework commands differ from the packaged manifest.'
    }
    $unexpectedState = @(Get-ChildItem -LiteralPath $resolvedDataRoot -Force |
            Where-Object Name -cne 'keys')
    $databasePath = Join-Path $resolvedDataRoot 'hosthunter.db'
    if ([IO.File]::Exists($databasePath) -or $unexpectedState.Count -ne 0) {
        throw 'The verifier requires a fresh data volume; the separate SSH-key mount is allowed.'
    }

    [pscustomobject][ordered]@{
        ModulePath = $resolvedModulePath
        ExpectedCommands = $expectedCommands
        DataRoot = $resolvedDataRoot
        DatabasePath = $databasePath
        RuntimeDirectory = $resolvedRuntimeDirectory
        UserName = $userName
        Fingerprint = $fingerprint
        PasswordPath = $passwordPath
        MigrationCount = $migrationFiles.Count
        ReceiptPath = $resolvedReceiptPath
    }
}
