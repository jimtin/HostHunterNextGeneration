Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:HHClientProtocolVersion = 1
$script:HHClientGeneratedCommands = @()
$script:HHClientLocalCommands = @('Start-HHVisualization', 'Stop-HHVisualization')
$script:HHClientGeneratedAliases = @()
$script:HHClientMetadata = $null
$script:HHClientRepoRoot = $null
$script:HHClientSourceFingerprint = $null
$script:HHClientControllerId = $null
$script:HHClientVisualizerRepoRoot = $null
$script:HHClientVisualizerUrl = 'http://127.0.0.1:4310'
$script:HHClientMaximumMetadataBytes = 8MB
$script:HHClientMaximumRequestBytes = 16MB
$script:HHClientMaximumFrameBytes = 32MB

function Test-HHClientAnimationSupported {
    if ($env:HH_CLIENT_NO_ANIMATION -ceq '1' -or
        -not [string]::IsNullOrWhiteSpace($env:CI) -or
        [Console]::IsInputRedirected -or [Console]::IsOutputRedirected -or
        $Host.Name -cne 'ConsoleHost') { return $false }
    try { return [bool]$Host.UI.SupportsVirtualTerminal }
    catch { return $false }
}

function Show-HHClientStartupAnimation {
    param([Parameter(Mandatory)][ValidateRange(1, 999)][int]$CommandCount)

    if (-not (Test-HHClientAnimationSupported)) { return }
    $esc = [char]27
    $radar = @('◴', '◷', '◶', '◵')
    $messages = @(
        'Scanning the horizon',
        'Waking the framework',
        'Linking the command deck',
        'Calibrating HostHunter'
    )
    [Console]::Write("${esc}[?25l")
    try {
        for ($frame = 0; $frame -lt 14; $frame++) {
            $pulse = $radar[$frame % $radar.Count]
            $message = $messages[[Math]::Min(
                    [int][Math]::Floor($frame / 4), $messages.Count - 1
                )]
            $dots = '.' * (($frame % 3) + 1)
            $line = "  $pulse  $message$dots"
            [Console]::Write("`r${esc}[2K${esc}[38;5;82m$line${esc}[0m")
            Start-Sleep -Milliseconds 240
        }
        [Console]::Write("`r${esc}[2K")
        Write-Host '  ╭─ HostHunter ─────────────────────────╮' -ForegroundColor Green
        Write-Host '  │  ✓ Framework online                 │' -ForegroundColor Green
        Write-Host ("  │  ✓ {0,-3} commands ready               │" -f $CommandCount) `
            -ForegroundColor Green
        Write-Host '  │  Welcome back, hunter.              │' -ForegroundColor Green
        Write-Host '  ╰─────────────────────────────────────╯' -ForegroundColor Green
    }
    finally { [Console]::Write("${esc}[?25h") }
}

function Get-HHClientConfigurationPath {
    $configurationRoot = if (-not [string]::IsNullOrWhiteSpace($env:XDG_CONFIG_HOME)) {
        $env:XDG_CONFIG_HOME
    }
    else { Join-Path $HOME '.config' }
    Join-Path $configurationRoot 'hosthunter/client.json'
}

function Get-HHClientRepositoryRoot {
    (Get-HHClientConfiguration).RepoRoot
}

function Get-HHClientConfiguration {
    $configuration = $null
    if (-not [string]::IsNullOrWhiteSpace($env:HH_CLIENT_REPO_ROOT)) {
        $repoRoot = (Resolve-Path -LiteralPath $env:HH_CLIENT_REPO_ROOT).Path
    }
    else {
        $configurationPath = Get-HHClientConfigurationPath
        if (-not [IO.File]::Exists($configurationPath)) {
            throw "HostHunter.Client is not configured. Re-run Install-HHClient.ps1."
        }
        $configuration = Get-Content -LiteralPath $configurationPath -Raw |
            ConvertFrom-Json -AsHashtable
        if ([string]$configuration.schema -cne 'HostHunter.ClientConfiguration.v2') {
            throw 'HostHunter.Client configuration version is unsupported. Re-run Install-HHClient.ps1.'
        }
        if ([string]::IsNullOrWhiteSpace([string]$configuration.repoRoot)) {
            throw 'HostHunter.Client configuration does not contain a repository root.'
        }
        try { $repoRoot = (Resolve-Path -LiteralPath ([string]$configuration.repoRoot)).Path }
        catch { throw 'The configured HostHunter repository moved. Re-run Install-HHClient.ps1.' }
    }
    $visualizerPath = if (-not [string]::IsNullOrWhiteSpace($env:HH_VISUALIZER_REPO_ROOT)) {
        $env:HH_VISUALIZER_REPO_ROOT
    }
    elseif ($null -ne $configuration -and
        -not [string]::IsNullOrWhiteSpace([string]$configuration.visualizerRepoRoot)) {
        [string]$configuration.visualizerRepoRoot
    }
    else { $null }
    $visualizerRoot = $null
    if ($null -ne $visualizerPath) {
        try { $visualizerRoot = (Resolve-Path -LiteralPath $visualizerPath).Path }
        catch { throw 'The configured HostHunter visualizer repository moved. Re-run Install-HHClient.ps1.' }
    }
    $url = if ($null -ne $configuration -and
        -not [string]::IsNullOrWhiteSpace([string]$configuration.visualizerUrl)) {
        [string]$configuration.visualizerUrl
    } else { 'http://127.0.0.1:4310' }
    $parsedUrl = $null
    if (-not [Uri]::TryCreate($url,[UriKind]::Absolute,[ref]$parsedUrl) -or
        $parsedUrl.Scheme -cne 'http' -or $parsedUrl.Host -cne '127.0.0.1' -or
        -not [string]::IsNullOrWhiteSpace($parsedUrl.UserInfo) -or
        $parsedUrl.AbsolutePath -cne '/' -or -not [string]::IsNullOrWhiteSpace($parsedUrl.Query) -or
        -not [string]::IsNullOrWhiteSpace($parsedUrl.Fragment)) {
        throw 'The configured visualizer URL must be an uncredentialed loopback HTTP origin.'
    }
    $url = $parsedUrl.GetLeftPart([UriPartial]::Authority)
    [pscustomobject]@{ RepoRoot=$repoRoot; VisualizerRepoRoot=$visualizerRoot; VisualizerUrl=$url }
}

function Use-HHClientLock {
    param([Parameter(Mandatory)][scriptblock]$Action)

    $stateRoot = if (-not [string]::IsNullOrWhiteSpace($env:XDG_STATE_HOME)) {
        $env:XDG_STATE_HOME
    }
    else { Join-Path $HOME '.local/state' }
    $lockRoot = Join-Path $stateRoot 'hosthunter'
    [IO.Directory]::CreateDirectory($lockRoot) | Out-Null
    $lockPath = Join-Path $lockRoot 'client.lock'
    $stream = $null
    try {
        $stream = [IO.FileStream]::new(
            $lockPath,
            [IO.FileMode]::OpenOrCreate,
            [IO.FileAccess]::ReadWrite,
            [IO.FileShare]::None
        )
    }
    catch {
        throw 'Another HostHunter client session is starting or invoking a command. No retry was attempted.'
    }
    try { & $Action }
    finally { $stream.Dispose() }
}

function Invoke-HHClientDockerCapture {
    param([Parameter(Mandatory)][string[]]$Arguments)

    $output = @(& docker @Arguments 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "Docker command failed: $([string]::Join([Environment]::NewLine, $output))"
    }
    $output
}

function Get-HHClientRuntimeProject {
    $project = if ([string]::IsNullOrWhiteSpace($env:HH_RUNTIME_PROJECT)) {
        'hosthunter-next-generation-runtime'
    }
    else { $env:HH_RUNTIME_PROJECT }
    if ($project -cnotmatch '^[a-z0-9][a-z0-9_-]{2,47}$') {
        throw 'HH_RUNTIME_PROJECT contains an invalid Docker Compose project name.'
    }
    $project
}

function Get-HHClientControllerId {
    $runtimeProject = Get-HHClientRuntimeProject
    $ids = @(Invoke-HHClientDockerCapture -Arguments @(
            'ps', '--filter',
            "label=com.docker.compose.project=$runtimeProject",
            '--filter', 'label=com.docker.compose.service=controller',
            '--format', '{{.ID}}'
        ) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    if ($ids.Count -gt 1) { throw 'More than one HostHunter runtime controller is running.' }
    if ($ids.Count -eq 1) { return [string]$ids[0] }
    $null
}

function Get-HHClientSourceFingerprint {
    param([Parameter(Mandatory)][string]$RepoRoot)

    $fingerprintScript = Join-Path $RepoRoot 'scripts/client/Get-HHSourceFingerprint.ps1'
    if (-not [IO.File]::Exists($fingerprintScript)) {
        throw 'The HostHunter source fingerprint helper is missing.'
    }
    [string](& $fingerprintScript -RepoRoot $RepoRoot)
}

function Test-HHClientDockerReady {
    & docker info *> $null
    $LASTEXITCODE -eq 0
}

function Open-HHClientDockerDesktop {
    & /usr/bin/open -gj -a Docker 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'Docker Desktop could not be started.' }
}

function Connect-HHClientDocker {
    param(
        [ValidateRange(1, 300)][int]$MaximumWaitSeconds = 120,
        [bool]$PlatformIsMacOS = $IsMacOS
    )

    if (Test-HHClientDockerReady) { return }
    if (-not $PlatformIsMacOS) {
        throw 'Docker is installed but its engine is not running.'
    }
    Open-HHClientDockerDesktop
    $deadline = [DateTime]::UtcNow.AddSeconds($MaximumWaitSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 500
        if (Test-HHClientDockerReady) { return }
    }
    throw "Docker Desktop did not become ready within $MaximumWaitSeconds seconds."
}

function Connect-HHClientRuntime {
    param(
        [Parameter(Mandatory)][string]$RepoRoot,
        [Parameter(Mandatory)][string]$SourceFingerprint,
        [ValidateSet('Preserve','Enable','Disable')][string]$VisualizationMode = 'Preserve',
        [AllowNull()][string]$VisualizerRepoRoot
    )

    if ($null -eq (Get-Command docker -ErrorAction SilentlyContinue)) {
        throw 'Docker is required to use HostHunter.Client.'
    }
    Connect-HHClientDocker

    $controllerId = Get-HHClientControllerId
    if ($VisualizationMode -ceq 'Enable' -and
        [string]::IsNullOrWhiteSpace($VisualizerRepoRoot)) {
        throw 'A visualizer repository is required when visualization is enabled.'
    }
    if ($null -ne $controllerId) {
        $actual = [string](Invoke-HHClientDockerCapture -Arguments @(
                'inspect', '--format',
                '{{ index .Config.Labels "com.hosthunter.source-fingerprint" }}',
                $controllerId
            ) | Select-Object -First 1)
        $actualVisualizer = [string](Invoke-HHClientDockerCapture -Arguments @(
                'inspect', '--format',
                '{{ index .Config.Labels "com.hosthunter.visualizer-enabled" }}',
                $controllerId
            ) | Select-Object -First 1)
        $modeMatches = $VisualizationMode -ceq 'Preserve' -or
            ($VisualizationMode -ceq 'Enable' -and $actualVisualizer -ceq 'true') -or
            ($VisualizationMode -ceq 'Disable' -and $actualVisualizer -cne 'true')
        if ($actual -ceq $SourceFingerprint -and $modeMatches) {
            return $controllerId
        }
    }

    $visualizerEnabled = $VisualizationMode -ceq 'Enable'

    $startScript = Join-Path $RepoRoot 'scripts/runtime/hosthunter.sh'
    if (-not [IO.File]::Exists($startScript)) { throw 'HostHunter runtime start script is missing.' }
    $previousFingerprint = $env:HH_SOURCE_FINGERPRINT
    $previousVisualizerEnabled = $env:HH_VISUALIZER_ENABLED
    $previousVisualizerToken = $env:HH_VISUALIZER_TOKEN_SOURCE
    try {
        $env:HH_SOURCE_FINGERPRINT = $SourceFingerprint
        $env:HH_VISUALIZER_ENABLED = if ($visualizerEnabled) { 'true' } else { 'false' }
        $env:HH_VISUALIZER_TOKEN_SOURCE = if ($visualizerEnabled) {
            Join-Path $VisualizerRepoRoot '.secrets/producer_token'
        } else { $null }
        $startOutput = @(& /usr/bin/env bash $startScript start 2>&1)
        if ($LASTEXITCODE -ne 0) {
            throw "HostHunter runtime failed to start: $([string]::Join([Environment]::NewLine, $startOutput))"
        }
        foreach ($line in $startOutput) {
            Write-Information $line -Tags HostHunterRuntime -InformationAction Continue
        }
    }
    finally {
        $env:HH_SOURCE_FINGERPRINT = $previousFingerprint
        $env:HH_VISUALIZER_ENABLED = $previousVisualizerEnabled
        $env:HH_VISUALIZER_TOKEN_SOURCE = $previousVisualizerToken
    }

    $controllerId = Get-HHClientControllerId
    if ($null -eq $controllerId) { throw 'HostHunter runtime started without a controller container.' }
    $actual = [string](Invoke-HHClientDockerCapture -Arguments @(
            'inspect', '--format',
            '{{ index .Config.Labels "com.hosthunter.source-fingerprint" }}',
            $controllerId
        ) | Select-Object -First 1)
    if ($actual -cne $SourceFingerprint) {
        throw 'HostHunter controller source fingerprint does not match the checked-out source.'
    }
    $controllerId
}

function Get-HHClientDefinition {
    param([Parameter(Mandatory)][string]$ControllerId)

    $json = [string]::Join('', @(
            Invoke-HHClientDockerCapture -Arguments @(
                'exec', $ControllerId, '/usr/local/bin/hosthunter-controller', 'describe'
            )
        ))
    if ([Text.Encoding]::UTF8.GetByteCount($json) -gt $script:HHClientMaximumMetadataBytes) {
        throw 'HostHunter controller metadata exceeds the protocol size limit.'
    }
    $metadata = $json | ConvertFrom-Json -Depth 20
    if ($metadata.schema -cne 'HostHunter.ClientCommandMetadata.v1' -or
        [int]$metadata.protocolVersion -ne $script:HHClientProtocolVersion) {
        throw 'HostHunter client/controller protocol versions are incompatible.'
    }
    if ([string]$metadata.sourceFingerprint -cne $script:HHClientSourceFingerprint) {
        throw 'HostHunter command metadata came from a different source fingerprint.'
    }
    if (@($metadata.commands).Count -eq 0) {
        throw 'HostHunter controller returned no exported commands.'
    }
    $names = @($metadata.commands | ForEach-Object { [string]$_.name })
    if (@($names | Sort-Object -Unique).Count -ne $names.Count) {
        throw 'HostHunter controller returned duplicate command metadata.'
    }
    $aliasNames = @($metadata.aliases | ForEach-Object { [string]$_.name })
    if (@($aliasNames | Sort-Object -Unique).Count -ne $aliasNames.Count) {
        throw 'HostHunter controller returned duplicate alias metadata.'
    }
    foreach ($alias in @($metadata.aliases)) {
        if ([string]$alias.name -cnotmatch '^[A-Za-z][A-Za-z0-9]*-[A-Za-z][A-Za-z0-9]*$' -or
            [string]$alias.target -cnotin $names) {
            throw 'HostHunter controller returned invalid alias metadata.'
        }
    }
    $metadata
}

function ConvertFrom-HHClientPayload {
    param([Parameter(Mandatory)][string]$Payload)

    $xml = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Payload))
    [Management.Automation.PSSerializer]::Deserialize($xml)
}

function Invoke-HHClientCommand {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter',
        '',
        Justification = 'Parameters are consumed inside the lock-owned invocation scriptblock.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$CommandName,
        [Parameter(Mandatory)][Collections.IDictionary]$Parameters,
        [Parameter(Mandatory)][bool]$HasPipelineInput,
        [AllowEmptyCollection()][object[]]$PipelineInput = @()
    )

    Use-HHClientLock {
        $controllerId = Connect-HHClientRuntime -RepoRoot $script:HHClientRepoRoot `
            -SourceFingerprint $script:HHClientSourceFingerprint `
            -VisualizationMode Preserve
        $request = [pscustomobject][ordered]@{
            CommandName = $CommandName
            Parameters = $Parameters
            HasPipelineInput = $HasPipelineInput
            PipelineInput = $PipelineInput
        }
        $requestXml = [Management.Automation.PSSerializer]::Serialize($request, 20)
        $requestFrame = [ordered]@{
            schema = 'HostHunter.ClientInvocation.v1'
            payload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($requestXml))
        } | ConvertTo-Json -Compress
        if ([Text.Encoding]::UTF8.GetByteCount($requestFrame) -gt $script:HHClientMaximumRequestBytes) {
            throw 'HostHunter command input exceeds the protocol size limit.'
        }

        $startInfo = [Diagnostics.ProcessStartInfo]::new()
        $startInfo.FileName = 'docker'
        foreach ($argument in @(
                'exec', '-i', $controllerId, '/usr/local/bin/hosthunter-controller', 'invoke-native'
            )) { [void]$startInfo.ArgumentList.Add($argument) }
        $startInfo.UseShellExecute = $false
        $startInfo.RedirectStandardInput = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        $process = [Diagnostics.Process]::new()
        $process.StartInfo = $startInfo
        if (-not $process.Start()) { throw 'Unable to start the HostHunter Docker bridge.' }
        try {
            $stderrTask = $process.StandardError.ReadToEndAsync()
            $process.StandardInput.WriteLine($requestFrame)
            $process.StandardInput.Flush()
            $terminal = $null
            $credentialRequested = $false
            $confirmationRequestCount = 0
            while ($null -ne ($line = $process.StandardOutput.ReadLine())) {
                if ([string]::IsNullOrWhiteSpace($line)) { continue }
                if ([Text.Encoding]::UTF8.GetByteCount($line) -gt $script:HHClientMaximumFrameBytes) {
                    throw 'HostHunter controller emitted an oversized protocol frame.'
                }
                try { $frame = $line | ConvertFrom-Json -Depth 10 }
                catch { throw "HostHunter controller emitted an invalid protocol frame: $line" }
                if ($null -ne $terminal) {
                    throw 'HostHunter controller emitted data after its terminal frame.'
                }
                switch ([string]$frame.type) {
                    confirmation_request {
                        $confirmationRequestCount++
                        if ($confirmationRequestCount -gt 8) {
                            throw 'HostHunter controller requested too many confirmations.'
                        }
                        $prompt = [Text.Encoding]::UTF8.GetString(
                            [Convert]::FromBase64String([string]$frame.prompt)
                        )
                        if ($prompt.Length -gt 4096) {
                            throw 'HostHunter controller emitted an oversized confirmation prompt.'
                        }
                        $answer = Read-Host -Prompt $prompt
                        $defaultYes = $prompt -match '(?i)\[Y/n\]\s*$'
                        $accepted = ([string]::IsNullOrWhiteSpace([string]$answer) -and
                                $defaultYes) -or [string]$answer -match '^(?i:y|yes)$'
                        $confirmationResponse = if ($accepted) {
                            'confirmation yes'
                        }
                        else { 'confirmation no' }
                        $process.StandardInput.WriteLine($confirmationResponse)
                        $process.StandardInput.Flush()
                    }
                    credential_request {
                        if ($credentialRequested) {
                            throw 'HostHunter controller requested credentials more than once.'
                        }
                        $credentialRequested = $true
                        $prompt = [Text.Encoding]::UTF8.GetString(
                            [Convert]::FromBase64String([string]$frame.prompt)
                        )
                        if ($prompt.Length -gt 4096) {
                            throw 'HostHunter controller emitted an oversized credential prompt.'
                        }
                        $secure = Read-Host -Prompt $prompt -AsSecureString
                        if ($null -eq $secure) { throw 'Credential entry was cancelled.' }
                        $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
                        $passwordBytes = $null
                        $plain = $null
                        try {
                            $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
                            $passwordBytes = [Text.Encoding]::UTF8.GetBytes($plain)
                            $response = 'credential ' + [Convert]::ToBase64String($passwordBytes)
                            $process.StandardInput.WriteLine($response)
                            $process.StandardInput.Flush()
                        }
                        finally {
                            if ($null -ne $passwordBytes) {
                                [Array]::Clear($passwordBytes, 0, $passwordBytes.Length)
                            }
                            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
                            $plain = $null
                        }
                    }
                    output {
                        $PSCmdlet.WriteObject((ConvertFrom-HHClientPayload $frame.payload), $false)
                    }
                    error {
                        $remote = ConvertFrom-HHClientPayload $frame.payload
                        $message = if ($null -ne $remote.Exception) {
                            [string]$remote.Exception.Message
                        } else { [string]$remote }
                        $PSCmdlet.WriteError([Management.Automation.ErrorRecord]::new(
                                [Management.Automation.RemoteException]::new($message),
                                'HostHunterRemoteError',
                                [Management.Automation.ErrorCategory]::NotSpecified,
                                $CommandName
                            ))
                    }
                    warning { $PSCmdlet.WriteWarning([string](ConvertFrom-HHClientPayload $frame.payload)) }
                    verbose { $PSCmdlet.WriteVerbose([string](ConvertFrom-HHClientPayload $frame.payload)) }
                    debug { $PSCmdlet.WriteDebug([string](ConvertFrom-HHClientPayload $frame.payload)) }
                    information {
                        $record = ConvertFrom-HHClientPayload $frame.payload
                        $PSCmdlet.WriteInformation($record.MessageData, [string[]]$record.Tags)
                    }
                    progress {
                        $record = ConvertFrom-HHClientPayload $frame.payload
                        $PSCmdlet.WriteProgress($record)
                    }
                    terminal {
                        if ([string]$frame.status -cnotin @('succeeded', 'failed')) {
                            throw 'HostHunter controller emitted an invalid terminal status.'
                        }
                        $terminal = $frame
                    }
                    default {
                        throw @(
                            "This HostHunter.Client version does not support controller frame"
                            "'$($frame.type)'. Reload PowerShell to load the current client from"
                            'the HostHunter repository.'
                        ) -join ' '
                    }
                }
            }
            $process.StandardInput.Close()
            $process.WaitForExit()
            $stderr = $stderrTask.GetAwaiter().GetResult()
            if ($null -eq $terminal) {
                throw "HostHunter controller ended without a terminal frame. $stderr"
            }
            if ($terminal.status -cne 'succeeded' -or $process.ExitCode -ne 0) {
                throw "HostHunter command '$CommandName' failed: $($terminal.message)"
            }
        }
        finally {
            if (-not $process.HasExited) { $process.Kill($true) }
            $process.Dispose()
        }
    }
}

function Sync-HHClientCommand {
    param([Parameter(Mandatory)][object]$Metadata)

    $exported = [Collections.Generic.List[string]]::new()
    $aliases = if ($null -eq $Metadata.PSObject.Properties['aliases']) {
        @()
    } else { @($Metadata.aliases) }
    foreach ($command in @($Metadata.commands)) {
        $name = [string]$command.name
        if ($name -cnotmatch '^[A-Za-z][A-Za-z0-9]*-[A-Za-z][A-Za-z0-9]*$') {
            throw "HostHunter controller returned invalid command name '$name'."
        }
        $declaration = [string]$command.declaration
        if ([string]::IsNullOrWhiteSpace($declaration) -or $declaration.Length -gt 262144) {
            throw "HostHunter controller returned invalid declaration metadata for '$name'."
        }
        $declarationTokens = $null
        $declarationErrors = $null
        $declarationAst = [Management.Automation.Language.Parser]::ParseInput(
            $declaration, [ref]$declarationTokens, [ref]$declarationErrors
        )
        if ($declarationErrors.Count -gt 0 -or $null -eq $declarationAst.ParamBlock -or
            $declarationAst.EndBlock.Statements.Count -ne 0 -or
            $null -ne $declarationAst.BeginBlock -or $null -ne $declarationAst.ProcessBlock) {
            throw "HostHunter controller returned executable declaration metadata for '$name'."
        }
        $parameterNames = @($declarationAst.ParamBlock.Parameters | ForEach-Object {
                $_.Name.VariablePath.UserPath
            })
        foreach ($pipelineParameter in @($command.pipelineParameters)) {
            if ([string]$pipelineParameter -cnotin $parameterNames) {
                throw "HostHunter controller returned an unknown pipeline parameter for '$name'."
            }
        }
        $pipelineItems = @($command.pipelineParameters) |
            ForEach-Object { "'$($_.Replace("'", "''"))'" }
        $pipelineLiteral = '@(' + ($pipelineItems -join ', ') + ')'
        $source = @"
function script:$name {
$($command.declaration)
begin {
    `$__hhPipelineInput = [Collections.Generic.List[object]]::new()
    `$__hhExpectingInput = `$MyInvocation.ExpectingInput
}
process {
    if (`$__hhExpectingInput) { `$__hhPipelineInput.Add(`$_) }
}
end {
    `$__hhParameters = @{}
    foreach (`$__hhEntry in `$PSBoundParameters.GetEnumerator()) {
        `$__hhParameters[`$__hhEntry.Key] = `$__hhEntry.Value
    }
    if (`$__hhExpectingInput) {
        foreach (`$__hhPipelineName in $pipelineLiteral) {
            [void]`$__hhParameters.Remove(`$__hhPipelineName)
        }
    }
    Invoke-HHClientCommand -CommandName '$name' -Parameters `$__hhParameters -HasPipelineInput:`$__hhExpectingInput -PipelineInput `$__hhPipelineInput.ToArray()
}
}
"@
        $tokens = $null
        $errors = $null
        [void][Management.Automation.Language.Parser]::ParseInput(
            $source, [ref]$tokens, [ref]$errors
        )
        if ($errors.Count -gt 0) {
            throw "Generated HostHunter client proxy '$name' did not parse."
        }
        . ([scriptblock]::Create($source))
        $exported.Add($name)
    }
    $script:HHClientGeneratedCommands = $exported.ToArray()
    foreach ($oldAlias in $script:HHClientGeneratedAliases) {
        Remove-Item -LiteralPath "Alias:$oldAlias" -Force -ErrorAction SilentlyContinue
    }
    $generatedAliases = [Collections.Generic.List[string]]::new()
    foreach ($alias in $aliases) {
        Set-Alias -Name ([string]$alias.name) -Value ([string]$alias.target) -Scope Script
        $generatedAliases.Add([string]$alias.name)
    }
    $script:HHClientGeneratedAliases = $generatedAliases.ToArray()
    Export-ModuleMember -Function @($script:HHClientGeneratedCommands + $script:HHClientLocalCommands) `
        -Alias $script:HHClientGeneratedAliases
}

$visualizationLifecyclePath = Join-Path $PSScriptRoot 'Private/VisualizationLifecycle.ps1'
if (-not [IO.File]::Exists($visualizationLifecyclePath)) {
    throw 'HostHunter visualization lifecycle component is missing.'
}
. $visualizationLifecyclePath

if ($env:HH_CLIENT_SKIP_AUTO_START -cne '1') {
    Use-HHClientLock {
        $configuration = Get-HHClientConfiguration
        $script:HHClientRepoRoot = $configuration.RepoRoot
        $script:HHClientVisualizerRepoRoot = $configuration.VisualizerRepoRoot
        $script:HHClientVisualizerUrl = $configuration.VisualizerUrl
        $script:HHClientSourceFingerprint = Get-HHClientSourceFingerprint $script:HHClientRepoRoot
        $script:HHClientControllerId = Connect-HHClientRuntime `
            -RepoRoot $script:HHClientRepoRoot `
            -SourceFingerprint $script:HHClientSourceFingerprint `
            -VisualizationMode Preserve
        $script:HHClientMetadata = Get-HHClientDefinition $script:HHClientControllerId
        Sync-HHClientCommand $script:HHClientMetadata
        Show-HHClientStartupAnimation -CommandCount @($script:HHClientMetadata.commands).Count
    }
    Show-HHVisualizationStartupPrompt
}
else {
    Export-ModuleMember -Function $script:HHClientLocalCommands
}
