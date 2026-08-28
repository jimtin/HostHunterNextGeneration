function Test-HHVisualizationPromptSupported {
    if ($env:HH_CLIENT_NO_VISUALIZATION_PROMPT -ceq '1' -or
        -not [string]::IsNullOrWhiteSpace($env:CI) -or
        [Console]::IsInputRedirected -or $Host.Name -cne 'ConsoleHost') { return $false }
    $true
}

function Test-HHVisualizationAnimationSupported {
    if ($env:HH_CLIENT_NO_ANIMATION -ceq '1' -or
        $env:HH_CLIENT_NO_VISUALIZATION_ANIMATION -ceq '1') { return $false }
    Test-HHVisualizationPromptSupported
}

function Write-HHVisualizationHost {
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text,
        [ValidateSet('Accent','Success','Warning','Failure','Muted')][string]$Style = 'Muted',
        [switch]$NoNewline
    )

    $color = switch ($Style) {
        Accent { [ConsoleColor]::Green }
        Success { [ConsoleColor]::Green }
        Warning { [ConsoleColor]::Yellow }
        Failure { [ConsoleColor]::Red }
        default { [ConsoleColor]::DarkGray }
    }
    Write-Host $Text -ForegroundColor $color -NoNewline:$NoNewline
}

function Get-HHVisualizationSafeMessage {
    param([Parameter(Mandatory)][object]$ErrorRecord)

    $message = [string]$ErrorRecord.Exception.Message
    if ([string]::IsNullOrWhiteSpace($message)) { $message = 'Unknown lifecycle failure.' }
    $message = $message -replace '(?i)(token|secret|password|credential)(\s*[:=]\s*)\S+', `
        '$1$2<redacted>'
    if ($message.Length -gt 320) { $message = $message.Substring(0, 320) + '…' }
    $message
}

function Start-HHVisualizationDisplay {
    $animated = Test-HHVisualizationAnimationSupported
    if (-not $animated) { return $false }

    Write-HHVisualizationHost -Text "`e[?25l" -NoNewline
    try {
        $frames = @('◐','◓','◑','◒')
        $messages = @(
            'Opening the investigation deck',
            'Lighting the topology',
            'Calibrating the signal map',
            'Calling the visual horizon'
        )
        for ($index = 0; $index -lt $frames.Count; $index++) {
            $dots = '.' * (($index % 3) + 1)
            Write-HHVisualizationHost -Text (
                "`r`e[2K  $($frames[$index]) $($messages[$index])$dots"
            ) -Style Accent -NoNewline
            Start-Sleep -Milliseconds 45
        }
        Write-HHVisualizationHost -Text "`r`e[2K╭─ HostHunter Visualization ───────────────────╮" `
            -Style Accent
        Write-HHVisualizationHost -Text '│  Preparing the investigation workspace       │' `
            -Style Muted
        Write-HHVisualizationHost -Text '╰───────────────────────────────────────────────╯' `
            -Style Accent
        $true
    }
    catch {
        Write-HHVisualizationHost -Text "`e[?25h" -NoNewline
        throw
    }
}

function Stop-HHVisualizationDisplay {
    param([bool]$Animated)
    if ($Animated) { Write-HHVisualizationHost -Text "`e[?25h" -NoNewline }
}

function Write-HHVisualizationStep {
    param(
        [Parameter(Mandatory)][ValidateSet('Running','Succeeded','Failed','Detail')]
        [string]$State,
        [Parameter(Mandatory)][string]$Message
    )

    if (-not (Test-HHVisualizationAnimationSupported)) {
        Write-Information ([pscustomobject][ordered]@{
                Component = 'HostHunterVisualization'
                State = $State
                Message = $Message
            }) -Tags HostHunterVisualization
        return
    }

    $prefix = switch ($State) {
        Running { '◐' }
        Succeeded { '✓' }
        Failed { '✗' }
        default { '·' }
    }
    $style = switch ($State) {
        Running { 'Accent' }
        Succeeded { 'Success' }
        Failed { 'Failure' }
        default { 'Muted' }
    }
    Write-HHVisualizationHost -Text "  $prefix $Message" -Style $style
}

function Invoke-HHVisualizationStep {
    param(
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][scriptblock]$Action
    )

    Write-HHVisualizationStep -State Running -Message $Label
    try {
        $result = & $Action
        Write-HHVisualizationStep -State Succeeded -Message $Label
        $result
    }
    catch {
        $message = Get-HHVisualizationSafeMessage -ErrorRecord $_
        Write-HHVisualizationStep -State Failed -Message "$Label — $message"
        throw
    }
}

function Complete-HHVisualizationDisplay {
    param([Parameter(Mandatory)][object]$Receipt)

    if (-not (Test-HHVisualizationAnimationSupported)) { return }
    $mission = if ($null -eq $Receipt.MissionId) { 'not selected' } else {
        $text = [string]$Receipt.MissionId
        if ($text.Length -gt 8) { $text.Substring(0, 8) + '…' } else { $text }
    }
    Write-HHVisualizationHost -Text ''
    Write-HHVisualizationHost -Text '  ✓ Visualization online' -Style Success
    Write-HHVisualizationHost -Text "  Mission: $mission" -Style Muted
    Write-HHVisualizationHost -Text "  Open: $script:HHClientVisualizerUrl" -Style Accent
    Write-HHVisualizationHost -Text '  Welcome to the hunt.' -Style Success
}

function Test-HHVisualizationRunning {
    $ids = @(Invoke-HHClientDockerCapture -Arguments @(
            'ps', '--filter', 'label=com.docker.compose.project=hosthunter-visualizer',
            '--filter', 'label=com.docker.compose.service=app', '--format', '{{.ID}}'
        ) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    if ($ids.Count -gt 1) { throw 'More than one HostHunter visualizer app container is running.' }
    $ids.Count -eq 1
}

function Invoke-HHVisualizationControllerAction {
    param(
        [Parameter(Mandatory)][string]$ControllerId,
        [Parameter(Mandatory)][ValidateSet('status','start','new','pause')][string]$Action
    )
    $json = [string]::Join('', @(
            Invoke-HHClientDockerCapture -Arguments @(
                'exec', $ControllerId, '/usr/local/bin/hosthunter-controller',
                'visualization', $Action
            )
        ))
    if ([Text.Encoding]::UTF8.GetByteCount($json) -gt 65536) {
        throw 'HostHunter visualization lifecycle response exceeded 64 KiB.'
    }
    try { $json | ConvertFrom-Json -Depth 8 }
    catch { throw 'HostHunter controller returned an invalid visualization lifecycle response.' }
}

function Invoke-HHVisualizerRepoScript {
    param(
        [Parameter(Mandatory)][ValidateSet('up.sh','down.sh')][string]$Name,
        [Parameter(Mandatory)][string]$VisualizerRepoRoot
    )
    $path = Join-Path $VisualizerRepoRoot "scripts/$Name"
    if (-not [IO.File]::Exists($path)) {
        throw "The configured visualizer repository is missing scripts/$Name."
    }
    $output = @(& /usr/bin/env bash $path 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "Visualizer lifecycle script '$Name' failed. Run it directly for its local diagnostic output."
    }
    foreach ($line in $output) {
        $text = [string]$line
        if ($text -match '(?i)(token|secret|password|credential)') {
            $text = '<sensitive lifecycle diagnostic withheld>'
        }
        Write-HHVisualizationStep -State Detail -Message $text
    }
}

function Open-HHVisualizationBrowser {
    param([Parameter(Mandatory)][string]$Url)
    & /usr/bin/open $Url
    if ($LASTEXITCODE -ne 0) { throw 'The visualizer started, but macOS could not open its URL.' }
}

function Start-HHVisualization {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact='Medium')]
    param([switch]$NewMission, [switch]$Open)

    if (-not $PSCmdlet.ShouldProcess('HostHunter visualizer', 'Start or resume visualization')) { return }
    $openWasSpecified = $PSBoundParameters.ContainsKey('Open')
    $openValue = [bool]$Open
    $animated = Start-HHVisualizationDisplay
    try {
        $receipt = Use-HHClientLock {
            if ([string]::IsNullOrWhiteSpace($script:HHClientVisualizerRepoRoot)) {
                throw 'No visualizer repository is configured. Re-run Install-HHClient.ps1 with -VisualizerRepoRoot.'
            }
            Invoke-HHVisualizationStep -Label 'Checking Docker engine' -Action {
                Connect-HHClientDocker
            }
            $running = Invoke-HHVisualizationStep -Label 'Checking Visualizer state' -Action {
                Test-HHVisualizationRunning
            }
            if (-not $running) {
                Invoke-HHVisualizationStep -Label 'Launching Visualizer containers' -Action {
                    Invoke-HHVisualizerRepoScript -Name up.sh `
                        -VisualizerRepoRoot $script:HHClientVisualizerRepoRoot
                }
            }
            $controllerId = Invoke-HHVisualizationStep `
                -Label 'Connecting the HostHunter producer' -Action {
                    Connect-HHClientRuntime -RepoRoot $script:HHClientRepoRoot `
                        -SourceFingerprint $script:HHClientSourceFingerprint `
                        -VisualizationMode Enable `
                        -VisualizerRepoRoot $script:HHClientVisualizerRepoRoot
                }
            $status = Invoke-HHVisualizationStep `
                -Label 'Authenticating the Visualizer contract' -Action {
                    Invoke-HHVisualizationControllerAction -ControllerId $controllerId `
                        -Action status
                }
            $createNew = [bool]$NewMission
            if (-not $createNew -and $null -ne $status.ActiveMissionId -and
                (Test-HHVisualizationPromptSupported)) {
                $missionPrompt = 'Start a new mission? Visualizer-derived data for the ' +
                    'previous mission is replaced only after acceptance; ' +
                    'HostHunter evidence is preserved [y/N]'
                $answer = Read-Host -Prompt $missionPrompt
                $createNew = [string]$answer -match '^(?i:y|yes)$'
            }
            $lifecycleAction = if ($createNew) { 'new' } else { 'start' }
            $missionLabel = if ($createNew) {
                'Activating a new investigation mission'
            } else { 'Continuing the investigation mission' }
            $lifecycleReceipt = Invoke-HHVisualizationStep -Label $missionLabel -Action {
                Invoke-HHVisualizationControllerAction -ControllerId $controllerId `
                    -Action $lifecycleAction
            }
            $openRequested = if ($openWasSpecified) {
                $openValue
            }
            elseif (Test-HHVisualizationPromptSupported) {
                $answer = Read-Host -Prompt 'Open the HostHunter visualizer? [Y/n]'
                [string]::IsNullOrWhiteSpace([string]$answer) -or
                    [string]$answer -match '^(?i:y|yes)$'
            }
            else { $false }
            if ($openRequested) {
                Invoke-HHVisualizationStep -Label 'Opening the visual workspace' -Action {
                    Open-HHVisualizationBrowser -Url $script:HHClientVisualizerUrl
                }
            }
            $lifecycleReceipt
        }
        Complete-HHVisualizationDisplay -Receipt $receipt
        $receipt
    }
    finally { Stop-HHVisualizationDisplay -Animated $animated }
}

function Stop-HHVisualization {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact='Medium')]
    param()

    if (-not $PSCmdlet.ShouldProcess('HostHunter visualizer', 'Pause publishing and stop containers')) { return }
    Use-HHClientLock {
        if ([string]::IsNullOrWhiteSpace($script:HHClientVisualizerRepoRoot)) {
            throw 'No visualizer repository is configured. Re-run Install-HHClient.ps1 with -VisualizerRepoRoot.'
        }
        Connect-HHClientDocker
        if (-not (Test-HHVisualizationRunning)) {
            $controllerId = Get-HHClientControllerId
            if ($null -ne $controllerId) {
                $paused = Invoke-HHVisualizationControllerAction `
                    -ControllerId $controllerId -Action pause
                return [pscustomobject][ordered]@{
                    Status = 'already-stopped'
                    PublishingState = 'Paused'
                    MissionId = $paused.MissionId
                }
            }
            return [pscustomobject][ordered]@{
                Status = 'already-stopped'
                PublishingState = 'Unknown'
                MissionId = $null
            }
        }
        $controllerId = Connect-HHClientRuntime -RepoRoot $script:HHClientRepoRoot `
            -SourceFingerprint $script:HHClientSourceFingerprint `
            -VisualizationMode Enable `
            -VisualizerRepoRoot $script:HHClientVisualizerRepoRoot
        $receipt = Invoke-HHVisualizationControllerAction -ControllerId $controllerId -Action pause
        if (Test-HHVisualizationRunning) {
            Invoke-HHVisualizerRepoScript -Name down.sh `
                -VisualizerRepoRoot $script:HHClientVisualizerRepoRoot
        }
        $receipt
    }
}

function Show-HHVisualizationStartupPrompt {
    if ([string]::IsNullOrWhiteSpace($script:HHClientVisualizerRepoRoot) -or
        -not (Test-HHVisualizationPromptSupported)) { return }
    try {
        Connect-HHClientDocker
        if (Test-HHVisualizationRunning) {
            Start-HHVisualization -Confirm:$false | Out-Host
            return
        }
        $answer = Read-Host -Prompt 'Start the HostHunter visualizer? [y/N]'
        if ([string]$answer -match '^(?i:y|yes)$') {
            Start-HHVisualization -Confirm:$false | Out-Host
        }
    }
    catch {
        $message = Get-HHVisualizationSafeMessage -ErrorRecord $_
        Write-Warning "HostHunter is ready, but visualization startup was not completed: $message"
    }
}
