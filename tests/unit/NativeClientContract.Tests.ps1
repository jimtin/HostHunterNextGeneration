Describe 'native PowerShell client contract' -Tag Unit {
    BeforeDiscovery {
        $env:HH_CLIENT_SKIP_AUTO_START = '1'
        $discoveryRoot = if (-not [string]::IsNullOrWhiteSpace(
                $env:HH_TEST_CLIENT_SOURCE_ROOT
            )) { $env:HH_TEST_CLIENT_SOURCE_ROOT } else {
            Join-Path (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path `
                'client/HostHunter.Client'
        }
        Import-Module (Join-Path $discoveryRoot 'HostHunter.Client.psd1') -Force
    }

    BeforeAll {
        $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        $clientSourceRoot = if (-not [string]::IsNullOrWhiteSpace($env:HH_TEST_CLIENT_SOURCE_ROOT)) {
            $env:HH_TEST_CLIENT_SOURCE_ROOT
        } else { Join-Path $repoRoot 'client/HostHunter.Client' }
        $clientManifest = Join-Path $clientSourceRoot 'HostHunter.Client.psd1'
        $script:metadataScript = Join-Path $repoRoot `
            'scripts/runtime/Get-HHClientCommandMetadata.ps1'
        $script:fingerprintScript = Join-Path $repoRoot 'scripts/client/Get-HHSourceFingerprint.ps1'
        $script:installerScript = Join-Path $repoRoot 'scripts/client/Install-HHClient.ps1'
        $script:installedJourneyScript = Join-Path $repoRoot `
            'scripts/client/Test-HHInstalledNativeClientSsh.ps1'
        $script:nativeClientHelpers = Join-Path $repoRoot `
            'scripts/client/NativeClientTestHelpers.ps1'
        . $script:nativeClientHelpers
        $script:previousSkip = $env:HH_CLIENT_SKIP_AUTO_START
        $env:HH_CLIENT_SKIP_AUTO_START = '1'
        Import-Module $clientManifest -Force
    }

    AfterAll {
        $env:HH_CLIENT_SKIP_AUTO_START = $script:previousSkip
        Remove-Module HostHunter.Client -Force -ErrorAction Ignore
    }

    It 'keeps managed-host communication and product behavior out of the Mac client' {
        $source = Get-Content -LiteralPath (
            Join-Path $clientSourceRoot 'HostHunter.Client.psm1'
        ) -Raw
        $source | Should -Not -Match 'New-PSSession|Invoke-Command|ssh-keyscan|\bssh\b|HttpClient|TcpClient'
        $source | Should -Not -Match 'Set-HHTarget|Invoke-HHCommand|Get-HHTarget'
        $source | Should -Match 'Invoke-HHClientCommand'
    }

    It 'discovers the authoritative export surface without a hard-coded command list' {
        $previousModule = $env:HH_RUNTIME_MODULE_PATH
        $previousFingerprint = $env:HH_SOURCE_FINGERPRINT
        try {
            $runtimeSourceRoot = if (-not [string]::IsNullOrWhiteSpace(
                    $env:HH_TEST_SOURCE_ROOT
                )) { $env:HH_TEST_SOURCE_ROOT } else {
                Join-Path $repoRoot 'src/HostHunterNextGeneration'
            }
            $env:HH_RUNTIME_MODULE_PATH = Join-Path $runtimeSourceRoot `
                'HostHunterNextGeneration.psd1'
            $env:HH_SOURCE_FINGERPRINT = 'contract-fingerprint'
            $metadata = & $script:metadataScript | ConvertFrom-Json -Depth 20
        }
        finally {
            $env:HH_RUNTIME_MODULE_PATH = $previousModule
            $env:HH_SOURCE_FINGERPRINT = $previousFingerprint
        }
        $metadata.schema | Should -BeExactly HostHunter.ClientCommandMetadata.v1
        $metadata.sourceFingerprint | Should -BeExactly contract-fingerprint
        @($metadata.commands).Count | Should -Be 12
        @($metadata.commands.name | Sort-Object) | Should -Be @(
            Get-Command -Module HostHunterNextGeneration -CommandType Function |
                Sort-Object Name | Select-Object -ExpandProperty Name
        )
        @($metadata.commands | Where-Object { [string]::IsNullOrWhiteSpace($_.declaration) }) |
            Should -HaveCount 0
        (Get-Content -LiteralPath $script:metadataScript -Raw) |
            Should -Not -Match "'Set-HHTarget'|'Invoke-HHCommand'|'Get-HHTarget'"
    }

    InModuleScope HostHunter.Client {
        It 'generates and invokes an unseen pipeline cmdlet through one generic bridge' {
            $script:captured = $null
            Mock Invoke-HHClientCommand {
                $script:captured = [pscustomobject]@{
                    CommandName = $CommandName
                    Parameters = $Parameters
                    HasPipelineInput = $HasPipelineInput
                    PipelineInput = $PipelineInput
                }
            }
            $metadata = [pscustomobject]@{ aliases = @(); commands = @(
                    [pscustomobject]@{
                        name = 'Test-HHDynamic'
                        declaration = @'
[CmdletBinding()]
param(
    [Parameter(ValueFromPipeline=$true)]
    [string]$Name,
    [switch]$Force
)
'@
                        pipelineParameters = @('Name')
                    }
                ) }

            Sync-HHClientCommand $metadata
            @('alpha', 'beta') | Test-HHDynamic -Force

            Should -Invoke Invoke-HHClientCommand -Times 1 -Exactly
            $script:captured.CommandName | Should -BeExactly Test-HHDynamic
            $script:captured.HasPipelineInput | Should -BeTrue
            $script:captured.PipelineInput | Should -Be @('alpha', 'beta')
            $script:captured.Parameters.Contains('Name') | Should -BeFalse
            [bool]$script:captured.Parameters.Force | Should -BeTrue
        }

        It 'rejects executable container metadata before defining a proxy' {
            $metadata = [pscustomobject]@{ aliases = @(); commands = @(
                    [pscustomobject]@{
                        name = 'Test-HHInjected'
                        declaration = "[CmdletBinding()]`nparam()`nRemove-Item /tmp/example"
                        pipelineParameters = @()
                    }
                ) }

            { Sync-HHClientCommand $metadata } |
                Should -Throw '*executable declaration metadata*'
            Get-Command Test-HHInjected -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        }

        It 'creates container-declared aliases without client-specific logic' {
            Mock Invoke-HHClientCommand { 'aliased' }
            $metadata = [pscustomobject]@{
                commands = @([pscustomobject]@{
                        name = 'Test-HHDynamic'
                        declaration = "[CmdletBinding()]`nparam()"
                        pipelineParameters = @()
                    })
                aliases = @([pscustomobject]@{
                        name = 'Test-HHDynamics'
                        target = 'Test-HHDynamic'
                    })
            }

            Sync-HHClientCommand $metadata
            Test-HHDynamics | Should -BeExactly aliased
            Should -Invoke Invoke-HHClientCommand -Times 1 -Exactly
        }

        It 'fails immediately rather than waiting or retrying when another client owns the lock' {
            $stateRoot = Join-Path $TestDrive ([Guid]::NewGuid().ToString('N'))
            $previousState = $env:XDG_STATE_HOME
            $env:XDG_STATE_HOME = $stateRoot
            $lockRoot = Join-Path $stateRoot 'hosthunter'
            [IO.Directory]::CreateDirectory($lockRoot) | Out-Null
            $held = [IO.FileStream]::new(
                (Join-Path $lockRoot 'client.lock'), [IO.FileMode]::OpenOrCreate,
                [IO.FileAccess]::ReadWrite, [IO.FileShare]::None
            )
            try {
                { Use-HHClientLock { throw 'must not run' } } |
                    Should -Throw '*No retry was attempted*'
            }
            finally {
                $held.Dispose()
                $env:XDG_STATE_HOME = $previousState
            }
        }

        It 'uses a validated run-scoped runtime project without changing the default' {
            $previousRuntimeProject = $env:HH_RUNTIME_PROJECT
            try {
                $env:HH_RUNTIME_PROJECT = $null
                Get-HHClientRuntimeProject | Should -BeExactly 'hosthunter-next-generation-runtime'
                $env:HH_RUNTIME_PROJECT = 'hosthunter-native-runtime-1234'
                Get-HHClientRuntimeProject | Should -BeExactly 'hosthunter-native-runtime-1234'
                $env:HH_RUNTIME_PROJECT = '../wrong'
                { Get-HHClientRuntimeProject } | Should -Throw '*invalid Docker Compose project*'
            }
            finally { $env:HH_RUNTIME_PROJECT = $previousRuntimeProject }
        }

        It 'starts Docker Desktop once and only polls readiness afterward' {
            $script:dockerReadinessChecks = 0
            Mock Test-HHClientDockerReady {
                $script:dockerReadinessChecks++
                $script:dockerReadinessChecks -ge 2
            }
            Mock Open-HHClientDockerDesktop {}
            Mock Start-Sleep {}

            Connect-HHClientDocker -MaximumWaitSeconds 1 -PlatformIsMacOS $true

            Should -Invoke Open-HHClientDockerDesktop -Times 1 -Exactly
            Should -Invoke Test-HHClientDockerReady -Times 2 -Exactly
        }

        It 'continues an existing mission by default without restarting the visualizer' {
            $script:HHClientRepoRoot = '/workspace'
            $script:HHClientVisualizerRepoRoot = '/visualizer'
            $script:HHClientSourceFingerprint = 'fingerprint'
            $script:actions = [Collections.Generic.List[string]]::new()
            $missionId = [Guid]::NewGuid()
            Mock Use-HHClientLock { & $Action }
            Mock Connect-HHClientDocker {}
            Mock Test-HHVisualizationRunning { $true }
            Mock Connect-HHClientRuntime { 'controller-id' }
            Mock Test-HHVisualizationPromptSupported { $false }
            Mock Test-HHVisualizationAnimationSupported { $false }
            Mock Invoke-HHVisualizerRepoScript {}
            Mock Invoke-HHVisualizationControllerAction {
                $script:actions.Add($Action)
                if ($Action -ceq 'status') {
                    [pscustomobject]@{ ActiveMissionId=$missionId }
                }
                else { [pscustomobject]@{ Status='continued'; MissionId=$missionId } }
            }

            $receipt = Start-HHVisualization -Open:$false -Confirm:$false

            $receipt.Status | Should -BeExactly continued
            $script:actions.ToArray() | Should -Be @('status','start')
            Should -Not -Invoke Invoke-HHVisualizerRepoScript
            Should -Invoke Connect-HHClientRuntime -Times 1 -Exactly -ParameterFilter {
                $VisualizationMode -ceq 'Enable' -and $VisualizerRepoRoot -ceq '/visualizer'
            }
        }

        It 'defaults the new-mission prompt to no and browser prompt to yes' {
            $script:HHClientRepoRoot = '/workspace'
            $script:HHClientVisualizerRepoRoot = '/visualizer'
            $script:HHClientVisualizerUrl = 'http://127.0.0.1:4310'
            $script:HHClientSourceFingerprint = 'fingerprint'
            $script:prompts = 0
            $script:actions = [Collections.Generic.List[string]]::new()
            $missionId = [Guid]::NewGuid()
            Mock Use-HHClientLock { & $Action }
            Mock Connect-HHClientDocker {}
            Mock Test-HHVisualizationRunning { $true }
            Mock Connect-HHClientRuntime { 'controller-id' }
            Mock Test-HHVisualizationPromptSupported { $true }
            Mock Test-HHVisualizationAnimationSupported { $false }
            Mock Read-Host { $script:prompts++; '' }
            Mock Open-HHVisualizationBrowser {}
            Mock Invoke-HHVisualizationControllerAction {
                $script:actions.Add($Action)
                if ($Action -ceq 'status') { [pscustomobject]@{ActiveMissionId=$missionId} }
                else { [pscustomobject]@{Status='continued';MissionId=$missionId} }
            }

            Start-HHVisualization -Confirm:$false | Out-Null

            $script:actions.ToArray() | Should -Be @('status','start')
            $script:prompts | Should -Be 2
            Should -Invoke Open-HHVisualizationBrowser -Times 1 -Exactly -ParameterFilter {
                $Url -ceq 'http://127.0.0.1:4310'
            }
        }

        It 'uses an explicit interactive yes to request a new mission' {
            $script:HHClientRepoRoot = '/workspace'
            $script:HHClientVisualizerRepoRoot = '/visualizer'
            $script:HHClientSourceFingerprint = 'fingerprint'
            $script:actions = [Collections.Generic.List[string]]::new()
            $missionId = [Guid]::NewGuid()
            Mock Use-HHClientLock { & $Action }
            Mock Connect-HHClientDocker {}
            Mock Test-HHVisualizationRunning { $true }
            Mock Connect-HHClientRuntime { 'controller-id' }
            Mock Test-HHVisualizationPromptSupported { $true }
            Mock Test-HHVisualizationAnimationSupported { $false }
            Mock Read-Host { if ($Prompt -match 'new mission') { 'Y' } else { 'N' } }
            Mock Open-HHVisualizationBrowser {}
            Mock Invoke-HHVisualizationControllerAction {
                $script:actions.Add($Action)
                if ($Action -ceq 'status') { [pscustomobject]@{ActiveMissionId=$missionId} }
                else { [pscustomobject]@{Status='started';MissionId=[Guid]::NewGuid()} }
            }

            Start-HHVisualization -Confirm:$false | Out-Null

            $script:actions.ToArray() | Should -Be @('status','new')
            Should -Not -Invoke Open-HHVisualizationBrowser
        }

        It 'pauses publishing before it stops visualizer containers' {
            $script:HHClientRepoRoot = '/workspace'
            $script:HHClientVisualizerRepoRoot = '/visualizer'
            $script:HHClientSourceFingerprint = 'fingerprint'
            $script:order = [Collections.Generic.List[string]]::new()
            Mock Use-HHClientLock { & $Action }
            Mock Connect-HHClientDocker {}
            Mock Connect-HHClientRuntime { 'controller-id' }
            Mock Test-HHVisualizationRunning { $true }
            Mock Invoke-HHVisualizationControllerAction {
                $script:order.Add("controller:$Action")
                [pscustomobject]@{ Status='paused' }
            }
            Mock Invoke-HHVisualizerRepoScript { $script:order.Add("repo:$Name") }

            $receipt = Stop-HHVisualization -Confirm:$false

            $receipt.Status | Should -BeExactly paused
            $script:order.ToArray() | Should -Be @('controller:pause','repo:down.sh')
        }

        It 'reports an already stopped visualizer without starting or rebuilding the controller' {
            $script:HHClientVisualizerRepoRoot = '/visualizer'
            Mock Use-HHClientLock { & $Action }
            Mock Connect-HHClientDocker {}
            Mock Test-HHVisualizationRunning { $false }
            Mock Get-HHClientControllerId { $null }
            Mock Connect-HHClientRuntime { throw 'must not run' }
            Mock Invoke-HHVisualizationControllerAction { throw 'must not run' }
            Mock Invoke-HHVisualizerRepoScript { throw 'must not run' }

            $receipt = Stop-HHVisualization -Confirm:$false

            $receipt.Status | Should -BeExactly 'already-stopped'
            $receipt.PublishingState | Should -BeExactly Unknown
            Should -Not -Invoke Connect-HHClientRuntime
            Should -Not -Invoke Invoke-HHVisualizationControllerAction
            Should -Not -Invoke Invoke-HHVisualizerRepoScript
        }

        It 'persists a pause through an existing controller when the visualizer is already stopped' {
            $script:HHClientVisualizerRepoRoot = '/visualizer'
            Mock Use-HHClientLock { & $Action }
            Mock Connect-HHClientDocker {}
            Mock Test-HHVisualizationRunning { $false }
            Mock Get-HHClientControllerId { 'existing-controller' }
            Mock Connect-HHClientRuntime { throw 'must not run' }
            Mock Invoke-HHVisualizationControllerAction {
                [pscustomobject]@{ Status='paused'; MissionId=$null }
            }
            Mock Invoke-HHVisualizerRepoScript { throw 'must not run' }

            $receipt = Stop-HHVisualization -Confirm:$false

            $receipt.Status | Should -BeExactly 'already-stopped'
            $receipt.PublishingState | Should -BeExactly Paused
            Should -Invoke Invoke-HHVisualizationControllerAction -Times 1 -Exactly `
                -ParameterFilter { $ControllerId -ceq 'existing-controller' -and $Action -ceq 'pause' }
            Should -Not -Invoke Connect-HHClientRuntime
            Should -Not -Invoke Invoke-HHVisualizerRepoScript
        }

        It 'keeps the separate stopped-visualizer startup prompt defaulted to no' {
            $script:HHClientVisualizerRepoRoot = '/visualizer'
            Mock Test-HHVisualizationPromptSupported { $true }
            Mock Connect-HHClientDocker {}
            Mock Test-HHVisualizationRunning { $false }
            Mock Read-Host { '' }
            Mock Start-HHVisualization {}

            Show-HHVisualizationStartupPrompt

            Should -Invoke Read-Host -Times 1 -Exactly -ParameterFilter {
                $Prompt -match '\[y/N\]$'
            }
            Should -Not -Invoke Start-HHVisualization
        }

        It 'continues through the lifecycle command when the visualizer is already running' {
            $script:HHClientVisualizerRepoRoot = '/visualizer'
            Mock Test-HHVisualizationPromptSupported { $true }
            Mock Connect-HHClientDocker {}
            Mock Test-HHVisualizationRunning { $true }
            Mock Read-Host { throw 'the generic start prompt must not run' }
            Mock Start-HHVisualization {}

            Show-HHVisualizationStartupPrompt

            Should -Invoke Start-HHVisualization -Times 1 -Exactly -ParameterFilter {
                $Confirm -eq $false
            }
            Should -Not -Invoke Read-Host
        }

        It 'warns without breaking the loaded framework when prompted startup fails' {
            $script:HHClientVisualizerRepoRoot = '/visualizer'
            Mock Test-HHVisualizationPromptSupported { $true }
            Mock Connect-HHClientDocker {}
            Mock Test-HHVisualizationRunning { $true }
            Mock Start-HHVisualization { throw 'producer token: do-not-print' }
            Mock Write-Warning {}

            { Show-HHVisualizationStartupPrompt } | Should -Not -Throw

            Should -Invoke Write-Warning -Times 1 -Exactly -ParameterFilter {
                $Message -match 'HostHunter is ready' -and
                $Message -notmatch 'do-not-print'
            }
        }

        It 'does not make configured visualization equivalent to enabled publishing' {
            $lifecyclePath = Join-Path `
                (Split-Path -Parent (Get-Module HostHunter.Client).Path) `
                'Private/VisualizationLifecycle.ps1'
            $source = @(
                Get-Content -LiteralPath (Get-Module HostHunter.Client).Path -Raw
                Get-Content -LiteralPath $lifecyclePath -Raw
            ) -join "`n"
            $source | Should -Match '-VisualizationMode Preserve'
            $source | Should -Match '-VisualizationMode Enable'
            $source | Should -Not -Match 'visualizerEnabled\s*=\s*-not\s+\[string\]::IsNullOrWhiteSpace'
        }

        It 'keeps visualization lifecycle behavior out of the client module monolith' {
            $moduleSource = Get-Content -LiteralPath (Get-Module HostHunter.Client).Path -Raw
            $lifecyclePath = Join-Path `
                (Split-Path -Parent (Get-Module HostHunter.Client).Path) `
                'Private/VisualizationLifecycle.ps1'
            $lifecycleSource = Get-Content -LiteralPath $lifecyclePath -Raw

            $moduleSource | Should -Not -Match 'function Start-HHVisualization'
            $moduleSource | Should -Match "Private/VisualizationLifecycle\.ps1"
            $lifecycleSource | Should -Match 'function Start-HHVisualization'
            $lifecycleSource | Should -Match 'function Stop-HHVisualization'
        }

        It 'rejects a configured browser URL outside the loopback origin' {
            $configurationRoot = Join-Path $TestDrive 'invalid-url-config'
            $configurationPath = Join-Path $configurationRoot 'hosthunter/client.json'
            [IO.Directory]::CreateDirectory((Split-Path -Parent $configurationPath)) | Out-Null
            [IO.File]::WriteAllText($configurationPath, (@{
                        schema='HostHunter.ClientConfiguration.v2'
                        repoRoot='/workspace'
                        visualizerRepoRoot=$null
                        visualizerUrl='https://example.invalid/'
                    } | ConvertTo-Json -Compress))
            $previousConfigurationRoot = $env:XDG_CONFIG_HOME
            $previousRepoRoot = $env:HH_CLIENT_REPO_ROOT
            try {
                $env:XDG_CONFIG_HOME = $configurationRoot
                $env:HH_CLIENT_REPO_ROOT = $null
                { Get-HHClientConfiguration } | Should -Throw '*loopback HTTP origin*'
            }
            finally {
                $env:XDG_CONFIG_HOME = $previousConfigurationRoot
                $env:HH_CLIENT_REPO_ROOT = $previousRepoRoot
            }
        }

        It 'rejects stale configuration versions and moved visualizer repositories' {
            $configurationRoot = Join-Path $TestDrive 'stale-client-config'
            $configurationPath = Join-Path $configurationRoot 'hosthunter/client.json'
            [IO.Directory]::CreateDirectory((Split-Path -Parent $configurationPath)) | Out-Null
            $previousConfigurationRoot = $env:XDG_CONFIG_HOME
            $previousRepoRoot = $env:HH_CLIENT_REPO_ROOT
            try {
                $env:XDG_CONFIG_HOME = $configurationRoot
                $env:HH_CLIENT_REPO_ROOT = $null
                [IO.File]::WriteAllText($configurationPath, (@{
                            schema='HostHunter.ClientConfiguration.v1'
                            repoRoot='/workspace';visualizerRepoRoot=$null
                            visualizerUrl='http://127.0.0.1:4310'
                        } | ConvertTo-Json -Compress))
                { Get-HHClientConfiguration } | Should -Throw '*version is unsupported*'

                [IO.File]::WriteAllText($configurationPath, (@{
                            schema='HostHunter.ClientConfiguration.v2'
                            repoRoot='/workspace';visualizerRepoRoot='/path/that/moved'
                            visualizerUrl='http://127.0.0.1:4310'
                        } | ConvertTo-Json -Compress))
                { Get-HHClientConfiguration } | Should -Throw '*visualizer repository moved*'
            }
            finally {
                $env:XDG_CONFIG_HOME = $previousConfigurationRoot
                $env:HH_CLIENT_REPO_ROOT = $previousRepoRoot
            }
        }

        It 'honors WhatIf before any visualization lifecycle mutation' {
            Mock Use-HHClientLock { throw 'must not run' }
            Start-HHVisualization -WhatIf
            Stop-HHVisualization -WhatIf
            Should -Not -Invoke Use-HHClientLock
        }

        It 'suppresses the startup animation without sleeping in automation' {
            Mock Test-HHClientAnimationSupported { $false }
            Mock Start-Sleep {}

            Show-HHClientStartupAnimation -CommandCount 11

            Should -Not -Invoke Start-Sleep
        }

        It 'renders a bounded three-second animation only after command discovery' {
            Mock Test-HHClientAnimationSupported { $true }
            Mock Start-Sleep {}
            Mock Write-Host {}

            Show-HHClientStartupAnimation -CommandCount 11

            Should -Invoke Start-Sleep -Times 14 -Exactly -ParameterFilter {
                $Milliseconds -eq 240
            }
            Should -Invoke Write-Host -Times 5 -Exactly
        }

        It 'renders a bounded Visualizer opening sequence and always restores the cursor' {
            $script:visualizerLines = [Collections.Generic.List[string]]::new()
            Mock Test-HHVisualizationAnimationSupported { $true }
            Mock Start-Sleep {}
            Mock Write-HHVisualizationHost {
                $script:visualizerLines.Add($Text)
            }

            $animated = Start-HHVisualizationDisplay
            Stop-HHVisualizationDisplay -Animated $animated

            $animated | Should -BeTrue
            Should -Invoke Start-Sleep -Times 4 -Exactly -ParameterFilter {
                $Milliseconds -eq 45
            }
            ($script:visualizerLines -join "`n") |
                Should -Match 'HostHunter Visualization'
            $script:visualizerLines[0] | Should -Match '\?25l'
            $script:visualizerLines[-1] | Should -Match '\?25h'
        }

        It 'does not sleep or animate Visualizer startup in automation' {
            Mock Test-HHVisualizationAnimationSupported { $false }
            Mock Start-Sleep {}
            Mock Write-HHVisualizationHost {}

            Start-HHVisualizationDisplay | Should -BeFalse

            Should -Not -Invoke Start-Sleep
            Should -Not -Invoke Write-HHVisualizationHost
        }

        It 'retains truthful step logs and redacts sensitive failure values' {
            $script:visualizerLines = [Collections.Generic.List[string]]::new()
            Mock Test-HHVisualizationAnimationSupported { $true }
            Mock Write-HHVisualizationHost {
                $script:visualizerLines.Add($Text)
            }

            { Invoke-HHVisualizationStep -Label 'Authenticating producer' -Action {
                    throw 'producer token: super-secret-value'
                } } | Should -Throw

            $rendered = $script:visualizerLines -join "`n"
            $rendered | Should -Match ([regex]::Escape(
                    "$([char]0x25d0) Authenticating producer"
                ))
            $rendered | Should -Match ([regex]::Escape(
                    "$([char]0x2717) Authenticating producer"
                ))
            $rendered | Should -Match '<redacted>'
            $rendered | Should -Not -Match 'super-secret-value'
        }
    }

    It 'changes the runtime fingerprint whenever an inventoried source file changes' {
        $root = Join-Path $TestDrive 'fingerprint-repo'
        [IO.Directory]::CreateDirectory((Join-Path $root 'scripts/runtime')) | Out-Null
        [IO.File]::WriteAllText((Join-Path $root 'Dockerfile.runtime'), 'FROM scratch')
        [IO.File]::WriteAllText((Join-Path $root 'scripts/runtime/example.ps1'), 'one')
        & git -C $root init --quiet
        & git -C $root add Dockerfile.runtime scripts/runtime/example.ps1
        $first = & $script:fingerprintScript -RepoRoot $root
        [IO.File]::WriteAllText((Join-Path $root 'scripts/runtime/example.ps1'), 'two')
        $second = & $script:fingerprintScript -RepoRoot $root
        $first | Should -Not -BeExactly $second
    }

    It 'selects exactly one native-client terminal receipt from incidental output' {
        $receipt = [pscustomobject]@{ Status='passed'; InvokedUniqueCommandCount=12 }
        (Select-HHNativeClientTerminalResult -InputObject @('incidental', $receipt)).Status |
            Should -BeExactly passed
        { Select-HHNativeClientTerminalResult -InputObject @('incidental') } |
            Should -Throw '*0 passing terminal receipts*'
        { Select-HHNativeClientTerminalResult -InputObject @($receipt, $receipt) } |
            Should -Throw '*2 passing terminal receipts*'
    }

    It 'bounds and redacts native-client failure diagnostics' {
        $message = Format-HHNativeClientFailure `
            -StandardError ('prefix ' + ('x' * 700)) `
            -StandardOutput 'producer token: do-not-print' `
            -MaximumCharacters 256

        $message.Length | Should -BeLessOrEqual 289
        $message | Should -Not -Match 'do-not-print'
        $message | Should -Match 'token:\s*<redacted>'
        $message | Should -Match 'stderr:'
        $message | Should -Match 'stdout:'
    }

    It 'installs idempotently for the current user and adds one marked profile import' {
        $testHome = Join-Path $TestDrive 'home'
        $testProfilePath = Join-Path $testHome '.config/powershell/profile.ps1'
        $visualizerRoot = Join-Path $TestDrive 'non-sibling-visualizer'
        [IO.Directory]::CreateDirectory((Join-Path $visualizerRoot 'scripts')) | Out-Null
        foreach ($name in @('up.sh','down.sh','bootstrap-secrets.sh')) {
            [IO.File]::WriteAllText((Join-Path $visualizerRoot "scripts/$name"), "#!/bin/sh`nexit 0`n")
        }
        [IO.File]::WriteAllText((Join-Path $visualizerRoot 'compose.yaml'), "services: {}`n")
        $previousConfig = $env:XDG_CONFIG_HOME
        try {
            $env:XDG_CONFIG_HOME = Join-Path $testHome '.config'
            $first = & $script:installerScript -RepoRoot $repoRoot `
                -VisualizerRepoRoot $visualizerRoot -UserHome $testHome `
                -ProfilePath $testProfilePath -Confirm:$false
            $second = & $script:installerScript -RepoRoot $repoRoot `
                -VisualizerRepoRoot $visualizerRoot -UserHome $testHome `
                -ProfilePath $testProfilePath -Confirm:$false
        }
        finally { $env:XDG_CONFIG_HOME = $previousConfig }
        $first.ModulePath | Should -BeExactly $second.ModulePath
        Join-Path $first.ModulePath 'HostHunter.Client.psd1' | Should -Exist
        Join-Path $first.ModulePath 'Private/VisualizationLifecycle.ps1' | Should -Exist
        $configuration = Get-Content -LiteralPath $first.ConfigurationPath -Raw |
            ConvertFrom-Json
        $configuration.schema | Should -BeExactly HostHunter.ClientConfiguration.v2
        $configuration.repoRoot | Should -BeExactly $repoRoot
        $configuration.visualizerRepoRoot | Should -BeExactly $visualizerRoot
        ([regex]::Matches(
                (Get-Content -LiteralPath $testProfilePath -Raw),
                [regex]::Escape('# HostHunter.Client auto-import begin')
            )).Count | Should -Be 1
        $profileContents = Get-Content -LiteralPath $testProfilePath -Raw
        $expectedSourceManifest = [regex]::Escape(
            (Join-Path $repoRoot 'client/HostHunter.Client/HostHunter.Client.psd1')
        )
        $profileContents | Should -Match $expectedSourceManifest
        $profileContents | Should -Match 'Import-Module .* -Force -ErrorAction Stop'
        if (-not $IsWindows) {
            [IO.File]::GetUnixFileMode($first.ConfigurationPath).ToString() |
                Should -BeExactly 'UserWrite, UserRead'
        }
    }

    It 'rejects a missing configured visualizer repository without changing the client' {
        { & $script:installerScript -RepoRoot $repoRoot `
                -VisualizerRepoRoot (Join-Path $TestDrive 'missing-visualizer') `
                -UserHome (Join-Path $TestDrive 'missing-home') -SkipProfile -Confirm:$false } |
            Should -Throw
    }

    It 'makes the installed-profile macOS journey require the framework and lifecycle commands in a fresh shell' {
        $source = Get-Content -LiteralPath $script:installedJourneyScript -Raw
        $source | Should -Match "'pwsh'"
        $source | Should -Not -Match "'-NoProfile'"
        $source | Should -Match 'RequireProfileLoadedClient'
        $source | Should -Match 'InvokedUniqueCommandCount -ne 12'
        $source | Should -Match 'fresh-process-installed-profile'
        $source | Should -Match "Environment\['DOCKER_CONFIG'\]"
        $source | Should -Match '\$journeyParameters\s*=\s*@\{'
        $journeySource = Get-Content -LiteralPath $script:installedJourneyScript.Replace(
            'Test-HHInstalledNativeClientSsh.ps1', 'Test-HHNativeClientSsh.ps1'
        ) -Raw
        $journeySource | Should -Match '-not \[string\]::IsNullOrWhiteSpace\(\[string\]\$targetName\)'
    }
}
