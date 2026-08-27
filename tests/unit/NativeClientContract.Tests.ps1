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
            $env:HH_RUNTIME_MODULE_PATH = Join-Path $repoRoot `
                'src/HostHunterNextGeneration/HostHunterNextGeneration.psd1'
            $env:HH_SOURCE_FINGERPRINT = 'contract-fingerprint'
            $metadata = & $script:metadataScript | ConvertFrom-Json -Depth 20
        }
        finally {
            $env:HH_RUNTIME_MODULE_PATH = $previousModule
            $env:HH_SOURCE_FINGERPRINT = $previousFingerprint
        }
        $metadata.schema | Should -BeExactly HostHunter.ClientCommandMetadata.v1
        $metadata.sourceFingerprint | Should -BeExactly contract-fingerprint
        @($metadata.commands).Count | Should -Be 11
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

    It 'installs idempotently for the current user and adds one marked profile import' {
        $testHome = Join-Path $TestDrive 'home'
        $testProfilePath = Join-Path $testHome '.config/powershell/profile.ps1'
        $previousConfig = $env:XDG_CONFIG_HOME
        try {
            $env:XDG_CONFIG_HOME = Join-Path $testHome '.config'
            $first = & $script:installerScript -RepoRoot $repoRoot -UserHome $testHome `
                -ProfilePath $testProfilePath -Confirm:$false
            $second = & $script:installerScript -RepoRoot $repoRoot -UserHome $testHome `
                -ProfilePath $testProfilePath -Confirm:$false
        }
        finally { $env:XDG_CONFIG_HOME = $previousConfig }
        $first.ModulePath | Should -BeExactly $second.ModulePath
        Join-Path $first.ModulePath 'HostHunter.Client.psd1' | Should -Exist
        $configuration = Get-Content -LiteralPath $first.ConfigurationPath -Raw |
            ConvertFrom-Json
        $configuration.repoRoot | Should -BeExactly $repoRoot
        ([regex]::Matches(
                (Get-Content -LiteralPath $testProfilePath -Raw),
                [regex]::Escape('# HostHunter.Client auto-import begin')
            )).Count | Should -Be 1
        $profileContents = Get-Content -LiteralPath $testProfilePath -Raw
        $expectedSourceManifest = [regex]::Escape(
            (Join-Path $clientSourceRoot 'HostHunter.Client.psd1')
        )
        $profileContents | Should -Match $expectedSourceManifest
        $profileContents | Should -Match 'Import-Module .* -Force -ErrorAction Stop'
        if (-not $IsWindows) {
            [IO.File]::GetUnixFileMode($first.ConfigurationPath).ToString() |
                Should -BeExactly 'UserWrite, UserRead'
        }
    }

    It 'makes the installed-profile macOS journey require all eleven commands in a fresh shell' {
        $source = Get-Content -LiteralPath $script:installedJourneyScript -Raw
        $source | Should -Match "'pwsh'"
        $source | Should -Not -Match "'-NoProfile'"
        $source | Should -Match 'RequireProfileLoadedClient'
        $source | Should -Match 'InvokedUniqueCommandCount -ne 11'
        $source | Should -Match 'fresh-process-installed-profile'
        $source | Should -Match "Environment\['DOCKER_CONFIG'\]"
    }
}
