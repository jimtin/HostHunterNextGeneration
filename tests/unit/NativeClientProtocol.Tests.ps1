Describe 'native client protocol' -Tag Unit {
    BeforeAll {
        $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        $protocolScript = Join-Path $repoRoot 'scripts/runtime/Invoke-HHClientProtocol.ps1'
        $moduleRoot = Join-Path $TestDrive 'HostHunterNextGeneration'
        [IO.Directory]::CreateDirectory($moduleRoot) | Out-Null
        [IO.File]::WriteAllText((Join-Path $moduleRoot 'HostHunterNextGeneration.psm1'), @'
function Test-HHProtocolStreams {
    [CmdletBinding()]
    param()
    Write-Output 'output-value'
    Write-Warning 'warning-value'
    Write-Verbose 'verbose-value'
    Write-Debug 'debug-value'
    Write-Information 'information-value' -Tags client
    Write-Progress -Activity 'protocol-progress' -Status 'running' -PercentComplete 50
}
function Test-HHProtocolFailure {
    [CmdletBinding()]
    param()
    throw 'protocol-failure'
}
Export-ModuleMember -Function Test-HHProtocolStreams, Test-HHProtocolFailure
'@)
        New-ModuleManifest -Path (Join-Path $moduleRoot 'HostHunterNextGeneration.psd1') `
            -RootModule HostHunterNextGeneration.psm1 -ModuleVersion 1.0.0 `
            -FunctionsToExport Test-HHProtocolStreams, Test-HHProtocolFailure

        function Invoke-TestProtocol {
            param([Parameter(Mandatory)][string]$InputLine)

            $startInfo = [Diagnostics.ProcessStartInfo]::new()
            $startInfo.FileName = 'pwsh'
            foreach ($argument in @(
                    '-NoLogo', '-NoProfile', '-NonInteractive', '-File', $protocolScript
                )) { [void]$startInfo.ArgumentList.Add($argument) }
            $startInfo.UseShellExecute = $false
            $startInfo.RedirectStandardInput = $true
            $startInfo.RedirectStandardOutput = $true
            $startInfo.RedirectStandardError = $true
            $startInfo.Environment['HH_RUNTIME_MODULE_PATH'] = `
                (Join-Path $moduleRoot 'HostHunterNextGeneration.psd1')
            $process = [Diagnostics.Process]::new()
            $process.StartInfo = $startInfo
            [void]$process.Start()
            try {
                $process.StandardInput.WriteLine($InputLine)
                $process.StandardInput.Close()
                $stdout = $process.StandardOutput.ReadToEnd()
                $stderr = $process.StandardError.ReadToEnd()
                if (-not $process.WaitForExit(15000)) {
                    $process.Kill($true)
                    throw 'Protocol test process exceeded 15 seconds.'
                }
                [pscustomobject]@{
                    ExitCode = $process.ExitCode
                    StandardError = $stderr
                    Frames = @($stdout -split "`n" | Where-Object {
                            -not [string]::IsNullOrWhiteSpace($_)
                        } | ForEach-Object { $_ | ConvertFrom-Json -Depth 20 })
                }
            }
            finally { $process.Dispose() }
        }

        function ConvertTo-TestProtocolRequest {
            param(
                [Parameter(Mandatory)][string]$CommandName,
                [Collections.IDictionary]$Parameters = @{}
            )
            $request = [pscustomobject]@{
                CommandName = $CommandName
                Parameters = $Parameters
                HasPipelineInput = $false
                PipelineInput = @()
            }
            $xml = [Management.Automation.PSSerializer]::Serialize($request, 20)
            [ordered]@{
                schema = 'HostHunter.ClientInvocation.v1'
                payload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($xml))
            } | ConvertTo-Json -Compress
        }
    }

    It 'streams every native PowerShell stream and one successful terminal frame' {
        $request = ConvertTo-TestProtocolRequest -CommandName Test-HHProtocolStreams `
            -Parameters @{ Verbose = $true; Debug = $true; InformationAction = 'Continue' }
        $result = Invoke-TestProtocol $request

        $result.ExitCode | Should -Be 0
        $result.StandardError | Should -BeNullOrEmpty
        @($result.Frames.type) | Should -Contain output
        @($result.Frames.type) | Should -Contain warning
        @($result.Frames.type) | Should -Contain verbose
        @($result.Frames.type) | Should -Contain debug
        @($result.Frames.type) | Should -Contain information
        @($result.Frames.type) | Should -Contain progress
        @($result.Frames | Where-Object type -EQ terminal) | Should -HaveCount 1
        ($result.Frames | Where-Object type -EQ terminal).status | Should -BeExactly succeeded
    }

    It 'ends a thrown command once with a failed terminal frame' {
        $result = Invoke-TestProtocol (
            ConvertTo-TestProtocolRequest -CommandName Test-HHProtocolFailure
        )

        $result.ExitCode | Should -Be 1
        @($result.Frames | Where-Object type -EQ error).Count | Should -BeGreaterOrEqual 1
        @($result.Frames | Where-Object type -EQ terminal) | Should -HaveCount 1
        ($result.Frames | Where-Object type -EQ terminal).status | Should -BeExactly failed
    }

    It 'rejects malformed input with a terminal failure rather than hanging' {
        $result = Invoke-TestProtocol '{"schema":"wrong"}'

        $result.ExitCode | Should -Be 1
        @($result.Frames | Where-Object type -EQ terminal) | Should -HaveCount 1
        ($result.Frames | Where-Object type -EQ terminal).message |
            Should -Match 'schema is unsupported'
    }
}
