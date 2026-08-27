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
function Test-HHProtocolConfirmation {
    [CmdletBinding()]
    param()
    $client = [Net.Sockets.TcpClient]::new('127.0.0.1', [int]$env:HH_CLIENT_BROKER_PORT)
    try {
        $stream = $client.GetStream()
        $reader = [IO.StreamReader]::new($stream, [Text.Encoding]::UTF8, $false, 1024, $true)
        $writer = [IO.StreamWriter]::new($stream, [Text.UTF8Encoding]::new($false), 1024, $true)
        $writer.AutoFlush = $true
        $prompt = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('Trust fixture?'))
        $writer.WriteLine($env:HH_CLIENT_BROKER_TOKEN)
        $writer.WriteLine('confirmation')
        $writer.WriteLine($prompt)
        if ($reader.ReadLine() -cne 'yes') { throw 'confirmation declined' }
        'confirmed'
    }
    finally { $client.Dispose() }
}
function Test-HHProtocolSeededCredential {
    [CmdletBinding()]
    param()
    function Invoke-BrokerRequest([string]$Kind, [string]$Value) {
        $client = [Net.Sockets.TcpClient]::new('127.0.0.1', [int]$env:HH_CLIENT_BROKER_PORT)
        try {
            $stream = $client.GetStream()
            $reader = [IO.StreamReader]::new($stream, [Text.Encoding]::UTF8, $false, 1024, $true)
            $writer = [IO.StreamWriter]::new($stream, [Text.UTF8Encoding]::new($false), 1024, $true)
            $writer.AutoFlush = $true
            $writer.WriteLine($env:HH_CLIENT_BROKER_TOKEN)
            $writer.WriteLine($Kind)
            $writer.WriteLine($Value)
            $reader.ReadLine()
        }
        finally { $client.Dispose() }
    }
    $secret = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('seeded-fixture'))
    if ((Invoke-BrokerRequest credential_seed $secret) -cne 'ok') { throw 'seed failed' }
    $prompt = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('Password?'))
    $restored = Invoke-BrokerRequest credential_acquire $prompt
    if ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($restored)) -cne
        'seeded-fixture') { throw 'restored credential mismatch' }
    'credential-restored-without-client-prompt'
}
Export-ModuleMember -Function Test-HHProtocolStreams, Test-HHProtocolFailure, `
    Test-HHProtocolConfirmation, Test-HHProtocolSeededCredential
'@)
        New-ModuleManifest -Path (Join-Path $moduleRoot 'HostHunterNextGeneration.psd1') `
            -RootModule HostHunterNextGeneration.psm1 -ModuleVersion 1.0.0 `
            -FunctionsToExport Test-HHProtocolStreams, Test-HHProtocolFailure, `
                Test-HHProtocolConfirmation, Test-HHProtocolSeededCredential

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

        function Invoke-TestConfirmationProtocol {
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
                $process.StandardInput.WriteLine((
                        ConvertTo-TestProtocolRequest -CommandName Test-HHProtocolConfirmation
                    ))
                $process.StandardInput.Flush()
                $confirmation = $process.StandardOutput.ReadLine() | ConvertFrom-Json
                $confirmation.type | Should -BeExactly confirmation_request
                [Text.Encoding]::UTF8.GetString(
                    [Convert]::FromBase64String([string]$confirmation.prompt)
                ) | Should -BeExactly 'Trust fixture?'
                $process.StandardInput.WriteLine('confirmation yes')
                $process.StandardInput.Close()
                $remaining = $process.StandardOutput.ReadToEnd()
                $stderr = $process.StandardError.ReadToEnd()
                if (-not $process.WaitForExit(15000)) {
                    $process.Kill($true)
                    throw 'Interactive protocol test process exceeded 15 seconds.'
                }
                [pscustomobject]@{
                    ExitCode = $process.ExitCode
                    StandardError = $stderr
                    Frames = @($remaining -split "`n" | Where-Object {
                            -not [string]::IsNullOrWhiteSpace($_)
                        } | ForEach-Object { $_ | ConvertFrom-Json -Depth 20 })
                }
            }
            finally { $process.Dispose() }
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
        $terminal = $result.Frames | Where-Object type -EQ terminal
        $terminal.status | Should -BeExactly failed
        $terminal.message | Should -BeExactly protocol-failure
        $terminal.message | Should -Not -Match 'EndInvoke'
    }

    It 'rejects malformed input with a terminal failure rather than hanging' {
        $result = Invoke-TestProtocol '{"schema":"wrong"}'

        $result.ExitCode | Should -Be 1
        @($result.Frames | Where-Object type -EQ terminal) | Should -HaveCount 1
        ($result.Frames | Where-Object type -EQ terminal).message |
            Should -Match 'schema is unsupported'
    }

    It 'round trips a bounded confirmation independently from credentials' {
        $result = Invoke-TestConfirmationProtocol

        $result.ExitCode | Should -Be 0
        $result.StandardError | Should -BeNullOrEmpty
        @($result.Frames | Where-Object type -EQ output) | Should -HaveCount 1
        @($result.Frames | Where-Object type -EQ terminal) | Should -HaveCount 1
        ($result.Frames | Where-Object type -EQ terminal).status | Should -BeExactly succeeded
    }

    It 'uses a seeded broker credential without requesting it from the macOS client' {
        $result = Invoke-TestProtocol (
            ConvertTo-TestProtocolRequest -CommandName Test-HHProtocolSeededCredential
        )

        $result.ExitCode | Should -Be 0
        @($result.Frames | Where-Object type -EQ credential_request) | Should -HaveCount 0
        @($result.Frames | Where-Object type -EQ output) | Should -HaveCount 1
        $payload = [string](
            $result.Frames | Where-Object type -EQ output
        ).payload
        $xml = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload))
        [Management.Automation.PSSerializer]::Deserialize($xml) |
            Should -BeExactly 'credential-restored-without-client-prompt'
        ($result.Frames | ConvertTo-Json -Compress -Depth 20) |
            Should -Not -Match 'seeded-fixture'
    }
}
