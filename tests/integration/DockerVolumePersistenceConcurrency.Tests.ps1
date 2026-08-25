BeforeAll {
    $sourceRoot = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
        Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration'
    }
    else { $env:HH_TEST_SOURCE_ROOT }
    $script:providerWorkerPath = [IO.Path]::GetFullPath((Join-Path `
                $PSScriptRoot '../helpers/Invoke-HHDockerVolumeProviderWorker.ps1'))
    $candidateModulePath = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_MODULE_PATH)) {
        Join-Path $sourceRoot 'HostHunterNextGeneration.psd1'
    }
    elseif ([IO.Directory]::Exists($env:HH_TEST_MODULE_PATH)) {
        Join-Path $env:HH_TEST_MODULE_PATH 'HostHunterNextGeneration.psd1'
    }
    else { $env:HH_TEST_MODULE_PATH }
    $script:providerModulePath = [IO.Path]::GetFullPath($candidateModulePath)

    function New-HHProviderWorkerProcess {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
            'PSUseShouldProcessForStateChangingFunctions',
            '',
            Justification = 'Starts an isolated integration-test worker process.'
        )]
        param(
            [Parameter(Mandatory)][object]$Roots,
            [Parameter(Mandatory)][string]$ReadyPath,
            [Parameter(Mandatory)][string]$StartPath,
            [Parameter(Mandatory)][string]$ResultPath,
            [Parameter(Mandatory)][ValidateSet('Initialize', 'Advance')][string]$Mode,
            [Parameter(Mandatory)][int]$Offset
        )

        $startInfo = [Diagnostics.ProcessStartInfo]::new()
        $startInfo.FileName = Join-Path $PSHOME 'pwsh'
        $startInfo.UseShellExecute = $false
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        foreach ($argument in @(
                '-NoLogo', '-NoProfile', '-NonInteractive',
                '-File', $script:providerWorkerPath,
                '-ModulePath', $script:providerModulePath,
                '-DataRoot', $Roots.Data,
                '-SecretRoot', $Roots.Secret,
                '-AnchorRoot', $Roots.Anchor,
                '-ReadyPath', $ReadyPath,
                '-StartPath', $StartPath,
                '-ResultPath', $ResultPath,
                '-Mode', $Mode,
                '-Offset', [string]$Offset
            )) {
            $startInfo.ArgumentList.Add($argument)
        }
        $process = [Diagnostics.Process]::new()
        $process.StartInfo = $startInfo
        if (-not $process.Start()) {
            throw 'A Docker-volume provider worker process could not start.'
        }
        return $process
    }

    function Wait-HHProviderWorkersReady {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)][Diagnostics.Process[]]$Process,
            [Parameter(Mandatory)][string[]]$ReadyPath
        )

        $deadline = [DateTime]::UtcNow.AddSeconds(15)
        while (@($ReadyPath | Where-Object { -not [IO.File]::Exists($_) }).Count -gt 0) {
            foreach ($worker in $Process) {
                if ($worker.HasExited) {
                    $errorText = $worker.StandardError.ReadToEnd()
                    throw "A provider worker exited before the barrier: $errorText"
                }
            }
            if ([DateTime]::UtcNow -ge $deadline) {
                throw 'Docker-volume provider workers did not reach the barrier.'
            }
            Start-Sleep -Milliseconds 20
        }
    }

    function Complete-HHProviderWorkerPhase {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
            'PSUseShouldProcessForStateChangingFunctions',
            '',
            Justification = 'Releases and joins isolated integration-test workers.'
        )]
        param(
            [Parameter(Mandatory)][Diagnostics.Process[]]$Process,
            [Parameter(Mandatory)][string]$StartPath
        )

        [IO.File]::WriteAllText($StartPath, 'START')
        foreach ($worker in $Process) {
            if (-not $worker.WaitForExit(20000)) {
                try { $worker.Kill($true) }
                catch { Write-Debug 'The timed-out provider worker was already stopped.' }
                throw 'A Docker-volume provider worker timed out.'
            }
            $standardOutput = $worker.StandardOutput.ReadToEnd()
            $standardError = $worker.StandardError.ReadToEnd()
            if ($worker.ExitCode -ne 0) {
                throw "A provider worker failed: $standardError $standardOutput"
            }
            $standardOutput | Should -BeNullOrEmpty
            $standardError | Should -BeNullOrEmpty
            $worker.Dispose()
        }
    }
}

Describe 'Docker-volume multiprocess persistence' -Tag Integration -Skip:(!$IsLinux) {
    It 'serializes atomic key creation and permits exactly one CAS winner per phase' {
        $prefix = [Guid]::NewGuid().ToString('N')
        $roots = [pscustomobject]@{
            Data = Join-Path $TestDrive "$prefix-data"
            Secret = Join-Path $TestDrive "$prefix-secret"
            Anchor = Join-Path $TestDrive "$prefix-anchor"
        }
        $directoryMode = [IO.UnixFileMode]::UserRead -bor
            [IO.UnixFileMode]::UserWrite -bor [IO.UnixFileMode]::UserExecute
        foreach ($path in @($roots.Data, $roots.Secret, $roots.Anchor)) {
            [IO.Directory]::CreateDirectory($path) | Out-Null
            [IO.File]::SetUnixFileMode($path, $directoryMode)
        }

        foreach ($phase in @('Initialize', 'Advance')) {
            $readyPaths = @(
                (Join-Path $TestDrive "$prefix-$phase-1.ready"),
                (Join-Path $TestDrive "$prefix-$phase-2.ready")
            )
            $resultPaths = @(
                (Join-Path $TestDrive "$prefix-$phase-1.result"),
                (Join-Path $TestDrive "$prefix-$phase-2.result")
            )
            $startPath = Join-Path $TestDrive "$prefix-$phase.start"
            $workers = @(
                (New-HHProviderWorkerProcess -Roots $roots `
                    -ReadyPath $readyPaths[0] -StartPath $startPath `
                    -ResultPath $resultPaths[0] -Mode $phase -Offset 1),
                (New-HHProviderWorkerProcess -Roots $roots `
                    -ReadyPath $readyPaths[1] -StartPath $startPath `
                    -ResultPath $resultPaths[1] -Mode $phase -Offset 2)
            )
            Wait-HHProviderWorkersReady -Process $workers -ReadyPath $readyPaths
            Complete-HHProviderWorkerPhase -Process $workers -StartPath $startPath
            $statuses = @($resultPaths | ForEach-Object {
                    [IO.File]::ReadAllText($_)
                })
            if ($phase -eq 'Initialize') {
                @($statuses | Where-Object { $_ -eq 'INITIALIZED' }).Count |
                    Should -Be 1
                @($statuses | Where-Object { $_ -eq 'DUPLICATE' }).Count |
                    Should -Be 1
            }
            else {
                @($statuses | Where-Object { $_ -eq 'ADVANCED' }).Count |
                    Should -Be 1
                @($statuses | Where-Object { $_ -eq 'STALE' }).Count |
                    Should -Be 1
            }
        }

        Get-ChildItem -LiteralPath $roots.Secret -Recurse -File |
            ForEach-Object {
                $_.UnixFileMode | Should -Be (
                    [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite
                )
            }
        Get-ChildItem -LiteralPath $roots.Anchor -Recurse -File |
            ForEach-Object {
                $_.UnixFileMode | Should -Be (
                    [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite
                )
            }
    }
}
