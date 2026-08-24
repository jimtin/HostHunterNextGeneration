if ([string]::IsNullOrWhiteSpace($env:HH_TEST_MODULE_PATH)) {
    throw 'HH_TEST_MODULE_PATH is required for SQLite fault integration proof.'
}

Describe 'packaged SQLite process interruption recovery' -Tag Integration {
    BeforeAll {
        $script:workerPath = Join-Path $PSScriptRoot `
            '../fixtures/sqlite-fault/Invoke-SqliteFaultWorker.ps1'

        function Start-HHSqliteFaultProcess {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
                'PSUseShouldProcessForStateChangingFunctions', '',
                Justification = 'Starts only the bounded package integration-test worker.'
            )]
            [CmdletBinding()]
            param(
                [Parameter(Mandatory)][string]$Mode,
                [Parameter(Mandatory)][string]$DataRoot,
                [Parameter(Mandatory)][string]$ReceiptPath,
                [string]$CounterPath
            )

            $start = [Diagnostics.ProcessStartInfo]::new()
            $start.FileName = (Get-Command pwsh -ErrorAction Stop).Source
            $start.UseShellExecute = $false
            $start.RedirectStandardOutput = $true
            $start.RedirectStandardError = $true
            foreach ($argument in @(
                    '-NoLogo', '-NoProfile', '-NonInteractive', '-File', $script:workerPath,
                    '-ModulePath', $env:HH_TEST_MODULE_PATH, '-DataRoot', $DataRoot,
                    '-Mode', $Mode, '-ReceiptPath', $ReceiptPath
                )) { $null = $start.ArgumentList.Add($argument) }
            if (-not [string]::IsNullOrWhiteSpace($CounterPath)) {
                $null = $start.ArgumentList.Add('-CounterPath')
                $null = $start.ArgumentList.Add($CounterPath)
            }
            $process = [Diagnostics.Process]::new()
            $process.StartInfo = $start
            if (-not $process.Start()) { throw 'SQLite fault worker did not start.' }
            return $process
        }

        function Wait-HHSqliteFaultReceipt {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory)][string]$Path,
                [Parameter(Mandatory)][Diagnostics.Process]$Process
            )

            $deadline = [DateTimeOffset]::UtcNow.AddSeconds(20)
            while (-not [IO.File]::Exists($Path)) {
                if ($Process.HasExited) {
                    throw "SQLite fault worker exited early: $($Process.StandardError.ReadToEnd())"
                }
                if ([DateTimeOffset]::UtcNow -ge $deadline) {
                    throw 'SQLite fault worker receipt timed out.'
                }
                Start-Sleep -Milliseconds 50
            }
            return [IO.File]::ReadAllText($Path) | ConvertFrom-Json
        }

        function Stop-HHSqliteFaultProcess {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
                'PSUseShouldProcessForStateChangingFunctions', '',
                Justification = 'Kills only the explicitly tracked disposable test worker.'
            )]
            [CmdletBinding()]
            param([Parameter(Mandatory)][Diagnostics.Process]$Process)

            if (-not $Process.HasExited) { $Process.Kill($true) }
            $Process.WaitForExit(10000) | Should -BeTrue
            $Process.Dispose()
        }
    }

    It 'recovers a killed unarmed intent as failed and never dispatched' {
        $dataRoot = Join-Path $TestDrive 'unarmed'
        $readyPath = Join-Path $TestDrive 'unarmed-ready.json'
        $worker = Start-HHSqliteFaultProcess -Mode CreateUnarmed `
            -DataRoot $dataRoot -ReceiptPath $readyPath
        $ready = Wait-HHSqliteFaultReceipt -Path $readyPath -Process $worker
        $ready.ready | Should -BeTrue
        Stop-HHSqliteFaultProcess -Process $worker

        $recoveredPath = Join-Path $TestDrive 'unarmed-recovered.json'
        $recovery = Start-HHSqliteFaultProcess -Mode Recover `
            -DataRoot $dataRoot -ReceiptPath $recoveredPath
        $recovery.WaitForExit(20000) | Should -BeTrue
        $recovery.ExitCode | Should -Be 0
        $receipt = [IO.File]::ReadAllText($recoveredPath) | ConvertFrom-Json
        $receipt.Status | Should -BeExactly Failed
        $receipt.OutcomeStatus | Should -BeExactly Failed
        $receipt.DispatchState | Should -BeExactly NotDispatched
        $receipt.RecoveryState | Should -BeExactly RecoveredNotDispatched
        $receipt.RecoveryReceipts[0].InvocationId | Should -BeExactly $ready.invocationId
        $recovery.Dispose()
    }

    It 'recovers a killed armed intent as unknown without replaying the endpoint action' {
        $dataRoot = Join-Path $TestDrive 'armed'
        $readyPath = Join-Path $TestDrive 'armed-ready.json'
        $counterPath = Join-Path $TestDrive 'endpoint-count.txt'
        $worker = Start-HHSqliteFaultProcess -Mode CreateArmed `
            -DataRoot $dataRoot -ReceiptPath $readyPath -CounterPath $counterPath
        $ready = Wait-HHSqliteFaultReceipt -Path $readyPath -Process $worker
        $ready.ready | Should -BeTrue
        [IO.File]::ReadAllText($counterPath) | Should -BeExactly '1'
        Stop-HHSqliteFaultProcess -Process $worker

        $recoveredPath = Join-Path $TestDrive 'armed-recovered.json'
        $recovery = Start-HHSqliteFaultProcess -Mode Recover `
            -DataRoot $dataRoot -ReceiptPath $recoveredPath
        $recovery.WaitForExit(20000) | Should -BeTrue
        $recovery.ExitCode | Should -Be 0
        $receipt = [IO.File]::ReadAllText($recoveredPath) | ConvertFrom-Json
        $receipt.Status | Should -BeExactly Unknown
        $receipt.OutcomeStatus | Should -BeExactly Unknown
        $receipt.DispatchState | Should -BeExactly DispatchUncertain
        $receipt.RecoveryState | Should -BeExactly RecoveredDispatchUncertain
        [IO.File]::ReadAllText($counterPath) | Should -BeExactly '1'
        $recovery.Dispose()
    }

    It 'refuses a competing live operation owner without corrupting its receipt' {
        $dataRoot = Join-Path $TestDrive 'owner'
        $ownerPath = Join-Path $TestDrive 'owner.json'
        $owner = Start-HHSqliteFaultProcess -Mode HoldOperation `
            -DataRoot $dataRoot -ReceiptPath $ownerPath
        $null = Wait-HHSqliteFaultReceipt -Path $ownerPath -Process $owner

        $contenderPath = Join-Path $TestDrive 'contender.json'
        $contender = Start-HHSqliteFaultProcess -Mode HoldOperation `
            -DataRoot $dataRoot -ReceiptPath $contenderPath
        $contender.WaitForExit(20000) | Should -BeTrue
        $contender.ExitCode | Should -Be 1
        $receipt = [IO.File]::ReadAllText($contenderPath) | ConvertFrom-Json
        $receipt.ready | Should -BeFalse
        $receipt.errorId | Should -Match '^OperationBusy'
        $receipt.message | Should -Not -Match '(?i)(key|secret|token).*[0-9a-f]{32}'

        Stop-HHSqliteFaultProcess -Process $owner
        $contender.Dispose()
    }
}
