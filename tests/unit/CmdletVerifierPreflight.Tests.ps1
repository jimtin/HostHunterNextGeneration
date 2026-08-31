Describe 'cmdlet verifier preflight' -Tag Unit {
    BeforeAll {
        $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        . (Join-Path $script:repoRoot 'tests/e2e/HHCmdletVerifierSupport.ps1')
        $script:modulePath = Join-Path $script:repoRoot `
            'src/HostHunterNextGeneration/HostHunterNextGeneration.psd1'
        $script:orderedJourney = @(Get-HHCmdletVerifierManifestCommand `
                -ModulePath $script:modulePath)
    }

    BeforeEach {
        $script:dataRoot = Join-Path $TestDrive ([Guid]::NewGuid().ToString('N') + '-data')
        $script:runtimeRoot = Join-Path $TestDrive ([Guid]::NewGuid().ToString('N') + '-runtime')
        $script:receiptPath = Join-Path $TestDrive (
            [Guid]::NewGuid().ToString('N') + '/cmdlets/receipt.json'
        )
        [IO.Directory]::CreateDirectory((Join-Path $script:dataRoot 'keys')) | Out-Null
        [IO.Directory]::CreateDirectory($script:runtimeRoot) | Out-Null
        [IO.File]::WriteAllText((Join-Path $script:runtimeRoot 'username'), 'hhfixture')
        [IO.File]::WriteAllText(
            (Join-Path $script:runtimeRoot 'hostkey.sha256'),
            ('SHA256:' + ('A' * 43))
        )
        [IO.File]::WriteAllText(
            (Join-Path $script:runtimeRoot 'password'),
            'HH-PREFLIGHT-SECRET-CANARY'
        )
    }

    It 'proves the manifest, migrations, fixture access and receipt write without exposing the password' {
        $result = Invoke-HHCmdletVerifierPreflight `
            -ModulePath $script:modulePath `
            -OrderedJourney $script:orderedJourney `
            -DataRoot $script:dataRoot `
            -RuntimeDirectory $script:runtimeRoot `
            -ReceiptPath $script:receiptPath

        $result.ExpectedCommands | Should -Be $script:orderedJourney
        $result.MigrationCount | Should -BeGreaterThan 0
        $result.UserName | Should -BeExactly hhfixture
        $result.PSObject.Properties.Name | Should -Not -Contain Password
        ($result | ConvertTo-Json -Depth 4) | Should -Not -Match 'HH-PREFLIGHT-SECRET-CANARY'
        @(Get-ChildItem -LiteralPath (Split-Path -Parent $script:receiptPath) -Force) |
            Should -HaveCount 0
    }

    It 'fails before module import when the ordered journey drifts from the manifest' {
        {
            Invoke-HHCmdletVerifierPreflight `
                -ModulePath $script:modulePath `
                -OrderedJourney @('Get-HHTarget') `
                -DataRoot $script:dataRoot `
                -RuntimeDirectory $script:runtimeRoot `
                -ReceiptPath $script:receiptPath
        } | Should -Throw '*ordered journey does not match*'
    }

    It 'returns a precise non-secret fixture error' {
        [IO.File]::WriteAllText((Join-Path $script:runtimeRoot 'hostkey.sha256'), 'invalid')
        $message = $null
        try {
            Invoke-HHCmdletVerifierPreflight `
                -ModulePath $script:modulePath `
                -OrderedJourney $script:orderedJourney `
                -DataRoot $script:dataRoot `
                -RuntimeDirectory $script:runtimeRoot `
                -ReceiptPath $script:receiptPath
        }
        catch { $message = $_.Exception.Message }
        $message | Should -BeExactly 'The SSH fixture fingerprint is invalid.'
        $message | Should -Not -Match 'HH-PREFLIGHT-SECRET-CANARY'
    }

    It 'emits a precise preflight receipt before any cmdlet when fixture setup is unavailable' {
        $journey = Join-Path $script:repoRoot 'tests/e2e/TargetAndCommandJourneys.Tests.ps1'
        $missingRuntime = Join-Path $TestDrive 'missing-runtime'
        $receipt = Join-Path $TestDrive 'preflight-failure/receipt.json'
        $names = @(
            'HH_RUNTIME_MODULE_PATH', 'HH_DATA_ROOT', 'HH_SSH_RUNTIME_DIR',
            'HH_CMDLET_RECEIPT', 'HH_SOURCE_SHA', 'HH_SOURCE_FINGERPRINT',
            'HH_CMDLET_RUN_ID', 'HH_DIRTY_TREE', 'HH_VERIFIER_IMAGE_ID'
        )
        $previous = @{}
        foreach ($name in $names) { $previous[$name] = [Environment]::GetEnvironmentVariable($name) }
        try {
            $env:HH_RUNTIME_MODULE_PATH = $script:modulePath
            $env:HH_DATA_ROOT = $script:dataRoot
            $env:HH_SSH_RUNTIME_DIR = $missingRuntime
            $env:HH_CMDLET_RECEIPT = $receipt
            $env:HH_SOURCE_SHA = '0123456789abcdef0123456789abcdef01234567'
            $env:HH_SOURCE_FINGERPRINT = ('a' * 64)
            $env:HH_CMDLET_RUN_ID = 'focused-preflight-receipt'
            $env:HH_DIRTY_TREE = 'true'
            $env:HH_VERIFIER_IMAGE_ID = 'sha256:' + ('b' * 64)
            $null = @(& pwsh -NoLogo -NoProfile -NonInteractive -File $journey 2>&1)
            $LASTEXITCODE | Should -Be 1
        }
        finally {
            foreach ($name in $names) {
                [Environment]::SetEnvironmentVariable($name, $previous[$name])
            }
        }

        $result = Get-Content -LiteralPath $receipt -Raw | ConvertFrom-Json -Depth 20
        $result.status | Should -BeExactly failed
        $result.failurePhase | Should -BeExactly preflight
        $result.infrastructureFailure | Should -Match 'mounted non-symlink directory'
        $result.sourceFingerprint | Should -BeExactly ('a' * 64)
        $result.runId | Should -BeExactly focused-preflight-receipt
        @($result.rows) | Should -HaveCount $script:orderedJourney.Count
        @($result.rows.status | Sort-Object -Unique) | Should -Be @('not-run')
        [IO.File]::Exists((Join-Path $script:dataRoot 'hosthunter.db')) | Should -BeFalse
    }
}
