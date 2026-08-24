BeforeAll {
    $script:modulePath = if (-not [string]::IsNullOrWhiteSpace($env:HH_TEST_MODULE_PATH)) {
        (Resolve-Path -LiteralPath $env:HH_TEST_MODULE_PATH).Path
    }
    else {
        (Get-Content -LiteralPath /artifacts/build/module-path.txt -Raw).Trim()
    }
    $script:runtimeDirectory = $env:HH_SSH_RUNTIME_DIR
    $script:targetHost = $env:HH_SSH_HOST
    $script:targetPort = [int]$env:HH_SSH_PORT
    $script:userName = [IO.File]::ReadAllText(
        (Join-Path $script:runtimeDirectory 'username')
    ).Trim()
    $script:fingerprint = [IO.File]::ReadAllText(
        (Join-Path $script:runtimeDirectory 'hostkey.sha256')
    ).Trim()
    $env:DISPLAY = 'hosthunter-e2e'
    $env:SSH_ASKPASS = (Resolve-Path (
            Join-Path $PSScriptRoot '../fixtures/ssh/fixture-askpass.sh'
        )).Path
    $env:SSH_ASKPASS_REQUIRE = 'force'
    $env:HH_SSH_PASSWORD_FILE = Join-Path $script:runtimeDirectory 'password'
    Import-Module $script:modulePath -Force

    function Invoke-HHFreshPowerShell {
        param([Parameter(Mandatory)][string]$Script)

        $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Script))
        $output = @(& pwsh -NoLogo -NoProfile -NonInteractive `
                -EncodedCommand $encoded 2>&1)
        [pscustomobject]@{
            ExitCode = $LASTEXITCODE
            Output = $output
            Text = ($output | Out-String)
        }
    }

    function Get-HHFreshImportPrefix {
        "`$ErrorActionPreference='Stop'; Import-Module '$script:modulePath' -Force; "
    }
}

Describe 'packaged HostHunter SQLite operator journeys' -Tag E2E {
    It 'imports exactly eight public commands without creating local state' {
        $commands = @(Get-Command -Module HostHunterNextGeneration | Sort-Object Name)
        $commands.Name | Should -Be @(
            'Enable-HHSshKeyAuthentication'
            'Get-HHAuditOutput'
            'Get-HHAuditRecord'
            'Get-HHTarget'
            'Invoke-HHCommand'
            'Remove-HHTarget'
            'Set-HHTarget'
            'Test-HHTarget'
        )
        Test-Path -LiteralPath $env:HH_DATA_ROOT | Should -BeFalse
    }

    It 'returns empty targets, retests, and audit history without initializing state' {
        @(Get-HHTarget).Count | Should -Be 0
        @(Test-HHTarget).Count | Should -Be 0
        @(Get-HHAuditRecord).Count | Should -Be 0
        @(Get-HHAuditRecord -First 1).Count | Should -Be 0
        Test-Path -LiteralPath $env:HH_DATA_ROOT | Should -BeFalse
    }

    It 'rejects invalid command text before creating an intent or local state' {
        { Invoke-HHCommand -Command 'if (' } |
            Should -Throw '*Command text is not valid PowerShell*'
        Test-Path -LiteralPath $env:HH_DATA_ROOT | Should -BeFalse
    }

    It 'previews target creation and WinRM refusal without creating state' {
        Set-HHTarget -Name alpha -HostName $script:targetHost `
            -Port $script:targetPort -UserName $script:userName `
            -HostKeyFingerprint $script:fingerprint -WhatIf
        {
            Set-HHTarget -Name windows -HostName windows.test -UserName operator `
                -Transport WinRM -Authentication Kerberos -Confirm:$false
        } | Should -Throw '*WinRM target creation is deferred*'
        Test-Path -LiteralPath $env:HH_DATA_ROOT | Should -BeFalse
    }

    It 'validates and saves a password target through the real SSH fixture' {
        $target = Set-HHTarget -Name alpha -HostName $script:targetHost `
            -Port $script:targetPort -UserName $script:userName `
            -HostKeyFingerprint $script:fingerprint -Confirm:$false
        $target.Name | Should -BeExactly alpha
        $target.Authentication | Should -BeExactly Password
        $target.PowerShellRuntime | Should -BeExactly PowerShell7
        $target.LastValidatedPSEdition | Should -BeExactly Core
        Test-Path -LiteralPath (Join-Path $env:HH_DATA_ROOT 'hosthunter.db') |
            Should -BeTrue
        foreach ($legacy in @('targets.json', 'audit/ledger.jsonl', 'audit/ledger.head.json')) {
            Test-Path -LiteralPath (Join-Path $env:HH_DATA_ROOT $legacy) | Should -BeFalse
        }
    }

    It 'reloads the authenticated target in a fresh PowerShell process' {
        $fresh = Invoke-HHFreshPowerShell -Script (
            (Get-HHFreshImportPrefix) +
            "`$target=Get-HHTarget -Name alpha; `$target | ConvertTo-Json -Compress"
        )
        $fresh.ExitCode | Should -Be 0
        $target = $fresh.Output[-1] | ConvertFrom-Json
        $target.Name | Should -BeExactly alpha
        $target.Authentication | Should -BeExactly Password
    }

    It 'previews runtime-distinct profiles and removal without changing authenticated state' {
        $beforeTargets = @((Get-HHTarget) | ConvertTo-Json -Depth 8 -Compress)
        $beforeAudit = @((Get-HHAuditRecord -First 100).Sequence)
        $profiles = @(
            [pscustomobject]@{
                Name = 'preview-ps7'; Transport = 'SSH'; HostName = $script:targetHost
                Port = $script:targetPort; UserName = $script:userName
                Authentication = 'Password'; PowerShellRuntime = 'PowerShell7'
                HostKeyFingerprint = $script:fingerprint
            }
            [pscustomobject]@{
                Name = 'preview-ps51'; Transport = 'SSH'; HostName = $script:targetHost
                Port = $script:targetPort; UserName = $script:userName
                Authentication = 'Password'; PowerShellRuntime = 'WindowsPowerShell51'
                HostKeyFingerprint = $script:fingerprint
            }
        )
        $null = $profiles | Set-HHTarget -WhatIf
        Remove-HHTarget -Name alpha -WhatIf
        @((Get-HHTarget) | ConvertTo-Json -Depth 8 -Compress) |
            Should -BeExactly $beforeTargets
        @((Get-HHAuditRecord -First 100).Sequence) | Should -Be $beforeAudit
    }

    It 'rejects duplicate and over-limit proposals without changing saved targets' {
        $before = @((Get-HHTarget) | ConvertTo-Json -Depth 8 -Compress)
        {
            Set-HHTarget -Name @('duplicate', 'DUPLICATE') `
                -HostName @($script:targetHost, 'ssh-target-alt') `
                -UserName @($script:userName, $script:userName) `
                -HostKeyFingerprint @($script:fingerprint, $script:fingerprint) -WhatIf
        } | Should -Throw
        {
            Set-HHTarget -Name (1..9 | ForEach-Object { "target-$_" }) `
                -HostName (1..9 | ForEach-Object { $script:targetHost }) `
                -UserName (1..9 | ForEach-Object { $script:userName }) -WhatIf
        } | Should -Throw
        @((Get-HHTarget) | ConvertTo-Json -Depth 8 -Compress) |
            Should -BeExactly $before
    }

    It 'displays targets without the local key but refuses remote authority' {
        $keyPath = Join-Path $env:HH_DATA_ROOT 'audit/audit.key'
        $heldKeyPath = "$keyPath.e2e-held"
        [IO.File]::Move($keyPath, $heldKeyPath, $false)
        try {
            $warnings = @()
            $visible = @(Get-HHTarget -WarningVariable warnings)
            $visible.Count | Should -Be 1
            $visible[0].Name | Should -BeExactly alpha
            ($warnings | Out-String) | Should -Match 'cannot be authenticated'
            { Test-HHTarget -Name alpha } | Should -Throw '*audit key*'
            { Invoke-HHCommand -Command "'must-not-run'" -Target alpha } |
                Should -Throw '*audit key*'
        }
        finally {
            [IO.File]::Move($heldKeyPath, $keyPath, $false)
        }
    }

    It 'revalidates the saved target without changing its profile' {
        $before = Get-HHTarget -Name alpha
        $result = Test-HHTarget -Name alpha
        $after = Get-HHTarget -Name alpha
        $result.Succeeded | Should -BeTrue
        $result.RemotePSEdition | Should -BeExactly Core
        ($before | ConvertTo-Json -Depth 8 -Compress) |
            Should -BeExactly ($after | ConvertTo-Json -Depth 8 -Compress)
    }

    It 'runs complete command text and records every PowerShell stream' {
        $script:commandText = @'
Write-Output 'output-value'
Write-Warning 'warning-value'
Write-Verbose 'verbose-value' -Verbose
Write-Debug 'debug-value' -Debug
Write-Information 'information-value' -InformationAction Continue
Write-Error 'nonterminating-error' -ErrorAction Continue
'@
        $script:commandResult = Invoke-HHCommand -Command $script:commandText `
            -Target alpha -Reason troubleshooting -CaseId CASE-SQLITE-001
        $script:commandResult.Succeeded | Should -BeTrue
        $script:commandResult.DispatchState | Should -BeExactly Completed
        @($script:commandResult.StreamEvents).Count | Should -BeGreaterOrEqual 6
        @($script:commandResult.StreamEvents.Stream | Sort-Object -Unique) |
            Should -Be @('Debug', 'Error', 'Information', 'Output', 'Verbose', 'Warning')
    }

    It 'supports bounded, cursor, target, operation, status, case, and time audit queries' {
        $records = @(Get-HHAuditRecord -First 100)
        $records.Count | Should -BeGreaterThan 1
        @($records.Sequence) | Should -Be @($records.Sequence | Sort-Object -Descending)
        $newest = $records[0]
        $older = @(Get-HHAuditRecord -BeforeSequence $newest.Sequence -First 100)
        @($older.Sequence) | Should -Not -Contain $newest.Sequence
        @(Get-HHAuditRecord -TargetName ALPHA -First 100).Count |
            Should -BeGreaterThan 0
        @(Get-HHAuditRecord -Operation InvokeCommand -Status Succeeded -First 100).Count |
            Should -BeGreaterThan 0
        @(Get-HHAuditRecord -CaseId CASE-SQLITE-001 -First 100).Count | Should -Be 1
        $from = [DateTimeOffset]::Parse($records[-1].IntentAtUtc).AddSeconds(-1)
        $to = [DateTimeOffset]::Parse($records[0].IntentAtUtc).AddSeconds(1)
        @(Get-HHAuditRecord -FromUtc $from -ToUtc $to -First 100).Count |
            Should -Be $records.Count
        { Get-HHAuditRecord -First 0 } | Should -Throw
        { Get-HHAuditRecord -First 1001 } | Should -Throw
    }

    It 'queries exact command and context without writing another audit event' {
        $before = @(Get-HHAuditRecord -First 100)
        $record = @(Get-HHAuditRecord -InvocationId $script:commandResult.InvocationId `
                -CaseId CASE-SQLITE-001 -Operation InvokeCommand -Status Succeeded -First 1)[0]
        $record.CommandText | Should -BeExactly $script:commandText
        $record.Reason | Should -BeExactly troubleshooting
        $record.CaseId | Should -BeExactly CASE-SQLITE-001
        $record.TargetName | Should -BeExactly alpha
        $after = @(Get-HHAuditRecord -First 100)
        $after.Count | Should -Be $before.Count
        $after[0].Sequence | Should -Be $before[0].Sequence
    }

    It 'retrieves complete ordered output after a fresh process restart' {
        $fresh = Invoke-HHFreshPowerShell -Script (
            (Get-HHFreshImportPrefix) +
            "`$events=@(Get-HHAuditOutput -InvocationId '$($script:commandResult.InvocationId)'); " +
            "[pscustomobject]@{Count=`$events.Count;Streams=@(`$events.Stream)} | ConvertTo-Json -Compress"
        )
        $fresh.ExitCode | Should -Be 0
        $receipt = $fresh.Output[-1] | ConvertFrom-Json
        $receipt.Count | Should -BeGreaterOrEqual 6
        @($receipt.Streams | Sort-Object -Unique) |
            Should -Be @('Debug', 'Error', 'Information', 'Output', 'Verbose', 'Warning')
    }

    It 'converts the password profile to a separately proven SSH key profile' {
        $before = @((Get-HHTarget -Name alpha) | ConvertTo-Json -Depth 8 -Compress)
        $null = Enable-HHSshKeyAuthentication -Name alpha -WhatIf
        @((Get-HHTarget -Name alpha) | ConvertTo-Json -Depth 8 -Compress) |
            Should -BeExactly $before
        $transition = Enable-HHSshKeyAuthentication -Name alpha -Confirm:$false
        $transition.Authentication | Should -BeExactly PublicKey
        $transition.KeyPath | Should -Not -BeNullOrEmpty
        (Get-HHTarget -Name alpha).Authentication | Should -BeExactly PublicKey
    }

    It 'uses the proven key profile for a subsequent command' {
        $result = Invoke-HHCommand -Command "'key-authenticated'" -Target alpha
        $result.Succeeded | Should -BeTrue
        @($result.StreamEvents | Where-Object {
                $_.Stream -eq 'Output' -and $_.Phase -eq 'Command'
            })[0].Value |
            Should -BeExactly key-authenticated
    }

    It 'removes the target atomically and preserves queryable audit history' {
        @(Remove-HHTarget -Name alpha -Confirm:$false).Count | Should -Be 0
        @(Get-HHTarget).Count | Should -Be 0
        { Invoke-HHCommand -Command 'Get-Date' -Target alpha } |
            Should -Throw '*Unknown target*'
        @(Get-HHAuditRecord -TargetName alpha -First 100).Count |
            Should -BeGreaterThan 0
    }

    It 'fails closed for unknown audit output and leaves legacy persistence absent' {
        { Get-HHAuditOutput -InvocationId ('f' * 32) } |
            Should -Throw '*No audit invocation exists*'
        foreach ($legacy in @('targets.json', 'audit/ledger.jsonl', 'audit/ledger.head.json')) {
            Test-Path -LiteralPath (Join-Path $env:HH_DATA_ROOT $legacy) | Should -BeFalse
        }
    }
}
