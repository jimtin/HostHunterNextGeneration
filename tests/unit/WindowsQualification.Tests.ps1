BeforeAll {
    $script:qualificationPath = Join-Path $PSScriptRoot `
        '../../scripts/qualification/Test-HHWindowsController.ps1'
    $script:qualificationSource = Get-Content -LiteralPath $script:qualificationPath -Raw
    $script:qualificationAst = [Management.Automation.Language.Parser]::ParseFile(
        $script:qualificationPath,
        [ref]$null,
        [ref]$null
    )
}

Describe 'Windows exact-package qualification contract' -Tag Unit {
    It 'emits Debug without enabling the interactive Debug common parameter' {
        $streamHereString = [regex]::Match(
            $script:qualificationSource,
            '(?s)\$streamCommand\s*=\s*@''(?<body>.*?)''@'
        )

        $streamHereString.Success | Should -BeTrue
        $streamHereString.Groups['body'].Value |
            Should -Match '\$DebugPreference\s*=\s*''Continue'''
        $streamHereString.Groups['body'].Value | Should -Match "Write-Debug\s+'debug'"
        $streamHereString.Groups['body'].Value | Should -Not -Match 'Write-Debug[^\r\n]*-Debug'

        foreach ($streamCommand in @(
                "Write-Output 'output'",
                "Write-Warning 'warning'",
                "Write-Verbose 'verbose' -Verbose",
                "Write-Information 'information' -InformationAction Continue",
                "Write-Error 'error' -ErrorAction Continue"
            )) {
            $streamHereString.Groups['body'].Value | Should -Match ([regex]::Escape($streamCommand))
        }
    }

    It 'uses one finite redacted marker pair for every qualification phase' {
        $expectedPhases = @(
            'NativePackage',
            'TargetValidation',
            'DirectPowerShell7',
            'DirectWindowsPowerShell51',
            'MixedRuntime',
            'WindowsProcessAuditPolicy',
            'SshKeyBootstrap',
            'AgentKeyProof',
            'PasswordRecovery',
            'Cleanup'
        )
        $markerCalls = @($script:qualificationAst.FindAll({
                    param($Node)
                    $Node -is [Management.Automation.Language.CommandAst] -and
                    $Node.GetCommandName() -ceq 'Write-HHQualificationPhase'
                }, $true))

        $markerCalls.Count | Should -Be ($expectedPhases.Count * 2)
        foreach ($phase in $expectedPhases) {
            @($markerCalls | Where-Object {
                    $_.Extent.Text -cmatch "-Phase\s+$phase\s+-Status\s+Started"
                }).Count | Should -Be 1
            @($markerCalls | Where-Object {
                    $_.Extent.Text -cmatch "-Phase\s+$phase\s+-Status\s+Passed"
                }).Count | Should -Be 1
        }

        $markerFunctions = @($script:qualificationAst.FindAll({
                param($Node)
                $Node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                $Node.Name -ceq 'Write-HHQualificationPhase'
            }, $true))
        $markerFunctions.Count | Should -Be 1
        $markerFunction = $markerFunctions[0]
        $markerFunction.Extent.Text |
            Should -Match 'HH_QUALIFICATION_PHASE\|\$Phase\|\$Status'
        $markerFunction.Extent.Text |
            Should -Not -Match '(?i)HostKey|UserName|SshHost|Fingerprint|CommandText'
    }

    It 'qualifies both requested runtimes and forbids runtime fallback' {
        $script:qualificationSource |
            Should -Match 'PowerShellRuntime\s+PowerShell7'
        $script:qualificationSource |
            Should -Match 'PowerShellRuntime\s+WindowsPowerShell51'
        $script:qualificationSource |
            Should -Match 'Assert-HHRuntimeResult\s+-Result\s+\$directResult\s+-Runtime\s+PowerShell7'
        $script:qualificationSource |
            Should -Match 'Assert-HHRuntimeResult\s+-Result\s+\$compatibilityResult\s+-Runtime\s+WindowsPowerShell51'
        $script:qualificationSource | Should -Not -Match '(?i)fallback'
    }

    It 'makes PowerShell cleanup commands explicitly noninteractive' {
        $cleanupCommands = @($script:qualificationAst.FindAll({
                    param($Node)
                    $Node -is [Management.Automation.Language.CommandAst] -and
                    $Node.GetCommandName() -cin @(
                        'Remove-HHTarget',
                        'Remove-Item',
                        'Remove-Module'
                    )
                }, $true))

        $cleanupCommands.Count | Should -BeGreaterThan 0
        foreach ($cleanupCommand in $cleanupCommands) {
            $cleanupCommand.Extent.Text | Should -Match '-Confirm:\$false'
        }
    }

    It 'uses a run-scoped agent without passing a secret through process configuration' {
        $bootstrapCalls = @($script:qualificationAst.FindAll({
                    param($Node)
                    $Node -is [Management.Automation.Language.CommandAst] -and
                    $Node.GetCommandName() -ceq 'Enable-HHSshKeyAuthentication'
                }, $true))
        $bootstrapCalls.Count | Should -Be 1
        $bootstrapCalls[0].Extent.Text | Should -Not -Match '-KeyPath|-UseExistingKey'

        $script:qualificationSource |
            Should -Match "-FileName '/usr/bin/ssh-agent'\s+``?\r?\n\s+-ArgumentList @\('-s'\)"
        $script:qualificationSource |
            Should -Match '-FileName ''/usr/bin/ssh-add''\s+`?\r?\n\s+-ArgumentList @\(\$transition.KeyPath\)'
        $script:qualificationSource |
            Should -Match '-ArgumentList @\(''-d'', \[string\]\$transition.KeyPath\)'
        $script:qualificationSource |
            Should -Match "-FileName '/usr/bin/ssh-agent' -ArgumentList @\('-k'\)"
        $script:qualificationSource |
            Should -Match '\$env:SSH_AUTH_SOCK = \$originalSshAuthSock'
        $script:qualificationSource |
            Should -Match '\$env:SSH_AGENT_PID = \$originalSshAgentPid'

        $nativeProcessCalls = @($script:qualificationAst.FindAll({
                    param($Node)
                    $Node -is [Management.Automation.Language.CommandAst] -and
                    $Node.GetCommandName() -ceq 'Invoke-HHInteractiveNativeProcess'
                }, $true))
        foreach ($nativeProcessCall in $nativeProcessCalls) {
            $nativeProcessCall.Extent.Text |
                Should -Not -Match '(?is)-ArgumentList.*\$[A-Za-z0-9_]*(Password|Passphrase|Secret)'
        }
        $script:qualificationSource |
            Should -Not -Match '(?i)\$env:[A-Za-z0-9_]*(Password|Passphrase|Secret)'
    }

    It 'derives and post-verifies both exact Keychain cleanup items' {
        $script:qualificationSource |
            Should -Not -Match 'com\.hosthunter\.nextgeneration\.audit-master-key'
        $script:qualificationSource |
            Should -Match 'AuditService\s*=\s*\$script:HHAuditKeychainService'
        $script:qualificationSource |
            Should -Match 'AnchorService\s*=\s*\$script:HHPersistenceAnchorKeychainService'

        $cleanupBlock = [regex]::Match(
            $script:qualificationSource,
            '(?s)\$keychainItems\s*=\s*@\(.*?\$cleanupComplete\s*=\s*\$true'
        )
        $cleanupBlock.Success | Should -BeTrue
        $cleanupBlock.Value | Should -Match (
            '(?s)Test-HHQualificationSecurityItem.*?' +
            'Invoke-HHQualificationSecurityDelete'
        )
        $cleanupBlock.Value | Should -Match (
            '(?s)Invoke-HHQualificationSecurityDelete.*?' +
            'Test-HHQualificationSecurityItem'
        )
    }

    It 'uses an explicit successful noninteractive password-recovery command' {
        $script:qualificationSource | Should -Match (
            "'pwsh', '-NoLogo', '-NoProfile', '-NonInteractive', '-Command',\s*" +
            "'Write-Output HH_PASSWORD_AUTH_STILL_ENABLED; exit 0'"
        )
        $script:qualificationSource |
            Should -Not -Match '"''HH_PASSWORD_AUTH_STILL_ENABLED''"'
    }

    It 'qualifies process auditing on both runtimes and restores the starting state' {
        $script:qualificationSource | Should -Match (
            '(?s)' +
            'Set-HHWindowsProcessAuditPolicy\s+-State\s+Enabled.*?' +
            '-Target\s+windows-ps7\s+-Escalate'
        )
        $script:qualificationSource | Should -Match (
            '(?s)Set-HHWindowsProcessAuditPolicy\s+-State\s+Enabled.*?' +
            '-Target\s+windows-ps51\s+-Escalate'
        )
        $script:qualificationSource |
            Should -Match 'Set-HHEscalationPreference\s+-Method\s+WindowsTokenPrivilege'
        $script:qualificationSource |
            Should -Match '(?s)Invoke-HHWindowsProcessAuditEventProbe.*?-ExpectCommandLine\s+\$true'
        $script:qualificationSource |
            Should -Match '(?s)Invoke-HHWindowsProcessAuditEventProbe.*?-ExpectCommandLine\s+\$false'
        $script:qualificationSource |
            Should -Match '(?s)finally\s*\{.*?Set-HHWindowsProcessAuditPolicy\s+-State\s+\$restoreAuditState'
        $script:qualificationSource | Should -Match (
            '(?s)finally\s*\{.*?' +
            'Set-HHWindowsProcessAuditPolicy\s+-State\s+\$restoreAuditState.*?' +
            '-Target\s+windows-ps51\s+-Escalate.*?' +
            'Assert-HHWindowsProcessAuditPolicyResult\s+.*?' +
            '-Result\s+\$restoreResult\s+-Runtime\s+WindowsPowerShell51'
        )
        $script:qualificationSource |
            Should -Match 'processAuditPolicyRestored\s*=\s*\$processAuditPolicyRestored'
    }

    It 'polls event 4688 by process identity without persisting command-line content' {
        $script:qualificationSource | Should -Match "Id\s*=\s*4688"
        $script:qualificationSource | Should -Match "\['NewProcessId'\]"
        $script:qualificationSource | Should -Match "\['ProcessId'\]"
        $script:qualificationSource | Should -Match '\$creatorProcessId\s*=\s*\$PID'
        $script:qualificationSource | Should -Match (
            'ToInt64\(\$eventCreatorProcessId\.Substring\(2\),\s*16\)\s*-eq\s*' +
            '\$creatorProcessId'
        )
        $script:qualificationSource | Should -Match 'AddSeconds\(30\)'
        $script:qualificationSource | Should -Match (
            'HostHunter\.WindowsProcessAuditEventProbe\.v1'
        )
        $receiptBlock = [regex]::Match(
            $script:qualificationSource,
            '(?s)\[ordered\]@\{\s*status\s*=\s*''passed''.*?\}\s*\|\s*ConvertTo-Json'
        )
        $receiptBlock.Success | Should -BeTrue
        $receiptBlock.Value | Should -Not -Match '(?i)CommandLine(Content|Text|Value)'
        $receiptBlock.Value | Should -Not -Match '(?i)MarkerProcessId|NewProcessId'
    }
}
