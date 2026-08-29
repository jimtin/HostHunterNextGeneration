BeforeAll {
    $script:repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    $script:qualificationPath = Join-Path `
        $script:repositoryRoot 'scripts/qualification/Test-HHWindowsCmdlets.ps1'
    $script:source = Get-Content -LiteralPath $script:qualificationPath -Raw
    $script:wrapper = Get-Content -LiteralPath (Join-Path `
        $script:repositoryRoot 'scripts/qualification/windows-cmdlets.sh') -Raw
}

Describe 'Live Windows cmdlet qualification contract' -Tag Unit {
    It 'records exactly one row for every exported cmdlet' {
        foreach ($cmdlet in @(
                'Get-HHTarget', 'Set-HHTarget', 'Get-TargetHostDetails',
                'Test-HHTarget', 'Invoke-HHCommand', 'Get-HHAuditRecord',
                'Get-HHAuditOutput',
                'Enable-HHSshKeyAuthentication', 'Set-HHWindowsProcessAuditPolicy',
                'Set-HHEscalationPreference', 'Get-HHEscalationPreference',
                'Remove-HHTarget'
            )) {
            $script:source | Should -Match (
                'Invoke-QualificationStep\s+' + [regex]::Escape($cmdlet)
            )
        }
    }

    It 'derives and restores the original policy through the engine' {
        $script:source | Should -Match "Reason 'exact-SHA Windows qualification restoration'"
        $script:source | Should -Match 'policyRestored = -not \$policyChanged'
        $script:source | Should -Match 'policyRestorationOutcome = \$policyRestorationOutcome'
        $script:source | Should -Match 'AuditBefore\.ProcessCreation'
        $script:source | Should -Match '-band 1'
        $script:source | Should -Match "\) \{ 'Unchanged' \}"
        $script:source | Should -Match 'HostHunter\.WindowsProcessAuditEventProbe\.v1'
        $script:source | Should -Match 'windowsAuditEventVerified = \$windowsAuditEventVerified'
        $script:source | Should -Not -Match 'RestoreProcessCreationState'
        $script:source | Should -Not -Match '\b(?:ssh|scp|sftp)\b\s+-'
    }

    It 'reuses one cloned saved public-key target without an interactive broker' {
        $script:source | Should -Match "Authentication -ceq 'PublicKey'"
        $script:source | Should -Match '-Authentication PublicKey -KeyPath \$savedTarget\.KeyPath'
        $script:source | Should -Match 'Enable-HHSshKeyAuthentication -Name \$selectedTargetName'
        $script:source | Should -Match "authenticationMode = 'existing-public-key'"
        $script:source | Should -Match 'operatorStateCloned = \$true'
        $script:source | Should -Match 'Invoke-HHVisualizationLifecycleCore -Action pause'
        $script:source | Should -Match 'cloneMissionPaused = \$cloneMissionPaused'
        $script:source | Should -Not -Match (
            'Get-Credential|Read-Host|confirmation_request|credential_request|askpass'
        )
        $script:source | Should -Not -Match 'QualificationKeyCleanup|remoteKeyInstalled'
    }

    It 'uses the actual Remove-HHTarget parameter contract' {
        $script:source | Should -Not -Match 'Remove-HHTarget[^\r\n]+-Reason'
        $script:source | Should -Match (
            'Remove-HHTarget -Name \$selectedTargetName -Confirm:\$false'
        )
    }

    It 'clones every trust-domain volume read-only and cleans only disposable state' {
        $script:wrapper | Should -Match 'roles=\(data secrets anchors ssh evidence\)'
        $script:wrapper | Should -Match '--preflight'
        $script:wrapper | Should -Match 'docker pause "\$source_controller"'
        $script:wrapper | Should -Match 'docker unpause "\$source_controller"'
        $script:wrapper | Should -Match '\$\{source_volumes\[\$index\]\}:/source:ro'
        $script:wrapper | Should -Match 'cp -a /source/\. /destination/'
        $script:wrapper | Should -Match 'docker volume rm "\$\{volumes\[@\]\}"'
        $script:wrapper | Should -Match 'Get-HHTarget \| Where-Object'
        $script:wrapper | Should -Match 'eligible_count'
        $script:wrapper | Should -Not -Match '--interactive|--tty'
        $script:wrapper | Should -Not -Match '\b(?:ssh|scp|sftp)\b\s+-'
    }

    It 'binds Windows proof to the exact build image and not the coverage verdict' {
        $script:wrapper | Should -Match 'HH_RELEASE_BUILD_RECEIPT'
        $script:wrapper | Should -Match '\.images\.controller\.id'
        $script:wrapper | Should -Match '--entrypoint pwsh "\$image_id"'
        $script:wrapper | Should -Match 'authenticationMode=="existing-public-key"'
        $script:wrapper | Should -Match 'cloneMissionPaused==true'
        $script:wrapper | Should -Not -Match 'verify-local\.json|Heavy-proof receipt'
    }
}
