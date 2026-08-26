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
                'Get-HHTarget', 'Set-HHTarget', 'Test-HHTarget', 'Invoke-HHCommand',
                'Get-HHAuditRecord', 'Get-HHAuditOutput',
                'Enable-HHSshKeyAuthentication', 'Set-HHWindowsProcessAuditPolicy',
                'Set-HHEscalationPreference', 'Get-HHEscalationPreference',
                'Remove-HHTarget'
            )) {
            $script:source | Should -Match (
                'Invoke-QualificationStep\s+' + [regex]::Escape($cmdlet)
            )
        }
    }

    It 'restores policy and removes the exact remote key through the engine' {
        $script:source | Should -Match "Reason 'exact-SHA Windows qualification restoration'"
        $script:source | Should -Match 'policyRestored = -not \$policyChanged'
        $script:source | Should -Match 'policyRestorationOutcome = \$policyRestorationOutcome'
        $script:source | Should -Match "\) \{ 'Unchanged' \}"
        $script:source | Should -Match 'HostHunter\.QualificationKeyCleanup\.v1'
        $script:source | Should -Match 'HostHunter\.WindowsProcessAuditEventProbe\.v1'
        $script:source | Should -Match 'windowsAuditEventVerified = \$windowsAuditEventVerified'
        $script:source | Should -Match 'Invoke-HHCommand -Target \$script:targetName -Command \$cleanupCommand'
        $script:source | Should -Match 'remoteQualificationKeyRemoved = -not \$remoteKeyInstalled'
        $script:source | Should -Not -Match '\b(?:ssh|scp|sftp)\b\s+-'
    }

    It 'uses the actual Remove-HHTarget parameter contract' {
        $script:source | Should -Not -Match 'Remove-HHTarget[^\r\n]+-Reason'
        $script:source | Should -Match 'Remove-HHTarget -Name \$targetName -Confirm:\$false'
    }

    It 'binds Windows proof to the exact build image and not the coverage verdict' {
        $script:wrapper | Should -Match 'HH_RELEASE_BUILD_RECEIPT'
        $script:wrapper | Should -Match '\.images\.controller\.id'
        $script:wrapper | Should -Not -Match 'verify-local\.json|Heavy-proof receipt'
    }
}
