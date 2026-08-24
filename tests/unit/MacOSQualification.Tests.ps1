BeforeAll {
    $script:qualificationPath = Join-Path $PSScriptRoot `
        '../../scripts/qualification/Test-HHMacOSAnchor.ps1'
    $script:qualificationSource = Get-Content -LiteralPath $script:qualificationPath -Raw
    $script:qualificationAst = [Management.Automation.Language.Parser]::ParseFile(
        $script:qualificationPath,
        [ref]$null,
        [ref]$null
    )
}

Describe 'macOS exact-package qualification cleanup contract' -Tag Unit {
    It 'derives both Keychain service identities from the production module' {
        $script:qualificationSource |
            Should -Not -Match 'com\.hosthunter\.nextgeneration\.audit-master-key'
        $script:qualificationSource |
            Should -Match 'AuditService\s*=\s*\$script:HHAuditKeychainService'
        $script:qualificationSource |
            Should -Match 'AnchorService\s*=\s*\$script:HHPersistenceAnchorKeychainService'
        $script:qualificationSource |
            Should -Match '\$auditService\s*=\s*\[string\]\$identity\.AuditService'
        $script:qualificationSource |
            Should -Match '\$anchorService\s*=\s*\[string\]\$identity\.AnchorService'
    }

    It 'does not accept item-not-found as successful deletion' {
        $deleteFunctions = @($script:qualificationAst.FindAll({
                param($Node)
                $Node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                $Node.Name -ceq 'Invoke-HHQualificationSecurityDelete'
            }, $true))
        $deleteFunctions.Count | Should -Be 1
        $deleteFunction = $deleteFunctions[0]

        $deleteFunction.Extent.Text | Should -Match '\$process\.ExitCode\s+-ne\s+0'
        $deleteFunction.Extent.Text | Should -Not -Match '0\s*,\s*44'
    }

    It 'proves each exact item exists before deletion and is absent afterward' {
        $finallyAsts = @($script:qualificationAst.FindAll({
                    param($Node)
                    $Node -is [Management.Automation.Language.TryStatementAst] -and
                    $null -ne $Node.Finally -and
                    $Node.Finally.Extent.Text -cmatch '\$cleanupComplete\s*='
                }, $true))
        $finallyAsts.Count | Should -Be 1
        $finallyAst = $finallyAsts[0]
        $cleanupSource = $finallyAst.Finally.Extent.Text

        $cleanupSource | Should -Match (
            '(?s)foreach \(\$item in \$keychainItems\).*?' +
            'Test-HHQualificationSecurityItem.*?Invoke-HHQualificationSecurityDelete'
        )
        $cleanupSource | Should -Match (
            '(?s)Invoke-HHQualificationSecurityDelete.*?' +
            'foreach \(\$item in \$keychainItems\).*?Test-HHQualificationSecurityItem'
        )
        $cleanupSource | Should -Match (
            '(?s)Test-HHQualificationSecurityItem.*?' +
            '\$cleanupComplete\s*='
        )
    }

    It 'removes a partial exact Keychain lifecycle without claiming a passed qualification' {
        $script:qualificationSource |
            Should -Match '\$qualificationCompleted\s*=\s*\$false'
        $script:qualificationSource |
            Should -Match '(?s)if \(\$itemPresent\).*?Invoke-HHQualificationSecurityDelete'
        $script:qualificationSource |
            Should -Match '(?s)\(-not \$qualificationCompleted\).*?\$itemsPresentBeforeCleanup'
    }

    It 'keeps disposable scope and receipt binding intact' {
        $script:qualificationSource |
            Should -Match "hosthunter-native-qualification-'\s*\+\s*\[Guid\]::NewGuid"
        $script:qualificationSource | Should -Match 'candidateSha\s*=\s*\$CandidateSha'
        $script:qualificationSource |
            Should -Match 'packageArchiveSha256\s*=\s*\$PackageArchiveSha256'
        $script:qualificationSource | Should -Match 'redacted\s*=\s*\$true'
    }
}
