BeforeAll {
    $script:publishPath = Join-Path $PSScriptRoot '../../scripts/release/publish-github.sh'
    $script:publishSource = Get-Content -LiteralPath $script:publishPath -Raw
}

Describe 'Publication native qualification receipt contract' -Tag Unit {
    It 'requires proven macOS rollback and exact Keychain cleanup' {
        foreach ($requiredPredicate in @(
                '.platform == "macOS"',
                '.rollbackRejected == true',
                '.spaceContainingDataRootVerified == true',
                '.keychainItemCount == 2',
                '.cleanupComplete == true',
                '.redacted == true'
            )) {
            $script:publishSource | Should -Match ([regex]::Escape($requiredPredicate))
        }
    }

    It 'requires both runtimes, mixed attribution, protected-key use, and exact cleanup' {
        foreach ($requiredPredicate in @(
                '.directRuntime == "PowerShell7"',
                '.directEdition == "Core"',
                '.directExecutionMode == "Direct"',
                '.compatibilityRuntime == "WindowsPowerShell51"',
                '.compatibilityEdition == "Desktop"',
                '.compatibilityExecutionMode == "WindowsPowerShellCompatibility"',
                '.mixedTargetCount == 2',
                '.spaceContainingDataRootVerified == true',
                '.keyTransitionSucceeded == true',
                '.runScopedSshAgentVerified == true',
                '.runScopedSshAgentIdentityRemoved == true',
                '.runScopedSshAgentStopped == true',
                '.passwordAuthenticationPreserved == true',
                '.remoteQualificationKeyRemoved == true',
                '.cleanupComplete == true',
                '.redacted == true'
            )) {
            $script:publishSource | Should -Match ([regex]::Escape($requiredPredicate))
        }
    }
}
