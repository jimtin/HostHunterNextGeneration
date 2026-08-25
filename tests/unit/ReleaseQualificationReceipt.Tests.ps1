BeforeAll {
    $script:publishPath = Join-Path $PSScriptRoot '../../scripts/release/publish-github.sh'
    $script:publishSource = Get-Content -LiteralPath $script:publishPath -Raw
}

Describe 'Publication Docker qualification receipt contract' -Tag Unit {
    It 'requires the exact hardened production runtime without macOS qualification' {
        foreach ($requiredPredicate in @(
                '.controller.dockerSocketMounted == false',
                '.parser.networkMode == "none"',
                '.parser.secretDatabaseOrSshMountCount == 0',
                '.exactVolumeDestructionVerified == true',
                '.cliJourney.journeys == 23',
                '.cliJourney.spaceContainingDataRootVerified == true',
                '.runtimeReceiptSha256 == $runtimeSha'
            )) {
            $script:publishSource | Should -Match ([regex]::Escape($requiredPredicate))
        }
        $script:publishSource | Should -Not -Match 'macos_receipt='
    }

    It 'requires both runtimes, audit policy, protected-key use, and exact volume cleanup' {
        foreach ($requiredPredicate in @(
                '.controllerMode == "LinuxDockerVolume"',
                '.controllerImageId == $imageId',
                '.controllerVolumeCount == 6',
                '.controllerVolumeCleanupComplete == true',
                '.controllerVolumesDestroyed == 6',
                '.stablePackagedModuleVerified == true',
                '.directRuntime == "PowerShell7"',
                '.directEdition == "Core"',
                '.directExecutionMode == "Direct"',
                '.compatibilityRuntime == "WindowsPowerShell51"',
                '.compatibilityEdition == "Desktop"',
                '.compatibilityExecutionMode == "WindowsPowerShellCompatibility"',
                '.mixedTargetCount == 2',
                '.restartPersistenceVerified == true',
                '.escalationPreferenceVerified == true',
                '.processAuditPowerShell7Verified == true',
                '.processAuditWindowsPowerShell51Verified == true',
                '.commandLineEnabledEventVerified == true',
                '.commandLineDisabledEventVerified == true',
                '.processAuditPolicyRestored == true',
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
