$sourceRoot = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
    (Resolve-Path (Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration')).Path
}
else { $env:HH_TEST_SOURCE_ROOT }
$script:fastHookRepoRoot = (Resolve-Path (Join-Path $sourceRoot '../..')).Path
$script:preCommitHook = Get-Content (Join-Path $script:fastHookRepoRoot '.githooks/pre-commit') -Raw
$script:prePushHook = Get-Content (Join-Path $script:fastHookRepoRoot '.githooks/pre-push') -Raw
$script:preCommit = Get-Content (Join-Path $script:fastHookRepoRoot 'scripts/precommit.sh') -Raw
$script:prePush = Get-Content (Join-Path $script:fastHookRepoRoot 'scripts/prepush.sh') -Raw
$script:cmdlets = Get-Content (Join-Path $script:fastHookRepoRoot 'scripts/verify-cmdlets.sh') -Raw
$script:cmdletCompose = Get-Content (Join-Path $script:fastHookRepoRoot 'compose.cmdlets.yml') -Raw
$script:journey = Get-Content (
    Join-Path $script:fastHookRepoRoot 'tests/e2e/TargetAndCommandJourneys.Tests.ps1') -Raw

Describe 'fast hook and cmdlet test contract' -Tag Unit {
    It 'gives pre-commit one 45-second root timeout and no broad test lane' {
        $preCommitHook | Should -Match 'run-bounded\.sh"[\s\S]*precommit 45 30'
        $preCommit | Should -Match 'scan-secrets\.sh'
        $preCommit | Should -Match 'lanes/static\.sh'
        $preCommit | Should -Match 'lanes/focused-unit\.sh'
        $preCommit | Should -Match 'run-bounded\.sh" focused-unit 30 20'
        $preCommit | Should -Match 'docker image inspect "\$test_image"'
        $preCommit | Should -Match 'Cached test image is missing; run:'
        $preCommit | Should -Not -Match 'bash scripts/lanes/unit-smoke\.sh'
        $preCommit | Should -Not -Match '(?m)^\s*"\$\{repo_root\}/scripts/(verify-cmdlets|verify-local)\.sh"'
        $preCommit | Should -Not -Match '(?m)^\s*docker compose.*\bbuild\b'
    }

    It 'keeps pre-push slim and excludes release-only proof' {
        $prePushHook | Should -Match 'run-bounded\.sh"[\s\S]*prepush 180 90'
        foreach ($required in @(
                'scan-secrets.sh', 'scan-dependencies.sh', 'lanes/static.sh',
                'lanes/unit-smoke.sh', 'verify-cmdlets.sh')) {
            $prePush | Should -Match ([regex]::Escape($required))
        }
        $prePush | Should -Match 'run-bounded\.sh" unit-smoke 45 30'
        $prePush | Should -Match 'docker image inspect "\$test_image"'
        $prePush | Should -Match 'Cached test image is missing; run:'
        $prePush | Should -Not -Match 'verify-local|scan-images|windows-cmdlets|lanes/integration|lanes/build'
    }

    It 'runs the native macOS journey only for its owned client surfaces' {
        $prePush | Should -Match 'client/HostHunter\.Client/\*\|scripts/client/\*\|scripts/runtime/\*'
        $prePush | Should -Match 'if \[\[ "\$native_client_changed" == true \]\]'
        ([regex]::Matches($prePush, 'Test-HHInstalledNativeClientSsh\.ps1')).Count |
            Should -Be 1
    }

    It 'bounds the one cmdlet verifier to 90 seconds without retries or broad runners' {
        $cmdlets | Should -Match 'run-bounded\.sh" cmdlet-verifier 90 60'
        $cmdlets | Should -Not -Match '(?i)retry|verify-local|prepush|precommit'
        $cmdlets | Should -Not -Match '(?m)^\s*docker build'
        $cmdlets | Should -Match 'cached HostHunter controller is stale'
        ([regex]::Matches($cmdlets, 'docker compose[\s\S]{0,160}run --rm verifier')).Count |
            Should -Be 1
    }

    It 'gives the non-root verifier write access only through the host artifact group' {
        $cmdletCompose | Should -Match 'user:\s*"10001:10001"'
        $cmdletCompose | Should -Match 'group_add:[\s\S]{0,100}\$\{HH_HOST_GID:-1000\}'
        $cmdletCompose | Should -Match '\$\{HH_CMDLET_ARTIFACT_ROOT:\?[^}]+\}:/artifacts'
    }

    It 'derives expected commands from the packaged manifest and fails additions closed' {
        $journey | Should -Match 'Import-PowerShellDataFile -LiteralPath \$modulePath'
        $journey | Should -Match '\$moduleManifest\.FunctionsToExport \| Sort-Object -Unique'
        $journey | Should -Match 'Compare-Object -ReferenceObject \$expectedCommands'
        $journey | Should -Match '\$rows\.Count -eq \$expectedCommands\.Count'
    }
}
