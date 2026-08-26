Set-StrictMode -Version Latest

BeforeAll {
    $script:root = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    $script:dockerfile = Get-Content (Join-Path $script:root 'Dockerfile.runtime') -Raw
    $script:compose = Get-Content (Join-Path $script:root 'compose.runtime.yml') -Raw
}

Describe 'Production runtime container contract' -Tag Unit {
    It 'packages exactly one production Linux controller without test tooling' {
        $script:dockerfile | Should -Match 'FROM runtime-base AS package-builder'
        $script:dockerfile | Should -Match 'FROM controller AS production'
        $script:dockerfile | Should -Not -Match 'runtime-e2e|Pester|tests/e2e|evtx|parser'
        $script:dockerfile | Should -Match '(?m)^USER 10001:10001$'
    }

    It 'declares one controller and no parser or journey service' {
        $script:compose | Should -Match '(?m)^  controller:$'
        $script:compose | Should -Not -Match '(?m)^  (parser|journey):$'
    }

    It 'uses five distinct external trust-domain volumes' {
        ([regex]::Matches($script:compose, '(?m)^    external: true$')).Count |
            Should -Be 5
        foreach ($name in @('data', 'secrets', 'anchors', 'ssh', 'evidence')) {
            $script:compose | Should -Match ("(?m)^  {0}:$" -f [regex]::Escape($name))
        }
        $script:compose | Should -Not -Match 'parser-socket'
    }

    It 'keeps the controller non-root read-only and resource bounded' {
        $script:compose | Should -Match '(?m)^    read_only: true$'
        $script:compose | Should -Match '(?ms)^    cap_drop:\s+- ALL$'
        $script:compose | Should -Match 'no-new-privileges:true'
        $script:compose | Should -Match '(?m)^    pids_limit: 128$'
        $script:compose | Should -Match '(?m)^    mem_limit: 512m$'
        $script:compose | Should -Not -Match '/var/run/docker.sock'
    }

    It 'exposes only doctor, serve, and the constrained cmdlet dispatcher' {
        $entrypoint = Get-Content (Join-Path $script:root 'scripts/runtime/controller-entrypoint.sh') -Raw
        $launcher = Get-Content (Join-Path $script:root 'scripts/runtime/hosthunter.sh') -Raw
        $entrypoint | Should -Match 'serve\)'
        $entrypoint | Should -Match 'doctor\)'
        $entrypoint | Should -Match 'invoke\)'
        $launcher | Should -Not -Match '(?m)^\s*(shell|run)\)'
        $entrypoint | Should -Not -Match '(?m)^\s*(shell|run)\)'
    }
}
