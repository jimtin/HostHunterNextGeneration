Set-StrictMode -Version Latest

BeforeAll {
    $script:repositoryRoot = (Resolve-Path -LiteralPath (
            Join-Path $PSScriptRoot '../..'
        )).Path
    $script:dockerfile = Get-Content -LiteralPath (
        Join-Path $script:repositoryRoot 'Dockerfile.runtime'
    ) -Raw
    $script:compose = Get-Content -LiteralPath (
        Join-Path $script:repositoryRoot 'compose.runtime.yml'
    ) -Raw
    $script:runtimeRoot = Join-Path $script:repositoryRoot 'scripts/runtime'
}

Describe 'Production runtime container contract' -Tag Unit {
    It 'builds a package in a separate stage and copies it to one stable production path' {
        $script:dockerfile | Should -Match 'FROM runtime-base AS package-builder'
        $script:dockerfile | Should -Match `
            'module_path="\$\(cat /out/module-path\.txt\)"'
        $script:dockerfile | Should -Match `
            'COPY --from=package-builder --chown=0:0 /runtime-module /opt/hosthunter/module'
        $script:dockerfile | Should -Match `
            'HH_RUNTIME_MODULE_PATH=/opt/hosthunter/module/HostHunterNextGeneration\.psd1'
        $script:dockerfile | Should -Not -Match `
            '/(?:opt/hosthunter/module|HostHunterNextGeneration)/0\.\d+\.'
        $script:dockerfile.TrimEnd() | Should -Match 'FROM controller AS production$'
    }

    It 'keeps all test tooling outside the final production image' {
        $testTarget = [regex]::Match(
            $script:dockerfile,
            '(?s)FROM controller AS runtime-e2e(?<body>.*?)FROM controller AS production'
        )
        $testTarget.Success | Should -BeTrue
        $testTarget.Groups['body'].Value | Should -Match 'Pester'
        $testTarget.Groups['body'].Value | Should -Match 'tests/e2e'
        $productionTail = $script:dockerfile.Substring(
            $script:dockerfile.LastIndexOf('FROM controller AS production')
        )
        $productionTail | Should -Not -Match 'Pester|tests/e2e|runtime-tests'
    }

    It 'declares the common non-root read-only security and resource controls' {
        $script:compose | Should -Match '(?m)^  read_only: true$'
        $script:compose | Should -Match '(?ms)^  cap_drop:\s+- ALL$'
        $script:compose | Should -Match '(?m)^    - no-new-privileges:true$'
        $script:compose | Should -Match '(?m)^  pids_limit: 128$'
        $script:compose | Should -Match '(?m)^  mem_limit: 512m$'
        $script:compose | Should -Match '(?m)^  cpus: 1\.0$'
        $script:compose | Should -Match 'size=64m'
        $script:compose | Should -Match '(?ms)^  logging:\s+driver: none$'
        $script:compose | Should -Not -Match '/var/run/docker\.sock'
        $script:dockerfile | Should -Match '(?m)^USER 10001:10001$'
    }

    It 'gives the controller outbound networking and six distinct external volumes' {
        $controller = [regex]::Match(
            $script:compose,
            '(?s)^  controller:(?<body>.*?)^  journey:',
            [Text.RegularExpressions.RegexOptions]::Multiline
        ).Groups['body'].Value
        $controller | Should -Match '(?m)^    networks:$'
        $controller | Should -Match '(?m)^      - runtime$'
        $controller | Should -Match 'environment: \*controller-environment'
        $controller | Should -Match 'volumes: \*controller-volumes'
        ([regex]::Matches($script:compose, '(?m)^    external: true$')).Count |
            Should -Be 6
        foreach ($name in @('data', 'secrets', 'anchors', 'ssh', 'evidence',
                'parser-socket')) {
            $script:compose | Should -Match "(?m)^  $([regex]::Escape($name)):`$"
        }
    }

    It 'isolates the parser from network, controller state, secrets, and SSH' {
        $parser = [regex]::Match(
            $script:compose,
            '(?s)^  parser:(?<body>.*?)^  controller:',
            [Text.RegularExpressions.RegexOptions]::Multiline
        ).Groups['body'].Value
        $parser | Should -Match '(?m)^    network_mode: none$'
        $parser | Should -Match '(?m)^        target: /evidence$'
        $parser | Should -Match '(?m)^        read_only: true$'
        $parser | Should -Match '(?m)^        target: /run/hosthunter-parser$'
        $parser | Should -Not -Match `
            'hosthunter-(data|secrets|anchors|ssh)|HH_(DATA|SECRET|ANCHOR|SSH)_ROOT'
        $parser | Should -Match '(?m)^    mem_limit: 256m$'
        $parser | Should -Match '(?m)^    cpus: 0\.5$'
        $parser | Should -Match '(?m)^    pids_limit: 64$'
    }

    It 'selects DockerVolume only for controller-bearing services' {
        $environmentAnchor = [regex]::Match(
            $script:compose,
            '(?s)^x-controller-environment:(?<body>.*?)^services:',
            [Text.RegularExpressions.RegexOptions]::Multiline
        ).Groups['body'].Value
        $environmentAnchor | Should -Match 'HH_SECRET_PROVIDER: DockerVolume'
        $environmentAnchor | Should -Match `
            'HH_SECRET_ROOT: /var/lib/hosthunter-secrets'
        $environmentAnchor | Should -Match `
            'HH_ANCHOR_ROOT: /var/lib/hosthunter-anchors'
        $parserImage = [regex]::Match(
            $script:dockerfile,
            '(?s)FROM ubuntu:24\.04.*? AS parser(?<body>.*?)FROM powershell-assets AS pester-assets'
        ).Groups['body'].Value
        $parserImage | Should -Not -Match `
            'HH_SECRET_PROVIDER|HH_SECRET_ROOT|HH_ANCHOR_ROOT|HH_DATA_ROOT|HH_SSH_ROOT'
    }

    It 'uses one immutable EVTX request and a provisional-until-complete socket protocol' {
        $sidecar = Get-Content -LiteralPath (
            Join-Path $script:runtimeRoot 'parser-sidecar.py'
        ) -Raw
        $client = Get-Content -LiteralPath (
            Join-Path $script:runtimeRoot 'Invoke-HHParserSocketClient.ps1'
        ) -Raw
        $sidecar | Should -Match 'PROTOCOL = "hosthunter\.parser\.v1"'
        $sidecar | Should -Match 'O_NOFOLLOW'
        $sidecar | Should -Match 'pass_fds='
        $sidecar | Should -Match '/proc/self/fd/'
        $sidecar | Should -Match 'MAX_EVIDENCE_BYTES = 256 \* 1024 \* 1024'
        $sidecar | Should -Match '"provisional": True'
        $sidecar | Should -Match 'final_hash = sha256_descriptor'
        $client | Should -Match 'ProvisionalRecordConsumer'
        $client | Should -Match 'terminal completion receipt'
        $client | Should -Not -Match 'Set-Content|Out-File|Add-Content'
    }

    It 'reuses all 23 existing package-backed CLI journeys without copying their logic' {
        $journeyScript = Get-Content -LiteralPath (
            Join-Path $script:runtimeRoot 'run-journeys.sh'
        ) -Raw
        $journeyScript | Should -Match "expected_journeys=23"
        $journeyScript | Should -Match '"spaceContainingDataRootVerified":true'
        $journeyScript | Should -Match 'tests/e2e/TargetAndCommandJourneys\.Tests\.ps1'
        $journeyScript | Should -Match 'Invoke-HHPesterLane\.ps1'
        $script:dockerfile | Should -Match `
            'COPY --chown=10001:10001 tests/e2e'
    }

    It 'keeps every PowerShell runtime helper syntactically valid' {
        foreach ($path in Get-ChildItem -LiteralPath $script:runtimeRoot -Filter '*.ps1') {
            $tokens = $null
            $errors = $null
            [void][Management.Automation.Language.Parser]::ParseFile(
                $path.FullName,
                [ref]$tokens,
                [ref]$errors
            )
            @($errors).Count | Should -Be 0 -Because $path.Name
        }
    }
}
