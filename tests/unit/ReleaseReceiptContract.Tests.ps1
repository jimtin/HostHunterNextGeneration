Set-StrictMode -Version Latest

BeforeAll {
    $script:previousNoBytecode = $env:PYTHONDONTWRITEBYTECODE
    $env:PYTHONDONTWRITEBYTECODE = '1'
    $script:repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '../..')).Path
    $script:stateScript = Join-Path $script:repositoryRoot 'scripts/release/release-receipt-state.py'
    $script:runner = Get-Content -LiteralPath (
        Join-Path $script:repositoryRoot 'scripts/release/verify-candidate.sh'
    ) -Raw
    $script:aggregate = Get-Content -LiteralPath (
        Join-Path $script:repositoryRoot 'scripts/release/aggregate-candidate.sh'
    ) -Raw
    $script:cleanupPlanner = Get-Content -LiteralPath (
        Join-Path $script:repositoryRoot 'scripts/release/prepare-artifact-cleanup.sh'
    ) -Raw
    $script:heavyRunner = Get-Content -LiteralPath (
        Join-Path $script:repositoryRoot 'scripts/verify-local.sh'
    ) -Raw
    $script:buildRunner = Get-Content -LiteralPath (
        Join-Path $script:repositoryRoot 'scripts/release/build-candidate.sh'
    ) -Raw
    $script:cmdletRunner = Get-Content -LiteralPath (
        Join-Path $script:repositoryRoot 'scripts/verify-cmdlets.sh'
    ) -Raw
    $script:testCompose = Get-Content -LiteralPath (
        Join-Path $script:repositoryRoot 'compose.test.yml'
    ) -Raw
}

AfterAll {
    $env:PYTHONDONTWRITEBYTECODE = $script:previousNoBytecode
}

Describe 'Immutable exact-SHA release receipt state machine' -Tag Unit {
    BeforeEach {
        $script:temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) (
            'hh-release-' + [guid]::NewGuid().ToString('N')
        )
        [void](New-Item -ItemType Directory -Path $script:temporaryRoot)
        $script:candidateSha = '0123456789abcdef0123456789abcdef01234567'
        $script:candidateRoot = Join-Path $script:temporaryRoot $script:candidateSha
    }

    AfterEach {
        Remove-Item -LiteralPath $script:temporaryRoot -Recurse -Force
    }

    It 'atomically consumes a SHA and refuses a second claim' {
        & python3 $script:stateScript claim --root $script:candidateRoot `
            --sha $script:candidateSha --tree ('a' * 40) `
            --started '2026-08-26T00:00:00Z' --pid $PID | Out-Null
        $LASTEXITCODE | Should -Be 0

        & python3 $script:stateScript claim --root $script:candidateRoot `
            --sha $script:candidateSha --tree ('a' * 40) `
            --started '2026-08-26T00:00:00Z' --pid $PID 2>$null
        $LASTEXITCODE | Should -Be 73
        (Get-Content (Join-Path $script:candidateRoot 'claim.json') -Raw |
            ConvertFrom-Json).candidateSha | Should -Be $script:candidateSha
    }

    It 'seals stale owner loss as aborted and still refuses rerun' {
        & python3 $script:stateScript claim --root $script:candidateRoot `
            --sha $script:candidateSha --tree ('b' * 40) `
            --started '2026-08-26T00:00:00Z' --pid 2147483647 | Out-Null
        & python3 $script:stateScript recover --root $script:candidateRoot `
            --sha $script:candidateSha --stale-after 0 | Out-Null
        $receipt = Get-Content (Join-Path $script:candidateRoot 'receipt.json') `
            -Raw | ConvertFrom-Json
        $receipt.status | Should -Be 'aborted'
        $receipt.terminalPhase | Should -Be 'stale-claim-recovery'

        & python3 $script:stateScript claim --root $script:candidateRoot `
            --sha $script:candidateSha --tree ('b' * 40) `
            --started '2026-08-26T00:00:00Z' --pid $PID 2>$null
        $LASTEXITCODE | Should -Be 73
    }

    It 'never overwrites a terminal receipt' {
        & python3 $script:stateScript claim --root $script:candidateRoot `
            --sha $script:candidateSha --tree ('c' * 40) `
            --started '2026-08-26T00:00:00Z' --pid $PID | Out-Null
        & python3 $script:stateScript seal --root $script:candidateRoot `
            --sha $script:candidateSha --status failed --phase test `
            --exit-code 1 --reason first --finished '2026-08-26T00:01:00Z' | Out-Null
        $before = Get-FileHash (Join-Path $script:candidateRoot 'receipt.json')
        & python3 $script:stateScript seal --root $script:candidateRoot `
            --sha $script:candidateSha --status passed --phase test `
            --exit-code 0 --reason second --finished '2026-08-26T00:02:00Z' 2>$null
        $LASTEXITCODE | Should -Be 73
        (Get-FileHash (Join-Path $script:candidateRoot 'receipt.json')).Hash |
            Should -Be $before.Hash
    }

    It 'keeps a passing cmdlet verdict visible when heavy proof fails' {
        & python3 $script:stateScript claim --root $script:candidateRoot `
            --sha $script:candidateSha --tree ('d' * 40) `
            --started '2026-08-26T00:00:00Z' --pid $PID | Out-Null
        & python3 $script:stateScript record --root $script:candidateRoot `
            --sha $script:candidateSha --kind cmdlet --status passed | Out-Null
        & python3 $script:stateScript record --root $script:candidateRoot `
            --sha $script:candidateSha --kind heavy --status failed --reason coverage | Out-Null
        & python3 $script:stateScript seal --root $script:candidateRoot `
            --sha $script:candidateSha --status failed --phase aggregation `
            --exit-code 1 --reason heavy-failed --finished '2026-08-26T00:03:00Z' | Out-Null

        $before = @(Get-ChildItem -LiteralPath $script:candidateRoot |
                Select-Object Name, Length, LastWriteTimeUtc)
        $result = & python3 $script:stateScript aggregate --root $script:candidateRoot |
            ConvertFrom-Json
        $after = @(Get-ChildItem -LiteralPath $script:candidateRoot |
                Select-Object Name, Length, LastWriteTimeUtc)
        $result.releaseStatus | Should -Be 'failed'
        $result.cmdletVerdict.status | Should -Be 'passed'
        $result.heavyProofVerdict.status | Should -Be 'failed'
        $result.receiptSha256.cmdlet | Should -Match '^[a-f0-9]{64}$'
        $result.receiptSha256.heavyProof | Should -Match '^[a-f0-9]{64}$'
        $result.receiptSha256.terminal | Should -Match '^[a-f0-9]{64}$'
        ($after | ConvertTo-Json -Compress) | Should -Be ($before | ConvertTo-Json -Compress)
    }

    It 'keeps the live Windows verdict independent and requires it for release' {
        & python3 $script:stateScript claim --root $script:candidateRoot `
            --sha $script:candidateSha --tree ('f' * 40) `
            --started '2026-08-26T00:00:00Z' --pid $PID | Out-Null
        & python3 $script:stateScript record --root $script:candidateRoot `
            --sha $script:candidateSha --kind cmdlet --status passed | Out-Null
        & python3 $script:stateScript record --root $script:candidateRoot `
            --sha $script:candidateSha --kind heavy --status passed | Out-Null
        & python3 $script:stateScript record --root $script:candidateRoot `
            --sha $script:candidateSha --kind windows --status blocked `
            --reason live-host-unavailable | Out-Null
        & python3 $script:stateScript seal --root $script:candidateRoot `
            --sha $script:candidateSha --status blocked --phase windows-qualification `
            --exit-code 2 --reason live-host-unavailable `
            --finished '2026-08-26T00:03:00Z' | Out-Null

        $result = & python3 $script:stateScript aggregate --root $script:candidateRoot |
            ConvertFrom-Json
        $result.releaseStatus | Should -Be 'blocked'
        $result.cmdletVerdict.status | Should -Be 'passed'
        $result.heavyProofVerdict.status | Should -Be 'passed'
        $result.windowsQualificationVerdict.status | Should -Be 'blocked'
        $result.receiptSha256.windowsQualification | Should -Match '^[a-f0-9]{64}$'
    }

    It 'binds the immutable build receipt independently from later verdicts' {
        & python3 $script:stateScript claim --root $script:candidateRoot `
            --sha $script:candidateSha --tree ('1' * 40) `
            --started '2026-08-26T00:00:00Z' --pid $PID | Out-Null
        $source = Join-Path $script:temporaryRoot 'build.json'
        @{
            candidateSha = $script:candidateSha
            candidateTree = ('1' * 40)
            status = 'passed'
            retryCount = 0
            buildCount = 4
            images = @{
                controller = @{ tag = 'controller:sha'; id = ('sha256:' + ('a' * 64)) }
                test = @{ tag = 'test:sha'; id = ('sha256:' + ('b' * 64)) }
                sshFixture = @{ tag = 'ssh:sha'; id = ('sha256:' + ('c' * 64)) }
                verifier = @{ tag = 'verifier:sha'; id = ('sha256:' + ('d' * 64)) }
            }
        } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $source
        & python3 $script:stateScript record --root $script:candidateRoot `
            --sha $script:candidateSha --kind build --source $source | Out-Null
        & python3 $script:stateScript seal --root $script:candidateRoot `
            --sha $script:candidateSha --status failed --phase aggregation `
            --exit-code 1 --reason later-failure --finished '2026-08-26T00:03:00Z' | Out-Null

        $result = & python3 $script:stateScript aggregate --root $script:candidateRoot |
            ConvertFrom-Json
        $result.buildVerdict.status | Should -Be 'passed'
        $result.buildVerdict.buildCount | Should -Be 4
        $result.buildVerdict.images.controller.id | Should -Be ('sha256:' + ('a' * 64))
        $result.receiptSha256.build | Should -Match '^[a-f0-9]{64}$'
    }

    It 'copies only allowlisted verdict fields from component receipts' {
        & python3 $script:stateScript claim --root $script:candidateRoot `
            --sha $script:candidateSha --tree ('e' * 40) `
            --started '2026-08-26T00:00:00Z' --pid $PID | Out-Null
        $source = Join-Path $script:temporaryRoot 'source.json'
        @{
            status = 'passed'
            reason = 'TOKEN=must-not-be-retained'
            environment = @{ TOKEN = 'must-not-be-retained' }
            rows = @(@{
                    cmdlet = 'Get-HHTarget'
                    status = 'passed'
                    rawOutput = 'must-not-be-retained'
                })
        } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $source
        & python3 $script:stateScript record --root $script:candidateRoot `
            --sha $script:candidateSha --kind cmdlet --source $source | Out-Null

        $copied = Get-Content (Join-Path $script:candidateRoot 'cmdlet-receipt.json') `
            -Raw
        $copied | Should -Not -Match 'must-not-be-retained|environment|rawOutput'
        ($copied | ConvertFrom-Json).rows[0].cmdlet | Should -Be 'Get-HHTarget'
    }

    It 'has no internal retry and traps interruption for terminal sealing' {
        $script:runner | Should -Match 'python3 "\$state" claim'
        $script:runner | Should -Match 'terminal_status=aborted'
        $script:runner | Should -Match 'trap cleanup EXIT'
        $script:runner | Should -Not -Match '(?m)^\s*(until|while)\s+'
        $script:aggregate | Should -Match 'release-receipt-state\.py" aggregate'
        $script:aggregate | Should -Not -Match '(?m)^\s*(mv|cp|mkdir|tee)\s'
    }

    It 'does not consume an exact SHA before read-only readiness passes' {
        $clean = $script:runner.IndexOf('status --porcelain=v1')
        $docker = $script:runner.IndexOf('docker info')
        $windows = $script:runner.IndexOf('Live Windows qualification command is required')
        $claim = $script:runner.IndexOf('python3 "$state" claim')
        $clean | Should -BeGreaterThan -1
        $docker | Should -BeGreaterThan $clean
        $windows | Should -BeGreaterThan $docker
        $claim | Should -BeGreaterThan $windows
    }

    It 'builds once then runs cmdlets and Windows before the independent heavy phases' {
        $build = $script:runner.IndexOf('terminal_phase=build')
        $cmdlets = $script:runner.IndexOf('terminal_phase=cmdlet-verdict')
        $windows = $script:runner.IndexOf('terminal_phase=windows-qualification')
        $heavy = $script:runner.IndexOf('terminal_phase=release-proof')
        $build | Should -BeGreaterThan -1
        $cmdlets | Should -BeGreaterThan $build
        $windows | Should -BeGreaterThan $cmdlets
        $heavy | Should -BeGreaterThan $windows
        $script:buildRunner | Should -Match 'buildCount:\s*4'
        ([regex]::Matches($script:buildRunner, '(?m)^docker build ')).Count | Should -Be 4
        $script:buildRunner | Should -Match 'Invoke-HHBranchProbe\|HH_BRANCH_COVERAGE'
        $script:cmdletRunner | Should -Match 'HH_RELEASE_IMAGES_PREBUILT'
        $script:cmdletRunner | Should -Match 'HH_RELEASE_VERIFIER_IMAGE_ID'
        $script:heavyRunner | Should -Not -Match 'docker\s+compose[^\r\n]*\sbuild(?:\s|$)'
        $script:heavyRunner | Should -Not -Match '(?m)^\s*(until|while)\s+'
    }

    It 'continues integration and security after a coverage failure' {
        $coverage = $script:heavyRunner.IndexOf('run_phase release-unit-coverage')
        $integration = $script:heavyRunner.IndexOf('run_phase release-critical-integration')
        $security = $script:heavyRunner.IndexOf('run_phase release-security')
        $coverage | Should -BeGreaterThan -1
        $integration | Should -BeGreaterThan $coverage
        $security | Should -BeGreaterThan $integration
        $script:heavyRunner | Should -Not -Match 'phase_passed release-unit-coverage'
        $script:heavyRunner | Should -Match 'run --rm --no-deps coverage'
        $script:testCompose | Should -Match '(?ms)^  coverage:.*?network_mode: none'
    }

    It 'prepares writable artifacts and binds coverage to the exact candidate tree' {
        $script:heavyRunner | Should -Match 'scripts/lib/prepare-artifacts\.sh "\$repo_root"'
        $script:heavyRunner | Should -Match 'export HH_CANDIDATE_SHA="\$candidate_sha"'
        $script:heavyRunner | Should -Match 'export HH_CANDIDATE_TREE'
        $script:heavyRunner | Should -Match 'sourceInventory,metrics,uncovered'
        $script:testCompose | Should -Match 'HH_CANDIDATE_SHA: \$\{HH_CANDIDATE_SHA:-\}'
        $script:testCompose | Should -Match 'HH_CANDIDATE_TREE: \$\{HH_CANDIDATE_TREE:-\}'
    }

    It 'rejects a passing component receipt from a failed process' {
        $script:runner | Should -Match 'contradictory passing receipt'
        $script:runner | Should -Match '\$exit_code" -ne 0 && "\$source_status" == passed'
    }

    It 'never lets artifact cleanup remove a consumed-SHA tombstone' {
        $script:cleanupPlanner | Should -Match (
            'claim\.json\|receipt\.json\|build-receipt\.json\|cmdlet-receipt\.json\|heavy-receipt\.json\|windows-receipt\.json'
        )
        $script:cleanupPlanner | Should -Not -Match (
            'add_target "\$candidate" superseded'
        )
    }
}
