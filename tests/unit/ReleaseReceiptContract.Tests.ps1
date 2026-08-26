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

    It 'never lets artifact cleanup remove a consumed-SHA tombstone' {
        $script:cleanupPlanner | Should -Match (
            'claim\.json\|receipt\.json\|cmdlet-receipt\.json\|heavy-receipt\.json\|windows-receipt\.json'
        )
        $script:cleanupPlanner | Should -Not -Match (
            'add_target "\$candidate" superseded'
        )
    }
}
