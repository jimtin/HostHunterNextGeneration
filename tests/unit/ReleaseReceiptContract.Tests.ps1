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
    $script:sqliteRunner = Get-Content -LiteralPath (
        Join-Path $script:repositoryRoot 'scripts/lanes/sqlite-integration.sh'
    ) -Raw
    $script:newValidCoverageReceipt = {
        param([string] $CandidateSha, [string] $CandidateTree)
        $inventory = @(
            [ordered]@{ path = 'src/HostHunterNextGeneration/A.ps1'; sha256 = ('a' * 64) }
            [ordered]@{ path = 'src/HostHunterNextGeneration/B.ps1'; sha256 = ('b' * 64) }
        )
        $inventoryJson = $inventory | ConvertTo-Json -Compress
        $sourceHash = [Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData(
                [Text.Encoding]::UTF8.GetBytes($inventoryJson)
            )
        ).ToLowerInvariant()
        [pscustomobject][ordered]@{
            schemaVersion = 1
            candidateSha = $CandidateSha
            candidateTree = $CandidateTree
            component = 'coverage'
            status = 'passed'
            exitCode = 0
            retryCount = 0
            coverage = [pscustomobject][ordered]@{
                status = 'passed'
                minimum = 90
                invocationCount = 1
                testCount = 30
                candidateSha = $CandidateSha
                candidateTree = $CandidateTree
                sourceHash = $sourceHash
                sourceFileCount = $inventory.Count
                sourceInventory = $inventory
                metrics = [pscustomobject][ordered]@{
                    statements = [pscustomobject]@{ covered = 90; total = 100 }
                    lines = [pscustomobject]@{ covered = 91; total = 100 }
                    functions = [pscustomobject]@{ covered = 19; total = 20 }
                }
            }
        }
    }
    $script:bindCoverageToSourceRoot = {
        param([object] $Receipt, [string] $SourceRoot)
        $inventory = @(
            Get-ChildItem -LiteralPath @(
                (Join-Path $SourceRoot 'src/HostHunterNextGeneration')
                (Join-Path $SourceRoot 'client/HostHunter.Client')
            ) -Recurse -File |
                Where-Object {
                    $_.Extension -in @('.ps1', '.psm1') -and
                    [string]::IsNullOrEmpty($_.LinkType)
                } |
                ForEach-Object {
                    [pscustomobject][ordered]@{
                        path = [IO.Path]::GetRelativePath(
                            $SourceRoot,
                            $_.FullName
                        ).Replace([IO.Path]::DirectorySeparatorChar, '/')
                        sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).
                            Hash.ToLowerInvariant()
                    }
                } |
                Sort-Object path
        )
        $Receipt.coverage.sourceInventory = $inventory
        $Receipt.coverage.sourceFileCount = $inventory.Count
        $inventoryJson = $inventory | ConvertTo-Json -Compress
        $Receipt.coverage.sourceHash = [Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData(
                [Text.Encoding]::UTF8.GetBytes($inventoryJson)
            )
        ).ToLowerInvariant()
        $Receipt
    }
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

    It 'keeps a passing cmdlet verdict visible when security proof fails' {
        & python3 $script:stateScript claim --root $script:candidateRoot `
            --sha $script:candidateSha --tree ('d' * 40) `
            --started '2026-08-26T00:00:00Z' --pid $PID | Out-Null
        $coverageSource = Join-Path $script:temporaryRoot 'coverage.json'
        (& $script:newValidCoverageReceipt $script:candidateSha ('d' * 40)) |
            ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $coverageSource
        & python3 $script:stateScript record --root $script:candidateRoot `
            --sha $script:candidateSha --kind cmdlet --status passed | Out-Null
        & python3 $script:stateScript record --root $script:candidateRoot `
            --sha $script:candidateSha --kind coverage --source $coverageSource | Out-Null
        & python3 $script:stateScript record --root $script:candidateRoot `
            --sha $script:candidateSha --kind persistence --status passed | Out-Null
        & python3 $script:stateScript record --root $script:candidateRoot `
            --sha $script:candidateSha --kind security --status failed --reason scan | Out-Null
        & python3 $script:stateScript record --root $script:candidateRoot `
            --sha $script:candidateSha --kind orchestration --status failed --reason scan | Out-Null
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
        $result.coverageVerdict.status | Should -Be 'passed'
        $result.persistenceVerdict.status | Should -Be 'passed'
        $result.securityVerdict.status | Should -Be 'failed'
        $result.releaseProofOrchestrationVerdict.status | Should -Be 'failed'
        $result.receiptSha256.cmdlet | Should -Match '^[a-f0-9]{64}$'
        $result.receiptSha256.coverage | Should -Match '^[a-f0-9]{64}$'
        $result.receiptSha256.persistence | Should -Match '^[a-f0-9]{64}$'
        $result.receiptSha256.security | Should -Match '^[a-f0-9]{64}$'
        $result.receiptSha256.releaseProofOrchestration | Should -Match '^[a-f0-9]{64}$'
        $result.receiptSha256.terminal | Should -Match '^[a-f0-9]{64}$'
        ($after | ConvertTo-Json -Compress) | Should -Be ($before | ConvertTo-Json -Compress)
    }

    It 'keeps the live Windows verdict independent and requires it for release' {
        & python3 $script:stateScript claim --root $script:candidateRoot `
            --sha $script:candidateSha --tree ('f' * 40) `
            --started '2026-08-26T00:00:00Z' --pid $PID | Out-Null
        $coverageSource = Join-Path $script:temporaryRoot 'coverage.json'
        (& $script:newValidCoverageReceipt $script:candidateSha ('f' * 40)) |
            ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $coverageSource
        & python3 $script:stateScript record --root $script:candidateRoot `
            --sha $script:candidateSha --kind cmdlet --status passed | Out-Null
        & python3 $script:stateScript record --root $script:candidateRoot `
            --sha $script:candidateSha --kind coverage --source $coverageSource | Out-Null
        & python3 $script:stateScript record --root $script:candidateRoot `
            --sha $script:candidateSha --kind persistence --status passed | Out-Null
        & python3 $script:stateScript record --root $script:candidateRoot `
            --sha $script:candidateSha --kind security --status passed | Out-Null
        & python3 $script:stateScript record --root $script:candidateRoot `
            --sha $script:candidateSha --kind orchestration --status passed | Out-Null
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
        $result.coverageVerdict.status | Should -Be 'passed'
        $result.persistenceVerdict.status | Should -Be 'passed'
        $result.securityVerdict.status | Should -Be 'passed'
        $result.releaseProofOrchestrationVerdict.status | Should -Be 'passed'
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

    It 'retains only a machine-safe dependency skip reason from a component receipt' {
        & python3 $script:stateScript claim --root $script:candidateRoot `
            --sha $script:candidateSha --tree ('e' * 40) `
            --started '2026-08-26T00:00:00Z' --pid $PID | Out-Null
        $source = Join-Path $script:temporaryRoot 'persistence.json'
        @{
            candidateSha = $script:candidateSha
            status = 'not-run'
            reason = 'not_run_due_to_release-module'
        } | ConvertTo-Json | Set-Content -LiteralPath $source
        & python3 $script:stateScript record --root $script:candidateRoot `
            --sha $script:candidateSha --kind persistence --source $source | Out-Null

        $copied = Get-Content (
            Join-Path $script:candidateRoot 'persistence-receipt.json'
        ) -Raw | ConvertFrom-Json
        $copied.status | Should -Be 'not-run'
        $copied.reason | Should -BeExactly 'not_run_due_to_release-module'
    }

    It 'rejects every incoherent form of passing coverage evidence' {
        $tree = 'c' * 40
        $cases = @(
            @{ name = 'top-tree'; mutate = { param($v) $v.candidateTree = ('d' * 40) } }
            @{ name = 'summary-sha'; mutate = { param($v) $v.coverage.candidateSha = ('f' * 40) } }
            @{ name = 'summary-status'; mutate = { param($v) $v.coverage.status = 'threshold_failed' } }
            @{ name = 'invocations'; mutate = { param($v) $v.coverage.invocationCount = 2 } }
            @{ name = 'tests'; mutate = { param($v) $v.coverage.testCount = 0 } }
            @{ name = 'minimum'; mutate = { param($v) $v.coverage.minimum = 89 } }
            @{ name = 'metric-set'; mutate = {
                    param($v)
                    $v.coverage.metrics | Add-Member branches ([pscustomobject]@{
                            covered = 9; total = 10
                        })
                } }
            @{ name = 'metric-count'; mutate = {
                    param($v)
                    $v.coverage.metrics.lines.total = 0
                } }
            @{ name = 'threshold'; mutate = {
                    param($v)
                    $v.coverage.metrics.statements.covered = 899
                    $v.coverage.metrics.statements.total = 999
                } }
            @{ name = 'inventory-count'; mutate = {
                    param($v)
                    $v.coverage.sourceFileCount = 3
                } }
            @{ name = 'duplicate-path'; mutate = {
                    param($v)
                    $v.coverage.sourceInventory[1].path =
                        $v.coverage.sourceInventory[0].path
                } }
            @{ name = 'unsafe-path'; mutate = {
                    param($v)
                    $v.coverage.sourceInventory[0].path = '../escape.ps1'
                } }
            @{ name = 'inventory-hash'; mutate = {
                    param($v)
                    $v.coverage.sourceInventory[0].sha256 = 'not-a-hash'
                } }
            @{ name = 'source-hash'; mutate = {
                    param($v)
                    $v.coverage.sourceHash = ('0' * 64)
                } }
        )

        foreach ($case in $cases) {
            $caseParent = Join-Path $script:temporaryRoot $case.name
            [void](New-Item -ItemType Directory -Path $caseParent)
            $caseRoot = Join-Path $caseParent $script:candidateSha
            & python3 $script:stateScript claim --root $caseRoot `
                --sha $script:candidateSha --tree $tree `
                --started '2026-08-26T00:00:00Z' --pid $PID | Out-Null
            $value = & $script:newValidCoverageReceipt $script:candidateSha $tree
            & $case.mutate $value
            $source = Join-Path $caseParent 'coverage.json'
            $value | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $source
            & python3 $script:stateScript record --root $caseRoot `
                --sha $script:candidateSha --kind coverage --source $source 2>$null
            $LASTEXITCODE | Should -Be 73 -Because $case.name
            Test-Path (Join-Path $caseRoot 'coverage-receipt.json') |
                Should -BeFalse -Because $case.name
        }

        $syntheticParent = Join-Path $script:temporaryRoot 'synthetic'
        [void](New-Item -ItemType Directory -Path $syntheticParent)
        $syntheticRoot = Join-Path $syntheticParent $script:candidateSha
        & python3 $script:stateScript claim --root $syntheticRoot `
            --sha $script:candidateSha --tree $tree `
            --started '2026-08-26T00:00:00Z' --pid $PID | Out-Null
        & python3 $script:stateScript record --root $syntheticRoot `
            --sha $script:candidateSha --kind coverage --status passed 2>$null
        $LASTEXITCODE | Should -Be 73
    }

    It 'binds passing coverage to every real candidate source file' {
        $tree = '9' * 40
        $sourceRoot = Join-Path $script:temporaryRoot 'source-root'
        $productionRoot = Join-Path $sourceRoot 'src/HostHunterNextGeneration'
        $clientRoot = Join-Path $sourceRoot 'client/HostHunter.Client'
        [void](New-Item -ItemType Directory -Path $productionRoot, $clientRoot)
        Set-Content -LiteralPath (Join-Path $productionRoot 'A.ps1') -Value 'function A {}'
        Set-Content -LiteralPath (Join-Path $productionRoot 'Module.psm1') -Value 'function B {}'
        Set-Content -LiteralPath (Join-Path $clientRoot 'Client.ps1') -Value 'function C {}'
        Set-Content -LiteralPath (Join-Path $clientRoot 'Ignored.txt') -Value 'ignored'
        [void](New-Item -ItemType SymbolicLink `
            -Path (Join-Path $productionRoot 'Linked.ps1') `
            -Target (Join-Path $productionRoot 'A.ps1'))

        $validParent = Join-Path $script:temporaryRoot 'source-valid'
        [void](New-Item -ItemType Directory -Path $validParent)
        $validRoot = Join-Path $validParent $script:candidateSha
        & python3 $script:stateScript claim --root $validRoot `
            --sha $script:candidateSha --tree $tree `
            --started '2026-08-26T00:00:00Z' --pid $PID | Out-Null
        $valid = & $script:newValidCoverageReceipt $script:candidateSha $tree
        $valid = & $script:bindCoverageToSourceRoot $valid $sourceRoot
        $validSource = Join-Path $validParent 'coverage.json'
        $valid | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $validSource
        & python3 $script:stateScript record --root $validRoot `
            --sha $script:candidateSha --kind coverage --source $validSource `
            --source-root $sourceRoot | Out-Null
        $LASTEXITCODE | Should -Be 0

        $recompute = {
            param($value)
            $value.coverage.sourceFileCount = $value.coverage.sourceInventory.Count
            $json = $value.coverage.sourceInventory | ConvertTo-Json -Compress
            $value.coverage.sourceHash = [Convert]::ToHexString(
                [Security.Cryptography.SHA256]::HashData(
                    [Text.Encoding]::UTF8.GetBytes($json)
                )
            ).ToLowerInvariant()
        }
        $cases = @(
            @{ name = 'missing'; mutate = {
                    param($v)
                    $v.coverage.sourceInventory = @($v.coverage.sourceInventory | Select-Object -Skip 1)
                } }
            @{ name = 'extra'; mutate = {
                    param($v)
                    $v.coverage.sourceInventory = @($v.coverage.sourceInventory) +
                        [pscustomobject][ordered]@{
                            path = 'src/HostHunterNextGeneration/Extra.ps1'
                            sha256 = ('e' * 64)
                        }
                } }
            @{ name = 'hash'; mutate = {
                    param($v)
                    $v.coverage.sourceInventory[0].sha256 = ('f' * 64)
                } }
            @{ name = 'symlink'; mutate = {
                    param($v)
                    $v.coverage.sourceInventory = @($v.coverage.sourceInventory) +
                        [pscustomobject][ordered]@{
                            path = 'src/HostHunterNextGeneration/Linked.ps1'
                            sha256 = (Get-FileHash -LiteralPath (
                                    Join-Path $productionRoot 'Linked.ps1'
                                ) -Algorithm SHA256).Hash.ToLowerInvariant()
                        }
                } }
        )
        foreach ($case in $cases) {
            $caseParent = Join-Path $script:temporaryRoot ('source-' + $case.name)
            [void](New-Item -ItemType Directory -Path $caseParent)
            $caseRoot = Join-Path $caseParent $script:candidateSha
            & python3 $script:stateScript claim --root $caseRoot `
                --sha $script:candidateSha --tree $tree `
                --started '2026-08-26T00:00:00Z' --pid $PID | Out-Null
            $value = & $script:newValidCoverageReceipt $script:candidateSha $tree
            $value = & $script:bindCoverageToSourceRoot $value $sourceRoot
            & $case.mutate $value
            & $recompute $value
            $source = Join-Path $caseParent 'coverage.json'
            $value | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $source
            & python3 $script:stateScript record --root $caseRoot `
                --sha $script:candidateSha --kind coverage --source $source `
                --source-root $sourceRoot 2>$null
            $LASTEXITCODE | Should -Be 73 -Because $case.name
        }
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
        $windows = $script:runner.IndexOf('bash -c "$windows_preflight_command"')
        $claim = $script:runner.IndexOf('python3 "$state" claim')
        $clean | Should -BeGreaterThan -1
        $docker | Should -BeGreaterThan $clean
        $windows | Should -BeGreaterThan $docker
        $claim | Should -BeGreaterThan $windows
    }

    It 'uses the canonical saved-key Windows qualifier without a TTY or command override' {
        $script:runner | Should -Match (
            'windows_command="\./scripts/qualification/windows-cmdlets\.sh \$candidate_sha"'
        )
        $script:runner | Should -Match (
            "windows_preflight_command='\./scripts/qualification/windows-cmdlets\.sh --preflight'"
        )
        $script:runner | Should -Not -Match 'HH_WINDOWS_QUALIFICATION_COMMAND'
        $script:runner | Should -Not -Match '\[\[ -t 0 && -t 1 \]\]'
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
        $script:buildRunner | Should -Not -Match 'Invoke-HHBranchProbe|HH_BRANCH_COVERAGE'
        $script:cmdletRunner | Should -Match 'HH_RELEASE_IMAGES_PREBUILT'
        $script:cmdletRunner | Should -Match 'HH_RELEASE_VERIFIER_IMAGE_ID'
        $script:heavyRunner | Should -Not -Match 'docker\s+compose[^\r\n]*\sbuild(?:\s|$)'
        $script:heavyRunner | Should -Not -Match '(?m)^\s*(until|while)\s+'
        $script:runner | Should -Match '\.artifacts/summary/coverage\.json'
        $script:runner | Should -Match '\.artifacts/summary/persistence\.json'
        $script:runner | Should -Match '\.artifacts/summary/security\.json'
        $script:runner | Should -Match 'record_result coverage'
        $script:runner | Should -Match 'record_result persistence'
        $script:runner | Should -Match 'record_result security'
        $script:runner | Should -Match 'record_result orchestration'
    }

    It 'records receipts without expanding an unset optional argument array' {
        $script:runner | Should -Not -Match 'source_root_arguments'
        $script:runner | Should -Match '--source-root "\$source_root"'
        $script:runner | Should -Match '--kind "\$kind" --source "\$source" >/dev/null'
    }

    It 'continues persistence and security after a coverage failure' {
        $coverage = $script:heavyRunner.IndexOf(
            'run_component coverage release-unit-coverage'
        )
        $persistence = $script:heavyRunner.IndexOf(
            'run_component persistence release-sqlite-faults'
        )
        $security = $script:heavyRunner.IndexOf(
            'run_component security release-security'
        )
        $coverage | Should -BeGreaterThan -1
        $persistence | Should -BeGreaterThan $coverage
        $security | Should -BeGreaterThan $persistence
        $script:heavyRunner | Should -Not -Match 'phase_passed release-unit-coverage'
        $script:heavyRunner | Should -Match 'run --rm --no-deps coverage'
        $script:heavyRunner | Should -Not -Match 'release-critical-integration'
        $script:testCompose | Should -Match '(?ms)^  coverage:.*?network_mode: none'
    }

    It 'keeps release persistence writes in its isolated artifact mount' {
        $persistenceService = [regex]::Match(
            $script:testCompose,
            '(?ms)^  persistence:\r?\n(?<body>.*?)(?=^  [a-z][a-z0-9-]*:|\z)'
        )
        $persistenceService.Success | Should -BeTrue
        $persistenceService.Groups['body'].Value | Should -Match 'read_only: true'
        $persistenceService.Groups['body'].Value | Should -Match 'network_mode: none'
        $persistenceService.Groups['body'].Value | Should -Match '(?m)^    cap_drop:'
        $persistenceService.Groups['body'].Value |
            Should -Match 'no-new-privileges:true'
        $persistenceService.Groups['body'].Value |
            Should -Match '\.\:/workspace:ro'
        $persistenceService.Groups['body'].Value |
            Should -Match '\./\.artifacts/build:/artifacts/build:ro'
        $persistenceService.Groups['body'].Value |
            Should -Match '\./\.artifacts/release-proof:/artifacts/release-proof'

        $script:heavyRunner | Should -Match (
            'HH_SQLITE_RELEASE_ARTIFACT_ROOT=\$artifact_root'
        )
        $script:sqliteRunner | Should -Match (
            'release_artifact_root="\$\{HH_SQLITE_RELEASE_ARTIFACT_ROOT:-\$artifact_mount_root\}"'
        )
        $script:sqliteRunner | Should -Match (
            'module_marker="\$artifact_mount_root/build/module-path\.txt"'
        )
        $script:sqliteRunner | Should -Match (
            '<"\$module_marker"'
        )
        $script:sqliteRunner | Should -Not -Match (
            '</artifacts/build/module-path\.txt'
        )
        $script:sqliteRunner | Should -Match (
            'host_module_path="\$artifact_mount_root/\$module_relative_path"'
        )
        $script:sqliteRunner | Should -Match (
            '\[\[ -f "\$host_module_path" && ! -L "\$host_module_path" \]\]'
        )
        $script:sqliteRunner | Should -Not -Match '(?m)^test -f "\$module_path"$'
        $script:sqliteRunner | Should -Match (
            'persistence pwsh -NoLogo -NoProfile -NonInteractive'
        )
        $script:sqliteRunner | Should -Match (
            '--volume "\$artifact_mount_root/build:/artifacts/build:ro"'
        )
        $script:sqliteRunner | Should -Match (
            '--read-only --network none --cap-drop ALL'
        )
        $script:sqliteRunner | Should -Match '--env HOME=/tmp'
        $script:sqliteRunner | Should -Match '--env XDG_CACHE_HOME=/tmp/cache'
        $script:sqliteRunner | Should -Match '--env XDG_CONFIG_HOME=/tmp/config'
        $script:sqliteRunner | Should -Match '--env XDG_DATA_HOME=/tmp/data'
        $script:sqliteRunner | Should -Not -Match (
            '--volume "\$repo_root/\$artifact_root:/artifacts"'
        )
        $script:sqliteRunner | Should -Match (
            'SQLite release artifacts must remain under %s'
        )
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
        foreach ($receiptName in @(
                'claim.json', 'receipt.json', 'build-receipt.json',
                'cmdlet-receipt.json', 'windows-receipt.json',
                'coverage-receipt.json', 'persistence-receipt.json',
                'security-receipt.json', 'orchestration-receipt.json'
            )) {
            $script:cleanupPlanner | Should -Match ([regex]::Escape($receiptName))
        }
        $script:cleanupPlanner | Should -Not -Match (
            'add_target "\$candidate" superseded'
        )
    }
}
