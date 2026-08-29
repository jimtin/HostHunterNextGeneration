Describe 'fast unit and native coverage contract' -Tag Unit {
    BeforeAll {
        $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        $script:coverageRunner = Get-Content -LiteralPath (
            Join-Path $repoRoot 'scripts/coverage/Invoke-HHUnitCoverage.ps1'
        ) -Raw
        $script:smokeRunner = Get-Content -LiteralPath (
            Join-Path $repoRoot 'scripts/coverage/Invoke-HHUnitSmoke.ps1'
        ) -Raw
        $script:unitLane = Get-Content -LiteralPath (
            Join-Path $repoRoot 'scripts/lanes/unit.sh'
        ) -Raw
        $script:metricEvaluator = Join-Path $repoRoot 'scripts/coverage/Test-HHCoverageMetrics.ps1'

        function Get-HHNativeMetricFixture {
            $result = [ordered]@{}
            foreach ($name in @('statements', 'lines', 'functions')) {
                $result[$name] = [pscustomobject]@{
                    covered = 100
                    total = 100
                    definition = "$name fixture"
                }
            }
            $result
        }
    }

    It 'runs the ordinary unit smoke once without coverage or nested runners' {
        ([regex]::Matches($smokeRunner, '(?m)^\s*\$result = Invoke-Pester\b')).Count |
            Should -Be 1
        $smokeRunner | Should -Match 'CodeCoverage\.Enabled = \$false'
        $smokeRunner | Should -Match "Filter\.Tag = @\('Unit'\)"
        $smokeRunner | Should -Not -Match 'Start-Process|System\.Diagnostics\.Process|Get-Command\s+pwsh'
    }

    It 'uses one standard native Pester coverage invocation and three retained metrics' {
        ([regex]::Matches($coverageRunner, '(?m)^\s*\$result = Invoke-Pester\b')).Count |
            Should -Be 1
        $coverageRunner | Should -Match "Filter\.Tag = @\('Unit'\)"
        $coverageRunner | Should -Match "CodeCoverage\.OutputFormat = 'JaCoCo'"
        $coverageRunner | Should -Match "TestResult\.OutputFormat = 'JUnitXml'"
        $coverageRunner | Should -Match "collector = 'pester-native'"
        $coverageRunner | Should -Match 'invocationCount = 1'
        $coverageRunner | Should -Not -Match 'Instrument-HHBranches|HostHunterCoverageHits|temporaryRoot'
        $coverageRunner | Should -Not -Match 'Start-Process|System\.Diagnostics\.Process|Get-Command\s+pwsh'
        $coverageRunner | Should -Not -Match 'Tag\s*=.*Integration|HH_SSH|Invoke-HHManagedHostOperation'
    }

    It 'has separate smoke and coverage modes with fail-closed terminal receipts' {
        $unitLane | Should -Match 'mode="\$\{1:-smoke\}"'
        $unitLane | Should -Match 'Invoke-HHUnitSmoke\.ps1'
        $unitLane | Should -Match 'Invoke-HHUnitCoverage\.ps1'
        $unitLane | Should -Match '\[\[ -s "\$summary" \]\]'
        ([regex]::Matches($unitLane, '(?m)^\s*pwsh\s')).Count | Should -Be 2
        $unitLane | Should -Not -Match 'retry|shard|worker|while\s|until\s'
    }

    It 'fails each retained metric independently at the threshold' {
        foreach ($name in @('statements', 'lines', 'functions')) {
            $metrics = Get-HHNativeMetricFixture
            $metrics[$name].covered = 89
            $result = & $metricEvaluator -Metrics $metrics -Minimum 90
            $result.passed | Should -BeFalse
            $result.metrics[$name].passed | Should -BeFalse
            @($result.metrics.Values | Where-Object { -not $_.passed }).Count | Should -Be 1
        }
    }

    It 'fails closed for missing or empty retained metrics' {
        $metrics = Get-HHNativeMetricFixture
        $metrics.Remove('functions')
        { & $metricEvaluator -Metrics $metrics -Minimum 90 } |
            Should -Throw "*Coverage metric 'functions' is missing*"

        $metrics = Get-HHNativeMetricFixture
        $metrics.lines.covered = 0
        $metrics.lines.total = 0
        $result = & $metricEvaluator -Metrics $metrics -Minimum 0
        $result.passed | Should -BeFalse
        $result.metrics.lines.reason | Should -Be 'invalid denominator or covered count'
    }

    It 'uses the exact ratio rather than a rounded displayed percentage' {
        $metrics = Get-HHNativeMetricFixture
        $metrics.statements.covered = 8999996
        $metrics.statements.total = 10000000
        $result = & $metricEvaluator -Metrics $metrics -Minimum 90
        $result.metrics.statements.percentage | Should -Be 90
        $result.metrics.statements.passed | Should -BeFalse
        $result.passed | Should -BeFalse
    }

    It 'removes the superseded AST transformer and branch fixture' {
        Test-Path -LiteralPath (
            Join-Path $repoRoot 'scripts/coverage/Instrument-HHBranches.ps1'
        ) | Should -BeFalse
        Test-Path -LiteralPath (
            Join-Path $repoRoot 'tests/coverage/fixtures/BranchFixture.ps1'
        ) | Should -BeFalse
    }
}
