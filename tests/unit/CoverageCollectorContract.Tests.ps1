Describe 'release coverage collector contract' -Tag Unit {
    BeforeAll {
        $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        $script:instrumenter = Join-Path $repoRoot 'scripts/coverage/Instrument-HHBranches.ps1'
        $script:metricEvaluator = Join-Path $repoRoot 'scripts/coverage/Test-HHCoverageMetrics.ps1'
        $fixture = Join-Path $repoRoot 'tests/coverage/fixtures/BranchFixture.ps1'
        $instrumentedFixture = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
            $null
        }
        else { Join-Path $env:HH_TEST_SOURCE_ROOT 'BranchFixture.ps1' }
        $coverageFixture = if ($instrumentedFixture -and (Test-Path -LiteralPath $instrumentedFixture)) {
            $instrumentedFixture
        }
        else { $fixture }
        . $coverageFixture
        $null = Invoke-HHCoverageFixture -Mode alpha -Value 2 -Items @(1, 2)
        $null = Invoke-HHCoverageFixture -Mode other -Value 0 -Items @()
        $null = Invoke-HHCoverageFixture -Mode throw -Value 0 -Items @()
        function Get-HHMetricFixture {
            $result = [ordered]@{}
            foreach ($name in @('statements', 'branches', 'functions', 'lines')) {
                $result[$name] = [pscustomobject]@{
                    covered = 100; total = 100; definition = "$name fixture"
                }
            }
            $result
        }
    }

    It 'uses one in-memory outcome set and preserves the six supported branch families' {
        $output = Join-Path $TestDrive 'BranchFixture.instrumented.ps1'
        $manifestPath = Join-Path $TestDrive 'manifest.json'
        & $instrumenter -Path $fixture -OutputPath $output -ManifestPath $manifestPath
        $generated = Get-Content -LiteralPath $output -Raw
        $generated | Should -Match "GetData\('HostHunterCoverageHits'\)"
        $generated | Should -Match 'TryAdd'
        $legacyLogName = 'HH_BRANCH' + '_LOG'
        $generated | Should -Not -Match "$legacyLogName|Mutex|WriteAllText|compact\.json|checksum"

        $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        $manifest.schemaVersion | Should -Be 3
        @($manifest.branches.kind | Sort-Object -Unique) | Should -Be @(
            'for', 'foreach', 'if', 'switch', 'try-catch', 'while'
        )

        $prior = [AppDomain]::CurrentDomain.GetData('HostHunterCoverageHits')
        $hits = [Collections.Concurrent.ConcurrentDictionary[string, byte]]::new([StringComparer]::Ordinal)
        try {
            [AppDomain]::CurrentDomain.SetData('HostHunterCoverageHits', $hits)
            . $output
            Invoke-HHCoverageFixture -Mode alpha -Value 2 -Items @(1, 2) | Should -Be 'positive:alpha:7:normal'
            Invoke-HHCoverageFixture -Mode other -Value 0 -Items @() | Should -Be 'not-positive:default:0:normal'
            Invoke-HHCoverageFixture -Mode throw -Value 0 -Items @() | Should -Be 'not-positive:default:0:caught'
            $hits.Count | Should -Be $manifest.outcomeCount
        }
        finally {
            [AppDomain]::CurrentDomain.SetData('HostHunterCoverageHits', $prior)
        }
    }

    It 'fails closed for an unsupported decision construct' {
        $unsupported = Join-Path $TestDrive 'unsupported.ps1'
        Set-Content -LiteralPath $unsupported -Value "`$value = `$true ? 1 : 0" -Encoding utf8NoBOM
        {
            & $instrumenter -Path $unsupported -OutputPath (Join-Path $TestDrive 'out.ps1') `
                -ManifestPath (Join-Path $TestDrive 'out.json')
        } | Should -Throw '*Unsupported coverage decision*TernaryExpressionAst*'
    }

    It 'has exactly two in-process unit-only Pester invocations' {
        $runner = Get-Content -LiteralPath (
            Join-Path $repoRoot 'scripts/coverage/Invoke-HHUnitCoverage.ps1'
        ) -Raw
        ([regex]::Matches($runner, '(?m)^\s*\$\w+Result = Invoke-Pester\b')).Count | Should -Be 2
        ([regex]::Matches($runner, "Filter\.Tag = @\('Unit'\)")).Count | Should -Be 2
        $runner | Should -Not -Match 'Get-Command\s+pwsh|Start-Process|System\.Diagnostics\.Process|Tag\s*=.*Integration'
    }

    It 'fails each of the four independent thresholds without conflating metrics' {
        foreach ($name in @('statements', 'branches', 'functions', 'lines')) {
            $inputMetrics = Get-HHMetricFixture
            $inputMetrics[$name].covered = 89
            $result = & $metricEvaluator -Metrics $inputMetrics -Minimum 90
            $result.passed | Should -BeFalse
            $result.metrics[$name].passed | Should -BeFalse
            @($result.metrics.Values | Where-Object { -not $_.passed }).Count | Should -Be 1
        }
    }

    It 'fails a zero denominator even when the percentage threshold is zero' {
        $inputMetrics = Get-HHMetricFixture
        $inputMetrics.branches.covered = 0
        $inputMetrics.branches.total = 0
        $result = & $metricEvaluator -Metrics $inputMetrics -Minimum 0
        $result.passed | Should -BeFalse
        $result.metrics.branches.reason | Should -Be 'invalid denominator or covered count'
    }
}
