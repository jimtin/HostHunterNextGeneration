Describe 'coverage foundation fixture' -Tag 'Unit' {
    BeforeAll {
        $sourcePath = if ([string]::IsNullOrWhiteSpace($env:HH_COVERAGE_FIXTURE_PATH)) {
            Join-Path $PSScriptRoot 'fixtures/BranchFixture.ps1'
        }
        else {
            $env:HH_COVERAGE_FIXTURE_PATH
        }
        . $sourcePath
        if (-not [string]::IsNullOrWhiteSpace($env:HH_COVERAGE_EXTRA_PATH)) {
            . $env:HH_COVERAGE_EXTRA_PATH
        }

        $goldenById = @{}
        foreach ($entry in (Get-Content -LiteralPath (
                    Join-Path $PSScriptRoot 'fixtures/BranchFixture.expected.json'
                ) -Raw | ConvertFrom-Json)) {
            $goldenById[$entry.id] = @($entry.output)
        }

        function Assert-HHGoldenCase {
            param(
                [Parameter(Mandatory)][string]$Id,
                [Parameter(Mandatory)][string]$Mode,
                [Parameter(Mandatory)][int]$Value,
                [Parameter(Mandatory)][AllowEmptyCollection()][int[]]$Items,
                [switch]$ThrowInTrapScope
            )

            $env:HH_COVERAGE_CASE = $Id
            $actual = @(Invoke-HHBranchFixture -Mode $Mode -Value $Value -Items $Items `
                    -ThrowInTrapScope:$ThrowInTrapScope)
            $expectedJson = @($goldenById[$Id]) | ConvertTo-Json -Compress
            $actualJson = $actual | ConvertTo-Json -Compress
            if ($actualJson -cne $expectedJson) {
                throw "Fixture case '$Id' differed from its golden result."
            }
        }
    }

    It 'covers the positive alpha paths' {
        Assert-HHGoldenCase -Id 'positive-alpha' -Mode 'alpha' -Value 2 -Items @(1, 2, 4)
    }

    It 'covers zero and empty collection paths' {
        Assert-HHGoldenCase -Id 'zero-beta-empty' -Mode 'beta' -Value 0 -Items @()
    }

    It 'covers negative, continue, break, and implicit switch-default paths' {
        Assert-HHGoldenCase -Id 'negative-default' -Mode 'other' -Value -1 -Items @(-1, 0, 4)
    }

    It 'covers regex switch matching' {
        Assert-HHGoldenCase -Id 'regex-match' -Mode 'regex-42' -Value 2 -Items @(1)
    }

    It 'covers wildcard switch and trap handling' {
        Assert-HHGoldenCase -Id 'wildcard-and-trap' -Mode 'wildcard-value' -Value 1 `
            -Items @(1) -ThrowInTrapScope
    }

    It 'covers the typed catch' {
        Assert-HHGoldenCase -Id 'catch-invalid' -Mode 'throw-invalid' -Value 1 -Items @(1)
    }

    It 'covers the fallback catch' {
        Assert-HHGoldenCase -Id 'catch-other' -Mode 'throw-other' -Value 1 -Items @(1)
    }
}
