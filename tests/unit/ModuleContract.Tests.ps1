Describe 'HostHunter module contract' -Tag Unit {
    BeforeEach {
        $env:HH_COVERAGE_CASE = [Guid]::NewGuid().ToString('N')
    }

    It 'imports and exposes exactly the approved commands' {
        $sourceRoot = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
            Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration'
        }
        else {
            $env:HH_TEST_SOURCE_ROOT
        }
        $modulePath = Join-Path $sourceRoot 'HostHunterNextGeneration.psd1'
        $manifest = Import-PowerShellDataFile -LiteralPath $modulePath
        $declared = @($manifest.FunctionsToExport | Sort-Object -Unique)
        $declared.Count | Should -Be 17
        Import-Module $modulePath -Force
        $actual = @(Get-Command -Module HostHunterNextGeneration -CommandType Function |
                Select-Object -ExpandProperty Name | Sort-Object)
        $actual | Should -Be $declared
        $alias = Get-Command Get-HHTargets -Module HostHunterNextGeneration `
            -CommandType Alias
        $alias.Definition | Should -BeExactly Get-HHTarget
    }
}
