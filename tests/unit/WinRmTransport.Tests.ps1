BeforeAll {
    $sourceRoot = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
        Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration'
    }
    else {
        $env:HH_TEST_SOURCE_ROOT
    }
    . (Join-Path $sourceRoot 'Private/WinRmTransport.ps1')
}

Describe 'WinRM platform boundary' -Tag Unit {
    BeforeEach {
        $env:HH_COVERAGE_CASE = [Guid]::NewGuid().ToString('N')
    }

    It 'rejects WinRM on a non-Windows controller' {
        { Assert-HHWinRmControllerSupported -IsWindowsController $false } |
            Should -Throw '*supported Windows controller*'
    }

    It 'accepts a supported Windows controller' {
        { Assert-HHWinRmControllerSupported -IsWindowsController $true } |
            Should -Not -Throw
    }

    It 'fails closed while real WinRM remains unqualified' {
        { Test-HHWinRmPowerShellEndpoint -Target @{ Name = 'win' } -IsWindowsController $true } |
            Should -Throw '*qualification is blocked*'
    }
}
