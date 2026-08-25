Set-StrictMode -Version Latest

BeforeAll {
    $sourceRoot = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
        Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration'
    }
    else {
        $env:HH_TEST_SOURCE_ROOT
    }
    $sourceRoot = (Resolve-Path -LiteralPath $sourceRoot).Path
}

Describe 'HostHunter Forensics load order' -Tag Unit {
    It 'loads every private forensics function without exporting it' {
        $module = Import-Module (Join-Path $sourceRoot 'HostHunterNextGeneration.psd1') -Force -PassThru
        try {
            & $module {
                Get-Command -Name ConvertTo-HHEcsProcessStartEvent -CommandType Function |
                    Should -Not -BeNullOrEmpty
                Get-Command -Name Write-HHForensicsEventBatch -CommandType Function |
                    Should -Not -BeNullOrEmpty
            }
            Get-Command -Name ConvertTo-HHEcsProcessStartEvent -ErrorAction SilentlyContinue |
                Should -BeNullOrEmpty
            Get-Command -Name Write-HHForensicsEventBatch -ErrorAction SilentlyContinue |
                Should -BeNullOrEmpty
            @($module.ExportedFunctions.Keys).Count | Should -Be 11
        }
        finally {
            Remove-Module $module -Force -ErrorAction SilentlyContinue
        }
    }

    It 'fails closed when the load order escapes the forensics root' {
        $copyRoot = Join-Path $TestDrive 'module-copy'
        Copy-Item -LiteralPath $sourceRoot -Destination $copyRoot -Recurse
        $manifestPath = Join-Path $copyRoot 'Forensics/Forensics.LoadOrder.psd1'
        @'
@{
    SchemaVersion = 1
    PrivateFiles = @('../Private/Configuration.ps1')
}
'@ | Set-Content -LiteralPath $manifestPath -Encoding utf8NoBOM

        { Import-Module (Join-Path $copyRoot 'HostHunterNextGeneration.psd1') -Force } |
            Should -Throw '*escapes its module root*'
    }

    It 'fails closed on duplicate load-order entries' {
        $copyRoot = Join-Path $TestDrive 'module-duplicate'
        Copy-Item -LiteralPath $sourceRoot -Destination $copyRoot -Recurse
        $manifestPath = Join-Path $copyRoot 'Forensics/Forensics.LoadOrder.psd1'
        @'
@{
    SchemaVersion = 1
    PrivateFiles = @(
        'Private/Identity/ForensicsIdentity.ps1'
        'Private/Identity/ForensicsIdentity.ps1'
    )
}
'@ | Set-Content -LiteralPath $manifestPath -Encoding utf8NoBOM

        { Import-Module (Join-Path $copyRoot 'HostHunterNextGeneration.psd1') -Force } |
            Should -Throw '*duplicated*'
    }

    It 'fails closed when the load-order manifest has unexpected metadata' {
        $copyRoot = Join-Path $TestDrive 'module-invalid-manifest'
        Copy-Item -LiteralPath $sourceRoot -Destination $copyRoot -Recurse
        $manifestPath = Join-Path $copyRoot 'Forensics/Forensics.LoadOrder.psd1'
        @'
@{
    SchemaVersion = 1
    PrivateFiles = @('Private/Identity/ForensicsIdentity.ps1')
    Unexpected = 'metadata'
}
'@ | Set-Content -LiteralPath $manifestPath -Encoding utf8NoBOM

        { Import-Module (Join-Path $copyRoot 'HostHunterNextGeneration.psd1') -Force } |
            Should -Throw '*load-order manifest is invalid*'
    }

    It 'fails closed when the load order contains a blank path' {
        $copyRoot = Join-Path $TestDrive 'module-blank-path'
        Copy-Item -LiteralPath $sourceRoot -Destination $copyRoot -Recurse
        $manifestPath = Join-Path $copyRoot 'Forensics/Forensics.LoadOrder.psd1'
        @'
@{
    SchemaVersion = 1
    PrivateFiles = @(' ')
}
'@ | Set-Content -LiteralPath $manifestPath -Encoding utf8NoBOM

        { Import-Module (Join-Path $copyRoot 'HostHunterNextGeneration.psd1') -Force } |
            Should -Throw '*contains an unsafe path*'
    }
}
