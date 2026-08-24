BeforeAll {
    $sourceRoot = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
        Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration'
    }
    else { $env:HH_TEST_SOURCE_ROOT }
    . (Join-Path $sourceRoot 'Private/DurableFilePublisher.ps1')
}

Describe 'durable file publisher' -Tag Unit {
    BeforeEach {
        $script:root = Join-Path $TestDrive ([Guid]::NewGuid().ToString('N'))
        [IO.Directory]::CreateDirectory($script:root) | Out-Null
    }

    It 'atomically publishes a same-parent regular file without replacement' {
        $source = Join-Path $script:root '.staging.tmp'
        $destination = Join-Path $script:root 'output.hhout'
        [IO.File]::WriteAllText($source, 'durable content')

        Publish-HHDurableFile -SourcePath $source -DestinationPath $destination

        $source | Should -Not -Exist
        $destination | Should -Exist
        [IO.File]::ReadAllText($destination) | Should -BeExactly 'durable content'
    }

    It 'fails closed with Collision and preserves both files' {
        $source = Join-Path $script:root '.staging.tmp'
        $destination = Join-Path $script:root 'output.hhout'
        [IO.File]::WriteAllText($source, 'new')
        [IO.File]::WriteAllText($destination, 'existing')

        $failure = $null
        try {
            Publish-HHDurableFile -SourcePath $source -DestinationPath $destination
        }
        catch { $failure = $_.Exception }

        $failure | Should -Not -BeNullOrEmpty
        [string]$failure.InnerException.FailureState | Should -BeExactly Collision
        [IO.File]::ReadAllText($source) | Should -BeExactly 'new'
        [IO.File]::ReadAllText($destination) | Should -BeExactly 'existing'
    }

    It 'rejects a cross-directory publication before rename' {
        $other = Join-Path $script:root 'other'
        [IO.Directory]::CreateDirectory($other) | Out-Null
        $source = Join-Path $script:root '.staging.tmp'
        $destination = Join-Path $other 'output.hhout'
        [IO.File]::WriteAllText($source, 'new')

        $failure = $null
        try {
            Publish-HHDurableFile -SourcePath $source -DestinationPath $destination
        }
        catch { $failure = $_.Exception }

        [string]$failure.InnerException.FailureState | Should -BeExactly PreRename
        $source | Should -Exist
        $destination | Should -Not -Exist
    }

    It 'rejects a linked source before rename' -Skip:$IsWindows {
        $real = Join-Path $script:root 'real.tmp'
        $source = Join-Path $script:root 'linked.tmp'
        $destination = Join-Path $script:root 'output.hhout'
        [IO.File]::WriteAllText($real, 'new')
        [IO.File]::CreateSymbolicLink($source, $real) | Out-Null

        { Publish-HHDurableFile -SourcePath $source -DestinationPath $destination } |
            Should -Throw '*regular, non-link*'
        $source | Should -Exist
        $destination | Should -Not -Exist
    }

    It 'prefers a package-adjacent helper with the expected exact filename' {
        $privateRoot = Join-Path $script:root 'Private'
        $interopRoot = Join-Path $privateRoot 'Interop'
        [IO.Directory]::CreateDirectory($interopRoot) | Out-Null
        Copy-Item -LiteralPath (Join-Path $sourceRoot 'Private/DurableFilePublisher.ps1') `
            -Destination (Join-Path $privateRoot 'DurableFilePublisher.ps1')
        Copy-Item -LiteralPath (
            Join-Path $env:HH_DURABILITY_HELPER_ROOT 'HostHunter.Persistence.Durability.dll'
        ) -Destination (Join-Path $interopRoot 'HostHunter.Persistence.Durability.dll')

        $resolved = & {
            . (Join-Path $privateRoot 'DurableFilePublisher.ps1')
            Get-HHDurablePublisherAssemblyPath
        }
        $resolved | Should -BeExactly (
            Join-Path $interopRoot 'HostHunter.Persistence.Durability.dll'
        )
    }
}
