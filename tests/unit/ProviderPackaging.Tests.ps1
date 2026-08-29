Describe 'SQLite provider packaging contract' -Tag Unit {
    BeforeAll {
        $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        $script:projectPath = Join-Path `
            $script:repoRoot 'eng/sqlite/HostHunter.Sqlite.Dependencies.csproj'
        $script:lockPath = Join-Path $script:repoRoot 'eng/sqlite/packages.lock.json'
        $script:sbomPath = Join-Path `
            $script:repoRoot 'eng/sqlite/sqlite-dependencies.cdx.json'
        $script:durabilityProjectPath = Join-Path `
            $script:repoRoot 'eng/durability/HostHunter.Persistence.Durability.csproj'
        $script:durabilityLockPath = Join-Path `
            $script:repoRoot 'eng/durability/packages.lock.json'
        $script:moduleManifestPath = Join-Path `
            $script:repoRoot 'src/HostHunterNextGeneration/HostHunterNextGeneration.psd1'
        $script:restoreScriptPath = Join-Path `
            $script:repoRoot 'scripts/dependencies/restore-sqlite.sh'
    }

    It 'pins the net8 provider graph and two Linux container RIDs' {
        [xml]$project = Get-Content -LiteralPath $script:projectPath -Raw
        $project.Project.PropertyGroup.TargetFramework | Should -BeExactly 'net8.0'
        @($project.Project.PropertyGroup.RuntimeIdentifiers -split ';' | Sort-Object) |
            Should -Be @('linux-arm64', 'linux-x64')

        $directPackages = @{}
        foreach ($reference in $project.Project.ItemGroup.PackageReference) {
            $directPackages[[string] $reference.Include] = [string] $reference.Version
        }
        $directPackages.Keys.Count | Should -Be 3
        $directPackages['Microsoft.Data.Sqlite.Core'] | Should -BeExactly '10.0.11'
        $directPackages['SQLitePCLRaw.bundle_e_sqlite3'] | Should -BeExactly '3.0.5'
        $directPackages['JsonSchema.Net'] | Should -BeExactly '9.4.0'
    }

    It 'locks exactly the approved ten-package dependency graph' {
        $lock = Get-Content -LiteralPath $script:lockPath -Raw |
            ConvertFrom-Json -Depth 20
        $dependencies = $lock.dependencies.'net8.0'
        @($dependencies.PSObject.Properties.Name | Sort-Object) | Should -Be @(
            'Humanizer.Core'
            'Json.More.Net'
            'JsonPointer.Net'
            'JsonSchema.Net'
            'Microsoft.Data.Sqlite.Core'
            'SQLite'
            'SQLitePCLRaw.bundle_e_sqlite3'
            'SQLitePCLRaw.config.e_sqlite3'
            'SQLitePCLRaw.core'
            'SQLitePCLRaw.provider.e_sqlite3'
        )
        $dependencies.'Microsoft.Data.Sqlite.Core'.resolved |
            Should -BeExactly '10.0.11'
        $dependencies.'SQLitePCLRaw.bundle_e_sqlite3'.resolved |
            Should -BeExactly '3.0.5'
        $dependencies.SQLite.resolved | Should -BeExactly '3.53.4'

        @($lock.dependencies.PSObject.Properties.Name | Sort-Object) | Should -Be @(
            'net8.0'
            'net8.0/linux-arm64'
            'net8.0/linux-x64'
        )
    }

    It 'exports exactly the approved nine SQLite assets for each qualified RID' {
        $restoreSource = Get-Content -LiteralPath $script:restoreScriptPath -Raw
        $ridMatch = [regex]::Match(
            $restoreSource,
            '(?ms)expected_rids=\((?<body>.*?)\)'
        )
        $assetMatch = [regex]::Match(
            $restoreSource,
            '(?ms)expected_assets=\((?<body>.*?)\)'
        )
        $ridMatch.Success | Should -BeTrue
        $assetMatch.Success | Should -BeTrue

        $rids = @($ridMatch.Groups['body'].Value -split '\s+' |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        $assets = @($assetMatch.Groups['body'].Value -split '\s+' |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) })

        $rids | Should -Be @('linux-arm64', 'linux-x64')
        $assets | Should -Be @(
            'Humanizer.dll'
            'Json.More.dll'
            'JsonPointer.Net.dll'
            'JsonSchema.Net.dll'
            'Microsoft.Data.Sqlite.dll'
            'SQLitePCLRaw.batteries_v2.dll'
            'SQLitePCLRaw.core.dll'
            'SQLitePCLRaw.provider.e_sqlite3.dll'
            'libe_sqlite3.so'
        )
        $assets.Count | Should -Be 9
        @($assets | Select-Object -Unique).Count | Should -Be 9

        $restoreSource | Should -Match 'actual_rids=\(\)'
        $restoreSource | Should -Match (
            [regex]::Escape('[[ "${actual_rids[*]}" == "${expected_rids[*]}" ]]')
        )
        $restoreSource | Should -Match (
            [regex]::Escape('[[ "$(find "$rid_root" -maxdepth 1 -type f | wc -l)" -eq "${#expected_assets[@]}" ]]')
        )
        $restoreSource | Should -Match 'for asset in "\$\{expected_assets\[@\]\}"'
        $restoreSource | Should -Match '\[\[ -f "\$rid_root/\$asset" \]\]'
    }

    It 'ships an SBOM entry for every locked package' {
        $lock = Get-Content -LiteralPath $script:lockPath -Raw |
            ConvertFrom-Json -Depth 20
        $sbom = Get-Content -LiteralPath $script:sbomPath -Raw |
            ConvertFrom-Json -Depth 20
        $sbom.bomFormat | Should -BeExactly 'CycloneDX'
        $sbom.specVersion | Should -BeExactly '1.6'

        $lockedPurls = @(
            foreach ($property in $lock.dependencies.'net8.0'.PSObject.Properties) {
                "pkg:nuget/$($property.Name)@$($property.Value.resolved)"
            }
        ) | Sort-Object
        @($sbom.components.purl | Sort-Object) | Should -Be $lockedPurls
        @($sbom.components.purl | Select-Object -Unique).Count | Should -Be 10
    }

    It 'defines a dependency-free locked AnyCPU durability helper' {
        [xml]$project = Get-Content -LiteralPath $script:durabilityProjectPath -Raw
        $project.Project.PropertyGroup.TargetFramework | Should -BeExactly 'net8.0'
        $project.Project.PropertyGroup.AssemblyName |
            Should -BeExactly 'HostHunter.Persistence.Durability'
        $project.Project.PropertyGroup.RestoreLockedMode | Should -BeExactly 'true'
        @($project.SelectNodes('//PackageReference')).Count | Should -Be 0

        $lock = Get-Content -LiteralPath $script:durabilityLockPath -Raw |
            ConvertFrom-Json -Depth 10
        @($lock.dependencies.PSObject.Properties.Name) | Should -Be @('net8.0')
        @($lock.dependencies.'net8.0'.PSObject.Properties).Count | Should -Be 0
    }

    It 'declares the exact 0.4.0-preview1 package identity' {
        $manifest = Test-ModuleManifest -Path $script:moduleManifestPath -ErrorAction Stop
        $manifest.Version.ToString() | Should -BeExactly '0.4.0'
        [string]$manifest.PrivateData.PSData.Prerelease |
            Should -BeExactly 'preview1'
    }
}
