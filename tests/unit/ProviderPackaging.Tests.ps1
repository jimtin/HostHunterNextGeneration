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
        $script:evtxMetadataPath = Join-Path `
            $script:repoRoot 'eng/forensics/evtx-dump-assets.json'
        $script:moduleManifestPath = Join-Path `
            $script:repoRoot 'src/HostHunterNextGeneration/HostHunterNextGeneration.psd1'
    }

    It 'pins the net8 provider graph and four supported RIDs' {
        [xml]$project = Get-Content -LiteralPath $script:projectPath -Raw
        $project.Project.PropertyGroup.TargetFramework | Should -BeExactly 'net8.0'
        @($project.Project.PropertyGroup.RuntimeIdentifiers -split ';' | Sort-Object) |
            Should -Be @('linux-arm64', 'linux-x64', 'osx-arm64', 'win-x64')

        $directPackages = @{}
        foreach ($reference in $project.Project.ItemGroup.PackageReference) {
            $directPackages[[string] $reference.Include] = [string] $reference.Version
        }
        $directPackages.Keys.Count | Should -Be 2
        $directPackages['Microsoft.Data.Sqlite.Core'] | Should -BeExactly '10.0.11'
        $directPackages['SQLitePCLRaw.bundle_e_sqlite3'] | Should -BeExactly '3.0.5'
    }

    It 'locks exactly the approved six-package dependency graph' {
        $lock = Get-Content -LiteralPath $script:lockPath -Raw |
            ConvertFrom-Json -Depth 20
        $dependencies = $lock.dependencies.'net8.0'
        @($dependencies.PSObject.Properties.Name | Sort-Object) | Should -Be @(
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
            'net8.0/osx-arm64'
            'net8.0/win-x64'
        )
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
        @($sbom.components.purl | Select-Object -Unique).Count | Should -Be 6
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

    It 'pins the exact evtx_dump 0.12.2 assets and distributable licenses' {
        $metadata = Get-Content -LiteralPath $script:evtxMetadataPath -Raw |
            ConvertFrom-Json -Depth 10
        $metadata.name | Should -BeExactly 'evtx_dump'
        $metadata.version | Should -BeExactly '0.12.2'
        $metadata.licenseExpression | Should -BeExactly 'MIT OR Apache-2.0'
        @($metadata.assets.PSObject.Properties.Name | Sort-Object) | Should -Be @(
            'linux-arm64'
            'linux-x64'
            'osx-arm64'
            'osx-x64'
        )
        foreach ($asset in $metadata.assets.PSObject.Properties.Value) {
            $asset.sha256 | Should -Match '^[a-f0-9]{64}$'
        }
        Join-Path $script:repoRoot 'eng/forensics/licenses/LICENSE-APACHE' |
            Should -Exist
        Join-Path $script:repoRoot 'eng/forensics/licenses/LICENSE-MIT' |
            Should -Exist
    }

    It 'declares the exact 0.3.0-preview1 package identity' {
        $manifest = Test-ModuleManifest -Path $script:moduleManifestPath -ErrorAction Stop
        $manifest.Version.ToString() | Should -BeExactly '0.3.0'
        [string]$manifest.PrivateData.PSData.Prerelease |
            Should -BeExactly 'preview1'
    }
}
