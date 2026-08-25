Describe 'Packaged SQLite provider' -Tag Integration {
    BeforeAll {
        if ([string]::IsNullOrWhiteSpace($env:HH_TEST_MODULE_PATH)) {
            throw 'HH_TEST_MODULE_PATH is required for package integration proof.'
        }
        $script:modulePath = (Resolve-Path -LiteralPath $env:HH_TEST_MODULE_PATH).Path
        if ([IO.Path]::GetExtension($script:modulePath) -cne '.psd1') {
            throw 'HH_TEST_MODULE_PATH must identify the packaged module manifest.'
        }
        $script:packageRoot = Split-Path -Parent $script:modulePath
        if ($script:packageRoot -like '*/src/HostHunterNextGeneration') {
            throw 'Source import is not package integration evidence.'
        }
    }

    It 'contains exactly four managed and one native asset per supported RID' {
        $nativeByRid = [ordered]@{
            'linux-arm64' = 'libe_sqlite3.so'
            'linux-x64'   = 'libe_sqlite3.so'
            'osx-arm64'   = 'libe_sqlite3.dylib'
            'win-x64'     = 'e_sqlite3.dll'
        }
        $managed = @(
            'Microsoft.Data.Sqlite.dll'
            'SQLitePCLRaw.batteries_v2.dll'
            'SQLitePCLRaw.core.dll'
            'SQLitePCLRaw.provider.e_sqlite3.dll'
        )

        foreach ($rid in $nativeByRid.Keys) {
            $actual = @(
                Get-ChildItem -LiteralPath (Join-Path $script:packageRoot "lib/$rid") `
                    -File |
                    Select-Object -ExpandProperty Name |
                    Sort-Object
            )
            $actual | Should -Be @(($managed + $nativeByRid[$rid]) | Sort-Object)
        }
    }

    It 'contains exactly one first-party durable publication helper outside RID provider assets' {
        $helperPath = Join-Path `
            $script:packageRoot 'Private/Interop/HostHunter.Persistence.Durability.dll'
        $helperPath | Should -Exist
        @(
            Get-ChildItem -LiteralPath $script:packageRoot `
                -Filter 'HostHunter.Persistence.Durability.dll' -File -Recurse
        ).Count | Should -Be 1

        $identity = [Reflection.AssemblyName]::GetAssemblyName($helperPath)
        $identity.Name | Should -BeExactly 'HostHunter.Persistence.Durability'
        $identity.Version.ToString() | Should -BeExactly '0.1.0.0'

        $receiptPath = [IO.Path]::GetFullPath(
            (Join-Path $script:packageRoot '../../module-package.json')
        )
        $receipt = Get-Content -LiteralPath $receiptPath -Raw |
            ConvertFrom-Json -Depth 10
        $receipt.durabilityHelper.relativePath |
            Should -BeExactly 'Private/Interop/HostHunter.Persistence.Durability.dll'
        $receipt.durabilityHelper.thirdPartyPackages | Should -Be 0
        $receipt.durabilityHelper.sha256 | Should -BeExactly (
            (Get-FileHash -LiteralPath $helperPath -Algorithm SHA256).Hash.ToLowerInvariant()
        )
    }

    It 'contains the exact pinned evtx_dump parser inventory and licenses' {
        $metadataPath = Join-Path `
            $script:packageRoot 'dependencies/evtx_dump/evtx-dump-assets.json'
        $metadata = Get-Content -LiteralPath $metadataPath -Raw |
            ConvertFrom-Json -Depth 10
        foreach ($rid in @('linux-arm64', 'linux-x64', 'osx-arm64', 'osx-x64')) {
            $parserPath = Join-Path $script:packageRoot "tools/evtx_dump/$rid/evtx_dump"
            $parserPath | Should -Exist
            (Get-FileHash -LiteralPath $parserPath -Algorithm SHA256).Hash.ToLowerInvariant() |
                Should -BeExactly ([string]$metadata.assets.$rid.sha256)
        }
        Join-Path $script:packageRoot 'dependencies/evtx_dump/LICENSE-APACHE' |
            Should -Exist
        Join-Path $script:packageRoot 'dependencies/evtx_dump/LICENSE-MIT' |
            Should -Exist
    }

    It 'keeps import and help provider-lazy' {
        Import-Module $script:modulePath -Force -ErrorAction Stop
        Get-Command -Module HostHunterNextGeneration | Should -Not -BeNullOrEmpty
        Get-Help Get-HHTarget -ErrorAction Stop | Should -Not -BeNullOrEmpty

        @(
            [AppDomain]::CurrentDomain.GetAssemblies() |
                Where-Object {
                    $_.GetName().Name -in @('Microsoft.Data.Sqlite', 'SQLitePCLRaw.core')
                }
        ).Count | Should -Be 0
    }

    It 'loads the adjacent native library and reports SQLite 3.53.4' {
        if (-not $IsLinux) {
            Set-ItResult -Skipped -Because 'Canonical package integration runs on Linux.'
            return
        }
        $architecture = [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture
        $rid = switch ($architecture) {
            ([Runtime.InteropServices.Architecture]::Arm64) { 'linux-arm64'; break }
            ([Runtime.InteropServices.Architecture]::X64) { 'linux-x64'; break }
            default { throw "Unsupported integration architecture: $architecture" }
        }
        $providerRoot = Join-Path $script:packageRoot "lib/$rid"
        foreach ($assemblyName in @(
                'SQLitePCLRaw.core.dll'
                'SQLitePCLRaw.provider.e_sqlite3.dll'
                'SQLitePCLRaw.batteries_v2.dll'
                'Microsoft.Data.Sqlite.dll'
            )) {
            [Reflection.Assembly]::LoadFrom(
                (Join-Path $providerRoot $assemblyName)
            ) | Out-Null
        }
        [SQLitePCL.Batteries_V2]::Init()

        $connection = [Microsoft.Data.Sqlite.SqliteConnection]::new('Data Source=:memory:')
        try {
            $connection.Open()
            $command = $connection.CreateCommand()
            $command.CommandText = 'SELECT sqlite_version()'
            $command.ExecuteScalar() | Should -BeExactly '3.53.4'
        }
        finally {
            $connection.Dispose()
        }
    }
}
