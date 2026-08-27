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

    It 'contains exactly four managed and one native asset per Linux container RID' {
        $nativeByRid = [ordered]@{
            'linux-arm64' = 'libe_sqlite3.so'
            'linux-x64'   = 'libe_sqlite3.so'
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

    It 'keeps import and help provider-lazy' {
        $previousModulePath = $env:HH_PROVIDER_LAZY_MODULE_PATH
        try {
            $env:HH_PROVIDER_LAZY_MODULE_PATH = $script:modulePath
            $childScript = @'
$ErrorActionPreference = 'Stop'
Import-Module $env:HH_PROVIDER_LAZY_MODULE_PATH -Force -ErrorAction Stop
if ($null -eq (Get-Command -Module HostHunterNextGeneration)) { exit 2 }
if ($null -eq (Get-Help Get-HHTarget -ErrorAction Stop)) { exit 3 }
$loaded = @(
    [AppDomain]::CurrentDomain.GetAssemblies() |
        Where-Object {
            $_.GetName().Name -in @('Microsoft.Data.Sqlite', 'SQLitePCLRaw.core')
        }
)
if ($loaded.Count -ne 0) {
    $loaded | ForEach-Object { $_.GetName().Name } | Write-Error
    exit 4
}
'provider-lazy'
'@
            $encoded = [Convert]::ToBase64String(
                [Text.Encoding]::Unicode.GetBytes($childScript)
            )
            $output = @(& pwsh -NoLogo -NoProfile -NonInteractive `
                    -EncodedCommand $encoded 2>&1)
            $LASTEXITCODE | Should -Be 0 -Because ([string]::Join("`n", $output))
            $output[-1] | Should -BeExactly 'provider-lazy'
        }
        finally { $env:HH_PROVIDER_LAZY_MODULE_PATH = $previousModulePath }
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
