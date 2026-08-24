if ([string]::IsNullOrWhiteSpace($env:HH_TEST_MODULE_PATH)) {
    throw 'HH_TEST_MODULE_PATH is required for SQLite fault integration proof.'
}

Describe 'packaged SQLite WAL contention' -Tag Integration {
    It 'keeps the committed writer intact when a competing writer is busy' {
        Import-Module $env:HH_TEST_MODULE_PATH -Force
        $module = Get-Module HostHunterNextGeneration
        $provider = Join-Path (Split-Path -Parent $env:HH_TEST_MODULE_PATH) 'lib'
        $result = & $module {
            param($Root, $Provider)
            $persistence = Get-HHPersistenceContext -DataRoot $Root
            $key = [byte[]](1..32)
            $null = Initialize-HHSqliteDatabase -PersistenceContext $persistence `
                -MasterKey $key -ProviderRoot $Provider
            $first = New-HHSqliteConnection -DatabasePath $persistence.DatabasePath `
                -Mode ReadWrite -ProviderRoot $Provider
            $second = New-HHSqliteConnection -DatabasePath $persistence.DatabasePath `
                -Mode ReadWrite -ProviderRoot $Provider
            $second.DefaultTimeout = 1
            $null = Invoke-HHSqliteNonQuery -Connection $second -Sql 'PRAGMA busy_timeout=100;'
            $firstTransaction = $first.BeginTransaction()
            try {
                $null = Invoke-HHSqliteNonQuery -Connection $first `
                    -Transaction $firstTransaction `
                    -Sql "UPDATE target_store_state SET snapshot_hash=zeroblob(32) WHERE singleton_id=1;"
                $busy = $null
                try {
                    $secondTransaction = $second.BeginTransaction()
                    try {
                        $null = Invoke-HHSqliteNonQuery -Connection $second `
                            -Transaction $secondTransaction `
                            -Sql "UPDATE target_store_state SET snapshot_hash=randomblob(32) WHERE singleton_id=1;"
                    }
                    finally { $secondTransaction.Dispose() }
                }
                catch { $busy = $_ }
                $firstTransaction.Commit()
                $stored = [string](Invoke-HHSqliteScalar -Connection $first `
                    -Sql 'SELECT hex(snapshot_hash) FROM target_store_state WHERE singleton_id=1;')
                [ordered]@{
                    BusyException = $busy.Exception.GetType().FullName
                    BusyMessage = $busy.Exception.ToString()
                    StoredValue = $stored
                    JournalMode = [string](Invoke-HHSqliteScalar -Connection $first -Sql 'PRAGMA journal_mode;')
                }
            }
            finally {
                $firstTransaction.Dispose()
                $first.Dispose()
                $second.Dispose()
                [Array]::Clear($key, 0, $key.Length)
            }
        } (Join-Path $TestDrive 'wal') $provider

        $result.BusyException | Should -Match 'MethodInvocationException'
        $result.BusyMessage | Should -Match '(?i)(locked|busy)'
        $result.StoredValue | Should -BeExactly ('0' * 64)
        $result.JournalMode | Should -BeExactly wal
    }
}
