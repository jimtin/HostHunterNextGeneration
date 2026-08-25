$sourceRoot = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
    Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration'
}
else { $env:HH_TEST_SOURCE_ROOT }
Import-Module (Join-Path $sourceRoot 'HostHunterNextGeneration.psd1') -Force
if ([IO.Directory]::Exists('/opt/hosthunter-sqlite/lib')) {
    $env:HH_SQLITE_PROVIDER_ROOT = '/opt/hosthunter-sqlite/lib'
}

Describe 'authenticated escalation preference repository' -Tag Unit {
    InModuleScope HostHunterNextGeneration {
        BeforeEach {
            $script:root = Join-Path $TestDrive ([Guid]::NewGuid().ToString('N'))
            $script:persistence = Get-HHPersistenceContext -DataRoot $script:root
        }

        It 'resolves the unset authenticated state to the sole built-in method' -Skip:$IsMacOS {
            $context = Open-HHAuthenticatedPersistence `
                -PersistenceContext $script:persistence -AllowAnchorAdvance
            try {
                $preference = Get-HHAuthenticatedEscalationPreference -Context $context
                $preference.Method | Should -BeExactly WindowsTokenPrivilege
                $preference.Source | Should -BeExactly BuiltIn
                $preference.IsPersisted | Should -BeFalse
                $preference.Generation | Should -Be 0
                $preference.IntegrityVerified | Should -BeTrue
            }
            finally { Close-HHAuthenticatedPersistence -Context $context }
        }

        It 'persists, anchors, reopens, and idempotently returns the only allowed method' -Skip:$IsMacOS {
            $context = Open-HHAuthenticatedPersistence `
                -PersistenceContext $script:persistence -AllowAnchorAdvance
            try {
                $receipt = Set-HHAuthenticatedEscalationPreference -Context $context `
                    -Method WindowsTokenPrivilege `
                    -RequestedAtUtc ([DateTimeOffset]'2026-08-25T01:02:03Z')
                $receipt.Changed | Should -BeTrue
                $receipt.Committed | Should -BeTrue
                $receipt.Generation | Should -Be 1
                $receipt.Source | Should -BeExactly Persisted

                $again = Set-HHAuthenticatedEscalationPreference -Context $context `
                    -Method WindowsTokenPrivilege
                $again.Changed | Should -BeFalse
                $again.Generation | Should -Be 1
            }
            finally { Close-HHAuthenticatedPersistence -Context $context }

            $reopened = Open-HHAuthenticatedPersistence -PersistenceContext $script:persistence
            try {
                $preference = Get-HHAuthenticatedEscalationPreference -Context $reopened
                $preference.Method | Should -BeExactly WindowsTokenPrivilege
                $preference.Source | Should -BeExactly Persisted
                $preference.Generation | Should -Be 1
                $reopened.Anchor.ConfigurationGeneration | Should -Be 1
            }
            finally { Close-HHAuthenticatedPersistence -Context $reopened }
        }

        It 'rolls back a failed preference transaction without advancing the seal' -Skip:$IsMacOS {
            $context = Open-HHAuthenticatedPersistence `
                -PersistenceContext $script:persistence -AllowAnchorAdvance
            try {
                $before = [byte[]]$context.Anchor.Artifact.Clone()
                {
                    Invoke-HHAnchoredPersistenceTransaction -Context $context -Action {
                        param($Connection, $Transaction, $WriterContext)
                        $current = Read-HHConfigurationRepositorySnapshot `
                            -Connection $Connection -Transaction $Transaction `
                            -MasterKey $WriterContext.MasterKey
                        $null = Set-HHConfigurationEscalationPreference `
                            -Connection $Connection -Transaction $Transaction `
                            -MasterKey $WriterContext.MasterKey `
                            -Method WindowsTokenPrivilege `
                            -RequestedAtUtc ([DateTimeOffset]::UtcNow) `
                            -CurrentSnapshot $current
                        throw 'simulated rollback'
                    }
                } | Should -Throw '*simulated rollback*'
                [Convert]::ToHexString($context.Anchor.Artifact) |
                    Should -BeExactly ([Convert]::ToHexString($before))
                (Get-HHAuthenticatedEscalationPreference -Context $context).IsPersisted |
                    Should -BeFalse
            }
            finally { Close-HHAuthenticatedPersistence -Context $context }
        }

        It 'fails closed when configuration state or its append-only chain is tampered' -Skip:$IsMacOS {
            $context = Open-HHAuthenticatedPersistence `
                -PersistenceContext $script:persistence -AllowAnchorAdvance
            try {
                $null = Set-HHAuthenticatedEscalationPreference -Context $context `
                    -Method WindowsTokenPrivilege
                $null = Invoke-HHSqliteNonQuery -Connection $context.Connection `
                    -Sql 'PRAGMA ignore_check_constraints=ON;'
                $null = Invoke-HHSqliteNonQuery -Connection $context.Connection -Sql @'
UPDATE configuration_store_state SET state_mac=zeroblob(32) WHERE singleton_id=1;
'@
                {
                    Read-HHConfigurationRepositorySnapshot -Connection $context.Connection `
                        -MasterKey $context.MasterKey
                } | Should -Throw -ErrorId 'AuditIntegrityFailed*'
            }
            finally { Close-HHAuthenticatedPersistence -Context $context }
        }

        It 'rejects invalid MAC inputs and a stale compare-and-swap snapshot' -Skip:$IsMacOS {
            {
                Get-HHConfigurationStateMac -DatabaseId ([byte[]](1, 2)) `
                    -LedgerId ([byte[]]::new(16)) -Generation 0 `
                    -EscalationMethod $null -PriorMutationMac ([byte[]]::new(32)) `
                    -MasterKey ([byte[]]::new(32))
            } | Should -Throw '*identity is invalid*'

            $context = Open-HHAuthenticatedPersistence `
                -PersistenceContext $script:persistence -AllowAnchorAdvance
            try {
                $stale = Read-HHConfigurationRepositorySnapshot `
                    -Connection $context.Connection -MasterKey $context.MasterKey
                $null = Set-HHAuthenticatedEscalationPreference -Context $context `
                    -Method WindowsTokenPrivilege
                $transaction = $context.Connection.BeginTransaction()
                try {
                    {
                        Set-HHConfigurationEscalationPreference `
                            -Connection $context.Connection -Transaction $transaction `
                            -MasterKey $context.MasterKey -Method WindowsTokenPrivilege `
                            -RequestedAtUtc ([DateTimeOffset]::UtcNow) `
                            -CurrentSnapshot $stale `
                            -MutationId ([Guid]::NewGuid().ToByteArray())
                    } | Should -Throw
                    $transaction.Rollback()
                }
                finally { $transaction.Dispose() }
            }
            finally { Close-HHAuthenticatedPersistence -Context $context }
        }

        It 'validates mutation identities at both MAC and repository boundaries' -Skip:$IsMacOS {
            $key = [byte[]]::new(32)
            {
                Get-HHConfigurationMutationMac -MutationId ([byte[]]::new(15)) `
                    -PreviousGeneration 0 -CurrentGeneration 1 `
                    -RequestedAtUtc '2026-08-25T00:00:00Z' `
                    -BeforeMethod WindowsTokenPrivilege `
                    -AfterMethod WindowsTokenPrivilege `
                    -PriorMutationMac ([byte[]]::new(32)) -MasterKey $key
            } | Should -Throw '*identity is invalid*'
            ([byte[]](Get-HHConfigurationMutationMac -MutationId ([byte[]]::new(16)) `
                    -PreviousGeneration 1 -CurrentGeneration 2 `
                    -RequestedAtUtc '2026-08-25T00:00:00Z' `
                    -BeforeMethod WindowsTokenPrivilege `
                    -AfterMethod WindowsTokenPrivilege `
                    -PriorMutationMac ([byte[]]::new(32)) -MasterKey $key)).Length |
                Should -Be 32

            $context = Open-HHAuthenticatedPersistence `
                -PersistenceContext $script:persistence -AllowAnchorAdvance
            try {
                $transaction = $context.Connection.BeginTransaction()
                try {
                    $snapshot = Read-HHConfigurationRepositorySnapshot `
                        -Connection $context.Connection -Transaction $transaction `
                        -MasterKey $context.MasterKey
                    {
                        Set-HHConfigurationEscalationPreference `
                            -Connection $context.Connection -Transaction $transaction `
                            -MasterKey $context.MasterKey -Method WindowsTokenPrivilege `
                            -RequestedAtUtc ([DateTimeOffset]::UtcNow) `
                            -CurrentSnapshot $snapshot -MutationId ([byte[]]::new(15))
                    } | Should -Throw '*exactly 16 bytes*'
                    $transaction.Rollback()
                }
                finally { $transaction.Dispose() }
            }
            finally { Close-HHAuthenticatedPersistence -Context $context }
        }

        It 'rejects missing configuration identity and state projections' {
            $connection = [pscustomobject]@{ DataSource = 'mock.db' }
            Mock Invoke-HHSqliteQuery {
                if ($Sql -match 'database_identity') { return @() }
                if ($Sql -match 'configuration_store_state') { return @() }
                return @()
            }
            {
                Read-HHConfigurationRepositorySnapshot -Connection $connection `
                    -MasterKey ([byte[]]::new(32))
            } | Should -Throw -ErrorId 'AuditIntegrityFailed*'

            $snapshot = [pscustomobject]@{
                Generation = 0L
                EscalationMethod = $null
                PriorMutationMac = [byte[]]::new(32)
            }
            {
                Set-HHConfigurationEscalationPreference `
                    -Connection $connection -Transaction ([pscustomobject]@{}) `
                    -MasterKey ([byte[]]::new(32)) -Method WindowsTokenPrivilege `
                    -RequestedAtUtc ([DateTimeOffset]'2026-08-25T00:00:00Z') `
                    -CurrentSnapshot $snapshot
            } | Should -Throw '*identity is missing*'
        }

        It 'rejects a forged configuration mutation chain before trusting its head' {
            $connection = [pscustomobject]@{ DataSource = 'mock.db' }
            $script:forgedBeforeMethod = $null
            Mock Invoke-HHSqliteQuery {
                if ($Sql -match 'database_identity') {
                    return [pscustomobject]@{
                        database_id = [byte[]]::new(16)
                        ledger_id = [byte[]]::new(16)
                    }
                }
                if ($Sql -match 'configuration_store_state') {
                    return [pscustomobject]@{
                        generation = 1L
                        escalation_method = 'WindowsTokenPrivilege'
                        state_mac = [byte[]]::new(32)
                        prior_mutation_mac = [byte[]]::new(32)
                        last_mutation_id = [byte[]]::new(16)
                    }
                }
                return [pscustomobject]@{
                    mutation_id = [byte[]]::new(16)
                    previous_generation = 0L
                    current_generation = 1L
                    requested_at_utc = '2026-08-25T00:00:00.0000000Z'
                    before_method = $script:forgedBeforeMethod
                    after_method = 'WindowsTokenPrivilege'
                    mutation_mac = [byte[]]::new(32)
                }
            }
            {
                Read-HHConfigurationRepositorySnapshot -Connection $connection `
                    -MasterKey ([byte[]](1..32))
            } | Should -Throw -ErrorId 'AuditIntegrityFailed*'

            $script:forgedBeforeMethod = 'WindowsTokenPrivilege'
            {
                Read-HHConfigurationRepositorySnapshot -Connection $connection `
                    -MasterKey ([byte[]](1..32))
            } | Should -Throw -ErrorId 'AuditIntegrityFailed*'
        }
    }
}
