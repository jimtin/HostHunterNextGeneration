if ([string]::IsNullOrWhiteSpace($env:HH_TEST_MODULE_PATH)) {
    throw 'HH_TEST_MODULE_PATH is required for target repository integration proof.'
}
$null = (Resolve-Path -LiteralPath $env:HH_TEST_MODULE_PATH).Path
Describe 'Packaged SQLite target repository lifecycle' -Tag Integration {
    It 'persists replace Add exact-profile CAS and hard-delete across fresh connections' {
        $dataRoot = Join-Path $TestDrive 'lifecycle'
        $loadedModule = Import-Module $env:HH_TEST_MODULE_PATH -Force -PassThru
        $loadedPackageRoot = Split-Path -Parent $env:HH_TEST_MODULE_PATH
        $loadedProviderRoot = Join-Path $loadedPackageRoot 'lib'
        $loadedMasterKey = [byte[]](1..32)
        $result = & $loadedModule {
            param($DataRoot, $ProviderRoot, $MasterKey)

            function New-IntegrationTarget {
                [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
                    'PSUseShouldProcessForStateChangingFunctions',
                    '',
                    Justification = 'Creates an in-memory integration-test target only.'
                )]
                param(
                    [string]$Name,
                    [string]$HostName,
                    [bool]$IsActive = $true,
                    [string]$UserName = 'operator',
                    [string]$Authentication = 'Password',
                    [string]$KeyPath = $null
                )

                New-HHTargetRecord `
                    -Name $Name -Transport SSH -HostName $HostName -Port 22 `
                    -UserName $UserName -Authentication $Authentication `
                    -PowerShellRuntime PowerShell7 `
                    -HostKeyFingerprint ('SHA256:' + ('A' * 43)) `
                    -KeyPath $KeyPath -IsActive $IsActive `
                    -LastValidatedAtUtc '2026-08-24T00:00:00.0000000Z' `
                    -LastValidatedPSEdition Core `
                    -LastValidatedPowerShellVersion '7.6.5' `
                    -LastValidatedExecutionMode Direct
            }

            $context = Get-HHPersistenceContext -DataRoot $DataRoot
            $null = Initialize-HHSqliteDatabase `
                -PersistenceContext $context `
                -MasterKey $MasterKey `
                -ProviderRoot $ProviderRoot
            $expectedAnchor = Read-HHPersistenceAnchor `
                -PersistenceContext $context `
                -MasterKey $MasterKey
            $connection = New-HHSqliteConnection `
                -DatabasePath $context.DatabasePath `
                -Mode ReadWrite `
                -ProviderRoot $ProviderRoot
            try {
                # The common initializer calls this same evidence helper after the
                # target slice is integrated. Keeping this assignment idempotent
                # lets the focused test run during that integration window.
                $state = Read-HHTargetRepositoryIdentityState -Connection $connection
                $emptyEvidence = Get-HHTargetRepositoryStateEvidence `
                    -DatabaseId ([byte[]]$state.database_id) `
                    -LedgerId ([byte[]]$state.ledger_id) `
                    -SchemaVersion 1 `
                    -Generation 0 `
                    -PriorMutationMac ([byte[]]$state.prior_mutation_mac) `
                    -Target @() `
                    -MasterKey $MasterKey
                $null = Invoke-HHSqliteNonQuery `
                    -Connection $connection `
                    -Sql @'
UPDATE target_store_state
SET snapshot_hash=@snapshot, target_state_mac=@state
WHERE singleton_id=1 AND generation=0;
'@ `
                    -Parameters @{
                        snapshot = $emptyEvidence.SnapshotHash
                        state = $emptyEvidence.TargetStateMac
                    }

                $alpha = New-IntegrationTarget -Name alpha -HostName alpha.example.test
                $transaction = $connection.BeginTransaction()
                try {
                    $set = Set-HHTargetRepository `
                        -Connection $connection -Transaction $transaction `
                        -MasterKey $MasterKey -Target @($alpha) -ExpectedGeneration 0 `
                        -MutationId ([Guid]::NewGuid().ToByteArray()) `
                        -RequestedAtUtc ([DateTimeOffset]::UtcNow) `
                        -ExpectedAnchor $expectedAnchor
                    $transaction.Commit()
                    $expectedAnchor.TargetGeneration = $set.CurrentGeneration
                    $expectedAnchor.TargetStateMac = $set.TargetStateMac
                }
                finally { $transaction.Dispose() }

                $beta = New-IntegrationTarget -Name beta -HostName beta.example.test
                $transaction = $connection.BeginTransaction()
                try {
                    $added = Set-HHTargetRepository `
                        -Connection $connection -Transaction $transaction `
                        -MasterKey $MasterKey -Target @($beta) -Add `
                        -ExpectedGeneration $set.CurrentGeneration `
                        -MutationId ([Guid]::NewGuid().ToByteArray()) `
                        -RequestedAtUtc ([DateTimeOffset]::UtcNow) `
                        -ExpectedAnchor $expectedAnchor
                    $transaction.Commit()
                    $expectedAnchor.TargetGeneration = $added.CurrentGeneration
                    $expectedAnchor.TargetStateMac = $added.TargetStateMac
                }
                finally { $transaction.Dispose() }

                $publicKeyAlpha = New-IntegrationTarget `
                    -Name alpha -HostName alpha.example.test -UserName key-operator `
                    -Authentication PublicKey -KeyPath '/tmp/hosthunter-key'
                $transaction = $connection.BeginTransaction()
                try {
                    $updated = Update-HHTargetRepositoryRecord `
                        -Connection $connection -Transaction $transaction `
                        -MasterKey $MasterKey -Target $publicKeyAlpha -ExpectedTarget $alpha `
                        -MutationId ([Guid]::NewGuid().ToByteArray()) `
                        -RequestedAtUtc ([DateTimeOffset]::UtcNow) `
                        -ExpectedAnchor $expectedAnchor
                    $transaction.Commit()
                    $expectedAnchor.TargetGeneration = $updated.CurrentGeneration
                    $expectedAnchor.TargetStateMac = $updated.TargetStateMac
                }
                finally { $transaction.Dispose() }

                $transaction = $connection.BeginTransaction()
                try {
                    $removed = Remove-HHTargetRepository `
                        -Connection $connection -Transaction $transaction `
                        -MasterKey $MasterKey -Name alpha, beta `
                        -MutationId ([Guid]::NewGuid().ToByteArray()) `
                        -RequestedAtUtc ([DateTimeOffset]::UtcNow) `
                        -ExpectedAnchor $expectedAnchor
                    $transaction.Commit()
                }
                finally { $transaction.Dispose() }
            }
            finally { $connection.Dispose() }

            $reopened = New-HHSqliteConnection `
                -DatabasePath $context.DatabasePath `
                -Mode ReadOnly `
                -ProviderRoot $ProviderRoot
            try {
                $final = Read-HHTargetRepositorySnapshot `
                    -Connection $reopened `
                    -MasterKey $MasterKey
                $mutationCount = [long](Invoke-HHSqliteScalar `
                        -Connection $reopened `
                        -Sql 'SELECT COUNT(*) FROM target_mutations;')
                [pscustomobject]@{
                    SetGeneration = $set.CurrentGeneration
                    AddNames = @($added.CurrentTargets.Name)
                    UpdatedAuthentication = $updated.CurrentTarget.Authentication
                    RemovedCount = @($removed.CurrentTargets).Count
                    FinalGeneration = $final.Generation
                    FinalCount = @($final.Targets).Count
                    MutationCount = $mutationCount
                }
            }
            finally { $reopened.Dispose() }
        } $dataRoot $loadedProviderRoot $loadedMasterKey

        $result.SetGeneration | Should -Be 1
        @($result.AddNames) | Should -Be @('alpha', 'beta')
        $result.UpdatedAuthentication | Should -BeExactly PublicKey
        $result.RemovedCount | Should -Be 0
        $result.FinalGeneration | Should -Be 4
        $result.FinalCount | Should -Be 0
        $result.MutationCount | Should -Be 4
    }

    It 'rejects a stale generation from a competing connection without partial writes' {
        $dataRoot = Join-Path $TestDrive 'stale-generation'
        $loadedModule = Import-Module $env:HH_TEST_MODULE_PATH -Force -PassThru
        $loadedPackageRoot = Split-Path -Parent $env:HH_TEST_MODULE_PATH
        $loadedProviderRoot = Join-Path $loadedPackageRoot 'lib'
        $loadedMasterKey = [byte[]](1..32)
        $result = & $loadedModule {
            param($DataRoot, $ProviderRoot, $MasterKey)

            $context = Get-HHPersistenceContext -DataRoot $DataRoot
            $null = Initialize-HHSqliteDatabase `
                -PersistenceContext $context -MasterKey $MasterKey -ProviderRoot $ProviderRoot
            $expectedAnchor = Read-HHPersistenceAnchor `
                -PersistenceContext $context `
                -MasterKey $MasterKey
            $first = New-HHSqliteConnection `
                -DatabasePath $context.DatabasePath -Mode ReadWrite -ProviderRoot $ProviderRoot
            try {
                $state = Read-HHTargetRepositoryIdentityState -Connection $first
                $emptyEvidence = Get-HHTargetRepositoryStateEvidence `
                    -DatabaseId ([byte[]]$state.database_id) `
                    -LedgerId ([byte[]]$state.ledger_id) `
                    -SchemaVersion 1 -Generation 0 `
                    -PriorMutationMac ([byte[]]$state.prior_mutation_mac) `
                    -Target @() -MasterKey $MasterKey
                $null = Invoke-HHSqliteNonQuery -Connection $first -Sql @'
UPDATE target_store_state SET snapshot_hash=@snapshot,target_state_mac=@state
WHERE singleton_id=1 AND generation=0;
'@ -Parameters @{ snapshot = $emptyEvidence.SnapshotHash; state = $emptyEvidence.TargetStateMac }

                $target = New-HHTargetRecord `
                    -Name alpha -Transport SSH -HostName alpha.example.test -Port 22 `
                    -UserName operator -Authentication Password -PowerShellRuntime PowerShell7 `
                    -HostKeyFingerprint ('SHA256:' + ('A' * 43)) -KeyPath $null -IsActive $true `
                    -LastValidatedAtUtc '2026-08-24T00:00:00.0000000Z' `
                    -LastValidatedPSEdition Core -LastValidatedPowerShellVersion '7.6.5' `
                    -LastValidatedExecutionMode Direct
                $transaction = $first.BeginTransaction()
                try {
                    $null = Set-HHTargetRepository `
                        -Connection $first -Transaction $transaction -MasterKey $MasterKey `
                        -Target @($target) -ExpectedGeneration 0 `
                        -MutationId ([Guid]::NewGuid().ToByteArray()) `
                        -RequestedAtUtc ([DateTimeOffset]::UtcNow) `
                        -ExpectedAnchor $expectedAnchor
                    $transaction.Commit()
                    $expectedAnchor.TargetGeneration = 1L
                    $snapshotAfterCommit = Read-HHTargetRepositorySnapshot `
                        -Connection $first `
                        -MasterKey $MasterKey
                    $expectedAnchor.TargetStateMac = $snapshotAfterCommit.StateEvidence.TargetStateMac
                }
                finally { $transaction.Dispose() }

                $transaction = $first.BeginTransaction()
                try {
                    $caught = $null
                    try {
                        $null = Set-HHTargetRepository `
                            -Connection $first -Transaction $transaction -MasterKey $MasterKey `
                            -Target @($target) -ExpectedGeneration 0 `
                            -MutationId ([Guid]::NewGuid().ToByteArray()) `
                            -RequestedAtUtc ([DateTimeOffset]::UtcNow) `
                            -ExpectedAnchor $expectedAnchor
                    }
                    catch { $caught = $_ }
                    $transaction.Rollback()
                }
                finally { $transaction.Dispose() }
                $snapshot = Read-HHTargetRepositorySnapshot -Connection $first -MasterKey $MasterKey
                [pscustomobject]@{
                    ErrorId = $caught.FullyQualifiedErrorId
                    Generation = $snapshot.Generation
                    Count = @($snapshot.Targets).Count
                    MutationCount = [long](Invoke-HHSqliteScalar `
                            -Connection $first `
                            -Sql 'SELECT COUNT(*) FROM target_mutations;')
                }
            }
            finally { $first.Dispose() }
        } $dataRoot $loadedProviderRoot $loadedMasterKey

        $result.ErrorId | Should -Match '^TargetStoreCompareAndSwapFailed'
        $result.Generation | Should -Be 1
        $result.Count | Should -Be 1
        $result.MutationCount | Should -Be 1
    }
}
