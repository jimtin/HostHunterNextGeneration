$sourceRoot = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
    (Resolve-Path (Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration')).Path
}
else { $env:HH_TEST_SOURCE_ROOT }
Import-Module (Join-Path $sourceRoot 'HostHunterNextGeneration.psd1') -Force

Describe 'SQLite target repository domain and transaction adapter' -Tag Unit {
    InModuleScope HostHunterNextGeneration {
        BeforeEach {
            $script:masterKey = [byte[]](1..32)
            $script:databaseId = [Guid]::Parse('11111111-1111-1111-1111-111111111111').ToByteArray()
            $script:ledgerId = [Guid]::Parse('22222222-2222-2222-2222-222222222222').ToByteArray()
            $script:zeroMac = [byte[]]::new(32)
            $script:mutationId = [Guid]::Parse('33333333-3333-3333-3333-333333333333').ToByteArray()
            $script:now = [DateTimeOffset]::Parse('2026-08-24T10:20:30Z')
            $script:connection = [pscustomobject]@{ DataSource = '/test/hosthunter.db' }
            $script:transaction = [pscustomobject]@{ Id = 'transaction' }
        }

        BeforeAll {
        function New-RepositoryTestTarget {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
                'PSUseShouldProcessForStateChangingFunctions',
                '',
                Justification = 'Creates an in-memory test value only.'
            )]
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
                'PSAvoidUsingPlainTextForPassword',
                'CredentialStorage',
                Justification = 'CredentialStorage is a non-secret test enum, not password material.'
            )]
            param(
                [string]$Name = 'alpha',
                [string]$HostName = 'alpha.example.test',
                [string]$UserName = 'operator',
                [bool]$IsActive = $true,
                [string]$Authentication = 'Password',
                [string]$CredentialStorage,
                [string]$KeyPath = $null
            )

            $parameters = @{
                Name = $Name
                Transport = 'SSH'
                HostName = $HostName
                Port = 22
                UserName = $UserName
                Authentication = $Authentication
                PowerShellRuntime = 'PowerShell7'
                HostKeyFingerprint = ('SHA256:' + ('A' * 43))
                KeyPath = $KeyPath
                IsActive = $IsActive
                LastValidatedAtUtc = '2026-08-24T00:00:00.0000000Z'
                LastValidatedPSEdition = 'Core'
                LastValidatedPowerShellVersion = '7.6.5'
                LastValidatedExecutionMode = 'Direct'
            }
            if ($PSBoundParameters.ContainsKey('CredentialStorage')) {
                $parameters.CredentialStorage = $CredentialStorage
            }
            New-HHTargetRecord @parameters
        }

        function New-RepositoryTestEntry {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
                'PSUseShouldProcessForStateChangingFunctions',
                '',
                Justification = 'Creates an in-memory test value only.'
            )]
            param(
                [object]$Target = (New-RepositoryTestTarget),
                [long]$Revision = 1
            )

            [pscustomobject]@{ Target = $Target; Revision = $Revision }
        }

        function ConvertTo-RepositoryTestRow {
            param([object]$Entry)

            $item = $Entry.Target
            [pscustomobject]@{
                name = $item.Name
                transport = $item.Transport
                host_name = $item.HostName
                port = [long]$item.Port
                user_name = $item.UserName
                authentication = $item.Authentication
                credential_storage = $item.CredentialStorage
                powershell_runtime = $item.PowerShellRuntime
                host_key_fingerprint = $item.HostKeyFingerprint
                key_path = $item.KeyPath
                is_active = if ($item.IsActive) { 1L } else { 0L }
                last_validated_at_utc = $item.LastValidatedAtUtc
                last_validated_ps_edition = $item.LastValidatedPSEdition
                last_validated_powershell_version = $item.LastValidatedPowerShellVersion
                last_validated_execution_mode = $item.LastValidatedExecutionMode
                revision = $Entry.Revision
            }
        }

        function Set-RepositoryQueryFixture {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
                'PSUseShouldProcessForStateChangingFunctions',
                '',
                Justification = 'Configures Pester mocks in an isolated test scope.'
            )]
            param(
                [object[]]$Entry,
                [long]$Generation = 0,
                [byte[]]$PriorMutationMac = ([byte[]]::new(32)),
                [switch]$TamperMac
            )

            $evidence = Get-HHTargetRepositoryStateEvidence `
                -DatabaseId $script:databaseId `
                -LedgerId $script:ledgerId `
                -SchemaVersion 1 `
                -Generation $Generation `
                -PriorMutationMac $PriorMutationMac `
                -Target $Entry `
                -MasterKey $script:masterKey
            $stateMac = [byte[]]$evidence.TargetStateMac.Clone()
            if ($TamperMac) { $stateMac[0] = $stateMac[0] -bxor 0xff }
            $script:queryState = [pscustomobject]@{
                database_id = $script:databaseId
                ledger_id = $script:ledgerId
                format_version = 1L
                generation = $Generation
                snapshot_hash = $evidence.SnapshotHash
                target_state_mac = $stateMac
                prior_mutation_mac = $PriorMutationMac
                last_mutation_id = $null
            }
            $script:queryRows = @($Entry | ForEach-Object { ConvertTo-RepositoryTestRow -Entry $_ })
            $script:expectedAnchor = [pscustomobject]@{
                DatabaseId = $script:databaseId
                LedgerId = $script:ledgerId
                SchemaVersion = 1
                TargetGeneration = $Generation
                TargetStateMac = $stateMac
            }
            $script:nonQueries = [Collections.Generic.List[object]]::new()
            Mock Invoke-HHSqliteQuery {
                param($Connection, $Sql, $Parameters, $Transaction)
                $null = $Connection, $Parameters, $Transaction
                if ($Sql -match 'expected_count') {
                    $encryptedCount = @($script:queryRows | Where-Object {
                            $_.authentication -ceq 'Password' -and
                            $_.credential_storage -ceq 'Encrypted'
                        }).Count
                    return @([pscustomobject]@{
                            expected_count = [long]$encryptedCount
                            actual_count = [long]$encryptedCount
                            invalid_count = 0L
                        })
                }
                if ($Sql -match 'FROM database_identity') { return @($script:queryState) }
                if ($Sql -match 'FROM target_profiles') { return @($script:queryRows) }
                throw "Unexpected query: $Sql"
            }
            Mock Invoke-HHSqliteNonQuery {
                param($Connection, $Sql, $Parameters, $Transaction)
                $null = $Connection, $Transaction
                $script:nonQueries.Add([pscustomobject]@{ Sql = $Sql; Parameters = $Parameters })
                if ($Sql -match '^UPDATE target_store_state') { return 1 }
                return 1
            }
        }

        }

        It 'authenticates a deterministic ordinal snapshot containing active and inactive revisions' {
            $alpha = New-RepositoryTestEntry -Target (New-RepositoryTestTarget) -Revision 2
            $beta = New-RepositoryTestEntry -Target (
                New-RepositoryTestTarget -Name beta -HostName beta.example.test -IsActive $false
            ) -Revision 7

            $first = Get-HHTargetRepositoryStateEvidence `
                -DatabaseId $script:databaseId -LedgerId $script:ledgerId `
                -SchemaVersion 1 -Generation 4 -PriorMutationMac $script:zeroMac `
                -Target @($beta, $alpha) -MasterKey $script:masterKey
            $second = Get-HHTargetRepositoryStateEvidence `
                -DatabaseId $script:databaseId -LedgerId $script:ledgerId `
                -SchemaVersion 1 -Generation 4 -PriorMutationMac $script:zeroMac `
                -Target @($alpha, $beta) -MasterKey $script:masterKey
            (Test-HHPersistenceBytesEqual -Left $first.SnapshotHash -Right $second.SnapshotHash) |
                Should -BeTrue
            (Test-HHPersistenceBytesEqual -Left $first.TargetStateMac -Right $second.TargetStateMac) |
                Should -BeTrue
            @($first.Entries.Target.Name) | Should -Be @('alpha', 'beta')

            $changedInactive = Get-HHTargetRepositoryStateEvidence `
                -DatabaseId $script:databaseId -LedgerId $script:ledgerId `
                -SchemaVersion 1 -Generation 4 -PriorMutationMac $script:zeroMac `
                -Target @($alpha, (New-RepositoryTestEntry -Target $beta.Target -Revision 8)) `
                -MasterKey $script:masterKey
            (Test-HHPersistenceBytesEqual -Left $first.TargetStateMac -Right $changedInactive.TargetStateMac) |
                Should -BeFalse
        }

        It 'rejects malformed identity lengths null entries and invalid revisions' {
            $entry = New-RepositoryTestEntry
            {
                Get-HHTargetRepositoryStateEvidence `
                    -DatabaseId ([byte[]]::new(15)) -LedgerId $script:ledgerId `
                    -SchemaVersion 1 -Generation 0 -PriorMutationMac $script:zeroMac `
                    -Target @($entry) -MasterKey $script:masterKey
            } | Should -Throw '*invalid lengths*'
            { ConvertTo-HHTargetRepositoryEntry -InputObject $null } | Should -Throw '*cannot be null*'
            { ConvertTo-HHTargetRepositoryEntry -InputObject $entry.Target } | Should -Throw '*Revision*'
            { ConvertTo-HHTargetRepositoryEntry -InputObject ([pscustomobject]@{ Target = $entry.Target; Revision = 0 }) } |
                Should -Throw '*greater than zero*'
        }

        It 'preserves exact comparison and replace or Add activity semantics' {
            $alpha = New-RepositoryTestTarget
            $beta = New-RepositoryTestTarget -Name beta -HostName beta.example.test
            (Test-HHTargetRepositoryRecordExactMatch -ActualTarget $alpha -ExpectedTarget $alpha) |
                Should -BeTrue
            (Test-HHTargetRepositoryRecordExactMatch `
                -ActualTarget $alpha `
                -ExpectedTarget (New-RepositoryTestTarget -UserName changed)) | Should -BeFalse

            $replaced = @(Merge-HHTargetRepositoryRecord `
                    -ExistingTarget @($alpha, $beta) `
                    -IncomingTarget @(New-RepositoryTestTarget -Name gamma -HostName gamma.example.test))
            @($replaced | Where-Object IsActive).Name | Should -BeExactly gamma
            @($replaced | Where-Object { -not $_.IsActive }).Count | Should -Be 2

            $added = @(Merge-HHTargetRepositoryRecord `
                    -ExistingTarget $replaced `
                    -IncomingTarget @(New-RepositoryTestTarget -Name delta -HostName delta.example.test) `
                    -Add)
            @($added | Where-Object IsActive).Name | Should -Be @('delta', 'gamma')
        }

        It 'handles an authenticated empty repository and first-target mutation explicitly' {
            @(Select-HHTargetRepositoryTarget -Target @()).Count | Should -Be 0
            @(Select-HHTargetRepositoryTarget -Target @() -Name @('alpha')).Count |
                Should -Be 0

            $alpha = New-RepositoryTestTarget
            $merged = @(Merge-HHTargetRepositoryRecord `
                    -ExistingTarget @() `
                    -IncomingTarget @($alpha))
            $merged.Count | Should -Be 1
            $merged[0].Name | Should -BeExactly alpha
            $merged[0].IsActive | Should -BeTrue

            @(Get-HHTargetRepositoryEntriesForMutation `
                    -ExistingEntry @() `
                    -Target @()).Count | Should -Be 0
            $created = @(Get-HHTargetRepositoryEntriesForMutation `
                    -ExistingEntry @() `
                    -Target @($alpha))
            $created.Count | Should -Be 1
            $created[0].Target.Name | Should -BeExactly alpha
            $created[0].Revision | Should -Be 1
        }

        It 'treats a null optional field mismatch as an exact CAS mismatch' {
            $withFingerprint = New-RepositoryTestTarget
            $withoutFingerprint = $withFingerprint.PSObject.Copy()
            $withoutFingerprint.HostKeyFingerprint = $null

            (Test-HHTargetRepositoryRecordExactMatch `
                    -ActualTarget $withoutFingerprint -ExpectedTarget $withFingerprint) |
                Should -BeFalse
            (Test-HHTargetRepositoryRecordExactMatch `
                    -ActualTarget $withFingerprint -ExpectedTarget $withoutFingerprint) |
                Should -BeFalse
        }

        It 'filters display targets case-insensitively and marks them unverified' {
            $entries = @(
                New-RepositoryTestEntry
                New-RepositoryTestEntry -Target (
                    New-RepositoryTestTarget -Name beta -HostName beta.example.test -IsActive $false
                )
            )
            Set-RepositoryQueryFixture -Entry $entries
            $display = Read-HHTargetRepositoryDisplaySnapshot `
                -Connection $script:connection `
                -Name BETA
            $display.IntegrityVerified | Should -BeFalse
            @($display.Targets).Count | Should -Be 1
            $display.Targets[0].Name | Should -BeExactly beta
            {
                Read-HHTargetRepositoryDisplaySnapshot -Connection $script:connection -Name ' '
            } | Should -Throw '*filters cannot be empty*'
        }

        It 'reads authenticated targets when a public caller is in WhatIf mode' {
            $entry = New-RepositoryTestEntry
            Set-RepositoryQueryFixture -Entry @($entry) -Generation 1

            $snapshot = & {
                $WhatIfPreference = $true
                Read-HHTargetRepositorySnapshot `
                    -Connection $script:connection `
                    -MasterKey $script:masterKey `
                    -ExpectedAnchor $script:expectedAnchor
            }

            @($snapshot.Targets).Count | Should -Be 1
            $snapshot.Targets[0].Name | Should -BeExactly alpha
        }

        It 'authenticates a snapshot and rejects state or anchor tampering' {
            $entry = New-RepositoryTestEntry
            Set-RepositoryQueryFixture -Entry @($entry)
            $snapshot = Read-HHTargetRepositorySnapshot `
                -Connection $script:connection `
                -MasterKey $script:masterKey
            $snapshot.IntegrityVerified | Should -BeTrue
            $snapshot.Targets[0].Name | Should -BeExactly alpha

            Set-RepositoryQueryFixture -Entry @($entry) -TamperMac
            {
                Read-HHTargetRepositorySnapshot `
                    -Connection $script:connection `
                    -MasterKey $script:masterKey
            } | Should -Throw -ErrorId 'AuditIntegrityFailed*'

            Set-RepositoryQueryFixture -Entry @($entry)
            $badAnchor = [pscustomobject]@{
                DatabaseId = $script:databaseId
                LedgerId = $script:ledgerId
                SchemaVersion = 1
                TargetGeneration = 9L
                TargetStateMac = $script:queryState.target_state_mac
            }
            {
                Read-HHTargetRepositorySnapshot `
                    -Connection $script:connection `
                    -MasterKey $script:masterKey `
                    -ExpectedAnchor $badAnchor
            } | Should -Throw -ErrorId 'AuditIntegrityFailed*'
            {
                Read-HHTargetRepositorySnapshot `
                    -Connection $script:connection `
                    -MasterKey $script:masterKey `
                    -ExpectedAnchor ([pscustomobject]@{ TargetGeneration = 0L })
            } | Should -Throw -ErrorId 'AuditIntegrityFailed*'

            Set-RepositoryQueryFixture -Entry @($entry)
            $script:queryState.format_version = 2L
            {
                Read-HHTargetRepositorySnapshot `
                    -Connection $script:connection `
                    -MasterKey $script:masterKey
            } | Should -Throw -ErrorId 'AuditIntegrityFailed*'

            Set-RepositoryQueryFixture -Entry @($entry)
            $script:queryState.last_mutation_id = [byte[]]::new(15)
            {
                Read-HHTargetRepositorySnapshot `
                    -Connection $script:connection `
                    -MasterKey $script:masterKey
            } | Should -Throw -ErrorId 'AuditIntegrityFailed*'
        }

        It 'sets a replacement through generation CAS and increments changed revisions' {
            $existing = @(
                New-RepositoryTestEntry -Target (New-RepositoryTestTarget) -Revision 4
                New-RepositoryTestEntry -Target (
                    New-RepositoryTestTarget -Name beta -HostName beta.example.test
                ) -Revision 2
            )
            Set-RepositoryQueryFixture -Entry $existing -Generation 6
            $receipt = Set-HHTargetRepository `
                -Connection $script:connection `
                -Transaction $script:transaction `
                -MasterKey $script:masterKey `
                -Target @(New-RepositoryTestTarget -Name gamma -HostName gamma.example.test) `
                -ExpectedGeneration 6 `
                -MutationId $script:mutationId `
                -RequestedAtUtc $script:now `
                -ExpectedAnchor $script:expectedAnchor

            $receipt.PreviousGeneration | Should -Be 6
            $receipt.CurrentGeneration | Should -Be 7
            $receipt.Prepared | Should -BeTrue
            $receipt.Committed | Should -BeFalse
            @($receipt.CurrentTargets | Where-Object IsActive).Name | Should -BeExactly gamma
            @($script:nonQueries | Where-Object Sql -Match 'INSERT INTO target_mutations').Count |
                Should -Be 1
            @($script:nonQueries | Where-Object Sql -Match '^UPDATE target_store_state').Count |
                Should -Be 1
            @($script:nonQueries | Where-Object Sql -Match 'INSERT INTO target_profiles').Count |
                Should -Be 3
        }

        It 'fails stale generation before issuing mutation statements' {
            Set-RepositoryQueryFixture -Entry @((New-RepositoryTestEntry)) -Generation 3
            {
                Set-HHTargetRepository `
                    -Connection $script:connection -Transaction $script:transaction `
                    -MasterKey $script:masterKey -Target @(New-RepositoryTestTarget) `
                    -ExpectedGeneration 2 -MutationId $script:mutationId `
                    -RequestedAtUtc $script:now `
                    -ExpectedAnchor $script:expectedAnchor
            } | Should -Throw -ErrorId 'TargetStoreCompareAndSwapFailed*'
            $script:nonQueries.Count | Should -Be 0
        }

        It 'updates one exact profile and rejects a stale expected record' {
            $entry = New-RepositoryTestEntry -Revision 5
            Set-RepositoryQueryFixture -Entry @($entry) -Generation 1
            $replacement = New-RepositoryTestTarget -UserName key-operator -Authentication PublicKey -KeyPath '/tmp/key'
            $receipt = Update-HHTargetRepositoryRecord `
                -Connection $script:connection -Transaction $script:transaction `
                -MasterKey $script:masterKey -Target $replacement -ExpectedTarget $entry.Target `
                -MutationId $script:mutationId -RequestedAtUtc $script:now `
                -ExpectedAnchor $script:expectedAnchor
            $receipt.PreviousTarget.Authentication | Should -BeExactly Password
            $receipt.CurrentTarget.Authentication | Should -BeExactly PublicKey
            $receipt.CurrentGeneration | Should -Be 2
            $receipt.Prepared | Should -BeTrue
            $receipt.Committed | Should -BeFalse

            Set-RepositoryQueryFixture -Entry @($entry) -Generation 1
            {
                Update-HHTargetRepositoryRecord `
                    -Connection $script:connection -Transaction $script:transaction `
                    -MasterKey $script:masterKey -Target $replacement `
                    -ExpectedTarget (New-RepositoryTestTarget -UserName stale) `
                    -MutationId $script:mutationId -RequestedAtUtc $script:now `
                    -ExpectedAnchor $script:expectedAnchor
            } | Should -Throw -ErrorId 'TargetStoreCompareAndSwapFailed*'
        }

        It 'hard-deletes all requested profiles atomically including the last profile' {
            $entries = @(
                New-RepositoryTestEntry
                New-RepositoryTestEntry -Target (
                    New-RepositoryTestTarget -Name beta -HostName beta.example.test -IsActive $false
                )
            )
            Set-RepositoryQueryFixture -Entry $entries -Generation 8
            $receipt = Remove-HHTargetRepository `
                -Connection $script:connection -Transaction $script:transaction `
                -MasterKey $script:masterKey -Name alpha, beta `
                -MutationId $script:mutationId -RequestedAtUtc $script:now `
                -ExpectedAnchor $script:expectedAnchor
            $receipt.CurrentGeneration | Should -Be 9
            @($receipt.CurrentTargets).Count | Should -Be 0

            Set-RepositoryQueryFixture -Entry $entries -Generation 8
            {
                Remove-HHTargetRepository `
                    -Connection $script:connection -Transaction $script:transaction `
                    -MasterKey $script:masterKey -Name missing `
                    -MutationId $script:mutationId -RequestedAtUtc $script:now `
                    -ExpectedAnchor $script:expectedAnchor
            } | Should -Throw '*unknown target*'
            $script:nonQueries.Count | Should -Be 0
        }

        It 'rejects duplicate removal names and invalid mutation identifiers' {
            Set-RepositoryQueryFixture -Entry @((New-RepositoryTestEntry))
            {
                Remove-HHTargetRepository `
                    -Connection $script:connection -Transaction $script:transaction `
                    -MasterKey $script:masterKey -Name alpha, ALPHA `
                    -MutationId $script:mutationId -RequestedAtUtc $script:now `
                    -ExpectedAnchor $script:expectedAnchor
            } | Should -Throw '*must be unique*'

            $snapshot = Read-HHTargetRepositorySnapshot `
                -Connection $script:connection -Transaction $script:transaction `
                -MasterKey $script:masterKey
            {
                Write-HHTargetRepositoryMutation `
                    -Connection $script:connection -Transaction $script:transaction `
                    -MasterKey $script:masterKey -MutationId ([byte[]]::new(15)) `
                    -RequestedAtUtc $script:now -CurrentSnapshot $snapshot `
                    -Target $snapshot.Targets
            } | Should -Throw '*exactly 16 bytes*'
        }

        It 'returns authenticated and display mutation identifiers and rejects a missing state row' {
            Set-RepositoryQueryFixture -Entry @((New-RepositoryTestEntry)) -Generation 2
            $script:queryState.last_mutation_id = $script:mutationId
            $authenticated = Read-HHTargetRepositorySnapshot `
                -Connection $script:connection -MasterKey $script:masterKey
            $display = Read-HHTargetRepositoryDisplaySnapshot -Connection $script:connection
            (Test-HHPersistenceBytesEqual -Left $authenticated.LastMutationId `
                    -Right $script:mutationId) | Should -BeTrue
            (Test-HHPersistenceBytesEqual -Left $display.LastMutationId `
                    -Right $script:mutationId) | Should -BeTrue

            Mock Invoke-HHSqliteQuery { return @() }
            {
                Read-HHTargetRepositoryDisplaySnapshot -Connection $script:connection
            } | Should -Throw -ErrorId 'AuditIntegrityFailed*'
        }

        It 'preserves unchanged revisions and unrelated profiles during exact CAS update' {
            $alpha = New-RepositoryTestEntry -Revision 5
            $beta = New-RepositoryTestEntry -Target (
                New-RepositoryTestTarget -Name beta -HostName beta.example.test
            ) -Revision 7
            $unchanged = @(Get-HHTargetRepositoryEntriesForMutation `
                    -ExistingEntry @($alpha, $beta) -Target @($alpha.Target, $beta.Target))
            @($unchanged.Revision) | Should -Be @(5L, 7L)

            Set-RepositoryQueryFixture -Entry @($alpha, $beta) -Generation 3
            $replacement = New-RepositoryTestTarget -UserName key-operator `
                -Authentication PublicKey -KeyPath '/tmp/key'
            $receipt = Update-HHTargetRepositoryRecord `
                -Connection $script:connection -Transaction $script:transaction `
                -MasterKey $script:masterKey -Target $replacement -ExpectedTarget $alpha.Target `
                -MutationId $script:mutationId -RequestedAtUtc $script:now `
                -ExpectedAnchor $script:expectedAnchor
            @($receipt.CurrentTarget).Count | Should -Be 1
            @($script:nonQueries | Where-Object {
                    $_.Sql -Match 'INSERT INTO target_profiles' -and
                    $_.Parameters.name -ceq 'beta'
                }).Count | Should -Be 1
        }

        It 'fails both pre-write and final generation CAS races' {
            Set-RepositoryQueryFixture -Entry @((New-RepositoryTestEntry)) -Generation 4
            $snapshot = Read-HHTargetRepositorySnapshot `
                -Connection $script:connection -MasterKey $script:masterKey
            $script:queryState.generation = 5L
            {
                Write-HHTargetRepositoryMutation `
                    -Connection $script:connection -Transaction $script:transaction `
                    -MasterKey $script:masterKey -MutationId $script:mutationId `
                    -RequestedAtUtc $script:now -CurrentSnapshot $snapshot `
                    -Target $snapshot.Targets
            } | Should -Throw -ErrorId 'TargetStoreCompareAndSwapFailed*'
            $script:nonQueries.Count | Should -Be 0

            Set-RepositoryQueryFixture -Entry @((New-RepositoryTestEntry)) -Generation 4
            Mock Invoke-HHSqliteNonQuery {
                param($Sql)
                if ($Sql -match '^UPDATE target_store_state') { return 0 }
                return 1
            }
            {
                Set-HHTargetRepository `
                    -Connection $script:connection -Transaction $script:transaction `
                    -MasterKey $script:masterKey -Target @(New-RepositoryTestTarget) `
                    -ExpectedGeneration 4 -MutationId $script:mutationId `
                    -RequestedAtUtc $script:now -ExpectedAnchor $script:expectedAnchor
            } | Should -Throw -ErrorId 'TargetStoreCompareAndSwapFailed*'
        }

        It 'rejects whitespace removal names before reading repository state' {
            Set-RepositoryQueryFixture -Entry @((New-RepositoryTestEntry))
            {
                Remove-HHTargetRepository `
                    -Connection $script:connection -Transaction $script:transaction `
                    -MasterKey $script:masterKey -Name ' ' -MutationId $script:mutationId `
                    -RequestedAtUtc $script:now -ExpectedAnchor $script:expectedAnchor
            } | Should -Throw '*cannot be empty*'
            Should -Invoke Invoke-HHSqliteQuery -Times 0
        }
    }
}
