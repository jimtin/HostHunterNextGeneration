$sourceRoot = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
    Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration'
}
else { $env:HH_TEST_SOURCE_ROOT }
Import-Module (Join-Path $sourceRoot 'HostHunterNextGeneration.psd1') -Force

Describe 'SQLite audit query repository' -Tag Unit {
    InModuleScope HostHunterNextGeneration {
        BeforeEach {
            $script:key = [byte[]](0..31)
            $script:databaseId = [byte[]](1..16)
            $script:ledgerId = [byte[]](17..32)
            $script:connection = [pscustomobject]@{ DataSource = '/test/hosthunter.db' }
            $script:invocationA = [Guid]::Parse('11111111-1111-1111-1111-111111111111').ToByteArray()
            $script:invocationB = [Guid]::Parse('22222222-2222-2222-2222-222222222222').ToByteArray()
            $script:batchA = [Guid]::Parse('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa').ToByteArray()
            $script:batchB = [Guid]::Parse('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb').ToByteArray()
            $script:artifactId = [Guid]::Parse('33333333-3333-3333-3333-333333333333').ToByteArray()
            $script:invocationAText = ConvertTo-HHPersistenceIdentifierText $script:invocationA
            $script:invocationBText = ConvertTo-HHPersistenceIdentifierText $script:invocationB
            $script:batchAText = ConvertTo-HHPersistenceIdentifierText $script:batchA
            $script:rows = @(
                [pscustomobject]@{
                    sequence = 3L; invocation_id = $script:invocationA; batch_id = $script:batchA
                    operation = 'InvokeCommand'; target_name = 'Alpha'; transport = 'SSH'
                    host_name = 'alpha.test'; port = 22L; user_name = 'operator'
                    authentication = 'Password'; requested_runtime = 'PowerShell7'
                    requested_execution_mode = 'Direct'; intent_at_utc = '2026-08-24T03:00:00Z'
                    status = 'Succeeded'; failure_kind = $null; dispatch_state = 'Completed'
                    outcome_status = 'Succeeded'; completed_at_utc = '2026-08-24T03:01:00Z'
                    recovery_state = 'None'; command_envelope = [byte[]](1); reason_envelope = [byte[]](2)
                    case_envelope = [byte[]](3); relative_path = 'output/a.hha'; ciphertext_bytes = 100L
                    plaintext_bytes = 25L; stream_event_count = 2L
                }
                [pscustomobject]@{
                    sequence = 2L; invocation_id = $script:invocationB; batch_id = $script:batchB
                    operation = 'TestTarget'; target_name = 'Beta'; transport = 'SSH'
                    host_name = 'beta.test'; port = 22L; user_name = 'operator'
                    authentication = 'Password'; requested_runtime = 'PowerShell7'
                    requested_execution_mode = 'Direct'; intent_at_utc = '2026-08-24T02:00:00Z'
                    status = $null; failure_kind = $null; dispatch_state = $null
                    outcome_status = $null; completed_at_utc = $null; recovery_state = $null
                    command_envelope = [byte[]](4); reason_envelope = $null; case_envelope = $null
                    relative_path = $null; ciphertext_bytes = $null; plaintext_bytes = $null
                    stream_event_count = $null
                }
                [pscustomobject]@{
                    sequence = 1L; invocation_id = [Guid]::NewGuid().ToByteArray(); batch_id = $script:batchB
                    operation = 'InvokeCommand'; target_name = 'Gamma'; transport = 'SSH'
                    host_name = 'gamma.test'; port = 22L; user_name = 'operator'
                    authentication = 'Password'; requested_runtime = 'PowerShell7'
                    requested_execution_mode = 'Direct'; intent_at_utc = '2026-08-24T01:00:00Z'
                    status = 'Failed'; failure_kind = 'TransportFailure'; dispatch_state = 'Dispatched'
                    outcome_status = 'Failed'; completed_at_utc = '2026-08-24T01:01:00Z'
                    recovery_state = 'None'; command_envelope = [byte[]](5); reason_envelope = $null
                    case_envelope = [byte[]](6); relative_path = $null; ciphertext_bytes = $null
                    plaintext_bytes = $null; stream_event_count = $null
                }
            )
            Mock Invoke-HHSqliteQuery {
                param($Connection, $Sql, $Parameters)
                $null = $Connection, $Parameters
                if ($Sql -match 'SELECT database_id') {
                    return @([pscustomobject]@{ database_id = $script:databaseId })
                }
                return @($script:rows)
            }
            Mock Unprotect-HHAuditRepositoryText {
                param($Envelope, $MasterKey, $DatabaseId, $InvocationId, $Column, $Table)
                $null = $Envelope, $MasterKey, $DatabaseId, $InvocationId, $Table
                switch ($Column) {
                    command_envelope { 'Get-Date' }
                    reason_envelope { 'triage' }
                    case_envelope { 'CASE-001' }
                }
            }
            Mock Invoke-HHSqliteNonQuery { throw 'Audit queries must be read-only.' }
        }

        It 'applies every record filter with half-open time bounds and Pending projection' {
            @(Get-HHSqliteAuditRecord -Connection $script:connection -MasterKey $script:key `
                    -InvocationId $script:invocationAText -BatchId $script:batchAText `
                    -TargetName alpha -CaseId CASE-001 -FromUtc '2026-08-24T03:00:00Z' `
                    -ToUtc '2026-08-24T04:00:00Z' -Operation InvokeCommand `
                    -Status Succeeded -BeforeSequence 4 -First 10).Count | Should -Be 1
            @(Get-HHSqliteAuditRecord -Connection $script:connection -MasterKey $script:key `
                    -TargetName BETA -Operation TestTarget -Status Pending -First 10).Count |
                Should -Be 1
            @(Get-HHSqliteAuditRecord -Connection $script:connection -MasterKey $script:key `
                    -FromUtc '2026-08-24T03:00:00Z' -ToUtc '2026-08-24T03:00:01Z' `
                    -First 10).Count | Should -Be 1
            @(Get-HHSqliteAuditRecord -Connection $script:connection -MasterKey $script:key `
                    -ToUtc '2026-08-24T03:00:00Z' -First 10).Sequence | Should -Be @(2L, 1L)
            @(Get-HHSqliteAuditRecord -Connection $script:connection -MasterKey $script:key `
                    -BeforeSequence 3 -First 10).Sequence | Should -Be @(2L, 1L)
            @(Get-HHSqliteAuditRecord -Connection $script:connection -MasterKey $script:key `
                    -CaseId case-001 -First 10).Count | Should -Be 0
            Should -Invoke Invoke-HHSqliteNonQuery -Times 0
        }

        It 'defaults to the newest 100 records and exposes complete decrypted fields' {
            $template = $script:rows[0]
            $script:rows = @(for ($index = 105; $index -ge 1; $index--) {
                    $row = $template.PSObject.Copy()
                    $row.sequence = [long]$index
                    $row.invocation_id = [Guid]::NewGuid().ToByteArray()
                    $row
                })
            $records = @(Get-HHSqliteAuditRecord -Connection $script:connection -MasterKey $script:key)
            $records.Count | Should -Be 100
            $records[0].Sequence | Should -Be 105
            $records[-1].Sequence | Should -Be 6
            $records[0].CommandText | Should -BeExactly 'Get-Date'
            $records[0].Reason | Should -BeExactly triage
            $records[0].CaseId | Should -BeExactly CASE-001
            $records[0].PSObject.TypeNames | Should -Contain 'HostHunter.AuditRecord'
        }

        It 'fails when the database identity is absent' {
            Mock Invoke-HHSqliteQuery { return @() }
            {
                Get-HHSqliteAuditRecord -Connection $script:connection -MasterKey $script:key
            } | Should -Throw '*Database identity is unavailable*'
        }

        It 'treats explicitly empty filter sets as matching no rows and handles an empty repository' {
            @(Get-HHSqliteAuditRecord -Connection $script:connection -MasterKey $script:key `
                    -TargetName @() -First 10).Count | Should -Be 0
            @(Get-HHSqliteAuditRecord -Connection $script:connection -MasterKey $script:key `
                    -Operation @() -First 10).Count | Should -Be 0
            @(Get-HHSqliteAuditRecord -Connection $script:connection -MasterKey $script:key `
                    -Status @() -First 10).Count | Should -Be 0

            $script:rows = @()
            @(Get-HHSqliteAuditRecord -Connection $script:connection `
                    -MasterKey $script:key -First 10).Count | Should -Be 0
        }

        It 'rejects missing output rows and missing artifact publication' {
            $context = [pscustomobject]@{
                AuditRoot = '/data/audit'; OutputRoot = '/data/audit/output'; DataRoot = '/data'
            }
            $script:rows = @()
            {
                Get-HHSqliteAuditOutput -Connection $script:connection -PersistenceContext $context `
                    -MasterKey $script:key -InvocationId $script:invocationAText
            } | Should -Throw '*No audit invocation exists*'
            $script:rows = @([pscustomobject]@{
                    invocation_id = $script:invocationA; reserved_artifact_id = $script:artifactId
                    database_id = $script:databaseId; ledger_id = $script:ledgerId
                    relative_path = $null; ciphertext_hash = $null; ciphertext_bytes = $null
                })
            {
                Get-HHSqliteAuditOutput -Connection $script:connection -PersistenceContext $context `
                    -MasterKey $script:key -InvocationId $script:invocationAText
            } | Should -Throw '*Audit output is not available*'
        }

        It 'rejects escaping paths and propagates swapped identity hash and length failures' {
            $context = [pscustomobject]@{
                AuditRoot = '/data/audit'; OutputRoot = '/data/audit/output'; DataRoot = '/data'
            }
            $script:rows = @([pscustomobject]@{
                    invocation_id = $script:invocationA; reserved_artifact_id = $script:artifactId
                    database_id = $script:databaseId; ledger_id = $script:ledgerId
                    relative_path = '../../escape.hha'; ciphertext_hash = [byte[]]::new(32)
                    ciphertext_bytes = 100L
                })
            {
                Get-HHSqliteAuditOutput -Connection $script:connection -PersistenceContext $context `
                    -MasterKey $script:key -InvocationId $script:invocationAText
            } | Should -Throw -ErrorId 'AuditIntegrityFailed*'

            $script:rows[0].relative_path = 'output/a.hha'
            foreach ($failure in @('identity header', 'hash does not match', 'length does not match')) {
                Mock Read-HHAuditArtifactV2 { throw "The audit artifact $failure." }
                {
                    Get-HHSqliteAuditOutput -Connection $script:connection -PersistenceContext $context `
                        -MasterKey $script:key -InvocationId $script:invocationAText
                } | Should -Throw "*$failure*"
            }
        }
    }
}

Describe 'SQLite audit optional-envelope decryption' -Tag Unit {
    InModuleScope HostHunterNextGeneration {
        It 'returns null without attempting authenticated decryption for an absent envelope' {
            Unprotect-HHAuditRepositoryText -Envelope $null -MasterKey ([byte[]](0..31)) `
                -DatabaseId ([Guid]::NewGuid().ToByteArray()) `
                -InvocationId ([Guid]::NewGuid().ToByteArray()) `
                -Column reason_envelope | Should -BeNullOrEmpty
        }
    }
}
