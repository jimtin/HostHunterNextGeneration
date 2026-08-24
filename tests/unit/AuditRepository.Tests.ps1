$sourceRoot = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
    Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration'
}
else { $env:HH_TEST_SOURCE_ROOT }
Import-Module (Join-Path $sourceRoot 'HostHunterNextGeneration.psd1') -Force
if ([IO.Directory]::Exists('/opt/hosthunter-sqlite/lib')) {
    $env:HH_SQLITE_PROVIDER_ROOT = '/opt/hosthunter-sqlite/lib'
}

Describe 'SQLite audit repository' -Tag Unit {
    InModuleScope HostHunterNextGeneration {
        BeforeEach {
            $script:key = [byte[]](0..31)
            $stateRoot = Join-Path $TestDrive ([Guid]::NewGuid().ToString('N'))
            $script:context = Get-HHPersistenceContext -DataRoot $stateRoot
            $null = Initialize-HHSqliteDatabase -PersistenceContext $script:context `
                -MasterKey $script:key -AnchorWriter { }
            $script:connection = New-HHSqliteConnection -DatabasePath $script:context.DatabasePath
            $script:target = New-HHTargetRecord -Name server -Transport SSH `
                -HostName example.test -Port 22 -UserName operator -Authentication Password `
                -PowerShellRuntime PowerShell7 `
                -HostKeyFingerprint 'SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' `
                -KeyPath $null -IsActive $true -LastValidatedAtUtc '2026-08-24T00:00:00Z' `
                -LastValidatedPSEdition Core -LastValidatedPowerShellVersion 7.6.5 `
                -LastValidatedExecutionMode Direct
            $script:request = [pscustomobject]@{
                Target = $script:target
                CommandText = 'Get-Process -Name pwsh'
                Reason = 'triage'
                CaseId = 'CASE-001'
                RemoteOperations = @([pscustomobject][ordered]@{
                        Phase = 'Command'
                        PowerShellRuntime = 'PowerShell7'
                        ScriptText = 'param($CommandText) & ([scriptblock]::Create($CommandText))'
                        SerializedArguments = '<Objs><S>Get-Process -Name pwsh</S></Objs>'
                        Conditional = $false
                    })
            }
        }

        AfterEach {
            if ($null -ne $script:connection) { $script:connection.Dispose() }
        }

        It 'stores exact encrypted intent text, manifest, case lookup, and an authenticated event' {
            $transaction = $script:connection.BeginTransaction()
            try {
                $intent = @(Register-HHSqliteAuditBatch -Connection $script:connection `
                        -Transaction $transaction -MasterKey $script:key `
                        -Operation InvokeCommand -Request @($script:request) `
                        -IntentAtUtc ([DateTimeOffset]'2026-08-24T01:02:03Z'))[0]
                $transaction.Commit()
            }
            finally { $transaction.Dispose() }

            $intent.InvocationId | Should -Match '^[0-9a-f]{32}$'
            $intent.ArtifactId | Should -Match '^[0-9a-f]{32}$'
            $row = @(Invoke-HHSqliteQuery -Connection $script:connection -Sql @'
SELECT i.*, d.database_id FROM invocations i CROSS JOIN database_identity d;
'@)[0]
            [Text.Encoding]::UTF8.GetString((Unprotect-HHPersistenceValue `
                        -Envelope ([byte[]]$row.command_envelope) -MasterKey $script:key `
                        -AssociatedData (Get-HHAuditRepositoryAssociatedData `
                            -DatabaseId ([byte[]]$row.database_id) `
                            -RowId ([byte[]]$row.invocation_id) -Table invocations `
                            -Column command_envelope))) | Should -BeExactly 'Get-Process -Name pwsh'
            ([byte[]]$row.case_lookup).Length | Should -Be 32
            (Invoke-HHSqliteScalar -Connection $script:connection `
                    -Sql 'SELECT COUNT(*) FROM remote_operations;') | Should -Be 1
            $chain = Test-HHSqliteAuditChain -Connection $script:connection -MasterKey $script:key
            $chain.Sequence | Should -Be 1
            $chain.EventCount | Should -Be 1
        }

        It 'allocates one batch and contiguous audit sequence for multiple targets' {
            $secondTarget = New-HHTargetRecord -Name server2 -Transport SSH `
                -HostName second.example.test -Port 22 -UserName operator -Authentication Password `
                -PowerShellRuntime PowerShell7 `
                -HostKeyFingerprint 'SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB' `
                -KeyPath $null -IsActive $true -LastValidatedAtUtc '2026-08-24T00:00:00Z' `
                -LastValidatedPSEdition Core -LastValidatedPowerShellVersion 7.6.5 `
                -LastValidatedExecutionMode Direct
            $second = $script:request.PSObject.Copy()
            $second.Target = $secondTarget
            $transaction = $script:connection.BeginTransaction()
            try {
                $intents = @(Register-HHSqliteAuditBatch -Connection $script:connection `
                        -Transaction $transaction -MasterKey $script:key `
                        -Operation InvokeCommand -Request @($script:request, $second) `
                        -IntentAtUtc ([DateTimeOffset]'2026-08-24T01:02:03Z'))
                $transaction.Commit()
            }
            finally { $transaction.Dispose() }
            $intents.Count | Should -Be 2
            @($intents.Sequence) | Should -Be @(1L, 2L)
            $intents[0].BatchId | Should -BeExactly $intents[1].BatchId
            (Test-HHSqliteAuditChain -Connection $script:connection -MasterKey $script:key).Sequence |
                Should -Be 2
        }

        It 'fails chain verification after a row-level MAC mutation' {
            $transaction = $script:connection.BeginTransaction()
            try {
                $null = Register-HHSqliteAuditBatch -Connection $script:connection `
                    -Transaction $transaction -MasterKey $script:key `
                    -Operation InvokeCommand -Request @($script:request) `
                    -IntentAtUtc ([DateTimeOffset]'2026-08-24T01:02:03Z')
                $transaction.Commit()
            }
            finally { $transaction.Dispose() }
            $null = Invoke-HHSqliteNonQuery -Connection $script:connection `
                -Sql 'DROP TRIGGER audit_events_no_update;'
            $null = Invoke-HHSqliteNonQuery -Connection $script:connection `
                -Sql 'UPDATE audit_events SET event_mac=zeroblob(32) WHERE sequence=1;'
            {
                Test-HHSqliteAuditChain -Connection $script:connection -MasterKey $script:key
            } | Should -Throw -ErrorId 'AuditIntegrityFailed*'
        }

        It 'fails chain verification after an event is deleted from the front' {
            $transaction = $script:connection.BeginTransaction()
            try {
                $intent = @(Register-HHSqliteAuditBatch -Connection $script:connection `
                        -Transaction $transaction -MasterKey $script:key `
                        -Operation InvokeCommand -Request @($script:request) `
                        -IntentAtUtc ([DateTimeOffset]'2026-08-24T01:02:03Z'))[0]
                $null = Write-HHSqliteRemoteOperationEvent -Connection $script:connection `
                    -Transaction $transaction -MasterKey $script:key -Intent $intent `
                    -Ordinal 0 -EventKind DispatchArmed `
                    -EventAtUtc ([DateTimeOffset]'2026-08-24T01:02:04Z') `
                    -ExpectedOperation $intent.RemoteOperations[0]
                $transaction.Commit()
            }
            finally { $transaction.Dispose() }
            $null = Invoke-HHSqliteNonQuery -Connection $script:connection `
                -Sql 'DROP TRIGGER audit_events_no_delete;'
            $null = Invoke-HHSqliteNonQuery -Connection $script:connection `
                -Sql 'DELETE FROM audit_events WHERE sequence=1;'
            {
                Test-HHSqliteAuditChain -Connection $script:connection -MasterKey $script:key
            } | Should -Throw -ErrorId 'AuditIntegrityFailed*'
        }

        It 'fails chain verification after event sequence reordering' {
            $transaction = $script:connection.BeginTransaction()
            try {
                $intent = @(Register-HHSqliteAuditBatch -Connection $script:connection `
                        -Transaction $transaction -MasterKey $script:key `
                        -Operation InvokeCommand -Request @($script:request) `
                        -IntentAtUtc ([DateTimeOffset]'2026-08-24T01:02:03Z'))[0]
                $null = Write-HHSqliteRemoteOperationEvent -Connection $script:connection `
                    -Transaction $transaction -MasterKey $script:key -Intent $intent `
                    -Ordinal 0 -EventKind DispatchArmed `
                    -EventAtUtc ([DateTimeOffset]'2026-08-24T01:02:04Z') `
                    -ExpectedOperation $intent.RemoteOperations[0]
                $transaction.Commit()
            }
            finally { $transaction.Dispose() }
            $null = Invoke-HHSqliteNonQuery -Connection $script:connection `
                -Sql 'DROP TRIGGER audit_events_no_update;'
            $null = Invoke-HHSqliteNonQuery -Connection $script:connection `
                -Sql 'UPDATE audit_events SET sequence=99 WHERE sequence=1;'
            $null = Invoke-HHSqliteNonQuery -Connection $script:connection `
                -Sql 'UPDATE audit_events SET sequence=1 WHERE sequence=2;'
            $null = Invoke-HHSqliteNonQuery -Connection $script:connection `
                -Sql 'UPDATE audit_events SET sequence=2 WHERE sequence=99;'
            {
                Test-HHSqliteAuditChain -Connection $script:connection -MasterKey $script:key
            } | Should -Throw -ErrorId 'AuditIntegrityFailed*'
        }

        It 'rejects invalid intent identity and arm declaration edge cases' {
            $transaction = $script:connection.BeginTransaction()
            try {
                {
                    Register-HHSqliteAuditBatch -Connection $script:connection `
                        -Transaction $transaction -MasterKey $script:key `
                        -Operation InvokeCommand -Request @($script:request) `
                        -IntentAtUtc ([DateTimeOffset]'2026-08-24T01:02:03Z') `
                        -BatchId ([byte[]]::new(15))
                } | Should -Throw '*BatchId must contain exactly 16 bytes*'
            }
            finally {
                $transaction.Rollback()
                $transaction.Dispose()
            }

            $transaction = $script:connection.BeginTransaction()
            try {
                $intent = @(Register-HHSqliteAuditBatch -Connection $script:connection `
                        -Transaction $transaction -MasterKey $script:key `
                        -Operation InvokeCommand -Request @($script:request) `
                        -IntentAtUtc ([DateTimeOffset]'2026-08-24T01:02:03Z'))[0]
                {
                    Write-HHSqliteRemoteOperationEvent -Connection $script:connection `
                        -Transaction $transaction -MasterKey $script:key -Intent $intent `
                        -Ordinal 1 -EventKind Completed `
                        -EventAtUtc ([DateTimeOffset]'2026-08-24T01:02:04Z')
                } | Should -Throw '*ordinal 1 is not declared*'
                {
                    Write-HHSqliteRemoteOperationEvent -Connection $script:connection `
                        -Transaction $transaction -MasterKey $script:key -Intent $intent `
                        -Ordinal 0 -EventKind DispatchArmed `
                        -EventAtUtc ([DateTimeOffset]'2026-08-24T01:02:04Z')
                } | Should -Throw '*requires the exact expected operation*'
                $wrongOperation = $intent.RemoteOperations[0].PSObject.Copy()
                $wrongOperation.ScriptText = 'Get-Date'
                {
                    Write-HHSqliteRemoteOperationEvent -Connection $script:connection `
                        -Transaction $transaction -MasterKey $script:key -Intent $intent `
                        -Ordinal 0 -EventKind DispatchArmed `
                        -EventAtUtc ([DateTimeOffset]'2026-08-24T01:02:04Z') `
                        -ExpectedOperation $wrongOperation
                } | Should -Throw -ErrorId 'AuditIntegrityFailed*'
                $transaction.Rollback()
            }
            finally { $transaction.Dispose() }
        }

        It 'rejects duplicate arm and terminal records atomically' {
            $transaction = $script:connection.BeginTransaction()
            try {
                $intent = @(Register-HHSqliteAuditBatch -Connection $script:connection `
                        -Transaction $transaction -MasterKey $script:key `
                        -Operation InvokeCommand -Request @($script:request) `
                        -IntentAtUtc ([DateTimeOffset]'2026-08-24T01:02:03Z'))[0]
                $null = Write-HHSqliteRemoteOperationEvent -Connection $script:connection `
                    -Transaction $transaction -MasterKey $script:key -Intent $intent `
                    -Ordinal 0 -EventKind DispatchArmed `
                    -EventAtUtc ([DateTimeOffset]'2026-08-24T01:02:04Z') `
                    -ExpectedOperation $intent.RemoteOperations[0]
                {
                    Write-HHSqliteRemoteOperationEvent -Connection $script:connection `
                        -Transaction $transaction -MasterKey $script:key -Intent $intent `
                        -Ordinal 0 -EventKind DispatchArmed `
                        -EventAtUtc ([DateTimeOffset]'2026-08-24T01:02:05Z') `
                        -ExpectedOperation $intent.RemoteOperations[0]
                } | Should -Throw
                $null = Complete-HHSqliteAuditIntent -Connection $script:connection `
                    -Transaction $transaction -MasterKey $script:key -Intent $intent `
                    -Status Failed -FailureKind TransportFailure -DispatchState Dispatched `
                    -OutcomeStatus Failed -CompletedAtUtc ([DateTimeOffset]'2026-08-24T01:02:06Z') `
                    -Payload @{ message = 'failed' }
                {
                    Complete-HHSqliteAuditIntent -Connection $script:connection `
                        -Transaction $transaction -MasterKey $script:key -Intent $intent `
                        -Status Failed -FailureKind TransportFailure -DispatchState Dispatched `
                        -OutcomeStatus Failed -CompletedAtUtc ([DateTimeOffset]'2026-08-24T01:02:07Z') `
                        -Payload @{ message = 'duplicate' }
                } | Should -Throw
                $transaction.Rollback()
            }
            finally { $transaction.Dispose() }
        }

        It 'queries complete command text newest-first without writing an audit event' {
            $transaction = $script:connection.BeginTransaction()
            try {
                $intent = @(Register-HHSqliteAuditBatch -Connection $script:connection `
                        -Transaction $transaction -MasterKey $script:key `
                        -Operation InvokeCommand -Request @($script:request) `
                        -IntentAtUtc ([DateTimeOffset]'2026-08-24T01:02:03Z'))[0]
                $transaction.Commit()
            }
            finally { $transaction.Dispose() }
            $before = Invoke-HHSqliteScalar -Connection $script:connection `
                -Sql 'SELECT COUNT(*) FROM audit_events;'
            $allRecords = @(Get-HHSqliteAuditRecord -Connection $script:connection `
                    -MasterKey $script:key -First 10)
            $allRecords.Count | Should -Be 1
            $records = @(Get-HHSqliteAuditRecord -Connection $script:connection `
                    -MasterKey $script:key -InvocationId $intent.InvocationId `
                    -CaseId CASE-001 -Status Pending -First 10)
            $records.Count | Should -Be 1
            $records[0].CommandText | Should -BeExactly 'Get-Process -Name pwsh'
            $records[0].Reason | Should -BeExactly triage
            $records[0].CaseId | Should -BeExactly CASE-001
            $records[0].Status | Should -BeExactly Pending
            (Invoke-HHSqliteScalar -Connection $script:connection `
                    -Sql 'SELECT COUNT(*) FROM audit_events;') | Should -Be $before
            @(Get-HHSqliteAuditRecord -Connection $script:connection `
                    -MasterKey $script:key -CaseId wrong -First 10).Count | Should -Be 0
        }

        It 'arms the exact declaration, publishes v2 output, and commits a terminal record' {
            $transaction = $script:connection.BeginTransaction()
            try {
                $intent = @(Register-HHSqliteAuditBatch -Connection $script:connection `
                        -Transaction $transaction -MasterKey $script:key `
                        -Operation InvokeCommand -Request @($script:request) `
                        -IntentAtUtc ([DateTimeOffset]'2026-08-24T01:02:03Z'))[0]
                $null = Write-HHSqliteRemoteOperationEvent -Connection $script:connection `
                    -Transaction $transaction -MasterKey $script:key -Intent $intent `
                    -Ordinal 0 -EventKind DispatchArmed `
                    -EventAtUtc ([DateTimeOffset]'2026-08-24T01:02:04Z') `
                    -ExpectedOperation $intent.RemoteOperations[0]
                $transaction.Commit()
            }
            finally { $transaction.Dispose() }

            $identity = @(Invoke-HHSqliteQuery -Connection $script:connection `
                    -Sql 'SELECT database_id,ledger_id FROM database_identity;')[0]
            $streamEvent = [pscustomobject]@{
                RemoteSequence = 0L
                ObservedAtUtc = '2026-08-24T01:02:05Z'
                Phase = 'Command'
                Stream = 'Output'
                TypeName = 'System.String'
                SerializedByteCount = 6L
                IsTerminating = $false
                Value = 'pwsh'
            }
            $artifact = Save-HHSqliteTransportArtifact `
                -PersistenceContext $script:context -Intent $intent `
                -DatabaseId ([byte[]]$identity.database_id) -LedgerId ([byte[]]$identity.ledger_id) `
                -MasterKey $script:key -StreamEvent @($streamEvent)
            $transaction = $script:connection.BeginTransaction()
            try {
                $null = Write-HHSqliteRemoteOperationEvent -Connection $script:connection `
                    -Transaction $transaction -MasterKey $script:key -Intent $intent `
                    -Ordinal 0 -EventKind Completed `
                    -EventAtUtc ([DateTimeOffset]'2026-08-24T01:02:06Z') `
                    -Evidence @{ succeeded = $true }
                $null = Complete-HHSqliteAuditIntent -Connection $script:connection `
                    -Transaction $transaction -MasterKey $script:key -Intent $intent `
                    -Status Succeeded -DispatchState Completed -OutcomeStatus Succeeded `
                    -CompletedAtUtc ([DateTimeOffset]'2026-08-24T01:02:07Z') `
                    -Payload @{ succeeded = $true } -ArtifactReceipt $artifact
                $transaction.Commit()
            }
            finally { $transaction.Dispose() }

            $record = @(Get-HHSqliteAuditRecord -Connection $script:connection `
                    -MasterKey $script:key -InvocationId $intent.InvocationId -First 1)[0]
            $record.Status | Should -BeExactly Succeeded
            $record.StreamEventCount | Should -Be 1
            $events = @(Get-HHSqliteAuditOutput -Connection $script:connection `
                    -PersistenceContext $script:context -MasterKey $script:key `
                    -InvocationId $intent.InvocationId)
            $events.Count | Should -Be 1
            $events[0].Value | Should -BeExactly pwsh
            (Test-HHSqliteAuditChain -Connection $script:connection -MasterKey $script:key).Sequence |
                Should -Be 4
        }

        It 'rejects invalid identifiers, relationship ambiguity, and a timed-out scan' {
            { ConvertTo-HHPersistenceIdentifierByte -Identifier nope } | Should -Throw
            { ConvertTo-HHPersistenceIdentifierText -Identifier ([byte[]]::new(15)) } | Should -Throw
            $transaction = $script:connection.BeginTransaction()
            try {
                {
                    Write-HHSqliteAuditEvent -Connection $script:connection `
                        -Transaction $transaction -EventKind Intent `
                        -EventAtUtc ([DateTimeOffset]::UtcNow) -ProjectionHash ([byte[]]::new(32)) `
                        -RelatedEnvelopeHash ([byte[]]::new(32)) -MasterKey $script:key
                } | Should -Throw '*Exactly one*'
                $null = Register-HHSqliteAuditBatch -Connection $script:connection `
                    -Transaction $transaction -MasterKey $script:key `
                    -Operation InvokeCommand -Request @($script:request) `
                    -IntentAtUtc ([DateTimeOffset]'2026-08-24T01:02:03Z')
                $transaction.Commit()
            }
            finally { $transaction.Dispose() }

            $clockState = [pscustomobject]@{ Ticks = 0 }
            $clock = {
                $clockState.Ticks++
                [DateTimeOffset]::UtcNow.AddSeconds($clockState.Ticks)
            }.GetNewClosure()
            {
                Test-HHSqliteAuditChain -Connection $script:connection -MasterKey $script:key `
                    -TimeoutSeconds 1 -Clock $clock
            } | Should -Throw -ErrorId 'AuditIntegrityVerificationTimedOut*'
        }

        It 'clones binary identifiers and rejects malformed associated-data identities' {
            $identifier = [Guid]::NewGuid().ToByteArray()
            $converted = ConvertTo-HHPersistenceIdentifierByte -Identifier $identifier
            $converted | Should -Be $identifier
            [object]::ReferenceEquals($converted, $identifier) | Should -BeFalse
            {
                Get-HHAuditRepositoryAssociatedData -DatabaseId ([byte[]]::new(15)) `
                    -RowId ([Guid]::NewGuid().ToByteArray()) -Table invocations `
                    -Column command_envelope
            } | Should -Throw '*associated-data identity is invalid*'
        }

        It 'binds nullable event relationships into distinct authenticated MACs' {
            $common = @{
                Sequence = 1L
                EventId = [Guid]::NewGuid().ToByteArray()
                EventKind = 'Intent'
                EventAtUtc = '2026-08-24T01:02:03.0000000Z'
                ProjectionHash = [byte[]]::new(32)
                RelatedEnvelopeHash = [byte[]]::new(32)
                PreviousMac = [byte[]]::new(32)
                MasterKey = $script:key
            }
            $invocationMac = Get-HHSqliteAuditEventMac @common `
                -InvocationId ([Guid]::NewGuid().ToByteArray()) -TargetMutationId $null
            $mutationMac = Get-HHSqliteAuditEventMac @common `
                -InvocationId $null -TargetMutationId ([Guid]::NewGuid().ToByteArray())

            $invocationMac.Length | Should -Be 32
            $mutationMac.Length | Should -Be 32
            (Test-HHPersistenceBytesEqual -Left $invocationMac -Right $mutationMac) |
                Should -BeFalse
        }

        It 'fails intent and terminal writes when the database identity is unavailable' {
            Mock Invoke-HHSqliteQuery { @() }
            $transaction = $script:connection.BeginTransaction()
            try {
                {
                    Register-HHSqliteAuditBatch -Connection $script:connection `
                        -Transaction $transaction -MasterKey $script:key `
                        -Operation InvokeCommand -Request @($script:request) `
                        -IntentAtUtc ([DateTimeOffset]'2026-08-24T01:02:03Z')
                } | Should -Throw '*Database identity is unavailable*'
                {
                    Complete-HHSqliteAuditIntent -Connection $script:connection `
                        -Transaction $transaction -MasterKey $script:key `
                        -Intent ([pscustomobject]@{
                            InvocationId = '1' * 32; ArtifactId = '2' * 32
                        }) -Status Failed -FailureKind TransportFailure `
                        -DispatchState NotDispatched -OutcomeStatus Failed `
                        -CompletedAtUtc ([DateTimeOffset]'2026-08-24T01:02:03Z') `
                        -Payload @{ failed = $true }
                } | Should -Throw '*Database identity is unavailable*'
            }
            finally {
                $transaction.Rollback()
                $transaction.Dispose()
            }
        }

        It 'rejects an allocated audit sequence that drifts from the intent projection' {
            Mock Write-HHSqliteAuditEvent {
                [pscustomobject]@{ Sequence = 99L; EventId = [Guid]::NewGuid().ToByteArray() }
            }
            $transaction = $script:connection.BeginTransaction()
            try {
                {
                    Register-HHSqliteAuditBatch -Connection $script:connection `
                        -Transaction $transaction -MasterKey $script:key `
                        -Operation InvokeCommand -Request @($script:request) `
                        -IntentAtUtc ([DateTimeOffset]'2026-08-24T01:02:03Z')
                } | Should -Throw '*Audit sequence allocation drifted*'
            }
            finally {
                $transaction.Rollback()
                $transaction.Dispose()
            }
        }

        It 'handles empty artifact streams null observations and aborts a failed writer' {
            $writer = [pscustomobject]@{ State = 'Open' }
            Mock Open-HHAuditArtifactV2Writer { $writer }
            Mock Complete-HHAuditArtifactV2Writer {
                [pscustomobject]@{ StreamEventCount = 0L }
            }
            Mock Write-HHAuditArtifactV2Event
            Mock Abort-HHAuditArtifactV2Writer
            $intent = [pscustomobject]@{ InvocationId = '1' * 32; ArtifactId = '2' * 32 }

            $empty = Save-HHSqliteTransportArtifact -PersistenceContext $script:context `
                -Intent $intent -DatabaseId ([Guid]::NewGuid().ToByteArray()) `
                -LedgerId ([Guid]::NewGuid().ToByteArray()) -MasterKey $script:key `
                -StreamEvent @()
            $empty.StreamEventCount | Should -Be 0
            Should -Invoke Write-HHAuditArtifactV2Event -Times 0

            $streamRecord = [pscustomobject]@{
                RemoteSequence = $null; ObservedAtUtc = $null; Phase = 'Command'
                Stream = 'Output'; TypeName = 'System.String'; SerializedByteCount = 1L
                IsTerminating = $false; Value = 'x'
            }
            $null = Save-HHSqliteTransportArtifact -PersistenceContext $script:context `
                -Intent $intent -DatabaseId ([Guid]::NewGuid().ToByteArray()) `
                -LedgerId ([Guid]::NewGuid().ToByteArray()) -MasterKey $script:key `
                -StreamEvent @($streamRecord)
            Should -Invoke Write-HHAuditArtifactV2Event -Times 1 -ParameterFilter {
                $null -eq $EventRecord.RemoteSequence -and
                -not [string]::IsNullOrWhiteSpace($EventRecord.ObservedAtUtc)
            }

            Mock Write-HHAuditArtifactV2Event { throw 'writer fault' }
            {
                Save-HHSqliteTransportArtifact -PersistenceContext $script:context `
                    -Intent $intent -DatabaseId ([Guid]::NewGuid().ToByteArray()) `
                    -LedgerId ([Guid]::NewGuid().ToByteArray()) -MasterKey $script:key `
                    -StreamEvent @($streamRecord)
            } | Should -Throw '*writer fault*'
            Should -Invoke Abort-HHAuditArtifactV2Writer -Times 1
        }
    }
}
