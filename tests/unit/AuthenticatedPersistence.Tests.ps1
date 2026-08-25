$sourceRoot = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
    Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration'
}
else {
    $env:HH_TEST_SOURCE_ROOT
}
Import-Module (Join-Path $sourceRoot 'HostHunterNextGeneration.psd1') -Force

Describe 'authenticated persistence head comparison' -Tag Unit {
    InModuleScope HostHunterNextGeneration {
        BeforeEach {
            $script:baseHead = [pscustomobject]@{
                DatabaseId = [byte[]](0..15)
                LedgerId = [byte[]](16..31)
                SchemaVersion = 1
                AuditSequence = 4L
                AuditMac = [byte[]](32..63)
                TargetGeneration = 3L
                TargetStateMac = [byte[]](64..95)
                SchemaFingerprint = [byte[]](96..127)
            }
        }

        It 'accepts an exactly equal authenticated anchor' {
            $result = Test-HHPersistenceAnchorState `
                -DatabaseHead $script:baseHead `
                -Anchor $script:baseHead
            $result.IsEqual | Should -BeTrue
            $result.RequiresVerifiedAdvance | Should -BeFalse
        }

        It 'requires full verification before advancing an anchor behind the database' {
            $anchor = $script:baseHead.PSObject.Copy()
            $anchor.AuditSequence = 3L
            $anchor.TargetGeneration = 2L
            $result = Test-HHPersistenceAnchorState `
                -DatabaseHead $script:baseHead `
                -Anchor $anchor
            $result.IsEqual | Should -BeFalse
            $result.AuditAdvanceRequired | Should -BeTrue
            $result.TargetAdvanceRequired | Should -BeTrue
        }

        It 'rejects database rollback behind the external anchor' {
            $anchor = $script:baseHead.PSObject.Copy()
            $anchor.AuditSequence = 5L
            {
                Test-HHPersistenceAnchorState `
                    -DatabaseHead $script:baseHead `
                    -Anchor $anchor
            } | Should -Throw -ErrorId 'AuditRollbackDetected*'
        }

        It 'rejects identity and same-position MAC disagreement' {
            foreach ($propertyName in @('DatabaseId', 'LedgerId', 'SchemaFingerprint')) {
                $anchor = $script:baseHead.PSObject.Copy()
                $changed = [byte[]]$anchor.$propertyName.Clone()
                $changed[0] = $changed[0] -bxor 1
                $anchor.$propertyName = $changed
                {
                    Test-HHPersistenceAnchorState `
                        -DatabaseHead $script:baseHead `
                        -Anchor $anchor
                } | Should -Throw -ErrorId 'AuditIntegrityFailed*'
            }

            $anchor = $script:baseHead.PSObject.Copy()
            $anchor.TargetStateMac = [byte[]]::new(32)
            {
                Test-HHPersistenceAnchorState `
                    -DatabaseHead $script:baseHead `
                    -Anchor $anchor
            } | Should -Throw -ErrorId 'AuditIntegrityFailed*'

            $anchor = $script:baseHead.PSObject.Copy()
            $anchor.AuditMac = [byte[]]::new(32)
            {
                Test-HHPersistenceAnchorState `
                    -DatabaseHead $script:baseHead `
                    -Anchor $anchor
            } | Should -Throw -ErrorId 'AuditIntegrityFailed*'
        }

        It 'rejects unsupported or incomplete anchor metadata' {
            $anchor = $script:baseHead.PSObject.Copy()
            $anchor.SchemaVersion = 2
            {
                Test-HHPersistenceAnchorState `
                    -DatabaseHead $script:baseHead `
                    -Anchor $anchor
            } | Should -Throw -ErrorId 'PersistenceSchemaUnsupported*'

            $incomplete = [pscustomobject]@{ DatabaseId = [byte[]](0..15) }
            {
                Test-HHPersistenceAnchorState `
                    -DatabaseHead $script:baseHead `
                    -Anchor $incomplete
            } | Should -Throw -ErrorId 'AuditIntegrityFailed*'
        }

        It 'requires complete and valid configuration heads on both sides' {
            $database = $script:baseHead.PSObject.Copy()
            $anchor = $script:baseHead.PSObject.Copy()
            $database | Add-Member -NotePropertyName ConfigurationGeneration -NotePropertyValue 0L
            $database | Add-Member -NotePropertyName ConfigurationStateMac `
                -NotePropertyValue ([byte[]]::new(32))
            {
                Test-HHPersistenceAnchorState -DatabaseHead $database -Anchor $anchor
            } | Should -Throw -ErrorId 'AuditIntegrityFailed*'

            $anchor | Add-Member -NotePropertyName ConfigurationGeneration -NotePropertyValue 0L
            $anchor | Add-Member -NotePropertyName ConfigurationStateMac `
                -NotePropertyValue ([byte[]]::new(31))
            {
                Test-HHPersistenceAnchorState -DatabaseHead $database -Anchor $anchor
            } | Should -Throw -ErrorId 'AuditIntegrityFailed*'
        }

        It 'rejects invalid schema fingerprints and malformed configuration head rows' {
            {
                Get-HHSqlitePersistenceHead -Connection ([pscustomobject]@{}) `
                    -SchemaFingerprint ([byte[]]::new(31))
            } | Should -Throw '*32 bytes*'

            Mock Invoke-HHSqliteQuery {
                if ($Sql -match 'database_identity') {
                    return [pscustomobject]@{
                        database_id = [byte[]]::new(16)
                        ledger_id = [byte[]]::new(16)
                    }
                }
                if ($Sql -match 'target_store_state') {
                    return [pscustomobject]@{
                        generation = 0L
                        target_state_mac = [byte[]]::new(32)
                    }
                }
                if ($Sql -match 'configuration_store_state') { return @() }
                return @()
            }
            {
                Get-HHSqlitePersistenceHead `
                    -Connection ([pscustomobject]@{ DataSource = 'mock.db' }) `
                    -SchemaFingerprint ([byte[]]::new(32))
            } | Should -Throw -ErrorId 'AuditIntegrityFailed*'
        }

        It 'rejects malformed head lengths before comparison' {
            foreach ($propertyName in @(
                    'DatabaseId', 'LedgerId', 'AuditMac', 'TargetStateMac',
                    'SchemaFingerprint'
                )) {
                $anchor = $script:baseHead.PSObject.Copy()
                $anchor.$propertyName = [byte[]](1, 2, 3)
                {
                    Test-HHPersistenceAnchorState `
                        -DatabaseHead $script:baseHead `
                        -Anchor $anchor
                } | Should -Throw -ErrorId 'AuditIntegrityFailed*'
            }

        }

        It 'rejects negative positions before comparison' {
            foreach ($propertyName in @('AuditSequence', 'TargetGeneration')) {
                $databaseHead = $script:baseHead.PSObject.Copy()
                $anchor = $script:baseHead.PSObject.Copy()
                $databaseHead.$propertyName = -1L
                $anchor.$propertyName = -1L
                {
                    Test-HHPersistenceAnchorState `
                        -DatabaseHead $databaseHead `
                        -Anchor $anchor
                } | Should -Throw -ErrorId 'AuditIntegrityFailed*'
            }
        }

        It 'rejects target rollback independently of the audit position' {
            $anchor = $script:baseHead.PSObject.Copy()
            $anchor.TargetGeneration = 4L
            {
                Test-HHPersistenceAnchorState -DatabaseHead $script:baseHead -Anchor $anchor
            } | Should -Throw -ErrorId 'AuditRollbackDetected*'
        }

        It 'reports independent audit-only and target-only verified advances' {
            $auditAnchor = $script:baseHead.PSObject.Copy()
            $auditAnchor.AuditSequence = 3L
            $audit = Test-HHPersistenceAnchorState -DatabaseHead $script:baseHead -Anchor $auditAnchor
            $audit.AuditAdvanceRequired | Should -BeTrue
            $audit.TargetAdvanceRequired | Should -BeFalse

            $targetAnchor = $script:baseHead.PSObject.Copy()
            $targetAnchor.TargetGeneration = 2L
            $target = Test-HHPersistenceAnchorState -DatabaseHead $script:baseHead -Anchor $targetAnchor
            $target.AuditAdvanceRequired | Should -BeFalse
            $target.TargetAdvanceRequired | Should -BeTrue
        }
    }
}

Describe 'authenticated persistence coordinator' -Tag Unit {
    InModuleScope HostHunterNextGeneration {
        BeforeEach {
            if ([IO.Directory]::Exists('/opt/hosthunter-sqlite/lib')) {
                $env:HH_SQLITE_PROVIDER_ROOT = '/opt/hosthunter-sqlite/lib'
            }
            $script:stateRoot = Join-Path $TestDrive ([Guid]::NewGuid().ToString('N'))
            $script:persistenceContext = Get-HHPersistenceContext -DataRoot $script:stateRoot
        }

        It 'creates, authenticates, seals, closes, and reopens a database' -Skip:$IsMacOS {
            $context = Open-HHAuthenticatedPersistence `
                -PersistenceContext $script:persistenceContext `
                -AllowAnchorAdvance
            try {
                $context.Anchor.AuditSequence | Should -Be 0
                $context.Anchor.TargetGeneration | Should -Be 0
                $context.TargetSnapshot.Targets.Count | Should -Be 0
                $context.WriterLock | Should -Not -BeNullOrEmpty
            }
            finally { Close-HHAuthenticatedPersistence -Context $context }

            $reopened = Open-HHAuthenticatedPersistence `
                -PersistenceContext $script:persistenceContext
            try {
                $reopened.Anchor.AuditSequence | Should -Be 0
                $reopened.WriterLock | Should -BeNullOrEmpty
            }
            finally { Close-HHAuthenticatedPersistence -Context $reopened }
        }

        It 'reports an overall unknown state when anchor sealing fails after commit' -Skip:$IsMacOS {
            $context = Open-HHAuthenticatedPersistence `
                -PersistenceContext $script:persistenceContext `
                -AllowAnchorAdvance
            try {
                $context.AnchorWriter = { throw 'simulated anchor failure' }
                $caught = $null
                try {
                    Invoke-HHAnchoredPersistenceTransaction -Context $context -Action {
                        param($Connection, $Transaction, $WriterContext)
                        $target = New-HHTargetRecord -Name server -Transport SSH `
                            -HostName example.test -Port 22 -UserName operator `
                            -Authentication Password -PowerShellRuntime PowerShell7 `
                            -HostKeyFingerprint 'SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' `
                            -KeyPath $null -IsActive $true `
                            -LastValidatedAtUtc '2026-08-24T00:00:00Z' `
                            -LastValidatedPSEdition Core `
                            -LastValidatedPowerShellVersion 7.6.5 `
                            -LastValidatedExecutionMode Direct
                        $request = [pscustomobject]@{
                            Target = $target
                            CommandText = 'Get-Process'
                            Reason = $null
                            CaseId = $null
                            RemoteOperations = @([pscustomobject][ordered]@{
                                    Phase = 'Command'
                                    PowerShellRuntime = 'PowerShell7'
                                    ScriptText = 'Get-Process'
                                    SerializedArguments = '<Objs />'
                                    Conditional = $false
                                })
                        }
                        @(Register-HHSqliteAuditBatch -Connection $Connection `
                                -Transaction $Transaction -MasterKey $WriterContext.MasterKey `
                                -Operation InvokeCommand -Request @($request) `
                                -IntentAtUtc ([DateTimeOffset]'2026-08-24T02:00:00Z'))[0]
                    } | Out-Null
                }
                catch { $caught = $_ }
                $caught.Exception.Message |
                    Should -BeLike '*external persistence seal could not be proven*'
                $caught.Exception.Data['HHPersistenceCommitState'] | Should -BeExactly Unknown
            }
            finally { Close-HHAuthenticatedPersistence -Context $context }

            {
                $blocked = Open-HHAuthenticatedPersistence `
                    -PersistenceContext $script:persistenceContext
                Close-HHAuthenticatedPersistence -Context $blocked
            } | Should -Throw -ErrorId 'AuditRecoveryRequired*'

            $recovered = Open-HHAuthenticatedPersistence `
                -PersistenceContext $script:persistenceContext `
                -AllowAnchorAdvance
            try {
                $recovered.Anchor.AuditSequence | Should -Be 3
                $recovered.RecoveryReceipts.Count | Should -Be 1
                $recovered.RecoveryReceipts[0].RecoveryState |
                    Should -BeExactly RecoveredNotDispatched
                $record = @(Get-HHSqliteAuditRecord -Connection $recovered.Connection `
                        -MasterKey $recovered.MasterKey -Status Failed -First 1)[0]
                $record.Status | Should -BeExactly Failed
            }
            finally { Close-HHAuthenticatedPersistence -Context $recovered }
        }

        It 'commits a prepared receipt and seals the authenticated head' -Skip:$IsMacOS {
            $context = Open-HHAuthenticatedPersistence `
                -PersistenceContext $script:persistenceContext `
                -AllowAnchorAdvance
            try {
                $receipt = Invoke-HHAnchoredPersistenceTransaction -Context $context -Action {
                    param($Connection, $Transaction)
                    $null = $Connection, $Transaction
                    [pscustomobject]@{ Marker = 'committed' }
                }
                $receipt.Marker | Should -BeExactly committed
                $receipt.Prepared | Should -BeTrue
                $receipt.Committed | Should -BeTrue
                $context.Anchor.AuditSequence | Should -Be 0
                $context.Anchor.TargetGeneration | Should -Be 0
            }
            finally { Close-HHAuthenticatedPersistence -Context $context }
        }

        It 'rolls back action changes and does not advance the anchor when preparation fails' -Skip:$IsMacOS {
            $context = Open-HHAuthenticatedPersistence `
                -PersistenceContext $script:persistenceContext `
                -AllowAnchorAdvance
            try {
                $artifactBefore = [Convert]::ToHexString([byte[]]$context.Anchor.Artifact)
                {
                    Invoke-HHAnchoredPersistenceTransaction -Context $context -Action {
                        param($Connection, $Transaction)
                        $null = Invoke-HHSqliteNonQuery `
                            -Connection $Connection `
                            -Transaction $Transaction `
                            -Sql 'CREATE TABLE rollback_probe (id INTEGER PRIMARY KEY);'
                        throw 'simulated preparation failure'
                    }
                } | Should -Throw '*simulated preparation failure*'

                (Invoke-HHSqliteScalar -Connection $context.Connection -Sql @'
SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name='rollback_probe';
'@) | Should -Be 0
                [Convert]::ToHexString([byte[]]$context.Anchor.Artifact) |
                    Should -BeExactly $artifactBefore
            }
            finally { Close-HHAuthenticatedPersistence -Context $context }
        }

        It 'does not generate a replacement key for an existing database' -Skip:$IsMacOS {
            $context = Open-HHAuthenticatedPersistence `
                -PersistenceContext $script:persistenceContext `
                -AllowAnchorAdvance
            Close-HHAuthenticatedPersistence -Context $context
            [IO.File]::Delete((Join-Path $script:stateRoot 'audit/audit.key'))

            {
                Open-HHAuthenticatedPersistence `
                    -PersistenceContext $script:persistenceContext `
                    -AllowAnchorAdvance
            } | Should -Throw -ErrorId 'AuditKeyUnavailable*'
            Test-Path -LiteralPath (Join-Path $script:stateRoot 'audit/audit.key') |
                Should -BeFalse
        }

        It 'blocks an existing database whose external anchor is missing' -Skip:$IsMacOS {
            $context = Open-HHAuthenticatedPersistence `
                -PersistenceContext $script:persistenceContext `
                -AllowAnchorAdvance
            Close-HHAuthenticatedPersistence -Context $context
            [IO.File]::Delete($script:persistenceContext.AnchorPath)

            {
                Open-HHAuthenticatedPersistence `
                    -PersistenceContext $script:persistenceContext
            } | Should -Throw -ErrorId 'AuditKeyUnavailable*'
        }

        It 'acquires and releases an operation lock and accepts a null prepared receipt' -Skip:$IsMacOS {
            $context = Open-HHAuthenticatedPersistence `
                -PersistenceContext $script:persistenceContext `
                -OperationLock `
                -AllowAnchorAdvance
            try {
                $context.OperationLock | Should -Not -BeNullOrEmpty
                $result = Invoke-HHAnchoredPersistenceTransaction -Context $context -Action {
                    param($Connection, $Transaction)
                    $null = $Connection, $Transaction
                }
                $result | Should -BeNullOrEmpty
            }
            finally { Close-HHAuthenticatedPersistence -Context $context }
            $context.Connection | Should -BeNullOrEmpty
            $context.MasterKey | Should -BeNullOrEmpty
            $context.OperationLock | Should -BeNullOrEmpty
            Close-HHAuthenticatedPersistence -Context $null
        }

        It 'rejects an unauthenticated writer context before beginning a transaction' {
            {
                Invoke-HHAnchoredPersistenceTransaction `
                    -Context ([pscustomobject]@{ WriterLock = $null; Connection = $null }) `
                    -Action { }
            } | Should -Throw '*authenticated writer context*'
        }

        It 'uses injected master-key and anchor providers without file-key fallback' -Skip:$IsMacOS {
            $key = [byte[]](0..31)
            $artifactState = [pscustomobject]@{ Artifact = $null; KeyCalls = 0 }
            $masterKeyProvider = {
                param($PersistenceContext, $DatabaseExisted)
                $null = $PersistenceContext, $DatabaseExisted
                $artifactState.KeyCalls++
                [byte[]]$key.Clone()
            }.GetNewClosure()
            $anchorWriter = {
                param($PersistenceContext, $ExpectedArtifact, $NewArtifact, $MasterKey)
                $null = $PersistenceContext, $ExpectedArtifact, $MasterKey
                $artifactState.Artifact = [byte[]]$NewArtifact.Clone()
            }.GetNewClosure()
            $anchorReader = {
                param($PersistenceContext, $MasterKey)
                $null = $PersistenceContext, $MasterKey
                $databaseId = [byte[]]::new(16)
                $ledgerId = [byte[]]::new(16)
                $auditMac = [byte[]]::new(32)
                $targetStateMac = [byte[]]::new(32)
                $schemaFingerprint = [byte[]]::new(32)
                $configurationStateMac = [byte[]]::new(32)
                [Array]::Copy($artifactState.Artifact, 16, $databaseId, 0, 16)
                [Array]::Copy($artifactState.Artifact, 32, $ledgerId, 0, 16)
                [Array]::Copy($artifactState.Artifact, 60, $auditMac, 0, 32)
                [Array]::Copy($artifactState.Artifact, 100, $targetStateMac, 0, 32)
                [Array]::Copy($artifactState.Artifact, 132, $schemaFingerprint, 0, 32)
                [Array]::Copy($artifactState.Artifact, 172, $configurationStateMac, 0, 32)
                [pscustomobject]@{
                    DatabaseId = $databaseId
                    LedgerId = $ledgerId
                    SchemaVersion = 1
                    AuditSequence = 0L
                    AuditMac = $auditMac
                    TargetGeneration = 0L
                    TargetStateMac = $targetStateMac
                    SchemaFingerprint = $schemaFingerprint
                    ConfigurationGeneration = 0L
                    ConfigurationStateMac = $configurationStateMac
                    Artifact = [byte[]]$artifactState.Artifact.Clone()
                }
            }.GetNewClosure()

            $context = Open-HHAuthenticatedPersistence `
                -PersistenceContext $script:persistenceContext `
                -MasterKeyProvider $masterKeyProvider `
                -AnchorWriter $anchorWriter `
                -AnchorReader $anchorReader
            try {
                $artifactState.KeyCalls | Should -Be 1
                $artifactState.Artifact.Length | Should -Be 236
                Test-Path -LiteralPath (Join-Path $script:stateRoot 'audit/audit.key') |
                    Should -BeFalse
            }
            finally { Close-HHAuthenticatedPersistence -Context $context }
        }

        It 'closes an already-empty context idempotently' {
            $empty = [pscustomobject]@{
                Connection = $null
                MasterKey = $null
                WriterLock = $null
                OperationLock = $null
            }
            Close-HHAuthenticatedPersistence -Context $empty
            Close-HHAuthenticatedPersistence -Context $empty
            $empty.Connection | Should -BeNullOrEmpty
            $empty.MasterKey | Should -BeNullOrEmpty
        }
    }
}
