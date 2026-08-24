$sourceRoot = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
    Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration'
}
else {
    $env:HH_TEST_SOURCE_ROOT
}
Import-Module (Join-Path $sourceRoot 'HostHunterNextGeneration.psd1') -Force

Describe 'authenticated audit crash recovery' -Tag Unit {
    InModuleScope HostHunterNextGeneration {
        BeforeEach {
            $root = Join-Path $TestDrive ([Guid]::NewGuid().ToString('N'))
            $script:persistence = Get-HHPersistenceContext -DataRoot $root
            [IO.Directory]::CreateDirectory($script:persistence.OutputRoot) | Out-Null
            [IO.Directory]::CreateDirectory($script:persistence.RecoveryRoot) | Out-Null
            $script:context = [pscustomobject]@{
                Connection = [pscustomobject]@{ DataSource = 'mock' }
                PersistenceContext = $script:persistence
                MasterKey = [byte[]](0..31)
                WriterLock = [pscustomobject]@{}
                Anchor = [pscustomobject]@{
                    DatabaseId = [byte[]](32..47)
                    LedgerId = [byte[]](48..63)
                }
            }
            $script:invocationBytes = [byte[]](0..15)
            $script:artifactBytes = [byte[]](16..31)
            $script:pendingRow = [pscustomobject]@{
                invocation_id = $script:invocationBytes
                reserved_artifact_id = $script:artifactBytes
            }
            $script:operations = @()
            $script:queryCount = 0
            $script:eventCalls = [Collections.Generic.List[object]]::new()
            $script:completionCalls = [Collections.Generic.List[object]]::new()

            Mock Invoke-HHSqliteQuery {
                $script:queryCount++
                if ($script:queryCount -eq 1) { return @($script:pendingRow) }
                return @($script:operations)
            }
            Mock Invoke-HHAnchoredPersistenceTransaction {
                param($Context, $Action, $ArgumentList)
                & $Action $Context.Connection ([pscustomobject]@{}) $Context $ArgumentList
            }
            Mock Publish-HHDurableFile {
                [IO.File]::Move($SourcePath, $DestinationPath, $false)
            }
            Mock Write-HHSqliteRemoteOperationEvent {
                $script:eventCalls.Add([pscustomobject]@{
                        Ordinal = $Ordinal
                        EventKind = $EventKind
                        Evidence = $Evidence
                    })
            }
            Mock Complete-HHSqliteAuditIntent {
                $script:completionCalls.Add([pscustomobject]@{
                        Status = $Status
                        FailureKind = $FailureKind
                        DispatchState = $DispatchState
                        OutcomeStatus = $OutcomeStatus
                        Payload = $Payload
                        RecoveryState = $RecoveryState
                        ArtifactReceipt = $ArtifactReceipt
                    })
            }
        }

        It 'returns without a transaction and removes exact stale reservations when nothing is pending' {
            $reservation = Join-Path $script:persistence.RecoveryRoot `
                '.0123456789abcdef0123456789abcdef.capacity.reserve'
            [IO.File]::WriteAllBytes($reservation, [byte[]](1, 2, 3))
            Mock Invoke-HHSqliteQuery { @() }

            @(Recover-HHAuthenticatedAuditState -Context $script:context).Count |
                Should -Be 0
            Test-Path -LiteralPath $reservation | Should -BeFalse
            Should -Invoke Invoke-HHAnchoredPersistenceTransaction -Times 0
        }

        It 'fails closed on a reservation whose identity is not exact' {
            $unsafe = Join-Path $script:persistence.RecoveryRoot `
                '.NOT-HEX.capacity.reserve'
            [IO.File]::WriteAllBytes($unsafe, [byte[]](1))
            Mock Invoke-HHSqliteQuery { @() }

            {
                Recover-HHAuthenticatedAuditState -Context $script:context
            } | Should -Throw -ErrorId 'PersistencePathUnsafe*'
            Test-Path -LiteralPath $unsafe | Should -BeTrue
        }

        It 'fails closed on a reservation reparse point with an otherwise valid name' -Skip:$IsWindows {
            $target = Join-Path $TestDrive 'reservation-target'
            [IO.File]::WriteAllBytes($target, [byte[]](1))
            $link = Join-Path $script:persistence.RecoveryRoot `
                '.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.capacity.reserve'
            $null = New-Item -ItemType SymbolicLink -Path $link -Target $target
            Mock Invoke-HHSqliteQuery { @() }

            {
                Recover-HHAuthenticatedAuditState -Context $script:context
            } | Should -Throw -ErrorId 'PersistencePathUnsafe*'
            Test-Path -LiteralPath $link | Should -BeTrue
            Test-Path -LiteralPath $target | Should -BeTrue
        }

        It 'classifies unarmed and armed operations without retrying terminal work' {
            $reservation = Join-Path $script:persistence.RecoveryRoot `
                '.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.capacity.reserve'
            [IO.File]::WriteAllBytes($reservation, [byte[]](1))
            $script:operations = @(
                [pscustomobject]@{ ordinal = 0; armed = 0; terminal = 0 }
                [pscustomobject]@{ ordinal = 1; armed = 1; terminal = 0 }
                [pscustomobject]@{ ordinal = 2; armed = 1; terminal = 1 }
            )

            $receipts = @(Recover-HHAuthenticatedAuditState -Context $script:context)

            $receipts.Count | Should -Be 1
            $receipts[0].RecoveryState | Should -BeExactly RecoveredDispatchUncertain
            $receipts[0].DispatchState | Should -BeExactly DispatchUncertain
            $script:eventCalls.Count | Should -Be 2
            $script:eventCalls[0].Ordinal | Should -Be 0
            $script:eventCalls[0].EventKind | Should -BeExactly Skipped
            $script:eventCalls[1].Ordinal | Should -Be 1
            $script:eventCalls[1].EventKind | Should -BeExactly DispatchUncertain
            @($script:eventCalls | Where-Object { $_.Ordinal -eq 2 }).Count | Should -Be 0
            foreach ($call in @($script:eventCalls) + @($script:completionCalls)) {
                $payload = if ($null -ne $call.PSObject.Properties['Evidence']) {
                    $call.Evidence
                }
                else { $call.Payload }
                $payload.remoteRetryAttempted | Should -BeFalse
            }
            $script:completionCalls[0].Status | Should -BeExactly Unknown
            $script:completionCalls[0].FailureKind | Should -BeExactly TransportFailure
            $script:completionCalls[0].OutcomeStatus | Should -BeExactly Unknown
            Test-Path -LiteralPath $reservation | Should -BeFalse
        }

        It 'fails an interrupted invocation that never crossed the dispatch boundary' {
            $script:operations = @(
                [pscustomobject]@{ ordinal = 0; armed = 0; terminal = 0 }
            )

            $receipt = @(Recover-HHAuthenticatedAuditState -Context $script:context)[0]

            $receipt.Status | Should -BeExactly Failed
            $receipt.OutcomeStatus | Should -BeExactly Failed
            $receipt.DispatchState | Should -BeExactly NotDispatched
            $receipt.RecoveryState | Should -BeExactly RecoveredNotDispatched
            $script:eventCalls[0].EventKind | Should -BeExactly Skipped
            $script:eventCalls[0].Evidence.remoteRetryAttempted | Should -BeFalse
            $script:completionCalls[0].Status | Should -BeExactly Failed
            $script:completionCalls[0].OutcomeStatus | Should -BeExactly Failed
        }

        It 'attaches a complete identity-bound orphan as evidence for an armed invocation' {
            $invocationId = ConvertTo-HHPersistenceIdentifierText $script:invocationBytes
            $artifactId = ConvertTo-HHPersistenceIdentifierText $script:artifactBytes
            $finalPath = Join-Path $script:persistence.OutputRoot "$invocationId.hhout"
            $temporaryPath = Join-Path $script:persistence.OutputRoot `
                ".$invocationId.$artifactId.tmp"
            $script:operations = @(
                [pscustomobject]@{ ordinal = 0; armed = 1; terminal = 0 }
            )
            $writer = Open-HHAuditArtifactV2Writer `
                -DataRoot $script:persistence.DataRoot `
                -OutputRoot $script:persistence.OutputRoot `
                -RecoveryRoot $script:persistence.RecoveryRoot `
                -DatabaseId $script:context.Anchor.DatabaseId `
                -LedgerId $script:context.Anchor.LedgerId `
                -InvocationId $script:invocationBytes `
                -ArtifactId $script:artifactBytes `
                -MasterKey $script:context.MasterKey
            $published = Complete-HHAuditArtifactV2Writer -Writer $writer
            $published.Path | Should -BeExactly $finalPath
            [IO.File]::WriteAllText($temporaryPath, 'incomplete duplicate staging')

            $receipt = @(Recover-HHAuthenticatedAuditState -Context $script:context)[0]

            $receipt.RecoveryState | Should -BeExactly RecoveredPartialEvidence
            Test-Path -LiteralPath $finalPath | Should -BeTrue
            Test-Path -LiteralPath $temporaryPath | Should -BeFalse
            @(Get-ChildItem -LiteralPath $script:persistence.RecoveryRoot `
                    -Filter '*.partial' -File).Count | Should -Be 1
            $script:completionCalls[0].Payload.partialEvidenceQuarantined |
                Should -BeTrue
            $script:completionCalls[0].Payload.completeEvidenceAttached |
                Should -BeTrue
            $script:completionCalls[0].ArtifactReceipt.Path | Should -BeExactly $finalPath
            $script:completionCalls[0].ArtifactReceipt.Bytes | Should -Be $published.Bytes
            $script:completionCalls[0].ArtifactReceipt.CiphertextSha256 |
                Should -Be $published.CiphertextSha256
            $script:completionCalls[0].Payload.remoteRetryAttempted |
                Should -BeFalse
        }

        It 'fails integrity when complete output contradicts an unarmed invocation' {
            $invocationId = ConvertTo-HHPersistenceIdentifierText $script:invocationBytes
            $finalPath = Join-Path $script:persistence.OutputRoot "$invocationId.hhout"
            $script:operations = @(
                [pscustomobject]@{ ordinal = 0; armed = 0; terminal = 0 }
            )
            $writer = Open-HHAuditArtifactV2Writer `
                -DataRoot $script:persistence.DataRoot `
                -OutputRoot $script:persistence.OutputRoot `
                -RecoveryRoot $script:persistence.RecoveryRoot `
                -DatabaseId $script:context.Anchor.DatabaseId `
                -LedgerId $script:context.Anchor.LedgerId `
                -InvocationId $script:invocationBytes `
                -ArtifactId $script:artifactBytes `
                -MasterKey $script:context.MasterKey
            $null = Complete-HHAuditArtifactV2Writer -Writer $writer

            {
                Recover-HHAuthenticatedAuditState -Context $script:context
            } | Should -Throw -ErrorId 'AuditIntegrityFailed*'
            Test-Path -LiteralPath $finalPath | Should -BeTrue
            $script:eventCalls.Count | Should -Be 0
            $script:completionCalls.Count | Should -Be 0
        }

        It 'fails closed and leaves a tampered final orphan in place' {
            $invocationId = ConvertTo-HHPersistenceIdentifierText $script:invocationBytes
            $finalPath = Join-Path $script:persistence.OutputRoot "$invocationId.hhout"
            $writer = Open-HHAuditArtifactV2Writer `
                -DataRoot $script:persistence.DataRoot `
                -OutputRoot $script:persistence.OutputRoot `
                -RecoveryRoot $script:persistence.RecoveryRoot `
                -DatabaseId $script:context.Anchor.DatabaseId `
                -LedgerId $script:context.Anchor.LedgerId `
                -InvocationId $script:invocationBytes `
                -ArtifactId $script:artifactBytes `
                -MasterKey $script:context.MasterKey
            $null = Complete-HHAuditArtifactV2Writer -Writer $writer
            $bytes = [IO.File]::ReadAllBytes($finalPath)
            $bytes[90] = $bytes[90] -bxor 1
            [IO.File]::WriteAllBytes($finalPath, $bytes)

            {
                Recover-HHAuthenticatedAuditState -Context $script:context
            } | Should -Throw -ErrorId 'AuditIntegrityFailed*'
            Test-Path -LiteralPath $finalPath | Should -BeTrue
            @(Get-ChildItem -LiteralPath $script:persistence.RecoveryRoot `
                    -Filter '*.partial' -File).Count | Should -Be 0
            Should -Invoke Invoke-HHAnchoredPersistenceTransaction -Times 0
        }

        It 'quarantines an orphan temporary artifact when no final output exists' {
            $invocationId = ConvertTo-HHPersistenceIdentifierText $script:invocationBytes
            $artifactId = ConvertTo-HHPersistenceIdentifierText $script:artifactBytes
            $temporaryPath = Join-Path $script:persistence.OutputRoot `
                ".$invocationId.$artifactId.tmp"
            [IO.File]::WriteAllText($temporaryPath, 'temporary evidence')

            $receipt = @(Recover-HHAuthenticatedAuditState -Context $script:context)[0]

            $receipt.RecoveryState | Should -BeExactly RecoveredPartialEvidence
            $receipt.Status | Should -BeExactly Failed
            $receipt.DispatchState | Should -BeExactly NotDispatched
            Test-Path -LiteralPath $temporaryPath | Should -BeFalse
            @(Get-ChildItem -LiteralPath $script:persistence.RecoveryRoot `
                    -Filter '*.partial' -File).Count | Should -Be 1
        }

        It 'keeps a stale reservation until the anchored recovery transaction succeeds' {
            $reservation = Join-Path $script:persistence.RecoveryRoot `
                '.fedcba9876543210fedcba9876543210.capacity.reserve'
            [IO.File]::WriteAllBytes($reservation, [byte[]](1))
            Mock Invoke-HHAnchoredPersistenceTransaction { throw 'seal failed' }

            {
                Recover-HHAuthenticatedAuditState -Context $script:context
            } | Should -Throw '*seal failed*'
            Test-Path -LiteralPath $reservation | Should -BeTrue
            $script:eventCalls.Count | Should -Be 0
            $script:completionCalls.Count | Should -Be 0
        }
    }
}
