$sourceRoot = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
    Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration'
}
else { $env:HH_TEST_SOURCE_ROOT }
Import-Module (Join-Path $sourceRoot 'HostHunterNextGeneration.psd1') -Force

Describe 'authenticated audit orchestration' -Tag Unit {
    InModuleScope HostHunterNextGeneration {
        BeforeEach {
            $script:context = [pscustomobject]@{
                PersistenceContext = [pscustomobject]@{
                    DataRoot = '/data'; OutputRoot = '/data/output'; RecoveryRoot = '/data/recovery'
                }
                Anchor = [pscustomobject]@{
                    DatabaseId = [byte[]](1..16); LedgerId = [byte[]](17..32)
                }
                MasterKey = [byte[]](0..31)
            }
            $script:intent = [pscustomobject]@{
                BatchId = 'a' * 32
                InvocationId = '1' * 32
                ArtifactId = '2' * 32
                RemoteOperations = @(
                    [pscustomobject]@{ Phase = 'Identity'; ScriptText = 'one' }
                    [pscustomobject]@{ Phase = 'Command'; ScriptText = 'two' }
                )
            }
            $script:remoteEvents = [Collections.Generic.List[object]]::new()
            $script:terminal = [Collections.Generic.List[object]]::new()
            Mock Invoke-HHAnchoredPersistenceTransaction {
                param($Context, $ArgumentList, $Action)
                & $Action 'connection' 'transaction' $Context $ArgumentList
            }
            Mock Register-HHSqliteAuditBatch { @($script:intent) }
            Mock New-HHPersistenceCapacityReservation {
                [pscustomobject]@{ Path = '/data/recovery/reserve'; Released = $false }
            }
            Mock Open-HHAuditArtifactV2Writer { [pscustomobject]@{ EventCount = 0; State = 'Open' } }
            Mock Write-HHSqliteRemoteOperationEvent {
                param($Ordinal, $EventKind, $ExpectedOperation, $Evidence)
                $script:remoteEvents.Add([pscustomobject]@{
                        Ordinal = $Ordinal; Kind = $EventKind
                        Expected = $ExpectedOperation; Evidence = $Evidence
                    })
                [pscustomobject]@{ Ordinal = $Ordinal; Kind = $EventKind }
            }
            Mock Complete-HHSqliteAuditIntent {
                param($Status, $FailureKind, $DispatchState, $OutcomeStatus, $Payload, $ArtifactReceipt)
                $script:terminal.Add([pscustomobject]@{
                        Status = $Status; FailureKind = $FailureKind
                        DispatchState = $DispatchState; OutcomeStatus = $OutcomeStatus
                        Payload = $Payload; Artifact = $ArtifactReceipt
                    })
            }
            Mock Get-HHAuditIntentTransportContext { [pscustomobject]@{ Operation = 'InvokeCommand' } }
            $script:validated = [pscustomobject]@{
                FailureKind = 'TransportFailure'; DispatchState = 'DispatchUncertain'
                OutcomeStatus = 'Unknown'; RemoteIdentity = @{ UserName = 'operator' }
                RemotePowerShellVersion = '7.6.5'; RemotePSEdition = 'Core'
                ExecutionMode = 'Direct'; ValidatedAtUtc = '2026-08-24T00:00:00Z'
                HostKeyFingerprint = "SHA256:$('A' * 43)"; OutputBytes = 10L
                StreamEvents = @([pscustomobject]@{ Sequence = 0 }, [pscustomobject]@{ Sequence = 1 })
                ExceptionType = 'System.Exception'; HasSessionRemovalFailure = $true
                SessionRemovalFailure = 'close failed'; HasBootstrapOutcome = $true
                Installed = $true; RollbackAttempted = $true; RollbackSucceeded = $false
                ReconciliationRequired = $true; CommitState = 'Uncertain'
            }
            Mock Assert-HHTransportAuditResult { $script:validated }
            Mock Save-HHSqliteTransportArtifact {
                [pscustomobject]@{ RelativeFileName = 'artifact.hha'; StreamEventCount = 2L }
            }
            Mock Write-HHAuditArtifactV2Event
            Mock Complete-HHAuditArtifactV2Writer {
                [pscustomobject]@{ RelativeFileName = 'streamed.hha'; StreamEventCount = 2L }
            }
        }

        It 'registers intent inside the anchored transaction with exact request data' {
            $request = @([pscustomobject]@{ Target = 'alpha' })
            $result = @(Register-HHAuthenticatedAuditBatch `
                    -Context $script:context -Operation InvokeCommand -Request $request)
            $result.Count | Should -Be 1
            Should -Invoke Register-HHSqliteAuditBatch -Times 1 -ParameterFilter {
                $Connection -eq 'connection' -and $Transaction -eq 'transaction' -and
                $Operation -ceq 'InvokeCommand' -and @($Request).Count -eq 1
            }
        }

        It 'reserves capacity from the shared batch and cancels every intent on failure' {
            $second = $script:intent.PSObject.Copy()
            Mock New-HHPersistenceCapacityReservation { throw 'disk full' }
            Mock Complete-HHAuthenticatedUnstartedAuditIntent
            {
                Start-HHAuthenticatedAuditCapacityReservation `
                    -Context $script:context -Intent @($script:intent, $second)
            } | Should -Throw '*disk full*'
            Should -Invoke Complete-HHAuthenticatedUnstartedAuditIntent -Times 2 `
                -ParameterFilter { $Reason -ceq 'PersistenceCapacityInsufficient' }

            Mock New-HHPersistenceCapacityReservation {
                [pscustomobject]@{ Path = '/reserve' }
            }
            $receipt = Start-HHAuthenticatedAuditCapacityReservation `
                -Context $script:context -Intent @($script:intent, $second)
            $receipt.Path | Should -BeExactly '/reserve'
            Should -Invoke New-HHPersistenceCapacityReservation -Times 1 -ParameterFilter {
                $BatchId -ceq ('a' * 32) -and $InvocationCount -eq 2
            }
        }

        It 'preserves the capacity error and marks cancellation failure evidence' {
            Mock New-HHPersistenceCapacityReservation { throw 'disk full' }
            Mock Complete-HHAuthenticatedUnstartedAuditIntent { throw 'anchor unavailable' }
            $caught = $null
            try {
                Start-HHAuthenticatedAuditCapacityReservation `
                    -Context $script:context -Intent @($script:intent)
            }
            catch { $caught = $_ }
            $caught.Exception.Message | Should -BeExactly 'disk full'
            $caught.Exception.Data['HHAuditCancellationFailure'] | Should -BeTrue
        }

        It 'opens the artifact writer with anchored identities and exact reserved ids' {
            $null = Open-HHAuthenticatedAuditArtifactWriter `
                -Context $script:context -Intent $script:intent
            Should -Invoke Open-HHAuditArtifactV2Writer -Times 1 -ParameterFilter {
                $DataRoot -ceq '/data' -and $OutputRoot -ceq '/data/output' -and
                $RecoveryRoot -ceq '/data/recovery' -and $InvocationId.Length -eq 16 -and
                $ArtifactId.Length -eq 16 -and $MasterKey.Length -eq 32
            }
        }

        It 'arms each selected ordinal against its exact declaration' {
            Arm-HHAuthenticatedRemoteOperation `
                -Context $script:context -Intent $script:intent -Ordinal 0, 1
            @($script:remoteEvents.Ordinal) | Should -Be @(0, 1)
            @($script:remoteEvents.Kind) | Should -Be @('DispatchArmed', 'DispatchArmed')
            $script:remoteEvents[1].Expected.ScriptText | Should -BeExactly two
        }

        It 'cancels an unstarted intent by skipping every operation and writing one terminal' {
            Complete-HHAuthenticatedUnstartedAuditIntent `
                -Context $script:context -Intent $script:intent -Reason UserCancelled
            @($script:remoteEvents.Ordinal) | Should -Be @(0, 1)
            @($script:remoteEvents.Kind) | Should -Be @('Skipped', 'Skipped')
            $script:terminal.Count | Should -Be 1
            $script:terminal[0].Status | Should -BeExactly Cancelled
            $script:terminal[0].DispatchState | Should -BeExactly NotDispatched
            $script:terminal[0].Payload.remoteActivityStarted | Should -BeFalse
        }

        It 'cancels an empty defensive manifest without inventing remote operation events' {
            $emptyIntent = $script:intent.PSObject.Copy()
            $emptyIntent.RemoteOperations = @()

            Complete-HHAuthenticatedUnstartedAuditIntent `
                -Context $script:context -Intent $emptyIntent -Reason UserCancelled

            $script:remoteEvents.Count | Should -Be 0
            $script:terminal.Count | Should -Be 1
            $script:terminal[0].DispatchState | Should -BeExactly NotDispatched
        }

        It 'completes an empty defensive manifest without inventing terminal operation events' {
            $emptyIntent = $script:intent.PSObject.Copy()
            $emptyIntent.RemoteOperations = @()
            $script:validated.HasSessionRemovalFailure = $false
            $script:validated.HasBootstrapOutcome = $false
            $script:validated.OutcomeStatus = 'Succeeded'

            $null = Complete-HHAuthenticatedTransportAudit `
                -Context $script:context -Intent $emptyIntent `
                -TransportResult ([pscustomobject]@{}) -ArmedOrdinal @()

            $script:remoteEvents.Count | Should -Be 0
            $script:terminal[0].Status | Should -BeExactly Succeeded
        }

        It 'saves a fallback artifact and records uncertain mixed terminal evidence' {
            $artifact = Complete-HHAuthenticatedTransportAudit `
                -Context $script:context -Intent $script:intent `
                -TransportResult ([pscustomobject]@{}) -ArmedOrdinal 1
            $artifact.RelativeFileName | Should -BeExactly 'artifact.hha'
            @($script:remoteEvents.Kind) | Should -Be @('Skipped', 'Completed')
            $script:terminal[0].Status | Should -BeExactly Unknown
            $script:terminal[0].Payload.sessionRemovalFailure | Should -BeExactly 'close failed'
            $script:terminal[0].Payload.commitState | Should -BeExactly Uncertain
            $script:terminal[0].Artifact | Should -Be $artifact
        }

        It 'appends only missing streamed events and maps success and failure statuses' {
            $writer = [pscustomobject]@{ EventCount = 1; State = 'Open' }
            $script:validated.HasSessionRemovalFailure = $false
            $script:validated.HasBootstrapOutcome = $false
            $script:validated.OutcomeStatus = 'Succeeded'
            $null = Complete-HHAuthenticatedTransportAudit `
                -Context $script:context -Intent $script:intent `
                -TransportResult ([pscustomobject]@{}) -ArmedOrdinal 0, 1 `
                -ArtifactWriter $writer
            Should -Invoke Write-HHAuditArtifactV2Event -Times 1 -ParameterFilter {
                $EventRecord.Sequence -eq 1
            }
            $script:terminal[0].Status | Should -BeExactly Succeeded

            $script:validated.OutcomeStatus = 'Failed'
            $null = Complete-HHAuthenticatedTransportAudit `
                -Context $script:context -Intent $script:intent `
                -TransportResult ([pscustomobject]@{}) -ArmedOrdinal @() `
                -ArtifactWriter ([pscustomobject]@{ EventCount = 2; State = 'Open' })
            $script:terminal[1].Status | Should -BeExactly Failed
        }
    }
}
