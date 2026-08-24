if ([string]::IsNullOrWhiteSpace($env:HH_TEST_MODULE_PATH)) {
    throw 'HH_TEST_MODULE_PATH is required for SQLite fault integration proof.'
}

$hasBoundedFaultRoot = -not [string]::IsNullOrWhiteSpace($env:HH_SQLITE_FAULT_ROOT)

Describe 'packaged SQLite external capacity faults' -Tag Integration {
    It 'refuses the exact default predispatch reservation on a bounded filesystem' `
        -Skip:(-not $hasBoundedFaultRoot) {
        Import-Module $env:HH_TEST_MODULE_PATH -Force
        $module = Get-Module HostHunterNextGeneration
        $result = & $module {
            param($Root)
            $persistence = Get-HHPersistenceContext -DataRoot (Join-Path $Root 'predispatch')
            Initialize-HHPersistenceRoot -PersistenceContext $persistence
            try {
                $null = New-HHPersistenceCapacityReservation `
                    -PersistenceContext $persistence `
                    -BatchId ('a' * 32) -InvocationCount 1
                return [ordered]@{ ErrorId = 'unexpected-success'; Remaining = -1 }
            }
            catch {
                return [ordered]@{
                    ErrorId = [string]$_.FullyQualifiedErrorId
                    Remaining = @(Get-ChildItem -LiteralPath $persistence.RecoveryRoot `
                            -Filter '*.capacity.reserve' -File -Force).Count
                }
            }
        } $env:HH_SQLITE_FAULT_ROOT

        $result.ErrorId | Should -Match '^PersistenceCapacityInsufficient'
        $result.Remaining | Should -Be 0
    }

    It 'surfaces real SQLITE_FULL after an external process consumes space post-arm' `
        -Skip:(-not $hasBoundedFaultRoot) {
        Import-Module $env:HH_TEST_MODULE_PATH -Force
        $module = Get-Module HostHunterNextGeneration
        $provider = Join-Path (Split-Path -Parent $env:HH_TEST_MODULE_PATH) 'lib'
        $result = & $module {
            param($Root, $Provider)
            $dataRoot = Join-Path $Root 'mid-command'
            $persistence = Get-HHPersistenceContext -DataRoot $dataRoot
            $keyProvider = { ,([byte[]](1..32)) }
            $context = Open-HHAuthenticatedPersistence -PersistenceContext $persistence `
                -OperationLock -AllowAnchorAdvance -ProviderRoot $Provider `
                -MasterKeyProvider $keyProvider
            $fillerPath = Join-Path $Root 'external.fill'
            try {
                $target = New-HHTargetRecord -Name full-target -Transport SSH `
                    -HostName full.example.test -Port 22 -UserName operator `
                    -Authentication Password -PowerShellRuntime PowerShell7 `
                    -HostKeyFingerprint ('SHA256:' + ('A' * 43)) -KeyPath $null `
                    -IsActive $true -LastValidatedAtUtc '2026-08-24T00:00:00Z' `
                    -LastValidatedPSEdition Core -LastValidatedPowerShellVersion '7.6.5' `
                    -LastValidatedExecutionMode Direct
                $remote = Get-HHRemoteOperationManifestEntry -Phase Command `
                    -PowerShellRuntime PowerShell7 -ScriptText "'full-probe'"
                $request = [pscustomobject]@{
                    Target = $target; CommandText = "'full-probe'"
                    Reason = $null; CaseId = 'full-case'; RemoteOperations = @($remote)
                }
                $intent = @(Register-HHAuthenticatedAuditBatch -Context $context `
                        -Operation InvokeCommand -Request @($request))[0]
                Arm-HHAuthenticatedRemoteOperation -Context $context -Intent $intent -Ordinal 0

                $fill = [Diagnostics.Process]::Start('/usr/bin/dd', @(
                        'if=/dev/zero', "of=$fillerPath", 'bs=1048576', 'count=128'
                    ))
                $fill.WaitForExit()
                $fault = $null
                try {
                    $null = Invoke-HHAnchoredPersistenceTransaction -Context $context -Action {
                        param($Connection, $Transaction)
                        $null = Invoke-HHSqliteNonQuery -Connection $Connection `
                            -Transaction $Transaction `
                            -Sql 'INSERT INTO schema_migrations(version,name,sql_checksum,applied_at_utc) VALUES(99,@name,randomblob(32),@at);' `
                            -Parameters @{
                                name = 'external-capacity-fault'
                                at = '2026-08-24T03:00:00.0000000Z'
                            }
                    }
                }
                catch { $fault = $_ }
                [ordered]@{
                    InvocationId = $intent.InvocationId
                    Exception = $fault.Exception.ToString()
                    FillerExitCode = $fill.ExitCode
                }
            }
            finally {
                if ([IO.File]::Exists($fillerPath)) { [IO.File]::Delete($fillerPath) }
                Close-HHAuthenticatedPersistence -Context $context
            }
        } $env:HH_SQLITE_FAULT_ROOT $provider

        $result.InvocationId | Should -Match '^[a-f0-9]{32}$'
        $result.Exception | Should -Match '(?i)(database or disk is full|SQLITE_FULL)'
        $result.FillerExitCode | Should -Not -Be 0
    }
}
