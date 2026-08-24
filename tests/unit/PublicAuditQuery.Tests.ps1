$sourceRoot = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
    Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration'
}
else { $env:HH_TEST_SOURCE_ROOT }
Import-Module (Join-Path $sourceRoot 'HostHunterNextGeneration.psd1') -Force

Describe 'Public audit query commands' -Tag Unit {
    InModuleScope HostHunterNextGeneration {
        BeforeEach {
            $script:absentRoot = Join-Path $TestDrive 'absent'
            $script:runtime = [pscustomobject]@{ DataRoot = $script:absentRoot }
            Mock Get-HHRuntimeContext { $script:runtime }
            Mock Open-HHAuthenticatedPersistence { throw 'Persistence must not open for an absent root.' }
            Mock Close-HHAuthenticatedPersistence { }
        }

        It 'returns no records and does not initialize persistence when the data root is absent' {
            @(Get-HHAuditRecord).Count | Should -Be 0
            Should -Invoke Open-HHAuthenticatedPersistence -Times 0
        }

        It 'reports missing output without initializing persistence when the data root is absent' {
            {
                Get-HHAuditOutput -InvocationId '11111111111111111111111111111111'
            } | Should -Throw '*No audit invocation exists*'
            Should -Invoke Open-HHAuthenticatedPersistence -Times 0
        }

        It 'validates identifiers ranges sets and chronological bounds before persistence access' {
            { Get-HHAuditRecord -InvocationId invalid } | Should -Throw
            { Get-HHAuditRecord -BatchId invalid } | Should -Throw
            { Get-HHAuditRecord -First 0 } | Should -Throw
            { Get-HHAuditRecord -BeforeSequence 0 } | Should -Throw
            { Get-HHAuditRecord -Operation InvalidOperation } | Should -Throw
            { Get-HHAuditRecord -Status InvalidStatus } | Should -Throw
            {
                Get-HHAuditRecord -FromUtc '2026-08-24T02:00:00Z' `
                    -ToUtc '2026-08-24T02:00:00Z'
            } | Should -Throw '*FromUtc must be earlier*'
            { Get-HHAuditOutput -InvocationId invalid } | Should -Throw
            Should -Invoke Open-HHAuthenticatedPersistence -Times 0
        }

        It 'forwards explicit filters and closes authenticated persistence after a read' {
            $root = Join-Path $TestDrive 'present'
            $null = New-Item -ItemType Directory -Path $root
            $script:runtime = [pscustomobject]@{ DataRoot = $root }
            $script:opened = [pscustomobject]@{
                Connection = [pscustomobject]@{ DataSource = '/test/db' }
                MasterKey = [byte[]](0..31)
            }
            Mock Open-HHAuthenticatedPersistence { $script:opened }
            Mock Get-HHSqliteAuditRecord {
                [pscustomobject]@{ InvocationId = '11111111111111111111111111111111' }
            }
            $result = @(Get-HHAuditRecord -InvocationId '11111111111111111111111111111111' `
                    -BatchId '22222222222222222222222222222222' -TargetName alpha, beta `
                    -CaseId CASE-1 -FromUtc '2026-08-24T01:00:00Z' `
                    -ToUtc '2026-08-24T02:00:00Z' -Operation InvokeCommand `
                    -Status Succeeded -BeforeSequence 9 -First 7)
            $result.Count | Should -Be 1
            Should -Invoke Get-HHSqliteAuditRecord -Times 1 -ParameterFilter {
                $First -eq 7 -and $BeforeSequence -eq 9 -and $CaseId -ceq 'CASE-1' -and
                @($TargetName).Count -eq 2 -and $Operation -contains 'InvokeCommand' -and
                $Status -contains 'Succeeded'
            }
            Should -Invoke Close-HHAuthenticatedPersistence -Times 1 -ParameterFilter {
                $Context -eq $script:opened
            }
        }

        It 'forwards only the default limit when no optional record filters are supplied' {
            $root = Join-Path $TestDrive 'present-default-query'
            $null = New-Item -ItemType Directory -Path $root
            $script:runtime = [pscustomobject]@{ DataRoot = $root }
            $script:opened = [pscustomobject]@{
                Connection = [pscustomobject]@{ DataSource = '/test/db' }
                MasterKey = [byte[]](0..31)
            }
            Mock Open-HHAuthenticatedPersistence { $script:opened }
            Mock Get-HHSqliteAuditRecord { @() }

            @(Get-HHAuditRecord).Count | Should -Be 0

            Should -Invoke Get-HHSqliteAuditRecord -Times 1 -ParameterFilter {
                $First -eq 100 -and -not $PSBoundParameters.ContainsKey('TargetName') -and
                -not $PSBoundParameters.ContainsKey('BeforeSequence')
            }
            Should -Invoke Close-HHAuthenticatedPersistence -Times 1
        }

        It 'closes authenticated persistence when an output read fails' {
            $root = Join-Path $TestDrive 'present-output'
            $null = New-Item -ItemType Directory -Path $root
            $script:runtime = [pscustomobject]@{ DataRoot = $root }
            $script:opened = [pscustomobject]@{
                Connection = [pscustomobject]@{ DataSource = '/test/db' }
                MasterKey = [byte[]](0..31)
            }
            Mock Open-HHAuthenticatedPersistence { $script:opened }
            Mock Get-HHSqliteAuditOutput { throw 'artifact failure' }
            {
                Get-HHAuditOutput -InvocationId '11111111111111111111111111111111'
            } | Should -Throw '*artifact failure*'
            Should -Invoke Close-HHAuthenticatedPersistence -Times 1
        }
    }
}
