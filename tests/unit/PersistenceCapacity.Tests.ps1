$sourceRoot = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
    Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration'
}
else { $env:HH_TEST_SOURCE_ROOT }
Import-Module (Join-Path $sourceRoot 'HostHunterNextGeneration.psd1') -Force

Describe 'pre-dispatch persistence capacity reservation' -Tag Unit {
    InModuleScope HostHunterNextGeneration {
        BeforeEach {
            $script:root = Join-Path $TestDrive ([Guid]::NewGuid().ToString('N'))
            $script:context = Get-HHPersistenceContext -DataRoot $script:root
        }

        It 'writes and flushes real bytes for every invocation plus the recovery margin' {
            $reservation = New-HHPersistenceCapacityReservation `
                -PersistenceContext $script:context -BatchId ('a' * 32) `
                -InvocationCount 2 -ArtifactBytes 4096 -RecoveryMarginBytes 4096 `
                -BlockBytes 4096
            $reservation.ReservedBytes | Should -Be 12288
            [IO.FileInfo]::new($reservation.Path).Length | Should -Be 12288
            if (-not $IsWindows) {
                [IO.File]::GetUnixFileMode($reservation.Path) | Should -Be (
                    [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite
                )
            }
            Remove-HHPersistenceCapacityReservation -Reservation $reservation
            $reservation.Released | Should -BeTrue
            $reservation.Path | Should -Not -Exist
            { Remove-HHPersistenceCapacityReservation -Reservation $reservation } |
                Should -Not -Throw
        }

        It 'fails closed and removes partial capacity when allocation stops early' {
            {
                New-HHPersistenceCapacityReservation `
                    -PersistenceContext $script:context -BatchId ('b' * 32) `
                    -InvocationCount 1 -ArtifactBytes 8192 -RecoveryMarginBytes 4096 `
                    -BlockBytes 4096 -BlockWriter {
                    param($Stream, $Buffer, $Length)
                    $Stream.Write($Buffer, 0, $Length)
                    throw 'disk full'
                }
            } | Should -Throw '*could not reserve durable output*'
            @(Get-ChildItem -LiteralPath $script:context.RecoveryRoot -Force).Count | Should -Be 0
        }

        It 'refuses an existing reservation instead of sharing capacity ownership' {
            $first = New-HHPersistenceCapacityReservation `
                -PersistenceContext $script:context -BatchId ('c' * 32) `
                -InvocationCount 1 -ArtifactBytes 4096 -RecoveryMarginBytes 4096
            {
                New-HHPersistenceCapacityReservation `
                    -PersistenceContext $script:context -BatchId ('c' * 32) `
                    -InvocationCount 1 -ArtifactBytes 4096 -RecoveryMarginBytes 4096
            } | Should -Throw '*could not reserve durable output*'
            $first.Path | Should -Exist
            Remove-HHPersistenceCapacityReservation -Reservation $first
        }

        It 'rejects reservation arithmetic that exceeds the supported file length' {
            {
                New-HHPersistenceCapacityReservation `
                    -PersistenceContext $script:context -BatchId ('d' * 32) `
                    -InvocationCount 8 -ArtifactBytes ([long]::MaxValue) `
                    -RecoveryMarginBytes 4096
            } | Should -Throw '*Capacity reservation is too large*'
            $script:context.RecoveryRoot | Should -Not -Exist
        }

        It 'fails closed when a writer returns without reserving the declared length' {
            {
                New-HHPersistenceCapacityReservation `
                    -PersistenceContext $script:context -BatchId ('e' * 32) `
                    -InvocationCount 1 -ArtifactBytes 4096 -RecoveryMarginBytes 4096 `
                    -BlockBytes 4096 -BlockWriter {
                    param($Stream, $Buffer, $Length)
                    $Stream.Write($Buffer, 0, [Math]::Max(1, $Length - 1))
                }
            } | Should -Throw '*could not reserve durable output*'
            @(Get-ChildItem -LiteralPath $script:context.RecoveryRoot -Force).Count | Should -Be 0
        }

        It 'marks an already-absent owned reservation as released idempotently' {
            $reservation = [pscustomobject]@{
                Path = Join-Path $script:context.RecoveryRoot 'already-absent.reserve'
                Released = $false
            }

            Remove-HHPersistenceCapacityReservation -Reservation $reservation

            $reservation.Released | Should -BeTrue
            $reservation.Path | Should -Not -Exist
        }
    }
}
