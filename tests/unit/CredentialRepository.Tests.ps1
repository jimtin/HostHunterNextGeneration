$sourceRoot = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
    Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration'
}
else { $env:HH_TEST_SOURCE_ROOT }
Import-Module (Join-Path $sourceRoot 'HostHunterNextGeneration.psd1') -Force

Describe 'encrypted target credential repository' -Tag Unit {
    InModuleScope HostHunterNextGeneration {
        BeforeEach {
            $script:masterKey = [byte[]](1..32)
            $script:binding = [pscustomobject]@{
                database_id = [Guid]::Parse(
                    '11111111-1111-1111-1111-111111111111'
                ).ToByteArray()
                name = 'alpha'
                name_key = 'ALPHA'
                host_name = 'alpha.example.test'
                port = 22L
                user_name = 'operator'
                authentication = 'Password'
                credential_storage = 'Encrypted'
                revision = 7L
            }
            $script:storedEnvelope = $null
            Mock Invoke-HHSqliteQuery {
                param($Sql)
                if ($Sql -match 'SELECT d.database_id') { return @($script:binding) }
                if ($Sql -match 'SELECT password_envelope') {
                    return @([pscustomobject]@{
                            password_envelope = $script:storedEnvelope
                            target_revision = 7L
                        })
                }
                if ($Sql -match 'expected_count') {
                    return @([pscustomobject]@{
                            expected_count = 1L; actual_count = 1L; invalid_count = 0L
                        })
                }
                throw "Unexpected query: $Sql"
            }
            Mock Invoke-HHSqliteNonQuery {
                param($Sql, $Parameters)
                if ($Sql -match '^INSERT INTO target_credentials') {
                    $script:storedEnvelope = [byte[]]$Parameters.envelope.Clone()
                }
                1
            }
            $script:target = New-HHTargetRecord -Name alpha -Transport SSH `
                -HostName alpha.example.test -Port 22 -UserName operator `
                -Authentication Password -CredentialStorage Encrypted `
                -PowerShellRuntime PowerShell7 `
                -HostKeyFingerprint ('SHA256:' + ('A' * 43)) `
                -IsActive $true -LastValidatedAtUtc '2026-08-27T00:00:00Z' `
                -LastValidatedPSEdition Core `
                -LastValidatedPowerShellVersion '7.6.5' `
                -LastValidatedExecutionMode Direct
        }

        AfterEach {
            if ($null -ne $script:storedEnvelope) {
                [Array]::Clear($script:storedEnvelope, 0, $script:storedEnvelope.Length)
            }
        }

        It 'round trips an encrypted password without persisting plaintext' {
            $password = [Text.Encoding]::UTF8.GetBytes('unique-password-fixture-7291')
            try {
                Set-HHTargetCredential -Connection ([pscustomobject]@{}) `
                    -Transaction ([pscustomobject]@{}) -MasterKey $script:masterKey `
                    -Name alpha -PasswordBytes $password `
                    -StoredAtUtc ([DateTimeOffset]::Parse('2026-08-27T00:00:00Z'))

                $script:storedEnvelope | Should -Not -BeNullOrEmpty
                [Text.Encoding]::UTF8.GetString($script:storedEnvelope) |
                    Should -Not -Match 'unique-password-fixture-7291'
                $restored = Get-HHTargetCredential -Connection ([pscustomobject]@{}) `
                    -MasterKey $script:masterKey -Target $script:target
                try {
                    [Text.Encoding]::UTF8.GetString($restored) |
                        Should -BeExactly 'unique-password-fixture-7291'
                }
                finally { [Array]::Clear($restored, 0, $restored.Length) }
                Should -Invoke Invoke-HHSqliteNonQuery -Times 2 -Exactly
            }
            finally { [Array]::Clear($password, 0, $password.Length) }
        }

        It 'binds the envelope to the target revision and rejects stale state' {
            $password = [Text.Encoding]::UTF8.GetBytes('revision-secret')
            try {
                Set-HHTargetCredential -Connection ([pscustomobject]@{}) `
                    -Transaction ([pscustomobject]@{}) -MasterKey $script:masterKey `
                    -Name alpha -PasswordBytes $password `
                    -StoredAtUtc ([DateTimeOffset]::UtcNow)
                $script:binding.revision = 8L
                { Get-HHTargetCredential -Connection ([pscustomobject]@{}) `
                        -MasterKey $script:masterKey -Target $script:target } |
                    Should -Throw '*missing or stale*Set-HHTarget*'
            }
            finally { [Array]::Clear($password, 0, $password.Length) }
        }

        It 'rejects orphaned or mismatched credential rows' {
            Mock Invoke-HHSqliteQuery {
                @([pscustomobject]@{
                        expected_count = 1L; actual_count = 1L; invalid_count = 1L
                    })
            }
            { Assert-HHTargetCredentialState -Connection ([pscustomobject]@{}) } |
                Should -Throw '*failed integrity validation*'
        }
    }
}
