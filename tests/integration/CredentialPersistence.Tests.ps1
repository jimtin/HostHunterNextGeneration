$modulePath = if (-not [string]::IsNullOrWhiteSpace($env:HH_TEST_MODULE_PATH)) {
    $env:HH_TEST_MODULE_PATH
}
elseif ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
    Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration/HostHunterNextGeneration.psd1'
}
else { Join-Path $env:HH_TEST_SOURCE_ROOT 'HostHunterNextGeneration.psd1' }
Remove-Module HostHunterNextGeneration -Force -ErrorAction SilentlyContinue
Import-Module $modulePath -Force
if ([IO.Directory]::Exists('/opt/hosthunter-sqlite/lib')) {
    $env:HH_SQLITE_PROVIDER_ROOT = '/opt/hosthunter-sqlite/lib'
}

Describe 'encrypted credential persistence lifecycle' -Tag Integration {
    InModuleScope HostHunterNextGeneration {
        BeforeEach {
            $script:root = Join-Path $TestDrive ([Guid]::NewGuid().ToString('N'))
            $script:persistence = Get-HHPersistenceContext -DataRoot $script:root
            $script:passwordOne = [Text.Encoding]::UTF8.GetBytes(
                'first-plaintext-fixture-81d9'
            )
            $script:passwordTwo = [Text.Encoding]::UTF8.GetBytes(
                'replacement-plaintext-fixture-47ac'
            )
        }

        AfterEach {
            [Array]::Clear($script:passwordOne, 0, $script:passwordOne.Length)
            [Array]::Clear($script:passwordTwo, 0, $script:passwordTwo.Length)
        }

        BeforeAll {
        function New-CredentialIntegrationTarget {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
                'PSUseShouldProcessForStateChangingFunctions',
                '',
                Justification = 'Creates an in-memory integration-test target only.'
            )]
            param([Parameter(Mandatory)][string]$ValidatedAt)
            New-HHTargetRecord -Name alpha -Transport SSH `
                -HostName alpha.example.test -Port 22 -UserName operator `
                -Authentication Password -CredentialStorage Encrypted `
                -PowerShellRuntime PowerShell7 `
                -HostKeyFingerprint ('SHA256:' + ('A' * 43)) `
                -IsActive $true -LastValidatedAtUtc $ValidatedAt `
                -LastValidatedPSEdition Core `
                -LastValidatedPowerShellVersion 7.6.5 `
                -LastValidatedExecutionMode Direct
        }

        function Set-CredentialIntegrationTarget {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
                'PSUseShouldProcessForStateChangingFunctions',
                '',
                Justification = 'Runs inside an isolated caller-owned test transaction.'
            )]
            param(
                [Parameter(Mandatory)][object]$Context,
                [Parameter(Mandatory)][object]$Target,
                [Parameter(Mandatory)][byte[]]$Password
            )
            $arguments = [pscustomobject]@{ Target = $Target; Password = $Password }
            Invoke-HHAnchoredPersistenceTransaction -Context $Context `
                -ArgumentList @($arguments) -Action {
                param($Connection, $Transaction, $WriterContext, $ArgumentList)
                $data = $ArgumentList[0]
                $receipt = Set-HHTargetRepository -Connection $Connection `
                    -Transaction $Transaction -MasterKey $WriterContext.MasterKey `
                    -Target @($data.Target) `
                    -ExpectedGeneration $WriterContext.TargetSnapshot.Generation `
                    -MutationId ([Guid]::NewGuid().ToByteArray()) `
                    -RequestedAtUtc ([DateTimeOffset]::UtcNow) `
                    -ExpectedAnchor $WriterContext.Anchor
                Set-HHTargetCredential -Connection $Connection -Transaction $Transaction `
                    -MasterKey $WriterContext.MasterKey -Name $data.Target.Name `
                    -PasswordBytes $data.Password -StoredAtUtc ([DateTimeOffset]::UtcNow)
                Assert-HHTargetCredentialState -Connection $Connection -Transaction $Transaction
                $receipt
            }
        }
        }

        It 'builds fresh, atomically saves and replaces ciphertext, then purges on removal' -Skip:$IsMacOS {
            $context = Open-HHAuthenticatedPersistence `
                -PersistenceContext $script:persistence -OperationLock -AllowAnchorAdvance
            try {
                $firstTarget = New-CredentialIntegrationTarget `
                    -ValidatedAt '2026-08-27T00:00:00Z'
                $null = Set-CredentialIntegrationTarget -Context $context `
                    -Target $firstTarget -Password $script:passwordOne
                $firstEnvelope = [byte[]](Invoke-HHSqliteScalar `
                        -Connection $context.Connection `
                        -Sql 'SELECT password_envelope FROM target_credentials WHERE name_key=''ALPHA'';')
                [Text.Encoding]::UTF8.GetString($firstEnvelope) |
                    Should -Not -Match 'first-plaintext-fixture-81d9'

                $secondTarget = New-CredentialIntegrationTarget `
                    -ValidatedAt '2026-08-27T00:01:00Z'
                $null = Set-CredentialIntegrationTarget -Context $context `
                    -Target $secondTarget -Password $script:passwordTwo
                $secondEnvelope = [byte[]](Invoke-HHSqliteScalar `
                        -Connection $context.Connection `
                        -Sql 'SELECT password_envelope FROM target_credentials WHERE name_key=''ALPHA'';')
                (Test-HHPersistenceBytesEqual -Left $firstEnvelope -Right $secondEnvelope) |
                    Should -BeFalse
                $restored = Get-HHTargetCredential -Connection $context.Connection `
                    -MasterKey $context.MasterKey -Target $secondTarget
                try {
                    [Text.Encoding]::UTF8.GetString($restored) |
                        Should -BeExactly 'replacement-plaintext-fixture-47ac'
                }
                finally { [Array]::Clear($restored, 0, $restored.Length) }

                $null = Invoke-HHAnchoredPersistenceTransaction -Context $context `
                    -ArgumentList @([string[]]@('alpha')) -Action {
                    param($Connection, $Transaction, $WriterContext, $ArgumentList)
                    Remove-HHTargetRepository -Connection $Connection -Transaction $Transaction `
                        -MasterKey $WriterContext.MasterKey `
                        -Name ([string[]]$ArgumentList[0]) `
                        -MutationId ([Guid]::NewGuid().ToByteArray()) `
                        -RequestedAtUtc ([DateTimeOffset]::UtcNow) `
                        -ExpectedAnchor $WriterContext.Anchor
                }
                (Invoke-HHSqliteScalar -Connection $context.Connection `
                        -Sql 'SELECT COUNT(*) FROM target_credentials;') | Should -Be 0
                (Invoke-HHSqliteScalar -Connection $context.Connection `
                        -Sql 'PRAGMA integrity_check;') | Should -BeExactly ok
            }
            finally { Close-HHAuthenticatedPersistence -Context $context }

            foreach ($file in @(Get-ChildItem -LiteralPath $script:root -File -Recurse)) {
                $text = [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($file.FullName))
                $text | Should -Not -Match 'first-plaintext-fixture-81d9'
                $text | Should -Not -Match 'replacement-plaintext-fixture-47ac'
            }
            [Environment]::CommandLine | Should -Not -Match 'plaintext-fixture'
            ([string]::Join("`n", @(
                        [Environment]::GetEnvironmentVariables().Values
                    ))) | Should -Not -Match 'plaintext-fixture'
        }
    }
}
