$sourceRoot = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
    Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration'
}
else { $env:HH_TEST_SOURCE_ROOT }
Import-Module (Join-Path $sourceRoot 'HostHunterNextGeneration.psd1') -Force

Describe 'native client interaction' -Tag Unit {
    InModuleScope HostHunterNextGeneration {
        BeforeEach {
            $script:previousInteractionEnvironment = @{}
            foreach ($name in @(
                    'HH_CLIENT_CONFIRM_PATH', 'HH_CLIENT_CREDENTIAL_PATH',
                    'HH_CLIENT_BROKER_PORT', 'HH_CLIENT_BROKER_TOKEN'
                )) {
                $script:previousInteractionEnvironment[$name] =
                    [Environment]::GetEnvironmentVariable($name, 'Process')
            }
            $script:helper = Join-Path $TestDrive 'client-confirm.sh'
            [IO.File]::WriteAllText($script:helper, '# fixture')
            $env:HH_CLIENT_CONFIRM_PATH = $script:helper
            $env:HH_CLIENT_CREDENTIAL_PATH = $script:helper
            $env:HH_CLIENT_BROKER_PORT = '12345'
            $env:HH_CLIENT_BROKER_TOKEN = 'fixture-token'
        }

        AfterEach {
            foreach ($entry in $script:previousInteractionEnvironment.GetEnumerator()) {
                [Environment]::SetEnvironmentVariable($entry.Key, $entry.Value, 'Process')
            }
        }

        It 'returns exact bounded yes and no responses from the helper' {
            Mock Invoke-HHNativeProcess {
                [pscustomobject]@{ ExitCode = 0; StandardOutput = 'yes'; StandardError = '' }
            }
            Request-HHClientConfirmation -Prompt 'Trust fixture?' | Should -BeTrue

            Mock Invoke-HHNativeProcess {
                [pscustomobject]@{ ExitCode = 0; StandardOutput = 'no'; StandardError = '' }
            }
            Request-HHClientConfirmation -Prompt 'Trust fixture?' | Should -BeFalse
            Should -Invoke Invoke-HHNativeProcess -Times 2 -ParameterFilter {
                $FileName -ceq $script:helper -and $TimeoutSeconds -eq 125 -and
                $ArgumentList.Count -eq 1
            }
        }

        It 'fails closed without the native interaction broker' {
            Mock Invoke-HHNativeProcess { throw 'must not run' }
            Remove-Item Env:HH_CLIENT_BROKER_TOKEN
            { Request-HHClientConfirmation -Prompt 'Trust fixture?' } |
                Should -Throw '*Interactive confirmation requires the HostHunter native client*'
            Should -Not -Invoke Invoke-HHNativeProcess
        }

        It 'rejects helper failure and invalid output' {
            Mock Invoke-HHNativeProcess {
                [pscustomobject]@{ ExitCode = 1; StandardOutput = ''; StandardError = 'broker ended' }
            }
            { Request-HHClientConfirmation -Prompt 'Trust fixture?' } |
                Should -Throw '*confirmation failed*broker ended*'

            Mock Invoke-HHNativeProcess {
                [pscustomobject]@{ ExitCode = 0; StandardOutput = 'maybe'; StandardError = '' }
            }
            { Request-HHClientConfirmation -Prompt 'Trust fixture?' } |
                Should -Throw '*invalid confirmation response*'
        }

        It 'acquires and seeds bounded credentials without putting a password in arguments' {
            $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('fixture-secret'))
            Mock Invoke-HHNativeProcess {
                param($ArgumentList)
                if ($ArgumentList[0] -ceq 'acquire') {
                    return [pscustomobject]@{
                        ExitCode = 0; StandardOutput = $encoded; StandardError = ''
                    }
                }
                [pscustomobject]@{ ExitCode = 0; StandardOutput = 'ok'; StandardError = '' }
            }
            $bytes = Get-HHClientCredentialBytes -Prompt 'Password?'
            try {
                [Text.Encoding]::UTF8.GetString($bytes) | Should -BeExactly 'fixture-secret'
                Set-HHClientCredentialBytes -PasswordBytes $bytes
            }
            finally { [Array]::Clear($bytes, 0, $bytes.Length) }
            Should -Invoke Invoke-HHNativeProcess -Times 1 -ParameterFilter {
                $ArgumentList[0] -ceq 'seed' -and $ArgumentList.Count -eq 1 -and
                $null -ne $StandardInputBytes -and
                ([Text.Encoding]::ASCII.GetString($StandardInputBytes) -notmatch 'fixture-secret')
            }
        }

        It 'uses key-first and password-risk prompts with safe defaults' {
            Mock Request-HHClientConfirmation { $true }
            Request-HHSshKeyOnboardingChoice -TargetLabel alpha | Should -BeTrue
            Request-HHPasswordStorageConsent -TargetLabel alpha | Should -BeTrue
            Should -Invoke Request-HHClientConfirmation -Times 1 -ParameterFilter {
                $Prompt -match 'recommends SSH key' -and $Prompt -match '\[Y/n\]'
            }
            Should -Invoke Request-HHClientConfirmation -Times 1 -ParameterFilter {
                $Prompt -match 'WARNING' -and $Prompt -match 'macOS account' -and
                $Prompt -match 'Docker runtime' -and $Prompt -match '\[y/N\]'
            }
        }
    }
}
