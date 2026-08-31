$sourceRoot = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
    Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration'
}
else { $env:HH_TEST_SOURCE_ROOT }
Import-Module (Join-Path $sourceRoot 'HostHunterNextGeneration.psd1') -Force

Describe 'CIM deterministic identity and exact-byte digest' -Tag Unit {
    InModuleScope HostHunterNextGeneration {
        It 'returns the same RFC 4122 identity for the same source record' {
            $parameters = @{
                EndpointId = 'hh_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                Provider = 'Microsoft-Windows-Security-Auditing'
                Channel = 'Security'
                EventCode = '4688'
                EventVersion = 2
                RecordId = '2814'
                Timestamp = [DateTimeOffset]'2026-08-29T04:12:31.427Z'
            }
            $one = New-HHForensicEventIdentity @parameters
            $two = New-HHForensicEventIdentity @parameters
            $one | Should -BeOfType ([Guid])
            $one | Should -Be $two
            $one.ToString('D') | Should -Match '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
        }

        It 'changes identity when any source identity component changes' {
            $common = @{
                EndpointId = 'hh_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                Provider = 'Microsoft-Windows-Security-Auditing'; Channel = 'Security'
                EventCode = '4688'; EventVersion = 2; RecordId = '2814'
                Timestamp = [DateTimeOffset]'2026-08-29T04:12:31.427Z'
            }
            $original = New-HHForensicEventIdentity @common
            foreach ($change in @(
                    @{ RecordId='2815' },
                    @{ EventCode='4624' },
                    @{ EventVersion=1 },
                    @{ Timestamp=[DateTimeOffset]'2026-08-29T04:12:31.428Z' },
                    @{ EndpointId='hh_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' }
                )) {
                $candidate = @{} + $common
                foreach ($key in $change.Keys) { $candidate[$key] = $change[$key] }
                (New-HHForensicEventIdentity @candidate) | Should -Not -Be $original
            }
        }

        It 'hashes exact UTF-8 payload bytes as lower-case SHA256' {
            $text = '{"process":{"command_line":"pwsh.exe --token=HH_SECRET_CANARY"}}'
            $bytes = [Text.UTF8Encoding]::new($false).GetBytes($text)
            $expected = [Convert]::ToHexString(
                [Security.Cryptography.SHA256]::HashData($bytes)
            ).ToLowerInvariant()
            $digest = Get-HHForensicPayloadDigest -PayloadBytes $bytes
            $digest | Should -BeExactly $expected
            $digest | Should -Match '^[a-f0-9]{64}$'
        }

        It 'does not normalize whitespace or sensitive command-line bytes before hashing' {
            $encoding = [Text.UTF8Encoding]::new($false)
            $one = $encoding.GetBytes('{"command_line":"pwsh.exe -Password secret"}')
            $two = $encoding.GetBytes('{ "command_line": "pwsh.exe -Password secret" }')
            $three = $encoding.GetBytes('{"command_line":"pwsh.exe -Password SECRET"}')

            (Get-HHForensicPayloadDigest -PayloadBytes $one) |
                Should -Not -BeExactly (Get-HHForensicPayloadDigest -PayloadBytes $two)
            (Get-HHForensicPayloadDigest -PayloadBytes $one) |
                Should -Not -BeExactly (Get-HHForensicPayloadDigest -PayloadBytes $three)
        }
    }
}
