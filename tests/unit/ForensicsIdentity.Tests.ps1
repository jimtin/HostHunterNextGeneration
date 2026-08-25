BeforeAll {
    $sourceRoot = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
        Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration'
    }
    else { $env:HH_TEST_SOURCE_ROOT }
    . (Join-Path $sourceRoot 'Forensics/Private/Identity/ForensicsIdentity.ps1')
}

Describe 'Forensics deterministic identities' -Tag Unit {
    It 'uses unambiguous four-byte big-endian UTF-8 length frames' {
        Get-HHForensicsLengthFramedSha256 -Value @('a', 'bc') |
            Should -BeExactly 'b534ce16ac9c8b36823f39a395ce8e0e3c7ad9605b82b5444f18cadacd217a5d'
        Get-HHForensicsLengthFramedSha256 -Value @('ab', 'c') |
            Should -BeExactly 'f2939f903016e5bb29b1e4a61cdbd376220ca03a24180b39995f2d50f2e0a647'
    }

    It 'canonicalizes null, timestamps, and invariant numeric values deterministically' {
        ConvertTo-HHForensicsCanonicalString -Value $null | Should -BeExactly ''
        ConvertTo-HHForensicsCanonicalString -Value ([uint64]256) | Should -BeExactly '256'
        ConvertTo-HHForensicsCanonicalString -Value ([datetime]'2026-08-25T00:00:00Z') |
            Should -Match '^2026-08-25T00:00:00\.0000000Z$'
        ConvertTo-HHForensicsCanonicalString -Value ([DateTimeOffset]'2026-08-25T10:00:00+10:00') |
            Should -Match '^2026-08-25T00:00:00\.0000000\+00:00$'
    }

    It 'makes Security 4688 process identity depend on stable evidence context' {
        $parameters = @{
            HostId = 'host-001'
            ProcessId = [uint64]256
            Timestamp = '2026-08-25T02:00:00.0000000Z'
            EventRecordId = '201'
        }
        $id = Get-HHForensicsSecurityProcessEntityId @parameters
        $id | Should -BeExactly '518f33c2650567dd30a66c120776deb984da927f6ec779993bbe71d84428aaa4'

        $changed = $parameters.Clone()
        $changed.EventRecordId = '202'
        Get-HHForensicsSecurityProcessEntityId @changed | Should -Not -BeExactly $id
    }

    It 'does not define a Security process identity from PID alone' {
        $one = Get-HHForensicsSecurityProcessEntityId -HostId host-a -ProcessId 42 `
            -Timestamp '2026-08-25T00:00:00Z' -EventRecordId 1
        $two = Get-HHForensicsSecurityProcessEntityId -HostId host-b -ProcessId 42 `
            -Timestamp '2026-08-25T00:00:00Z' -EventRecordId 1
        $one | Should -Not -BeExactly $two
    }

    It 'creates replay-stable event ids and distinguishes providers' {
        $parameters = @{
            HostId = 'host-001'
            Provider = 'Microsoft-Windows-Sysmon'
            Channel = 'Microsoft-Windows-Sysmon/Operational'
            EventCode = '1'
            EventRecordId = '101'
            Timestamp = '2026-08-25T01:02:03.1230000Z'
            SourceIdentity = ('b' * 64)
            SourceOrdinal = 1
        }
        $one = Get-HHForensicsEventId @parameters
        Get-HHForensicsEventId @parameters | Should -BeExactly $one
        $parameters.Provider = 'Microsoft-Windows-Security-Auditing'
        Get-HHForensicsEventId @parameters | Should -Not -BeExactly $one
        $parameters.Provider = 'Microsoft-Windows-Sysmon'
        $parameters.SourceOrdinal = 2
        Get-HHForensicsEventId @parameters | Should -Not -BeExactly $one
    }
}
