$sourceRoot = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
    Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration'
}
else { $env:HH_TEST_SOURCE_ROOT }
Import-Module (Join-Path $sourceRoot 'HostHunterNextGeneration.psd1') -Force

Describe 'CIM process selection and primary-token normalization' -Tag Unit {
    InModuleScope HostHunterNextGeneration {
        BeforeEach {
            $script:processes = @(
                [pscustomobject]@{
                    Id=101;Name='pwsh';Path='C:\Program Files\PowerShell\7\pwsh.exe'
                    StartTimeUtc='2026-08-29T05:00:00Z'
                }
                [pscustomobject]@{
                    Id=102;Name='PWSH.EXE';Path='C:\Tools\pwsh.exe'
                    StartTimeUtc='2026-08-29T05:01:00Z'
                }
                [pscustomobject]@{
                    Id=103;Name='powershell'
                    Path='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
                    StartTimeUtc='2026-08-29T05:02:00Z'
                }
            )
            $script:cimContext = [pscustomobject]@{
                MissionId = [Guid]'77777777-7777-4777-8777-777777777777'
                EventId = [Guid]'30000000-0000-4000-8000-000000000009'
                EndpointId = 'hh_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                HostName = 'LAB-WS01'
                AgentId = [Guid]'88888888-8888-4888-8888-888888888888'
                AgentVersion = '0.7.0'
                CollectedAtUtc = [DateTimeOffset]'2026-08-29T05:32:01Z'
            }
        }

        It 'selects one process by PID' {
            $result = Resolve-HHProcessSelection -Processes $script:processes -ProcessId 103
            $result.Status | Should -BeExactly complete
            @($result.Processes).Count | Should -Be 1
            $result.Processes[0].Id | Should -Be 103
        }

        It 'matches an exact process basename case-insensitively with an optional exe suffix' {
            $withSuffix = Resolve-HHProcessSelection -Processes $script:processes `
                -ProcessName 'PwSh.ExE'
            $withoutSuffix = Resolve-HHProcessSelection -Processes $script:processes `
                -ProcessName 'pwsh'

            $withSuffix.Status | Should -BeExactly complete
            @($withSuffix.Processes.Id | Sort-Object) | Should -Be @(101, 102)
            @($withoutSuffix.Processes.Id | Sort-Object) | Should -Be @(101, 102)
            @($withSuffix.Processes.Id) | Should -Not -Contain 103
        }

        It 'rejects wildcard and path-like process names instead of broadening selection' -TestCases @(
            @{ ProcessNameCase = 'pw*' }
            @{ ProcessNameCase = 'pwsh?.exe' }
            @{ ProcessNameCase = 'C:\Tools\pwsh.exe' }
        ) {
            param($ProcessNameCase)
            $invalidSelection = $ProcessNameCase
            { Resolve-HHProcessSelection -Processes $script:processes -ProcessName $invalidSelection } |
                Should -Throw '*process name*'
        }

        It 'returns a finite unavailable result when no process matches' {
            $result = Resolve-HHProcessSelection -Processes $script:processes `
                -ProcessName 'notepad.exe'
            $result.Status | Should -BeExactly unavailable
            @($result.Processes).Count | Should -Be 0
            @($result.Issues).Count | Should -Be 1
        }

        It 'fails closed when exact-name selection exceeds the 64-process bound' {
            $many = 1..65 | ForEach-Object {
                [pscustomobject]@{ Id = $_; Name = 'pwsh'; Path = 'C:\pwsh.exe' }
            }
            $result = Resolve-HHProcessSelection -Processes $many -ProcessName pwsh.exe
            $result.Status | Should -BeExactly failed
            $result.FailureKind | Should -BeExactly TooManyMatches
            @($result.Processes).Count | Should -Be 0
        }

        It 'builds complete primary-token evidence and deduplicates privilege names' {
            $record = ConvertTo-HHProcessTokenRecord -Context $script:cimContext -InputObject (
                [pscustomobject]@{
                    Status = 'complete'
                    ObservedAtUtc = '2026-08-29T05:32:00Z'
                    ProcessId = 3020
                    ProcessName = 'runas.exe'
                    ProcessPath = 'C:\Windows\System32\runas.exe'
                    ProcessStartBeforeUtc = '2026-08-29T05:29:50Z'
                    ProcessStartAfterUtc = '2026-08-29T05:29:50Z'
                    UserSid = 'S-1-5-21-1000-1000-1000-1101'
                    UserName = 'alice'
                    UserDomain = 'LAB'
                    TokenId = '112233445566'
                    AuthenticationId = '0x4a5b00'
                    ModifiedId = '112233445570'
                    Privileges = @(
                        [pscustomobject]@{ Name='SeChangeNotifyPrivilege'; Enabled=$true; EnabledByDefault=$true; Removed=$false; UsedForAccess=$true }
                        [pscustomobject]@{ Name='SeDebugPrivilege'; Enabled=$false; EnabledByDefault=$false; Removed=$false; UsedForAccess=$false }
                        [pscustomobject]@{ Name='SeDebugPrivilege'; Enabled=$false; EnabledByDefault=$false; Removed=$false; UsedForAccess=$false }
                    )
                    Issues = @()
                }
            )

            $record.event.kind | Should -BeExactly state
            $record.hosthunter.schema.name | Should -BeExactly 'process.access-token'
            $record.hosthunter.process_token.observation.status | Should -BeExactly complete
            $record.process.pid | Should -Be 3020
            $record.process.entity_id | Should -Not -BeNullOrEmpty
            $record.process.start | Should -BeExactly '2026-08-29T05:29:50.000Z'
            $record.hosthunter.process_token.token.authentication_id | Should -BeExactly '4872960'
            @($record.hosthunter.process_token.privileges).Count | Should -Be 2
        }

        It 'downgrades a PID-reuse race and refuses to bind token state to the replacement process' {
            $record = ConvertTo-HHProcessTokenRecord -Context $script:cimContext -InputObject (
                [pscustomobject]@{
                    Status = 'complete'; ObservedAtUtc = '2026-08-29T05:32:00Z'
                    ProcessId = 3020; ProcessName = 'pwsh.exe'
                    ProcessStartBeforeUtc = '2026-08-29T05:29:50Z'
                    ProcessStartAfterUtc = '2026-08-29T05:31:59Z'
                    UserSid = 'S-1-5-18'; Privileges = @(); Issues = @()
                }
            )
            $record.hosthunter.process_token.observation.status | Should -BeExactly partial
            @($record.hosthunter.process_token.observation.issues.code) |
                Should -Contain process_instance_changed
            $record.process.PSObject.Properties['entity_id'] | Should -BeNullOrEmpty
        }

        It 'represents access denied as unavailable without inventing an empty token' {
            $record = ConvertTo-HHProcessTokenRecord -Context $script:cimContext -InputObject (
                [pscustomobject]@{
                    Status = 'unavailable'; ObservedAtUtc = '2026-08-29T05:32:00Z'
                    ProcessId = 4; ProcessName = 'System'
                    ProcessStartBeforeUtc = '2026-08-29T04:00:00Z'
                    ProcessStartAfterUtc = '2026-08-29T04:00:00Z'
                    Issues = @([pscustomobject]@{ Code='access_denied'; Message='Token query was denied.' })
                }
            )
            $record.hosthunter.process_token.observation.status | Should -BeExactly unavailable
            @($record.hosthunter.process_token.observation.issues.code) |
                Should -Contain access_denied
            $record.hosthunter.process_token.PSObject.Properties['token'] | Should -BeNullOrEmpty
            $record.hosthunter.process_token.PSObject.Properties['privileges'] |
                Should -BeNullOrEmpty
        }
    }
}
