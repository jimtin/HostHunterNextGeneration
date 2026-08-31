$sourceRoot = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
    Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration'
}
else { $env:HH_TEST_SOURCE_ROOT }
Import-Module (Join-Path $sourceRoot 'HostHunterNextGeneration.psd1') -Force

Describe 'CIM Windows Security-event normalization' -Tag Unit {
    InModuleScope HostHunterNextGeneration {
        BeforeEach {
            $script:cimContext = [pscustomobject]@{
                MissionId = [Guid]'77777777-7777-4777-8777-777777777777'
                EventId = [Guid]'30000000-0000-4000-8000-000000000001'
                EndpointId = 'hh_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                HostName = 'LAB-WS01'
                AgentId = [Guid]'88888888-8888-4888-8888-888888888888'
                AgentVersion = '0.7.0'
                CollectedAtUtc = [DateTimeOffset]'2026-08-29T05:00:02Z'
            }
        }

        It 'normalizes 4688 v0 without fabricating newer-version fields' {
            $record = ConvertTo-HHSecurityEventRecord -Context $script:cimContext -InputObject (
                [pscustomobject]@{
                    EventId = 4688
                    Version = 0
                    RecordId = 2812L
                    TimeCreated = [DateTimeOffset]'2026-08-29T04:10:00Z'
                    Computer = 'LAB-WS01'
                    Data = [ordered]@{
                        SubjectUserSid = 'S-1-5-18'
                        SubjectUserName = 'SYSTEM'
                        SubjectDomainName = 'NT AUTHORITY'
                        SubjectLogonId = '0x3e7'
                        NewProcessId = '0x280'
                        NewProcessName = 'C:\Windows\System32\cmd.exe'
                        TokenElevationType = '%%1936'
                        ProcessId = '0x200'
                        CommandLine = 'must-not-be-fabricated-for-v0'
                        ParentProcessName = 'C:\Windows\explorer.exe'
                        MandatoryLabel = 'S-1-16-8192'
                    }
                }
            )

            $record.hosthunter.schema.name | Should -BeExactly 'process.start'
            $record.hosthunter.source.event_version | Should -Be 0
            $record.hosthunter.source.record_id | Should -BeExactly '2812'
            $record.process.pid | Should -Be 640
            $record.process.parent.pid | Should -Be 512
            $record.process.name | Should -BeExactly 'cmd.exe'
            $record.user.logon_id | Should -BeExactly '999'
            $record.process.PSObject.Properties['command_line'] | Should -BeNullOrEmpty
            $record.process.PSObject.Properties['integrity_level'] | Should -BeNullOrEmpty
            $record.process.parent.PSObject.Properties['executable'] | Should -BeNullOrEmpty
            $record.hosthunter.PSObject.Properties['process'] | Should -BeNullOrEmpty
        }

        It 'preserves a collected 4688 v1 command line exactly as sensitive evidence' {
            $canary = 'pwsh.exe -Password ''HH_SECRET_CANARY_7&< >'' --token=a=b=c'
            $record = ConvertTo-HHSecurityEventRecord -Context $script:cimContext -InputObject (
                [pscustomobject]@{
                    EventId = 4688
                    Version = 1
                    RecordId = 2813L
                    TimeCreated = [DateTimeOffset]'2026-08-29T04:11:00Z'
                    Computer = 'LAB-WS01'
                    Data = [ordered]@{
                        SubjectUserSid = 'S-1-5-21-1000'
                        SubjectUserName = 'analyst'
                        SubjectDomainName = 'LAB'
                        SubjectLogonId = '0x4a5af0'
                        NewProcessId = '0x2a8'
                        NewProcessName = 'C:\Program Files\PowerShell\7\pwsh.exe'
                        TokenElevationType = '%%1938'
                        ProcessId = '0x280'
                        CommandLine = $canary
                    }
                }
            )

            $record.process.command_line | Should -BeExactly $canary
            ($record | ConvertTo-Json -Depth 20 -Compress) | Should -Match (
                [regex]::Escape('HH_SECRET_CANARY_7&< >')
            )
            $record.process.PSObject.Properties['integrity_level'] | Should -BeNullOrEmpty
            $record.hosthunter.source.event_version | Should -Be 1
        }

        It 'normalizes every declared 4688 v2 identity and process field' {
            $record = ConvertTo-HHSecurityEventRecord -Context $script:cimContext -InputObject (
                [pscustomobject]@{
                    EventId = 4688
                    Version = 2
                    RecordId = 2814L
                    TimeCreated = [DateTimeOffset]'2026-08-29T04:12:31.427Z'
                    Computer = 'LAB-WS01.lab.example'
                    Data = [ordered]@{
                        SubjectUserSid = 'S-1-5-18'
                        SubjectUserName = 'SYSTEM'
                        SubjectDomainName = 'NT AUTHORITY'
                        SubjectLogonId = '0x3e7'
                        NewProcessId = '0x2bc'
                        NewProcessName = 'C:\Windows\System32\rundll32.exe'
                        TokenElevationType = '%%1938'
                        ProcessId = '0xe74'
                        CommandLine = 'rundll32.exe example.dll,EntryPoint'
                        TargetUserSid = 'S-1-5-21-1000'
                        TargetUserName = 'analyst'
                        TargetDomainName = 'LAB'
                        TargetLogonId = '0x4a5af0'
                        ParentProcessName = 'C:\Windows\explorer.exe'
                        MandatoryLabel = 'S-1-16-8192'
                    }
                }
            )

            $record.process.pid | Should -Be 700
            $record.process.parent.pid | Should -Be 3700
            $record.process.parent.name | Should -BeExactly 'explorer.exe'
            $record.process.integrity_level | Should -BeExactly 'medium'
            $record.process.command_line | Should -BeExactly 'rundll32.exe example.dll,EntryPoint'
            $record.hosthunter.process.target_user.id | Should -BeExactly 'S-1-5-21-1000'
            $record.hosthunter.process.target_user.logon_id | Should -BeExactly '4872944'
        }

        It 'normalizes 4689 v0 without inventing outcome or process correlation' {
            $record = ConvertTo-HHSecurityEventRecord -Context $script:cimContext -InputObject (
                [pscustomobject]@{
                    EventId = 4689
                    Version = 0
                    RecordId = 2815L
                    TimeCreated = [DateTimeOffset]'2026-08-29T04:13:05.125Z'
                    Computer = 'LAB-WS01.lab.example'
                    Data = [ordered]@{
                        SubjectUserSid = 'S-1-5-18'
                        SubjectUserName = 'SYSTEM'
                        SubjectDomainName = 'NT AUTHORITY'
                        SubjectLogonId = '0x3e7'
                        ProcessId = '0x2bc'
                        ProcessName = 'C:\Windows\System32\rundll32.exe'
                        Status = '0xC0000005'
                    }
                }
            )

            $record.hosthunter.schema.name | Should -BeExactly 'process.end'
            $record.hosthunter.source.event_code | Should -BeExactly '4689'
            $record.process.pid | Should -Be 700
            $record.process.name | Should -BeExactly 'rundll32.exe'
            $record.process.executable | Should -BeExactly 'C:\Windows\System32\rundll32.exe'
            $record.process.end | Should -BeExactly $record.'@timestamp'
            $record.process.exit_code | Should -Be 3221225477
            $record.user.logon_id | Should -BeExactly '999'
            $record.process.PSObject.Properties['entity_id'] | Should -BeNullOrEmpty
            $record.event.PSObject.Properties['outcome'] | Should -BeNullOrEmpty
        }

        It 'builds a bounded Security XPath that resumes strictly after the saved record' {
            $filter = New-HHWindowsSecurityEventFilterXPath -EventId 4689 `
                -Since ([DateTimeOffset]'2026-08-29T04:13:05.125Z') `
                -Until ([DateTimeOffset]'2026-08-29T05:13:05.125Z') `
                -AfterRecordId 2815

            $filter | Should -Match 'EventID=4689'
            $filter | Should -Match 'EventRecordID>2815'
            $filter | Should -Match "SystemTime>='2026-08-29T04:13:05.125Z'"
            $filter | Should -Match "SystemTime<='2026-08-29T05:13:05.125Z'"
        }

        It 'applies the distinct authentication semantics for each supported event code' -TestCases @(
            @{ Code = 4624; Name = 'authentication.session.start'; Outcome = 'success'; Type = 'start' }
            @{ Code = 4625; Name = 'authentication.logon.failure'; Outcome = 'failure'; Type = 'start' }
            @{ Code = 4634; Name = 'authentication.session.end'; Outcome = 'success'; Type = 'end' }
            @{ Code = 4647; Name = 'authentication.session.logoff-initiated'; Outcome = $null; Type = 'info' }
            @{ Code = 4648; Name = 'authentication.explicit-credential-use'; Outcome = 'unknown'; Type = 'start' }
            @{ Code = 4672; Name = 'authentication.session.special-privileges'; Outcome = $null; Type = 'info' }
        ) {
            param($Code, $Name, $Outcome, $Type)

            $data = [ordered]@{
                SubjectUserSid = 'S-1-5-18'
                SubjectUserName = 'SYSTEM'
                SubjectDomainName = 'NT AUTHORITY'
                SubjectLogonId = '0x3e7'
                TargetUserSid = 'S-1-5-21-1000'
                TargetUserName = 'alice'
                TargetDomainName = 'LAB'
                TargetLogonId = '0x4a5b00'
                LogonType = '10'
                ProcessId = '0x388'
                ProcessName = 'C:\Windows\System32\svchost.exe'
                Status = '0xC000006D'
                SubStatus = '0xC000006A'
                PrivilegeList = 'SeDebugPrivilege SeBackupPrivilege SeDebugPrivilege'
                TargetServerName = 'server.example.test'
            }
            $record = ConvertTo-HHSecurityEventRecord -Context $script:cimContext -InputObject (
                [pscustomobject]@{
                    EventId = $Code
                    Version = if ($Code -eq 4624) { 2 } else { 0 }
                    RecordId = [long](4000 + $Code)
                    TimeCreated = [DateTimeOffset]'2026-08-29T05:02:00Z'
                    Computer = 'LAB-WS01'
                    Data = $data
                }
            )

            $record.hosthunter.schema.name | Should -BeExactly $Name
            @($record.event.type) | Should -Contain $Type
            if ($null -eq $Outcome) {
                $record.event.PSObject.Properties['outcome'] | Should -BeNullOrEmpty
            }
            else {
                $record.event.outcome | Should -BeExactly $Outcome
            }
        }

        It 'decodes failure codes and deduplicates 4672 privileges without treating them as token state' {
            $failed = ConvertTo-HHSecurityEventRecord -Context $script:cimContext -InputObject (
                [pscustomobject]@{
                    EventId = 4625; Version = 0; RecordId = 4200L
                    TimeCreated = [DateTimeOffset]'2026-08-29T05:03:00Z'; Computer = 'LAB-WS01'
                    Data = [ordered]@{
                        SubjectUserSid = 'S-1-5-18'; SubjectLogonId = '0x3e7'
                        TargetUserName = 'alice'; TargetDomainName = 'LAB'; LogonType = '3'
                        Status = '0xC000006D'; SubStatus = '0xC000006A'
                    }
                }
            )
            $failed.hosthunter.failure.status_code | Should -Be 3221225581
            $failed.hosthunter.failure.sub_status_code | Should -Be 3221225578

            $privileged = ConvertTo-HHSecurityEventRecord -Context $script:cimContext -InputObject (
                [pscustomobject]@{
                    EventId = 4672; Version = 0; RecordId = 4201L
                    TimeCreated = [DateTimeOffset]'2026-08-29T05:04:00Z'; Computer = 'LAB-WS01'
                    Data = [ordered]@{
                        SubjectUserSid = 'S-1-5-18'; SubjectUserName = 'SYSTEM'
                        SubjectDomainName = 'NT AUTHORITY'; SubjectLogonId = '0x3e7'
                        PrivilegeList = 'SeDebugPrivilege SeBackupPrivilege SeDebugPrivilege'
                    }
                }
            )
            @($privileged.hosthunter.privileges) | Should -Be @(
                'SeDebugPrivilege', 'SeBackupPrivilege'
            )
            $privileged.hosthunter.PSObject.Properties['process_token'] |
                Should -BeNullOrEmpty
        }

        It 'rejects unsupported source versions and malformed unsigned native values' {
            $base = [pscustomobject]@{
                EventId = 4688; Version = 3; RecordId = 1L
                TimeCreated = [DateTimeOffset]'2026-08-29T05:00:00Z'; Computer = 'LAB-WS01'
                Data = [ordered]@{ NewProcessId = '0x100'; NewProcessName = 'C:\x.exe' }
            }
            { ConvertTo-HHSecurityEventRecord -Context $script:cimContext -InputObject $base } |
                Should -Throw '*version*'

            $base.Version = 2
            $base.Data.NewProcessId = '-1'
            { ConvertTo-HHSecurityEventRecord -Context $script:cimContext -InputObject $base } |
                Should -Throw '*process*'
        }
    }
}
