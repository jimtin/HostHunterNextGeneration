$sourceRoot = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
    Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration'
}
else { $env:HH_TEST_SOURCE_ROOT }
Import-Module (Join-Path $sourceRoot 'HostHunterNextGeneration.psd1') -Force

Describe 'controller-generated CIM schema validation' -Tag Unit {
    It 'accepts canonical process end, permits unmatched PID evidence, and rejects semantic drift' {
        InModuleScope HostHunterNextGeneration {
            Initialize-HHSqliteProvider -ProviderRoot '/opt/hosthunter-sqlite/lib'
            $examplePath = Join-Path (Get-Location) `
                'CIM_Specification/examples/process-end-4689-v0.v1.json'
            $canonical = [IO.File]::ReadAllBytes($examplePath)
            { Assert-HHForensicPayloadSchema -PayloadBytes $canonical } |
                Should -Not -Throw
            $record = Get-Content -LiteralPath $examplePath -Raw |
                ConvertFrom-Json -Depth 30
            (New-HHForensicEventIdentity `
                    -EndpointId $record.host.id `
                    -Provider $record.hosthunter.source.provider `
                    -Channel $record.hosthunter.source.channel `
                    -EventCode $record.hosthunter.source.event_code `
                    -EventVersion $record.hosthunter.source.event_version `
                    -RecordId $record.hosthunter.source.record_id `
                    -Timestamp ([DateTimeOffset]$record.'@timestamp')).ToString('D') |
                Should -BeExactly $record.event.id

            $withoutIdentity = [Text.UTF8Encoding]::new($false).GetBytes((
                    $record | ForEach-Object {
                        $_.process.PSObject.Properties.Remove('entity_id')
                        $_
                    } | ConvertTo-Json -Compress -Depth 30
                ))
            { Assert-HHForensicPayloadSchema -PayloadBytes $withoutIdentity } |
                Should -Not -Throw

            $wrongEnd = Get-Content -LiteralPath $examplePath -Raw |
                ConvertFrom-Json -Depth 30
            $wrongEnd.process.end = '2026-08-29T04:13:05.126Z'
            $wrongBytes = [Text.UTF8Encoding]::new($false).GetBytes(
                ($wrongEnd | ConvertTo-Json -Compress -Depth 30)
            )
            { Assert-HHForensicPayloadSchema -PayloadBytes $wrongBytes } |
                Should -Throw '*process.end must equal @timestamp*'
        }
    }

    It 'validates every generated event family before persistence' {
        InModuleScope HostHunterNextGeneration {
            Initialize-HHSqliteProvider -ProviderRoot '/opt/hosthunter-sqlite/lib'
            $baseContext = [pscustomobject]@{
                MissionId=[Guid]'77777777-7777-4777-8777-777777777777'
                EventId=[Guid]'30000000-0000-4000-8000-000000000001'
                EndpointId='hh_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                HostName='LAB-WS01'
                AgentId=[Guid]'88888888-8888-4888-8888-888888888888'
                AgentVersion='0.7.0'
                CollectedAtUtc=[DateTimeOffset]'2026-08-29T05:02:02Z'
            }
            $data = [ordered]@{
                SubjectUserSid='S-1-5-18'
                SubjectUserName='SYSTEM'
                SubjectDomainName='NT AUTHORITY'
                SubjectLogonId='0x3e7'
                TargetUserSid='S-1-5-21-1000'
                TargetUserName='alice'
                TargetDomainName='LAB'
                TargetLogonId='0x4a5b00'
                LogonType='10'
                LogonProcessName='User32'
                AuthenticationPackageName='Negotiate'
                KeyLength='0'
                ProcessId='0x388'
                ProcessName='C:\Windows\System32\svchost.exe'
                NewProcessId='0x2bc'
                NewProcessName='C:\Windows\System32\cmd.exe'
                TokenElevationType='%%1938'
                CommandLine='cmd.exe /c whoami'
                Status='0xC000006D'
                SubStatus='0xC000006A'
                PrivilegeList='SeDebugPrivilege SeBackupPrivilege'
                TargetServerName='server.example.test'
            }
            $outputs = [Collections.Generic.List[object]]::new()
            foreach($code in @(4688,4689,4624,4625,4634,4647,4648,4672)){
                $version=if($code -in @(4688,4624)){2}else{0}
                $outputs.Add((ConvertTo-HHSecurityEventRecord `
                            -Context $baseContext `
                            -InputObject ([pscustomobject]@{
                                EventId=$code
                                Version=$version
                                RecordId=[long](5000+$code)
                                TimeCreated=[DateTimeOffset]'2026-08-29T05:02:00Z'
                                Computer='LAB-WS01'
                                Data=$data
                            })))
            }
            $outputs.Add((ConvertTo-HHProcessTokenRecord `
                        -Context $baseContext `
                        -InputObject ([pscustomobject]@{
                            Status='complete'
                            ObservedAtUtc='2026-08-29T05:32:00Z'
                            ProcessId=3020
                            ProcessName='pwsh.exe'
                            ProcessPath='C:\Program Files\PowerShell\7\pwsh.exe'
                            ProcessStartBeforeUtc='2026-08-29T05:29:50Z'
                            ProcessStartAfterUtc='2026-08-29T05:29:50Z'
                            UserSid='S-1-5-21-1000'
                            UserName='alice'
                            UserDomain='LAB'
                            TokenId='1'
                            AuthenticationId='2'
                            ModifiedId='3'
                            Privileges=@([pscustomobject]@{
                                    Name='SeDebugPrivilege'
                                    Enabled=$false
                                    EnabledByDefault=$false
                                    Removed=$false
                                    UsedForAccess=$false
                                })
                            Issues=@()
                        })))
            $outputs.Add((ConvertTo-HHProcessTokenRecord `
                        -Context $baseContext `
                        -InputObject ([pscustomobject]@{
                            Status='unavailable'
                            ObservedAtUtc='2026-08-29T05:32:00Z'
                            ProcessId=4
                            ProcessName='System'
                            ProcessStartBeforeUtc='2026-08-29T04:00:00Z'
                            ProcessStartAfterUtc='2026-08-29T04:00:00Z'
                            Issues=@([pscustomobject]@{
                                    Code='access_denied'
                                    Message='Token query was denied.'
                                })
                        })))
            $user = [pscustomobject]@{
                Id='S-1-5-21-1000';Name='alice';Domain='LAB';Type='user'
            }
            $outputs.Add((Resolve-HHEffectiveRightsRecord `
                        -Context $baseContext `
                        -InputObject ([pscustomobject]@{
                            Status='complete'
                            ObservedAtUtc='2026-08-29T05:40:00Z'
                            User=$user
                            MembershipResolution='complete'
                            AssignmentResolution='complete'
                            PolicySourceResolution='not_collected'
                            Issues=@()
                            Assignments=@([pscustomobject]@{
                                    Name='SeDebugPrivilege'
                                    AssignedTo=$user
                                    MembershipPath=@($user)
                                })
                        })))
            $outputs.Add((Resolve-HHEffectiveRightsRecord `
                        -Context $baseContext `
                        -InputObject ([pscustomobject]@{
                            Status='failed'
                            ObservedAtUtc='2026-08-29T05:40:00Z'
                            User=[pscustomobject]@{Name='missing-user';Domain='LAB'}
                            MembershipResolution='failed'
                            AssignmentResolution='failed'
                            PolicySourceResolution='not_collected'
                            Issues=@([pscustomobject]@{
                                    Code='identity_resolution_failed'
                                    Message='Identity was not resolved.'
                                })
                        })))
            foreach($output in $outputs){
                $bytes=[Text.UTF8Encoding]::new($false).GetBytes(
                    ($output|ConvertTo-Json -Compress -Depth 30)
                )
                {Assert-HHForensicPayloadSchema -PayloadBytes $bytes} |
                    Should -Not -Throw
            }
            $outputs.Count|Should -Be 12
        }
    }
}
