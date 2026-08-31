$sourceRoot = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
    Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration'
}
else { $env:HH_TEST_SOURCE_ROOT }
Import-Module (Join-Path $sourceRoot 'HostHunterNextGeneration.psd1') -Force

Describe 'CIM effective-rights normalization' -Tag Unit {
    InModuleScope HostHunterNextGeneration {
        BeforeEach {
            $script:cimContext = [pscustomobject]@{
                MissionId = [Guid]'77777777-7777-4777-8777-777777777777'
                EventId = [Guid]'30000000-0000-4000-8000-000000000010'
                EndpointId = 'hh_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                HostName = 'LAB-WS01'
                AgentId = [Guid]'88888888-8888-4888-8888-888888888888'
                AgentVersion = '0.7.0'
                CollectedAtUtc = [DateTimeOffset]'2026-08-29T05:40:03Z'
            }
            $script:user = [pscustomobject]@{
                Id='S-1-5-21-1000-1000-1000-1101';Name='alice';Domain='LAB';Type='user'
            }
            $script:domainUsers = [pscustomobject]@{
                Id='S-1-5-21-1000-1000-1000-513';Name='Domain Users';Domain='LAB';Type='group'
            }
            $script:analysts = [pscustomobject]@{
                Id='S-1-5-21-1000-1000-1000-2100';Name='IR Analysts';Domain='LAB';Type='group'
            }
            $script:admins = [pscustomobject]@{
                Id='S-1-5-32-544';Name='Administrators';Domain='BUILTIN';Type='well_known_group'
            }
        }

        It 'retains every direct and nested membership origin with unknown attribution by default' {
            $record = Resolve-HHEffectiveRightsRecord -Context $script:cimContext -InputObject (
                [pscustomobject]@{
                    Status='complete';ObservedAtUtc='2026-08-29T05:40:00Z';User=$script:user
                    MembershipResolution='complete';AssignmentResolution='complete'
                    PolicySourceResolution='partial';Issues=@()
                    Assignments=@(
                        [pscustomobject]@{
                            Name='SeDebugPrivilege';AssignedTo=$script:admins
                            MembershipPath=@($script:user,$script:analysts,$script:admins)
                        },
                        [pscustomobject]@{
                            Name='SeDebugPrivilege';AssignedTo=$script:admins
                            MembershipPath=@($script:user,$script:domainUsers,$script:admins)
                        },
                        [pscustomobject]@{
                            Name='SeDenyNetworkLogonRight';AssignedTo=$script:user
                            MembershipPath=@($script:user)
                        }
                    )
                }
            )

            $record.hosthunter.schema.name | Should -BeExactly 'user.effective-rights'
            $right = @($record.hosthunter.user_rights.rights | Where-Object name -eq 'SeDebugPrivilege')[0]
            @($right.origins).Count | Should -Be 2
            @($right.origins[0].membership_path).Count | Should -Be 3
            $right.origins[0].membership_path[0].id | Should -BeExactly $script:user.Id
            $right.origins[0].membership_path[-1].id | Should -BeExactly $script:admins.Id
            @($right.origins.policy_source.attribution_status | Sort-Object -Unique) |
                Should -Be @('unknown')

            $direct = @($record.hosthunter.user_rights.rights |
                    Where-Object name -eq 'SeDenyNetworkLogonRight')[0].origins[0]
            $direct.relationship | Should -BeExactly direct
            $direct.PSObject.Properties['membership_path'] | Should -BeNullOrEmpty
        }

        It 'applies deny precedence to every paired logon right without suppressing origins' -TestCases @(
            @{ Allow='SeInteractiveLogonRight'; Deny='SeDenyInteractiveLogonRight' }
            @{ Allow='SeNetworkLogonRight'; Deny='SeDenyNetworkLogonRight' }
            @{ Allow='SeBatchLogonRight'; Deny='SeDenyBatchLogonRight' }
            @{ Allow='SeServiceLogonRight'; Deny='SeDenyServiceLogonRight' }
            @{ Allow='SeRemoteInteractiveLogonRight'; Deny='SeDenyRemoteInteractiveLogonRight' }
        ) {
            param($Allow,$Deny)
            $record = Resolve-HHEffectiveRightsRecord -Context $script:cimContext -InputObject (
                [pscustomobject]@{
                    Status='complete';ObservedAtUtc='2026-08-29T05:40:00Z';User=$script:user
                    MembershipResolution='complete';AssignmentResolution='complete'
                    PolicySourceResolution='partial';Issues=@()
                    Assignments=@(
                        [pscustomobject]@{
                            Name=$Allow;AssignedTo=$script:domainUsers
                            MembershipPath=@($script:user,$script:domainUsers)
                        },
                        [pscustomobject]@{
                            Name=$Deny;AssignedTo=$script:user;MembershipPath=@($script:user)
                        }
                    )
                }
            )
            $allowRight = @($record.hosthunter.user_rights.rights |
                    Where-Object name -eq $Allow)[0]
            $denyRight = @($record.hosthunter.user_rights.rights |
                    Where-Object name -eq $Deny)[0]
            $allowRight.state | Should -BeExactly overridden
            @($allowRight.overridden_by) | Should -Be @($Deny)
            @($allowRight.origins).Count | Should -Be 1
            $denyRight.state | Should -BeExactly effective
        }

        It 'preserves observed policy attribution only when supporting evidence is supplied' {
            $record = Resolve-HHEffectiveRightsRecord -Context $script:cimContext -InputObject (
                [pscustomobject]@{
                    Status='complete';ObservedAtUtc='2026-08-29T05:40:00Z';User=$script:user
                    MembershipResolution='complete';AssignmentResolution='complete'
                    PolicySourceResolution='complete';Issues=@()
                    Assignments=@([pscustomobject]@{
                            Name='SeBackupPrivilege';AssignedTo=$script:admins
                            MembershipPath=@($script:user,$script:admins)
                            PolicySource=[pscustomobject]@{
                                AttributionStatus='observed';Type='group_policy'
                                Id='{10000000-0000-4000-8000-000000000001}'
                                Name='Endpoint Admin Rights';Evidence='group_policy_result'
                            }
                        })
                }
            )
            $source = $record.hosthunter.user_rights.rights[0].origins[0].policy_source
            $source.attribution_status | Should -BeExactly observed
            $source.type | Should -BeExactly group_policy
            $source.evidence | Should -BeExactly group_policy_result
        }

        It 'returns truthful partial evidence when group membership cannot be completed' {
            $record = Resolve-HHEffectiveRightsRecord -Context $script:cimContext -InputObject (
                [pscustomobject]@{
                    Status='partial';ObservedAtUtc='2026-08-29T05:40:00Z';User=$script:user
                    MembershipResolution='partial';AssignmentResolution='complete'
                    PolicySourceResolution='partial'
                    Issues=@([pscustomobject]@{
                            Code='domain_membership_unavailable'
                            Message='The domain controller was unavailable.'
                        })
                    Assignments=@([pscustomobject]@{
                            Name='SeChangeNotifyPrivilege';AssignedTo=$script:user
                            MembershipPath=@($script:user)
                        })
                }
            )
            $record.hosthunter.user_rights.observation.status | Should -BeExactly partial
            $record.hosthunter.user_rights.evaluation.membership_resolution |
                Should -BeExactly partial
            @($record.hosthunter.user_rights.observation.issues.code) |
                Should -Contain domain_membership_unavailable
            @($record.hosthunter.user_rights.rights).Count | Should -Be 1
        }

        It 'represents unresolved identity as failed without fabricating a SID or empty rights' {
            $record = Resolve-HHEffectiveRightsRecord -Context $script:cimContext -InputObject (
                [pscustomobject]@{
                    Status='failed';ObservedAtUtc='2026-08-29T05:40:00Z'
                    User=[pscustomobject]@{ Name='missing-user';Domain='LAB' }
                    MembershipResolution='failed';AssignmentResolution='failed'
                    PolicySourceResolution='not_collected'
                    Issues=@([pscustomobject]@{
                            Code='identity_resolution_failed';Message='Identity was not resolved.'
                        })
                }
            )
            $record.hosthunter.user_rights.observation.status | Should -BeExactly failed
            $record.user.PSObject.Properties['id'] | Should -BeNullOrEmpty
            $record.hosthunter.user_rights.PSObject.Properties['rights'] | Should -BeNullOrEmpty
            @($record.hosthunter.user_rights.observation.issues.code) |
                Should -Contain identity_resolution_failed
        }
    }
}
