Set-StrictMode -Version Latest

function Get-HHWindowsSecurityEventsRemoteScriptBlock {
    [CmdletBinding()]
    param()
    {
        param(
            [string]$FilterXPath,
            [int]$First
        )
        $observed=[DateTimeOffset]::UtcNow
        if(-not [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([Runtime.InteropServices.OSPlatform]::Windows)){
            return [pscustomobject]@{
                Status='unsupported';ObservedAtUtc=$observed;Records=@();HasMore=$false
                Issues=@([pscustomobject]@{
                        Code='windows_required'
                        Message='Windows Security events are unavailable on this endpoint.'
                    })
            }
        }
        try{
            $events=@(Get-WinEvent -LogName Security -FilterXPath $FilterXPath `
                    -Oldest -MaxEvents ($First+1) -ErrorAction Stop)
            $hasMore=$events.Count -gt $First
            $records=@($events|Select-Object -First $First|ForEach-Object{
                    [xml]$xml=$_.ToXml();$data=[ordered]@{}
                    foreach($node in @($xml.Event.EventData.Data)){
                        $name=[string]$node.Name
                        if(-not [string]::IsNullOrWhiteSpace($name)){$data[$name]=[string]$node.'#text'}
                    }
                    [pscustomobject]@{
                        EventId=[int]$_.Id;Version=[int]$_.Version;RecordId=[long]$_.RecordId
                        TimeCreated=[DateTimeOffset]$_.TimeCreated;Computer=[string]$_.MachineName;Data=$data
                    }
                })
            [pscustomobject]@{
                Status='complete';ObservedAtUtc=$observed;Records=$records
                HasMore=$hasMore;Issues=@()
            }
        }catch{
            if([string]$_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*'){
                return [pscustomobject]@{
                    Status='complete';ObservedAtUtc=$observed;Records=@()
                    HasMore=$false;Issues=@()
                }
            }
            $denied=$_.Exception -is [UnauthorizedAccessException] -or
                $_.CategoryInfo.Category -eq `
                    [Management.Automation.ErrorCategory]::PermissionDenied
            [pscustomobject]@{
                Status=if($denied){'unavailable'}else{'failed'}
                ObservedAtUtc=$observed;Records=@();HasMore=$false
                Issues=@([pscustomobject]@{
                        Code=if($denied){
                            'security_log_access_denied'
                        }else{
                            'security_log_query_failed'
                        }
                        Message=if($denied){
                            'Access to the Windows Security log was denied.'
                        }else{
                            'The Windows Security log query failed.'
                        }
                    })
            }
        }
    }
}

function Get-HHWindowsProcessTokenRemoteScriptBlock {
    [CmdletBinding()]
    param()
    {
        param([string]$SelectorType,[object[]]$SelectorValue)
        $observed=[DateTimeOffset]::UtcNow
        if(-not [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([Runtime.InteropServices.OSPlatform]::Windows)){
            return [pscustomobject]@{
                Status='unsupported';ObservedAtUtc=$observed;Records=@()
                Issues=@([pscustomobject]@{
                        Code='windows_required'
                        Message='Windows access tokens are unavailable on this endpoint.'
                    })
            }
        }
        if($null -eq ('HostHunterNativeToken' -as [type])){
            Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

public sealed class HostHunterTokenPrivilege {
    public string Name { get; set; } = "";
    public bool Enabled { get; set; }
    public bool EnabledByDefault { get; set; }
    public bool Removed { get; set; }
    public bool UsedForAccess { get; set; }
}
public sealed class HostHunterTokenResult {
    public string UserSid { get; set; } = "";
    public string UserName { get; set; } = "";
    public string UserDomain { get; set; } = "";
    public string TokenId { get; set; } = "";
    public string AuthenticationId { get; set; } = "";
    public string ModifiedId { get; set; } = "";
    public HostHunterTokenPrivilege[] Privileges { get; set; } =
        Array.Empty<HostHunterTokenPrivilege>();
}
public static class HostHunterNativeToken {
    const uint PROCESS_QUERY_LIMITED_INFORMATION=0x1000, TOKEN_QUERY=0x0008;
    const int TokenPrivileges=3, TokenStatistics=10;
    [StructLayout(LayoutKind.Sequential)]
    struct LUID { public uint LowPart; public int HighPart; }
    [StructLayout(LayoutKind.Sequential)]
    struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }
    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_STATISTICS {
        public LUID TokenId, AuthenticationId;
        public long ExpirationTime;
        public int TokenType, ImpersonationLevel;
        public uint DynamicCharged, DynamicAvailable;
        public uint GroupCount, PrivilegeCount;
        public LUID ModifiedId;
    }
    [DllImport("kernel32.dll",SetLastError=true)]
    static extern IntPtr OpenProcess(uint access,bool inherit,uint pid);
    [DllImport("kernel32.dll",SetLastError=true)]
    static extern bool CloseHandle(IntPtr handle);
    [DllImport("advapi32.dll",SetLastError=true)]
    static extern bool OpenProcessToken(
        IntPtr process,uint access,out IntPtr token
    );
    [DllImport("advapi32.dll",SetLastError=true)]
    static extern bool GetTokenInformation(
        IntPtr token,int cls,IntPtr buffer,int length,out int returned
    );
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
    static extern bool LookupPrivilegeName(
        string system,ref LUID luid,System.Text.StringBuilder name,ref int length
    );
    static ulong ToUInt64(LUID value) {
        return ((ulong)(uint)value.HighPart<<32)|value.LowPart;
    }
    static IntPtr ReadToken(IntPtr token,int cls,out int length) {
        GetTokenInformation(token,cls,IntPtr.Zero,0,out length);
        IntPtr value=Marshal.AllocHGlobal(length);
        if(!GetTokenInformation(token,cls,value,length,out length)){
            int error=Marshal.GetLastWin32Error();
            Marshal.FreeHGlobal(value);
            throw new Win32Exception(error);
        }
        return value;
    }
    public static HostHunterTokenResult Query(uint pid) {
        IntPtr process=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,false,pid);
        if(process==IntPtr.Zero){
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        IntPtr token=IntPtr.Zero;
        try {
            if(!OpenProcessToken(process,TOKEN_QUERY,out token)){
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            var identity=new WindowsIdentity(token);
            string account=identity.Name??"", domain="", name=account;
            int slash=account.IndexOf('\\');
            if(slash>=0){
                domain=account.Substring(0,slash);
                name=account.Substring(slash+1);
            }
            int size;
            IntPtr statsPtr=ReadToken(token,TokenStatistics,out size);
            TOKEN_STATISTICS stats;
            try{
                stats=Marshal.PtrToStructure<TOKEN_STATISTICS>(statsPtr);
            }finally{
                Marshal.FreeHGlobal(statsPtr);
            }
            IntPtr privilegesPtr=ReadToken(token,TokenPrivileges,out size);
            var privileges=new List<HostHunterTokenPrivilege>();
            try {
                uint count=(uint)Marshal.ReadInt32(privilegesPtr);
                int itemSize=Marshal.SizeOf<LUID_AND_ATTRIBUTES>();
                for(int i=0;i<count;i++){
                    var item=Marshal.PtrToStructure<LUID_AND_ATTRIBUTES>(
                        IntPtr.Add(privilegesPtr,4+i*itemSize)
                    );
                    int chars=0;
                    LookupPrivilegeName(null,ref item.Luid,null,ref chars);
                    var builder=new System.Text.StringBuilder(chars+1);
                    if(!LookupPrivilegeName(
                            null,ref item.Luid,builder,ref chars
                        )){
                        continue;
                    }
                    privileges.Add(new HostHunterTokenPrivilege{
                        Name=builder.ToString(),
                        Enabled=(item.Attributes&2)!=0,
                        EnabledByDefault=(item.Attributes&1)!=0,
                        Removed=(item.Attributes&4)!=0,
                        UsedForAccess=(item.Attributes&0x80000000)!=0
                    });
                }
            } finally {
                Marshal.FreeHGlobal(privilegesPtr);
            }
            return new HostHunterTokenResult{
                UserSid=identity.User?.Value??"",
                UserName=name,
                UserDomain=domain,
                TokenId=ToUInt64(stats.TokenId).ToString(),
                AuthenticationId=ToUInt64(stats.AuthenticationId).ToString(),
                ModifiedId=ToUInt64(stats.ModifiedId).ToString(),
                Privileges=privileges.ToArray()
            };
        } finally {
            if(token!=IntPtr.Zero){
                CloseHandle(token);
            }
            CloseHandle(process);
        }
    }
}
'@
        }
        $processes=@(Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
                try{
                    $started=([DateTimeOffset]$_.StartTime).UtcDateTime.ToString('o')
                }catch{
                    $started=$null
                }
                try{
                    $path=[string]$_.Path
                }catch{
                    $path=$null
                }
                [pscustomobject]@{
                    Id=[uint32]$_.Id;Name=[string]$_.ProcessName
                    Path=$path;StartTimeUtc=$started
                }
            })
        if($SelectorType -ceq 'ProcessId'){
            $selected=@($processes | Where-Object {
                    [uint32]$_.Id -in @($SelectorValue | ForEach-Object {[uint32]$_})
                })
        }
        else{
            $names=@($SelectorValue | ForEach-Object {
                    $text=([string]$_).ToLowerInvariant()
                    if($text.EndsWith('.exe')){
                        $text.Substring(0,$text.Length-4)
                    }else{
                        $text
                    }
                })
            $selected=@($processes | Where-Object {
                    $candidate=([string]$_.Name).ToLowerInvariant()
                    if($candidate.EndsWith('.exe')){
                        $candidate=$candidate.Substring(0,$candidate.Length-4)
                    }
                    $candidate -in $names
                })
        }
        if($selected.Count -gt 64){
            return [pscustomobject]@{
                Status='failed';ObservedAtUtc=$observed;Records=@()
                Issues=@([pscustomobject]@{
                        Code='too_many_matches'
                        Message='Exact selection exceeded 64 processes.'
                    })
            }
        }
        if($selected.Count -eq 0){
            return [pscustomobject]@{
                Status='unavailable';ObservedAtUtc=$observed;Records=@()
                Issues=@([pscustomobject]@{
                        Code='process_not_found';Message='No exact process matched.'
                    })
            }
        }
        $records=@($selected | ForEach-Object {
                $process=$_
                $before=$process.StartTimeUtc
                try{
                    $token=[HostHunterNativeToken]::Query([uint32]$process.Id)
                    try{
                        $currentProcess=Get-Process -Id $process.Id -ErrorAction Stop
                        $after=([DateTimeOffset]$currentProcess.StartTime).UtcDateTime.ToString('o')
                    }catch{
                        $after=$null
                    }
                    [pscustomobject]@{
                        Status='complete';ObservedAtUtc=$observed
                        ProcessId=$process.Id
                        ProcessName=if($process.Name.EndsWith('.exe')){
                            $process.Name
                        }else{
                            "$($process.Name).exe"
                        }
                        ProcessPath=$process.Path
                        ProcessStartBeforeUtc=$before;ProcessStartAfterUtc=$after
                        UserSid=$token.UserSid;UserName=$token.UserName
                        UserDomain=$token.UserDomain;TokenId=$token.TokenId
                        AuthenticationId=$token.AuthenticationId
                        ModifiedId=$token.ModifiedId
                        Privileges=@($token.Privileges);Issues=@()
                    }
                }catch{
                    $denied=$_.Exception -is [UnauthorizedAccessException] -or
                        $_.Exception.Message -match 'denied'
                    [pscustomobject]@{
                        Status='unavailable';ObservedAtUtc=$observed
                        ProcessId=$process.Id;ProcessName=$process.Name
                        ProcessPath=$process.Path
                        ProcessStartBeforeUtc=$before;ProcessStartAfterUtc=$before
                        Issues=@([pscustomobject]@{
                                Code=if($denied){
                                    'access_denied'
                                }else{
                                    'token_query_failed'
                                }
                                Message=if($denied){
                                    'Token query was denied.'
                                }else{
                                    'Token query failed.'
                                }
                            })
                    }
                }
            })
        [pscustomobject]@{
            Status='complete';ObservedAtUtc=$observed;Records=$records;Issues=@()
        }
    }
}

function Get-HHWindowsEffectiveRightsRemoteScriptBlock {
    [CmdletBinding()]
    param()
    {
        param([string]$Identity)
        $observed=[DateTimeOffset]::UtcNow
        if(-not [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([Runtime.InteropServices.OSPlatform]::Windows)){
            return [pscustomobject]@{
                Status='unsupported';ObservedAtUtc=$observed;Records=@()
                Issues=@([pscustomobject]@{
                        Code='windows_required'
                        Message='Windows effective rights are unavailable on this endpoint.'
                    })
            }
        }
        try{
            $account=[Security.Principal.NTAccount]::new($Identity)
            $sid=$account.Translate([Security.Principal.SecurityIdentifier])
            $resolved=$sid.Translate([Security.Principal.NTAccount]).Value
            $parts=$resolved -split '\\',2
            $user=[pscustomobject]@{
                Id=$sid.Value
                Name=if($parts.Count -eq 2){$parts[1]}else{$parts[0]}
                Domain=if($parts.Count -eq 2){$parts[0]}else{$null}
                Type='user'
            }
        }catch{
            return [pscustomobject]@{
                Status='complete';ObservedAtUtc=$observed
                Records=@([pscustomobject]@{
                        Status='failed';ObservedAtUtc=$observed
                        User=[pscustomobject]@{Name=$Identity}
                        MembershipResolution='failed'
                        AssignmentResolution='failed'
                        PolicySourceResolution='not_collected'
                        Issues=@([pscustomobject]@{
                                Code='identity_resolution_failed'
                                Message='Identity was not resolved.'
                            })
                    })
                Issues=@()
            }
        }
        $members=[ordered]@{$sid.Value=$user}
        $membershipStatus='complete'
        $issues=[Collections.Generic.List[object]]::new()
        try{
            Add-Type -AssemblyName System.DirectoryServices.AccountManagement -ErrorAction Stop
            $contextType=if($user.Domain -and
                $user.Domain -notin @($env:COMPUTERNAME,'.')){
                [DirectoryServices.AccountManagement.ContextType]::Domain
            }else{
                [DirectoryServices.AccountManagement.ContextType]::Machine
            }
            $context=[DirectoryServices.AccountManagement.PrincipalContext]::new(
                $contextType,$user.Domain
            )
            try{
                $principal=[DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity(
                    $context,$Identity
                )
                if($null -eq $principal){throw 'The principal was not found.'}
                foreach($group in $principal.GetAuthorizationGroups()){
                    if($null -eq $group.Sid){continue}
                    $name=[string]$group.SamAccountName
                    $members[$group.Sid.Value]=[pscustomobject]@{
                        Id=$group.Sid.Value;Name=$name;Domain=[string]$user.Domain
                        Type=if($group.Sid.IsWellKnown(
                                [Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid
                            )){
                            'well_known_group'
                        }else{
                            'group'
                        }
                    }
                }
            }finally{
                $context.Dispose()
            }
        }catch{
            $membershipStatus='partial'
            $issues.Add([pscustomobject]@{
                    Code='group_membership_partial'
                    Message='Not all authorization groups could be resolved.'
                })
        }
        $path=Join-Path ([IO.Path]::GetTempPath()) ("hh-rights-$([Guid]::NewGuid().ToString('N')).inf")
        try{
            & secedit.exe /export /cfg $path /areas USER_RIGHTS /quiet | Out-Null
            if($LASTEXITCODE -ne 0 -or -not [IO.File]::Exists($path)){throw 'secedit export failed.'}
            $assignments=[Collections.Generic.List[object]]::new()
            foreach($line in Get-Content -LiteralPath $path -Encoding Unicode){
                if($line -notmatch `
                    '^(Se[A-Za-z0-9]+(?:Privilege|Right))\s*=\s*(.*)$'){
                    continue
                }
                $right=$matches[1]
                foreach($assigned in @(
                        $matches[2] -split ',' | ForEach-Object {
                            $_.Trim().TrimStart('*')
                        } | Where-Object {$_}
                    )){
                    if(-not $members.Contains($assigned)){continue}
                    $assignedTo=$members[$assigned]
                    $pathItems=if($assigned -ceq $sid.Value){@($user)}else{@($user,$assignedTo)}
                    $assignments.Add([pscustomobject]@{
                            Name=$right;AssignedTo=$assignedTo
                            MembershipPath=$pathItems
                        })
                }
            }
            $record=[pscustomobject]@{
                Status=if($membershipStatus -ceq 'complete'){
                    'complete'
                }else{
                    'partial'
                }
                ObservedAtUtc=$observed;User=$user
                MembershipResolution=$membershipStatus
                AssignmentResolution='complete'
                PolicySourceResolution='not_collected'
                Issues=@($issues);Assignments=@($assignments)
            }
        }catch{
            $record=[pscustomobject]@{
                Status='unavailable';ObservedAtUtc=$observed;User=$user
                MembershipResolution=$membershipStatus
                AssignmentResolution='failed'
                PolicySourceResolution='not_collected'
                Issues=@($issues)+@([pscustomobject]@{
                        Code='rights_policy_unavailable'
                        Message=(
                            'The target-host user-right assignment policy ' +
                            'could not be read.'
                        )
                    })
            }
        }finally{
            Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        }
        [pscustomobject]@{
            Status='complete';ObservedAtUtc=$observed;Records=@($record);Issues=@()
        }
    }
}
