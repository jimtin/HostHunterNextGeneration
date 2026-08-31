Set-StrictMode -Version Latest

function ConvertTo-HHCimUtcText {
    [CmdletBinding()]
    param([Parameter(Mandatory)][DateTimeOffset]$Value)
    $Value.UtcDateTime.ToString(
        'yyyy-MM-ddTHH:mm:ss.fffZ', [Globalization.CultureInfo]::InvariantCulture
    )
}

function ConvertTo-HHUnsignedDecimalText {
    [CmdletBinding()]
    param([AllowNull()][object]$Value, [string]$Field='native value')
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    $text = ([string]$Value).Trim()
    try {
        $number = if ($text.StartsWith('0x',[StringComparison]::OrdinalIgnoreCase)) {
            [Convert]::ToUInt64($text.Substring(2),16)
        }
        else { [Convert]::ToUInt64($text,[Globalization.CultureInfo]::InvariantCulture) }
    }
    catch { throw "$Field is not a valid unsigned native value." }
    $number.ToString([Globalization.CultureInfo]::InvariantCulture)
}

function ConvertTo-HHUInt32 {
    [CmdletBinding()]
    param([AllowNull()][object]$Value, [string]$Field='process identifier')
    $decimal = ConvertTo-HHUnsignedDecimalText -Value $Value -Field $Field
    if ($null -eq $decimal) { return $null }
    try { [Convert]::ToUInt32($decimal,[Globalization.CultureInfo]::InvariantCulture) }
    catch { throw "$Field is outside the unsigned 32-bit range." }
}

function Get-HHForensicPayloadDigest {
    [CmdletBinding()]
    param([Parameter(Mandatory)][byte[]]$PayloadBytes)
    [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($PayloadBytes)).ToLowerInvariant()
}

function New-HHForensicEventIdentity {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Creates an in-memory deterministic identifier without changing system state.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$EndpointId,
        [Parameter(Mandatory)][string]$Provider,
        [Parameter(Mandatory)][string]$Channel,
        [Parameter(Mandatory)][string]$EventCode,
        [Parameter(Mandatory)][ValidateRange(0,65535)][int]$EventVersion,
        [Parameter(Mandatory)][string]$RecordId,
        [Parameter(Mandatory)][DateTimeOffset]$Timestamp
    )
    $identity = @(
        'HostHunter/forensic-event-identity/v1',$EndpointId,$Provider,$Channel,
        $EventCode,$EventVersion.ToString([Globalization.CultureInfo]::InvariantCulture),
        $RecordId,(ConvertTo-HHCimUtcText $Timestamp)
    ) -join "`n"
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($identity)
    try {
        $hash = [Security.Cryptography.SHA256]::HashData($bytes)
        $guidBytes = [byte[]]::new(16)
        [Array]::Copy($hash,$guidBytes,16)
        # Guid(byte[]) uses little endian for the first three fields. Byte 7 is
        # therefore the printed version nibble; byte 8 owns the RFC variant.
        $guidBytes[7] = ($guidBytes[7] -band 0x0f) -bor 0x50
        $guidBytes[8] = ($guidBytes[8] -band 0x3f) -bor 0x80
        [Guid]::new($guidBytes)
    }
    finally {
        [Array]::Clear($bytes,0,$bytes.Length)
        if ($null -ne $hash) { [Array]::Clear($hash,0,$hash.Length) }
    }
}

function New-HHForensicEnvelope {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Creates an in-memory event document without changing system state.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][DateTimeOffset]$Timestamp,
        [Parameter(Mandatory)][ValidateSet('event','state')][string]$Kind,
        [Parameter(Mandatory)][string[]]$Category,
        [Parameter(Mandatory)][string[]]$Type,
        [Parameter(Mandatory)][string]$Action,
        [Parameter(Mandatory)][string]$Dataset,
        [Parameter(Mandatory)][string]$SchemaName,
        [Parameter(Mandatory)][string]$Provider,
        [Parameter(Mandatory)][string]$Channel,
        [Parameter(Mandatory)][string]$EventCode,
        [Parameter(Mandatory)][int]$EventVersion,
        [Parameter(Mandatory)][string]$RecordId,
        [string]$Computer,
        [AllowNull()][string]$Outcome,
        [string]$Normalizer='HostHunter.CIM'
    )
    $eventDocument = [ordered]@{
        id=([Guid]$Context.EventId).ToString('D').ToLowerInvariant();kind=$Kind
        category=@($Category);type=@($Type);action=$Action;dataset=$Dataset
        module='hosthunter';provider='HostHunter'
        created=(ConvertTo-HHCimUtcText ([DateTimeOffset]$Context.CollectedAtUtc))
    }
    if (-not [string]::IsNullOrWhiteSpace($Outcome)) { $eventDocument.outcome=$Outcome }
    [ordered]@{
        '@timestamp'=(ConvertTo-HHCimUtcText $Timestamp)
        ecs=[ordered]@{version='9.5.0'}
        event=$eventDocument
        agent=[ordered]@{
            id=([Guid]$Context.AgentId).ToString('D').ToLowerInvariant()
            name='hosthunter-controller';type='hosthunter';version=[string]$Context.AgentVersion
        }
        host=[ordered]@{id=[string]$Context.EndpointId;hostname=([string]$Context.HostName).Split('.')[0]}
        hosthunter=[ordered]@{
            schema=[ordered]@{name=$SchemaName;version='1.0.0'}
            collection_run=[ordered]@{id=([Guid]$Context.MissionId).ToString('D').ToLowerInvariant()}
            source=[ordered]@{
                provider=$Provider;channel=$Channel;event_code=$EventCode
                event_version=$EventVersion;record_id=$RecordId
                computer=if ([string]::IsNullOrWhiteSpace($Computer)) {[string]$Context.HostName}else{$Computer}
            }
            provenance=[ordered]@{
                transport='powershell7_over_ssh'
                collected_at=(ConvertTo-HHCimUtcText ([DateTimeOffset]$Context.CollectedAtUtc))
                normalizer=[ordered]@{name=$Normalizer;version='1.0.0'}
            }
        }
    }
}

function ConvertTo-HHPrincipal {
    [CmdletBinding()]
    param(
        [AllowNull()][object]$Id,[AllowNull()][object]$Name,
        [AllowNull()][object]$Domain,[AllowNull()][object]$LogonId,
        [AllowNull()][object]$Type
    )
    $value=[ordered]@{}
    if(-not [string]::IsNullOrWhiteSpace([string]$Id)){$value.id=[string]$Id}
    if(-not [string]::IsNullOrWhiteSpace([string]$Name)){$value.name=[string]$Name}
    if(-not [string]::IsNullOrWhiteSpace([string]$Domain)){$value.domain=[string]$Domain}
    $luid=ConvertTo-HHUnsignedDecimalText -Value $LogonId -Field 'logon identifier'
    if($null -ne $luid){$value.logon_id=$luid}
    if(-not [string]::IsNullOrWhiteSpace([string]$Type)){$value.type=[string]$Type}
    [pscustomobject]$value
}

function Get-HHDataValue {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Data,[Parameter(Mandatory)][string]$Name)
    if ($Data -is [Collections.IDictionary]) {
        if ($Data.Contains($Name)) { return $Data[$Name] }
        return $null
    }
    $property=$Data.PSObject.Properties[$Name]
    if($null -eq $property){return $null}
    $property.Value
}

function Get-HHWindowsLeafName {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    @($Path -split '[\\/]')[-1]
}

function ConvertTo-HHSecurityEventRecord {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$InputObject,[Parameter(Mandatory)][object]$Context)
    $code=[int]$InputObject.EventId;$version=[int]$InputObject.Version
    $supported=@{4688=@(0,1,2);4689=@(0);4624=@(0,1,2);4625=@(0);4634=@(0);4647=@(0);4648=@(0);4672=@(0)}
    if(-not $supported.ContainsKey($code)){throw "Security event code '$code' is unsupported."}
    if($version -notin $supported[$code]){throw "Security event $code version $version is unsupported."}
    $timestamp=[DateTimeOffset]$InputObject.TimeCreated;$data=$InputObject.Data
    $definitions=@{
        4688=@('process.start','process-started','hosthunter.process_start',@('process'),@('start'),$null)
        4689=@('process.end','process-ended','hosthunter.process_end',@('process'),@('end'),$null)
        4624=@('authentication.session.start','user-logon-succeeded','hosthunter.authentication_session',@('authentication'),@('start'),'success')
        4625=@('authentication.logon.failure','user-logon-failed','hosthunter.authentication_attempt',@('authentication'),@('start'),'failure')
        4634=@('authentication.session.end','user-logon-session-ended','hosthunter.authentication_session',@('authentication'),@('end'),'success')
        4647=@('authentication.session.logoff-initiated','user-logoff-initiated','hosthunter.authentication_session',@('authentication'),@('info'),$null)
        4648=@('authentication.explicit-credential-use','explicit-credentials-used','hosthunter.credential_use',@('authentication'),@('start'),'unknown')
        4672=@(
            'authentication.session.special-privileges','special-privileges-assigned',
            'hosthunter.special_privileges',@('authentication','iam'),@('info'),$null
        )
    }
    $definition=$definitions[$code]
    $envelope=New-HHForensicEnvelope -Context $Context -Timestamp $timestamp -Kind event `
        -Category $definition[3] -Type $definition[4] -Action $definition[1] `
        -Dataset $definition[2] -SchemaName $definition[0] `
        -Provider 'Microsoft-Windows-Security-Auditing' -Channel Security `
        -EventCode ([string]$code) -EventVersion $version -RecordId ([string]$InputObject.RecordId) `
        -Computer ([string]$InputObject.Computer) -Outcome $definition[5] `
        -Normalizer "HostHunter.Security$code"
    if($code -eq 4688){
        $processId=ConvertTo-HHUInt32 (Get-HHDataValue $data NewProcessId) 'new process identifier'
        $parentPid=ConvertTo-HHUInt32 (Get-HHDataValue $data ProcessId) 'parent process identifier'
        if($null -eq $processId -or $null -eq $parentPid){throw 'The process event is missing a process identifier.'}
        $path=[string](Get-HHDataValue $data NewProcessName)
        if([string]::IsNullOrWhiteSpace($path)){throw 'The process event is missing a process executable.'}
        $elevation=switch([string](Get-HHDataValue $data TokenElevationType)){
            '%%1936'{'full'};'%%1937'{'elevated'};'%%1938'{'limited'};default{'unknown'}
        }
        $process=[ordered]@{
            pid=$processId;entity_id="$($envelope.host.hostname):$($processId):$(ConvertTo-HHCimUtcText $timestamp)"
            name=(Get-HHWindowsLeafName $path);executable=$path;token_elevation=$elevation
            parent=[ordered]@{pid=$parentPid}
        }
        if($version -ge 1){
            $commandLine=Get-HHDataValue $data CommandLine
            if($null -ne $commandLine){$process.command_line=[string]$commandLine}
        }
        if($version -ge 2){
            $parentPath=[string](Get-HHDataValue $data ParentProcessName)
            if(-not [string]::IsNullOrWhiteSpace($parentPath)){
                $process.parent.name=Get-HHWindowsLeafName $parentPath;$process.parent.executable=$parentPath
            }
            $integrity=switch([string](Get-HHDataValue $data MandatoryLabel)){
                'S-1-16-0'{'untrusted'};'S-1-16-4096'{'low'};'S-1-16-8192'{'medium'}
                'S-1-16-8448'{'medium_plus'};'S-1-16-12288'{'high'}
                'S-1-16-16384'{'system'};'S-1-16-20480'{'protected'}
                'S-1-16-28672'{'secure'};default{$null}
            }
            if($null -ne $integrity){$process.integrity_level=$integrity}
            $target=ConvertTo-HHPrincipal -Id (Get-HHDataValue $data TargetUserSid) `
                -Name (Get-HHDataValue $data TargetUserName) -Domain (Get-HHDataValue $data TargetDomainName) `
                -LogonId (Get-HHDataValue $data TargetLogonId)
            if(@($target.PSObject.Properties).Count -gt 0){$envelope.hosthunter.process=[ordered]@{target_user=$target}}
        }
        $envelope.process=$process
        $envelope.user=ConvertTo-HHPrincipal -Id (Get-HHDataValue $data SubjectUserSid) `
            -Name (Get-HHDataValue $data SubjectUserName) -Domain (Get-HHDataValue $data SubjectDomainName) `
            -LogonId (Get-HHDataValue $data SubjectLogonId)
        return [pscustomobject]$envelope
    }
    if($code -eq 4689){
        $processId=ConvertTo-HHUInt32 (Get-HHDataValue $data ProcessId) 'process identifier'
        if($null -eq $processId){throw 'The process-end event is missing a process identifier.'}
        $path=[string](Get-HHDataValue $data ProcessName)
        if([string]::IsNullOrWhiteSpace($path)){
            throw 'The process-end event is missing a process executable.'
        }
        $exitCode=ConvertTo-HHUInt32 (Get-HHDataValue $data Status) 'process exit status'
        if($null -eq $exitCode){throw 'The process-end event is missing an exit status.'}
        $envelope.process=[ordered]@{
            pid=$processId;name=(Get-HHWindowsLeafName $path);executable=$path
            end=(ConvertTo-HHCimUtcText $timestamp);exit_code=$exitCode
        }
        $envelope.user=ConvertTo-HHPrincipal -Id (Get-HHDataValue $data SubjectUserSid) `
            -Name (Get-HHDataValue $data SubjectUserName) -Domain (Get-HHDataValue $data SubjectDomainName) `
            -LogonId (Get-HHDataValue $data SubjectLogonId)
        return [pscustomobject]$envelope
    }
    $subject=ConvertTo-HHPrincipal -Id (Get-HHDataValue $data SubjectUserSid) `
        -Name (Get-HHDataValue $data SubjectUserName) -Domain (Get-HHDataValue $data SubjectDomainName) `
        -LogonId (Get-HHDataValue $data SubjectLogonId)
    $target=ConvertTo-HHPrincipal -Id (Get-HHDataValue $data TargetUserSid) `
        -Name (Get-HHDataValue $data TargetUserName) -Domain (Get-HHDataValue $data TargetDomainName) `
        -LogonId (Get-HHDataValue $data TargetLogonId)
    $envelope.user=if($code -eq 4634){$target}else{$subject}
    if($code -in @(4624,4625,4648) -and @($target.PSObject.Properties).Count -gt 0){$envelope.user|Add-Member NoteProperty target $target}
    $logonType=Get-HHDataValue $data LogonType
    if($code -in @(4624,4625,4634)){
        $envelope.hosthunter.authentication=[ordered]@{}
        if($null -ne $logonType){$envelope.hosthunter.authentication.logon_type=[ordered]@{id=[int]$logonType;name=(Get-HHLogonTypeName ([int]$logonType))}}
    }
    if($code -in @(4624,4625)){
        $logonProcess=Get-HHDataValue $data LogonProcessName
        $authenticationPackage=Get-HHDataValue $data AuthenticationPackageName
        $keyLength=Get-HHDataValue $data KeyLength
        if($null -ne $logonProcess){$envelope.hosthunter.authentication.logon_process=[string]$logonProcess}
        if($null -ne $authenticationPackage){$envelope.hosthunter.authentication.authentication_package=[string]$authenticationPackage}
        if($null -ne $keyLength){$envelope.hosthunter.authentication.key_length_bits=[int]$keyLength}
        $ntlm=Get-HHDataValue $data LmPackageName
        if(-not [string]::IsNullOrWhiteSpace([string]$ntlm)){$envelope.hosthunter.authentication.ntlm_package=[string]$ntlm}
    }
    if($code -eq 4625){
        $envelope.hosthunter.failure=[ordered]@{
            status_code=[uint64](ConvertTo-HHUnsignedDecimalText (Get-HHDataValue $data Status) 'status code')
            sub_status_code=[uint64](ConvertTo-HHUnsignedDecimalText (Get-HHDataValue $data SubStatus) 'sub-status code')
        }
    }
    if($code -eq 4648){
        $processId=ConvertTo-HHUInt32 (Get-HHDataValue $data ProcessId)
        $path=[string](Get-HHDataValue $data ProcessName)
        $envelope.process=[ordered]@{pid=$processId}
        if(-not [string]::IsNullOrWhiteSpace($path)){$envelope.process.name=Get-HHWindowsLeafName $path;$envelope.process.executable=$path}
        $envelope.hosthunter.authentication=[ordered]@{}
        $targetGuid=Get-HHDataValue $data TargetLogonGuid
        $targetInfo=Get-HHDataValue $data TargetServerName
        if(-not [string]::IsNullOrWhiteSpace([string]$targetGuid) -and
            [string]$targetGuid -cne '{00000000-0000-0000-0000-000000000000}'){
            $envelope.hosthunter.authentication.target_logon_guid = (
                [Guid]([string]$targetGuid).Trim('{}')
            ).ToString('D').ToLowerInvariant()
        }
        if(-not [string]::IsNullOrWhiteSpace([string]$targetInfo)){$envelope.hosthunter.authentication.target_info=[string]$targetInfo}
    }
    if($code -eq 4672){
        $envelope.hosthunter.privileges=@([string](Get-HHDataValue $data PrivilegeList) -split '\s+' | Where-Object {$_} | Select-Object -Unique)
    }
    [pscustomobject]$envelope
}

function Get-HHLogonTypeName {
    [CmdletBinding()]
    param([int]$Id)
    switch($Id){
        2{'interactive'}
        3{'network'}
        4{'batch'}
        5{'service'}
        7{'unlock'}
        8{'network_cleartext'}
        9{'new_credentials'}
        10{'remote_interactive'}
        11{'cached_interactive'}
        default{'unknown'}
    }
}

function Resolve-HHProcessSelection {
    [CmdletBinding(DefaultParameterSetName='ProcessId')]
    param(
        [Parameter(Mandatory)][object[]]$Processes,
        [Parameter(Mandatory,ParameterSetName='ProcessId')][uint32[]]$ProcessId,
        [Parameter(Mandatory,ParameterSetName='ProcessName')][string[]]$ProcessName
    )
    $selectedProcesses=@(if($PSCmdlet.ParameterSetName -ceq 'ProcessId'){
        @($Processes|Where-Object{[uint32]$_.Id -in $ProcessId})
    }else{
        $normalized=@($ProcessName|ForEach-Object{
                if([string]::IsNullOrWhiteSpace($_) -or $_ -match '[*?\[\]\\/]'){throw 'An exact process name without wildcard or path characters is required.'}
                if($_.EndsWith('.exe',[StringComparison]::OrdinalIgnoreCase)){$_.Substring(0,$_.Length-4).ToLowerInvariant()}else{$_.ToLowerInvariant()}
            })
        @($Processes|Where-Object{
                $candidate=[string]$_.Name
                if($candidate.EndsWith('.exe',[StringComparison]::OrdinalIgnoreCase)){$candidate=$candidate.Substring(0,$candidate.Length-4)}
                $candidate.ToLowerInvariant() -in $normalized
            })
    })
    if($selectedProcesses.Count -gt 64){return [pscustomobject]@{Status='failed';FailureKind='TooManyMatches';Processes=@();Issues=@()}}
    if($selectedProcesses.Count -eq 0){
        return [pscustomobject]@{
            Status='unavailable'
            Processes=@()
            Issues=@([pscustomobject]@{
                    Code='process_not_found';Message='No exact process matched.'
                })
        }
    }
    [pscustomobject]@{Status='complete';Processes=@($selectedProcesses);Issues=@()}
}

function ConvertTo-HHObservationIssue {
    [CmdletBinding()]
    param([AllowNull()][object[]]$Issue)
    @($Issue|ForEach-Object{
            $value=[ordered]@{code=([string]$_.Code).ToLowerInvariant()}
            if($null -ne $_.PSObject.Properties['Scope'] -and -not [string]::IsNullOrWhiteSpace([string]$_.Scope)){$value.scope=[string]$_.Scope}
            $detail=if($null -ne $_.PSObject.Properties['Detail']){
                [string]$_.Detail
            }elseif($null -ne $_.PSObject.Properties['Message']){
                [string]$_.Message
            }else{
                $null
            }
            if(-not [string]::IsNullOrWhiteSpace($detail)){$value.detail=$detail}
            [pscustomobject]$value
        })
}

function ConvertTo-HHPrincipalReference {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$InputObject)
    $value=[ordered]@{}
    foreach($pair in @(@('id','Id'),@('name','Name'),@('domain','Domain'),@('type','Type'))){
        $entry=Get-HHDataValue $InputObject $pair[1]
        if(-not [string]::IsNullOrWhiteSpace([string]$entry)){$value[$pair[0]]=[string]$entry}
    }
    [pscustomobject]$value
}

function ConvertTo-HHProcessTokenRecord {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$InputObject,[Parameter(Mandatory)][object]$Context)
    $observed=[DateTimeOffset]$InputObject.ObservedAtUtc
    $before=if($null -ne $InputObject.PSObject.Properties['ProcessStartBeforeUtc']){[DateTimeOffset]$InputObject.ProcessStartBeforeUtc}else{$null}
    $after=if($null -ne $InputObject.PSObject.Properties['ProcessStartAfterUtc']){[DateTimeOffset]$InputObject.ProcessStartAfterUtc}else{$null}
    $status=[string]$InputObject.Status;$issues=@(ConvertTo-HHObservationIssue @($InputObject.Issues))
    $race=$null -ne $before -and $null -ne $after -and $before -ne $after
    if($race){$status='partial';$issues+=,[pscustomobject]@{code='process_instance_changed';detail='The process start time changed during token collection.'}}
    $outcome=if($status -ceq 'complete'){'success'}elseif($status -ceq 'partial'){'unknown'}else{'failure'}
    $envelope=New-HHForensicEnvelope -Context $Context -Timestamp $observed -Kind state `
        -Category @('process','iam') -Type @('info') -Action 'primary-process-token-observed' `
        -Dataset 'hosthunter.process_access_token' -SchemaName 'process.access-token' `
        -Provider 'Microsoft Windows API' -Channel AccessToken -EventCode 'primary-process-token' `
        -EventVersion 1 -RecordId "$($Context.HostName):$($InputObject.ProcessId):$(ConvertTo-HHCimUtcText $observed)" `
        -Outcome $outcome -Normalizer 'HostHunter.PrimaryToken'
    $process=[ordered]@{pid=[uint32]$InputObject.ProcessId}
    $processName=Get-HHDataValue $InputObject ProcessName
    $processPath=Get-HHDataValue $InputObject ProcessPath
    if(-not [string]::IsNullOrWhiteSpace([string]$processName)){$process.name=[string]$processName}
    if(-not [string]::IsNullOrWhiteSpace([string]$processPath)){$process.executable=[string]$processPath}
    if($null -ne $before){$process.start=ConvertTo-HHCimUtcText $before}
    if(-not $race -and $null -ne $before){$process.entity_id="$($Context.HostName):$($InputObject.ProcessId):$(ConvertTo-HHCimUtcText $before)"}
    $envelope.process=$process
    $observation=[ordered]@{status=$status;observed_at=(ConvertTo-HHCimUtcText $observed)}
    if($issues.Count -gt 0){$observation.issues=$issues}
    $envelope.hosthunter.process_token=[ordered]@{observation=$observation}
    if($status -ceq 'complete' -and -not $race){
        $token=[ordered]@{type='primary'}
        foreach($pair in @(@('id','TokenId'),@('authentication_id','AuthenticationId'),@('modified_id','ModifiedId'))){
            $value=ConvertTo-HHUnsignedDecimalText $InputObject.($pair[1]) $pair[1]
            if($null -ne $value){$token[$pair[0]]=$value}
        }
        $envelope.hosthunter.process_token.token=$token
        $seen=@{};$privileges=[Collections.Generic.List[object]]::new()
        foreach($privilege in @($InputObject.Privileges)){
            $key=([string]$privilege.Name).ToLowerInvariant();if($seen.ContainsKey($key)){continue};$seen[$key]=$true
            $privileges.Add([ordered]@{
                    name=[string]$privilege.Name
                    enabled=[bool]$privilege.Enabled
                    enabled_by_default=[bool]$privilege.EnabledByDefault
                    removed=[bool]$privilege.Removed
                    used_for_access=[bool]$privilege.UsedForAccess
                })
        }
        $envelope.hosthunter.process_token.privileges=@($privileges)
        $envelope.user=ConvertTo-HHPrincipal -Id (Get-HHDataValue $InputObject UserSid) `
            -Name (Get-HHDataValue $InputObject UserName) `
            -Domain (Get-HHDataValue $InputObject UserDomain) `
            -LogonId (Get-HHDataValue $InputObject AuthenticationId)
    }
    [pscustomobject]$envelope
}

function Resolve-HHEffectiveRightsRecord {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$InputObject,[Parameter(Mandatory)][object]$Context)
    $observed=[DateTimeOffset]$InputObject.ObservedAtUtc;$status=[string]$InputObject.Status
    $outcome=if($status -ceq 'complete'){'success'}elseif($status -ceq 'failed'){'failure'}else{'unknown'}
    $userId=Get-HHDataValue $InputObject.User Id
    $envelope=New-HHForensicEnvelope -Context $Context -Timestamp $observed -Kind state `
        -Category @('iam') -Type @('info') -Action 'user-effective-rights-observed' `
        -Dataset 'hosthunter.user_effective_rights' -SchemaName 'user.effective-rights' `
        -Provider HostHunter -Channel EffectiveUserRights -EventCode 'target-host-policy' `
        -EventVersion 1 -RecordId "$($Context.HostName):$($userId):$(ConvertTo-HHCimUtcText $observed)" `
        -Outcome $outcome -Normalizer 'HostHunter.EffectiveUserRights'
    $envelope.user=ConvertTo-HHPrincipal -Id $userId `
        -Name (Get-HHDataValue $InputObject.User Name) `
        -Domain (Get-HHDataValue $InputObject.User Domain)
    $issues=@(ConvertTo-HHObservationIssue @($InputObject.Issues))
    $observation=[ordered]@{status=$status;observed_at=(ConvertTo-HHCimUtcText $observed)}
    if($issues.Count -gt 0){$observation.issues=$issues}
    $rights=[ordered]@{
        observation=$observation
        evaluation=[ordered]@{
            scope='target_host_effective_policy';membership_resolution=[string]$InputObject.MembershipResolution
            assignment_resolution=[string]$InputObject.AssignmentResolution
            policy_source_resolution=[string]$InputObject.PolicySourceResolution
        }
    }
    if($status -in @('complete','partial')){
        $grouped=@($InputObject.Assignments|Group-Object Name)
        $rightRecords=[Collections.Generic.List[object]]::new()
        $denyPairs=@{
            SeInteractiveLogonRight='SeDenyInteractiveLogonRight';SeNetworkLogonRight='SeDenyNetworkLogonRight'
            SeBatchLogonRight='SeDenyBatchLogonRight';SeServiceLogonRight='SeDenyServiceLogonRight'
            SeRemoteInteractiveLogonRight='SeDenyRemoteInteractiveLogonRight'
        }
        $assignedNames=@($grouped.Name)
        foreach($group in $grouped){
            $name=[string]$group.Name;$isPrivilege=$name.EndsWith('Privilege',[StringComparison]::Ordinal)
            $isDeny=$name.StartsWith('SeDeny',[StringComparison]::Ordinal)
            $overridden=$denyPairs.ContainsKey($name) -and $denyPairs[$name] -in $assignedNames
            $origins=@($group.Group|ForEach-Object{
                    $source=[ordered]@{attribution_status='unknown';type='unknown';evidence='unknown'}
                    if($null -ne $_.PSObject.Properties['PolicySource'] -and $null -ne $_.PolicySource){
                        $candidate=$_.PolicySource
                        $source=[ordered]@{
                            attribution_status=[string]$candidate.AttributionStatus
                            type=[string]$candidate.Type
                            evidence=[string]$candidate.Evidence
                        }
                        if(-not [string]::IsNullOrWhiteSpace([string]$candidate.Id)){$source.id=[string]$candidate.Id}
                        if(-not [string]::IsNullOrWhiteSpace([string]$candidate.Name)){$source.name=[string]$candidate.Name}
                    }
                    $origin=[ordered]@{
                        assigned_to=(ConvertTo-HHPrincipalReference $_.AssignedTo)
                        relationship=if(@($_.MembershipPath).Count -le 1){
                            'direct'
                        }else{
                            'group_membership'
                        }
                        policy_source=$source
                    }
                    if(@($_.MembershipPath).Count -gt 1){$origin.membership_path=@($_.MembershipPath|ForEach-Object{ConvertTo-HHPrincipalReference $_})}
                    [pscustomobject]$origin
                })
            $record=[ordered]@{
                name=$name
                kind=if($isPrivilege){'privilege'}else{'logon_right'}
                effect=if($isPrivilege){'grant'}elseif($isDeny){'deny'}else{'allow'}
                state=if($overridden){'overridden'}else{'effective'}
                origins=$origins
            }
            if($overridden){$record.overridden_by=@($denyPairs[$name])}
            $rightRecords.Add($record)
        }
        $rights.rights=@($rightRecords)
    }
    $envelope.hosthunter.user_rights=$rights
    [pscustomobject]$envelope
}
