Set-StrictMode -Version Latest

function Get-HHHostDetailsRemoteScriptBlock {
    [CmdletBinding()]
    param()
    {
        $observed=[DateTimeOffset]::UtcNow
        $endpointIsWindows=[Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([Runtime.InteropServices.OSPlatform]::Windows)
        $raw=[ordered]@{ ObservedAtUtc=$observed.UtcDateTime.ToString('o'); Platform=if($endpointIsWindows){'windows'}else{'linux'} }
        $sources=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        $results=[Collections.Generic.List[object]]::new()
        function Set-Observed {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
                'PSUseShouldProcessForStateChangingFunctions',
                '',
                Justification = 'Remote collection helper only appends an in-memory field result.'
            )]
            param([string]$field,[string]$source,$value)
            $null=$sources.Add($source)
            if ($null -eq $value -or ($value -is [string] -and [string]::IsNullOrWhiteSpace($value))) {
                $results.Add([pscustomobject]@{field=$field;status='not_reported';source_method=$source;detail='The endpoint did not report this optional value.'})
            } else {
                $results.Add([pscustomobject]@{field=$field;status='observed';source_method=$source;observed_at=$raw.ObservedAtUtc})
            }
        }
        function Set-Failed {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
                'PSUseShouldProcessForStateChangingFunctions',
                '',
                Justification = 'Remote collection helper only appends an in-memory field result.'
            )]
            param([string]$field,[string]$source,$errorRecord)
            $null=$sources.Add($source)
            $status=if($errorRecord.Exception -is [UnauthorizedAccessException] -or
                $errorRecord.CategoryInfo.Category -eq [Management.Automation.ErrorCategory]::PermissionDenied){'access_denied'}else{'collection_failed'}
            $results.Add([pscustomobject]@{field=$field;status=$status;source_method=$source;detail='The endpoint could not provide this field.'})
        }
        try {
            $raw.Hostname=[Environment]::MachineName
            Set-Observed 'host.hostname' 'dotnet_environment' $raw.Hostname
            $raw.Architecture=[Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()
            Set-Observed 'host.architecture' 'dotnet_runtime_information' $raw.Architecture
            $raw.OsFull=[Runtime.InteropServices.RuntimeInformation]::OSDescription.Trim()
            Set-Observed 'host.os.full' 'dotnet_runtime_information' $raw.OsFull
            $raw.OsKernel=[Environment]::OSVersion.VersionString
            Set-Observed 'host.os.kernel' 'dotnet_runtime_information' $raw.OsKernel
        } catch { $null = $_.Exception }
        try {
            $raw.Fqdn=([Net.Dns]::GetHostEntry([Environment]::MachineName).HostName).ToLowerInvariant()
            Set-Observed 'host.name' 'dotnet_network_information' $raw.Fqdn
        } catch { Set-Failed 'host.name' 'dotnet_network_information' $_ }
        try {
            $interfaces=@([Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | ForEach-Object {
                $addresses=@($_.GetIPProperties().UnicastAddresses | ForEach-Object Address | Where-Object {
                    if($_.AddressFamily -notin @([Net.Sockets.AddressFamily]::InterNetwork,[Net.Sockets.AddressFamily]::InterNetworkV6)){return $false}
                    if([Net.IPAddress]::IsLoopback($_) -or $_.Equals([Net.IPAddress]::Any) -or $_.Equals([Net.IPAddress]::IPv6Any) -or $_.IsIPv6LinkLocal){return $false}
                    $octets=$_.GetAddressBytes()
                    -not ($_.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork -and $octets[0] -eq 169 -and $octets[1] -eq 254)
                } | ForEach-Object ToString | Sort-Object -Unique | Select-Object -First 16)
                if($addresses.Count -gt 0){[pscustomobject]@{name=$_.Name;addresses=$addresses}}
            } | Select-Object -First 32)
            $raw.Interfaces=$interfaces
            $raw.Ip=@($interfaces.addresses | Sort-Object -Unique | Select-Object -First 64)
            Set-Observed 'host.ip' 'dotnet_network_information' $(if($raw.Ip.Count){$raw.Ip}else{$null})
            Set-Observed 'hosthunter.network.interfaces' 'dotnet_network_information' $(if($interfaces.Count){$interfaces}else{$null})
        } catch { Set-Failed 'host.ip' 'dotnet_network_information' $_; Set-Failed 'hosthunter.network.interfaces' 'dotnet_network_information' $_ }
        try {
            $zone=[TimeZoneInfo]::Local
            $raw.TimeZoneId=$zone.Id; $raw.UtcOffsetSeconds=[int]$zone.GetUtcOffset($observed).TotalSeconds
            Set-Observed 'hosthunter.time_zone.id' 'dotnet_time_zone' $raw.TimeZoneId
            Set-Observed 'hosthunter.time_zone.utc_offset_seconds' 'dotnet_time_zone' $raw.UtcOffsetSeconds
        } catch { Set-Failed 'hosthunter.time_zone.id' 'dotnet_time_zone' $_; Set-Failed 'hosthunter.time_zone.utc_offset_seconds' 'dotnet_time_zone' $_ }
        if($endpointIsWindows){
            try {
                $cs=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
                $raw.Domain=[string]$cs.Domain; $raw.MembershipType=if($cs.PartOfDomain){'domain'}else{'workgroup'}
                $raw.MembershipName=[string]$cs.Domain
                $roles=@('standalone_workstation','member_workstation','standalone_server','member_server','backup_domain_controller','primary_domain_controller')
                $raw.DirectoryRole=if([int]$cs.DomainRole -ge 0 -and [int]$cs.DomainRole -lt $roles.Count){$roles[[int]$cs.DomainRole]}else{'unknown'}
                $raw.Manufacturer=[string]$cs.Manufacturer; $raw.Model=[string]$cs.Model
                $raw.LogicalProcessors=[int]$cs.NumberOfLogicalProcessors; $raw.MemoryBytes=[long]$cs.TotalPhysicalMemory
                foreach($pair in @(@('host.domain',$raw.Domain),@('hosthunter.membership.type',$raw.MembershipType),@('hosthunter.membership.name',$raw.MembershipName),@('hosthunter.membership.directory_role',$raw.DirectoryRole),@('hosthunter.hardware.manufacturer',$raw.Manufacturer),@('hosthunter.hardware.model',$raw.Model),@('hosthunter.hardware.logical_processor_count',$raw.LogicalProcessors),@('hosthunter.hardware.total_memory_bytes',$raw.MemoryBytes))){Set-Observed $pair[0] 'win32_computer_system' $pair[1]}
            } catch {
                foreach($field in @('host.domain','hosthunter.membership.type','hosthunter.membership.name','hosthunter.membership.directory_role','hosthunter.hardware.manufacturer','hosthunter.hardware.model','hosthunter.hardware.logical_processor_count','hosthunter.hardware.total_memory_bytes')){Set-Failed $field 'win32_computer_system' $_}
            }
            try {
                $os=Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
                $raw.OsFamily='windows'; $raw.OsName=[string]$os.Caption; $raw.OsVersion=[string]$os.Version; $raw.OsBuild=[string]$os.BuildNumber; $raw.OsEdition=[string]$os.Caption
                $raw.BootTime=([DateTimeOffset]$os.LastBootUpTime).UtcDateTime.ToString('o')
                foreach($pair in @(@('host.os.family',$raw.OsFamily),@('host.os.name',$raw.OsName),@('host.os.version',$raw.OsVersion),@('hosthunter.os.build',$raw.OsBuild),@('hosthunter.os.edition',$raw.OsEdition),@('hosthunter.boot.time',$raw.BootTime))){Set-Observed $pair[0] 'win32_operating_system' $pair[1]}
            } catch {
                foreach($field in @('host.os.family','host.os.name','host.os.version','hosthunter.os.build','hosthunter.os.edition','hosthunter.boot.time')){Set-Failed $field 'win32_operating_system' $_}
            }
            try { $native=(Get-ItemPropertyValue 'HKLM:\SOFTWARE\Microsoft\Cryptography' MachineGuid -ErrorAction Stop) } catch { $native=$null }
        } else {
            $raw.MembershipType='none'; Set-Observed 'hosthunter.membership.type' 'linux_os_release' $raw.MembershipType
            foreach($field in @('host.domain','hosthunter.membership.name','hosthunter.membership.directory_role')){
                $results.Add([pscustomobject]@{field=$field;status='not_applicable';source_method='linux_os_release';detail='This field is not applicable to the observed Linux membership model.'})
            }
            try {
                $values=@{}; Get-Content /etc/os-release -ErrorAction Stop | ForEach-Object { if($_ -match '^([^=]+)=(.*)$'){$values[$matches[1]]=$matches[2].Trim('"')} }
                $raw.OsFamily=[string]$values.ID; $raw.OsName=[string]$values.NAME; $raw.OsVersion=[string]$values.VERSION_ID; $raw.OsEdition=[string]$values.VERSION_CODENAME
                foreach($pair in @(@('host.os.family',$raw.OsFamily),@('host.os.name',$raw.OsName),@('host.os.version',$raw.OsVersion),@('hosthunter.os.edition',$raw.OsEdition))){Set-Observed $pair[0] 'linux_os_release' $pair[1]}
            } catch {
                foreach($field in @('host.os.family','host.os.name','host.os.version','hosthunter.os.edition')){Set-Failed $field 'linux_os_release' $_}
            }
            try { $raw.Manufacturer=(Get-Content /sys/class/dmi/id/sys_vendor -Raw -ErrorAction Stop).Trim(); Set-Observed 'hosthunter.hardware.manufacturer' 'linux_sysfs' $raw.Manufacturer } catch { Set-Observed 'hosthunter.hardware.manufacturer' 'linux_sysfs' $null }
            try { $raw.Model=(Get-Content /sys/class/dmi/id/product_name -Raw -ErrorAction Stop).Trim(); Set-Observed 'hosthunter.hardware.model' 'linux_sysfs' $raw.Model } catch { Set-Observed 'hosthunter.hardware.model' 'linux_sysfs' $null }
            $raw.LogicalProcessors=[Environment]::ProcessorCount; Set-Observed 'hosthunter.hardware.logical_processor_count' 'dotnet_environment' $raw.LogicalProcessors
            try { $kb=[long](([regex]::Match((Get-Content /proc/meminfo -Raw),'MemTotal:\s+(\d+)')).Groups[1].Value); $raw.MemoryBytes=$kb*1024; Set-Observed 'hosthunter.hardware.total_memory_bytes' 'linux_procfs' $raw.MemoryBytes } catch { Set-Failed 'hosthunter.hardware.total_memory_bytes' 'linux_procfs' $_ }
            try {
                $bootMatch=[regex]::Match((Get-Content /proc/stat -Raw -ErrorAction Stop),'(?m)^btime\s+(\d+)\s*$')
                if(-not $bootMatch.Success){throw 'The endpoint did not report procfs btime.'}
                $raw.BootTime=[DateTimeOffset]::FromUnixTimeSeconds([long]$bootMatch.Groups[1].Value).UtcDateTime.ToString('o')
                Set-Observed 'hosthunter.boot.time' 'linux_procfs_btime' $raw.BootTime
            } catch { Set-Failed 'hosthunter.boot.time' 'linux_procfs_btime' $_ }
            try { $native=(Get-Content /etc/machine-id -Raw -ErrorAction Stop).Trim() } catch { $native=$null }
        }
        Set-Observed 'host.os.type' 'dotnet_runtime_information' $raw.Platform
        if(-not [string]::IsNullOrWhiteSpace($native)){
            $bytes=[Text.Encoding]::UTF8.GetBytes("$($raw.Platform):$native")
            try{$raw.NativeIdentityDigest=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()}finally{[Array]::Clear($bytes,0,$bytes.Length);$native=$null}
        }
        $expected=[ordered]@{
            'host.hostname'='dotnet_environment';'host.name'='dotnet_network_information';'host.architecture'='dotnet_runtime_information';'host.ip'='dotnet_network_information';
            'host.os.type'='dotnet_runtime_information';'host.os.family'=if($endpointIsWindows){'win32_operating_system'}else{'linux_os_release'};'host.os.name'=if($endpointIsWindows){'win32_operating_system'}else{'linux_os_release'};
            'host.os.full'='dotnet_runtime_information';'host.os.version'=if($endpointIsWindows){'win32_operating_system'}else{'linux_os_release'};'host.os.kernel'='dotnet_runtime_information';
            'host.domain'=if($endpointIsWindows){'win32_computer_system'}else{'linux_os_release'};'hosthunter.membership.type'=if($endpointIsWindows){'win32_computer_system'}else{'linux_os_release'};
            'hosthunter.membership.name'=if($endpointIsWindows){'win32_computer_system'}else{'linux_os_release'};'hosthunter.membership.directory_role'=if($endpointIsWindows){'win32_computer_system'}else{'linux_os_release'};
            'hosthunter.os.build'=if($endpointIsWindows){'win32_operating_system'}else{'linux_os_release'};'hosthunter.os.edition'=if($endpointIsWindows){'win32_operating_system'}else{'linux_os_release'};
            'hosthunter.hardware.manufacturer'=if($endpointIsWindows){'win32_computer_system'}else{'linux_sysfs'};'hosthunter.hardware.model'=if($endpointIsWindows){'win32_computer_system'}else{'linux_sysfs'};
            'hosthunter.hardware.logical_processor_count'=if($endpointIsWindows){'win32_computer_system'}else{'dotnet_environment'};'hosthunter.hardware.total_memory_bytes'=if($endpointIsWindows){'win32_computer_system'}else{'linux_procfs'};
            'hosthunter.network.interfaces'='dotnet_network_information';'hosthunter.boot.time'=if($endpointIsWindows){'win32_operating_system'}else{'linux_procfs_btime'};
            'hosthunter.time_zone.id'='dotnet_time_zone';'hosthunter.time_zone.utc_offset_seconds'='dotnet_time_zone'
        }
        $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach($result in $results){if(-not $seen.Add([string]$result.field)){throw "Host details collector produced duplicate field result '$($result.field)'."}}
        foreach($entry in $expected.GetEnumerator()){
            if(-not $seen.Contains([string]$entry.Key)){
                $null=$sources.Add([string]$entry.Value)
                $results.Add([pscustomobject]@{field=[string]$entry.Key;status='not_reported';source_method=[string]$entry.Value;detail='The endpoint did not report this optional value.'})
            }
        }
        $raw.FieldResults=@($results | Sort-Object field); $raw.SourceMethods=@($sources | Sort-Object)
        [pscustomobject]$raw
    }
}

function Add-HHOptionalProperty {
    param([Collections.IDictionary]$Map,[string]$Name,$Value)
    if ($null -ne $Value -and -not ($Value -is [string] -and [string]::IsNullOrWhiteSpace($Value))) { $Map[$Name]=$Value }
}

function Get-HHVisualizerAgentId {
    [CmdletBinding()]
    param([Parameter(Mandatory)][byte[]]$DatabaseId)
    if ($DatabaseId.Length -ne 16) { throw 'The HostHunter database identity must contain 16 bytes.' }
    $domain=[Text.UTF8Encoding]::new($false).GetBytes('HostHunter/visualizer-agent/v1')
    $digestInput=[byte[]]::new($domain.Length+$DatabaseId.Length)
    try {
        [Array]::Copy($domain,0,$digestInput,0,$domain.Length)
        [Array]::Copy($DatabaseId,0,$digestInput,$domain.Length,$DatabaseId.Length)
        $digest=[Security.Cryptography.SHA256]::HashData($digestInput)
        $id=[byte[]]$digest[0..15]
        $id[7]=($id[7] -band 0x0f) -bor 0x50
        $id[8]=($id[8] -band 0x3f) -bor 0x80
        ([Guid]::new($id)).ToString('D').ToLowerInvariant()
    }
    finally {
        [Array]::Clear($domain,0,$domain.Length);[Array]::Clear($digestInput,0,$digestInput.Length)
        if($null -ne $digest){[Array]::Clear($digest,0,$digest.Length)}
        if($null -ne $id){[Array]::Clear($id,0,$id.Length)}
    }
}

function Assert-HHHostDetailsPayloadSchema {
    [CmdletBinding()]
    param([Parameter(Mandatory)][byte[]]$PayloadBytes)

    if ($PayloadBytes.Length -lt 2 -or $PayloadBytes.Length -gt 262144) {
        throw 'The host-details payload size is outside the committed contract.'
    }
    $schemaPath=Join-Path $script:HHModuleRoot 'Private/Schemas/host-details-observation.v1.schema.json'
    if(-not [IO.File]::Exists($schemaPath)){throw 'The packaged host-details schema is unavailable.'}
    if($null -eq ('Json.Schema.JsonSchema' -as [type])){
        throw 'The packaged JSON Schema 2020-12 validator is unavailable.'
    }
    $schema=[Json.Schema.JsonSchema]::FromText([IO.File]::ReadAllText($schemaPath))
    $node=$null
    try {
        $node=[Text.Json.Nodes.JsonNode]::Parse($PayloadBytes)
        $options=[Json.Schema.EvaluationOptions]::new()
        $options.OutputFormat=[Json.Schema.OutputFormat]::List
        $options.RequireFormatValidation=$true
        $evaluation=$schema.Evaluate($node,$options)
        if(-not $evaluation.IsValid){
            $locations=@($evaluation.Details | Where-Object {
                    -not $_.IsValid -and $null -ne $_.Errors -and $_.Errors.Count -gt 0
                } | ForEach-Object {
                    $location=[string]$_.InstanceLocation
                    if([string]::IsNullOrWhiteSpace($location)){'/'}else{"/$($location -replace ' ','/')"}
                } | Sort-Object -Unique | Select-Object -First 8)
            $suffix=if($locations.Count){" Invalid location(s): $($locations -join ', ')."}else{''}
            throw "The host-details payload does not conform to the committed JSON Schema 2020-12 contract.$suffix"
        }
    }
    catch [Text.Json.JsonException] {
        throw 'The host-details payload is not valid UTF-8 JSON.'
    }
    $true
}

function ConvertTo-HHHostDetailsPayload {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Raw,[Parameter(Mandatory)][object]$Target,
        [Parameter(Mandatory)][Guid]$MissionId,[Parameter(Mandatory)][Guid]$EventId,
        [Parameter(Mandatory)][string]$EndpointId,[Parameter(Mandatory)][string]$IdentityStrategy,
        [Parameter(Mandatory)][byte[]]$BatchId,[Parameter(Mandatory)][byte[]]$InvocationId,
        [Parameter(Mandatory)][byte[]]$DatabaseId
    )
    $rawView = [ordered]@{}
    foreach ($propertyName in @(
            'ObservedAtUtc','Platform','Hostname','Fqdn','Domain','Architecture','Ip',
            'OsFamily','OsName','OsFull','OsVersion','OsKernel','OsBuild','OsEdition',
            'MembershipType','MembershipName','DirectoryRole','Manufacturer','Model',
            'LogicalProcessors','MemoryBytes','Interfaces','BootTime','TimeZoneId',
            'UtcOffsetSeconds','FieldResults','SourceMethods'
        )) {
        $property = $Raw.PSObject.Properties[$propertyName]
        $rawView[$propertyName] = if ($null -eq $property) { $null } else { $property.Value }
    }
    $nativeIdentityProperty=$Raw.PSObject.Properties['NativeIdentityDigest']
    $canonicalRemote=[ordered]@{}
    foreach($entry in $rawView.GetEnumerator()){$canonicalRemote[$entry.Key]=$entry.Value}
    $canonicalRemote.NativeIdentityDigest=if($null -eq $nativeIdentityProperty){$null}else{$nativeIdentityProperty.Value}
    $canonicalBytes=[Text.UTF8Encoding]::new($false).GetBytes(($canonicalRemote|ConvertTo-Json -Compress -Depth 12))
    try{$nativeHash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($canonicalBytes)).ToLowerInvariant()}finally{[Array]::Clear($canonicalBytes,0,$canonicalBytes.Length)}
    $Raw = [pscustomobject]$rawView
    $observed=[DateTimeOffset]::Parse([string]$Raw.ObservedAtUtc).UtcDateTime.ToString('o')
    $hostMap=[ordered]@{id=$EndpointId}; Add-HHOptionalProperty $hostMap hostname $Raw.Hostname; Add-HHOptionalProperty $hostMap name $Raw.Fqdn; Add-HHOptionalProperty $hostMap domain $Raw.Domain; Add-HHOptionalProperty $hostMap architecture $Raw.Architecture; if(@($Raw.Ip).Count){$hostMap.ip=@($Raw.Ip)}
    $os=[ordered]@{}; Add-HHOptionalProperty $os type $Raw.Platform; Add-HHOptionalProperty $os family $Raw.OsFamily; Add-HHOptionalProperty $os name $Raw.OsName; Add-HHOptionalProperty $os full $Raw.OsFull; Add-HHOptionalProperty $os version $Raw.OsVersion; Add-HHOptionalProperty $os kernel $Raw.OsKernel; if($os.Count){$hostMap.os=$os}
    $membership=[ordered]@{type=$(if($Raw.MembershipType){$Raw.MembershipType}else{'unknown'})}; Add-HHOptionalProperty $membership name $Raw.MembershipName; Add-HHOptionalProperty $membership directory_role $Raw.DirectoryRole
    $hardware=[ordered]@{}; Add-HHOptionalProperty $hardware manufacturer $Raw.Manufacturer; Add-HHOptionalProperty $hardware model $Raw.Model; Add-HHOptionalProperty $hardware logical_processor_count $Raw.LogicalProcessors; Add-HHOptionalProperty $hardware total_memory_bytes $Raw.MemoryBytes
    $created=[DateTimeOffset]::UtcNow.UtcDateTime.ToString('o')
    $payload=[ordered]@{
        '@timestamp'=$observed; ecs=[ordered]@{version='9.5.0'}
        event=[ordered]@{id=$EventId.ToString('D').ToLowerInvariant();kind='asset';category=@('host');type=@('info');action='host-details-collected';dataset='hosthunter.host_details';module='hosthunter';provider='HostHunter';created=$created;hash=$nativeHash}
        agent=[ordered]@{id=(Get-HHVisualizerAgentId -DatabaseId $DatabaseId);name='hosthunter-controller';type='hosthunter';version=(Get-HHModuleVersionText)}
        host=$hostMap
        hosthunter=[ordered]@{
            schema=[ordered]@{name='host-details';version='1.0.0'}
            target=[ordered]@{name=[string]$Target.Name;connection_address=[string]$Target.HostName;port=[int]$Target.Port}
            identity=[ordered]@{strategy=$IdentityStrategy;match_status='exact'}
            membership=$membership
            collection_run=[ordered]@{id=$MissionId.ToString('D').ToLowerInvariant()}
            collection=[ordered]@{status=$(if(@($Raw.FieldResults).Count -gt 0 -and @($Raw.FieldResults | Where-Object status -ne 'observed').Count -eq 0){'complete'}else{'partial'});last_successful_connection_at=$observed;field_results=@($Raw.FieldResults)}
            provenance=[ordered]@{
                engine_operation='GetHostDetails';transport='powershell7_over_ssh'
                controller_platform='linux_container'
                source_methods=@(@($Raw.SourceMethods) + @(
                            'hosthunter_identity','hosthunter_target'
                        ) | Sort-Object -Unique)
            }
            audit=[ordered]@{batch_id=[Convert]::ToHexString($BatchId).ToLowerInvariant();invocation_id=[Convert]::ToHexString($InvocationId).ToLowerInvariant()}
        }
    }
    if(@($Raw.Ip).Count){$payload.related=[ordered]@{ip=@($Raw.Ip)}}
    $osExtra=[ordered]@{}; Add-HHOptionalProperty $osExtra build $Raw.OsBuild; Add-HHOptionalProperty $osExtra edition $Raw.OsEdition; if($osExtra.Count){$payload.hosthunter.os=$osExtra}
    if($hardware.Count){$payload.hosthunter.hardware=$hardware}
    if(@($Raw.Interfaces).Count){$payload.hosthunter.network=[ordered]@{interfaces=@($Raw.Interfaces)}}
    if($Raw.BootTime){$payload.hosthunter.boot=[ordered]@{time=[DateTimeOffset]::Parse([string]$Raw.BootTime).UtcDateTime.ToString('o')}}
    if($Raw.TimeZoneId){$payload.hosthunter.time_zone=[ordered]@{id=[string]$Raw.TimeZoneId;utc_offset_seconds=[int]$Raw.UtcOffsetSeconds}}
    [pscustomobject]$payload
}
