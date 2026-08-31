Set-StrictMode -Version Latest

function Get-HHForensicCollectionContext {
    [CmdletBinding()]
    param([string[]]$Name)
    $runtime=Get-HHRuntimeContext
    if(-not [IO.File]::Exists($runtime.DatabasePath)){throw 'No active HostHunter targets are available.'}
    $context=Open-HHAuthenticatedPersistence -PersistenceContext $runtime
    try{
        $parameters=@{Connection=$context.Connection;MasterKey=$context.MasterKey;ExpectedAnchor=$context.Anchor}
        if($null -ne $Name){$parameters.Name=$Name}
        $targets=@((Read-HHTargetRepositorySnapshot @parameters).Targets|Where-Object IsActive)
        if($targets.Count -eq 0){throw 'No active HostHunter targets are available.'}
        $latest=Get-HHLatestVisualizerMissionRecord -Connection $context.Connection -Transaction $null
        $current=if($null -eq $context.VisualizerSnapshot.CurrentMissionId){$null}else{[Guid]::new([byte[]]$context.VisualizerSnapshot.CurrentMissionId)}
        $mission=if($null -ne $current){$current}elseif($null -ne $latest){[Guid]::new([byte[]]$latest.MissionId)}else{$null}
        if($null -eq $mission){throw 'Start a HostHunter mission before collecting forensic endpoint information.'}
        [pscustomobject]@{
            Runtime=$runtime;Targets=$targets;MissionId=$mission;PublishingEnabled=$null -ne $current
            AgentId=[Guid]::new([byte[]]$context.Anchor.DatabaseId);AgentVersion=Get-HHModuleVersionText
        }
    }finally{Close-HHAuthenticatedPersistence -Context $context}
}

function Assert-HHForensicVisualizerCapability {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Collection,[scriptblock]$ProducerSender)
    if(-not $Collection.PublishingEnabled){return}
    $status=Invoke-HHVisualizerStatus -RequestSender $ProducerSender
    if($status.ActiveMissionId -ne $Collection.MissionId){
        throw 'Visualizer mission state does not match the active HostHunter mission.'
    }
}

function Assert-HHForensicPayloadSchema {
    [CmdletBinding()]
    param([Parameter(Mandatory)][byte[]]$PayloadBytes)
    if($PayloadBytes.Length -lt 2 -or $PayloadBytes.Length -gt 262144){throw 'Forensic payload size is invalid.'}
    try{
        $text=[Text.UTF8Encoding]::new($false,$true).GetString($PayloadBytes)
        $payload=$text|ConvertFrom-Json -Depth 30
    }catch{throw 'Forensic payload is not valid UTF-8 JSON.'}
    $schemaKey="$([string]$payload.hosthunter.schema.name)/$([string]$payload.hosthunter.schema.version)"
    if($schemaKey -cnotin $script:HHForensicEventSchemas){throw "Forensic schema '$schemaKey' is not registered."}
    $eventId=[Guid]::Empty;$missionId=[Guid]::Empty
    if(-not [Guid]::TryParseExact([string]$payload.event.id,'D',[ref]$eventId) -or
        -not [Guid]::TryParseExact([string]$payload.hosthunter.collection_run.id,'D',[ref]$missionId)){
        throw 'Forensic payload identifiers are invalid.'
    }
    if([string]$payload.hosthunter.provenance.transport -cne 'powershell7_over_ssh'){
        throw 'Forensic payload provenance must use the managed PowerShell 7 over SSH engine.'
    }
    $schemaRoot=Join-Path $script:HHModuleRoot 'Private/Schemas'
    $schemaFile=switch([string]$payload.hosthunter.schema.name){
        'process.start'{'process-start.v1.schema.json'}
        'process.end'{'process-end.v1.schema.json'}
        'authentication.session.start'{'authentication-session-start.v1.schema.json'}
        'authentication.logon.failure'{'authentication-logon-failure.v1.schema.json'}
        'authentication.session.end'{'authentication-session-end.v1.schema.json'}
        'authentication.session.logoff-initiated'{'authentication-session-logoff-initiated.v1.schema.json'}
        'authentication.explicit-credential-use'{'authentication-explicit-credential-use.v1.schema.json'}
        'authentication.session.special-privileges'{'authentication-session-special-privileges.v1.schema.json'}
        'process.access-token'{'process-access-token.v1.schema.json'}
        'user.effective-rights'{'user-effective-rights.v1.schema.json'}
    }
    if(-not [IO.File]::Exists((Join-Path $schemaRoot $schemaFile))){
        $schemaRoot=[IO.Path]::GetFullPath((Join-Path $script:HHModuleRoot '../../CIM_Specification/schemas'))
    }
    if(-not [IO.File]::Exists((Join-Path $schemaRoot $schemaFile))){throw 'The packaged forensic JSON Schema registry is unavailable.'}
    if($null -eq ('Json.Schema.JsonSchema' -as [type])){throw 'The packaged JSON Schema 2020-12 validator is unavailable.'}
    $options=[Json.Schema.EvaluationOptions]::new();$options.OutputFormat=[Json.Schema.OutputFormat]::List;$options.RequireFormatValidation=$true
    foreach($name in @('forensic-event-envelope.v1.schema.json','authentication-common.v1.schema.json',$schemaFile)|Select-Object -Unique){
        $candidate=[Json.Schema.JsonSchema]::FromText([IO.File]::ReadAllText((Join-Path $schemaRoot $name)))
        $options.SchemaRegistry.Register($candidate)
        if($name -ceq $schemaFile){$schema=$candidate}
    }
    try{$node=[Text.Json.Nodes.JsonNode]::Parse($PayloadBytes)}catch [Text.Json.JsonException]{throw 'Forensic payload is not valid UTF-8 JSON.'}
    $evaluation=$schema.Evaluate($node,$options)
    if(-not $evaluation.IsValid){
        $locations=@(
            $evaluation.Details | Where-Object {
                -not $_.IsValid -and $null -ne $_.Errors -and $_.Errors.Count -gt 0
            } | ForEach-Object {
                [string]$_.InstanceLocation
            } | Sort-Object -Unique | Select-Object -First 8
        )
        throw "Forensic payload does not conform to '$schemaKey'. Invalid location(s): $($locations -join ', ')."
    }
    if($schemaKey -ceq 'process.end/1.0.0'){
        $processEnd=Get-HHDataValue -Data $payload.process -Name end
        $eventTime=Get-HHDataValue -Data $payload -Name '@timestamp'
        if((ConvertTo-HHCimUtcText ([DateTimeOffset]$processEnd)) -cne
            (ConvertTo-HHCimUtcText ([DateTimeOffset]$eventTime))){
            throw "Forensic payload does not conform to '$schemaKey'. process.end must equal @timestamp."
        }
    }
    $payload
}

function Get-HHForensicCursorPosition {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Collection,
        [Parameter(Mandatory)][object]$Target,
        [Parameter(Mandatory)][string]$SourceName,
        [AllowNull()][Nullable[DateTimeOffset]]$ExplicitSince
    )
    if($null -ne $ExplicitSince){
        return [pscustomobject]@{Since=[DateTimeOffset]$ExplicitSince;AfterRecordId=$null}
    }
    $read=Open-HHAuthenticatedPersistence -PersistenceContext $Collection.Runtime
    try{
        $cursor=Get-HHForensicCollectionCursor -Connection $read.Connection -Transaction $null `
            -TargetNameKey $Target.Name.ToUpperInvariant() -SourceName $SourceName
        if($null -ne $cursor){
            $recordId=0L
            if(-not [long]::TryParse(
                    [string]$cursor.RecordId,
                    [Globalization.NumberStyles]::None,
                    [Globalization.CultureInfo]::InvariantCulture,
                    [ref]$recordId
                )){throw 'The saved Windows Security-event cursor is invalid.'}
            return [pscustomobject]@{
                Since=[DateTimeOffset]$cursor.OccurredAtUtc
                AfterRecordId=$recordId
            }
        }
    }finally{Close-HHAuthenticatedPersistence -Context $read}
    $start=if($null -ne $Target.LastValidatedAtUtc){
        [DateTimeOffset]$Target.LastValidatedAtUtc
    }else{[DateTimeOffset]::UtcNow.AddMinutes(-5)}
    [pscustomobject]@{Since=$start;AfterRecordId=$null}
}

function New-HHWindowsSecurityEventFilterXPath {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Builds and returns a read-only Windows Event Log XPath filter.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateCount(1,16)][int[]]$EventId,
        [Parameter(Mandatory)][DateTimeOffset]$Since,
        [AllowNull()][Nullable[DateTimeOffset]]$Until,
        [AllowNull()][Nullable[long]]$AfterRecordId
    )
    $eventClause=@($EventId|Sort-Object -Unique|ForEach-Object{"EventID=$_"}) -join ' or '
    $predicates=[Collections.Generic.List[string]]::new()
    $predicates.Add("Provider[@Name='Microsoft-Windows-Security-Auditing']")
    $predicates.Add("($eventClause)")
    $predicates.Add("TimeCreated[@SystemTime>='$(ConvertTo-HHCimUtcText $Since)']")
    if($null -ne $Until){
        $predicates.Add("TimeCreated[@SystemTime<='$(ConvertTo-HHCimUtcText ([DateTimeOffset]$Until))']")
    }
    if($null -ne $AfterRecordId){
        $predicates.Add("EventRecordID>$([long]$AfterRecordId)")
    }
    "*[System[$($predicates -join ' and ')]]"
}

function Invoke-HHForensicRemoteCollection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Target,
        [Parameter(Mandatory)][string]$Operation,
        [Parameter(Mandatory)][string]$Command,
        [Parameter(Mandatory)][scriptblock]$RemoteScriptBlock,
        [AllowEmptyCollection()][object[]]$RemoteArgumentList=@(),
        [ValidateRange(1,8)][int]$ThrottleLimit=8,[string]$Reason,[string]$CaseId
    )
    $augmenter={
        param($SelectedTarget,$TransportResult,$CommandResult)
        if($TransportResult.Succeeded){
            $values=@($CommandResult.StreamEvents|Where-Object{$_.Phase -ceq 'Command' -and $_.Stream -ceq 'Output'}|ForEach-Object Value)
            if($values.Count -ne 1){throw "Forensic collection for '$($SelectedTarget.Name)' returned an invalid finite result."}
            $TransportResult|Add-Member NoteProperty ForensicRaw $values[0]
        }
        $TransportResult
    }
    @(Invoke-HHManagedHostCommandCoordinator -Command $Command -Target @($Target.Name) `
        -ThrottleLimit $ThrottleLimit -Reason $Reason -CaseId $CaseId -Operation $Operation `
        -RemoteScriptBlock $RemoteScriptBlock -RemoteArgumentList $RemoteArgumentList `
        -TransportResultAugmenter $augmenter)[0]
}

function Get-HHForensicSourceIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Kind,
        [Parameter(Mandatory)][object]$Raw,
        [Parameter(Mandatory)][string]$HostName
    )
    switch($Kind){
        'Security'{
            return [pscustomobject]@{
                Provider='Microsoft-Windows-Security-Auditing';Channel='Security'
                EventCode=[string]$Raw.EventId;EventVersion=[int]$Raw.Version
                RecordId=[string]$Raw.RecordId
                Timestamp=[DateTimeOffset]$Raw.TimeCreated
            }
        }
        'ProcessToken'{
            $when=[DateTimeOffset]$Raw.ObservedAtUtc
            return [pscustomobject]@{
                Provider='Microsoft Windows API';Channel='AccessToken'
                EventCode='primary-process-token';EventVersion=1
                RecordId="$HostName`:$($Raw.ProcessId):$(ConvertTo-HHCimUtcText $when)"
                Timestamp=$when
            }
        }
        'EffectiveRights'{
            $when=[DateTimeOffset]$Raw.ObservedAtUtc;$sid=Get-HHDataValue $Raw.User Id
            return [pscustomobject]@{
                Provider='HostHunter';Channel='EffectiveUserRights'
                EventCode='target-host-policy';EventVersion=1
                RecordId="$HostName`:$sid`:$(ConvertTo-HHCimUtcText $when)"
                Timestamp=$when
            }
        }
    }
}

function Save-HHForensicTransportResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Collection,[Parameter(Mandatory)][object]$Target,
        [Parameter(Mandatory)][object]$Transport,[Parameter(Mandatory)][ValidateSet('Security','ProcessToken','EffectiveRights')][string]$Kind,
        [AllowNull()][object]$Cursor,[scriptblock]$ProducerSender
    )
    if(-not $Transport.Succeeded){return $Transport}
    $rawEnvelope=$Transport.ForensicRaw
    $records=@($rawEnvelope.Records)
    $hasMore=[bool](Get-HHDataValue $rawEnvelope HasMore)
    if($records.Count -eq 0){
        return [pscustomobject][ordered]@{Target=$Target.Name;Status=[string]$rawEnvelope.Status;HasMore=$hasMore;Issues=@($rawEnvelope.Issues);Events=@()}
    }
    $write=Open-HHAuthenticatedPersistence -PersistenceContext $Collection.Runtime -OperationLock -AllowAnchorAdvance
    try{
        $data=[pscustomobject]@{Records=$records;Kind=$Kind;Target=$Target;Transport=$Transport;Collection=$Collection;Cursor=$Cursor}
        $stored=Invoke-HHAnchoredPersistenceTransaction -Context $write -ArgumentList @($data) -Action {
            param($Connection,$Transaction,$WriterContext,$ArgumentList)
            $d=$ArgumentList[0]
            $identity=Resolve-HHVisualizerEndpointIdentity -Connection $Connection -Transaction $Transaction `
                -MasterKey $WriterContext.MasterKey -TargetName $d.Target.Name `
                -NativeIdentityDigest $null -ObservedAtUtc ([DateTimeOffset]$d.Transport.ForensicRaw.ObservedAtUtc)
            $items=[Collections.Generic.List[object]]::new();$payloads=[Collections.Generic.List[object]]::new()
            foreach($raw in $d.Records){
                $source=Get-HHForensicSourceIdentity -Kind $d.Kind -Raw $raw -HostName $d.Target.HostName
                $eventId=New-HHForensicEventIdentity -EndpointId $identity.EndpointId -Provider $source.Provider `
                    -Channel $source.Channel -EventCode $source.EventCode -EventVersion $source.EventVersion `
                    -RecordId $source.RecordId -Timestamp $source.Timestamp
                $context=[pscustomobject]@{
                    MissionId=$d.Collection.MissionId;EventId=$eventId
                    EndpointId=$identity.EndpointId;HostName=$d.Target.HostName
                    AgentId=$d.Collection.AgentId
                    AgentVersion=$d.Collection.AgentVersion
                    CollectedAtUtc=[DateTimeOffset]$d.Transport.ForensicRaw.ObservedAtUtc
                }
                $payload=switch($d.Kind){
                    'Security'{ConvertTo-HHSecurityEventRecord -InputObject $raw -Context $context}
                    'ProcessToken'{ConvertTo-HHProcessTokenRecord -InputObject $raw -Context $context}
                    'EffectiveRights'{Resolve-HHEffectiveRightsRecord -InputObject $raw -Context $context}
                }
                $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($payload|ConvertTo-Json -Compress -Depth 30))
                Assert-HHForensicPayloadSchema -PayloadBytes $bytes|Out-Null
                $items.Add([pscustomobject]@{
                        EventId=$eventId;MissionId=$d.Collection.MissionId
                        TargetNameKey=$identity.TargetNameKey
                        EndpointId=$identity.EndpointId
                        SchemaName=[string]$payload.hosthunter.schema.name
                        OccurredAtUtc=$source.Timestamp
                        CollectedAtUtc=[DateTimeOffset]$d.Transport.ForensicRaw.ObservedAtUtc
                        PayloadBytes=$bytes
                    })
                $payloads.Add([pscustomobject]@{Payload=$payload;PayloadBytes=$bytes;EventId=$eventId})
            }
            $cursorData=if($null -eq $d.Cursor){
                $null
            }else{
                [pscustomobject]@{
                    TargetNameKey=$identity.TargetNameKey
                    SourceName=$d.Cursor.SourceName
                    OccurredAtUtc=$d.Cursor.OccurredAtUtc
                    RecordId=$d.Cursor.RecordId
                }
            }
            $receipts=@(Add-HHVisualizerForensicEventBatch -Connection $Connection -Transaction $Transaction `
                -MasterKey $WriterContext.MasterKey -CurrentSnapshot $WriterContext.VisualizerSnapshot `
                -ForensicEvent @($items) -Cursor $cursorData)
            for($index=0;$index -lt $payloads.Count;$index++){
                $payloads[$index]|Add-Member NoteProperty Created ([bool]$receipts[$index].Created)
            }
            [pscustomobject]@{Payloads=@($payloads);Receipts=$receipts}
        }
    }finally{Close-HHAuthenticatedPersistence -Context $write}
    $output=[Collections.Generic.List[object]]::new()
    foreach($item in @($stored.Payloads)){
        $delivery=if(-not $item.Created){
            [pscustomobject]@{
                Delivered=$false;StatusCode=$null;FailureKind='AlreadyRecorded'
            }
        }elseif($Collection.PublishingEnabled){
            Send-HHVisualizerForensicEvent -MissionId $Collection.MissionId `
                -EventId $item.EventId -PayloadBytes $item.PayloadBytes `
                -RequestSender $ProducerSender
        }else{
            [pscustomobject]@{
                Delivered=$false;StatusCode=$null;FailureKind='PublishingPaused'
            }
        }
        if($item.Created -and $Collection.PublishingEnabled){
            $deliveryWrite=Open-HHAuthenticatedPersistence -PersistenceContext $Collection.Runtime -OperationLock -AllowAnchorAdvance
            try{
                $deliveryData=[pscustomobject]@{Id=([Guid]$item.EventId).ToByteArray();Delivery=$delivery;At=[DateTimeOffset]::UtcNow}
                Invoke-HHAnchoredPersistenceTransaction -Context $deliveryWrite -ArgumentList @($deliveryData) -Action {
                    param($Connection,$Transaction,$WriterContext,$ArgumentList);$d=$ArgumentList[0]
                    Set-HHVisualizerDeliveryResult -Connection $Connection -Transaction $Transaction `
                        -MasterKey $WriterContext.MasterKey -CurrentSnapshot $WriterContext.VisualizerSnapshot `
                        -Kind Forensic -Id $d.Id -Delivered ([bool]$d.Delivery.Delivered) `
                        -StatusCode $d.Delivery.StatusCode -AttemptedAtUtc $d.At
                }|Out-Null
            }finally{Close-HHAuthenticatedPersistence -Context $deliveryWrite}
        }
        $item.Payload|Add-Member NoteProperty VisualizerDelivered ([bool]$delivery.Delivered)
        $item.Payload|Add-Member NoteProperty VisualizerPublishingState $(if($Collection.PublishingEnabled){'Enabled'}else{'Paused'})
        $item.Payload|Add-Member NoteProperty CollectionHasMore $hasMore
        $output.Add($item.Payload)
    }
    @($output)
}

function Invoke-HHManagedHostSecurityEventOperation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet(
            'GetProcessStartEvents','GetProcessEndEvents','GetAuthenticationEvents'
        )][string]$Operation,
        [ValidateCount(1,8)][string[]]$Name,[DateTimeOffset]$Since,[DateTimeOffset]$Until,
        [ValidateRange(1,500)][int]$First=100,[ValidateRange(1,8)][int]$ThrottleLimit=8,
        [string]$Reason,[string]$CaseId,[scriptblock]$ProducerSender
    )
    $collection=Get-HHForensicCollectionContext -Name $Name
    Assert-HHForensicVisualizerCapability -Collection $collection -ProducerSender $ProducerSender
    $definition=switch($Operation){
        'GetProcessStartEvents'{[pscustomobject]@{Ids=@(4688);Source='windows.security.process-start'}}
        'GetProcessEndEvents'{[pscustomobject]@{Ids=@(4689);Source='windows.security.process-end'}}
        default{[pscustomobject]@{Ids=@(4624,4625,4634,4647,4648,4672);Source='windows.security.authentication'}}
    }
    $sourceName=$definition.Source
    $output=[Collections.Generic.List[object]]::new();$remote=Get-HHWindowsSecurityEventsRemoteScriptBlock
    foreach($target in $collection.Targets){
        $position=Get-HHForensicCursorPosition -Collection $collection -Target $target -SourceName $sourceName `
            -ExplicitSince $(if($PSBoundParameters.ContainsKey('Since')){[Nullable[DateTimeOffset]]$Since}else{$null})
        $filterXPath=New-HHWindowsSecurityEventFilterXPath -EventId $definition.Ids `
            -Since $position.Since `
            -Until $(if($PSBoundParameters.ContainsKey('Until')){[Nullable[DateTimeOffset]]$Until}else{$null}) `
            -AfterRecordId $(if($null -ne $position.AfterRecordId){[Nullable[long]]$position.AfterRecordId}else{$null})
        $transport=Invoke-HHForensicRemoteCollection -Target $target -Operation $Operation `
            -Command "Collect bounded $sourceName records" -RemoteScriptBlock $remote `
            -RemoteArgumentList @($filterXPath,$First) `
            -ThrottleLimit $ThrottleLimit -Reason $Reason -CaseId $CaseId
        $records=@(if($transport.Succeeded){@($transport.ForensicRaw.Records)}else{@()})
        $cursor=if($records.Count -eq 0){$null}else{
            $last=@($records|Sort-Object {[DateTimeOffset]$_.TimeCreated},{[long]$_.RecordId})[-1]
            [pscustomobject]@{SourceName=$sourceName;OccurredAtUtc=[DateTimeOffset]$last.TimeCreated;RecordId=[string]$last.RecordId}
        }
        foreach($item in @(Save-HHForensicTransportResult `
                    -Collection $collection -Target $target -Transport $transport `
                    -Kind Security -Cursor $cursor -ProducerSender $ProducerSender)){
            $output.Add($item)
        }
    }
    @($output)
}

function Invoke-HHManagedHostGetProcessStartEventsOperation {
    [CmdletBinding()]
    param(
        [string[]]$Name,[DateTimeOffset]$Since,[DateTimeOffset]$Until,
        [int]$First=100,[int]$ThrottleLimit=8,
        [string]$Reason,[string]$CaseId,[scriptblock]$ProducerSender
    )
    Invoke-HHManagedHostSecurityEventOperation @PSBoundParameters -Operation GetProcessStartEvents
}
function Invoke-HHManagedHostGetProcessEndEventsOperation {
    [CmdletBinding()]
    param(
        [string[]]$Name,[DateTimeOffset]$Since,[DateTimeOffset]$Until,
        [int]$First=100,[int]$ThrottleLimit=8,
        [string]$Reason,[string]$CaseId,[scriptblock]$ProducerSender
    )
    Invoke-HHManagedHostSecurityEventOperation @PSBoundParameters -Operation GetProcessEndEvents
}
function Invoke-HHManagedHostGetAuthenticationEventsOperation {
    [CmdletBinding()]
    param(
        [string[]]$Name,[DateTimeOffset]$Since,[DateTimeOffset]$Until,
        [int]$First=100,[int]$ThrottleLimit=8,
        [string]$Reason,[string]$CaseId,[scriptblock]$ProducerSender
    )
    Invoke-HHManagedHostSecurityEventOperation @PSBoundParameters -Operation GetAuthenticationEvents
}

function Invoke-HHManagedHostGetProcessAccessTokenOperation {
    [CmdletBinding(DefaultParameterSetName='ProcessId')]
    param(
        [string[]]$Name,
        [Parameter(Mandatory,ParameterSetName='ProcessId')][uint32[]]$ProcessId,
        [Parameter(Mandatory,ParameterSetName='ProcessName')][string[]]$ProcessName,
        [int]$ThrottleLimit=8,[string]$Reason,[string]$CaseId,
        [scriptblock]$ProducerSender
    )
    $collection=Get-HHForensicCollectionContext -Name $Name
    Assert-HHForensicVisualizerCapability `
        -Collection $collection -ProducerSender $ProducerSender
    $selectorType=$PSCmdlet.ParameterSetName
    $selector=if($selectorType -ceq 'ProcessId'){@($ProcessId)}else{@($ProcessName)}
    $remote=Get-HHWindowsProcessTokenRemoteScriptBlock;$output=[Collections.Generic.List[object]]::new()
    foreach($target in $collection.Targets){
        $transport=Invoke-HHForensicRemoteCollection -Target $target `
            -Operation GetProcessAccessToken `
            -Command 'Collect bounded primary process access-token evidence' `
            -RemoteScriptBlock $remote -RemoteArgumentList @($selectorType,$selector) `
            -ThrottleLimit $ThrottleLimit -Reason $Reason -CaseId $CaseId
        foreach($item in @(Save-HHForensicTransportResult `
                    -Collection $collection -Target $target -Transport $transport `
                    -Kind ProcessToken -ProducerSender $ProducerSender)){
            $output.Add($item)
        }
    }
    @($output)
}

function Invoke-HHManagedHostGetUserEffectiveRightsOperation {
    [CmdletBinding()]
    param(
        [string[]]$Name,[string]$Identity,[int]$ThrottleLimit=8,
        [string]$Reason,[string]$CaseId,[scriptblock]$ProducerSender
    )
    $collection=Get-HHForensicCollectionContext -Name $Name
    Assert-HHForensicVisualizerCapability `
        -Collection $collection -ProducerSender $ProducerSender
    $remote=Get-HHWindowsEffectiveRightsRemoteScriptBlock;$output=[Collections.Generic.List[object]]::new()
    foreach($target in $collection.Targets){
        $requested=if($PSBoundParameters.ContainsKey('Identity')){$Identity}else{[string]$target.UserName}
        $transport=Invoke-HHForensicRemoteCollection -Target $target `
            -Operation GetUserEffectiveRights `
            -Command 'Collect bounded effective user-right evidence' `
            -RemoteScriptBlock $remote -RemoteArgumentList @($requested) `
            -ThrottleLimit $ThrottleLimit -Reason $Reason -CaseId $CaseId
        foreach($item in @(Save-HHForensicTransportResult `
                    -Collection $collection -Target $target -Transport $transport `
                    -Kind EffectiveRights -ProducerSender $ProducerSender)){
            $output.Add($item)
        }
    }
    @($output)
}
