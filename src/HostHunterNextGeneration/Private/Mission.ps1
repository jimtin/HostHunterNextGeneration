Set-StrictMode -Version Latest

function Get-HHModuleVersionText {
    [CmdletBinding()]
    param()
    $manifest = Import-PowerShellDataFile -LiteralPath (
        Join-Path $script:HHModuleRoot 'HostHunterNextGeneration.psd1'
    )
    [string]$manifest.ModuleVersion
}

function Get-HHCurrentMissionId {
    [CmdletBinding()]
    param()
    $runtime = Get-HHRuntimeContext
    $context = Open-HHAuthenticatedPersistence -PersistenceContext $runtime
    try {
        if ($null -eq $context.VisualizerSnapshot.CurrentMissionId) { return $null }
        [Guid]::new([byte[]]$context.VisualizerSnapshot.CurrentMissionId)
    }
    finally { Close-HHAuthenticatedPersistence -Context $context }
}

function Get-HHLocalMissionState {
    [CmdletBinding()]
    param()
    $runtime = Get-HHRuntimeContext
    $context = Open-HHAuthenticatedPersistence -PersistenceContext $runtime
    try {
        $current = if ($null -eq $context.VisualizerSnapshot.CurrentMissionId) { $null } else {
            [Guid]::new([byte[]]$context.VisualizerSnapshot.CurrentMissionId)
        }
        $latest = Get-HHLatestVisualizerMissionRecord -Connection $context.Connection -Transaction $null
        [pscustomobject]@{
            PublishingState = if ($null -eq $current) { 'Paused' } else { 'Enabled' }
            CurrentMissionId = $current
            LatestMissionId = if ($null -eq $latest) { $null } else {
                [Guid]::new([byte[]]$latest.MissionId)
            }
        }
    }
    finally { Close-HHAuthenticatedPersistence -Context $context }
}

function Set-HHCurrentMissionCore {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Private mission state transition is owned by the lifecycle coordinator.'
    )]
    [CmdletBinding()]
    param([AllowNull()][Nullable[Guid]]$MissionId, [switch]$Reconciled)

    $runtime = Get-HHRuntimeContext
    $context = Open-HHAuthenticatedPersistence -PersistenceContext $runtime `
        -OperationLock -AllowAnchorAdvance
    try {
        $idBytes = if ($null -eq $MissionId) { $null } else { ([Guid]$MissionId).ToByteArray() }
        $data = [pscustomobject]@{ Id=$idBytes; Reconciled=[bool]$Reconciled; At=[DateTimeOffset]::UtcNow }
        Invoke-HHAnchoredPersistenceTransaction -Context $context -ArgumentList @($data) -Action {
            param($Connection,$Transaction,$WriterContext,$ArgumentList)
            $item = $ArgumentList[0]
            if ($item.Reconciled) {
                Set-HHVisualizerMissionReconciled -Connection $Connection -Transaction $Transaction `
                    -MasterKey $WriterContext.MasterKey -CurrentSnapshot $WriterContext.VisualizerSnapshot `
                    -MissionId $item.Id -ReconciledAtUtc $item.At
            }
            else {
                Set-HHVisualizerCurrentMission -Connection $Connection -Transaction $Transaction `
                    -MasterKey $WriterContext.MasterKey -CurrentSnapshot $WriterContext.VisualizerSnapshot `
                    -MissionId $item.Id
            }
        } | Out-Null
    }
    finally { Close-HHAuthenticatedPersistence -Context $context }
}

function Start-HHMissionCore {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Private mission creation is owned by the lifecycle coordinator.'
    )]
    [CmdletBinding()]
    param([scriptblock]$ProducerSender)

    $runtime = Get-HHRuntimeContext
    $context = Open-HHAuthenticatedPersistence -PersistenceContext $runtime `
        -OperationLock -AllowAnchorAdvance
    try {
        $missionBytes = [Guid]::NewGuid().ToByteArray()
        $missionId = [Guid]::new($missionBytes)
        $started = [DateTimeOffset]::UtcNow
        $payloadObject = [ordered]@{
            schema_version = '1.0.0'
            collection_run_id = $missionId.ToString('D').ToLowerInvariant()
            started_at = $started.UtcDateTime.ToString('o',[Globalization.CultureInfo]::InvariantCulture)
            producer = [ordered]@{ name='HostHunter'; version=(Get-HHModuleVersionText) }
        }
        $payloadBytes = [Text.UTF8Encoding]::new($false).GetBytes(
            ($payloadObject | ConvertTo-Json -Compress -Depth 5)
        )
        $data = [pscustomobject]@{ MissionId=$missionBytes; Started=$started; Payload=$payloadBytes }
        $stored = Invoke-HHAnchoredPersistenceTransaction -Context $context `
            -ArgumentList @($data) -Action {
            param($Connection,$Transaction,$WriterContext,$ArgumentList)
            $inputData=$ArgumentList[0]
            Add-HHVisualizerMission -Connection $Connection -Transaction $Transaction `
                -MasterKey $WriterContext.MasterKey -CurrentSnapshot $WriterContext.VisualizerSnapshot `
                -MissionId $inputData.MissionId -ActivationId $null `
                -StartedAtUtc $inputData.Started -PayloadBytes $inputData.Payload
        }
    }
    finally { Close-HHAuthenticatedPersistence -Context $context }

    $delivery = Send-HHVisualizerMission -MissionId $missionId `
        -PayloadBytes ([byte[]]$stored.PayloadBytes) -Sender $ProducerSender
    $write = Open-HHAuthenticatedPersistence -PersistenceContext $runtime `
        -OperationLock -AllowAnchorAdvance
    try {
        $deliveryData=[pscustomobject]@{ Id=$missionBytes; Delivery=$delivery; At=[DateTimeOffset]::UtcNow }
        Invoke-HHAnchoredPersistenceTransaction -Context $write `
            -ArgumentList @($deliveryData) -Action {
            param($Connection,$Transaction,$WriterContext,$ArgumentList)
            $d=$ArgumentList[0]
            Set-HHVisualizerDeliveryResult -Connection $Connection -Transaction $Transaction `
                -MasterKey $WriterContext.MasterKey -CurrentSnapshot $WriterContext.VisualizerSnapshot `
                -Kind Mission -Id $d.Id -Delivered ([bool]$d.Delivery.Delivered) `
                -StatusCode $d.Delivery.StatusCode -AttemptedAtUtc $d.At
        } | Out-Null
    }
    finally { Close-HHAuthenticatedPersistence -Context $write }

    [pscustomobject][ordered]@{
        MissionId=$missionId; StartedAtUtc=$started
        VisualizerDelivered=[bool]$delivery.Delivered; VisualizerStatusCode=$delivery.StatusCode
    }
}

function Invoke-HHPendingVisualizerObservationReplay {
    [CmdletBinding()]
    param([scriptblock]$ProducerSender)

    $runtime = Get-HHRuntimeContext
    $read = Open-HHAuthenticatedPersistence -PersistenceContext $runtime
    try {
        if ($null -eq $read.VisualizerSnapshot.CurrentMissionId) {
            return [pscustomobject]@{ Replayed=0; Remaining=0 }
        }
        $pending = @(Read-HHPendingVisualizerObservations -Connection $read.Connection `
                -Transaction $null -MasterKey $read.MasterKey `
                -MissionId ([byte[]]$read.VisualizerSnapshot.CurrentMissionId) -First 100)
    }
    finally { Close-HHAuthenticatedPersistence -Context $read }

    $replayed = 0
    foreach ($item in $pending) {
        try {
            $delivery = Send-HHVisualizerObservation `
                -MissionId ([Guid]::new([byte[]]$item.MissionId)) `
                -EventId ([Guid]::new([byte[]]$item.EventId)) `
                -PayloadBytes ([byte[]]$item.PayloadBytes) -Sender $ProducerSender
            if (-not $delivery.Delivered) { continue }
            $write = Open-HHAuthenticatedPersistence -PersistenceContext $runtime `
                -OperationLock -AllowAnchorAdvance
            try {
                $data = [pscustomobject]@{
                    EventId=[byte[]]$item.EventId; At=[DateTimeOffset]::UtcNow
                }
                Invoke-HHAnchoredPersistenceTransaction -Context $write `
                    -ArgumentList @($data) -Action {
                    param($Connection,$Transaction,$WriterContext,$ArgumentList)
                    $entry = $ArgumentList[0]
                    Set-HHVisualizerObservationReconciled -Connection $Connection `
                        -Transaction $Transaction -MasterKey $WriterContext.MasterKey `
                        -CurrentSnapshot $WriterContext.VisualizerSnapshot `
                        -EventId $entry.EventId -ReconciledAtUtc $entry.At
                } | Out-Null
            }
            finally { Close-HHAuthenticatedPersistence -Context $write }
            $replayed++
        }
        finally {
            [Array]::Clear([byte[]]$item.PayloadBytes,0,([byte[]]$item.PayloadBytes).Length)
        }
    }
    [pscustomobject]@{ Replayed=$replayed; Remaining=($pending.Count-$replayed) }
}

function Invoke-HHPendingVisualizerForensicEventReplay {
    [CmdletBinding()]
    param([scriptblock]$ProducerSender)
    $runtime=Get-HHRuntimeContext
    $read=Open-HHAuthenticatedPersistence -PersistenceContext $runtime
    try{
        if($null -eq $read.VisualizerSnapshot.CurrentMissionId){return [pscustomobject]@{Replayed=0;Remaining=0}}
        $mission=[byte[]]$read.VisualizerSnapshot.CurrentMissionId
        $pending=@(Read-HHPendingVisualizerForensicEvent -Connection $read.Connection `
            -Transaction $null -MasterKey $read.MasterKey -MissionId $mission -First 100)
    }finally{Close-HHAuthenticatedPersistence -Context $read}
    $replayed=0
    foreach($item in $pending){
        try{
            $delivery=Send-HHVisualizerForensicEvent -MissionId ([Guid]::new($mission)) `
                -EventId $item.EventId -PayloadBytes $item.PayloadBytes -RequestSender $ProducerSender
            if(-not $delivery.Delivered){continue}
            $write=Open-HHAuthenticatedPersistence -PersistenceContext $runtime -OperationLock -AllowAnchorAdvance
            try{
                $data=[pscustomobject]@{Id=$item.EventId.ToByteArray();At=[DateTimeOffset]::UtcNow}
                Invoke-HHAnchoredPersistenceTransaction -Context $write -ArgumentList @($data) -Action {
                    param($Connection,$Transaction,$WriterContext,$ArgumentList);$d=$ArgumentList[0]
                    Set-HHVisualizerForensicEventReconciled -Connection $Connection -Transaction $Transaction `
                        -MasterKey $WriterContext.MasterKey -CurrentSnapshot $WriterContext.VisualizerSnapshot `
                        -EventId $d.Id -ReconciledAtUtc $d.At
                }|Out-Null
            }finally{Close-HHAuthenticatedPersistence -Context $write}
            $replayed++
        }finally{[Array]::Clear([byte[]]$item.PayloadBytes,0,([byte[]]$item.PayloadBytes).Length)}
    }
    [pscustomobject]@{Replayed=$replayed;Remaining=$pending.Count-$replayed}
}

function New-HHVisualizationStartReceipt {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'This private formatter returns a receipt and does not create external state.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Status,
        [Parameter(Mandatory)][Guid]$MissionId,
        [Parameter(Mandatory)][bool]$CreatedNewMission,
        [scriptblock]$ProducerSender
    )
    $replay = Invoke-HHPendingVisualizerObservationReplay -ProducerSender $ProducerSender
    $forensicReplay = Invoke-HHPendingVisualizerForensicEventReplay -ProducerSender $ProducerSender
    [pscustomobject][ordered]@{
        Status=$Status; PublishingState='Enabled'; MissionId=$MissionId
        Connection='authenticated'; CreatedNewMission=$CreatedNewMission
        ReplayedObservations=[int]$replay.Replayed
        PendingObservations=[int]$replay.Remaining
        ReplayedForensicEvents=[int]$forensicReplay.Replayed
        PendingForensicEvents=[int]$forensicReplay.Remaining
    }
}

function Invoke-HHVisualizationLifecycleCore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('status','start','new','pause')][string]$Action,
        [scriptblock]$StatusSender,
        [scriptblock]$ProducerSender
    )

    $local = Get-HHLocalMissionState
    if ($Action -ceq 'pause') {
        Set-HHCurrentMissionCore -MissionId $null
        return [pscustomobject][ordered]@{
            Status='paused'; PublishingState='Paused'; MissionId=$local.CurrentMissionId
        }
    }
    $remote = Invoke-HHVisualizerStatus -Sender $StatusSender
    if ($Action -ceq 'status') {
        return [pscustomobject][ordered]@{
            Status='ready'; PublishingState=$local.PublishingState
            LocalMissionId=$local.CurrentMissionId; LatestLocalMissionId=$local.LatestMissionId
            ActiveMissionId=$remote.ActiveMissionId; Connection='authenticated'
        }
    }
    if ($Action -ceq 'new' -or $null -eq $remote.ActiveMissionId) {
        $mission = Start-HHMissionCore -ProducerSender $ProducerSender
        if (-not $mission.VisualizerDelivered) {
            throw 'The mission was retained locally but the visualizer did not accept it; the prior mission remains selected.'
        }
        return New-HHVisualizationStartReceipt -Status started -MissionId $mission.MissionId `
            -CreatedNewMission $true -ProducerSender $ProducerSender
    }
    if ($local.CurrentMissionId -eq $remote.ActiveMissionId) {
        return New-HHVisualizationStartReceipt -Status continued `
            -MissionId $remote.ActiveMissionId -CreatedNewMission $false `
            -ProducerSender $ProducerSender
    }
    $runtime = Get-HHRuntimeContext
    $context = Open-HHAuthenticatedPersistence -PersistenceContext $runtime
    try {
        $match = Get-HHVisualizerMissionRecord -Connection $context.Connection `
            -Transaction $null -MissionId $remote.ActiveMissionId.ToByteArray()
    }
    finally { Close-HHAuthenticatedPersistence -Context $context }
    if ($null -eq $match) {
        throw 'Visualizer active mission does not exist in HostHunter authenticated state. Refusing to guess or overwrite it.'
    }
    Set-HHCurrentMissionCore -MissionId $remote.ActiveMissionId `
        -Reconciled:($match.DeliveryStatus -ceq 'Pending')
    New-HHVisualizationStartReceipt -Status continued -MissionId $remote.ActiveMissionId `
        -CreatedNewMission $false -ProducerSender $ProducerSender
}
