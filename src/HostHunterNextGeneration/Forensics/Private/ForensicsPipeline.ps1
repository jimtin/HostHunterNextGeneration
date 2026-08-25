Set-StrictMode -Version Latest

function Test-HHForensicsCommandLinePrivacyWarningRequired {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][object]$EcsEvent)

    return $EcsEvent.event.kind -ceq 'event' -and
        (Get-HHForensicsContractKey -Value $EcsEvent.process) -contains 'command_line'
}

function ConvertTo-HHForensicsCanonicalEcsEvent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$EcsEvent,
        [Parameter(Mandatory)][long]$Ordinal
    )

    [void](Test-HHEcsProcessStartContract -Event $EcsEvent)
    $json = $EcsEvent | ConvertTo-Json -Depth 100 -Compress
    $bytes = [Text.UTF8Encoding]::new($false, $true).GetBytes($json)
    return [pscustomobject]@{
        EventId = [string]$EcsEvent.event.id
        SourceKey = [string]$EcsEvent.hosthunter.evidence.source_identity
        Ordinal = $Ordinal
        OccurredAtUtc = [string]$EcsEvent.'@timestamp'
        BodyBytes = $bytes
    }
}

function Split-HHForensicsCanonicalEventBatch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RunId,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$CanonicalEvents
    )

    $batches = [Collections.Generic.List[object]]::new()
    $current = [Collections.Generic.List[object]]::new()
    foreach ($canonicalEvent in @($CanonicalEvents)) {
        $candidate = @($current) + @($canonicalEvent)
        $fits = $candidate.Count -le 250
        if ($fits) {
            $candidateBody = New-HHForensicsCanonicalBatchBody `
                -RunId $RunId -CreationOrder $batches.Count -CanonicalEvents $candidate
            try { $fits = $candidateBody.Length -le 524288 }
            finally { [Array]::Clear($candidateBody, 0, $candidateBody.Length) }
        }
        if (-not $fits) {
            if ($current.Count -eq 0) {
                Stop-HHForensicsOperation -ErrorId ForensicsBatchRejected `
                    -Message 'One canonical ECS event exceeds the bounded delivery batch size.' `
                    -Category LimitsExceeded -TargetObject $canonicalEvent.EventId
            }
            $batches.Add([pscustomobject]@{ Events = @($current) })
            $current.Clear()
        }
        $current.Add($canonicalEvent)
    }
    if ($current.Count -gt 0) {
        $batches.Add([pscustomobject]@{ Events = @($current) })
    }
    return @($batches)
}

function Invoke-HHForensicsLocalProcessStartPipeline {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Private coordinator; any future public caller owns ShouldProcess.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$EvidencePath,
        [Parameter(Mandatory)][ValidatePattern('^[a-fA-F0-9]{64}$')]
        [string]$ExpectedEvidenceSha256,
        [Parameter(Mandatory)][object]$PersistenceContext,
        [Parameter(Mandatory)][scriptblock]$ForensicsKeyProvider,
        [Parameter(Mandatory)][scriptblock]$AnchorReader,
        [Parameter(Mandatory)][scriptblock]$AnchorWriter,
        [Parameter(Mandatory)][string]$RunId,
        [Parameter(Mandatory)][object]$EventContext,
        [object]$Parser,
        [string]$StagingRoot,
        [string]$BaseUri,
        [AllowNull()][scriptblock]$AccessTokenProvider,
        [AllowNull()][scriptblock]$Transport
    )

    if ([string]::IsNullOrWhiteSpace($RunId)) {
        throw [ArgumentException]::new('A local Process Start pipeline requires a run ID.')
    }
    if ($null -eq $Parser) { $Parser = Resolve-HHForensicsEvtxParser }
    $records = [Collections.Generic.List[object]]::new()
    $consumer = { param($Record) $records.Add($Record) }.GetNewClosure()
    $parsed = Invoke-HHForensicsEvtxParser -EvidencePath $EvidencePath `
        -ExpectedEvidenceSha256 $ExpectedEvidenceSha256 -Parser $Parser `
        -RecordConsumer $consumer -StagingRoot $StagingRoot

    $canonicalEvents = [Collections.Generic.List[object]]::new()
    $commandLineWarningRequired = $false
    foreach ($record in $records) {
        $ecsEvent = ConvertTo-HHEcsProcessStartEvent -Record $record -Context $EventContext
        if ($null -eq $ecsEvent) { continue }
        if (Test-HHForensicsCommandLinePrivacyWarningRequired -EcsEvent $ecsEvent) {
            $commandLineWarningRequired = $true
        }
        $canonicalEvents.Add((ConvertTo-HHForensicsCanonicalEcsEvent `
                    -EcsEvent $ecsEvent -Ordinal ($canonicalEvents.Count + 1L)))
    }
    if ($commandLineWarningRequired) {
        Write-Warning (
            'Process command lines may contain plaintext credentials or personal data. ' +
            'HostHunter preserves them only in protected forensic event storage.'
        )
    }

    $context = $null
    $batchReceipts = [Collections.Generic.List[object]]::new()
    try {
        $context = Open-HHForensicsPersistence `
            -PersistenceContext $PersistenceContext `
            -ForensicsKeyProvider $ForensicsKeyProvider `
            -AnchorReader $AnchorReader -AnchorWriter $AnchorWriter `
            -AllowAnchorInitialize -AllowAnchorAdvance
        $batches = @(Split-HHForensicsCanonicalEventBatch `
                -RunId $RunId -CanonicalEvents @($canonicalEvents))
        for ($index = 0; $index -lt $batches.Count; $index++) {
            $resourceKey = "event-batch:${RunId}:$index"
            $resourceUri = "/v1/event-batches/$RunId/$index"
            $receipt = Write-HHForensicsEventBatch -Context $context -RunId $RunId `
                -ResourceKey $resourceKey -IdempotencyKey $resourceKey `
                -ResourceUri $resourceUri -CanonicalEvents @($batches[$index].Events) `
                -CreationOrder $index
            $delivery = $null
            if (-not [string]::IsNullOrWhiteSpace($BaseUri)) {
                if ($null -eq $AccessTokenProvider) {
                    throw [ArgumentException]::new(
                        'API delivery requires an explicit access-token provider.'
                    )
                }
                $delivery = Invoke-HHForensicsOutboxDelivery -Context $context `
                    -BaseUri $BaseUri -AccessTokenProvider $AccessTokenProvider `
                    -ResourceKey $resourceKey -Transport $Transport
            }
            $batchReceipts.Add([pscustomobject]@{
                    ResourceKey = $resourceKey
                    EventCount = @($batches[$index].Events).Count
                    Status = if ($null -eq $delivery) { 'PREPARED' } else { $delivery.Status }
                })
            $null = $receipt
        }
    }
    finally {
        foreach ($canonicalEvent in $canonicalEvents) {
            [Array]::Clear($canonicalEvent.BodyBytes, 0, $canonicalEvent.BodyBytes.Length)
        }
        if ($null -ne $context) { Close-HHForensicsPersistence -Context $context }
    }
    return [pscustomobject]@{
        Marker = 'HostHunter.Forensics.LocalProcessStartPipeline.v1'
        RunId = $RunId
        ParsedRecordCount = $parsed.Records
        CanonicalEventCount = $canonicalEvents.Count
        BatchCount = $batchReceipts.Count
        Batches = @($batchReceipts)
        CommandLinePrivacyWarningIssued = $commandLineWarningRequired
        PlaintextParserArtifactCreated = $parsed.PlaintextOutputArtifact
    }
}
