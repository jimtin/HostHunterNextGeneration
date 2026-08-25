Set-StrictMode -Version Latest

$script:HHEcsVersion = '9.5.0'
$script:HHProcessStartContractVersion = '1.0.0'

function Get-HHForensicsPropertyValue {
    [CmdletBinding()]
    param(
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory)][string]$Name
    )

    if ($null -eq $InputObject) { return $null }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Get-HHForensicsAttributeValue {
    [CmdletBinding()]
    param(
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory)][string]$Name
    )

    $attributes = Get-HHForensicsPropertyValue -InputObject $InputObject -Name '#attributes'
    return Get-HHForensicsPropertyValue -InputObject $attributes -Name $Name
}

function Get-HHForensicsTextValue {
    [CmdletBinding()]
    param([AllowNull()][object]$InputObject)

    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [string] -or $InputObject -is [ValueType]) {
        return [string]$InputObject
    }
    $text = Get-HHForensicsPropertyValue -InputObject $InputObject -Name '#text'
    if ($null -ne $text) { return [string]$text }
    return $null
}

function ConvertTo-HHForensicsEventDataAnalysis {
    [CmdletBinding()]
    param([AllowNull()][object]$EventData)

    $pairs = [Collections.Generic.List[object]]::new()
    $warnings = [Collections.Generic.List[string]]::new()
    $data = Get-HHForensicsPropertyValue -InputObject $EventData -Name 'Data'
    $ordinal = 0
    foreach ($item in @($data)) {
        $ordinal++
        if ($null -eq $item) {
            $pairs.Add([pscustomobject][ordered]@{
                    ordinal = $ordinal; name = $null; value = $null
                })
            $warnings.Add("null_event_data_pair:$ordinal")
            continue
        }
        $name = Get-HHForensicsAttributeValue -InputObject $item -Name 'Name'
        $value = Get-HHForensicsTextValue -InputObject $item
        $pairs.Add([pscustomobject][ordered]@{
                ordinal = $ordinal
                name = if ($null -eq $name) { $null } else { [string]$name }
                value = if ($null -eq $value) { $null } else { [string]$value }
            })
        if ([string]::IsNullOrWhiteSpace([string]$name)) {
            $warnings.Add("unnamed_event_data_pair:$ordinal")
        }
    }
    return [pscustomobject]@{
        Pairs = $pairs.ToArray()
        Warnings = $warnings
        ConsumedNames = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::Ordinal
        )
    }
}

function Get-HHForensicsEventDataValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][psobject]$Analysis,
        [Parameter(Mandatory)][string]$Name
    )

    $projections = @($Analysis.Pairs | Where-Object { $_.name -ceq $Name })
    if ($projections.Count -gt 1) {
        $Analysis.Warnings.Add("duplicate_event_data_name:$Name")
        throw [IO.InvalidDataException]::new(
            "EventData contains duplicate consumed field '$Name'."
        )
    }
    if ($projections.Count -eq 0) { return $null }
    [void]$Analysis.ConsumedNames.Add($Name)
    return $projections[0].value
}

function Complete-HHForensicsEventDataAnalysis {
    [CmdletBinding()]
    param([Parameter(Mandatory)][psobject]$Analysis)

    $unconsumed = [Collections.Generic.List[string]]::new()
    foreach ($pair in $Analysis.Pairs) {
        if (-not [string]::IsNullOrWhiteSpace([string]$pair.name) -and
            -not $Analysis.ConsumedNames.Contains([string]$pair.name)) {
            $unconsumed.Add([string]$pair.name)
        }
    }
    foreach ($name in @($unconsumed | Select-Object -Unique)) {
        $Analysis.Warnings.Add("unconsumed_event_data:$name")
    }
    return [ordered]@{
        pairs = @($Analysis.Pairs)
        unconsumed_names = @($unconsumed | Select-Object -Unique)
        warnings = @($Analysis.Warnings)
    }
}

function ConvertTo-HHForensicsUtcTimestamp {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Value)

    $parsed = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParse(
            $Value,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AssumeUniversal,
            [ref]$parsed
        )) {
        throw [FormatException]::new("The event timestamp '$Value' is invalid.")
    }
    return $parsed.UtcDateTime.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
}

function ConvertTo-HHForensicsProcessId {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Value)

    try {
        if ($Value -match '^0[xX][0-9a-fA-F]+$') {
            return [Convert]::ToUInt64($Value.Substring(2), 16)
        }
        return [Convert]::ToUInt64($Value, [Globalization.CultureInfo]::InvariantCulture)
    }
    catch {
        throw [FormatException]::new("The process id '$Value' is invalid.", $_.Exception)
    }
}

function Get-HHForensicsExecutableName {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $segments = $Path -split '[\\/]'
    return [string]$segments[$segments.Count - 1]
}

function Get-HHForensicsRequiredContextValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][psobject]$Context,
        [Parameter(Mandatory)][string]$Name
    )

    $value = Get-HHForensicsPropertyValue -InputObject $Context -Name $Name
    if ([string]::IsNullOrWhiteSpace([string]$value)) {
        throw [ArgumentException]::new("Forensics normalization context requires '$Name'.")
    }
    return [string]$value
}

function ConvertTo-HHForensicsProvenance {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][psobject]$Record,
        [Parameter(Mandatory)][psobject]$Context,
        [Parameter(Mandatory)][string]$Channel,
        [Parameter(Mandatory)][string]$EventRecordId,
        [Parameter(Mandatory)][string]$Provider,
        [Parameter(Mandatory)][string]$SourceVersion,
        [AllowNull()][psobject]$EventDataAnalysis
    )

    $artifactSha = Get-HHForensicsRequiredContextValue -Context $Context -Name 'ArtifactSha256'
    $evidence = [ordered]@{
        artifact_sha256 = $artifactSha.ToLowerInvariant()
        channel = $Channel
        event_record_id = $EventRecordId
        source_identity = [string]$Record.SourceIdentity
        source_ordinal = [long]$Record.SourceOrdinal
        original_sha256 = [string]$Record.OriginalSha256
        provider = $Provider
        source_version = $SourceVersion
    }
    foreach ($projection in @(
            @{ Context = 'ArtifactId'; Evidence = 'artifact_id' },
            @{ Context = 'EvidenceRelativePath'; Evidence = 'relative_path' }
        )) {
        $value = Get-HHForensicsPropertyValue -InputObject $Context -Name $projection.Context
        if (-not [string]::IsNullOrWhiteSpace([string]$value)) {
            $evidence[$projection.Evidence] = [string]$value
        }
    }

    $provenance = [ordered]@{
        contract = [ordered]@{
            name = 'hosthunter.process_start'
            version = $script:HHProcessStartContractVersion
        }
        evidence = $evidence
        parser = [ordered]@{
            name = 'evtx_dump'
            version = [string](Get-HHForensicsRequiredContextValue -Context $Context -Name 'ParserVersion')
        }
        sensitive_fields = @('event.original', 'process.command_line', 'process.parent.command_line')
    }
    $acquisitionId = Get-HHForensicsPropertyValue -InputObject $Context -Name 'AcquisitionId'
    if (-not [string]::IsNullOrWhiteSpace([string]$acquisitionId)) {
        $provenance.acquisition = [ordered]@{ id = [string]$acquisitionId }
    }
    if ($null -ne $EventDataAnalysis) {
        $provenance.event_data = Complete-HHForensicsEventDataAnalysis `
            -Analysis $EventDataAnalysis
    }
    return $provenance
}

function ConvertTo-HHEcsPipelineErrorEvent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][psobject]$Record,
        [Parameter(Mandatory)][psobject]$Context,
        [Parameter(Mandatory)][string]$Provider,
        [Parameter(Mandatory)][string]$Channel,
        [Parameter(Mandatory)][string]$EventCode,
        [Parameter(Mandatory)][string]$EventRecordId,
        [Parameter(Mandatory)][string]$SourceVersion,
        [Parameter(Mandatory)][string]$ErrorCode,
        [Parameter(Mandatory)][string]$Message,
        [AllowNull()][psobject]$EventDataAnalysis
    )

    $hostId = Get-HHForensicsRequiredContextValue -Context $Context -Name 'HostId'
    $artifactSha = Get-HHForensicsRequiredContextValue -Context $Context -Name 'ArtifactSha256'
    $runStartedAt = ConvertTo-HHForensicsUtcTimestamp -Value (
        Get-HHForensicsRequiredContextValue -Context $Context -Name 'RunStartedAt'
    )
    $eventId = Get-HHForensicsLengthFramedSha256 -Value @(
        'hosthunter.pipeline-error.v1',
        $artifactSha.ToLowerInvariant(),
        $Record.SourceIdentity,
        $Record.SourceOrdinal,
        $Record.OriginalSha256,
        $ErrorCode
    )
    $hostName = Get-HHForensicsPropertyValue -InputObject $Context -Name 'HostName'

    $pipelineEvent = [pscustomobject][ordered]@{
        '@timestamp' = $runStartedAt
        ecs = [ordered]@{ version = $script:HHEcsVersion }
        event = [ordered]@{
            action = 'process-start-normalization-failed'
            category = @('process')
            code = $EventCode
            id = $eventId
            kind = 'pipeline_error'
            module = 'hosthunter'
            original = [string]$Record.Original
            provider = $Provider
        }
        error = [ordered]@{
            code = $ErrorCode
            message = $Message
            type = 'HostHunter.ProcessStartNormalizationError'
        }
        host = [ordered]@{
            id = $hostId
            name = if ([string]::IsNullOrWhiteSpace([string]$hostName)) { 'unknown' } else { [string]$hostName }
            os = [ordered]@{ type = 'windows' }
        }
        hosthunter = ConvertTo-HHForensicsProvenance -Record $Record -Context $Context `
            -Channel $Channel -EventRecordId $EventRecordId -Provider $Provider `
            -SourceVersion $SourceVersion -EventDataAnalysis $EventDataAnalysis
    }
    [void](Test-HHEcsProcessStartContract -Event $pipelineEvent)
    return $pipelineEvent
}

function ConvertTo-HHEcsProcessStartEvent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][psobject]$Record,
        [Parameter(Mandatory)][psobject]$Context
    )

    if ($Record.Marker -cne 'HostHunter.Forensics.JsonlRecord.v2') {
        throw [IO.InvalidDataException]::new('The input is not a HostHunter parser JSONL record.')
    }
    foreach ($field in @('HostId', 'ArtifactSha256', 'ParserVersion', 'RunStartedAt')) {
        [void](Get-HHForensicsRequiredContextValue -Context $Context -Name $field)
    }
    $artifactIdentity = Get-HHForensicsRequiredContextValue `
        -Context $Context -Name 'ArtifactSha256'
    if ($Record.SourceIdentity -cne $artifactIdentity.ToLowerInvariant()) {
        throw [Security.SecurityException]::new(
            'The parser record source identity does not match the admitted evidence artifact.'
        )
    }

    $eventRoot = Get-HHForensicsPropertyValue -InputObject $Record.Data -Name 'Event'
    $system = Get-HHForensicsPropertyValue -InputObject $eventRoot -Name 'System'
    $providerNode = Get-HHForensicsPropertyValue -InputObject $system -Name 'Provider'
    $provider = [string](Get-HHForensicsAttributeValue -InputObject $providerNode -Name 'Name')
    $eventCode = Get-HHForensicsTextValue -InputObject (
        Get-HHForensicsPropertyValue -InputObject $system -Name 'EventID'
    )
    $channel = [string](Get-HHForensicsTextValue -InputObject (
            Get-HHForensicsPropertyValue -InputObject $system -Name 'Channel'
        ))

    $isSysmon = $provider -ceq 'Microsoft-Windows-Sysmon' -and $eventCode -ceq '1'
    $isSecurity = $provider -ceq 'Microsoft-Windows-Security-Auditing' -and $eventCode -ceq '4688'
    if (-not $isSysmon -and -not $isSecurity) { return $null }

    $version = Get-HHForensicsTextValue -InputObject (
        Get-HHForensicsPropertyValue -InputObject $system -Name 'Version'
    )
    $recordId = Get-HHForensicsTextValue -InputObject (
        Get-HHForensicsPropertyValue -InputObject $system -Name 'EventRecordID'
    )
    if ([string]::IsNullOrWhiteSpace($recordId)) { $recordId = 'unknown' }
    if ([string]::IsNullOrWhiteSpace($channel)) { $channel = 'unknown' }
    if ([string]::IsNullOrWhiteSpace($version)) { $version = 'unknown' }

    $supportedVersion = ($isSysmon -and $version -in @('3', '4', '5')) -or
        ($isSecurity -and $version -in @('0', '1', '2'))
    if (-not $supportedVersion) {
        return ConvertTo-HHEcsPipelineErrorEvent -Record $Record -Context $Context `
            -Provider $provider -Channel $channel -EventCode $eventCode `
            -EventRecordId $recordId -SourceVersion $version `
            -ErrorCode 'unsupported_event_version' `
            -Message "Provider '$provider' event $eventCode version '$version' is not supported."
    }

    $eventDataAnalysis = $null
    try {
        $timeCreated = Get-HHForensicsPropertyValue -InputObject $system -Name 'TimeCreated'
        $systemTime = [string](Get-HHForensicsAttributeValue -InputObject $timeCreated -Name 'SystemTime')
        $timestamp = ConvertTo-HHForensicsUtcTimestamp -Value $systemTime
        $eventDataAnalysis = ConvertTo-HHForensicsEventDataAnalysis -EventData (
            Get-HHForensicsPropertyValue -InputObject $eventRoot -Name 'EventData'
        )
        $computer = [string](Get-HHForensicsTextValue -InputObject (
                Get-HHForensicsPropertyValue -InputObject $system -Name 'Computer'
            ))
        $hostName = Get-HHForensicsPropertyValue -InputObject $Context -Name 'HostName'
        if ([string]::IsNullOrWhiteSpace([string]$hostName)) { $hostName = $computer }
        if ([string]::IsNullOrWhiteSpace([string]$hostName)) { $hostName = 'unknown' }

        $hostId = Get-HHForensicsRequiredContextValue -Context $Context -Name 'HostId'
        $dataset = if ($isSysmon) {
            'hosthunter.windows_sysmon_operational'
        }
        else { 'hosthunter.windows_security' }

        if ($isSysmon) {
            foreach ($required in @('UtcTime', 'ProcessGuid', 'ProcessId', 'Image')) {
                $requiredValue = Get-HHForensicsEventDataValue `
                    -Analysis $eventDataAnalysis -Name $required
                if ([string]::IsNullOrWhiteSpace([string]$requiredValue)) {
                    throw [IO.InvalidDataException]::new("Sysmon Event 1 is missing required field '$required'.")
                }
            }
            $timestamp = ConvertTo-HHForensicsUtcTimestamp -Value ([string](
                    Get-HHForensicsEventDataValue -Analysis $eventDataAnalysis -Name 'UtcTime'
                ))
            $processId = ConvertTo-HHForensicsProcessId -Value ([string](
                    Get-HHForensicsEventDataValue -Analysis $eventDataAnalysis -Name 'ProcessId'
                ))
            $executable = [string](Get-HHForensicsEventDataValue `
                    -Analysis $eventDataAnalysis -Name 'Image')
            $entityId = [string](Get-HHForensicsEventDataValue `
                    -Analysis $eventDataAnalysis -Name 'ProcessGuid')
            $parent = [ordered]@{}
            $parentProcessGuid = Get-HHForensicsEventDataValue `
                -Analysis $eventDataAnalysis -Name 'ParentProcessGuid'
            if (-not [string]::IsNullOrWhiteSpace([string]$parentProcessGuid)) {
                $parent.entity_id = [string]$parentProcessGuid
            }
            $parentProcessId = Get-HHForensicsEventDataValue `
                -Analysis $eventDataAnalysis -Name 'ParentProcessId'
            if (-not [string]::IsNullOrWhiteSpace([string]$parentProcessId)) {
                $parent.pid = ConvertTo-HHForensicsProcessId -Value ([string]$parentProcessId)
            }
            $parentImage = Get-HHForensicsEventDataValue `
                -Analysis $eventDataAnalysis -Name 'ParentImage'
            if (-not [string]::IsNullOrWhiteSpace([string]$parentImage)) {
                $parent.executable = [string]$parentImage
                $parent.name = Get-HHForensicsExecutableName -Path ([string]$parentImage)
            }
            $parentCommandLine = Get-HHForensicsEventDataValue `
                -Analysis $eventDataAnalysis -Name 'ParentCommandLine'
            if (-not [string]::IsNullOrWhiteSpace([string]$parentCommandLine)) {
                $parent.command_line = [string]$parentCommandLine
            }
            $userName = [string](Get-HHForensicsEventDataValue `
                    -Analysis $eventDataAnalysis -Name 'User')
        }
        else {
            foreach ($required in @('NewProcessId', 'NewProcessName')) {
                $requiredValue = Get-HHForensicsEventDataValue `
                    -Analysis $eventDataAnalysis -Name $required
                if ([string]::IsNullOrWhiteSpace([string]$requiredValue)) {
                    throw [IO.InvalidDataException]::new("Security Event 4688 is missing required field '$required'.")
                }
            }
            $processId = ConvertTo-HHForensicsProcessId -Value ([string](
                    Get-HHForensicsEventDataValue -Analysis $eventDataAnalysis -Name 'NewProcessId'
                ))
            $executable = [string](Get-HHForensicsEventDataValue `
                    -Analysis $eventDataAnalysis -Name 'NewProcessName')
            $entityId = Get-HHForensicsSecurityProcessEntityId -HostId $hostId `
                -ProcessId $processId -Timestamp $timestamp -EventRecordId $recordId
            $parent = [ordered]@{}
            $creatorProcessId = Get-HHForensicsEventDataValue `
                -Analysis $eventDataAnalysis -Name 'ProcessId'
            if (-not [string]::IsNullOrWhiteSpace([string]$creatorProcessId)) {
                $parent.pid = ConvertTo-HHForensicsProcessId -Value ([string]$creatorProcessId)
            }
            $parentProcessName = Get-HHForensicsEventDataValue `
                -Analysis $eventDataAnalysis -Name 'ParentProcessName'
            if (-not [string]::IsNullOrWhiteSpace([string]$parentProcessName) -and
                [string]$parentProcessName -cne '-') {
                $parent.executable = [string]$parentProcessName
                $parent.name = Get-HHForensicsExecutableName -Path ([string]$parentProcessName)
            }
            $userName = [string](Get-HHForensicsEventDataValue `
                    -Analysis $eventDataAnalysis -Name 'SubjectUserName')
            $subjectDomainName = Get-HHForensicsEventDataValue `
                -Analysis $eventDataAnalysis -Name 'SubjectDomainName'
            if (-not [string]::IsNullOrWhiteSpace([string]$subjectDomainName) -and
                -not [string]::IsNullOrWhiteSpace($userName)) {
                $userName = "$subjectDomainName\$userName"
            }
        }

        $eventId = Get-HHForensicsEventId -HostId $hostId `
            -Provider $provider -Channel $channel -EventCode $eventCode `
            -EventRecordId $recordId -Timestamp $timestamp `
            -SourceIdentity $Record.SourceIdentity -SourceOrdinal $Record.SourceOrdinal
        $process = [ordered]@{
            entity_id = $entityId
            executable = $executable
            name = Get-HHForensicsExecutableName -Path $executable
            pid = $processId
            start = $timestamp
        }
        $commandLine = [string](Get-HHForensicsEventDataValue `
                -Analysis $eventDataAnalysis -Name 'CommandLine')
        if (-not [string]::IsNullOrWhiteSpace($commandLine) -and $commandLine -cne '-') {
            $process.command_line = $commandLine
        }
        if ($parent.Count -gt 0) { $process.parent = $parent }
        $processUserNullReason = $null
        if ($isSecurity -and $version -ceq '2') {
            $targetUserName = [string](Get-HHForensicsEventDataValue `
                    -Analysis $eventDataAnalysis -Name 'TargetUserName')
            $targetDomainName = [string](Get-HHForensicsEventDataValue `
                    -Analysis $eventDataAnalysis -Name 'TargetDomainName')
            $targetUserSid = [string](Get-HHForensicsEventDataValue `
                    -Analysis $eventDataAnalysis -Name 'TargetUserSid')
            $nameIsPlaceholder = [string]::IsNullOrWhiteSpace($targetUserName) -or
                $targetUserName -ceq '-'
            $sidIsPlaceholder = [string]::IsNullOrWhiteSpace($targetUserSid) -or
                $targetUserSid -ceq '-' -or $targetUserSid -ceq 'S-1-0-0' -or
                $targetUserSid -ceq '0x0'
            if (-not $nameIsPlaceholder -and -not $sidIsPlaceholder) {
                $process.user = [ordered]@{
                    name = if ([string]::IsNullOrWhiteSpace($targetDomainName)) {
                        $targetUserName
                    }
                    else { "$targetDomainName\$targetUserName" }
                }
                $process.user.id = $targetUserSid
            }
            elseif ($nameIsPlaceholder -and $sidIsPlaceholder) {
                $processUserNullReason = 'target_subject_placeholders'
            }
            elseif ($nameIsPlaceholder) {
                $processUserNullReason = 'target_user_name_placeholder'
            }
            else {
                $processUserNullReason = 'target_user_sid_placeholder'
            }
        }

        $normalized = [ordered]@{
            '@timestamp' = $timestamp
            ecs = [ordered]@{ version = $script:HHEcsVersion }
            event = [ordered]@{
                action = 'process-started'
                category = @('process')
                code = $eventCode
                dataset = $dataset
                id = $eventId
                kind = 'event'
                module = 'hosthunter'
                original = [string]$Record.Original
                provider = $provider
                type = @('start')
            }
            host = [ordered]@{
                id = $hostId
                name = [string]$hostName
                os = [ordered]@{ type = 'windows' }
            }
            process = $process
            hosthunter = ConvertTo-HHForensicsProvenance -Record $Record -Context $Context `
                -Channel $channel -EventRecordId $recordId -Provider $provider `
                -SourceVersion $version -EventDataAnalysis $eventDataAnalysis
        }
        if ($null -ne $processUserNullReason) {
            $normalized.hosthunter.normalization = [ordered]@{
                process_user_null_reason = $processUserNullReason
            }
        }
        if (-not [string]::IsNullOrWhiteSpace($userName) -and $userName -cne '-') {
            $normalized.user = [ordered]@{ name = $userName }
        }
        $ecsEvent = [pscustomobject]$normalized
        [void](Test-HHEcsProcessStartContract -Event $ecsEvent)
        return $ecsEvent
    }
    catch {
        return ConvertTo-HHEcsPipelineErrorEvent -Record $Record -Context $Context `
            -Provider $provider -Channel $channel -EventCode $eventCode `
            -EventRecordId $recordId -SourceVersion $version `
            -ErrorCode 'invalid_event_shape' -Message $_.Exception.Message `
            -EventDataAnalysis $eventDataAnalysis
    }
}
