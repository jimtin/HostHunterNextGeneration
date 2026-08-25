Set-StrictMode -Version Latest

function Get-HHForensicsContractKey {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Value)

    if ($Value -is [Collections.IDictionary]) { return @($Value.Keys) }
    return @($Value.PSObject.Properties.Name)
}

function Assert-HHForensicsExactKey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Value,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Required,
        [string[]]$Optional = @(),
        [Parameter(Mandatory)][string]$Path
    )

    if ($null -eq $Value -or $Value -is [string] -or $Value -is [ValueType]) {
        throw [IO.InvalidDataException]::new("ECS contract '$Path' must be an object.")
    }
    $keys = @(Get-HHForensicsContractKey -Value $Value)
    foreach ($requiredKey in $Required) {
        if ($keys -cnotcontains $requiredKey) {
            throw [IO.InvalidDataException]::new(
                "ECS contract '$Path' is missing '$requiredKey'."
            )
        }
    }
    $allowed = @($Required) + @($Optional)
    foreach ($key in $keys) {
        if ($allowed -cnotcontains [string]$key) {
            throw [IO.InvalidDataException]::new(
                "ECS contract '$Path' contains unexpected field '$key'."
            )
        }
    }
}

function Assert-HHForensicsStringValue {
    [CmdletBinding()]
    param(
        [AllowNull()][object]$Value,
        [Parameter(Mandatory)][string]$Path,
        [switch]$AllowEmpty
    )

    if ($Value -isnot [string] -or (-not $AllowEmpty -and
        [string]::IsNullOrWhiteSpace([string]$Value))) {
        throw [IO.InvalidDataException]::new("ECS contract '$Path' must be a string.")
    }
}

function Assert-HHForensicsBoundedStringValue {
    [CmdletBinding()]
    param(
        [AllowNull()][object]$Value,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][ValidateRange(1, 4194304)][int]$MaximumLength
    )

    Assert-HHForensicsStringValue -Value $Value -Path $Path
    if (([string]$Value).Length -gt $MaximumLength) {
        throw [IO.InvalidDataException]::new(
            "ECS contract '$Path' exceeds its maximum length."
        )
    }
}

function Assert-HHForensicsEventDataContract {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Value)

    Assert-HHForensicsExactKey -Value $Value `
        -Required @('pairs', 'unconsumed_names', 'warnings') -Path 'hosthunter.event_data'
    foreach ($pair in @($Value.pairs)) {
        Assert-HHForensicsExactKey -Value $pair -Required @('ordinal', 'name', 'value') `
            -Path 'hosthunter.event_data.pairs[]'
        if ([long]$pair.ordinal -lt 1) {
            throw [IO.InvalidDataException]::new('EventData pair ordinal must be positive.')
        }
        foreach ($field in @('name', 'value')) {
            if ($null -ne $pair.$field -and $pair.$field -isnot [string]) {
                throw [IO.InvalidDataException]::new("EventData pair '$field' must be null or string.")
            }
        }
    }
    foreach ($text in @($Value.unconsumed_names) + @($Value.warnings)) {
        Assert-HHForensicsStringValue -Value $text -Path 'hosthunter.event_data[]'
    }
}

function Test-HHEcsProcessStartContract {
    [CmdletBinding()]
    param([Parameter(Mandatory)][Alias('Event')][object]$EcsDocument)

    if ($null -eq $EcsDocument -or $EcsDocument -is [string] -or
        $EcsDocument -is [ValueType]) {
        throw [IO.InvalidDataException]::new("ECS contract '$' must be an object.")
    }
    $rootKeys = @(Get-HHForensicsContractKey -Value $EcsDocument)
    $pipelineError = $rootKeys -ccontains 'event' -and
        $EcsDocument.event.kind -ceq 'pipeline_error'
    $rootRequired = @('@timestamp', 'ecs', 'event', 'host', 'hosthunter')
    if ($pipelineError) { $rootRequired += 'error' } else { $rootRequired += 'process' }
    Assert-HHForensicsExactKey -Value $EcsDocument -Required $rootRequired `
        -Optional $(if ($pipelineError) { @() } else { @('user') }) -Path '$'
    Assert-HHForensicsStringValue -Value $EcsDocument.'@timestamp' -Path '@timestamp'

    Assert-HHForensicsExactKey -Value $EcsDocument.ecs -Required @('version') -Path 'ecs'
    if ($EcsDocument.ecs.version -cne '9.5.0') {
        throw [IO.InvalidDataException]::new('ECS contract version must be 9.5.0.')
    }
    Assert-HHForensicsExactKey -Value $EcsDocument.host -Required @('id', 'name', 'os') -Path 'host'
    Assert-HHForensicsStringValue -Value $EcsDocument.host.id -Path 'host.id'
    Assert-HHForensicsStringValue -Value $EcsDocument.host.name -Path 'host.name'
    Assert-HHForensicsExactKey -Value $EcsDocument.host.os -Required @('type') -Path 'host.os'
    if ($EcsDocument.host.os.type -cne 'windows') {
        throw [IO.InvalidDataException]::new('ECS host.os.type must be windows.')
    }

    $eventRequired = @('action', 'category', 'code', 'id', 'kind', 'module', 'original', 'provider')
    if (-not $pipelineError) { $eventRequired += @('dataset', 'type') }
    Assert-HHForensicsExactKey -Value $EcsDocument.event -Required $eventRequired -Path 'event'
    foreach ($field in @('action', 'code', 'id', 'kind', 'module', 'original', 'provider')) {
        Assert-HHForensicsStringValue -Value $EcsDocument.event.$field -Path "event.$field"
    }
    if ([string]$EcsDocument.event.id -notmatch '^[a-f0-9]{64}$') {
        throw [IO.InvalidDataException]::new('ECS event.id must be lowercase SHA-256.')
    }
    if (@($EcsDocument.event.category).Count -ne 1 -or $EcsDocument.event.category[0] -cne 'process') {
        throw [IO.InvalidDataException]::new('ECS event.category must equal process.')
    }

    if ($pipelineError) {
        if ($EcsDocument.event.action -cne 'process-start-normalization-failed' -or
            $EcsDocument.event.module -cne 'hosthunter') {
            throw [IO.InvalidDataException]::new('ECS pipeline error event projection is invalid.')
        }
        Assert-HHForensicsExactKey -Value $EcsDocument.error -Required @('code', 'message', 'type') `
            -Path 'error'
        foreach ($field in @('code', 'message', 'type')) {
            Assert-HHForensicsStringValue -Value $EcsDocument.error.$field -Path "error.$field"
        }
    }
    else {
        if ($EcsDocument.event.kind -cne 'event' -or $EcsDocument.event.action -cne 'process-started' -or
            $EcsDocument.event.module -cne 'hosthunter' -or @($EcsDocument.event.type).Count -ne 1 -or
            $EcsDocument.event.type[0] -cne 'start') {
            throw [IO.InvalidDataException]::new('ECS Process Start event projection is invalid.')
        }
        Assert-HHForensicsExactKey -Value $EcsDocument.process `
            -Required @('entity_id', 'executable', 'name', 'pid', 'start') `
            -Optional @('command_line', 'parent', 'user') -Path 'process'
        foreach ($field in @('entity_id', 'executable', 'name', 'start')) {
            Assert-HHForensicsStringValue -Value $EcsDocument.process.$field -Path "process.$field"
        }
        if ([long]$EcsDocument.process.pid -lt 0) {
            throw [IO.InvalidDataException]::new('ECS process.pid cannot be negative.')
        }
        Assert-HHForensicsBoundedStringValue -Value $EcsDocument.event.original `
            -Path 'event.original' -MaximumLength 4194304
        if ((Get-HHForensicsContractKey -Value $EcsDocument.process) -contains 'command_line') {
            Assert-HHForensicsBoundedStringValue -Value $EcsDocument.process.command_line `
                -Path 'process.command_line' -MaximumLength 1048576
        }
        if ((Get-HHForensicsContractKey -Value $EcsDocument.process) -contains 'parent') {
            Assert-HHForensicsExactKey -Value $EcsDocument.process.parent -Required @() `
                -Optional @('entity_id', 'executable', 'name', 'pid', 'command_line') `
                -Path 'process.parent'
            if ((Get-HHForensicsContractKey -Value $EcsDocument.process.parent) -contains
                'command_line') {
                Assert-HHForensicsBoundedStringValue `
                    -Value $EcsDocument.process.parent.command_line `
                    -Path 'process.parent.command_line' -MaximumLength 1048576
            }
        }
        if ((Get-HHForensicsContractKey -Value $EcsDocument.process) -contains 'user') {
            Assert-HHForensicsExactKey -Value $EcsDocument.process.user -Required @('name') `
                -Optional @('id') -Path 'process.user'
        }
        if ($EcsDocument.PSObject.Properties.Name -contains 'user') {
            Assert-HHForensicsExactKey -Value $EcsDocument.user -Required @('name') -Path 'user'
        }
    }

    if ($EcsDocument.event.kind -ceq 'pipeline_error') {
        Assert-HHForensicsBoundedStringValue -Value $EcsDocument.event.original `
            -Path 'event.original' -MaximumLength 4194304
    }

    Assert-HHForensicsExactKey -Value $EcsDocument.hosthunter `
        -Required @('contract', 'evidence', 'parser', 'sensitive_fields') `
        -Optional @('acquisition', 'event_data', 'normalization') -Path 'hosthunter'
    Assert-HHForensicsExactKey -Value $EcsDocument.hosthunter.contract `
        -Required @('name', 'version') -Path 'hosthunter.contract'
    if ($EcsDocument.hosthunter.contract.name -cne 'hosthunter.process_start' -or
        $EcsDocument.hosthunter.contract.version -cne '1.0.0') {
        throw [IO.InvalidDataException]::new('HostHunter mapping contract identity is invalid.')
    }
    Assert-HHForensicsExactKey -Value $EcsDocument.hosthunter.parser `
        -Required @('name', 'version') -Path 'hosthunter.parser'
    if ($EcsDocument.hosthunter.parser.name -cne 'evtx_dump' -or
        $EcsDocument.hosthunter.parser.version -cne '0.12.2') {
        throw [IO.InvalidDataException]::new('HostHunter parser provenance is invalid.')
    }
    Assert-HHForensicsExactKey -Value $EcsDocument.hosthunter.evidence `
        -Required @(
            'artifact_sha256', 'channel', 'event_record_id', 'original_sha256',
            'provider', 'source_identity', 'source_ordinal', 'source_version'
        ) -Optional @('artifact_id', 'relative_path') -Path 'hosthunter.evidence'
    foreach ($digest in @(
            $EcsDocument.hosthunter.evidence.artifact_sha256,
            $EcsDocument.hosthunter.evidence.original_sha256,
            $EcsDocument.hosthunter.evidence.source_identity
        )) {
        if ([string]$digest -notmatch '^[a-f0-9]{64}$') {
            throw [IO.InvalidDataException]::new('HostHunter evidence digest is invalid.')
        }
    }
    if ([long]$EcsDocument.hosthunter.evidence.source_ordinal -lt 1) {
        throw [IO.InvalidDataException]::new('HostHunter source ordinal must be positive.')
    }
    foreach ($bound in @(
            [pscustomobject]@{ Name = 'channel'; Maximum = 1024 },
            [pscustomobject]@{ Name = 'event_record_id'; Maximum = 128 },
            [pscustomobject]@{ Name = 'provider'; Maximum = 1024 },
            [pscustomobject]@{ Name = 'source_version'; Maximum = 128 }
        )) {
        Assert-HHForensicsBoundedStringValue `
            -Value $EcsDocument.hosthunter.evidence.($bound.Name) `
            -Path "hosthunter.evidence.$($bound.Name)" -MaximumLength $bound.Maximum
    }
    foreach ($bound in @(
            [pscustomobject]@{ Name = 'artifact_id'; Maximum = 1024 },
            [pscustomobject]@{ Name = 'relative_path'; Maximum = 4096 }
        )) {
        if ((Get-HHForensicsContractKey -Value $EcsDocument.hosthunter.evidence) -contains
            $bound.Name) {
            Assert-HHForensicsBoundedStringValue `
                -Value $EcsDocument.hosthunter.evidence.($bound.Name) `
                -Path "hosthunter.evidence.$($bound.Name)" -MaximumLength $bound.Maximum
        }
    }
    if ((Get-HHForensicsContractKey -Value $EcsDocument.hosthunter) -contains 'event_data') {
        Assert-HHForensicsEventDataContract -Value $EcsDocument.hosthunter.event_data
    }
    if ((Get-HHForensicsContractKey -Value $EcsDocument.hosthunter) -contains 'acquisition') {
        Assert-HHForensicsExactKey -Value $EcsDocument.hosthunter.acquisition -Required @('id') `
            -Path 'hosthunter.acquisition'
        Assert-HHForensicsBoundedStringValue -Value $EcsDocument.hosthunter.acquisition.id `
            -Path 'hosthunter.acquisition.id' -MaximumLength 1024
    }
    if ((Get-HHForensicsContractKey -Value $EcsDocument.hosthunter) -contains 'normalization') {
        Assert-HHForensicsExactKey -Value $EcsDocument.hosthunter.normalization `
            -Required @('process_user_null_reason') -Path 'hosthunter.normalization'
        if ($EcsDocument.hosthunter.normalization.process_user_null_reason -cnotin @(
                'target_subject_placeholders', 'target_user_name_placeholder',
                'target_user_sid_placeholder'
            )) {
            throw [IO.InvalidDataException]::new(
                'HostHunter process user null reason is invalid.'
            )
        }
    }
    foreach ($field in @($EcsDocument.hosthunter.sensitive_fields)) {
        Assert-HHForensicsStringValue -Value $field -Path 'hosthunter.sensitive_fields[]'
    }
    return $true
}
