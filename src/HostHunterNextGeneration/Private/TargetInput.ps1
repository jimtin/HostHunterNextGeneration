Set-StrictMode -Version Latest

function Get-HHInputValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Value,
        [Parameter(Mandatory)][int]$Index,
        [Parameter(Mandatory)][int]$ExpectedCount,
        [Parameter(Mandatory)][string]$Name
    )

    if ($Value.Count -eq 1) {
        return $Value[0]
    }
    if ($Value.Count -ne $ExpectedCount) {
        throw "Parameter '$Name' must contain either one value or $ExpectedCount values."
    }
    $Value[$Index]
}

function ConvertTo-HHProposedTarget {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$InputObject)

    foreach ($forbiddenProperty in @('Password', 'Credential', 'Secret', 'Token')) {
        if ($null -ne $InputObject.PSObject.Properties[$forbiddenProperty]) {
            throw "Proposed targets cannot contain '$forbiddenProperty'."
        }
    }
    $required = @('Name', 'Transport', 'HostName', 'Port', 'UserName', 'Authentication')
    foreach ($propertyName in $required) {
        if ($null -eq $InputObject.PSObject.Properties[$propertyName]) {
            throw "Proposed target is missing '$propertyName'."
        }
    }
    if ([string] $InputObject.Transport -ieq 'WinRM') {
        throw 'WinRM target creation is deferred until controlled Windows lab qualification is complete.'
    }
    $powerShellRuntime = if ($null -eq $InputObject.PSObject.Properties['PowerShellRuntime']) {
        'PowerShell7'
    }
    else {
        [string] $InputObject.PowerShellRuntime
    }
    $fingerprint = if ($null -eq $InputObject.PSObject.Properties['HostKeyFingerprint']) {
        $null
    }
    else {
        $InputObject.HostKeyFingerprint
    }
    $keyPath = if ($null -eq $InputObject.PSObject.Properties['KeyPath']) {
        $null
    }
    else {
        $InputObject.KeyPath
    }
    New-HHTargetRecord `
        -Name ([string]$InputObject.Name) `
        -Transport ([string]$InputObject.Transport) `
        -HostName ([string]$InputObject.HostName) `
        -Port ([int]$InputObject.Port) `
        -UserName ([string]$InputObject.UserName) `
        -Authentication ([string]$InputObject.Authentication) `
        -PowerShellRuntime $powerShellRuntime `
        -HostKeyFingerprint $fingerprint `
        -KeyPath $keyPath `
        -IsActive $true `
        -LastValidatedAtUtc ([DateTimeOffset]::UtcNow) `
        -LastValidatedPowerShellVersion $(
            if ($powerShellRuntime -ieq 'WindowsPowerShell51') { '5.1' } else { '7.0.0' }
        )
}

function Confirm-HHObservedRuntimeField {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$TransportResult,
        [Parameter(Mandatory)][string]$PropertyName
    )

    $property = $TransportResult.PSObject.Properties[$PropertyName]
    if ($null -eq $property -or $null -eq $property.Value -or
        [string]::IsNullOrWhiteSpace([string] $property.Value)) {
        throw "Target validation result is missing observed runtime field '$PropertyName'."
    }
}

function ConvertTo-HHValidatedProbeTarget {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Target,
        [Parameter(Mandatory)]$TransportResult
    )

    Confirm-HHObservedRuntimeField `
        -TransportResult $TransportResult `
        -PropertyName ValidatedAtUtc
    Confirm-HHObservedRuntimeField `
        -TransportResult $TransportResult `
        -PropertyName RemotePSEdition
    Confirm-HHObservedRuntimeField `
        -TransportResult $TransportResult `
        -PropertyName RemotePowerShellVersion
    Confirm-HHObservedRuntimeField `
        -TransportResult $TransportResult `
        -PropertyName ExecutionMode

    New-HHTargetRecord `
        -Name $Target.Name `
        -Transport $Target.Transport `
        -HostName $Target.HostName `
        -Port $Target.Port `
        -UserName $Target.UserName `
        -Authentication $Target.Authentication `
        -PowerShellRuntime $Target.PowerShellRuntime `
        -HostKeyFingerprint $Target.HostKeyFingerprint `
        -KeyPath $Target.KeyPath `
        -IsActive $true `
        -LastValidatedAtUtc $TransportResult.ValidatedAtUtc `
        -LastValidatedPSEdition $TransportResult.RemotePSEdition `
        -LastValidatedPowerShellVersion $TransportResult.RemotePowerShellVersion `
        -LastValidatedExecutionMode $TransportResult.ExecutionMode
}
