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
    $required = @('Name', 'HostName', 'Port', 'UserName', 'Authentication')
    foreach ($propertyName in $required) {
        if ($null -eq $InputObject.PSObject.Properties[$propertyName]) {
            throw "Proposed target is missing '$propertyName'."
        }
    }
    if ($null -ne $InputObject.PSObject.Properties['Transport'] -and
        [string]$InputObject.Transport -ine 'SSH') {
        throw 'Only SSH target creation is supported.'
    }
    $powerShellRuntime = if ($null -eq $InputObject.PSObject.Properties['PowerShellRuntime']) {
        'PowerShell7'
    }
    else {
        [string] $InputObject.PowerShellRuntime
    }
    if ($powerShellRuntime -ine 'PowerShell7') {
        throw 'Only PowerShell7 target creation is supported.'
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
        -Transport SSH `
        -HostName ([string]$InputObject.HostName) `
        -Port ([int]$InputObject.Port) `
        -UserName ([string]$InputObject.UserName) `
        -Authentication ([string]$InputObject.Authentication) `
        -CredentialStorage $(if ($null -ne $InputObject.PSObject.Properties['CredentialStorage']) {
                [string]$InputObject.CredentialStorage
            } elseif ([string]$InputObject.Authentication -ceq 'Password') { 'Prompt' } else { 'None' }) `
        -PowerShellRuntime $powerShellRuntime `
        -HostKeyFingerprint $fingerprint `
        -KeyPath $keyPath `
        -IsActive $true `
        -LastValidatedAtUtc ([DateTimeOffset]::UtcNow) `
        -LastValidatedPowerShellVersion '7.0.0'
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
        [Parameter(Mandatory)]$TransportResult,
        [ValidateLength(1, 128)][string]$Name
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

    $resolvedName = if ($PSBoundParameters.ContainsKey('Name')) { $Name } else { [string]$Target.Name }
    New-HHTargetRecord `
        -Name $resolvedName `
        -Transport $Target.Transport `
        -HostName $Target.HostName `
        -Port $Target.Port `
        -UserName $Target.UserName `
        -Authentication $Target.Authentication `
        -CredentialStorage $Target.CredentialStorage `
        -PowerShellRuntime $Target.PowerShellRuntime `
        -HostKeyFingerprint $Target.HostKeyFingerprint `
        -KeyPath $Target.KeyPath `
        -IsActive $true `
        -LastValidatedAtUtc $TransportResult.ValidatedAtUtc `
        -LastValidatedPSEdition $TransportResult.RemotePSEdition `
        -LastValidatedPowerShellVersion $TransportResult.RemotePowerShellVersion `
        -LastValidatedExecutionMode $TransportResult.ExecutionMode
}
