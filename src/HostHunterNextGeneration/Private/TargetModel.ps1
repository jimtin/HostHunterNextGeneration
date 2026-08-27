Set-StrictMode -Version Latest

$script:HHTargetSchemaProperties = @(
    'Name'
    'Transport'
    'HostName'
    'Port'
    'UserName'
    'Authentication'
    'CredentialStorage'
    'PowerShellRuntime'
    'HostKeyFingerprint'
    'KeyPath'
    'IsActive'
    'LastValidatedAtUtc'
    'LastValidatedPSEdition'
    'LastValidatedPowerShellVersion'
    'LastValidatedExecutionMode'
)

function Get-HHTargetEndpointKey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Transport,

        [Parameter(Mandatory)]
        [string] $HostName,

        [Parameter(Mandatory)]
        [int] $Port,

        [ValidateSet('PowerShell7', 'WindowsPowerShell51')]
        [string] $PowerShellRuntime = 'PowerShell7'
    )

    $normalizedHost = $HostName.Trim().TrimEnd('.').ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($normalizedHost)) {
        throw 'Target HostName must contain a host or IP address.'
    }

    $normalizedRuntime = if ($PowerShellRuntime -ieq 'WindowsPowerShell51') {
        'WindowsPowerShell51'
    }
    else {
        'PowerShell7'
    }
    $subsystem = if ($Transport -ieq 'SSH') { 'powershell' } else { '' }

    return '{0}|{1}|{2}|{3}|{4}' -f @(
        $Transport.ToUpperInvariant()
        $normalizedHost
        $Port
        $subsystem
        $normalizedRuntime
    )
}

function New-HHTargetRecord {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'This is a pure target value-object constructor and does not mutate system state.'
    )]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSAvoidUsingPlainTextForPassword',
        'CredentialStorage',
        Justification = 'CredentialStorage is a non-secret enum describing None, Prompt, or Encrypted state; it never contains a password.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter(Mandatory)]
        [ValidateSet('SSH', 'WinRM')]
        [string] $Transport,

        [Parameter(Mandatory)]
        [string] $HostName,

        [Parameter(Mandatory)]
        [ValidateRange(1, 65535)]
        [int] $Port,

        [Parameter(Mandatory)]
        [string] $UserName,

        [Parameter(Mandatory)]
        [ValidateSet('Password', 'PublicKey', 'Kerberos', 'Certificate')]
        [string] $Authentication,

        [AllowNull()]
        [ValidateSet('None', 'Prompt', 'Encrypted')]
        [string] $CredentialStorage,

        [ValidateSet('PowerShell7', 'WindowsPowerShell51')]
        [string] $PowerShellRuntime = 'PowerShell7',

        [AllowNull()]
        [string] $HostKeyFingerprint,

        [AllowNull()]
        [string] $KeyPath,

        [Parameter(Mandatory)]
        [bool] $IsActive,

        [Parameter(Mandatory)]
        [AllowNull()]
        [object] $LastValidatedAtUtc,

        [ValidateSet('Core', 'Desktop')]
        [string] $LastValidatedPSEdition,

        [Parameter(Mandatory)]
        [string] $LastValidatedPowerShellVersion,

        [ValidateSet('Direct', 'WindowsPowerShellCompatibility')]
        [string] $LastValidatedExecutionMode
    )

    $normalizedName = $Name.Trim()
    if ([string]::IsNullOrWhiteSpace($normalizedName) -or $normalizedName.Length -gt 128) {
        throw 'Target Name must contain between 1 and 128 characters.'
    }
    if ($normalizedName.IndexOfAny([char[]]@(0x00, 0x0A, 0x0D)) -ge 0) {
        throw 'Target Name cannot contain null or newline characters.'
    }

    $normalizedHostName = $HostName.Trim()
    if ([string]::IsNullOrWhiteSpace($normalizedHostName) -or
        $normalizedHostName.Length -gt 253 -or
        $normalizedHostName.StartsWith('-') -or
        $normalizedHostName -notmatch '^[\p{L}\p{N}._:%\[\]-]+$') {
        throw ('Target HostName must be a non-empty host or IP address containing only ' +
            'letters, numbers, dots, hyphens, colons, percent signs, or IPv6 brackets.')
    }
    $normalizedRuntime = if ($PowerShellRuntime -ieq 'WindowsPowerShell51') {
        'WindowsPowerShell51'
    }
    else {
        'PowerShell7'
    }
    [void] (Get-HHTargetEndpointKey `
            -Transport $Transport `
            -HostName $normalizedHostName `
            -Port $Port `
            -PowerShellRuntime $normalizedRuntime)

    $normalizedUserName = $UserName.Trim()
    if ([string]::IsNullOrWhiteSpace($normalizedUserName) -or
        $normalizedUserName.Length -gt 256 -or
        $normalizedUserName.StartsWith('-') -or
        $normalizedUserName -notmatch '^[\p{L}\p{N}._@+\\-]+$') {
        throw ('Target UserName must contain between 1 and 256 safe account-name characters. ' +
            'DOMAIN\user and user@domain forms are supported.')
    }

    $normalizedFingerprint = if ([string]::IsNullOrWhiteSpace($HostKeyFingerprint)) {
        $null
    }
    else {
        $HostKeyFingerprint.Trim()
    }
    if ($null -ne $normalizedFingerprint -and
        ($normalizedFingerprint.Length -gt 512 -or $normalizedFingerprint -match '[\r\n]')) {
        throw 'Target HostKeyFingerprint is invalid.'
    }

    $normalizedKeyPath = if ([string]::IsNullOrWhiteSpace($KeyPath)) {
        $null
    }
    else {
        $KeyPath.Trim()
    }

    if ($Transport -eq 'SSH' -and $Authentication -in @('Kerberos', 'Certificate')) {
        throw "Authentication '$Authentication' is not supported for SSH targets."
    }
    if ($Transport -eq 'WinRM' -and $Authentication -eq 'PublicKey') {
        throw "Authentication 'PublicKey' is not supported for WinRM targets."
    }
    if ($Transport -ne 'SSH' -and $null -ne $normalizedFingerprint) {
        throw 'HostKeyFingerprint is only valid for SSH targets.'
    }
    if ($Authentication -eq 'PublicKey') {
        if ($null -eq $normalizedKeyPath -or -not [System.IO.Path]::IsPathFullyQualified($normalizedKeyPath)) {
            throw 'PublicKey authentication requires an absolute KeyPath.'
        }
    }
    elseif ($null -ne $normalizedKeyPath) {
        throw 'KeyPath is only valid for PublicKey authentication.'
    }
    $normalizedCredentialStorage = if ($PSBoundParameters.ContainsKey('CredentialStorage')) {
        $CredentialStorage
    }
    elseif ($Authentication -ceq 'Password') { 'Prompt' }
    else { 'None' }
    if ($Authentication -ceq 'Password') {
        if ($normalizedCredentialStorage -cnotin @('Prompt', 'Encrypted')) {
            throw 'Password authentication requires Prompt or Encrypted credential storage.'
        }
    }
    elseif ($normalizedCredentialStorage -cne 'None') {
        throw 'Only password authentication can use credential storage.'
    }

    $validatedAt = [datetimeoffset]::MinValue
    if ($LastValidatedAtUtc -is [datetimeoffset]) {
        $validatedAt = $LastValidatedAtUtc
    }
    elseif ($LastValidatedAtUtc -is [datetime]) {
        if ($LastValidatedAtUtc.Kind -eq [DateTimeKind]::Unspecified) {
            throw 'LastValidatedAtUtc cannot use an unspecified DateTime kind.'
        }
        $validatedAt = [datetimeoffset] $LastValidatedAtUtc
    }
    else {
        $validatedText = [string] $LastValidatedAtUtc
        if ([string]::IsNullOrWhiteSpace($validatedText) -or
            $validatedText -notmatch '(Z|[+-]\d{2}:\d{2})$' -or
            -not [datetimeoffset]::TryParse(
                $validatedText,
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::RoundtripKind,
                [ref] $validatedAt
            )) {
            throw 'LastValidatedAtUtc must be an ISO-8601 timestamp with an explicit offset.'
        }
    }

    $version = $null
    if (-not [version]::TryParse($LastValidatedPowerShellVersion.Trim(), [ref] $version)) {
        throw 'LastValidatedPowerShellVersion must be a valid PowerShell version.'
    }

    $validatedPSEdition = if ($PSBoundParameters.ContainsKey('LastValidatedPSEdition')) {
        if ($LastValidatedPSEdition -ieq 'Desktop') { 'Desktop' } else { 'Core' }
    }
    elseif ($normalizedRuntime -ceq 'WindowsPowerShell51') {
        'Desktop'
    }
    else {
        'Core'
    }
    $validatedExecutionMode = if ($PSBoundParameters.ContainsKey('LastValidatedExecutionMode')) {
        if ($LastValidatedExecutionMode -ieq 'WindowsPowerShellCompatibility') {
            'WindowsPowerShellCompatibility'
        }
        else {
            'Direct'
        }
    }
    elseif ($normalizedRuntime -ceq 'WindowsPowerShell51') {
        'WindowsPowerShellCompatibility'
    }
    else {
        'Direct'
    }

    if ($normalizedRuntime -ceq 'PowerShell7') {
        if ($validatedPSEdition -cne 'Core' -or $version.Major -ne 7 -or
            $validatedExecutionMode -cne 'Direct') {
            throw 'PowerShell7 targets require observed Core edition, PowerShell 7, and Direct execution.'
        }
    }
    else {
        if ($Transport -ne 'SSH') {
            throw 'WindowsPowerShell51 targets are supported only through SSH in this release.'
        }
        if ($validatedPSEdition -cne 'Desktop' -or $version.Major -ne 5 -or
            $version.Minor -ne 1 -or
            $validatedExecutionMode -cne 'WindowsPowerShellCompatibility') {
            throw ('WindowsPowerShell51 targets require observed Desktop edition, PowerShell 5.1, ' +
                'and WindowsPowerShellCompatibility execution.')
        }
    }

    $record = [pscustomobject][ordered]@{
        Name                               = $normalizedName
        Transport                          = $Transport
        HostName                           = $normalizedHostName
        Port                               = $Port
        UserName                           = $normalizedUserName
        Authentication                     = $Authentication
        CredentialStorage                  = $normalizedCredentialStorage
        PowerShellRuntime                  = $normalizedRuntime
        HostKeyFingerprint                 = $normalizedFingerprint
        KeyPath                            = $normalizedKeyPath
        IsActive                           = $IsActive
        LastValidatedAtUtc                 = $validatedAt.UtcDateTime.ToString(
            'o',
            [Globalization.CultureInfo]::InvariantCulture
        )
        LastValidatedPSEdition             = $validatedPSEdition
        LastValidatedPowerShellVersion     = $version.ToString()
        LastValidatedExecutionMode         = $validatedExecutionMode
    }
    $record.PSObject.TypeNames.Insert(0, 'HostHunter.Target')
    return $record
}

function ConvertTo-HHValidatedTargetRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [AllowNull()]
        [object] $InputObject
    )

    process {
        if ($null -eq $InputObject) {
            throw 'Target record cannot be null.'
        }

        $candidate = if ($InputObject -is [Collections.IDictionary]) {
            [pscustomobject] $InputObject
        }
        else {
            $InputObject
        }
        $actualProperties = @($candidate.PSObject.Properties.Name)
        $missingProperties = @(
            $script:HHTargetSchemaProperties |
                Where-Object { $actualProperties -cnotcontains $_ }
        )
        $unexpectedProperties = @(
            $actualProperties |
                Where-Object { $script:HHTargetSchemaProperties -cnotcontains $_ }
        )
        if ($missingProperties.Count -gt 0 -or $unexpectedProperties.Count -gt 0) {
            $details = @()
            if ($missingProperties.Count -gt 0) {
                $details += "missing: $($missingProperties -join ', ')"
            }
            if ($unexpectedProperties.Count -gt 0) {
                $details += "unexpected: $($unexpectedProperties -join ', ')"
            }
            throw "Target record does not match schema v2 ($($details -join '; '))."
        }
        if ($candidate.IsActive -isnot [bool]) {
            throw 'Target IsActive must be a Boolean.'
        }

        $recordParameters = @{
            Name                               = [string] $candidate.Name
            Transport                          = [string] $candidate.Transport
            HostName                           = [string] $candidate.HostName
            Port                               = [int] $candidate.Port
            UserName                           = [string] $candidate.UserName
            Authentication                     = [string] $candidate.Authentication
            CredentialStorage                  = [string] $candidate.CredentialStorage
            PowerShellRuntime                  = [string] $candidate.PowerShellRuntime
            HostKeyFingerprint                 = $candidate.HostKeyFingerprint
            KeyPath                            = $candidate.KeyPath
            IsActive                           = [bool] $candidate.IsActive
            LastValidatedAtUtc                 = $candidate.LastValidatedAtUtc
            LastValidatedPSEdition             = [string] $candidate.LastValidatedPSEdition
            LastValidatedPowerShellVersion     = [string] $candidate.LastValidatedPowerShellVersion
            LastValidatedExecutionMode         = [string] $candidate.LastValidatedExecutionMode
        }
        return New-HHTargetRecord @recordParameters
    }
}

function Assert-HHTargetSet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Target,

        [switch] $AllowEmpty
    )

    $validatedTargets = @(
        foreach ($item in $Target) {
            ConvertTo-HHValidatedTargetRecord -InputObject $item
        }
    )
    if (-not $AllowEmpty -and $validatedTargets.Count -eq 0) {
        throw 'At least one target is required.'
    }
    if ($validatedTargets.Count -gt 8) {
        throw 'A maximum of eight targets can be stored.'
    }

    $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $endpoints = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($item in $validatedTargets) {
        if (-not $names.Add($item.Name)) {
            throw "Target names must be unique; duplicate name: '$($item.Name)'."
        }
        $endpointKey = Get-HHTargetEndpointKey `
            -Transport $item.Transport `
            -HostName $item.HostName `
            -Port $item.Port `
            -PowerShellRuntime $item.PowerShellRuntime
        if (-not $endpoints.Add($endpointKey)) {
            throw ("Target endpoint/runtime profiles must be unique; duplicate endpoint: " +
                "'$($item.Transport)://$($item.HostName):$($item.Port)' " +
                "with runtime '$($item.PowerShellRuntime)'.")
        }
    }

    return $validatedTargets
}
