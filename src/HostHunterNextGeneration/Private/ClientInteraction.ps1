Set-StrictMode -Version Latest

function Request-HHClientConfirmation {
    [CmdletBinding()]
    param([Parameter(Mandatory)][ValidateLength(1, 4096)][string]$Prompt)

    $helperPath = [Environment]::GetEnvironmentVariable('HH_CLIENT_CONFIRM_PATH', 'Process')
    $port = [Environment]::GetEnvironmentVariable('HH_CLIENT_BROKER_PORT', 'Process')
    $token = [Environment]::GetEnvironmentVariable('HH_CLIENT_BROKER_TOKEN', 'Process')
    if ([string]::IsNullOrWhiteSpace($helperPath) -or
        [string]::IsNullOrWhiteSpace($port) -or
        [string]::IsNullOrWhiteSpace($token) -or
        -not [IO.File]::Exists($helperPath)) {
        throw 'Interactive confirmation requires the HostHunter native client.'
    }

    $promptBytes = [Text.Encoding]::UTF8.GetBytes($Prompt)
    try {
        $encodedPrompt = [Convert]::ToBase64String($promptBytes)
        $result = Invoke-HHNativeProcess -FileName $helperPath `
            -ArgumentList @($encodedPrompt) -TimeoutSeconds 125
    }
    finally {
        [Array]::Clear($promptBytes, 0, $promptBytes.Length)
    }
    if ($result.ExitCode -ne 0) {
        throw "HostHunter confirmation failed: $($result.StandardError.Trim())"
    }
    switch ($result.StandardOutput.Trim()) {
        'yes' { return $true }
        'no' { return $false }
        default { throw 'HostHunter received an invalid confirmation response.' }
    }
}

function Get-HHClientCredentialBytes {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseSingularNouns',
        '',
        Justification = 'Bytes names the returned byte-array representation and the function is private.'
    )]
    [CmdletBinding()]
    [OutputType([byte[]])]
    param([Parameter(Mandatory)][ValidateLength(1, 4096)][string]$Prompt)

    $helperPath = [Environment]::GetEnvironmentVariable('HH_CLIENT_CREDENTIAL_PATH', 'Process')
    $port = [Environment]::GetEnvironmentVariable('HH_CLIENT_BROKER_PORT', 'Process')
    $token = [Environment]::GetEnvironmentVariable('HH_CLIENT_BROKER_TOKEN', 'Process')
    if ([string]::IsNullOrWhiteSpace($helperPath) -or
        [string]::IsNullOrWhiteSpace($port) -or
        [string]::IsNullOrWhiteSpace($token) -or
        -not [IO.File]::Exists($helperPath)) {
        throw 'Password authentication requires the HostHunter native client credential broker.'
    }

    $promptBytes = [Text.Encoding]::UTF8.GetBytes($Prompt)
    try {
        $encodedPrompt = [Convert]::ToBase64String($promptBytes)
        $result = Invoke-HHNativeProcess -FileName $helperPath `
            -ArgumentList @('acquire', $encodedPrompt) -TimeoutSeconds 125
    }
    finally { [Array]::Clear($promptBytes, 0, $promptBytes.Length) }
    if ($result.ExitCode -ne 0) {
        throw "Password acquisition failed: $($result.StandardError.Trim())"
    }
    try {
        $password = [Convert]::FromBase64String($result.StandardOutput.Trim())
    }
    catch { throw 'HostHunter received an invalid credential response.' }
    if ($password.Length -eq 0 -or $password.Length -gt 4096) {
        [Array]::Clear($password, 0, $password.Length)
        throw 'HostHunter received an invalid credential response.'
    }
    Write-Output -InputObject $password -NoEnumerate
}

function Set-HHClientCredentialBytes {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseSingularNouns',
        '',
        Justification = 'Bytes names the byte-array representation and the function is private.'
    )]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'This private helper seeds invocation-scoped broker memory inside an already authorized managed-host operation.'
    )]
    [CmdletBinding()]
    param([Parameter(Mandatory)][ValidateCount(1, 4096)][byte[]]$PasswordBytes)

    $helperPath = [Environment]::GetEnvironmentVariable('HH_CLIENT_CREDENTIAL_PATH', 'Process')
    if ([string]::IsNullOrWhiteSpace($helperPath) -or -not [IO.File]::Exists($helperPath)) {
        throw 'Stored password authentication requires the HostHunter native client credential broker.'
    }
    $encodedBytes = [Text.Encoding]::ASCII.GetBytes(
        ([Convert]::ToBase64String($PasswordBytes) + "`n")
    )
    try {
        $result = Invoke-HHNativeProcess -FileName $helperPath `
            -ArgumentList @('seed') -StandardInputBytes $encodedBytes -TimeoutSeconds 5
    }
    finally { [Array]::Clear($encodedBytes, 0, $encodedBytes.Length) }
    if ($result.ExitCode -ne 0 -or $result.StandardOutput.Trim() -cne 'ok') {
        throw 'HostHunter could not load the stored password into the credential broker.'
    }
}

function Initialize-HHStoredTargetCredential {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][object]$Target
    )

    $authenticationProperty = $Target.PSObject.Properties['Authentication']
    $storageProperty = $Target.PSObject.Properties['CredentialStorage']
    if ($null -eq $authenticationProperty -or
        [string]$authenticationProperty.Value -cne 'Password' -or
        $null -eq $storageProperty -or
        [string]$storageProperty.Value -cne 'Encrypted') { return }
    $password = Get-HHTargetCredential -Connection $Context.Connection `
        -MasterKey $Context.MasterKey -Target $Target
    try { Set-HHClientCredentialBytes -PasswordBytes $password }
    finally {
        if ($null -ne $password) { [Array]::Clear($password, 0, $password.Length) }
    }
}

function Get-HHStoredCredentialRecoveryAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Target,
        [AllowNull()][string]$FailureKind
    )

    $storage = $Target.PSObject.Properties['CredentialStorage']
    if ($FailureKind -ceq 'AuthenticationFailure' -and
        $null -ne $storage -and [string]$storage.Value -ceq 'Encrypted') {
        return "Run Set-HHTarget for '$($Target.Name)' to replace its saved password."
    }
    $null
}

function Request-HHSshKeyOnboardingChoice {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$TargetLabel)

    Request-HHClientConfirmation -Prompt @"
HostHunter recommends SSH key authentication for '$TargetLabel'.
It removes routine password prompts and avoids retaining the account password.
Install and prove a dedicated HostHunter SSH key now? [Y/n]
"@
}

function Request-HHPasswordStorageConsent {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$TargetLabel)

    Request-HHClientConfirmation -Prompt @"
WARNING: Save the password for '$TargetLabel'?

The password will be encrypted in SQLite with a key held in a separate Docker volume.
It will not be displayed or written to logs, but anyone who controls your macOS account
or HostHunter Docker runtime can use it to operate this target. A stolen database plus
its secret and anchor volumes may permit offline password recovery. Change the remote
password immediately if this Mac or its Docker state is compromised.

Store this password and use it automatically? [y/N]
"@
}
