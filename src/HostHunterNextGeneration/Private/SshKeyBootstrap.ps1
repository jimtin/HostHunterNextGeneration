Set-StrictMode -Version Latest

function New-HHSshKeyBootstrapPlan {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'This is a pure bootstrap-plan constructor and performs no mutation or network activity.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object] $Target,

        [Parameter(Mandatory)]
        [string] $KnownHostsPath,

        [Parameter(Mandatory)]
        [string] $KeyPath,

        [switch] $UseExistingKey,

        [ValidateRange(1, 300)]
        [int] $ConnectionTimeoutSeconds = 15
    )

    $validatedTarget = ConvertTo-HHValidatedTargetRecord -InputObject $Target
    if ($validatedTarget.Transport -cne 'SSH' -or $validatedTarget.Authentication -cne 'Password') {
        throw [ArgumentException]::new('SSH key bootstrap requires an SSH target using Password authentication.')
    }
    if (-not [IO.Path]::IsPathFullyQualified($KeyPath)) {
        throw [ArgumentException]::new('The SSH private-key path must be absolute.')
    }

    $passwordPlan = New-HHSshTransportPlan `
        -Target $validatedTarget `
        -KnownHostsPath $KnownHostsPath `
        -ConnectionTimeoutSeconds $ConnectionTimeoutSeconds
    $plan = [pscustomobject][ordered]@{
        Target = $validatedTarget
        KnownHostsPath = $passwordPlan.KnownHostsPath
        KeyPath = [IO.Path]::GetFullPath($KeyPath)
        UseExistingKey = [bool] $UseExistingKey
        KeyAction = if ($UseExistingKey) { 'UseExistingEd25519Key' } else { 'GenerateDedicatedEd25519Key' }
        ConnectionTimeoutSeconds = $ConnectionTimeoutSeconds
        PasswordTransportPlan = $passwordPlan
    }
    $plan.PSObject.TypeNames.Insert(0, 'HostHunter.SshKeyBootstrapPlan')
    return $plan
}

function Invoke-HHSshDefaultKeyGenerator {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $KeyPath,

        [Parameter(Mandatory)]
        [string] $Comment
    )

    $publicKeyPath = "$KeyPath.pub"
    if ([IO.File]::Exists($KeyPath) -or [IO.File]::Exists($publicKeyPath)) {
        throw [IO.IOException]::new('Dedicated SSH key generation refuses to overwrite an existing key pair.')
    }
    $keyDirectory = Split-Path -Parent $KeyPath
    [IO.Directory]::CreateDirectory($keyDirectory) | Out-Null
    if (-not $IsWindows) {
        [IO.File]::SetUnixFileMode(
            $keyDirectory,
            [IO.UnixFileMode]::UserRead -bor
            [IO.UnixFileMode]::UserWrite -bor
            [IO.UnixFileMode]::UserExecute
        )
    }

    & ssh-keygen -q -t ed25519 -f $KeyPath -C $Comment
    if ($LASTEXITCODE -ne 0 -or
        -not [IO.File]::Exists($KeyPath) -or
        -not [IO.File]::Exists($publicKeyPath)) {
        throw [IO.IOException]::new('Interactive Ed25519 key generation failed.')
    }
}

function Get-HHSshBootstrapPublicKey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $KeyPath,

        [scriptblock] $PublicKeyReader
    )

    $publicKeyLine = if ($null -ne $PublicKeyReader) {
        [string] (& $PublicKeyReader $KeyPath)
    }
    else {
        $publicKeyPath = "$KeyPath.pub"
        $publicKeyItem = Get-Item -LiteralPath $publicKeyPath -Force -ErrorAction SilentlyContinue
        if ($null -eq $publicKeyItem -or $publicKeyItem.PSIsContainer -or $null -ne $publicKeyItem.LinkType) {
            throw [IO.FileNotFoundException]::new('The selected SSH public key is missing or invalid.')
        }
        $nonEmptyLines = @([IO.File]::ReadAllLines($publicKeyItem.FullName) | Where-Object {
                -not [string]::IsNullOrWhiteSpace($_)
            })
        if ($nonEmptyLines.Count -ne 1) {
            throw [FormatException]::new('The selected SSH public-key file must contain exactly one key line.')
        }
        $nonEmptyLines[0]
    }

    $parts = @($publicKeyLine.Trim() -split '\s+')
    if ($parts.Count -lt 2 -or $parts[0] -cne 'ssh-ed25519') {
        throw [FormatException]::new('SSH key bootstrap requires an Ed25519 public key.')
    }
    $fingerprint = Get-HHSshPublicKeyFingerprint -PublicKeyLine "$($parts[0]) $($parts[1])"
    $marker = 'hosthunter-ng:{0}' -f $fingerprint.Substring('SHA256:'.Length)
    $exactLine = '{0} {1} {2}' -f $parts[0], $parts[1], $marker

    return [pscustomobject][ordered]@{
        Fingerprint = $fingerprint
        Marker = $marker
        ExactLine = $exactLine
    }
}

function Remove-HHSshGeneratedKey {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'This exact-path rollback helper runs only inside an already approved bootstrap operation.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $KeyPath,

        [scriptblock] $KeyRemover
    )

    if ($null -ne $KeyRemover) {
        & $KeyRemover $KeyPath
        return
    }
    foreach ($path in @($KeyPath, "$KeyPath.pub")) {
        if ([IO.File]::Exists($path)) {
            [IO.File]::Delete($path)
        }
    }
}

function New-HHSshKeyBootstrapRemoteOperationsManifest {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'This constructs non-secret audit metadata and performs no remote activity.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object] $Plan,

        [Parameter(Mandatory)]
        [object] $KeyMaterial
    )

    $null = $Plan

    $identityScriptText = (Get-HHSshIdentityProbeScriptBlock).ToString()
    $operations = [Collections.Generic.List[object]]::new()
    $operations.Add((Get-HHRemoteOperationManifestEntry `
                -Phase OuterIdentity `
                -PowerShellRuntime PowerShell7 `
                -ScriptText $identityScriptText `
                -ArgumentList @()))
    $operations.Add((Get-HHRemoteOperationManifestEntry `
                -Phase BootstrapInstall `
                -PowerShellRuntime PowerShell7 `
                -ScriptText ((Get-HHSshAuthorizedKeyInstallScriptBlock).ToString()) `
                -ArgumentList @($KeyMaterial.ExactLine, $KeyMaterial.Marker)))
    $operations.Add((Get-HHRemoteOperationManifestEntry `
                -Phase BootstrapKeyOnlyOuterIdentity `
                -PowerShellRuntime PowerShell7 `
                -ScriptText $identityScriptText `
                -ArgumentList @()))
    $operations.Add((Get-HHRemoteOperationManifestEntry `
                -Phase BootstrapReconcile `
                -PowerShellRuntime PowerShell7 `
                -ScriptText ((Get-HHSshAuthorizedKeyReconciliationScriptBlock).ToString()) `
                -ArgumentList @($KeyMaterial.ExactLine) `
                -Conditional $true))
    $operations.Add((Get-HHRemoteOperationManifestEntry `
                -Phase BootstrapRollback `
                -PowerShellRuntime PowerShell7 `
                -ScriptText ((Get-HHSshAuthorizedKeyRollbackScriptBlock).ToString()) `
                -ArgumentList @($KeyMaterial.ExactLine) `
                -Conditional $true))
    return @($operations)
}

function Assert-HHSshKeyBootstrapPreparedOperation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object] $PreparedOperation
    )

    if ($null -eq $PreparedOperation.PSObject.Properties['Marker'] -or
        $PreparedOperation.Marker -cne 'HostHunter.SshKeyBootstrapPreparedOperation.v1' -or
        $null -eq $PreparedOperation.PSObject.Properties['Plan'] -or
        $null -eq $PreparedOperation.PSObject.Properties['KeyMaterial'] -or
        $null -eq $PreparedOperation.PSObject.Properties['LocalGenerationOccurred'] -or
        $null -eq $PreparedOperation.PSObject.Properties['RemoteOperations']) {
        throw [ArgumentException]::new('The SSH key-bootstrap prepared operation is invalid.')
    }
    if ($null -eq $PreparedOperation.Plan -or
        $null -eq $PreparedOperation.KeyMaterial -or
        $PreparedOperation.KeyMaterial.Marker -notmatch '^hosthunter-ng:[A-Za-z0-9+/]+$' -or
        $PreparedOperation.KeyMaterial.ExactLine -cnotmatch '^ssh-ed25519\s+\S+\s+hosthunter-ng:[A-Za-z0-9+/]+$') {
        throw [ArgumentException]::new('The SSH key-bootstrap prepared key material is invalid.')
    }
    $expectedMaterial = Get-HHSshBootstrapPublicKey `
        -KeyPath $PreparedOperation.Plan.KeyPath `
        -PublicKeyReader {
            param($unusedPath)
            $null = $unusedPath
            $PreparedOperation.KeyMaterial.ExactLine
        }
    if ($expectedMaterial.ExactLine -cne [string] $PreparedOperation.KeyMaterial.ExactLine -or
        $expectedMaterial.Marker -cne [string] $PreparedOperation.KeyMaterial.Marker -or
        $expectedMaterial.Fingerprint -cne [string] $PreparedOperation.KeyMaterial.Fingerprint) {
        throw [ArgumentException]::new('The SSH key-bootstrap prepared key material is inconsistent.')
    }
    return $PreparedOperation
}

function Prepare-HHSshKeyBootstrapOperation {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseApprovedVerbs',
        '',
        Justification = 'Prepare is the explicit pre-network transaction phase named by the bootstrap contract.'
    )]
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)]
        [object] $Target,

        [Parameter(Mandatory)]
        [string] $KnownHostsPath,

        [Parameter(Mandatory)]
        [string] $KeyPath,

        [switch] $UseExistingKey,

        [ValidateRange(1, 300)]
        [int] $ConnectionTimeoutSeconds = 15,

        [scriptblock] $KeyGenerator,

        [scriptblock] $PublicKeyReader,

        [scriptblock] $KeyRemover
    )

    $plan = New-HHSshKeyBootstrapPlan `
        -Target $Target `
        -KnownHostsPath $KnownHostsPath `
        -KeyPath $KeyPath `
        -UseExistingKey:$UseExistingKey `
        -ConnectionTimeoutSeconds $ConnectionTimeoutSeconds
    if (-not $PSCmdlet.ShouldProcess($plan.KeyPath, 'Prepare exact Ed25519 bootstrap key material')) {
        $planned = [pscustomobject][ordered]@{
            Marker = 'HostHunter.SshKeyBootstrapPreparedOperation.v1'
            Planned = $true
            Plan = $plan
            KeyMaterial = $null
            LocalGenerationOccurred = $false
            RemoteOperations = @()
        }
        $planned.PSObject.TypeNames.Insert(0, 'HostHunter.SshKeyBootstrapPreparedOperation')
        return $planned
    }

    $generationAttempted = $false
    try {
        if (-not $plan.UseExistingKey) {
            $generationAttempted = $true
            if ($null -ne $KeyGenerator) {
                & $KeyGenerator $plan.KeyPath 'hosthunter-ng-dedicated'
            }
            else {
                Invoke-HHSshDefaultKeyGenerator `
                    -KeyPath $plan.KeyPath `
                    -Comment 'hosthunter-ng-dedicated'
            }
        }
        $keyMaterial = Get-HHSshBootstrapPublicKey `
            -KeyPath $plan.KeyPath `
            -PublicKeyReader $PublicKeyReader
    }
    catch {
        $preparationFailure = $_
        if ($generationAttempted) {
            try {
                Remove-HHSshGeneratedKey -KeyPath $plan.KeyPath -KeyRemover $KeyRemover
            }
            catch {
                $preparationFailure.Exception.Data['HHLocalKeyCleanupFailureType'] =
                    $_.Exception.GetType().FullName
            }
        }
        throw $preparationFailure
    }

    $prepared = [pscustomobject][ordered]@{
        Marker = 'HostHunter.SshKeyBootstrapPreparedOperation.v1'
        Planned = $false
        Plan = $plan
        KeyMaterial = $keyMaterial
        LocalGenerationOccurred = -not $plan.UseExistingKey
        RemoteOperations = @(
            New-HHSshKeyBootstrapRemoteOperationsManifest `
                -Plan $plan `
                -KeyMaterial $keyMaterial
        )
    }
    $prepared.PSObject.TypeNames.Insert(0, 'HostHunter.SshKeyBootstrapPreparedOperation')
    return $prepared
}

function Undo-HHSshKeyBootstrapPreparation {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)]
        [object] $PreparedOperation,

        [scriptblock] $KeyRemover
    )

    $prepared = Assert-HHSshKeyBootstrapPreparedOperation -PreparedOperation $PreparedOperation
    $attempted = [bool] $prepared.LocalGenerationOccurred
    if (-not $attempted -or
        -not $PSCmdlet.ShouldProcess($prepared.Plan.KeyPath, 'Remove exact locally generated SSH key pair')) {
        return [pscustomobject][ordered]@{
            Attempted = $attempted
            Removed = $false
            FailureType = $null
        }
    }
    try {
        Remove-HHSshGeneratedKey -KeyPath $prepared.Plan.KeyPath -KeyRemover $KeyRemover
        return [pscustomobject][ordered]@{
            Attempted = $true
            Removed = $true
            FailureType = $null
        }
    }
    catch {
        return [pscustomobject][ordered]@{
            Attempted = $true
            Removed = $false
            FailureType = $_.Exception.GetType().FullName
        }
    }
}

function Get-HHSshAuthorizedKeyInstallScriptBlock {
    [CmdletBinding()]
    param()

    return {
        param(
            [Parameter(Mandatory)]
            [string] $ExactLine,

            [Parameter(Mandatory)]
            [string] $Marker
        )

        $isAdministrator = $false
        if ($IsWindows) {
            $principal = [Security.Principal.WindowsPrincipal]::new(
                [Security.Principal.WindowsIdentity]::GetCurrent()
            )
            $isAdministrator = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        }
        $authorizedKeysPath = if ($IsWindows -and $isAdministrator) {
            Join-Path $env:ProgramData 'ssh/administrators_authorized_keys'
        }
        else {
            Join-Path (Join-Path $HOME '.ssh') 'authorized_keys'
        }
        $authorizedKeysDirectory = Split-Path -Parent $authorizedKeysPath
        [IO.Directory]::CreateDirectory($authorizedKeysDirectory) | Out-Null
        if (-not [IO.File]::Exists($authorizedKeysPath)) {
            [IO.File]::WriteAllText($authorizedKeysPath, '', [Text.UTF8Encoding]::new($false))
        }

        $existingLines = @([IO.File]::ReadAllLines($authorizedKeysPath))
        $markerSuffix = " $Marker"
        $markerCollisions = @($existingLines | Where-Object {
                $_.EndsWith($markerSuffix, [StringComparison]::Ordinal) -and $_ -cne $ExactLine
            })
        if ($markerCollisions.Count -gt 0) {
            throw 'The HostHunter authorized-key marker already belongs to a different key line.'
        }

        $added = $existingLines -cnotcontains $ExactLine
        if ($added) {
            $updatedLines = @($existingLines) + @($ExactLine)
            $temporaryPath = Join-Path $authorizedKeysDirectory (
                '.authorized_keys.hosthunter.{0}.tmp' -f [Guid]::NewGuid().ToString('N')
            )
            try {
                [IO.File]::WriteAllLines($temporaryPath, $updatedLines, [Text.UTF8Encoding]::new($false))
                if (-not $IsWindows) {
                    & chmod 0600 -- $temporaryPath
                    if ($LASTEXITCODE -ne 0) {
                        throw 'Unable to secure the temporary authorized_keys file.'
                    }
                }
                [IO.File]::Move($temporaryPath, $authorizedKeysPath, $true)
            }
            finally {
                if ([IO.File]::Exists($temporaryPath)) {
                    [IO.File]::Delete($temporaryPath)
                }
            }
        }

        if ($IsWindows) {
            $identityName = [Security.Principal.WindowsIdentity]::GetCurrent().Name
            $grants = if ($isAdministrator) {
                @('*S-1-5-32-544:(F)', '*S-1-5-18:(F)')
            }
            else {
                @("${identityName}:(F)", '*S-1-5-18:(F)')
            }
            & icacls $authorizedKeysPath '/inheritance:r' '/grant:r' $grants[0] $grants[1] | Out-Null
            if ($LASTEXITCODE -ne 0) {
                throw 'Unable to secure the Windows authorized_keys file.'
            }
        }
        else {
            & chmod 0700 -- $authorizedKeysDirectory
            $directoryExit = $LASTEXITCODE
            & chmod 0600 -- $authorizedKeysPath
            if ($directoryExit -ne 0 -or $LASTEXITCODE -ne 0) {
                throw 'Unable to secure the Unix authorized_keys path.'
            }
        }

        [pscustomobject][ordered]@{
            Operation = 'HostHunterAuthorizedKeyInstall.v1'
            Added = $added
            Marker = $Marker
            AuthorizedKeysPath = $authorizedKeysPath
        }
    }
}

function Get-HHSshAuthorizedKeyRollbackScriptBlock {
    [CmdletBinding()]
    param()

    return {
        param(
            [Parameter(Mandatory)]
            [string] $ExactLine
        )

        $isAdministrator = $false
        if ($IsWindows) {
            $principal = [Security.Principal.WindowsPrincipal]::new(
                [Security.Principal.WindowsIdentity]::GetCurrent()
            )
            $isAdministrator = $principal.IsInRole(
                [Security.Principal.WindowsBuiltInRole]::Administrator
            )
        }
        $authorizedKeysPath = if ($IsWindows -and $isAdministrator) {
            Join-Path $env:ProgramData 'ssh/administrators_authorized_keys'
        }
        else {
            Join-Path (Join-Path $HOME '.ssh') 'authorized_keys'
        }
        $removed = $false
        if ([IO.File]::Exists($authorizedKeysPath)) {
            $existingLines = @([IO.File]::ReadAllLines($authorizedKeysPath))
            $removeIndex = -1
            for ($index = $existingLines.Count - 1; $index -ge 0; $index--) {
                if ($existingLines[$index] -ceq $ExactLine) {
                    $removeIndex = $index
                    break
                }
            }
            if ($removeIndex -ge 0) {
                $updatedLines = [Collections.Generic.List[string]]::new()
                for ($index = 0; $index -lt $existingLines.Count; $index++) {
                    if ($index -ne $removeIndex) {
                        $updatedLines.Add($existingLines[$index])
                    }
                }
                $directory = Split-Path -Parent $authorizedKeysPath
                $temporaryPath = Join-Path $directory (
                    '.authorized_keys.hosthunter.rollback.{0}.tmp' -f [Guid]::NewGuid().ToString('N')
                )
                try {
                    [IO.File]::WriteAllLines(
                        $temporaryPath,
                        [string[]] $updatedLines,
                        [Text.UTF8Encoding]::new($false)
                    )
                    if (-not $IsWindows) {
                        & chmod 0600 -- $temporaryPath
                        if ($LASTEXITCODE -ne 0) {
                            throw 'Unable to secure the rollback authorized_keys file.'
                        }
                    }
                    [IO.File]::Move($temporaryPath, $authorizedKeysPath, $true)
                    $removed = $true
                }
                finally {
                    if ([IO.File]::Exists($temporaryPath)) {
                        [IO.File]::Delete($temporaryPath)
                    }
                }
            }
        }

        if ($removed -and -not $IsWindows) {
            & chmod 0600 -- $authorizedKeysPath
            if ($LASTEXITCODE -ne 0) {
                throw 'Unable to restore authorized_keys permissions after rollback.'
            }
        }

        $presentAfter = [IO.File]::Exists($authorizedKeysPath) -and
            @([IO.File]::ReadAllLines($authorizedKeysPath) | Where-Object {
                    $_ -ceq $ExactLine
                }).Count -gt 0

        [pscustomobject][ordered]@{
            Operation = 'HostHunterAuthorizedKeyRollback.v1'
            Removed = $removed
            PresentAfter = $presentAfter
        }
    }
}

function Get-HHSshAuthorizedKeyReconciliationScriptBlock {
    [CmdletBinding()]
    param()

    return {
        param(
            [Parameter(Mandatory)]
            [string] $ExactLine
        )

        $isAdministrator = $false
        if ($IsWindows) {
            $principal = [Security.Principal.WindowsPrincipal]::new(
                [Security.Principal.WindowsIdentity]::GetCurrent()
            )
            $isAdministrator = $principal.IsInRole(
                [Security.Principal.WindowsBuiltInRole]::Administrator
            )
        }
        $authorizedKeysPath = if ($IsWindows -and $isAdministrator) {
            Join-Path $env:ProgramData 'ssh/administrators_authorized_keys'
        }
        else {
            Join-Path (Join-Path $HOME '.ssh') 'authorized_keys'
        }
        $exactMatchCount = if ([IO.File]::Exists($authorizedKeysPath)) {
            @([IO.File]::ReadAllLines($authorizedKeysPath) | Where-Object {
                    $_ -ceq $ExactLine
                }).Count
        }
        else {
            0
        }
        [pscustomobject][ordered]@{
            Operation = 'HostHunterAuthorizedKeyReconciliation.v1'
            Present = $exactMatchCount -gt 0
            ExactMatchCount = $exactMatchCount
        }
    }
}

function Get-HHSshBootstrapOperationOutput {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $StreamEvents,

        [Parameter(Mandatory)]
        [string] $Operation
    )

    $operationMatches = @(
        $StreamEvents |
            Where-Object {
                $_.Stream -ceq 'Output' -and
                $null -ne $_.Value -and
                $null -ne $_.Value.PSObject.Properties['Operation'] -and
                $_.Value.Operation -ceq $Operation
            } |
            Select-Object -ExpandProperty Value
    )
    if ($operationMatches.Count -ne 1) {
        throw (New-HHSshClassifiedException -FailureKind TransportFailure `
                -Message "SSH key bootstrap operation '$Operation' returned an invalid result count.")
    }
    return $operationMatches[0]
}

function Get-HHSshBootstrapFiniteText {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object] $Value,

        [ValidateRange(1, 4096)]
        [int] $MaximumLength = 1024
    )

    $text = if ($null -eq $Value) { '' } else { [string] $Value }
    if ($text.Length -le $MaximumLength) {
        return $text
    }
    return $text.Substring(0, $MaximumLength)
}

function ConvertTo-HHSshBootstrapErrorProjection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object] $ErrorObject
    )

    $errorRecord = if ($ErrorObject -is [Management.Automation.ErrorRecord]) {
        $ErrorObject
    }
    else {
        $null
    }
    $exception = if ($null -ne $errorRecord) {
        $errorRecord.Exception
    }
    elseif ($ErrorObject -is [Exception]) {
        $ErrorObject
    }
    else {
        $null
    }
    $message = if ($null -ne $exception) {
        Get-HHSshBootstrapFiniteText -Value $exception.Message
    }
    else {
        Get-HHSshBootstrapFiniteText -Value $ErrorObject
    }
    $failureKind = try {
        Get-HHSshFailureKind -ErrorObject $ErrorObject
    }
    catch {
        'TransportFailure'
    }

    return [pscustomobject][ordered]@{
        Message = $message
        ExceptionType = if ($null -eq $exception) {
            $ErrorObject.GetType().FullName
        }
        else {
            $exception.GetType().FullName
        }
        FailureKind = $failureKind
        FullyQualifiedErrorId = if ($null -eq $errorRecord) {
            $null
        }
        else {
            Get-HHSshBootstrapFiniteText -Value $errorRecord.FullyQualifiedErrorId -MaximumLength 256
        }
        Category = if ($null -eq $errorRecord) {
            $null
        }
        else {
            [string] $errorRecord.CategoryInfo.Category
        }
    }
}

function Add-HHSshBootstrapEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [Collections.Generic.List[object]] $Destination,

        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]] $SourceEvents,

        [Parameter(Mandatory)]
        [ValidateRange(1, [long]::MaxValue)]
        [long] $RemainingBytes,

        [scriptblock] $Clock
    )

    [long] $addedBytes = 0
    foreach ($sourceEvent in $SourceEvents) {
        $isStreamEvent = $null -ne $sourceEvent -and
            $null -ne $sourceEvent.PSObject.Properties['Phase'] -and
            $null -ne $sourceEvent.PSObject.Properties['Stream'] -and
            $null -ne $sourceEvent.PSObject.Properties['Value']
        $value = if (-not $isStreamEvent) {
            [pscustomobject][ordered]@{
                Message = 'The SSH bootstrap received malformed partial stream evidence.'
                ExceptionType = if ($null -eq $sourceEvent) { 'null' } else { $sourceEvent.GetType().FullName }
                FailureKind = 'TransportFailure'
                FullyQualifiedErrorId = $null
                Category = $null
            }
        }
        elseif ($sourceEvent.Value -is [Management.Automation.ErrorRecord] -or
            $sourceEvent.Value -is [Exception]) {
            ConvertTo-HHSshBootstrapErrorProjection -ErrorObject $sourceEvent.Value
        }
        else {
            $sourceEvent.Value
        }
        $stream = if ($isStreamEvent -and
            [string] $sourceEvent.Stream -cin @(
                'Output', 'Error', 'Warning', 'Verbose', 'Debug', 'Information', 'Progress'
            )) {
            [string] $sourceEvent.Stream
        }
        else {
            'Error'
        }
        $phase = if ($isStreamEvent -and
            -not [string]::IsNullOrWhiteSpace([string] $sourceEvent.Phase)) {
            [string] $sourceEvent.Phase
        }
        else {
            'Bootstrap'
        }
        $typeName = if ($isStreamEvent -and
            -not [string]::IsNullOrWhiteSpace([string] $sourceEvent.TypeName)) {
            [string] $sourceEvent.TypeName
        }
        elseif ($null -eq $value) {
            'null'
        }
        else {
            $value.GetType().FullName
        }
        $remoteSequence = if ($isStreamEvent -and
            $null -ne $sourceEvent.PSObject.Properties['RemoteSequence']) {
            $sourceEvent.RemoteSequence
        }
        else {
            $null
        }
        $terminating = $isStreamEvent -and
            $null -ne $sourceEvent.PSObject.Properties['IsTerminating'] -and
            [bool] $sourceEvent.IsTerminating
        $eventParameters = @{
            Sequence = $Destination.Count
            Phase = $phase
            InputObject = $value
            StreamOverride = $stream
            TypeNameOverride = $typeName
            IsTerminating = $terminating
            Clock = $Clock
        }
        if ($null -ne $remoteSequence) {
            $eventParameters.RemoteSequence = [int] $remoteSequence
        }
        $eventRecord = New-HHSshStreamEvent @eventParameters
        if ($addedBytes + [long] $eventRecord.SerializedByteCount -gt $RemainingBytes) {
            throw (New-HHSshClassifiedException `
                    -FailureKind OutputLimitExceeded `
                    -Message "The cumulative SSH bootstrap output limit of $RemainingBytes remaining bytes was exceeded.")
        }
        $Destination.Add($eventRecord)
        $addedBytes += [long] $eventRecord.SerializedByteCount
    }
    return $addedBytes
}

function Add-HHSshBootstrapFiniteFailureEvent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [Collections.Generic.List[object]] $Destination,

        [Parameter(Mandatory)]
        [object] $ErrorObject,

        [Parameter(Mandatory)]
        [string] $Phase,

        [Parameter(Mandatory)]
        [ValidateRange(0, [long]::MaxValue)]
        [long] $RemainingBytes,

        [scriptblock] $Clock
    )

    if ($RemainingBytes -le 0) {
        return [long] 0
    }
    $projection = ConvertTo-HHSshBootstrapErrorProjection -ErrorObject $ErrorObject
    $eventRecord = New-HHSshStreamEvent `
        -Sequence $Destination.Count `
        -Phase $Phase `
        -InputObject $projection `
        -StreamOverride Error `
        -TypeNameOverride 'HostHunter.FiniteErrorProjection.v1' `
        -IsTerminating $true `
        -Clock $Clock
    if ([long] $eventRecord.SerializedByteCount -gt $RemainingBytes) {
        return [long] 0
    }
    $Destination.Add($eventRecord)
    return [long] $eventRecord.SerializedByteCount
}

function Get-HHSshBootstrapExceptionDataValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object] $ErrorObject,

        [Parameter(Mandatory)]
        [string] $Name
    )

    $exception = if ($ErrorObject -is [Management.Automation.ErrorRecord]) {
        $ErrorObject.Exception
    }
    elseif ($ErrorObject -is [Exception]) {
        $ErrorObject
    }
    else {
        $null
    }
    while ($null -ne $exception) {
        if ($exception.Data.Contains($Name)) {
            return $exception.Data[$Name]
        }
        $exception = $exception.InnerException
    }
    return $null
}

function Get-HHSshBootstrapObservedMismatchContext {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object] $ErrorObject,

        [Parameter(Mandatory)]
        [ValidateSet('PowerShell7')]
        [string] $RequestedPowerShellRuntime,

        [Parameter(Mandatory)]
        [string] $ExpectedHostKeyFingerprint
    )

    $null = $RequestedPowerShellRuntime

    if ((Get-HHSshFailureKind -ErrorObject $ErrorObject) -cne 'RuntimeMismatch') {
        return $null
    }

    $identity = Get-HHSshBootstrapExceptionDataValue `
        -ErrorObject $ErrorObject `
        -Name HHObservedIdentity
    $remotePowerShellVersion = [string] (
        Get-HHSshBootstrapExceptionDataValue `
            -ErrorObject $ErrorObject `
            -Name HHObservedRemotePowerShellVersion
    )
    $remotePSEdition = [string] (
        Get-HHSshBootstrapExceptionDataValue `
            -ErrorObject $ErrorObject `
            -Name HHObservedRemotePSEdition
    )
    $executionMode = [string] (
        Get-HHSshBootstrapExceptionDataValue `
            -ErrorObject $ErrorObject `
            -Name HHObservedExecutionMode
    )
    $validatedAtUtc = [string] (
        Get-HHSshBootstrapExceptionDataValue `
            -ErrorObject $ErrorObject `
            -Name HHObservedValidatedAtUtc
    )
    $hostKeyFingerprint = [string] (
        Get-HHSshBootstrapExceptionDataValue `
            -ErrorObject $ErrorObject `
            -Name HHObservedHostKeyFingerprint
    )

    if ($null -eq $identity -or
        [string]::IsNullOrWhiteSpace($remotePowerShellVersion) -or
        $remotePSEdition -cne 'Core' -or
        $executionMode -cne 'Direct' -or
        [string]::IsNullOrWhiteSpace($validatedAtUtc) -or
        $hostKeyFingerprint -cne $ExpectedHostKeyFingerprint -or
        $hostKeyFingerprint -cnotmatch '^SHA256:[A-Za-z0-9+/]{43}$') {
        return $null
    }

    $identityValues = @{}
    foreach ($name in @(
            'Marker',
            'PSEdition',
            'PowerShellVersion',
            'ProcessPath',
            'UserName',
            'MachineName'
        )) {
        $property = $identity.PSObject.Properties[$name]
        if ($null -eq $property -or
            [string]::IsNullOrWhiteSpace([string] $property.Value)) {
            return $null
        }
        $identityValues[$name] = [string] $property.Value
    }
    if ($identityValues.Marker -cne 'HostHunter.PowerShellIdentity.v1' -or
        $identityValues.PSEdition -cne $remotePSEdition -or
        $identityValues.PowerShellVersion -cne $remotePowerShellVersion) {
        return $null
    }

    $version = $null
    $observedAt = [DateTimeOffset]::MinValue
    if (-not [version]::TryParse($remotePowerShellVersion, [ref] $version) -or
        -not [DateTimeOffset]::TryParse($validatedAtUtc, [ref] $observedAt)) {
        return $null
    }
    $processLeaf = @($identityValues.ProcessPath -split '[\\/]')[-1]
    $processName = [IO.Path]::GetFileNameWithoutExtension($processLeaf)
    if ($processName -cne 'pwsh') {
        return $null
    }

    $isRequestedRuntime = $remotePSEdition -ceq 'Core' -and
        $version.Major -ge 7 -and
        $executionMode -ceq 'Direct'
    if ($isRequestedRuntime) {
        return $null
    }

    return [pscustomobject][ordered]@{
        Identity = $identity
        RemotePowerShellVersion = $remotePowerShellVersion
        RemotePSEdition = $remotePSEdition
        ExecutionMode = $executionMode
        HostKeyFingerprint = $hostKeyFingerprint
        ValidatedAtUtc = $observedAt.ToUniversalTime().ToString('o')
    }
}

function New-HHSshBootstrapCommitReceipt {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'This creates a fixed finite projection of an already completed callback result.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object] $CallbackReceipt,

        [Parameter(Mandatory)]
        [string] $TargetName
    )

    $committedProperty = $CallbackReceipt.PSObject.Properties['Committed']
    if ($null -eq $committedProperty -or
        $committedProperty.Value -isnot [bool] -or
        -not [bool] $committedProperty.Value) {
        throw [IO.InvalidDataException]::new(
            'The profile-transition committer did not return a proven Committed=true receipt.'
        )
    }
    return [pscustomobject][ordered]@{
        Committed = $true
        TargetName = $TargetName
        PreviousAuthentication = 'Password'
        CurrentAuthentication = 'PublicKey'
        ReceiptType = $CallbackReceipt.GetType().FullName
    }
}

function Invoke-HHSshKeyBootstrap {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High', DefaultParameterSetName = 'Direct')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Direct')]
        [object] $Target,

        [Parameter(Mandatory, ParameterSetName = 'Direct')]
        [string] $KnownHostsPath,

        [Parameter(Mandatory, ParameterSetName = 'Direct')]
        [string] $KeyPath,

        [Parameter(ParameterSetName = 'Direct')]
        [switch] $UseExistingKey,

        [Parameter(ParameterSetName = 'Direct')]
        [ValidateRange(1, 300)]
        [int] $ConnectionTimeoutSeconds = 15,

        [Parameter(Mandatory, ParameterSetName = 'Prepared')]
        [object] $PreparedOperation,

        [ValidateRange(1, [long]::MaxValue)]
        [long] $MaxOutputBytes = 104857600,

        [scriptblock] $SessionFactory,

        [scriptblock] $RemoteInvoker,

        [scriptblock] $SessionRemover,

        [Parameter(ParameterSetName = 'Direct')]
        [scriptblock] $KeyGenerator,

        [Parameter(ParameterSetName = 'Direct')]
        [scriptblock] $PublicKeyReader,

        [scriptblock] $KeyRemover,

        [scriptblock] $ProfileTransitionCommitter,

        [scriptblock] $OperationArmer,

        [scriptblock] $Clock
    )

    $prepared = $null
    $plan = if ($PSCmdlet.ParameterSetName -ceq 'Prepared') {
        if ($null -ne $PreparedOperation.PSObject.Properties['Planned'] -and
            [bool] $PreparedOperation.Planned) {
            throw [ArgumentException]::new(
                'A plan-only SSH key-bootstrap preparation cannot be executed.'
            )
        }
        $prepared = Assert-HHSshKeyBootstrapPreparedOperation `
            -PreparedOperation $PreparedOperation
        $prepared.Plan
    }
    else {
        New-HHSshKeyBootstrapPlan `
            -Target $Target `
            -KnownHostsPath $KnownHostsPath `
            -KeyPath $KeyPath `
            -UseExistingKey:$UseExistingKey `
            -ConnectionTimeoutSeconds $ConnectionTimeoutSeconds
    }
    $targetDescription = 'SSH://{0}@{1}:{2}' -f @(
        $plan.Target.UserName,
        $plan.Target.HostName,
        $plan.Target.Port
    )
    if (-not $PSCmdlet.ShouldProcess(
            $targetDescription,
            'Install and prove a dedicated HostHunter Ed25519 public key'
        )) {
        $plannedResult = [pscustomobject][ordered]@{
            Succeeded = $true
            Planned = $true
            FailureKind = $null
            DispatchState = 'NotDispatched'
            OutcomeStatus = 'Succeeded'
            ProfileTransition = $null
            Installed = $false
            ReconciliationAttempted = $false
            ReconciliationSucceeded = $null
            ReconciliationPresent = $null
            RollbackRequired = $false
            RollbackAttempted = $false
            RollbackSucceeded = $null
            CommitState = 'NotRequested'
            CommitReceipt = $null
            ReconciliationRequired = $false
            LocalKeyRemovedOnFailure = $false
            LocalKeyRemovalFailure = $null
            StreamEvents = @()
            OutputBytes = [long] 0
            EvidenceTruncated = $false
            RemotePowerShellVersion = $null
            RemotePSEdition = $null
            ExecutionMode = $null
            HostKeyFingerprint = $null
            RemoteIdentity = $null
            ValidatedAtUtc = $null
            ExceptionType = $null
            SessionRemovalFailure = $false
            SessionRemovalFailures = @()
            Plan = $plan
        }
        $plannedResult.PSObject.TypeNames.Insert(0, 'HostHunter.SshKeyBootstrapResult')
        return $plannedResult
    }

    $passwordContext = $null
    $publicKeyContext = $null
    $keyMaterial = $null
    $transition = $null
    $installOutput = $null
    [Nullable[bool]] $installed = $false
    $installAttempted = $false
    $rollbackRequired = $false
    $rollbackAttempted = $false
    [Nullable[bool]] $rollbackSucceeded = $null
    $rollbackFailure = $null
    $reconciliationAttempted = $false
    [Nullable[bool]] $reconciliationSucceeded = $null
    [Nullable[bool]] $reconciliationPresent = $null
    $reconciliationFailure = $null
    $localGenerationOccurred = $false
    $localKeyRemoved = $false
    $localKeyRemovalFailure = $null
    $commitState = 'NotRequested'
    $commitReceipt = $null
    $commitStateUnknown = $false
    $sessionRemovalFailure = $false
    $sessionRemovalFailures = [Collections.Generic.List[string]]::new()
    $allEvents = [Collections.Generic.List[object]]::new()
    [long] $outputBytes = 0
    $evidenceTruncated = $false
    $dispatchState = 'NotDispatched'
    $outcomeStatus = 'Failed'
    $mismatchEvidencePhase = $null
    $observedMismatchContext = $null
    $result = $null

    try {
        if ($null -eq $prepared) {
            $prepared = Prepare-HHSshKeyBootstrapOperation `
                -Target $plan.Target `
                -KnownHostsPath $plan.KnownHostsPath `
                -KeyPath $plan.KeyPath `
                -UseExistingKey:$plan.UseExistingKey `
                -ConnectionTimeoutSeconds $plan.ConnectionTimeoutSeconds `
                -KeyGenerator $KeyGenerator `
                -PublicKeyReader $PublicKeyReader `
                -KeyRemover $KeyRemover `
                -Confirm:$false
        }
        $keyMaterial = $prepared.KeyMaterial
        $localGenerationOccurred = [bool] $prepared.LocalGenerationOccurred

        [long] $remainingBytes = $MaxOutputBytes - $outputBytes
        try {
            if ($null -ne $OperationArmer) {
                & $OperationArmer @('OuterIdentity')
            }
            $passwordContext = Open-HHSshValidatedSession `
                -Plan $plan.PasswordTransportPlan `
                -SessionFactory $SessionFactory `
                -RemoteInvoker $RemoteInvoker `
                -SessionRemover $SessionRemover `
                -Clock $Clock `
                -MaxOutputBytes $remainingBytes
        }
        catch {
            $passwordOpenFailure = $_
            if ((Get-HHSshFailureKind -ErrorObject $passwordOpenFailure) -ceq 'RuntimeMismatch') {
                $mismatchEvidencePhase = 'PasswordIdentity'
                $observedMismatchContext = Get-HHSshBootstrapObservedMismatchContext `
                    -ErrorObject $passwordOpenFailure `
                    -RequestedPowerShellRuntime $plan.Target.PowerShellRuntime `
                    -ExpectedHostKeyFingerprint $plan.Target.HostKeyFingerprint
            }
            $partialEvents = Get-HHSshBootstrapExceptionDataValue `
                -ErrorObject $passwordOpenFailure `
                -Name HHStreamEvents
            if ($null -ne $partialEvents -and @($partialEvents).Count -gt 0) {
                try {
                    $addedBytes = Add-HHSshBootstrapEvidence `
                        -Destination $allEvents `
                        -SourceEvents @($partialEvents) `
                        -RemainingBytes ($MaxOutputBytes - $outputBytes) `
                        -Clock $Clock
                    $outputBytes += $addedBytes
                }
                catch {
                    $evidenceTruncated = $true
                }
            }
            throw $passwordOpenFailure
        }
        $addedBytes = Add-HHSshBootstrapEvidence `
            -Destination $allEvents `
            -SourceEvents @($passwordContext.IdentityEvents) `
            -RemainingBytes ($MaxOutputBytes - $outputBytes) `
            -Clock $Clock
        $outputBytes += $addedBytes

        $remainingBytes = $MaxOutputBytes - $outputBytes
        if ($remainingBytes -le 0) {
            throw (New-HHSshClassifiedException -FailureKind OutputLimitExceeded `
                    -Message 'No output budget remains before authorized-key installation.')
        }
        $installAttempted = $true
        $installFailure = $null
        try {
            if ($null -ne $OperationArmer) { & $OperationArmer @('BootstrapInstall') }
            $installEvents = @(Invoke-HHSshRemoteCapture `
                    -Session $passwordContext.Session `
                    -ScriptBlock (Get-HHSshAuthorizedKeyInstallScriptBlock) `
                    -ArgumentList @($keyMaterial.ExactLine, $keyMaterial.Marker) `
                    -Phase BootstrapInstall `
                    -MaxOutputBytes $remainingBytes `
                    -RemoteInvoker $RemoteInvoker `
                    -Clock $Clock)
            $addedBytes = Add-HHSshBootstrapEvidence `
                -Destination $allEvents `
                -SourceEvents $installEvents `
                -RemainingBytes ($MaxOutputBytes - $outputBytes) `
                -Clock $Clock
            $outputBytes += $addedBytes
            $installOutput = Get-HHSshBootstrapOperationOutput `
                -StreamEvents $installEvents `
                -Operation 'HostHunterAuthorizedKeyInstall.v1'
            if ($null -eq $installOutput.PSObject.Properties['Added'] -or
                $installOutput.Added -isnot [bool]) {
                throw (New-HHSshClassifiedException -FailureKind TransportFailure `
                        -Message 'SSH key installation returned invalid Added state.')
            }
            $installed = [bool] $installOutput.Added
            $rollbackRequired = [bool] $installOutput.Added
            $dispatchState = 'Completed'
        }
        catch {
            $installFailure = $_
            $partialEvents = Get-HHSshBootstrapExceptionDataValue `
                -ErrorObject $installFailure `
                -Name HHStreamEvents
            if ($null -ne $partialEvents -and @($partialEvents).Count -gt 0) {
                try {
                    $addedBytes = Add-HHSshBootstrapEvidence `
                        -Destination $allEvents `
                        -SourceEvents @($partialEvents) `
                        -RemainingBytes ($MaxOutputBytes - $outputBytes) `
                        -Clock $Clock
                    $outputBytes += $addedBytes
                }
                catch {
                    $evidenceTruncated = $true
                }
            }
            $reportedInstallDispatch = [string] (
                Get-HHSshBootstrapExceptionDataValue `
                    -ErrorObject $installFailure `
                    -Name HHDispatchState
            )
            if ($reportedInstallDispatch -ceq 'NotDispatched') {
                $installed = $false
                $dispatchState = 'NotDispatched'
            }
            else {
                $installed = $null
                $dispatchState = 'DispatchUncertain'
                $reconciliationAttempted = $true
                try {
                    $remainingBytes = $MaxOutputBytes - $outputBytes
                    if ($remainingBytes -le 0) {
                        throw (New-HHSshClassifiedException -FailureKind OutputLimitExceeded `
                                -Message 'No output budget remains before exact-line reconciliation.')
                    }
                    if ($null -ne $OperationArmer) {
                        & $OperationArmer @('BootstrapReconcile')
                    }
                    $reconciliationEvents = @(Invoke-HHSshRemoteCapture `
                            -Session $passwordContext.Session `
                            -ScriptBlock (Get-HHSshAuthorizedKeyReconciliationScriptBlock) `
                            -ArgumentList @($keyMaterial.ExactLine) `
                            -Phase BootstrapReconcile `
                            -MaxOutputBytes $remainingBytes `
                            -RemoteInvoker $RemoteInvoker `
                            -Clock $Clock)
                    $addedBytes = Add-HHSshBootstrapEvidence `
                        -Destination $allEvents `
                        -SourceEvents $reconciliationEvents `
                        -RemainingBytes ($MaxOutputBytes - $outputBytes) `
                        -Clock $Clock
                    $outputBytes += $addedBytes
                    $reconciliationOutput = Get-HHSshBootstrapOperationOutput `
                        -StreamEvents $reconciliationEvents `
                        -Operation 'HostHunterAuthorizedKeyReconciliation.v1'
                    if ($null -eq $reconciliationOutput.PSObject.Properties['Present'] -or
                        $reconciliationOutput.Present -isnot [bool]) {
                        throw (New-HHSshClassifiedException -FailureKind TransportFailure `
                                -Message 'SSH key reconciliation returned invalid Present state.')
                    }
                    $reconciliationSucceeded = $true
                    $reconciliationPresent = [bool] $reconciliationOutput.Present
                    $installed = [bool] $reconciliationOutput.Present
                    $rollbackRequired = [bool] $reconciliationOutput.Present
                    $dispatchState = 'Completed'
                }
                catch {
                    $reconciliationFailure = $_
                    $reconciliationSucceeded = $false
                    $reconciliationPresent = $null
                    $installed = $null
                    $partialEvents = Get-HHSshBootstrapExceptionDataValue `
                        -ErrorObject $reconciliationFailure `
                        -Name HHStreamEvents
                    if ($null -ne $partialEvents -and @($partialEvents).Count -gt 0) {
                        try {
                            $addedBytes = Add-HHSshBootstrapEvidence `
                                -Destination $allEvents `
                                -SourceEvents @($partialEvents) `
                                -RemainingBytes ($MaxOutputBytes - $outputBytes) `
                                -Clock $Clock
                            $outputBytes += $addedBytes
                        }
                        catch {
                            $evidenceTruncated = $true
                        }
                    }
                }
            }
        }
        if ($null -ne $installFailure) {
            throw $installFailure
        }

        $candidate = New-HHTargetRecord `
            -Name $plan.Target.Name `
            -Transport SSH `
            -HostName $plan.Target.HostName `
            -Port $plan.Target.Port `
            -UserName $plan.Target.UserName `
            -Authentication PublicKey `
            -PowerShellRuntime $plan.Target.PowerShellRuntime `
            -HostKeyFingerprint $plan.Target.HostKeyFingerprint `
            -KeyPath $plan.KeyPath `
            -IsActive $plan.Target.IsActive `
            -LastValidatedAtUtc $passwordContext.ValidatedAtUtc `
            -LastValidatedPSEdition $passwordContext.RemotePSEdition `
            -LastValidatedPowerShellVersion $passwordContext.RemotePowerShellVersion `
            -LastValidatedExecutionMode $passwordContext.ExecutionMode
        $publicKeyPlan = New-HHSshTransportPlan `
            -Target $candidate `
            -KnownHostsPath $plan.KnownHostsPath `
            -ConnectionTimeoutSeconds $plan.ConnectionTimeoutSeconds
        $remainingBytes = $MaxOutputBytes - $outputBytes
        if ($remainingBytes -le 0) {
            throw (New-HHSshClassifiedException -FailureKind OutputLimitExceeded `
                    -Message 'No output budget remains before the public-key-only identity proof.')
        }
        try {
            if ($null -ne $OperationArmer) {
                & $OperationArmer @('BootstrapKeyOnlyOuterIdentity')
            }
            $publicKeyContext = Open-HHSshValidatedSession `
                -Plan $publicKeyPlan `
                -SessionFactory $SessionFactory `
                -RemoteInvoker $RemoteInvoker `
                -SessionRemover $SessionRemover `
                -Clock $Clock `
                -MaxOutputBytes $remainingBytes
        }
        catch {
            $keyProofError = $_
            if ((Get-HHSshFailureKind -ErrorObject $keyProofError) -ceq 'RuntimeMismatch') {
                $mismatchEvidencePhase = 'PublicKeyIdentity'
                $observedMismatchContext = Get-HHSshBootstrapObservedMismatchContext `
                    -ErrorObject $keyProofError `
                    -RequestedPowerShellRuntime $plan.Target.PowerShellRuntime `
                    -ExpectedHostKeyFingerprint $plan.Target.HostKeyFingerprint
            }
            $partialEvents = Get-HHSshBootstrapExceptionDataValue `
                -ErrorObject $keyProofError `
                -Name HHStreamEvents
            if ($null -ne $partialEvents -and @($partialEvents).Count -gt 0) {
                try {
                    $addedBytes = Add-HHSshBootstrapEvidence `
                        -Destination $allEvents `
                        -SourceEvents @($partialEvents) `
                        -RemainingBytes ($MaxOutputBytes - $outputBytes) `
                        -Clock $Clock
                    $outputBytes += $addedBytes
                }
                catch {
                    $evidenceTruncated = $true
                }
            }
            $keyProofFailureKind = Get-HHSshFailureKind -ErrorObject $keyProofError
            if ($keyProofFailureKind -ceq 'TransportFailure' -and
                ($keyProofError.FullyQualifiedErrorId -like 'PSSessionOpenFailed*' -or
                    $keyProofError.Exception.GetType().FullName -eq
                    'System.Management.Automation.Remoting.PSRemotingTransportException')) {
                throw (New-HHSshClassifiedException `
                        -FailureKind AuthenticationFailure `
                        -Message 'The separate SSH public-key-only proof did not authenticate.' `
                        -InnerException $keyProofError.Exception)
            }
            throw $keyProofError
        }
        $addedBytes = Add-HHSshBootstrapEvidence `
            -Destination $allEvents `
            -SourceEvents @($publicKeyContext.IdentityEvents) `
            -RemainingBytes ($MaxOutputBytes - $outputBytes) `
            -Clock $Clock
        $outputBytes += $addedBytes

        $transition = New-HHTargetRecord `
            -Name $plan.Target.Name `
            -Transport SSH `
            -HostName $plan.Target.HostName `
            -Port $plan.Target.Port `
            -UserName $plan.Target.UserName `
            -Authentication PublicKey `
            -PowerShellRuntime $plan.Target.PowerShellRuntime `
            -HostKeyFingerprint $publicKeyContext.HostKeyFingerprint `
            -KeyPath $plan.KeyPath `
            -IsActive $plan.Target.IsActive `
            -LastValidatedAtUtc $publicKeyContext.ValidatedAtUtc `
            -LastValidatedPSEdition $publicKeyContext.RemotePSEdition `
            -LastValidatedPowerShellVersion $publicKeyContext.RemotePowerShellVersion `
            -LastValidatedExecutionMode $publicKeyContext.ExecutionMode

        if ($null -ne $ProfileTransitionCommitter) {
            $callbackReceipts = $null
            try {
                $callbackReceipts = @(& $ProfileTransitionCommitter `
                        $transition `
                        $plan.Target `
                        $prepared)
            }
            catch {
                $commitError = $_
                $reportedCommitState = [string] (
                    Get-HHSshBootstrapExceptionDataValue `
                        -ErrorObject $commitError `
                        -Name HHTargetStoreCommitState
                )
                if ($reportedCommitState -ceq 'Unknown') {
                    $commitState = 'Unknown'
                    $commitStateUnknown = $true
                }
                else {
                    $commitState = 'Failed'
                }
                throw $commitError
            }
            if (@($callbackReceipts).Count -ne 1) {
                $commitState = 'Unknown'
                $commitStateUnknown = $true
                throw [IO.InvalidDataException]::new(
                    'The profile-transition committer returned an invalid receipt count.'
                )
            }
            try {
                $commitReceipt = New-HHSshBootstrapCommitReceipt `
                    -CallbackReceipt $callbackReceipts[0] `
                    -TargetName $transition.Name
                $commitState = 'Committed'
            }
            catch {
                $commitState = 'Unknown'
                $commitStateUnknown = $true
                throw
            }
        }

        $dispatchState = 'Completed'
        $outcomeStatus = 'Succeeded'
        $result = [pscustomobject][ordered]@{
            Succeeded = $true
            Planned = $false
            FailureKind = $null
            DispatchState = $dispatchState
            OutcomeStatus = $outcomeStatus
            ProfileTransition = $transition
            Installed = $installed
            ReconciliationAttempted = $reconciliationAttempted
            ReconciliationSucceeded = $reconciliationSucceeded
            ReconciliationPresent = $reconciliationPresent
            RollbackRequired = $false
            RollbackAttempted = $false
            RollbackSucceeded = $null
            CommitState = $commitState
            CommitReceipt = $commitReceipt
            ReconciliationRequired = $false
            LocalKeyRemovedOnFailure = $false
            LocalKeyRemovalFailure = $null
            StreamEvents = @($allEvents)
            OutputBytes = $outputBytes
            EvidenceTruncated = $evidenceTruncated
            RemotePowerShellVersion = [string] $publicKeyContext.RemotePowerShellVersion
            RemotePSEdition = [string] $publicKeyContext.RemotePSEdition
            ExecutionMode = [string] $publicKeyContext.ExecutionMode
            HostKeyFingerprint = [string] $publicKeyContext.HostKeyFingerprint
            RemoteIdentity = $publicKeyContext.Identity
            ValidatedAtUtc = [string] $publicKeyContext.ValidatedAtUtc
            ExceptionType = $null
            SessionRemovalFailure = $false
            SessionRemovalFailures = @()
            Plan = $plan
        }
    }
    catch {
        $originalError = $_
        if ($rollbackRequired -and -not $commitStateUnknown -and $null -ne $passwordContext) {
            $remainingBytes = $MaxOutputBytes - $outputBytes
            if ($remainingBytes -le 0) {
                $rollbackFailure = New-HHSshClassifiedException `
                    -FailureKind OutputLimitExceeded `
                    -Message 'No output budget remains before exact authorized-key rollback.'
                $rollbackSucceeded = $null
            }
            else {
                $rollbackAttempted = $true
                try {
                    if ($null -ne $OperationArmer) {
                        & $OperationArmer @('BootstrapRollback')
                    }
                    $rollbackEvents = @(Invoke-HHSshRemoteCapture `
                            -Session $passwordContext.Session `
                            -ScriptBlock (Get-HHSshAuthorizedKeyRollbackScriptBlock) `
                            -ArgumentList @($keyMaterial.ExactLine) `
                            -Phase BootstrapRollback `
                            -MaxOutputBytes $remainingBytes `
                            -RemoteInvoker $RemoteInvoker `
                            -Clock $Clock)
                    $addedBytes = Add-HHSshBootstrapEvidence `
                        -Destination $allEvents `
                        -SourceEvents $rollbackEvents `
                        -RemainingBytes ($MaxOutputBytes - $outputBytes) `
                        -Clock $Clock
                    $outputBytes += $addedBytes
                    $rollbackOutput = Get-HHSshBootstrapOperationOutput `
                        -StreamEvents $rollbackEvents `
                        -Operation 'HostHunterAuthorizedKeyRollback.v1'
                    if ($null -eq $rollbackOutput.PSObject.Properties['PresentAfter'] -or
                        $rollbackOutput.PresentAfter -isnot [bool]) {
                        throw (New-HHSshClassifiedException -FailureKind TransportFailure `
                                -Message 'SSH key rollback returned invalid PresentAfter state.')
                    }
                    $rollbackSucceeded = -not [bool] $rollbackOutput.PresentAfter
                }
                catch {
                    $rollbackFailure = $_
                    $rollbackSucceeded = $null
                    $partialEvents = Get-HHSshBootstrapExceptionDataValue `
                        -ErrorObject $rollbackFailure `
                        -Name HHStreamEvents
                    if ($null -ne $partialEvents -and @($partialEvents).Count -gt 0) {
                        try {
                            $addedBytes = Add-HHSshBootstrapEvidence `
                                -Destination $allEvents `
                                -SourceEvents @($partialEvents) `
                                -RemainingBytes ($MaxOutputBytes - $outputBytes) `
                                -Clock $Clock
                            $outputBytes += $addedBytes
                        }
                        catch {
                            $evidenceTruncated = $true
                        }
                    }
                }
            }
        }

        $canRemoveGeneratedKey = $localGenerationOccurred -and
            (($installed -eq $false) -or ($rollbackSucceeded -eq $true))
        if ($canRemoveGeneratedKey) {
            try {
                Remove-HHSshGeneratedKey -KeyPath $plan.KeyPath -KeyRemover $KeyRemover
                $localKeyRemoved = $true
            }
            catch {
                $localKeyRemovalFailure = ConvertTo-HHSshBootstrapErrorProjection -ErrorObject $_
                $localKeyRemoved = $false
                $addedBytes = Add-HHSshBootstrapFiniteFailureEvent `
                    -Destination $allEvents `
                    -ErrorObject $_ `
                    -Phase LocalKeyCleanup `
                    -RemainingBytes ($MaxOutputBytes - $outputBytes) `
                    -Clock $Clock
                $outputBytes += $addedBytes
                if ($addedBytes -eq 0) {
                    $evidenceTruncated = $true
                }
            }
        }

        foreach ($failureEvidence in @(
                [pscustomobject]@{ Phase = 'BootstrapReconcile'; Error = $reconciliationFailure },
                [pscustomobject]@{ Phase = 'BootstrapRollback'; Error = $rollbackFailure },
                [pscustomobject]@{ Phase = 'Bootstrap'; Error = $originalError }
            )) {
            if ($null -ne $failureEvidence.Error) {
                $addedBytes = Add-HHSshBootstrapFiniteFailureEvent `
                    -Destination $allEvents `
                    -ErrorObject $failureEvidence.Error `
                    -Phase $failureEvidence.Phase `
                    -RemainingBytes ($MaxOutputBytes - $outputBytes) `
                    -Clock $Clock
                $outputBytes += $addedBytes
                if ($addedBytes -eq 0) {
                    $evidenceTruncated = $true
                }
            }
        }

        $originalFailureKind = Get-HHSshFailureKind -ErrorObject $originalError
        $isPublicKeyMismatch = $originalFailureKind -ceq 'RuntimeMismatch' -and
            $mismatchEvidencePhase -ceq 'PublicKeyIdentity'
        $isCompensatedPublicKeyMismatch = $isPublicKeyMismatch -and
            $null -ne $observedMismatchContext -and
            (([bool] $installed -and
                    $rollbackAttempted -and
                    $rollbackSucceeded -eq $true) -or
                ($installed -eq $false -and
                    -not $rollbackAttempted -and
                    $null -eq $rollbackSucceeded))
        if ($isPublicKeyMismatch -and -not $isCompensatedPublicKeyMismatch -and
            $rollbackRequired -and $rollbackSucceeded -ne $true) {
            $installed = $null
        }

        $hasStateUncertainty = $commitStateUnknown -or
            ($installAttempted -and $null -eq $installed) -or
            ($rollbackRequired -and $null -eq $rollbackSucceeded)
        if ($hasStateUncertainty) {
            $outcomeStatus = 'Unknown'
            if ($installAttempted -and $null -eq $installed) {
                $dispatchState = 'DispatchUncertain'
            }
        }
        elseif ($installAttempted -and $dispatchState -cne 'NotDispatched') {
            $dispatchState = 'Completed'
            $outcomeStatus = 'Failed'
        }
        else {
            $dispatchState = 'NotDispatched'
            $outcomeStatus = 'Failed'
        }
        $failureKind = if ($null -ne $rollbackFailure -or $commitStateUnknown) {
            'TransportFailure'
        }
        elseif ($originalFailureKind -ceq 'RuntimeMismatch' -and
            (($mismatchEvidencePhase -ceq 'PasswordIdentity' -and
                    $null -ne $observedMismatchContext) -or
                $isCompensatedPublicKeyMismatch)) {
            'RuntimeMismatch'
        }
        elseif ($originalFailureKind -ceq 'RuntimeMismatch') {
            'TransportFailure'
        }
        else {
            $originalFailureKind
        }
        $originalProjection = ConvertTo-HHSshBootstrapErrorProjection -ErrorObject $originalError
        $observedContext = if ($failureKind -ceq 'RuntimeMismatch' -and
            $null -ne $observedMismatchContext) {
            $observedMismatchContext
        }
        elseif ($null -ne $publicKeyContext) {
            $publicKeyContext
        }
        else {
            $passwordContext
        }
        $result = [pscustomobject][ordered]@{
            Succeeded = $false
            Planned = $false
            FailureKind = $failureKind
            DispatchState = $dispatchState
            OutcomeStatus = $outcomeStatus
            ProfileTransition = if ($commitStateUnknown) { $transition } else { $null }
            Installed = $installed
            ReconciliationAttempted = $reconciliationAttempted
            ReconciliationSucceeded = $reconciliationSucceeded
            ReconciliationPresent = $reconciliationPresent
            RollbackRequired = $rollbackRequired
            RollbackAttempted = $rollbackAttempted
            RollbackSucceeded = $rollbackSucceeded
            CommitState = $commitState
            CommitReceipt = $commitReceipt
            ReconciliationRequired = $hasStateUncertainty
            LocalKeyRemovedOnFailure = $localKeyRemoved
            LocalKeyRemovalFailure = $localKeyRemovalFailure
            StreamEvents = @($allEvents)
            OutputBytes = $outputBytes
            EvidenceTruncated = $evidenceTruncated
            RemotePowerShellVersion = if ($null -eq $observedContext) {
                $null
            }
            else {
                [string] $observedContext.RemotePowerShellVersion
            }
            RemotePSEdition = if ($null -eq $observedContext) {
                $null
            }
            else {
                [string] $observedContext.RemotePSEdition
            }
            ExecutionMode = if ($null -eq $observedContext) {
                $null
            }
            else {
                [string] $observedContext.ExecutionMode
            }
            HostKeyFingerprint = if ($null -eq $observedContext) {
                $null
            }
            else {
                [string] $observedContext.HostKeyFingerprint
            }
            RemoteIdentity = if ($null -eq $observedContext) {
                $null
            }
            else {
                $observedContext.Identity
            }
            ValidatedAtUtc = if ($null -eq $observedContext) {
                $null
            }
            else {
                [string] $observedContext.ValidatedAtUtc
            }
            ExceptionType = $originalProjection.ExceptionType
            SessionRemovalFailure = $false
            SessionRemovalFailures = @()
            Plan = $plan
        }
    }
    finally {
        foreach ($context in @($publicKeyContext, $passwordContext)) {
            if ($null -ne $context) {
                try {
                    Close-HHSshSession -Session $context.Session -SessionRemover $SessionRemover
                }
                catch {
                    $sessionRemovalFailure = $true
                    $sessionRemovalFailures.Add($_.Exception.GetType().FullName)
                    if ($null -ne $result) {
                        $addedBytes = Add-HHSshBootstrapFiniteFailureEvent `
                            -Destination $allEvents `
                            -ErrorObject $_ `
                            -Phase SessionCleanup `
                            -RemainingBytes ($MaxOutputBytes - $outputBytes) `
                            -Clock $Clock
                        $outputBytes += $addedBytes
                        if ($addedBytes -eq 0) {
                            $evidenceTruncated = $true
                        }
                    }
                }
            }
        }
        if ($null -ne $result) {
            $result.SessionRemovalFailure = $sessionRemovalFailure
            $result.SessionRemovalFailures = @($sessionRemovalFailures)
            $result.StreamEvents = @($allEvents)
            $result.OutputBytes = $outputBytes
            $result.EvidenceTruncated = $evidenceTruncated
            if ($sessionRemovalFailure -and $result.Succeeded) {
                $result.Succeeded = $false
                $result.FailureKind = 'TransportFailure'
                $result.DispatchState = 'Completed'
                $result.OutcomeStatus = 'Failed'
            }
        }
    }

    $result.PSObject.TypeNames.Insert(0, 'HostHunter.SshKeyBootstrapResult')
    return $result
}
