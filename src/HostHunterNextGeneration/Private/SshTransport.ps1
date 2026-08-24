Set-StrictMode -Version Latest

function New-HHSshClassifiedException {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'This creates an in-memory exception and does not mutate system state.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet(
            'TrustFailure',
            'AuthenticationFailure',
            'Timeout',
            'SubsystemFailure',
            'RuntimeMismatch',
            'RuntimeUnavailable',
            'TransportFailure',
            'RemoteCommandFailure',
            'OutputLimitExceeded'
        )]
        [string] $FailureKind,

        [Parameter(Mandatory)]
        [string] $Message,

        [AllowNull()]
        [Exception] $InnerException
    )

    $exception = [InvalidOperationException]::new($Message, $InnerException)
    $exception.Data['HHFailureKind'] = $FailureKind
    return $exception
}

function Get-HHSshFailureKind {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object] $ErrorObject
    )

    process {
        $exception = if ($ErrorObject -is [Management.Automation.ErrorRecord]) {
            $ErrorObject.Exception
        }
        elseif ($ErrorObject -is [Exception]) {
            $ErrorObject
        }
        else {
            $null
        }

        $messages = [Collections.Generic.List[string]]::new()
        while ($null -ne $exception) {
            if ($exception.Data.Contains('HHFailureKind')) {
                return [string] $exception.Data['HHFailureKind']
            }
            if ($exception -is [TimeoutException]) {
                return 'Timeout'
            }
            if (-not [string]::IsNullOrWhiteSpace($exception.Message)) {
                $messages.Add($exception.Message)
            }
            $exception = $exception.InnerException
        }

        if ($messages.Count -eq 0) {
            $messages.Add([string] $ErrorObject)
        }
        $message = $messages -join [Environment]::NewLine
        if ($message -match '(?i)host key verification failed|remote host identification has changed|known_hosts|fingerprint') {
            return 'TrustFailure'
        }
        if ($message -match '(?i)permission denied|authentication failed|unable to authenticate|publickey,password|access denied') {
            return 'AuthenticationFailure'
        }
        if ($message -match '(?i)timed?\s*out|timeout|operation has timed out') {
            return 'Timeout'
        }
        if ($message -match '(?i)subsystem request failed|powershell subsystem|identity probe|not a powershell 7 endpoint') {
            return 'SubsystemFailure'
        }
        if ($message -match '(?i)runtime mismatch|requested powershell runtime does not match') {
            return 'RuntimeMismatch'
        }
        if ($message -match '(?i)runtime unavailable|windows powershell compatibility.*unavailable') {
            return 'RuntimeUnavailable'
        }
        if ($message -match '(?i)output limit exceeded') {
            return 'OutputLimitExceeded'
        }
        return 'TransportFailure'
    }
}

function Get-HHSshRequestedPowerShellRuntime {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object] $InputObject
    )

    $runtimeProperty = $InputObject.PSObject.Properties['PowerShellRuntime']
    if ($null -eq $runtimeProperty -or
        [string]::IsNullOrWhiteSpace([string] $runtimeProperty.Value)) {
        throw [ArgumentException]::new(
            'The SSH transport requires an explicit PowerShellRuntime value.'
        )
    }
    $runtime = [string] $runtimeProperty.Value
    if ($runtime -cnotin @('PowerShell7', 'WindowsPowerShell51')) {
        throw [ArgumentException]::new("Unsupported PowerShell runtime '$runtime'.")
    }
    return $runtime
}

function Get-HHSshPublicKeyFingerprint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $PublicKeyLine
    )

    $parts = @($PublicKeyLine.Trim() -split '\s+')
    if ($parts.Count -lt 2 -or $parts[0] -notmatch '^(ssh-|ecdsa-|sk-)') {
        throw (New-HHSshClassifiedException -FailureKind TrustFailure `
                -Message 'The SSH public-key line is malformed.')
    }

    try {
        $keyBlob = [Convert]::FromBase64String($parts[1])
    }
    catch {
        throw (New-HHSshClassifiedException -FailureKind TrustFailure `
                -Message 'The SSH public-key blob is not valid base64.' `
                -InnerException $_.Exception)
    }
    $digest = [Security.Cryptography.SHA256]::HashData($keyBlob)
    return 'SHA256:{0}' -f [Convert]::ToBase64String($digest).TrimEnd('=')
}

function Get-HHSshKnownHostFingerprint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $KnownHostsPath,

        [Parameter(Mandatory)]
        [string] $HostName,

        [Parameter(Mandatory)]
        [ValidateRange(1, 65535)]
        [int] $Port,

        [bool] $IsWindowsPlatform = $IsWindows
    )

    if (-not [IO.Path]::IsPathFullyQualified($KnownHostsPath)) {
        throw (New-HHSshClassifiedException -FailureKind TrustFailure `
                -Message 'The managed known_hosts path must be absolute.')
    }
    $knownHostsItem = Get-Item -LiteralPath $KnownHostsPath -Force -ErrorAction SilentlyContinue
    if ($null -eq $knownHostsItem -or $knownHostsItem.PSIsContainer -or $null -ne $knownHostsItem.LinkType) {
        throw (New-HHSshClassifiedException -FailureKind TrustFailure `
                -Message 'The managed known_hosts file is missing, invalid, or a symbolic link.')
    }
    if (-not $IsWindowsPlatform) {
        $unsafeModes = [IO.UnixFileMode]::GroupWrite -bor [IO.UnixFileMode]::OtherWrite
        $actualMode = [IO.File]::GetUnixFileMode($knownHostsItem.FullName)
        if (($actualMode -band $unsafeModes) -ne 0) {
            throw (New-HHSshClassifiedException -FailureKind TrustFailure `
                    -Message 'The managed known_hosts file is writable by group or others.')
        }
    }

    $expectedHostToken = if ($Port -eq 22) {
        $HostName
    }
    else {
        '[{0}]:{1}' -f $HostName, $Port
    }
    $fingerprints = [Collections.Generic.List[string]]::new()
    foreach ($line in [IO.File]::ReadAllLines($knownHostsItem.FullName)) {
        $trimmed = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed.StartsWith('#')) {
            continue
        }
        $parts = @($trimmed -split '\s+')
        if ($parts.Count -lt 3) {
            continue
        }
        $hostMatches = @(
            @($parts[0] -split ',') | Where-Object {
                [string]::Equals($_, $expectedHostToken, [StringComparison]::OrdinalIgnoreCase)
            }
        )
        if ($hostMatches.Count -eq 0) {
            continue
        }
        $fingerprints.Add((Get-HHSshPublicKeyFingerprint -PublicKeyLine "$($parts[1]) $($parts[2])"))
    }
    return @($fingerprints | Sort-Object -Unique)
}

function New-HHSshTransportPlan {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'This is a pure connection-plan constructor and performs no network or filesystem mutation.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object] $Target,

        [Parameter(Mandatory)]
        [string] $KnownHostsPath,

        [ValidateRange(1, 300)]
        [int] $ConnectionTimeoutSeconds = 15,

        [bool] $IsWindowsPlatform = $IsWindows
    )

    $validatedTarget = ConvertTo-HHValidatedTargetRecord -InputObject $Target
    if ($validatedTarget.Transport -cne 'SSH') {
        throw [ArgumentException]::new('The SSH transport requires an SSH target record.')
    }
    if ($validatedTarget.Authentication -cnotin @('Password', 'PublicKey')) {
        throw [ArgumentException]::new(
            "SSH authentication must be Password or PublicKey, not '$($validatedTarget.Authentication)'."
        )
    }
    if ($validatedTarget.HostKeyFingerprint -notmatch '^SHA256:[A-Za-z0-9+/]+$') {
        throw (New-HHSshClassifiedException -FailureKind TrustFailure `
                -Message 'The SSH target does not contain a pinned SHA256 host-key fingerprint.')
    }

    $knownFingerprints = @(Get-HHSshKnownHostFingerprint `
            -KnownHostsPath $KnownHostsPath `
            -HostName $validatedTarget.HostName `
            -Port $validatedTarget.Port `
            -IsWindowsPlatform:$IsWindowsPlatform)
    if ($knownFingerprints -cnotcontains $validatedTarget.HostKeyFingerprint) {
        throw (New-HHSshClassifiedException -FailureKind TrustFailure `
                -Message 'The managed known_hosts entry does not match the pinned host-key fingerprint.')
    }

    $options = [ordered]@{
        ConnectTimeout = [string] $ConnectionTimeoutSeconds
        StrictHostKeyChecking = 'yes'
        UserKnownHostsFile = [IO.Path]::GetFullPath($KnownHostsPath)
    }
    if ($validatedTarget.Authentication -ceq 'Password') {
        $options.NumberOfPasswordPrompts = '1'
        $options.PasswordAuthentication = 'yes'
        $options.PreferredAuthentications = 'password'
        $options.PubkeyAuthentication = 'no'
    }
    else {
        $keyItem = Get-Item -LiteralPath $validatedTarget.KeyPath -Force -ErrorAction SilentlyContinue
        if ($null -eq $keyItem -or $keyItem.PSIsContainer -or $null -ne $keyItem.LinkType) {
            throw [IO.FileNotFoundException]::new('The selected SSH private key is missing or invalid.')
        }
        if (-not $IsWindowsPlatform) {
            $unsafeKeyModes = [IO.UnixFileMode]::GroupRead -bor
                [IO.UnixFileMode]::GroupWrite -bor
                [IO.UnixFileMode]::GroupExecute -bor
                [IO.UnixFileMode]::OtherRead -bor
                [IO.UnixFileMode]::OtherWrite -bor
                [IO.UnixFileMode]::OtherExecute
            $actualKeyMode = [IO.File]::GetUnixFileMode($keyItem.FullName)
            if (($actualKeyMode -band $unsafeKeyModes) -ne 0) {
                throw [UnauthorizedAccessException]::new(
                    'The selected SSH private key is accessible by group or others.'
                )
            }
        }
        $options.IdentitiesOnly = 'yes'
        $options.KbdInteractiveAuthentication = 'no'
        $options.PasswordAuthentication = 'no'
        $options.PreferredAuthentications = 'publickey'
        $options.PubkeyAuthentication = 'yes'
    }

    $plan = [pscustomobject][ordered]@{
        Target = $validatedTarget
        HostName = $validatedTarget.HostName
        Port = $validatedTarget.Port
        UserName = $validatedTarget.UserName
        Authentication = $validatedTarget.Authentication
        KeyFilePath = $validatedTarget.KeyPath
        KnownHostsPath = [IO.Path]::GetFullPath($KnownHostsPath)
        HostKeyFingerprint = $validatedTarget.HostKeyFingerprint
        ConnectingTimeoutMilliseconds = $ConnectionTimeoutSeconds * 1000
        Options = $options
    }
    $plan.PSObject.TypeNames.Insert(0, 'HostHunter.SshTransportPlan')
    return $plan
}

function New-HHSshStreamEvent {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'This creates an in-memory event and does not mutate system state.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateRange(0, [int]::MaxValue)]
        [int] $Sequence,

        [Parameter(Mandatory)]
        [string] $Phase,

        [Parameter(Mandatory)]
        [AllowNull()]
        [object] $InputObject,

        [ValidateSet('Output', 'Error', 'Warning', 'Verbose', 'Debug', 'Information', 'Progress')]
        [string] $StreamOverride,

        [string] $TypeNameOverride,

        [ValidateRange(0, [int]::MaxValue)]
        [Nullable[int]] $RemoteSequence,

        [bool] $IsTerminating = $false,

        [scriptblock] $Clock
    )

    $stream = if (-not [string]::IsNullOrWhiteSpace($StreamOverride)) {
        $StreamOverride
    }
    else {
        switch ($InputObject) {
            { $_ -is [Management.Automation.ErrorRecord] } { 'Error' }
            { $_ -is [Management.Automation.WarningRecord] } { 'Warning' }
            { $_ -is [Management.Automation.VerboseRecord] } { 'Verbose' }
            { $_ -is [Management.Automation.DebugRecord] } { 'Debug' }
            { $_ -is [Management.Automation.InformationRecord] } { 'Information' }
            { $_ -is [Management.Automation.ProgressRecord] } { 'Progress' }
            default { 'Output' }
        }
    }
    $observedAt = if ($null -eq $Clock) {
        [DateTimeOffset]::UtcNow
    }
    else {
        [DateTimeOffset] (& $Clock)
    }
    $typeName = if (-not [string]::IsNullOrWhiteSpace($TypeNameOverride)) {
        $TypeNameOverride
    }
    elseif ($null -eq $InputObject) {
        'null'
    }
    else {
        $InputObject.GetType().FullName
    }

    $serializedValue = [Management.Automation.PSSerializer]::Serialize($InputObject, 5)
    $serializedByteCount = [Text.Encoding]::UTF8.GetByteCount(
        "$Phase`n$stream`n$typeName`n$serializedValue`n"
    )
    $eventRecord = [pscustomobject][ordered]@{
        Sequence = $Sequence
        RemoteSequence = $RemoteSequence
        ObservedAtUtc = $observedAt.ToUniversalTime().ToString('o')
        Phase = $Phase
        Stream = $stream
        TypeName = $typeName
        SerializedByteCount = $serializedByteCount
        IsTerminating = $IsTerminating
        Value = $InputObject
    }
    $eventRecord.PSObject.TypeNames.Insert(0, 'HostHunter.SshStreamEvent')
    return $eventRecord
}

function Get-HHSshStreamEventByteCount {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $StreamEvents,

        [string] $ExcludePhase
    )

    [long] $totalBytes = 0
    foreach ($streamEvent in $StreamEvents) {
        if (-not [string]::IsNullOrWhiteSpace($ExcludePhase) -and
            $streamEvent.Phase -ceq $ExcludePhase) {
            continue
        }
        $totalBytes += [long] $streamEvent.SerializedByteCount
    }
    return $totalBytes
}

function Get-HHSshDirectEnvelopeScriptBlock {
    [CmdletBinding()]
    param()

    return {
        param(
            [Parameter(Mandatory)]
            [string] $CommandText,

            [Parameter(Mandatory)]
            [string] $SerializedCommandArguments
        )

        $remoteSequence = 0
        $terminated = $false
        $successOutputMarker = 'HostHunter.SuccessOutput.v1'
        try {
            $remoteCommand = [scriptblock]::Create($CommandText)
            $commandArguments = [Management.Automation.PSSerializer]::Deserialize(
                $SerializedCommandArguments
            )
            & {
                & $remoteCommand @CommandArguments |
                    ForEach-Object {
                        $successValue = $_
                        [pscustomobject][ordered]@{
                            Marker = $successOutputMarker
                            TypeName = if ($null -eq $successValue) {
                                'null'
                            }
                            else {
                                $successValue.GetType().FullName
                            }
                            Value = $successValue
                        }
                    }
            } *>&1 | ForEach-Object {
                $mergedValue = $_
                $isSuccessOutput = $null -ne $mergedValue -and
                    $null -ne $mergedValue.PSObject.Properties['Marker'] -and
                    $mergedValue.Marker -ceq $successOutputMarker
                if ($isSuccessOutput) {
                    $remoteValue = $mergedValue.Value
                    $remoteStream = 'Output'
                    $remoteTypeName = [string] $mergedValue.TypeName
                }
                else {
                    $remoteValue = $mergedValue
                    $remoteStream = switch ($remoteValue) {
                        { $_ -is [Management.Automation.ErrorRecord] } { 'Error' }
                        { $_ -is [Management.Automation.WarningRecord] } { 'Warning' }
                        { $_ -is [Management.Automation.VerboseRecord] } { 'Verbose' }
                        { $_ -is [Management.Automation.DebugRecord] } { 'Debug' }
                        { $_ -is [Management.Automation.InformationRecord] } { 'Information' }
                        default { 'Output' }
                    }
                    $remoteTypeName = if ($null -eq $remoteValue) {
                        'null'
                    }
                    else {
                        $remoteValue.GetType().FullName
                    }
                }
                [pscustomobject][ordered]@{
                    Marker = 'HostHunter.StreamEnvelope.v1'
                    Kind = 'Stream'
                    Sequence = $remoteSequence
                    Stream = $remoteStream
                    TypeName = $remoteTypeName
                    IsTerminating = $false
                    Value = $remoteValue
                }
                $remoteSequence++
            }
        }
        catch {
            $terminated = $true
            [pscustomobject][ordered]@{
                Marker = 'HostHunter.StreamEnvelope.v1'
                Kind = 'Stream'
                Sequence = $remoteSequence
                Stream = 'Error'
                TypeName = $_.GetType().FullName
                IsTerminating = $true
                Value = $_
            }
            $remoteSequence++
        }

        [pscustomobject][ordered]@{
            Marker = 'HostHunter.StreamEnvelope.v1'
            Kind = 'Completion'
            Sequence = $remoteSequence
            Terminated = $terminated
            FailureKind = if ($terminated) { 'RemoteCommandFailure' } else { $null }
            DispatchState = 'Completed'
            OutcomeStatus = if ($terminated) { 'Failed' } else { 'Succeeded' }
        }
    }
}

function Get-HHWindowsPowerShellCompatibilityEnvelopeScriptBlock {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseDeclaredVarsMoreThanAssignments',
        'dispatchState',
        Justification = 'The remote wrapper updates this value in a streaming closure and emits it afterward.'
    )]
    [CmdletBinding()]
    param()

    return {
        param(
            [Parameter(Mandatory)]
            [string] $CommandText,

            [Parameter(Mandatory)]
            [string] $SerializedCommandArguments,

            [bool] $IsWindowsTarget = $IsWindows,

            [scriptblock] $CompatibilitySessionFactory,

            [scriptblock] $CompatibilityInvoker,

            [scriptblock] $CompatibilitySessionRemover,

            [ValidateRange(1, 60000)]
            [int] $CompatibilityCleanupTimeoutMilliseconds = 5000
        )

        $compatibilitySession = $null
        $completionEnvelope = $null
        $failureKind = $null
        $failureMessage = $null
        $dispatchState = 'NotDispatched'
        $outcomeStatus = 'Failed'
        $nextSequence = 0
        $observedIdentity = $null

        if ($PSVersionTable.PSEdition -cne 'Core' -or $PSVersionTable.PSVersion.Major -lt 7) {
            $failureKind = 'RuntimeMismatch'
            $failureMessage = 'The outer SSH endpoint is not PowerShell 7 Core.'
        }
        elseif (-not $IsWindowsTarget) {
            $failureKind = 'RuntimeUnavailable'
            $failureMessage = 'Windows PowerShell compatibility is unavailable on this target platform.'
        }

        try {
            if ($null -eq $failureKind) {
            try {
                $compatibilitySession = if ($null -ne $CompatibilitySessionFactory) {
                    & $CompatibilitySessionFactory *>&1
                }
                else {
                    New-PSSession `
                        -UseWindowsPowerShell `
                        -ErrorAction Stop `
                        3>$null `
                        4>$null `
                        5>$null `
                        6>$null
                }
                if ($null -eq $compatibilitySession) {
                    throw 'The compatibility session factory returned no session.'
                }
                $identityProbe = {
                    [pscustomobject][ordered]@{
                        Marker = 'HostHunter.PowerShellIdentity.v1'
                        PSEdition = $PSVersionTable.PSEdition
                        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
                        # Process.MainModule and Get-Process.Path can serialize as empty
                        # through the nested SSH -> PS7 -> Windows PowerShell remoting path.
                        # Argument zero is the actual host executable and survives that
                        # compatibility boundary on Windows PowerShell 5.1.
                        ProcessPath = [string] [Environment]::GetCommandLineArgs()[0]
                        UserName = [Environment]::UserName
                        MachineName = [Environment]::MachineName
                    }
                }
                $identityCandidates = @(
                    if ($null -ne $CompatibilityInvoker) {
                        & $CompatibilityInvoker `
                            $compatibilitySession `
                            $identityProbe `
                            @() `
                            'Identity' `
                            *>&1
                    }
                    else {
                        Invoke-Command `
                            -Session $compatibilitySession `
                            -ScriptBlock $identityProbe `
                            -ErrorAction Stop `
                            *>&1
                    }
                )
                $identityCandidates = @(
                    $identityCandidates |
                        Where-Object {
                            $null -ne $_ -and
                            $null -ne $_.PSObject.Properties['Marker'] -and
                            $_.Marker -ceq 'HostHunter.PowerShellIdentity.v1'
                        }
                )
                $identityVersion = $null
                $identityProcessLeaf = if ($identityCandidates.Count -eq 1) {
                    @([string] $identityCandidates[0].ProcessPath -split '[\\/]')[-1]
                }
                else {
                    $null
                }
                $identityProcessName = if ([string]::IsNullOrWhiteSpace($identityProcessLeaf)) {
                    $null
                }
                else {
                    [IO.Path]::GetFileNameWithoutExtension($identityProcessLeaf)
                }
                $identityVersionIsValid = $identityCandidates.Count -eq 1 -and
                    [version]::TryParse(
                        [string] $identityCandidates[0].PowerShellVersion,
                        [ref] $identityVersion
                    )
                $identityIsComplete = $identityCandidates.Count -eq 1 -and
                    $identityVersionIsValid -and
                    -not [string]::IsNullOrWhiteSpace([string] $identityCandidates[0].PSEdition) -and
                    -not [string]::IsNullOrWhiteSpace($identityProcessName) -and
                    -not [string]::IsNullOrWhiteSpace([string] $identityCandidates[0].UserName) -and
                    -not [string]::IsNullOrWhiteSpace([string] $identityCandidates[0].MachineName)
                $identityIsSelfConsistent = $identityIsComplete -and (
                    ($identityCandidates[0].PSEdition -ceq 'Core' -and
                        $identityProcessName -ceq 'pwsh') -or
                    ($identityCandidates[0].PSEdition -ceq 'Desktop' -and
                        $identityProcessName -ceq 'powershell')
                )
                if (-not $identityIsSelfConsistent) {
                    $failureKind = 'TransportFailure'
                    $failureMessage = 'The compatibility identity response was malformed or internally inconsistent.'
                }
                elseif ($identityCandidates[0].PSEdition -cne 'Desktop' -or
                    $identityVersion.Major -ne 5 -or
                    $identityVersion.Minor -ne 1) {
                    $observedIdentity = $identityCandidates[0]
                    $failureKind = 'RuntimeMismatch'
                    $failureMessage = 'The compatibility session did not report Windows PowerShell 5.1 Desktop.'
                }
            }
            catch {
                $failureKind = 'RuntimeUnavailable'
                $failureMessage = 'Windows PowerShell compatibility could not be opened.'
                }
            }

            if ($null -eq $failureKind) {
                try {
                    $innerEnvelope = {
                        param(
                            [Parameter(Mandatory)]
                            [string] $InnerCommandText,

                            [Parameter(Mandatory)]
                            [string] $InnerSerializedCommandArguments
                        )

                        $innerSequence = 0
                        $innerTerminated = $false
                        $successOutputMarker = 'HostHunter.SuccessOutput.v1'
                        try {
                            $innerCommand = [scriptblock]::Create($InnerCommandText)
                            $innerArguments = [Management.Automation.PSSerializer]::Deserialize(
                                $InnerSerializedCommandArguments
                            )
                            & {
                                & $innerCommand @innerArguments |
                                    ForEach-Object {
                                        $successValue = $_
                                        [pscustomobject][ordered]@{
                                            Marker = $successOutputMarker
                                            TypeName = if ($null -eq $successValue) {
                                                'null'
                                            }
                                            else {
                                                $successValue.GetType().FullName
                                            }
                                            Value = $successValue
                                        }
                                    }
                            } *>&1 | ForEach-Object {
                                $mergedValue = $_
                                $isSuccessOutput = $null -ne $mergedValue -and
                                    $null -ne $mergedValue.PSObject.Properties['Marker'] -and
                                    $mergedValue.Marker -ceq $successOutputMarker
                                if ($isSuccessOutput) {
                                    $innerValue = $mergedValue.Value
                                    $innerStream = 'Output'
                                    $innerTypeName = [string] $mergedValue.TypeName
                                }
                                else {
                                    $innerValue = $mergedValue
                                    $innerStream = switch ($innerValue) {
                                        { $_ -is [Management.Automation.ErrorRecord] } { 'Error' }
                                        { $_ -is [Management.Automation.WarningRecord] } { 'Warning' }
                                        { $_ -is [Management.Automation.VerboseRecord] } { 'Verbose' }
                                        { $_ -is [Management.Automation.DebugRecord] } { 'Debug' }
                                        { $_ -is [Management.Automation.InformationRecord] } { 'Information' }
                                        default { 'Output' }
                                    }
                                    $innerTypeName = if ($null -eq $innerValue) {
                                        'null'
                                    }
                                    else {
                                        $innerValue.GetType().FullName
                                    }
                                }
                                [pscustomobject][ordered]@{
                                    Marker = 'HostHunter.StreamEnvelope.v1'
                                    Kind = 'Stream'
                                    Sequence = $innerSequence
                                    Stream = $innerStream
                                    TypeName = $innerTypeName
                                    IsTerminating = $false
                                    Value = $innerValue
                                }
                                $innerSequence++
                            }
                        }
                        catch {
                            $innerTerminated = $true
                            [pscustomobject][ordered]@{
                                Marker = 'HostHunter.StreamEnvelope.v1'
                                Kind = 'Stream'
                                Sequence = $innerSequence
                                Stream = 'Error'
                                TypeName = $_.GetType().FullName
                                IsTerminating = $true
                                Value = $_
                            }
                            $innerSequence++
                        }
                        [pscustomobject][ordered]@{
                            Marker = 'HostHunter.StreamEnvelope.v1'
                            Kind = 'Completion'
                            Sequence = $innerSequence
                            Terminated = $innerTerminated
                            FailureKind = if ($innerTerminated) { 'RemoteCommandFailure' } else { $null }
                            DispatchState = 'Completed'
                            OutcomeStatus = if ($innerTerminated) { 'Failed' } else { 'Succeeded' }
                        }
                    }

                    $dispatchState = 'DispatchUncertain'
                    $processInnerResult = {
                        $innerResult = $_
                        if ($null -eq $innerResult -or
                            $null -eq $innerResult.PSObject.Properties['Marker'] -or
                            $innerResult.Marker -cne 'HostHunter.StreamEnvelope.v1' -or
                            $null -eq $innerResult.PSObject.Properties['Kind'] -or
                            $innerResult.Kind -cnotin @('Stream', 'Completion') -or
                            $null -eq $innerResult.PSObject.Properties['Sequence'] -or
                            [int] $innerResult.Sequence -ne $nextSequence) {
                            throw 'The Windows PowerShell compatibility stream returned an invalid envelope.'
                        }
                        if ($innerResult.Kind -ceq 'Completion') {
                            if ($null -ne $completionEnvelope) {
                                throw 'The Windows PowerShell compatibility stream returned duplicate completion.'
                            }
                            foreach ($propertyName in @(
                                    'Terminated',
                                    'FailureKind',
                                    'DispatchState',
                                    'OutcomeStatus'
                                )) {
                                if ($null -eq $innerResult.PSObject.Properties[$propertyName]) {
                                    throw 'The Windows PowerShell compatibility completion is incomplete.'
                                }
                            }
                            $innerTerminated = $innerResult.Terminated -is [bool] -and
                                [bool] $innerResult.Terminated
                            $innerSucceeded = $innerResult.Terminated -is [bool] -and
                                -not [bool] $innerResult.Terminated -and
                                [string]::IsNullOrWhiteSpace([string] $innerResult.FailureKind) -and
                                $innerResult.DispatchState -ceq 'Completed' -and
                                $innerResult.OutcomeStatus -ceq 'Succeeded'
                            $innerFailed = $innerTerminated -and
                                $innerResult.FailureKind -ceq 'RemoteCommandFailure' -and
                                $innerResult.DispatchState -ceq 'Completed' -and
                                $innerResult.OutcomeStatus -ceq 'Failed'
                            if (-not $innerSucceeded -and -not $innerFailed) {
                                throw 'The Windows PowerShell compatibility completion is inconsistent.'
                            }
                            $completionEnvelope = $innerResult
                        }
                        else {
                            if ($null -ne $completionEnvelope) {
                                throw 'The Windows PowerShell compatibility stream returned data after completion.'
                            }
                            foreach ($propertyName in @('Stream', 'TypeName', 'IsTerminating', 'Value')) {
                                if ($null -eq $innerResult.PSObject.Properties[$propertyName]) {
                                    throw 'The Windows PowerShell compatibility stream envelope is incomplete.'
                                }
                            }
                            if ($innerResult.Stream -cnotin @(
                                    'Output', 'Error', 'Warning', 'Verbose', 'Debug', 'Information'
                                ) -or $innerResult.IsTerminating -isnot [bool]) {
                                throw 'The Windows PowerShell compatibility stream envelope is invalid.'
                            }
                            $dispatchState = 'Dispatched'
                            $innerResult
                            $nextSequence++
                        }
                    }
                    if ($null -ne $CompatibilityInvoker) {
                        & $CompatibilityInvoker `
                            $compatibilitySession `
                            $innerEnvelope `
                            @($CommandText, $SerializedCommandArguments) `
                            'Command' `
                            *>&1 | ForEach-Object -Process $processInnerResult
                    }
                    else {
                        Invoke-Command `
                            -Session $compatibilitySession `
                            -ScriptBlock $innerEnvelope `
                            -ArgumentList @($CommandText, $SerializedCommandArguments) `
                            -ErrorAction Stop `
                            *>&1 | ForEach-Object -Process $processInnerResult
                    }
                    if ($null -eq $completionEnvelope) {
                        throw 'The Windows PowerShell compatibility stream did not return completion.'
                    }
                    $dispatchState = [string] $completionEnvelope.DispatchState
                    $outcomeStatus = [string] $completionEnvelope.OutcomeStatus
                }
                catch {
                    $failureKind = 'TransportFailure'
                    $failureMessage = 'Windows PowerShell compatibility execution did not complete conclusively.'
                    $outcomeStatus = 'Unknown'
                }
            }
        }
        finally {
            if ($null -ne $compatibilitySession) {
                try {
                    if ($null -ne $CompatibilitySessionRemover) {
                        $cleanupResults = @(& $CompatibilitySessionRemover `
                                $compatibilitySession `
                                $CompatibilityCleanupTimeoutMilliseconds `
                                *>&1)
                        if (@($cleanupResults | Where-Object { $_ -is [bool] -and -not $_ }).Count -gt 0) {
                            throw [TimeoutException]::new(
                                'The compatibility session cleanup exceeded its deadline.'
                            )
                        }
                    }
                    else {
                        $compatibilityRunspace = $compatibilitySession.Runspace
                        if ($null -eq $compatibilityRunspace) {
                            throw 'The compatibility session has no runspace to close.'
                        }
                        $compatibilityRunspace.CloseAsync()
                        $cleanupStopwatch = [Diagnostics.Stopwatch]::StartNew()
                        while ($compatibilityRunspace.RunspaceStateInfo.State -cnotin @(
                                'Closed', 'Broken'
                            )) {
                            if ($cleanupStopwatch.ElapsedMilliseconds -ge
                                $CompatibilityCleanupTimeoutMilliseconds) {
                                throw [TimeoutException]::new(
                                    'The compatibility session cleanup exceeded its deadline.'
                                )
                            }
                            Start-Sleep -Milliseconds 25
                        }
                        Remove-PSSession -Session $compatibilitySession `
                            -Confirm:$false -ErrorAction Stop *>&1 |
                            Out-Null
                    }
                }
                catch {
                    $failureKind = 'TransportFailure'
                    $failureMessage = 'Windows PowerShell compatibility session cleanup failed.'
                    $outcomeStatus = if ($dispatchState -cin @('NotDispatched', 'Completed')) {
                        'Failed'
                    }
                    else {
                        'Unknown'
                    }
                }
            }
        }

        if ($null -ne $failureKind) {
            [pscustomobject][ordered]@{
                Marker = 'HostHunter.StreamEnvelope.v1'
                Kind = 'Stream'
                Sequence = $nextSequence
                Stream = 'Error'
                TypeName = 'HostHunter.RuntimeFailure'
                IsTerminating = $true
                Value = [pscustomobject][ordered]@{
                    Message = $failureMessage
                    FailureKind = $failureKind
                    ObservedIdentity = $observedIdentity
                }
                DispatchState = $dispatchState
            }
            $nextSequence++
            [pscustomobject][ordered]@{
                Marker = 'HostHunter.StreamEnvelope.v1'
                Kind = 'Completion'
                Sequence = $nextSequence
                Terminated = $true
                FailureKind = $failureKind
                DispatchState = $dispatchState
                OutcomeStatus = $outcomeStatus
            }
            return
        }

        [pscustomobject][ordered]@{
            Marker = 'HostHunter.StreamEnvelope.v1'
            Kind = 'Completion'
            Sequence = $nextSequence
            Terminated = [bool] $completionEnvelope.Terminated
            FailureKind = if ([bool] $completionEnvelope.Terminated) {
                'RemoteCommandFailure'
            }
            else {
                $null
            }
            DispatchState = 'Completed'
            OutcomeStatus = $outcomeStatus
        }
    }
}

function Get-HHSshRemoteEnvelopeScriptBlock {
    [CmdletBinding()]
    param(
        [ValidateSet('PowerShell7', 'WindowsPowerShell51')]
        [string] $PowerShellRuntime = 'PowerShell7'
    )

    if ($PowerShellRuntime -ceq 'WindowsPowerShell51') {
        return Get-HHWindowsPowerShellCompatibilityEnvelopeScriptBlock
    }
    return Get-HHSshDirectEnvelopeScriptBlock
}

function Test-HHSshStreamEnvelope {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object] $InputObject
    )

    return $null -ne $InputObject -and
        $null -ne $InputObject.PSObject.Properties['Marker'] -and
        $InputObject.Marker -ceq 'HostHunter.StreamEnvelope.v1' -and
        $null -ne $InputObject.PSObject.Properties['Kind'] -and
        $InputObject.Kind -cin @('Stream', 'Completion')
}

function Test-HHSshCompletionEnvelope {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object] $InputObject
    )

    if (-not (Test-HHSshStreamEnvelope -InputObject $InputObject) -or
        $InputObject.Kind -cne 'Completion') {
        return $false
    }
    foreach ($propertyName in @(
            'Sequence',
            'Terminated',
            'FailureKind',
            'DispatchState',
            'OutcomeStatus'
        )) {
        if ($null -eq $InputObject.PSObject.Properties[$propertyName]) {
            return $false
        }
    }
    if ($InputObject.Terminated -isnot [bool]) {
        return $false
    }

    $terminated = [bool] $InputObject.Terminated
    $failureKind = [string] $InputObject.FailureKind
    $dispatchState = [string] $InputObject.DispatchState
    $outcomeStatus = [string] $InputObject.OutcomeStatus
    if (-not $terminated) {
        return [string]::IsNullOrWhiteSpace($failureKind) -and
            $dispatchState -ceq 'Completed' -and
            $outcomeStatus -ceq 'Succeeded'
    }
    if ($failureKind -cnotin @(
            'RuntimeMismatch',
            'RuntimeUnavailable',
            'TransportFailure',
            'RemoteCommandFailure',
            'OutputLimitExceeded'
        )) {
        return $false
    }

    switch ($failureKind) {
        { $_ -cin @('RuntimeMismatch', 'RuntimeUnavailable') } {
            return $dispatchState -ceq 'NotDispatched' -and $outcomeStatus -ceq 'Failed'
        }
        'RemoteCommandFailure' {
            return $dispatchState -ceq 'Completed' -and $outcomeStatus -ceq 'Failed'
        }
        'OutputLimitExceeded' {
            return $dispatchState -ceq 'Dispatched' -and $outcomeStatus -ceq 'Failed'
        }
        'TransportFailure' {
            if ($dispatchState -cin @('Dispatched', 'DispatchUncertain')) {
                return $outcomeStatus -ceq 'Unknown'
            }
            return $dispatchState -cin @('NotDispatched', 'Completed') -and
                $outcomeStatus -ceq 'Failed'
        }
        default {
            return $false
        }
    }
}

function Invoke-HHSshRemoteCapture {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseDeclaredVarsMoreThanAssignments',
        'remoteTerminated',
        Justification = 'The variable is assigned by the streaming process closure and read after the pipeline ends.'
    )]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseDeclaredVarsMoreThanAssignments',
        'remoteFailureKind',
        Justification = 'The variable is assigned by the streaming process closure and read after the pipeline ends.'
    )]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseDeclaredVarsMoreThanAssignments',
        'remoteDispatchState',
        Justification = 'The variable is assigned by the streaming process closure and read after the pipeline ends.'
    )]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseDeclaredVarsMoreThanAssignments',
        'remoteOutcomeStatus',
        Justification = 'The variable is assigned by the streaming process closure and read after the pipeline ends.'
    )]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter',
        'MaxOutputBytes',
        Justification = 'The parameter is captured by the streaming process closure.'
    )]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter',
        'Clock',
        Justification = 'The parameter is captured by the streaming process closure.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object] $Session,

        [Parameter(Mandatory)]
        [scriptblock] $ScriptBlock,

        [AllowEmptyCollection()]
        [object[]] $ArgumentList = @(),

        [Parameter(Mandatory)]
        [string] $Phase,

        [ValidateRange(0, [int]::MaxValue)]
        [int] $SequenceStart = 0,

        [ValidateRange(1, [long]::MaxValue)]
        [long] $MaxOutputBytes = 104857600,

        [ValidateSet('PowerShell7', 'WindowsPowerShell51')]
        [string] $PowerShellRuntime = 'PowerShell7',

        [scriptblock] $RemoteInvoker,

        [scriptblock] $BridgeInvoker,

        [scriptblock] $Clock
    )

    $sequence = $SequenceStart
    [long] $serializedBytes = 0
    $capturedEvents = [Collections.Generic.List[object]]::new()
    $usesEnvelope = $PowerShellRuntime -ceq 'WindowsPowerShell51' -or $null -eq $RemoteInvoker
    $completionCount = 0
    $remoteTerminated = $false
    $remoteFailureKind = $null
    $remoteDispatchState = $null
    $remoteOutcomeStatus = $null
    $nextRemoteSequence = 0
    $lastObservedDispatchState = $null
    $captureItem = {
        $capturedItem = $_
        if ($usesEnvelope) {
            if (-not (Test-HHSshStreamEnvelope -InputObject $capturedItem)) {
                throw (New-HHSshClassifiedException -FailureKind TransportFailure `
                        -Message 'The SSH stream wrapper returned an invalid envelope.')
            }
            if ($completionCount -gt 0) {
                throw (New-HHSshClassifiedException -FailureKind TransportFailure `
                        -Message 'The SSH stream wrapper returned data after completion.')
            }
            if ($capturedItem.Kind -ceq 'Completion') {
                if (-not (Test-HHSshCompletionEnvelope -InputObject $capturedItem)) {
                    throw (New-HHSshClassifiedException -FailureKind TransportFailure `
                            -Message 'The SSH stream wrapper returned invalid completion metadata.')
                }
                if ([int] $capturedItem.Sequence -ne $nextRemoteSequence) {
                    throw (New-HHSshClassifiedException -FailureKind TransportFailure `
                            -Message 'The SSH stream wrapper returned an out-of-order completion envelope.')
                }
                $completionCount++
                $remoteTerminated = [bool] $capturedItem.Terminated
                $remoteFailureKind = [string] $capturedItem.FailureKind
                $remoteDispatchState = [string] $capturedItem.DispatchState
                $remoteOutcomeStatus = [string] $capturedItem.OutcomeStatus
                return
            }
            if ([int] $capturedItem.Sequence -ne $nextRemoteSequence) {
                throw (New-HHSshClassifiedException -FailureKind TransportFailure `
                        -Message 'The SSH stream wrapper returned an out-of-order stream envelope.')
            }
            if ($capturedItem.Stream -cnotin @('Output', 'Error', 'Warning', 'Verbose', 'Debug', 'Information')) {
                throw (New-HHSshClassifiedException -FailureKind TransportFailure `
                        -Message 'The SSH stream wrapper returned an invalid stream kind.')
            }
            if ($Phase -ceq 'Command') {
                $streamDispatchProperty = $capturedItem.PSObject.Properties['DispatchState']
                $lastObservedDispatchState = if ($null -eq $streamDispatchProperty -or
                    [string]::IsNullOrWhiteSpace([string] $streamDispatchProperty.Value)) {
                    'Dispatched'
                }
                else {
                    [string] $streamDispatchProperty.Value
                }
                if ($lastObservedDispatchState -cnotin @(
                        'NotDispatched', 'Dispatched', 'DispatchUncertain'
                    )) {
                    throw (New-HHSshClassifiedException -FailureKind TransportFailure `
                            -Message 'The SSH stream wrapper returned invalid stream dispatch metadata.')
                }
            }
            $eventRecord = New-HHSshStreamEvent `
                -Sequence $sequence `
                -Phase $Phase `
                -InputObject $capturedItem.Value `
                -StreamOverride $capturedItem.Stream `
                -TypeNameOverride $capturedItem.TypeName `
                -RemoteSequence ([int] $capturedItem.Sequence) `
                -IsTerminating ([bool] $capturedItem.IsTerminating) `
                -Clock $Clock
        }
        else {
            if ($Phase -ceq 'Command') {
                $lastObservedDispatchState = 'Dispatched'
            }
            $eventRecord = New-HHSshStreamEvent `
                -Sequence $sequence `
                -Phase $Phase `
                -InputObject $capturedItem `
                -Clock $Clock
        }
        if ($serializedBytes + $eventRecord.SerializedByteCount -gt $MaxOutputBytes) {
            $limitException = New-HHSshClassifiedException `
                -FailureKind OutputLimitExceeded `
                -Message "The serialized plaintext output limit of $MaxOutputBytes bytes was exceeded."
            $limitException.Data['HHStreamEvents'] = [object[]] $capturedEvents
            $limitException.Data['HHOutputBytes'] = $serializedBytes
            if ($Phase -ceq 'Command') {
                $limitException.Data['HHDispatchState'] = if (
                    [string]::IsNullOrWhiteSpace($lastObservedDispatchState)
                ) {
                    'Dispatched'
                }
                else {
                    $lastObservedDispatchState
                }
                $limitException.Data['HHOutcomeStatus'] = 'Failed'
            }
            throw $limitException
        }
        $capturedEvents.Add($eventRecord)
        $serializedBytes += $eventRecord.SerializedByteCount
        $sequence++
        if ($usesEnvelope) {
            $nextRemoteSequence++
        }
    }

    try {
        if ($PowerShellRuntime -ceq 'WindowsPowerShell51' -and $null -ne $BridgeInvoker) {
            $bridgeWrapper = Get-HHSshRemoteEnvelopeScriptBlock -PowerShellRuntime $PowerShellRuntime
            $bridgeArguments = @(
                $ScriptBlock.ToString()
                [Management.Automation.PSSerializer]::Serialize([object[]] $ArgumentList, 20)
            )
            & $BridgeInvoker $Session $bridgeWrapper $bridgeArguments |
                ForEach-Object -Process $captureItem
        }
        elseif ($PowerShellRuntime -ceq 'PowerShell7' -and $null -ne $RemoteInvoker) {
            & $RemoteInvoker $Session $ScriptBlock $ArgumentList | ForEach-Object -Process $captureItem
        }
        else {
            $invokeParameters = @{
                Session = $Session
                ScriptBlock = Get-HHSshRemoteEnvelopeScriptBlock -PowerShellRuntime $PowerShellRuntime
                ArgumentList = @(
                    $ScriptBlock.ToString()
                    [Management.Automation.PSSerializer]::Serialize([object[]] $ArgumentList, 20)
                )
                ErrorAction = 'Stop'
            }
            Invoke-Command @invokeParameters | ForEach-Object -Process $captureItem
        }
        if ($usesEnvelope) {
            if ($completionCount -ne 1) {
                throw (New-HHSshClassifiedException -FailureKind TransportFailure `
                        -Message 'The SSH stream wrapper did not return exactly one completion envelope.')
            }
            if (-not [string]::IsNullOrWhiteSpace($remoteFailureKind)) {
                $runtimeException = New-HHSshClassifiedException `
                    -FailureKind $remoteFailureKind `
                    -Message "The requested remote PowerShell runtime failed ($remoteFailureKind)."
                $runtimeException.Data['HHDispatchState'] = $remoteDispatchState
                $runtimeException.Data['HHOutcomeStatus'] = $remoteOutcomeStatus
                throw $runtimeException
            }
            if ($remoteTerminated) {
                $remoteException = New-HHSshClassifiedException -FailureKind RemoteCommandFailure `
                    -Message 'The remote PowerShell command terminated with an error.'
                $remoteException.Data['HHDispatchState'] = $remoteDispatchState
                $remoteException.Data['HHOutcomeStatus'] = 'Failed'
                throw $remoteException
            }
        }
    }
    catch {
        if (-not $_.Exception.Data.Contains('HHStreamEvents')) {
            $_.Exception.Data['HHStreamEvents'] = [object[]] $capturedEvents
            $_.Exception.Data['HHOutputBytes'] = $serializedBytes
        }
        if (-not $_.Exception.Data.Contains('HHDispatchState')) {
            $_.Exception.Data['HHDispatchState'] = if ($Phase -ceq 'Command') {
                if (-not [string]::IsNullOrWhiteSpace($lastObservedDispatchState)) {
                    $lastObservedDispatchState
                }
                else {
                    'DispatchUncertain'
                }
            }
            else {
                'NotDispatched'
            }
        }
        if (-not $_.Exception.Data.Contains('HHOutcomeStatus')) {
            $capturedFailureKind = Get-HHSshFailureKind -ErrorObject $_
            $_.Exception.Data['HHOutcomeStatus'] = if ($capturedFailureKind -ceq 'OutputLimitExceeded') {
                'Failed'
            }
            elseif ([string] $_.Exception.Data['HHDispatchState'] -cin @(
                    'Dispatched', 'DispatchUncertain'
                )) {
                'Unknown'
            }
            else {
                'Failed'
            }
        }
        throw
    }
    return @($capturedEvents)
}

function Get-HHSshIdentityProbeScriptBlock {
    [CmdletBinding()]
    param()

    return {
        [pscustomobject][ordered]@{
            Marker = 'HostHunter.PowerShellIdentity.v1'
            PSEdition = $PSVersionTable.PSEdition
            PowerShellVersion = $PSVersionTable.PSVersion.ToString()
            ProcessPath = if ($PSVersionTable.PSEdition -ceq 'Desktop') {
                # Environment.ProcessPath does not exist on .NET Framework and
                # therefore becomes empty inside Windows PowerShell 5.1.
                [string] [Environment]::GetCommandLineArgs()[0]
            }
            else {
                [string] [Environment]::ProcessPath
            }
            UserName = [Environment]::UserName
            MachineName = [Environment]::MachineName
        }
    }
}

function Get-HHSshValidatedIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $StreamEvents,

        [ValidateSet('PowerShell7', 'WindowsPowerShell51')]
        [string] $PowerShellRuntime = 'PowerShell7'
    )

    $candidates = @(
        $StreamEvents |
            Where-Object {
                $_.Stream -ceq 'Output' -and
                $null -ne $_.Value -and
                $null -ne $_.Value.PSObject.Properties['Marker'] -and
                $_.Value.Marker -ceq 'HostHunter.PowerShellIdentity.v1'
            } |
            Select-Object -ExpandProperty Value
    )
    if ($candidates.Count -ne 1) {
        throw (New-HHSshClassifiedException -FailureKind SubsystemFailure `
                -Message 'The mandatory remote PowerShell identity probe returned an invalid marker count.')
    }

    $identity = $candidates[0]
    $version = $null
    $processLeaf = @([string] $identity.ProcessPath -split '[\\/]')[-1]
    $processName = [IO.Path]::GetFileNameWithoutExtension($processLeaf)
    $isVersionValid = [version]::TryParse(
        [string] $identity.PowerShellVersion,
        [ref] $version
    )
    $isCommonIdentityValid = $isVersionValid -and
        $identity.PSEdition -cin @('Core', 'Desktop') -and
        -not [string]::IsNullOrWhiteSpace([string] $identity.UserName) -and
        -not [string]::IsNullOrWhiteSpace([string] $identity.MachineName) -and
        (($identity.PSEdition -ceq 'Core' -and $processName -ceq 'pwsh') -or
            ($identity.PSEdition -ceq 'Desktop' -and $processName -ceq 'powershell'))
    $isRequestedRuntime = if ($PowerShellRuntime -ceq 'WindowsPowerShell51') {
        $identity.PSEdition -ceq 'Desktop' -and
            $null -ne $version -and
            $version.Major -eq 5 -and
            $version.Minor -eq 1 -and
            $processName -ceq 'powershell'
    }
    else {
        $identity.PSEdition -ceq 'Core' -and
            $null -ne $version -and
            $version.Major -ge 7 -and
            $processName -ceq 'pwsh'
    }
    if (-not $isCommonIdentityValid) {
        throw (New-HHSshClassifiedException -FailureKind SubsystemFailure `
                -Message 'The mandatory remote PowerShell identity response was malformed or internally inconsistent.')
    }
    if (-not $isRequestedRuntime) {
        $mismatchMessage = if ($PowerShellRuntime -ceq 'PowerShell7') {
            'The requested PowerShell runtime does not match; the endpoint is not a PowerShell 7 endpoint.'
        }
        else {
            'The requested PowerShell runtime does not match Windows PowerShell 5.1 Desktop.'
        }
        $mismatchException = New-HHSshClassifiedException `
            -FailureKind RuntimeMismatch `
            -Message $mismatchMessage
        $mismatchException.Data['HHObservedIdentity'] = $identity
        $mismatchException.Data['HHObservedProbeRuntime'] = $PowerShellRuntime
        throw $mismatchException
    }
    return $identity
}

function Get-HHSshCommandRuntimeMismatchEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $StreamEvents,

        [Parameter(Mandatory)]
        [ValidateSet('PowerShell7', 'WindowsPowerShell51')]
        [string] $PowerShellRuntime
    )

    # A command-time runtime mismatch can currently be attributed only by the
    # Windows PowerShell compatibility wrapper. Treat similarly shaped command
    # output as untrusted data, not runtime evidence.
    if ($PowerShellRuntime -cne 'WindowsPowerShell51') {
        return $null
    }

    $candidateEvents = @(
        $StreamEvents |
            Where-Object {
                $phaseProperty = $_.PSObject.Properties['Phase']
                $streamProperty = $_.PSObject.Properties['Stream']
                $typeNameProperty = $_.PSObject.Properties['TypeName']
                $terminatingProperty = $_.PSObject.Properties['IsTerminating']
                $valueProperty = $_.PSObject.Properties['Value']
                if ($null -eq $phaseProperty -or $phaseProperty.Value -cne 'Command' -or
                    $null -eq $streamProperty -or $streamProperty.Value -cne 'Error' -or
                    $null -eq $typeNameProperty -or
                    $typeNameProperty.Value -cne 'HostHunter.RuntimeFailure' -or
                    $null -eq $terminatingProperty -or
                    $terminatingProperty.Value -isnot [bool] -or
                    -not [bool] $terminatingProperty.Value -or
                    $null -eq $valueProperty -or $null -eq $valueProperty.Value) {
                    return $false
                }

                $failureKindProperty = $valueProperty.Value.PSObject.Properties['FailureKind']
                return $null -ne $failureKindProperty -and
                    $failureKindProperty.Value -ceq 'RuntimeMismatch'
            }
    )
    if ($candidateEvents.Count -ne 1) {
        return $null
    }

    $failureValue = $candidateEvents[0].Value
    $identityProperty = $failureValue.PSObject.Properties['ObservedIdentity']
    if ($null -eq $identityProperty -or $null -eq $identityProperty.Value) {
        return $null
    }
    $identity = $identityProperty.Value

    # Reuse the canonical identity validator. A valid mismatch must be a
    # complete, self-consistent identity which specifically does not satisfy
    # the runtime requested from this wrapper. A matching, malformed, or
    # internally inconsistent identity makes the envelope contradictory.
    $syntheticIdentityEvent = [pscustomobject]@{
        Stream = 'Output'
        Value = $identity
    }
    try {
        $null = Get-HHSshValidatedIdentity `
            -StreamEvents @($syntheticIdentityEvent) `
            -PowerShellRuntime $PowerShellRuntime
        return $null
    }
    catch {
        if ((Get-HHSshFailureKind -ErrorObject $_) -cne 'RuntimeMismatch') {
            return $null
        }
    }

    $observedAt = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParse(
            [string] $candidateEvents[0].ObservedAtUtc,
            [ref] $observedAt
        )) {
        return $null
    }

    return [pscustomobject][ordered]@{
        RemotePowerShellVersion = [string] $identity.PowerShellVersion
        RemotePSEdition = [string] $identity.PSEdition
        ExecutionMode = 'WindowsPowerShellCompatibility'
        RemoteIdentity = $identity
        ValidatedAtUtc = $observedAt.ToUniversalTime().ToString('o')
    }
}

function Close-HHSshSession {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object] $Session,

        [scriptblock] $SessionRemover,

        [scriptblock] $SessionRemovalPowerShellFactory,

        [ValidateRange(1, 60000)]
        [int] $CleanupTimeoutMilliseconds = 5000,

        [Threading.CancellationToken] $CancellationToken = [Threading.CancellationToken]::None
    )

    if ($null -ne $SessionRemover) {
        # Injected removers own their bounded implementation and receive both
        # deadline and cancellation context. A false terminal value is the
        # deterministic test-seam signal that the deadline expired.
        $removalResults = @(& $SessionRemover `
                $Session `
                $CleanupTimeoutMilliseconds `
                $CancellationToken)
        if ($removalResults.Count -gt 0 -and
            $removalResults[-1] -is [bool] -and
            -not [bool] $removalResults[-1]) {
            throw [TimeoutException]::new(
                "The SSH session did not close within $CleanupTimeoutMilliseconds milliseconds."
            )
        }
        return
    }

    if ($null -eq $SessionRemovalPowerShellFactory -and
        $Session -isnot [Management.Automation.Runspaces.PSSession]) {
        throw [InvalidOperationException]::new(
            'Bounded native cleanup requires a PowerShell PSSession.'
        )
    }

    $stopwatch = [Diagnostics.Stopwatch]::StartNew()
    $removalPowerShell = if ($null -ne $SessionRemovalPowerShellFactory) {
        & $SessionRemovalPowerShellFactory
    }
    else {
        [PowerShell]::Create()
    }
    if ($null -eq $removalPowerShell) {
        throw [InvalidOperationException]::new(
            'The SSH session-removal worker factory returned no worker.'
        )
    }

    $asyncResult = $null
    $operationFinished = $false
    $stopRequested = $false
    try {
        $null = $removalPowerShell.AddCommand('Remove-PSSession').
            AddParameter('Session', @($Session)).
            AddParameter('Confirm', $false).
            AddParameter('ErrorAction', 'Stop')
        $asyncResult = $removalPowerShell.BeginInvoke()
        if ($null -eq $asyncResult -or $null -eq $asyncResult.AsyncWaitHandle) {
            throw [InvalidOperationException]::new(
                'The SSH session-removal worker returned no asynchronous wait handle.'
            )
        }

        $remainingMilliseconds = [Math]::Max(
            0,
            $CleanupTimeoutMilliseconds - $stopwatch.ElapsedMilliseconds
        )
        $waitHandles = [Threading.WaitHandle[]] @(
            $asyncResult.AsyncWaitHandle,
            $CancellationToken.WaitHandle
        )
        $waitResult = [Threading.WaitHandle]::WaitAny(
            $waitHandles,
            [int] $remainingMilliseconds
        )
        if ($waitResult -eq 1) {
            try {
                $null = $removalPowerShell.BeginStop($null, $null)
                $stopRequested = $true
            }
            catch {
                $null = $_.Exception
            }
            throw [OperationCanceledException]::new(
                'SSH session cleanup was cancelled.',
                $CancellationToken
            )
        }
        if ($waitResult -eq [Threading.WaitHandle]::WaitTimeout) {
            try {
                $null = $removalPowerShell.BeginStop($null, $null)
                $stopRequested = $true
            }
            catch {
                $null = $_.Exception
            }
            throw [TimeoutException]::new(
                "The SSH session did not close within $CleanupTimeoutMilliseconds milliseconds."
            )
        }

        $operationFinished = $true
        $null = $removalPowerShell.EndInvoke($asyncResult)
    }
    catch {
        if ($null -ne $asyncResult -and -not $operationFinished -and -not $stopRequested) {
            try {
                $null = $removalPowerShell.BeginStop($null, $null)
            }
            catch {
                $null = $_.Exception
            }
        }
        throw
    }
    finally {
        # Dispose is synchronous. Only call it once the worker has completed;
        # a timed-out worker has already received non-blocking cancellation.
        if ($null -eq $asyncResult -or $operationFinished) {
            $removalPowerShell.Dispose()
        }
    }
}

function Open-HHSshValidatedSession {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object] $Plan,

        [scriptblock] $SessionFactory,

        [scriptblock] $RemoteInvoker,

        [scriptblock] $BridgeInvoker,

        [scriptblock] $SessionRemover,

        [scriptblock] $Clock,

        [ValidateRange(1, [long]::MaxValue)]
        [long] $MaxOutputBytes = 104857600
    )

    $session = $null
    $context = $null
    $identityEvidence = [Collections.Generic.List[object]]::new()
    $requestedRuntime = Get-HHSshRequestedPowerShellRuntime -InputObject $Plan.Target
    try {
        $session = if ($null -ne $SessionFactory) {
            & $SessionFactory $Plan
        }
        else {
            $sessionParameters = @{
                HostName = $Plan.HostName
                Port = $Plan.Port
                UserName = $Plan.UserName
                ConnectingTimeout = $Plan.ConnectingTimeoutMilliseconds
                SSHTransport = $true
                Options = [hashtable] $Plan.Options
                ErrorAction = 'Stop'
            }
            if ($Plan.Authentication -ceq 'PublicKey') {
                $sessionParameters.KeyFilePath = $Plan.KeyFilePath
            }
            New-PSSession @sessionParameters
        }
        if ($null -eq $session) {
            throw (New-HHSshClassifiedException -FailureKind TransportFailure `
                    -Message 'The SSH session factory returned no session.')
        }

        $identityEvents = @(Invoke-HHSshRemoteCapture `
                -Session $session `
                -ScriptBlock (Get-HHSshIdentityProbeScriptBlock) `
                -Phase Identity `
                -MaxOutputBytes $MaxOutputBytes `
                -PowerShellRuntime PowerShell7 `
                -RemoteInvoker $RemoteInvoker `
                -Clock $Clock)
        foreach ($identityEvent in $identityEvents) {
            $identityEvidence.Add($identityEvent)
        }
        $outerIdentity = Get-HHSshValidatedIdentity `
            -StreamEvents $identityEvents `
            -PowerShellRuntime PowerShell7
        $identity = $outerIdentity
        $executionMode = 'Direct'
        if ($requestedRuntime -ceq 'WindowsPowerShell51') {
            $remainingIdentityBytes = $MaxOutputBytes - (
                Get-HHSshStreamEventByteCount -StreamEvents @($identityEvidence)
            )
            if ($remainingIdentityBytes -le 0) {
                throw (New-HHSshClassifiedException -FailureKind OutputLimitExceeded `
                        -Message "The serialized plaintext output limit of $MaxOutputBytes bytes was exceeded.")
            }
            $runtimeIdentityEvents = @(Invoke-HHSshRemoteCapture `
                    -Session $session `
                    -ScriptBlock (Get-HHSshIdentityProbeScriptBlock) `
                    -Phase RuntimeIdentity `
                    -SequenceStart $identityEvidence.Count `
                    -MaxOutputBytes $remainingIdentityBytes `
                    -PowerShellRuntime WindowsPowerShell51 `
                    -BridgeInvoker $BridgeInvoker `
                    -Clock $Clock)
            foreach ($identityEvent in $runtimeIdentityEvents) {
                $identityEvidence.Add($identityEvent)
            }
            $identity = Get-HHSshValidatedIdentity `
                -StreamEvents $runtimeIdentityEvents `
                -PowerShellRuntime WindowsPowerShell51
            $executionMode = 'WindowsPowerShellCompatibility'
        }
        # Runtime identity validation proves exactly one requested-runtime identity event.
        $validatedAt = $identityEvidence[-1].ObservedAtUtc

        $context = [pscustomobject][ordered]@{
            Session = $session
            Identity = $identity
            OuterIdentity = $outerIdentity
            IdentityEvents = @($identityEvidence)
            ValidatedAtUtc = $validatedAt
            RemotePowerShellVersion = [string] $identity.PowerShellVersion
            RemotePSEdition = [string] $identity.PSEdition
            PowerShellRuntime = $requestedRuntime
            ExecutionMode = $executionMode
            HostKeyFingerprint = [string] $Plan.HostKeyFingerprint
            OutputBytes = Get-HHSshStreamEventByteCount -StreamEvents @($identityEvidence)
        }
        $context.PSObject.TypeNames.Insert(0, 'HostHunter.SshSessionContext')
    }
    catch {
        $originalFailure = $_
        if ($identityEvidence.Count -gt 0) {
            $combinedEvidence = [Collections.Generic.List[object]]::new()
            foreach ($identityEvent in $identityEvidence) {
                $combinedEvidence.Add($identityEvent)
            }
            if ($originalFailure.Exception.Data.Contains('HHStreamEvents')) {
                foreach ($partialEvent in @($originalFailure.Exception.Data['HHStreamEvents'])) {
                    $partialEvent.Sequence = $combinedEvidence.Count
                    $combinedEvidence.Add($partialEvent)
                }
            }
            $originalFailure.Exception.Data['HHStreamEvents'] = [object[]] $combinedEvidence
            $originalFailure.Exception.Data['HHOutputBytes'] = Get-HHSshStreamEventByteCount `
                -StreamEvents @($combinedEvidence)
        }
        if ((Get-HHSshFailureKind -ErrorObject $originalFailure) -ceq 'RuntimeMismatch') {
            $observedIdentity = if ($originalFailure.Exception.Data.Contains('HHObservedIdentity')) {
                $originalFailure.Exception.Data['HHObservedIdentity']
            }
            else {
                $null
            }
            $observedProbeRuntime = if ($originalFailure.Exception.Data.Contains(
                    'HHObservedProbeRuntime'
                )) {
                [string] $originalFailure.Exception.Data['HHObservedProbeRuntime']
            }
            else {
                $null
            }
            $observedAtUtc = $null
            $failureIdentityEvidence = if ($originalFailure.Exception.Data.Contains(
                    'HHStreamEvents'
                )) {
                @($originalFailure.Exception.Data['HHStreamEvents'])
            }
            else {
                @($identityEvidence)
            }
            if ($null -eq $observedIdentity) {
                foreach ($identityEvent in $failureIdentityEvidence) {
                    $valueProperty = $identityEvent.PSObject.Properties['Value']
                    if ($null -eq $valueProperty -or $null -eq $valueProperty.Value) {
                        continue
                    }
                    $observedProperty = $valueProperty.Value.PSObject.Properties['ObservedIdentity']
                    if ($null -ne $observedProperty -and $null -ne $observedProperty.Value) {
                        $observedIdentity = $observedProperty.Value
                        $observedProbeRuntime = 'WindowsPowerShell51'
                        $observedAtUtc = $identityEvent.ObservedAtUtc
                    }
                }
            }
            if ($null -ne $observedIdentity -and
                $observedProbeRuntime -ceq $requestedRuntime) {
                if ([string]::IsNullOrWhiteSpace([string] $observedAtUtc)) {
                    $identityEvent = @($failureIdentityEvidence | Where-Object {
                            $_.Stream -ceq 'Output' -and
                            $null -ne $_.Value -and
                            $_.Value -eq $observedIdentity
                        } | Select-Object -Last 1)
                    if ($identityEvent.Count -eq 1) {
                        $observedAtUtc = $identityEvent[0].ObservedAtUtc
                    }
                }
                $originalFailure.Exception.Data['HHObservedIdentity'] = $observedIdentity
                $originalFailure.Exception.Data['HHObservedRemotePowerShellVersion'] =
                    [string] $observedIdentity.PowerShellVersion
                $originalFailure.Exception.Data['HHObservedRemotePSEdition'] =
                    [string] $observedIdentity.PSEdition
                $originalFailure.Exception.Data['HHObservedExecutionMode'] = if (
                    $observedProbeRuntime -ceq 'WindowsPowerShell51'
                ) {
                    'WindowsPowerShellCompatibility'
                }
                else {
                    'Direct'
                }
                $originalFailure.Exception.Data['HHObservedValidatedAtUtc'] = [string] $observedAtUtc
                $originalFailure.Exception.Data['HHObservedHostKeyFingerprint'] =
                    [string] $Plan.HostKeyFingerprint
            }
            elseif ($observedProbeRuntime -cne $requestedRuntime) {
                $originalFailure.Exception.Data['HHFailureKind'] = 'RuntimeUnavailable'
            }
        }
        if ($null -ne $session) {
            try {
                Close-HHSshSession -Session $session -SessionRemover $SessionRemover
            }
            catch {
                $null = $_.Exception
            }
        }
        throw $originalFailure
    }
    return $context
}

function Open-HHSshSession {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object] $Target,

        [Parameter(Mandatory)]
        [string] $KnownHostsPath,

        [ValidateRange(1, 300)]
        [int] $ConnectionTimeoutSeconds = 15,

        [ValidateRange(1, [long]::MaxValue)]
        [long] $MaxOutputBytes = 104857600,

        [scriptblock] $SessionFactory,

        [scriptblock] $RemoteInvoker,

        [scriptblock] $BridgeInvoker,

        [scriptblock] $SessionRemover,

        [scriptblock] $Clock
    )

    $plan = New-HHSshTransportPlan `
        -Target $Target `
        -KnownHostsPath $KnownHostsPath `
        -ConnectionTimeoutSeconds $ConnectionTimeoutSeconds
    return Open-HHSshValidatedSession `
        -Plan $plan `
        -SessionFactory $SessionFactory `
        -RemoteInvoker $RemoteInvoker `
        -BridgeInvoker $BridgeInvoker `
        -SessionRemover $SessionRemover `
        -Clock $Clock `
        -MaxOutputBytes $MaxOutputBytes
}

function Invoke-HHSshSessionCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object] $SessionContext,

        [Parameter(Mandatory)]
        [scriptblock] $ScriptBlock,

        [AllowEmptyCollection()]
        [object[]] $ArgumentList = @(),

        [ValidateRange(1, [long]::MaxValue)]
        [long] $MaxOutputBytes = 104857600,

        [scriptblock] $RemoteInvoker,

        [scriptblock] $BridgeInvoker,

        [scriptblock] $Clock
    )

    $events = [Collections.Generic.List[object]]::new()
    foreach ($identityEvent in @($SessionContext.IdentityEvents)) {
        $events.Add($identityEvent)
    }
    $powerShellRuntime = Get-HHSshRequestedPowerShellRuntime -InputObject $SessionContext
    try {
        $remainingBytes = $MaxOutputBytes - [long] $SessionContext.OutputBytes
        if ($remainingBytes -le 0) {
            $limitException = New-HHSshClassifiedException -FailureKind OutputLimitExceeded `
                -Message "The serialized plaintext output limit of $MaxOutputBytes bytes was exceeded."
            $limitException.Data['HHDispatchState'] = 'NotDispatched'
            $limitException.Data['HHOutcomeStatus'] = 'Failed'
            throw $limitException
        }
        $commandEvents = @(Invoke-HHSshRemoteCapture `
                -Session $SessionContext.Session `
                -ScriptBlock $ScriptBlock `
                -ArgumentList $ArgumentList `
                -Phase Command `
                -SequenceStart $events.Count `
                -MaxOutputBytes $remainingBytes `
                -PowerShellRuntime $powerShellRuntime `
                -RemoteInvoker $RemoteInvoker `
                -BridgeInvoker $BridgeInvoker `
                -Clock $Clock)
        foreach ($eventRecord in $commandEvents) {
            $events.Add($eventRecord)
        }
        $commandResult = [pscustomobject][ordered]@{
            Succeeded = $true
            FailureKind = $null
            StreamEvents = @($events)
            OutputBytes = Get-HHSshStreamEventByteCount -StreamEvents $events
            ExceptionType = $null
            DispatchState = 'Completed'
            OutcomeStatus = 'Succeeded'
            RemotePowerShellVersion = $null
            RemotePSEdition = $null
            ExecutionMode = $null
            RemoteIdentity = $null
            ValidatedAtUtc = $null
            HostKeyFingerprint = $null
        }
    }
    catch {
        if ($_.Exception.Data.Contains('HHStreamEvents')) {
            foreach ($eventRecord in @($_.Exception.Data['HHStreamEvents'])) {
                $eventRecord.Sequence = $events.Count
                $events.Add($eventRecord)
            }
        }
        $failureKind = Get-HHSshFailureKind -ErrorObject $_
        $mismatchEvidence = if ($failureKind -ceq 'RuntimeMismatch') {
            Get-HHSshCommandRuntimeMismatchEvidence `
                -StreamEvents @($events) `
                -PowerShellRuntime $powerShellRuntime
        }
        else {
            $null
        }
        if ($failureKind -ceq 'RuntimeMismatch' -and $null -eq $mismatchEvidence) {
            $failureKind = 'TransportFailure'
        }
        $commandResult = [pscustomobject][ordered]@{
            Succeeded = $false
            FailureKind = $failureKind
            StreamEvents = @($events)
            OutputBytes = Get-HHSshStreamEventByteCount -StreamEvents $events
            ExceptionType = $_.Exception.GetType().FullName
            DispatchState = if ($_.Exception.Data.Contains('HHDispatchState')) {
                [string] $_.Exception.Data['HHDispatchState']
            }
            else {
                'DispatchUncertain'
            }
            OutcomeStatus = if ($_.Exception.Data.Contains('HHOutcomeStatus')) {
                [string] $_.Exception.Data['HHOutcomeStatus']
            }
            else {
                'Unknown'
            }
            RemotePowerShellVersion = if ($null -ne $mismatchEvidence) {
                $mismatchEvidence.RemotePowerShellVersion
            }
            else { $null }
            RemotePSEdition = if ($null -ne $mismatchEvidence) {
                $mismatchEvidence.RemotePSEdition
            }
            else { $null }
            ExecutionMode = if ($null -ne $mismatchEvidence) {
                $mismatchEvidence.ExecutionMode
            }
            else { $null }
            RemoteIdentity = if ($null -ne $mismatchEvidence) {
                $mismatchEvidence.RemoteIdentity
            }
            else { $null }
            ValidatedAtUtc = if ($null -ne $mismatchEvidence) {
                $mismatchEvidence.ValidatedAtUtc
            }
            else { $null }
            HostKeyFingerprint = if ($null -ne $mismatchEvidence) {
                [string] $SessionContext.HostKeyFingerprint
            }
            else { $null }
        }
    }
    $commandResult.PSObject.TypeNames.Insert(0, 'HostHunter.SshCommandResult')
    return $commandResult
}

function Invoke-HHSshSessionFanOut {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter',
        'Clock',
        Justification = 'The parameter is captured by the streaming process closure.'
    )]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter',
        'EventObserver',
        Justification = 'The parameter is captured by the attributed streaming process closure.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Collections.IDictionary] $SessionContextByName,

        [Parameter(Mandatory)]
        [scriptblock] $ScriptBlock,

        [AllowEmptyCollection()]
        [object[]] $ArgumentList = @(),

        [ValidateRange(1, 8)]
        [int] $ThrottleLimit = 8,

        [ValidateRange(1, [long]::MaxValue)]
        [long] $MaxOutputBytes = 104857600,

        [ValidateRange(1, [long]::MaxValue)]
        [long] $MaxAggregateOutputBytes = 104857600,

        [scriptblock] $FanOutInvoker,

        [scriptblock] $EventObserver,

        [scriptblock] $Clock
    )

    if ($SessionContextByName.Count -lt 1 -or $SessionContextByName.Count -gt 8) {
        throw [ArgumentException]::new('SSH fan-out requires between one and eight session contexts.')
    }

    $stateByName = [ordered]@{}
    $nameByRunspaceId = [Collections.Generic.Dictionary[string, string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    $activeSessionsByRuntime = [ordered]@{
        PowerShell7 = [Collections.Generic.List[object]]::new()
        WindowsPowerShell51 = [Collections.Generic.List[object]]::new()
    }
    [long] $aggregateOutputBytes = 0
    foreach ($entry in $SessionContextByName.GetEnumerator()) {
        $targetName = [string] $entry.Key
        $context = $entry.Value
        if ([string]::IsNullOrWhiteSpace($targetName) -or
            $null -eq $context -or
            $null -eq $context.PSObject.Properties['Session'] -or
            $null -eq $context.Session) {
            throw [ArgumentException]::new('Each SSH fan-out entry requires a name and session context.')
        }
        $instanceIdProperty = $context.Session.PSObject.Properties['InstanceId']
        $instanceId = [Guid]::Empty
        if ($null -eq $instanceIdProperty -or
            -not [Guid]::TryParse([string] $instanceIdProperty.Value, [ref] $instanceId) -or
            $instanceId -eq [Guid]::Empty) {
            throw [ArgumentException]::new(
                "SSH fan-out session '$targetName' does not have a valid InstanceId."
            )
        }
        $instanceIdText = $instanceId.ToString('D')
        if ($nameByRunspaceId.ContainsKey($instanceIdText)) {
            throw [ArgumentException]::new('SSH fan-out session InstanceId values must be unique.')
        }
        $nameByRunspaceId.Add($instanceIdText, $targetName)
        $powerShellRuntime = Get-HHSshRequestedPowerShellRuntime -InputObject $context

        $events = [Collections.Generic.List[object]]::new()
        foreach ($identityEvent in @($context.IdentityEvents)) {
            $events.Add($identityEvent)
        }
        [long] $initialBytes = Get-HHSshStreamEventByteCount -StreamEvents $events
        if ($aggregateOutputBytes + $initialBytes -gt $MaxAggregateOutputBytes) {
            throw [InvalidOperationException]::new(
                'SSH fan-out identity evidence exceeds the aggregate controller output limit.'
            )
        }
        $aggregateOutputBytes += $initialBytes
        $state = [pscustomobject][ordered]@{
            TargetName = $targetName
            Context = $context
            PowerShellRuntime = $powerShellRuntime
            Events = $events
            OutputBytes = $initialBytes
            NextRemoteSequence = 0
            Completed = $false
            Terminated = $false
            FailureKind = $null
            ExceptionType = $null
            DispatchState = 'NotDispatched'
            OutcomeStatus = 'Failed'
        }
        if ($initialBytes -ge $MaxOutputBytes) {
            $state.FailureKind = 'OutputLimitExceeded'
            $state.ExceptionType = [InvalidOperationException].FullName
        }
        else {
            $activeSessionsByRuntime[$powerShellRuntime].Add($context.Session)
        }
        $stateByName[$targetName] = $state
    }

    $processEnvelope = {
        $envelope = $_
        if (-not (Test-HHSshStreamEnvelope -InputObject $envelope)) {
            throw (New-HHSshClassifiedException -FailureKind TransportFailure `
                    -Message 'SSH fan-out returned an invalid stream envelope.')
        }
        $runspaceProperty = $envelope.PSObject.Properties['RunspaceId']
        $runspaceId = [Guid]::Empty
        if ($null -eq $runspaceProperty -or
            -not [Guid]::TryParse([string] $runspaceProperty.Value, [ref] $runspaceId) -or
            -not $nameByRunspaceId.ContainsKey($runspaceId.ToString('D'))) {
            throw (New-HHSshClassifiedException -FailureKind TransportFailure `
                    -Message 'SSH fan-out could not attribute a stream envelope to a proven session.')
        }

        $envelopeTargetName = $nameByRunspaceId[$runspaceId.ToString('D')]
        $targetState = $stateByName[$envelopeTargetName]
        if ($targetState.Completed) {
            throw (New-HHSshClassifiedException -FailureKind TransportFailure `
                    -Message 'SSH fan-out received data after a target completion envelope.')
        }
        if ([int] $envelope.Sequence -ne $targetState.NextRemoteSequence) {
            throw (New-HHSshClassifiedException -FailureKind TransportFailure `
                    -Message 'SSH fan-out received an out-of-order target stream envelope.')
        }

        if ($envelope.Kind -ceq 'Completion') {
            if (-not (Test-HHSshCompletionEnvelope -InputObject $envelope)) {
                throw (New-HHSshClassifiedException -FailureKind TransportFailure `
                        -Message 'SSH fan-out returned invalid completion metadata.')
            }
            $targetState.Completed = $true
            $targetState.Terminated = [bool] $envelope.Terminated
            $targetState.FailureKind = if (
                [string]::IsNullOrWhiteSpace([string] $envelope.FailureKind)
            ) {
                $null
            }
            else {
                [string] $envelope.FailureKind
            }
            if (-not [string]::IsNullOrWhiteSpace($targetState.FailureKind)) {
                $targetState.ExceptionType = [InvalidOperationException].FullName
            }
            $targetState.DispatchState = [string] $envelope.DispatchState
            $targetState.OutcomeStatus = [string] $envelope.OutcomeStatus
            $targetState.NextRemoteSequence++
            return
        }
        if ($envelope.Stream -cnotin @('Output', 'Error', 'Warning', 'Verbose', 'Debug', 'Information')) {
            throw (New-HHSshClassifiedException -FailureKind TransportFailure `
                    -Message 'SSH fan-out returned an invalid stream kind.')
        }

        $eventRecord = New-HHSshStreamEvent `
            -Sequence $targetState.Events.Count `
            -Phase Command `
            -InputObject $envelope.Value `
            -StreamOverride $envelope.Stream `
            -TypeNameOverride $envelope.TypeName `
            -RemoteSequence ([int] $envelope.Sequence) `
            -IsTerminating ([bool] $envelope.IsTerminating) `
            -Clock $Clock
        if ($targetState.OutputBytes + $eventRecord.SerializedByteCount -gt $MaxOutputBytes -or
            $aggregateOutputBytes + $eventRecord.SerializedByteCount -gt $MaxAggregateOutputBytes) {
            $targetState.FailureKind = 'OutputLimitExceeded'
            $targetState.ExceptionType = [InvalidOperationException].FullName
            $targetState.DispatchState = 'Dispatched'
            $targetState.OutcomeStatus = 'Failed'
            $limitException = New-HHSshClassifiedException `
                -FailureKind OutputLimitExceeded `
                -Message "Target '$envelopeTargetName' exceeded the serialized plaintext output limit."
            $limitException.Data['HHTargetName'] = $envelopeTargetName
            throw $limitException
        }
        if ($null -ne $EventObserver) {
            & $EventObserver $envelopeTargetName $eventRecord | Out-Null
        }
        $targetState.Events.Add($eventRecord)
        $targetState.OutputBytes += $eventRecord.SerializedByteCount
        $aggregateOutputBytes += $eventRecord.SerializedByteCount
        $streamDispatchProperty = $envelope.PSObject.Properties['DispatchState']
        $targetState.DispatchState = if ($null -ne $streamDispatchProperty -and
            -not [string]::IsNullOrWhiteSpace([string] $streamDispatchProperty.Value)) {
            [string] $streamDispatchProperty.Value
        }
        else {
            'Dispatched'
        }
        $targetState.NextRemoteSequence++
    }

    foreach ($runtimeName in @('PowerShell7', 'WindowsPowerShell51')) {
        $activeSessions = $activeSessionsByRuntime[$runtimeName]
        if ($activeSessions.Count -eq 0) {
            continue
        }
        $sharedFailure = $null
        $protocolFailure = $false
        try {
            $remoteWrapper = Get-HHSshRemoteEnvelopeScriptBlock -PowerShellRuntime $runtimeName
            $remoteArguments = @(
                $ScriptBlock.ToString()
                [Management.Automation.PSSerializer]::Serialize([object[]] $ArgumentList, 20)
            )
            if ($null -ne $FanOutInvoker) {
                & $FanOutInvoker `
                    ([object[]] $activeSessions) `
                    $remoteWrapper `
                    $remoteArguments `
                    $ThrottleLimit `
                    $runtimeName | ForEach-Object -Process $processEnvelope
            }
            else {
                $invokeParameters = @{
                    Session = [object[]] $activeSessions
                    ScriptBlock = $remoteWrapper
                    ArgumentList = $remoteArguments
                    ThrottleLimit = $ThrottleLimit
                    ErrorAction = 'Stop'
                }
                Invoke-Command @invokeParameters | ForEach-Object -Process $processEnvelope
            }
        }
        catch {
            $sharedFailure = $_
            $protocolFailure = $_.Exception.Message -like 'SSH fan-out*'
        }
        foreach ($entry in $stateByName.GetEnumerator()) {
            $targetState = $entry.Value
            if ($targetState.PowerShellRuntime -cne $runtimeName -or
                ($targetState.Completed -and -not $protocolFailure) -or
                $targetState.FailureKind -ceq 'OutputLimitExceeded') {
                continue
            }
            $targetState.FailureKind = if ($protocolFailure) {
                'TransportFailure'
            }
            elseif ($null -eq $sharedFailure) {
                'TransportFailure'
            }
            elseif ((Get-HHSshFailureKind -ErrorObject $sharedFailure) -ceq 'OutputLimitExceeded') {
                'TransportFailure'
            }
            else {
                Get-HHSshFailureKind -ErrorObject $sharedFailure
            }
            $targetState.ExceptionType = if ($null -eq $sharedFailure) {
                [InvalidOperationException].FullName
            }
            else {
                $sharedFailure.Exception.GetType().FullName
            }
            $targetState.DispatchState = 'DispatchUncertain'
            $targetState.OutcomeStatus = 'Unknown'
        }
    }

    $resultByName = [ordered]@{}
    foreach ($entry in $stateByName.GetEnumerator()) {
        $targetState = $entry.Value
        if ($targetState.Completed -and $targetState.Terminated -and
            $null -eq $targetState.FailureKind) {
            $targetState.FailureKind = 'RemoteCommandFailure'
            $targetState.ExceptionType = [InvalidOperationException].FullName
            $targetState.DispatchState = 'Completed'
            $targetState.OutcomeStatus = 'Failed'
        }

        $mismatchEvidence = if ($targetState.FailureKind -ceq 'RuntimeMismatch') {
            Get-HHSshCommandRuntimeMismatchEvidence `
                -StreamEvents @($targetState.Events) `
                -PowerShellRuntime $targetState.PowerShellRuntime
        }
        else {
            $null
        }
        if ($targetState.FailureKind -ceq 'RuntimeMismatch' -and
            $null -eq $mismatchEvidence) {
            $targetState.FailureKind = 'TransportFailure'
        }

        $targetResult = [pscustomobject][ordered]@{
            TargetName = $targetState.TargetName
            Succeeded = $targetState.Completed -and
                [string]::IsNullOrWhiteSpace([string] $targetState.FailureKind) -and
                $targetState.DispatchState -ceq 'Completed' -and
                $targetState.OutcomeStatus -ceq 'Succeeded'
            FailureKind = $targetState.FailureKind
            StreamEvents = @($targetState.Events)
            OutputBytes = [long] $targetState.OutputBytes
            ExceptionType = $targetState.ExceptionType
            DispatchState = $targetState.DispatchState
            OutcomeStatus = $targetState.OutcomeStatus
            RemotePowerShellVersion = if ($null -ne $mismatchEvidence) {
                $mismatchEvidence.RemotePowerShellVersion
            }
            else { $null }
            RemotePSEdition = if ($null -ne $mismatchEvidence) {
                $mismatchEvidence.RemotePSEdition
            }
            else { $null }
            ExecutionMode = if ($null -ne $mismatchEvidence) {
                $mismatchEvidence.ExecutionMode
            }
            else { $null }
            RemoteIdentity = if ($null -ne $mismatchEvidence) {
                $mismatchEvidence.RemoteIdentity
            }
            else { $null }
            ValidatedAtUtc = if ($null -ne $mismatchEvidence) {
                $mismatchEvidence.ValidatedAtUtc
            }
            else { $null }
            HostKeyFingerprint = if ($null -ne $mismatchEvidence) {
                [string] $targetState.Context.HostKeyFingerprint
            }
            else { $null }
        }
        $targetResult.PSObject.TypeNames.Insert(0, 'HostHunter.SshCommandResult')
        $resultByName[$targetState.TargetName] = $targetResult
    }
    return $resultByName
}

function Invoke-HHSshTransport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object] $Target,

        [Parameter(Mandatory)]
        [string] $KnownHostsPath,

        [scriptblock] $RemoteScriptBlock,

        [AllowEmptyCollection()]
        [object[]] $ArgumentList = @(),

        [ValidateRange(1, 300)]
        [int] $ConnectionTimeoutSeconds = 15,

        [ValidateRange(1, [long]::MaxValue)]
        [long] $MaxOutputBytes = 104857600,

        [scriptblock] $SessionFactory,

        [scriptblock] $RemoteInvoker,

        [scriptblock] $BridgeInvoker,

        [scriptblock] $SessionRemover,

        [scriptblock] $Clock
    )

    $context = $null
    $result = $null
    $allEvents = [Collections.Generic.List[object]]::new()
    try {
        $context = Open-HHSshSession `
            -Target $Target `
            -KnownHostsPath $KnownHostsPath `
            -ConnectionTimeoutSeconds $ConnectionTimeoutSeconds `
            -MaxOutputBytes $MaxOutputBytes `
            -SessionFactory $SessionFactory `
            -RemoteInvoker $RemoteInvoker `
            -BridgeInvoker $BridgeInvoker `
            -SessionRemover $SessionRemover `
            -Clock $Clock
        foreach ($eventRecord in $context.IdentityEvents) {
            $allEvents.Add($eventRecord)
        }

        if ($null -ne $RemoteScriptBlock) {
            $commandResult = Invoke-HHSshSessionCommand `
                -SessionContext $context `
                -ScriptBlock $RemoteScriptBlock `
                -ArgumentList $ArgumentList `
                -MaxOutputBytes $MaxOutputBytes `
                -RemoteInvoker $RemoteInvoker `
                -BridgeInvoker $BridgeInvoker `
                -Clock $Clock
            $allEvents.Clear()
            foreach ($eventRecord in $commandResult.StreamEvents) {
                $allEvents.Add($eventRecord)
            }
            if (-not $commandResult.Succeeded) {
                $commandException = New-HHSshClassifiedException `
                    -FailureKind $commandResult.FailureKind `
                    -Message 'The SSH remote command did not complete successfully.'
                $commandException.Data['HHDispatchState'] = $commandResult.DispatchState
                $commandException.Data['HHOutcomeStatus'] = $commandResult.OutcomeStatus
                if ($commandResult.FailureKind -ceq 'RuntimeMismatch') {
                    $commandException.Data['HHObservedIdentity'] = $commandResult.RemoteIdentity
                    $commandException.Data['HHObservedRemotePowerShellVersion'] =
                        $commandResult.RemotePowerShellVersion
                    $commandException.Data['HHObservedRemotePSEdition'] =
                        $commandResult.RemotePSEdition
                    $commandException.Data['HHObservedExecutionMode'] =
                        $commandResult.ExecutionMode
                    $commandException.Data['HHObservedValidatedAtUtc'] =
                        $commandResult.ValidatedAtUtc
                    # The command wrapper cannot prove a host key. Reuse only
                    # the fingerprint proven by the already-open context.
                    $commandException.Data['HHObservedHostKeyFingerprint'] =
                        $context.HostKeyFingerprint
                }
                throw $commandException
            }
        }

        $result = [pscustomobject][ordered]@{
            Succeeded = $true
            FailureKind = $null
            ValidatedAtUtc = $context.ValidatedAtUtc
            RemotePowerShellVersion = $context.RemotePowerShellVersion
            RemotePSEdition = $context.RemotePSEdition
            ExecutionMode = $context.ExecutionMode
            RemoteIdentity = $context.Identity
            HostKeyFingerprint = $context.HostKeyFingerprint
            StreamEvents = @($allEvents)
            OutputBytes = Get-HHSshStreamEventByteCount -StreamEvents $allEvents
            ExceptionType = $null
            SessionRemovalFailure = $false
            DispatchState = if ($null -eq $RemoteScriptBlock) { 'NotDispatched' } else { 'Completed' }
            OutcomeStatus = 'Succeeded'
        }
    }
    catch {
        $failureKind = Get-HHSshFailureKind -ErrorObject $_
        $hasObservedMismatchIdentity = $failureKind -ceq 'RuntimeMismatch' -and
            $_.Exception.Data.Contains('HHObservedIdentity') -and
            $_.Exception.Data.Contains('HHObservedRemotePowerShellVersion') -and
            $_.Exception.Data.Contains('HHObservedRemotePSEdition') -and
            $_.Exception.Data.Contains('HHObservedExecutionMode') -and
            $_.Exception.Data.Contains('HHObservedValidatedAtUtc') -and
            $_.Exception.Data.Contains('HHObservedHostKeyFingerprint')
        if ($_.Exception.Data.Contains('HHStreamEvents')) {
            foreach ($eventRecord in @($_.Exception.Data['HHStreamEvents'])) {
                $eventRecord.Sequence = $allEvents.Count
                $allEvents.Add($eventRecord)
            }
        }
        # ErrorRecord has a large, cyclic object graph. Keeping it as the event
        # value makes ConvertTo-Json (used by the accountability sink) consume
        # unbounded CPU on native SSH authentication failures. Preserve the
        # observable error text and concrete exception type in a finite value.
        $allEvents.Add((New-HHSshStreamEvent `
                -Sequence $allEvents.Count `
                -Phase Transport `
                -InputObject ([string] $_) `
                -StreamOverride Error `
                -TypeNameOverride $_.Exception.GetType().FullName `
                -Clock $Clock))
        $result = [pscustomobject][ordered]@{
            Succeeded = $false
            FailureKind = $failureKind
            ValidatedAtUtc = if ($hasObservedMismatchIdentity) {
                [string] $_.Exception.Data['HHObservedValidatedAtUtc']
            }
            elseif ($null -ne $context) {
                $context.ValidatedAtUtc
            }
            else { $null }
            RemotePowerShellVersion = if ($hasObservedMismatchIdentity) {
                [string] $_.Exception.Data['HHObservedRemotePowerShellVersion']
            }
            elseif ($null -ne $context) {
                $context.RemotePowerShellVersion
            }
            else { $null }
            RemotePSEdition = if ($hasObservedMismatchIdentity) {
                [string] $_.Exception.Data['HHObservedRemotePSEdition']
            }
            elseif ($null -ne $context) {
                $context.RemotePSEdition
            }
            else { $null }
            ExecutionMode = if ($hasObservedMismatchIdentity) {
                [string] $_.Exception.Data['HHObservedExecutionMode']
            }
            elseif ($null -ne $context) {
                $context.ExecutionMode
            }
            else { $null }
            RemoteIdentity = if ($hasObservedMismatchIdentity) {
                $_.Exception.Data['HHObservedIdentity']
            }
            elseif ($null -ne $context) {
                $context.Identity
            }
            else { $null }
            HostKeyFingerprint = if ($hasObservedMismatchIdentity) {
                [string] $_.Exception.Data['HHObservedHostKeyFingerprint']
            }
            elseif ($null -ne $context) {
                $context.HostKeyFingerprint
            }
            else {
                $null
            }
            StreamEvents = @($allEvents)
            OutputBytes = Get-HHSshStreamEventByteCount `
                -StreamEvents $allEvents `
                -ExcludePhase Transport
            ExceptionType = $_.Exception.GetType().FullName
            SessionRemovalFailure = $false
            DispatchState = if ($_.Exception.Data.Contains('HHDispatchState')) {
                [string] $_.Exception.Data['HHDispatchState']
            }
            else {
                'NotDispatched'
            }
            OutcomeStatus = if ($_.Exception.Data.Contains('HHOutcomeStatus')) {
                [string] $_.Exception.Data['HHOutcomeStatus']
            }
            else {
                'Failed'
            }
        }
    }
    finally {
        if ($null -ne $context) {
            try {
                Close-HHSshSession -Session $context.Session -SessionRemover $SessionRemover
            }
            catch {
                $result.SessionRemovalFailure = $true
                if ($result.Succeeded) {
                    $result.Succeeded = $false
                    $result.FailureKind = 'TransportFailure'
                    $result.ExceptionType = $_.Exception.GetType().FullName
                    $result.OutcomeStatus = 'Failed'
                }
            }
        }
    }

    $result.PSObject.TypeNames.Insert(0, 'HostHunter.SshTransportResult')
    return $result
}
