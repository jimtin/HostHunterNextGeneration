BeforeAll {
    $env:HH_COVERAGE_CASE = [Guid]::NewGuid().ToString('N')
    $sourceRoot = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
        Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration'
    }
    else {
        $env:HH_TEST_SOURCE_ROOT
    }
    . (Join-Path $sourceRoot 'Private/TargetModel.ps1')
    . (Join-Path $sourceRoot 'Private/SshTransport.ps1')

    function New-SshTestTarget {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
            'PSUseShouldProcessForStateChangingFunctions',
            '',
            Justification = 'This test helper only constructs an in-memory target value.'
        )]
        [CmdletBinding()]
        param(
            [string] $Name = 'alpha',
            [string] $Transport = 'SSH',
            [string] $Authentication = 'Password',
            [string] $HostName = 'example.test',
            [int] $Port = 22,
            [ValidateSet('PowerShell7', 'WindowsPowerShell51')]
            [string] $PowerShellRuntime = 'PowerShell7',
            [string] $Fingerprint = $script:testFingerprint,
            [string] $KeyPath
        )

        New-HHTargetRecord `
            -Name $Name `
            -Transport $Transport `
            -HostName $HostName `
            -Port $Port `
            -UserName operator `
            -Authentication $Authentication `
            -PowerShellRuntime $PowerShellRuntime `
            -HostKeyFingerprint $Fingerprint `
            -KeyPath $KeyPath `
            -IsActive $true `
            -LastValidatedAtUtc ([DateTimeOffset]::Parse('2026-08-23T00:00:00Z')) `
            -LastValidatedPowerShellVersion $(
                if ($PowerShellRuntime -ceq 'WindowsPowerShell51') { '5.1.26100.1' } else { '7.6.5' }
            )
    }

    function Write-SshTestKnownHost {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string] $Path,

            [string] $HostToken = 'example.test',

            [string[]] $AdditionalLines = @()
        )

        $lines = @($AdditionalLines) + @("$HostToken ssh-ed25519 $script:testKeyBase64")
        [IO.File]::WriteAllLines($Path, $lines, [Text.UTF8Encoding]::new($false))
        if (-not $IsWindows) {
            [IO.File]::SetUnixFileMode(
                $Path,
                [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite
            )
        }
        return $Path
    }

    function New-SshTestIdentity {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
            'PSUseShouldProcessForStateChangingFunctions',
            '',
            Justification = 'This test helper only constructs an in-memory identity value.'
        )]
        [CmdletBinding()]
        param(
            [string] $Edition = 'Core',
            [string] $PowerShellVersion = '7.6.5',
            [string] $ProcessPath,
            [string] $UserName = 'operator',
            [string] $MachineName = 'fixture'
        )

        if (-not $PSBoundParameters.ContainsKey('ProcessPath')) {
            $ProcessPath = if ($Edition -ceq 'Desktop') {
                'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
            }
            else {
                '/opt/microsoft/powershell/7/pwsh'
            }
        }
        [pscustomobject]@{
            Marker = 'HostHunter.PowerShellIdentity.v1'
            PSEdition = $Edition
            PowerShellVersion = $PowerShellVersion
            ProcessPath = $ProcessPath
            UserName = $UserName
            MachineName = $MachineName
        }
    }

    function New-SshTestIdentityEvent {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
            'PSUseShouldProcessForStateChangingFunctions',
            '',
            Justification = 'This test helper only constructs an in-memory event value.'
        )]
        [CmdletBinding()]
        param([object] $Identity = (New-SshTestIdentity))

        New-HHSshStreamEvent `
            -Sequence 0 `
            -Phase Identity `
            -InputObject $Identity `
            -Clock { [DateTimeOffset]::Parse('2026-08-23T01:02:03Z') }
    }

    function New-SshTestContext {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
            'PSUseShouldProcessForStateChangingFunctions',
            '',
            Justification = 'This test helper only constructs an in-memory session context.'
        )]
        [CmdletBinding()]
        param(
            [Guid] $InstanceId = [Guid]::NewGuid(),
            [object[]] $IdentityEvents = @((New-SshTestIdentityEvent)),
            [long] $OutputBytes = -1,
            [ValidateSet('PowerShell7', 'WindowsPowerShell51')]
            [string] $PowerShellRuntime = 'PowerShell7'
        )

        if ($OutputBytes -lt 0) {
            $OutputBytes = Get-HHSshStreamEventByteCount -StreamEvents $IdentityEvents
        }
        [pscustomobject]@{
            Session = [pscustomobject]@{ InstanceId = $InstanceId }
            Identity = if ($PowerShellRuntime -ceq 'WindowsPowerShell51') {
                New-SshTestIdentity -Edition Desktop -PowerShellVersion '5.1.26100.1'
            }
            else {
                New-SshTestIdentity
            }
            OuterIdentity = New-SshTestIdentity
            IdentityEvents = $IdentityEvents
            ValidatedAtUtc = '2026-08-23T01:02:03.0000000Z'
            RemotePowerShellVersion = if ($PowerShellRuntime -ceq 'WindowsPowerShell51') {
                '5.1.26100.1'
            }
            else {
                '7.6.5'
            }
            RemotePSEdition = if ($PowerShellRuntime -ceq 'WindowsPowerShell51') {
                'Desktop'
            }
            else {
                'Core'
            }
            PowerShellRuntime = $PowerShellRuntime
            ExecutionMode = if ($PowerShellRuntime -ceq 'WindowsPowerShell51') {
                'WindowsPowerShellCompatibility'
            }
            else {
                'Direct'
            }
            HostKeyFingerprint = $script:testFingerprint
            OutputBytes = $OutputBytes
        }
    }

    function New-SshTestEnvelope {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
            'PSUseShouldProcessForStateChangingFunctions',
            '',
            Justification = 'This test helper only constructs an in-memory stream envelope.'
        )]
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [Guid] $RunspaceId,

            [int] $Sequence = 0,

            [ValidateSet('Stream', 'Completion')]
            [string] $Kind = 'Stream',

            [string] $Stream = 'Output',

            [object] $Value = 'value',

            [bool] $Terminated = $false,

            [bool] $IsTerminating = $false,

            [AllowNull()]
            [string] $FailureKind,

            [AllowNull()]
            [string] $DispatchState,

            [AllowNull()]
            [string] $OutcomeStatus
        )

        if ($Kind -ceq 'Completion') {
            if ($Terminated -and -not $PSBoundParameters.ContainsKey('FailureKind')) {
                $FailureKind = 'RemoteCommandFailure'
            }
            if (-not $PSBoundParameters.ContainsKey('DispatchState')) {
                $DispatchState = 'Completed'
            }
            if (-not $PSBoundParameters.ContainsKey('OutcomeStatus')) {
                $OutcomeStatus = if ($Terminated) { 'Failed' } else { 'Succeeded' }
            }
        }

        $envelope = [pscustomobject][ordered]@{
            Marker = 'HostHunter.StreamEnvelope.v1'
            Kind = $Kind
            Sequence = $Sequence
            Stream = $Stream
            TypeName = if ($null -eq $Value) { 'null' } else { $Value.GetType().FullName }
            IsTerminating = $IsTerminating
            Value = $Value
            Terminated = $Terminated
            FailureKind = $FailureKind
            DispatchState = $DispatchState
            OutcomeStatus = $OutcomeStatus
        }
        $envelope | Add-Member -NotePropertyName RunspaceId -NotePropertyValue $RunspaceId
        return $envelope
    }

    function New-SshTestRuntimeMismatchEnvelopeSet {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
            'PSUseShouldProcessForStateChangingFunctions',
            '',
            Justification = 'This test helper only constructs in-memory stream envelopes.'
        )]
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [Guid] $RunspaceId,

            [AllowNull()]
            [object] $ObservedIdentity
        )

        $failureValue = [pscustomobject][ordered]@{
            Message = 'The compatibility session did not report Windows PowerShell 5.1 Desktop.'
            FailureKind = 'RuntimeMismatch'
            ObservedIdentity = $ObservedIdentity
        }
        $failureEnvelope = New-SshTestEnvelope `
            -RunspaceId $RunspaceId `
            -Sequence 0 `
            -Stream Error `
            -Value $failureValue `
            -IsTerminating $true `
            -DispatchState NotDispatched
        $failureEnvelope.TypeName = 'HostHunter.RuntimeFailure'
        $failureEnvelope
        New-SshTestEnvelope `
            -RunspaceId $RunspaceId `
            -Sequence 1 `
            -Kind Completion `
            -Terminated $true `
            -FailureKind RuntimeMismatch `
            -DispatchState NotDispatched `
            -OutcomeStatus Failed
    }

    function New-SshTestPSSession {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
            'PSUseShouldProcessForStateChangingFunctions',
            '',
            Justification = 'This test helper constructs an unopened in-memory PSSession without network activity.'
        )]
        [CmdletBinding()]
        param([string] $Name = 'unit-session')

        $assembly = [Management.Automation.Runspaces.PSSession].Assembly
        $remoteRunspaceType = $assembly.GetType('System.Management.Automation.RemoteRunspace')
        $flags = [Reflection.BindingFlags]'Instance,Public,NonPublic'
        $remoteConstructor = $remoteRunspaceType.GetConstructors($flags) |
            Where-Object { $_.GetParameters().Count -eq 6 } |
            Select-Object -First 1
        $connection = [Management.Automation.Runspaces.SSHConnectionInfo]::new(
            'example.test',
            'operator',
            $null
        )
        $remoteRunspace = $remoteConstructor.Invoke(
            @($null, $connection, $null, $null, $Name, 1)
        )
        $sessionConstructor = [Management.Automation.Runspaces.PSSession].GetConstructors($flags)[0]
        return $sessionConstructor.Invoke(@($remoteRunspace))
    }

    function New-SshTestRemovalPowerShell {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
            'PSUseShouldProcessForStateChangingFunctions',
            '',
            Justification = 'This test helper constructs an in-memory async worker double.'
        )]
        [CmdletBinding()]
        param([bool] $IsCompleted = $true)

        $signal = [Threading.ManualResetEvent]::new($IsCompleted)
        $worker = [pscustomobject]@{
            Command = $null
            Parameters = [ordered]@{}
            AsyncResult = [pscustomobject]@{ AsyncWaitHandle = $signal }
            Signal = $signal
            BeginInvokeCalls = 0
            EndInvokeCalls = 0
            BeginStopCalls = 0
            DisposeCalls = 0
        }
        $worker | Add-Member -MemberType ScriptMethod -Name AddCommand -Value {
            param($commandName)
            $this.Command = $commandName
            return $this
        }
        $worker | Add-Member -MemberType ScriptMethod -Name AddParameter -Value {
            param($parameterName, $parameterValue)
            $this.Parameters[$parameterName] = $parameterValue
            return $this
        }
        $worker | Add-Member -MemberType ScriptMethod -Name BeginInvoke -Value {
            $this.BeginInvokeCalls++
            return $this.AsyncResult
        }
        $worker | Add-Member -MemberType ScriptMethod -Name EndInvoke -Value {
            param($unusedAsyncResult)
            $null = $unusedAsyncResult
            $this.EndInvokeCalls++
        }
        $worker | Add-Member -MemberType ScriptMethod -Name BeginStop -Value {
            param($unusedCallback, $unusedState)
            $null = $unusedCallback, $unusedState
            $this.BeginStopCalls++
            $this.Signal.Set() | Out-Null
            return [pscustomobject]@{}
        }
        $worker | Add-Member -MemberType ScriptMethod -Name Dispose -Value {
            $this.DisposeCalls++
        }
        return $worker
    }

    $script:testKeyBase64 = [Convert]::ToBase64String(
        [Text.Encoding]::UTF8.GetBytes('ssh-transport-unit-host-key')
    )
    $script:testFingerprint = Get-HHSshPublicKeyFingerprint `
        -PublicKeyLine "ssh-ed25519 $script:testKeyBase64"
}

Describe 'SSH transport trust and planning' -Tag Unit {
    BeforeEach {
        $env:HH_COVERAGE_CASE = [Guid]::NewGuid().ToString('N')
        $script:knownHostsPath = Join-Path $TestDrive "$($env:HH_COVERAGE_CASE)-known_hosts"
    }

    It 'calculates an OpenSSH SHA256 fingerprint and rejects malformed key lines' {
        $script:testFingerprint | Should -Match '^SHA256:[A-Za-z0-9+/]{43}$'
        { Get-HHSshPublicKeyFingerprint -PublicKeyLine 'not-a-key' } |
            Should -Throw '*malformed*'
        { Get-HHSshPublicKeyFingerprint -PublicKeyLine 'ssh-ed25519 %%%' } |
            Should -Throw '*valid base64*'
    }

    It 'reads only matching unique host keys while skipping comments and malformed entries' {
        $otherBlob = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('other-key'))
        Write-SshTestKnownHost -Path $script:knownHostsPath -AdditionalLines @(
            '# comment',
            '',
            'malformed',
            "elsewhere.test ssh-ed25519 $otherBlob",
            "alias.test,EXAMPLE.TEST ssh-ed25519 $script:testKeyBase64"
        ) | Out-Null

        $fingerprints = @(Get-HHSshKnownHostFingerprint `
                -KnownHostsPath $script:knownHostsPath `
                -HostName example.test `
                -Port 22)
        $fingerprints | Should -Be @($script:testFingerprint)
    }

    It 'matches the bracketed host token for a nonstandard port' {
        Write-SshTestKnownHost -Path $script:knownHostsPath -HostToken '[example.test]:2222' | Out-Null
        @(Get-HHSshKnownHostFingerprint `
                -KnownHostsPath $script:knownHostsPath `
                -HostName example.test `
                -Port 2222) | Should -Be @($script:testFingerprint)
    }

    It 'returns no fingerprints for an empty secured known-hosts file' {
        [IO.File]::WriteAllText($script:knownHostsPath, '')
        if (-not $IsWindows) {
            [IO.File]::SetUnixFileMode(
                $script:knownHostsPath,
                [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite
            )
        }

        @(Get-HHSshKnownHostFingerprint `
                -KnownHostsPath $script:knownHostsPath `
                -HostName example.test `
                -Port 22).Count | Should -Be 0
    }

    It 'rejects relative, missing, directory, and symbolic-link known-hosts paths' {
        { Get-HHSshKnownHostFingerprint -KnownHostsPath relative -HostName example.test -Port 22 } |
            Should -Throw '*absolute*'
        { Get-HHSshKnownHostFingerprint -KnownHostsPath $script:knownHostsPath -HostName example.test -Port 22 } |
            Should -Throw '*missing*'

        $directory = Join-Path $TestDrive 'known-hosts-directory'
        [IO.Directory]::CreateDirectory($directory) | Out-Null
        { Get-HHSshKnownHostFingerprint -KnownHostsPath $directory -HostName example.test -Port 22 } |
            Should -Throw '*invalid*'

        if (-not $IsWindows) {
            $realPath = Join-Path $TestDrive 'real-known-hosts'
            Write-SshTestKnownHost -Path $realPath | Out-Null
            [IO.File]::CreateSymbolicLink($script:knownHostsPath, $realPath) | Out-Null
            { Get-HHSshKnownHostFingerprint -KnownHostsPath $script:knownHostsPath `
                    -HostName example.test -Port 22 } | Should -Throw '*symbolic link*'
        }
    }

    It 'rejects a group-writable managed known-hosts file on Unix' -Skip:$IsWindows {
        Write-SshTestKnownHost -Path $script:knownHostsPath | Out-Null
        [IO.File]::SetUnixFileMode(
            $script:knownHostsPath,
            [IO.UnixFileMode]::UserRead -bor
            [IO.UnixFileMode]::UserWrite -bor
            [IO.UnixFileMode]::GroupWrite
        )
        { Get-HHSshKnownHostFingerprint -KnownHostsPath $script:knownHostsPath `
                -HostName example.test -Port 22 } | Should -Throw '*group or others*'
        @(Get-HHSshKnownHostFingerprint `
                -KnownHostsPath $script:knownHostsPath `
                -HostName example.test `
                -Port 22 `
                -IsWindowsPlatform $true) | Should -Be @($script:testFingerprint)
    }

    It 'builds a strict password plan without a credential value' {
        Write-SshTestKnownHost -Path $script:knownHostsPath | Out-Null
        $plan = New-HHSshTransportPlan `
            -Target (New-SshTestTarget) `
            -KnownHostsPath $script:knownHostsPath `
            -ConnectionTimeoutSeconds 9

        $plan.Authentication | Should -BeExactly 'Password'
        $plan.ConnectingTimeoutMilliseconds | Should -Be 9000
        $plan.Options.StrictHostKeyChecking | Should -BeExactly 'yes'
        $plan.Options.GlobalKnownHostsFile | Should -BeExactly 'none'
        $plan.Options.UpdateHostKeys | Should -BeExactly 'no'
        $plan.Options.Contains('UserKnownHostsFile') | Should -BeFalse
        $plan.KnownHostsPath | Should -BeExactly $script:knownHostsPath
        $plan.Options.NumberOfPasswordPrompts | Should -BeExactly '1'
        $plan.Options.PreferredAuthentications | Should -BeExactly 'password'
        $plan.Options.PubkeyAuthentication | Should -BeExactly 'no'
        $plan.PSObject.Properties.Name | Should -Not -Contain 'Credential'
    }

    It 'builds a key-only plan for a regular selected private key' {
        Write-SshTestKnownHost -Path $script:knownHostsPath | Out-Null
        $keyPath = Join-Path $TestDrive 'id_ed25519'
        [IO.File]::WriteAllText($keyPath, 'test-private-key-placeholder')
        if (-not $IsWindows) {
            [IO.File]::SetUnixFileMode(
                $keyPath,
                [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite
            )
        }
        $plan = New-HHSshTransportPlan `
            -Target (New-SshTestTarget -Authentication PublicKey -KeyPath $keyPath) `
            -KnownHostsPath $script:knownHostsPath

        $plan.Authentication | Should -BeExactly 'PublicKey'
        $plan.KeyFilePath | Should -BeExactly $keyPath
        $plan.Options.IdentitiesOnly | Should -BeExactly 'yes'
        $plan.Options.PasswordAuthentication | Should -BeExactly 'no'
        $plan.Options.PreferredAuthentications | Should -BeExactly 'publickey'
    }

    It 'rejects an invalid key path, wrong transport, absent pin, and mismatched pin' {
        Write-SshTestKnownHost -Path $script:knownHostsPath | Out-Null
        $missingKey = Join-Path $TestDrive 'missing-key'
        { New-HHSshTransportPlan `
                -Target (New-SshTestTarget -Authentication PublicKey -KeyPath $missingKey) `
                -KnownHostsPath $script:knownHostsPath } | Should -Throw '*missing or invalid*'

        if (-not $IsWindows) {
            $unsafeKey = Join-Path $TestDrive 'unsafe-key'
            [IO.File]::WriteAllText($unsafeKey, 'placeholder')
            [IO.File]::SetUnixFileMode(
                $unsafeKey,
                [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::OtherRead
            )
            { New-HHSshTransportPlan `
                    -Target (New-SshTestTarget -Authentication PublicKey -KeyPath $unsafeKey) `
                    -KnownHostsPath $script:knownHostsPath } | Should -Throw '*group or others*'
            (New-HHSshTransportPlan `
                    -Target (New-SshTestTarget -Authentication PublicKey -KeyPath $unsafeKey) `
                    -KnownHostsPath $script:knownHostsPath `
                    -IsWindowsPlatform $true).Authentication | Should -BeExactly 'PublicKey'
        }

        { New-HHSshTransportPlan `
                -Target (New-SshTestTarget -Transport WinRM -Authentication Password -Fingerprint $null) `
                -KnownHostsPath $script:knownHostsPath } | Should -Throw '*requires an SSH target*'
        { New-HHSshTransportPlan `
                -Target (New-SshTestTarget -Fingerprint 'incomplete') `
                -KnownHostsPath $script:knownHostsPath } | Should -Throw '*pinned SHA256*'

        $otherFingerprint = Get-HHSshPublicKeyFingerprint -PublicKeyLine (
            'ssh-ed25519 ' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('different'))
        )
        { New-HHSshTransportPlan `
                -Target (New-SshTestTarget -Fingerprint $otherFingerprint) `
                -KnownHostsPath $script:knownHostsPath } | Should -Throw '*does not match*'
    }

    It 'accepts an adversarial literal path through a safe environment token' {
        $pathRoot = Join-Path $TestDrive 'Application Support # `${PATH} "quoted"'
        [IO.Directory]::CreateDirectory($pathRoot) | Out-Null
        $literalPath = Join-Path $pathRoot "known_hosts'file"
        Write-SshTestKnownHost -Path $literalPath | Out-Null
        $plan = New-HHSshTransportPlan `
            -Target (New-SshTestTarget) `
            -KnownHostsPath $literalPath

        $name = 'HH_HH_KNOWN_HOSTS_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
        $binding = Enter-HHSshKnownHostsEnvironment -Plan $plan -VariableName $name
        try {
            $binding.Options.UserKnownHostsFile | Should -BeExactly ('${' + $name + '}')
            [Environment]::GetEnvironmentVariable($name, 'Process') |
                Should -BeExactly ([IO.Path]::GetFullPath($literalPath))
            $binding.Options.GlobalKnownHostsFile | Should -BeExactly 'none'
            $binding.Options.UpdateHostKeys | Should -BeExactly 'no'
        }
        finally {
            Exit-HHSshKnownHostsEnvironment -Binding $binding
        }
        [Environment]::GetEnvironmentVariable($name, 'Process') | Should -BeNullOrEmpty
    }

    It 'restores a preexisting binding and creates distinct concurrent names' {
        Write-SshTestKnownHost -Path $script:knownHostsPath | Out-Null
        $plan = New-HHSshTransportPlan `
            -Target (New-SshTestTarget) `
            -KnownHostsPath $script:knownHostsPath
        $fixedName = 'HH_HH_KNOWN_HOSTS_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'
        [Environment]::SetEnvironmentVariable($fixedName, 'previous-value', 'Process')
        $fixedBinding = Enter-HHSshKnownHostsEnvironment -Plan $plan -VariableName $fixedName
        $first = Enter-HHSshKnownHostsEnvironment -Plan $plan
        $second = Enter-HHSshKnownHostsEnvironment -Plan $plan
        try {
            $first.VariableName | Should -Not -BeExactly $second.VariableName
            $first.Options.UserKnownHostsFile | Should -Not -BeExactly $second.Options.UserKnownHostsFile
            [Environment]::GetEnvironmentVariable($fixedName, 'Process') |
                Should -BeExactly $plan.KnownHostsPath
        }
        finally {
            Exit-HHSshKnownHostsEnvironment -Binding $second
            Exit-HHSshKnownHostsEnvironment -Binding $first
            Exit-HHSshKnownHostsEnvironment -Binding $fixedBinding
        }
        [Environment]::GetEnvironmentVariable($fixedName, 'Process') |
            Should -BeExactly 'previous-value'
        [Environment]::SetEnvironmentVariable($fixedName, $null, 'Process')
    }

    It 'rejects unsafe binding names and control characters in known-hosts paths' {
        $plan = [pscustomobject]@{
            KnownHostsPath = [IO.Path]::Combine([IO.Path]::GetTempPath(), "bad`nknown_hosts")
            Options = @{}
        }
        { Enter-HHSshKnownHostsEnvironment -Plan $plan } |
            Should -Throw '*without control characters*'
        $plan.KnownHostsPath = [IO.Path]::Combine([IO.Path]::GetTempPath(), 'known_hosts')
        { Enter-HHSshKnownHostsEnvironment -Plan $plan -VariableName 'PATH' } |
            Should -Throw '*variable name is invalid*'
    }

    It 'enforces patched PowerShell floors and OpenSSH expansion capability' {
        foreach ($supported in @('7.4.19', '7.5.10', '7.6.5', '7.7.0')) {
            { Assert-HHSshControllerSupported `
                    -PowerShellVersion $supported `
                    -ControllerEdition Core `
                    -SshCapabilityProbe { $true } } | Should -Not -Throw
        }
        foreach ($unsupported in @('7.3.12', '7.4.18', '7.5.9', '7.6.4')) {
            { Assert-HHSshControllerSupported `
                    -PowerShellVersion $unsupported `
                    -ControllerEdition Core `
                    -SshCapabilityProbe { $true } } | Should -Throw '*patched PowerShell*'
        }
        { Assert-HHSshControllerSupported `
                -PowerShellVersion 7.6.5 `
                -ControllerEdition Desktop `
                -SshCapabilityProbe { $true } } | Should -Throw '*patched PowerShell*'
        { Assert-HHSshControllerSupported `
                -PowerShellVersion 7.6.5 `
                -ControllerEdition Core `
                -SshCapabilityProbe { $false } } | Should -Throw '*environment-variable expansion*'
    }

    It 'requires an explicit and exactly supported target runtime before SSH planning' {
        { Get-HHSshRequestedPowerShellRuntime -InputObject ([pscustomobject]@{}) } |
            Should -Throw '*requires an explicit PowerShellRuntime*'
        { Get-HHSshRequestedPowerShellRuntime -InputObject ([pscustomobject]@{
                    PowerShellRuntime = ' '
                }) } | Should -Throw '*requires an explicit PowerShellRuntime*'
        { Get-HHSshRequestedPowerShellRuntime -InputObject ([pscustomobject]@{
                    PowerShellRuntime = 'WindowsPowerShell51'
                }) } | Should -Throw "*Unsupported PowerShell runtime*"
        Get-HHSshRequestedPowerShellRuntime -InputObject ([pscustomobject]@{
                PowerShellRuntime = 'PowerShell7'
            }) | Should -BeExactly PowerShell7
    }

    It 'proves the installed OpenSSH expansion capability and removes its probe binding' {
        $beforeNames = @(Get-ChildItem Env:HH_HH_SSH_CAPABILITY_* -ErrorAction SilentlyContinue |
                ForEach-Object Name)

        { Assert-HHSshControllerSupported `
                -PowerShellVersion 7.6.5 `
                -ControllerEdition Core } | Should -Not -Throw

        @(Get-ChildItem Env:HH_HH_SSH_CAPABILITY_* -ErrorAction SilentlyContinue |
                ForEach-Object Name) | Should -Be $beforeNames
    }

    It 'rejects a controller without an OpenSSH application before connection' {
        Mock Get-Command { $null } -ParameterFilter {
            $Name -ceq 'ssh' -and $CommandType -eq [Management.Automation.CommandTypes]::Application
        }

        { Assert-HHSshControllerSupported `
                -PowerShellVersion 7.6.5 `
                -ControllerEdition Core } | Should -Throw '*environment-variable expansion*'
    }

    It 'binds a safe known-hosts path when no additional SSH options are needed' {
        $name = 'HH_HH_KNOWN_HOSTS_DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD'
        $binding = Enter-HHSshKnownHostsEnvironment -Plan ([pscustomobject]@{
                KnownHostsPath = [IO.Path]::Combine([IO.Path]::GetTempPath(), 'known_hosts')
                Options = @{}
            }) -VariableName $name
        try {
            @($binding.Options.Keys) | Should -Be @('UserKnownHostsFile')
        }
        finally {
            Exit-HHSshKnownHostsEnvironment -Binding $binding
        }
    }
}

Describe 'SSH failure and stream primitives' -Tag Unit {
    BeforeEach {
        $env:HH_COVERAGE_CASE = [Guid]::NewGuid().ToString('N')
    }

    It 'honors explicit classified exceptions before message heuristics' {
        $exception = New-HHSshClassifiedException `
            -FailureKind OutputLimitExceeded `
            -Message 'generic' `
            -InnerException ([Exception]::new('inner'))
        (Get-HHSshFailureKind -ErrorObject $exception) | Should -BeExactly 'OutputLimitExceeded'
        $exception.InnerException.Message | Should -BeExactly 'inner'
    }

    It 'classifies timeout exception types and trust, authentication, subsystem, and output messages' {
        Get-HHSshFailureKind -ErrorObject ([TimeoutException]::new('anything')) |
            Should -BeExactly 'Timeout'
        Get-HHSshFailureKind -ErrorObject ([Exception]::new('Host key verification failed')) |
            Should -BeExactly 'TrustFailure'
        Get-HHSshFailureKind -ErrorObject ([Exception]::new('Permission denied (publickey,password)')) |
            Should -BeExactly 'AuthenticationFailure'
        Get-HHSshFailureKind -ErrorObject ([Exception]::new('PowerShell subsystem request failed')) |
            Should -BeExactly 'SubsystemFailure'
        Get-HHSshFailureKind -ErrorObject ([Exception]::new('requested PowerShell runtime does not match')) |
            Should -BeExactly 'RuntimeMismatch'
        Get-HHSshFailureKind -ErrorObject ([Exception]::new('runtime unavailable')) |
            Should -BeExactly 'RuntimeUnavailable'
        Get-HHSshFailureKind -ErrorObject ([Exception]::new('output limit exceeded')) |
            Should -BeExactly 'OutputLimitExceeded'
        Get-HHSshFailureKind -ErrorObject ([Exception]::new('connection reset')) |
            Should -BeExactly 'TransportFailure'
    }

    It 'classifies nested exception text, error records, non-exceptions, and empty values' {
        $nested = [Exception]::new('outer', [Exception]::new('operation timed out'))
        Get-HHSshFailureKind -ErrorObject $nested | Should -BeExactly 'Timeout'
        $record = [Management.Automation.ErrorRecord]::new(
            [Exception]::new('access denied'),
            'auth',
            [Management.Automation.ErrorCategory]::SecurityError,
            $null
        )
        Get-HHSshFailureKind -ErrorObject $record | Should -BeExactly 'AuthenticationFailure'
        Get-HHSshFailureKind -ErrorObject 'known_hosts mismatch' | Should -BeExactly 'TrustFailure'
        Get-HHSshFailureKind -ErrorObject ([Exception]::new()) | Should -BeExactly 'TransportFailure'
        Get-HHSshFailureKind -ErrorObject ([Exception]::new(' ')) | Should -BeExactly 'TransportFailure'
    }

    It 'classifies a plain non-exception value without walking an exception chain' {
        Get-HHSshFailureKind -ErrorObject 'plain transport disconnect' |
            Should -BeExactly 'TransportFailure'
    }

    It 'types every supported PowerShell stream record and preserves a deterministic timestamp' {
        $records = @(
            [pscustomobject]@{ Expected = 'Error'; Value = [Management.Automation.ErrorRecord]::new(
                    [Exception]::new('error'), 'id',
                    [Management.Automation.ErrorCategory]::NotSpecified, $null) },
            [pscustomobject]@{ Expected = 'Warning'; Value = [Management.Automation.WarningRecord]::new('warning') },
            [pscustomobject]@{ Expected = 'Verbose'; Value = [Management.Automation.VerboseRecord]::new('verbose') },
            [pscustomobject]@{ Expected = 'Debug'; Value = [Management.Automation.DebugRecord]::new('debug') },
            [pscustomobject]@{ Expected = 'Information'; Value = [Management.Automation.InformationRecord]::new('info', 'unit') },
            [pscustomobject]@{ Expected = 'Progress'; Value = [Management.Automation.ProgressRecord]::new(1, 'activity', 'status') },
            [pscustomobject]@{ Expected = 'Output'; Value = 'output' }
        )
        foreach ($record in $records) {
            $eventRecord = New-HHSshStreamEvent `
                -Sequence 2 `
                -Phase Command `
                -InputObject $record.Value `
                -Clock { [DateTimeOffset]::Parse('2026-08-23T12:34:56+10:00') }
            $eventRecord.Stream | Should -BeExactly $record.Expected
            $eventRecord.ObservedAtUtc | Should -BeExactly '2026-08-23T02:34:56.0000000+00:00'
            $eventRecord.SerializedByteCount | Should -BeGreaterThan 0
        }
    }

    It 'supports null values and trusted envelope stream/type metadata' {
        $nullEvent = New-HHSshStreamEvent -Sequence 0 -Phase Command -InputObject $null
        $nullEvent.Stream | Should -BeExactly 'Output'
        $nullEvent.TypeName | Should -BeExactly 'null'

        $eventRecord = New-HHSshStreamEvent `
            -Sequence 1 `
            -Phase Command `
            -InputObject 'serialized warning' `
            -StreamOverride Warning `
            -TypeNameOverride 'System.Management.Automation.WarningRecord' `
            -RemoteSequence 7 `
            -IsTerminating $true
        $eventRecord.Stream | Should -BeExactly 'Warning'
        $eventRecord.RemoteSequence | Should -Be 7
        $eventRecord.IsTerminating | Should -BeTrue
    }

    It 'sums stream bytes and can exclude a local transport event' {
        $first = New-HHSshStreamEvent -Sequence 0 -Phase Command -InputObject 'a'
        $second = New-HHSshStreamEvent -Sequence 1 -Phase Transport -InputObject 'b'
        Get-HHSshStreamEventByteCount -StreamEvents @() | Should -Be 0
        Get-HHSshStreamEventByteCount -StreamEvents @($first, $second) |
            Should -Be ($first.SerializedByteCount + $second.SerializedByteCount)
        Get-HHSshStreamEventByteCount -StreamEvents @($first, $second) -ExcludePhase Transport |
            Should -Be $first.SerializedByteCount
    }

    It 'returns zero without entering aggregation for an empty stream set' {
        Get-HHSshStreamEventByteCount -StreamEvents @() | Should -Be 0
    }

    It 'validates stream-envelope markers and kinds' {
        Test-HHSshStreamEnvelope -InputObject $null | Should -BeFalse
        Test-HHSshStreamEnvelope -InputObject ([pscustomobject]@{ Marker = 'wrong'; Kind = 'Stream' }) |
            Should -BeFalse
        Test-HHSshStreamEnvelope -InputObject ([pscustomobject]@{
                Marker = 'HostHunter.StreamEnvelope.v1'; Kind = 'wrong' }) | Should -BeFalse
        Test-HHSshStreamEnvelope -InputObject ([pscustomobject]@{
                Marker = 'HostHunter.StreamEnvelope.v1'; Kind = 'Completion' }) | Should -BeTrue
    }

    It 'requires complete and internally consistent terminal metadata' {
        $validCompletion = [ordered]@{
            Marker = 'HostHunter.StreamEnvelope.v1'
            Kind = 'Completion'
            Sequence = 0
            Terminated = $false
            FailureKind = $null
            DispatchState = 'Completed'
            OutcomeStatus = 'Succeeded'
        }
        Test-HHSshCompletionEnvelope -InputObject ([pscustomobject] $validCompletion) |
            Should -BeTrue
        Test-HHSshCompletionEnvelope -InputObject $null | Should -BeFalse

        foreach ($requiredProperty in @(
                'Sequence',
                'Terminated',
                'FailureKind',
                'DispatchState',
                'OutcomeStatus'
            )) {
            $missingProperty = [pscustomobject]@{}
            foreach ($propertyName in @($validCompletion.Keys)) {
                if ($propertyName -cne $requiredProperty) {
                    $missingProperty | Add-Member `
                        -NotePropertyName $propertyName `
                        -NotePropertyValue $validCompletion[$propertyName]
                }
            }
            Test-HHSshCompletionEnvelope -InputObject $missingProperty | Should -BeFalse
        }

        $validFailures = @(
            @{ FailureKind = 'RuntimeMismatch'; DispatchState = 'NotDispatched'; OutcomeStatus = 'Failed' },
            @{ FailureKind = 'RuntimeUnavailable'; DispatchState = 'NotDispatched'; OutcomeStatus = 'Failed' },
            @{ FailureKind = 'RemoteCommandFailure'; DispatchState = 'Completed'; OutcomeStatus = 'Failed' },
            @{ FailureKind = 'OutputLimitExceeded'; DispatchState = 'Dispatched'; OutcomeStatus = 'Failed' },
            @{ FailureKind = 'TransportFailure'; DispatchState = 'NotDispatched'; OutcomeStatus = 'Failed' },
            @{ FailureKind = 'TransportFailure'; DispatchState = 'Completed'; OutcomeStatus = 'Failed' },
            @{ FailureKind = 'TransportFailure'; DispatchState = 'Dispatched'; OutcomeStatus = 'Unknown' },
            @{ FailureKind = 'TransportFailure'; DispatchState = 'DispatchUncertain'; OutcomeStatus = 'Unknown' }
        )
        foreach ($failure in $validFailures) {
            Test-HHSshCompletionEnvelope -InputObject ([pscustomobject]@{
                    Marker = 'HostHunter.StreamEnvelope.v1'
                    Kind = 'Completion'
                    Sequence = 0
                    Terminated = $true
                    FailureKind = $failure.FailureKind
                    DispatchState = $failure.DispatchState
                    OutcomeStatus = $failure.OutcomeStatus
                }) | Should -BeTrue
        }

        Test-HHSshCompletionEnvelope -InputObject ([pscustomobject]@{
                Marker = 'HostHunter.StreamEnvelope.v1'
                Kind = 'Completion'
                Sequence = 0
                Terminated = 'false'
                FailureKind = $null
                DispatchState = 'Completed'
                OutcomeStatus = 'Succeeded'
            }) | Should -BeFalse
        Test-HHSshCompletionEnvelope -InputObject ([pscustomobject]@{
                Marker = 'HostHunter.StreamEnvelope.v1'
                Kind = 'Completion'
                Sequence = 0
                Terminated = $true
                FailureKind = 'TransportFailure'
                DispatchState = 'Dispatched'
                OutcomeStatus = 'Failed'
            }) | Should -BeFalse
        Test-HHSshCompletionEnvelope -InputObject ([pscustomobject]@{
                Marker = 'HostHunter.StreamEnvelope.v1'
                Kind = 'Completion'
                Sequence = 0
                Terminated = $true
                FailureKind = 'UnknownFailure'
                DispatchState = 'Completed'
                OutcomeStatus = 'Failed'
            }) | Should -BeFalse
    }

    It 'merges and tags non-terminating streams inside the remote wrapper without truncation' {
        $wrapper = Get-HHSshRemoteEnvelopeScriptBlock
        $serializedArguments = [Management.Automation.PSSerializer]::Serialize(@('arg'), 20)
        $commandText = 'param($value) $value; Write-Error "nonterm" -ErrorAction Continue; ' +
            'Write-Warning "later"; Write-Verbose "verbose" -Verbose; ' +
            'Write-Debug "debug" -Debug; Write-Information "info"; "after"'
        $envelopes = @(& $wrapper `
                -CommandText $commandText `
                -SerializedCommandArguments $serializedArguments)

        @($envelopes | Where-Object Kind -eq Stream | ForEach-Object Stream) |
            Should -Be @('Output', 'Error', 'Warning', 'Verbose', 'Debug', 'Information', 'Output')
        @($envelopes | Where-Object Kind -eq Stream | ForEach-Object Sequence) |
            Should -Be @(0, 1, 2, 3, 4, 5, 6)
        ($envelopes[-1].Kind) | Should -BeExactly 'Completion'
        $envelopes[-1].Terminated | Should -BeFalse
    }

    It 'preserves Output origin when a command writes typed stream-record objects as data' {
        $wrapper = Get-HHSshRemoteEnvelopeScriptBlock
        $serializedArguments = [Management.Automation.PSSerializer]::Serialize(
            [object[]]@(),
            20
        )
        $commandText = {
            $records = @(
                [Management.Automation.ErrorRecord]::new(
                    [Exception]::new('error-data'),
                    'error-data-id',
                    [Management.Automation.ErrorCategory]::NotSpecified,
                    $null
                ),
                [Management.Automation.WarningRecord]::new('warning-data'),
                [Management.Automation.VerboseRecord]::new('verbose-data'),
                [Management.Automation.DebugRecord]::new('debug-data'),
                [Management.Automation.InformationRecord]::new('information-data', 'unit')
            )
            foreach ($record in $records) {
                Write-Output $record
            }
        }.ToString()

        $envelopes = @(& $wrapper `
                -CommandText $commandText `
                -SerializedCommandArguments $serializedArguments)

        @($envelopes | Where-Object Kind -eq Stream | ForEach-Object Stream) |
            Should -Be @('Output', 'Output', 'Output', 'Output', 'Output')
        @($envelopes | Where-Object Kind -eq Stream | ForEach-Object TypeName) |
            Should -Be @(
            'System.Management.Automation.ErrorRecord',
            'System.Management.Automation.WarningRecord',
            'System.Management.Automation.VerboseRecord',
            'System.Management.Automation.DebugRecord',
            'System.Management.Automation.InformationRecord'
        )
    }

    It 'marks a caught terminating remote command and still emits completion' {
        $wrapper = Get-HHSshRemoteEnvelopeScriptBlock
        $envelopes = @(& $wrapper `
                -CommandText '"before"; throw "terminal"; "after"' `
                -SerializedCommandArguments (
                    [Management.Automation.PSSerializer]::Serialize([object[]]@(), 20)
                ))
        @($envelopes | Where-Object Kind -eq Stream).Count | Should -Be 2
        ($envelopes | Where-Object {
                $null -ne $_.PSObject.Properties['IsTerminating'] -and $_.IsTerminating
            }).Stream | Should -BeExactly 'Error'
        $envelopes[-1].Terminated | Should -BeTrue
    }
}

Describe 'SSH identity and captured invocation lifecycle' -Tag Unit {
    BeforeEach {
        $env:HH_COVERAGE_CASE = [Guid]::NewGuid().ToString('N')
        $script:knownHostsPath = Join-Path $TestDrive "$($env:HH_COVERAGE_CASE)-known_hosts"
        Write-SshTestKnownHost -Path $script:knownHostsPath | Out-Null
        $script:removedSessions = 0
    }

    It 'accepts exactly one valid PowerShell 7 identity event' {
        $identity = Get-HHSshValidatedIdentity -StreamEvents @((New-SshTestIdentityEvent))
        $identity.PowerShellVersion | Should -BeExactly '7.6.5'
    }

    It 'rejects absent and duplicate identity markers' {
        { Get-HHSshValidatedIdentity -StreamEvents @() } | Should -Throw '*marker count*'
        $eventRecord = New-SshTestIdentityEvent
        { Get-HHSshValidatedIdentity -StreamEvents @($eventRecord, $eventRecord) } |
            Should -Throw '*marker count*'
    }

    It 'rejects a non-Core identity' {
        { Get-HHSshValidatedIdentity -StreamEvents @(
                (New-SshTestIdentityEvent -Identity (New-SshTestIdentity -Edition Desktop))
            ) } | Should -Throw '*malformed or internally inconsistent*'
    }

    It 'rejects an unparsable or pre-7 PowerShell identity version' {
        $malformedFailure = {
            Get-HHSshValidatedIdentity -StreamEvents @(
                (New-SshTestIdentityEvent -Identity (New-SshTestIdentity -PowerShellVersion invalid))
            )
        }
        $malformedFailure | Should -Throw '*malformed or internally inconsistent*'

        $mismatch = $null
        try {
            Get-HHSshValidatedIdentity -StreamEvents @(
                (New-SshTestIdentityEvent -Identity (New-SshTestIdentity -PowerShellVersion 6.2))
            ) | Out-Null
        }
        catch {
            $mismatch = $_
        }
        (Get-HHSshFailureKind -ErrorObject $mismatch) | Should -BeExactly 'RuntimeMismatch'
        $mismatch.Exception.Data['HHObservedIdentity'].PowerShellVersion |
            Should -BeExactly '6.2'
        $mismatch.Exception.Data['HHObservedProbeRuntime'] |
            Should -BeExactly 'PowerShell7'
    }

    It 'rejects a non-pwsh identity process' {
        { Get-HHSshValidatedIdentity -StreamEvents @(
                (New-SshTestIdentityEvent -Identity (New-SshTestIdentity -ProcessPath '/bin/bash'))
            ) } | Should -Throw '*malformed or internally inconsistent*'
    }

    It 'rejects blank identity user and machine values' {
        { Get-HHSshValidatedIdentity -StreamEvents @(
                (New-SshTestIdentityEvent -Identity (New-SshTestIdentity -UserName ' '))
            ) } | Should -Throw '*malformed or internally inconsistent*'
        { Get-HHSshValidatedIdentity -StreamEvents @(
                (New-SshTestIdentityEvent -Identity (New-SshTestIdentity -MachineName ' '))
            ) } | Should -Throw '*malformed or internally inconsistent*'
    }

    It 'captures injected records in order and stops enumeration at the byte limit' {
        $script:emitted = 0
        $failure = $null
        try {
            Invoke-HHSshRemoteCapture `
                -Session ([pscustomobject]@{}) `
                -ScriptBlock { 'unused' } `
                -Phase Command `
                -MaxOutputBytes 500 `
                -RemoteInvoker {
                    1..100 | ForEach-Object {
                        $script:emitted++
                        'x' * 200
                    }
                } | Out-Null
        }
        catch {
            $failure = $_
        }
        $failure | Should -Not -BeNullOrEmpty
        (Get-HHSshFailureKind -ErrorObject $failure) | Should -BeExactly 'OutputLimitExceeded'
        $script:emitted | Should -BeLessThan 100
        @($failure.Exception.Data['HHStreamEvents']).Count | Should -BeGreaterThan 0
    }

    It 'keeps identity-phase output-limit evidence pre-dispatch' {
        $failure = $null
        try {
            Invoke-HHSshRemoteCapture `
                -Session ([pscustomobject]@{}) `
                -ScriptBlock { 'unused' } `
                -Phase Identity `
                -MaxOutputBytes 1 `
                -RemoteInvoker { 'identity-value-too-large' } | Out-Null
        }
        catch {
            $failure = $_
        }

        $failure | Should -Not -BeNullOrEmpty
        (Get-HHSshFailureKind -ErrorObject $failure) | Should -BeExactly 'OutputLimitExceeded'
        $failure.Exception.Data['HHDispatchState'] | Should -BeExactly 'NotDispatched'
        @($failure.Exception.Data['HHStreamEvents']).Count | Should -Be 0
    }

    It 'opens, probes, and returns a typed validated session context' {
        $plan = New-HHSshTransportPlan -Target (New-SshTestTarget) -KnownHostsPath $script:knownHostsPath
        $script:testSession = [pscustomobject]@{ InstanceId = [Guid]::NewGuid() }
        $context = Open-HHSshValidatedSession `
            -Plan $plan `
            -SessionFactory { $script:testSession } `
            -RemoteInvoker {
                param($unusedSession, $remoteScript, $arguments)
                $null = $unusedSession
                & $remoteScript @arguments
            } `
            -Clock { [DateTimeOffset]::Parse('2026-08-23T01:02:03Z') }

        $context.Session | Should -Be $script:testSession
        $context.RemotePowerShellVersion | Should -BeExactly '7.6.5'
        $context.ValidatedAtUtc | Should -BeExactly '2026-08-23T01:02:03.0000000+00:00'
        $context.HostKeyFingerprint | Should -BeExactly $script:testFingerprint
        $context.OutputBytes | Should -BeGreaterThan 0
    }

    It 'rejects a null session factory result' {
        $plan = New-HHSshTransportPlan -Target (New-SshTestTarget) -KnownHostsPath $script:knownHostsPath
        { Open-HHSshValidatedSession -Plan $plan -SessionFactory { $null } } |
            Should -Throw '*returned no session*'
    }

    It 'closes a session when the mandatory identity probe fails and preserves that failure' {
        $plan = New-HHSshTransportPlan -Target (New-SshTestTarget) -KnownHostsPath $script:knownHostsPath
        { Open-HHSshValidatedSession `
                -Plan $plan `
                -SessionFactory { [pscustomobject]@{ InstanceId = [Guid]::NewGuid() } } `
                -RemoteInvoker { 'not-an-identity' } `
                -SessionRemover { $script:removedSessions++; throw 'cleanup also failed' } } |
            Should -Throw '*identity probe*'
        $script:removedSessions | Should -Be 1
    }

    It 'closes a session successfully after an invalid identity probe' {
        $plan = New-HHSshTransportPlan -Target (New-SshTestTarget) -KnownHostsPath $script:knownHostsPath
        { Open-HHSshValidatedSession `
                -Plan $plan `
                -SessionFactory { [pscustomobject]@{ InstanceId = [Guid]::NewGuid() } } `
                -RemoteInvoker { 'not-an-identity' } `
                -SessionRemover { $script:removedSessions++ } } |
            Should -Throw '*identity probe*'
        $script:removedSessions | Should -Be 1
    }

    It 'uses the public open seam and the injected close seam' {
        $script:testSession = [pscustomobject]@{ InstanceId = [Guid]::NewGuid() }
        $context = Open-HHSshSession `
            -Target (New-SshTestTarget) `
            -KnownHostsPath $script:knownHostsPath `
            -SessionFactory { $script:testSession } `
            -RemoteInvoker {
                param($unusedSession, $remoteScript, $arguments)
                $null = $unusedSession
                & $remoteScript @arguments
            }
        Close-HHSshSession -Session $context.Session -SessionRemover { $script:removedSessions++ }
        $script:removedSessions | Should -Be 1
    }

    It 'asynchronously closes a native outer session before final removal' {
        $session = [pscustomobject]@{ Name = 'outer-session' }
        $script:removalWorker = New-SshTestRemovalPowerShell

        Close-HHSshSession `
            -Session $session `
            -CleanupTimeoutMilliseconds 100 `
            -SessionRemovalPowerShellFactory { $script:removalWorker }

        $script:removalWorker.Command | Should -BeExactly 'Remove-PSSession'
        @($script:removalWorker.Parameters.Session).Count | Should -Be 1
        @($script:removalWorker.Parameters.Session)[0] | Should -Be $session
        $script:removalWorker.Parameters.Confirm | Should -BeFalse
        $script:removalWorker.Parameters.ErrorAction | Should -BeExactly 'Stop'
        $script:removalWorker.BeginInvokeCalls | Should -Be 1
        $script:removalWorker.EndInvokeCalls | Should -Be 1
        $script:removalWorker.BeginStopCalls | Should -Be 0
        $script:removalWorker.DisposeCalls | Should -Be 1
        $script:removalWorker.Signal.Dispose()
    }

    It 'bounds a stalled native outer-session close and skips final removal' {
        $session = [pscustomobject]@{ Name = 'stalled-outer-session' }
        $script:removalWorker = New-SshTestRemovalPowerShell -IsCompleted:$false
        $stopwatch = [Diagnostics.Stopwatch]::StartNew()

        { Close-HHSshSession `
                -Session $session `
                -CleanupTimeoutMilliseconds 25 `
                -SessionRemovalPowerShellFactory { $script:removalWorker } } |
            Should -Throw '*did not close within 25 milliseconds*'

        $stopwatch.Stop()
        $stopwatch.ElapsedMilliseconds | Should -BeLessThan 1000
        $script:removalWorker.BeginInvokeCalls | Should -Be 1
        $script:removalWorker.EndInvokeCalls | Should -Be 0
        $script:removalWorker.BeginStopCalls | Should -Be 1
        $script:removalWorker.DisposeCalls | Should -Be 0
        $script:removalWorker.Signal.Dispose()
    }

    It 'honours cancellation while waiting for a stalled native outer-session close' {
        $session = [pscustomobject]@{ Name = 'cancelled-outer-session' }
        $script:removalWorker = New-SshTestRemovalPowerShell -IsCompleted:$false
        $cancellation = [Threading.CancellationTokenSource]::new()
        $cancellation.CancelAfter(25)
        $stopwatch = [Diagnostics.Stopwatch]::StartNew()

        { Close-HHSshSession `
                -Session $session `
                -CleanupTimeoutMilliseconds 5000 `
                -CancellationToken $cancellation.Token `
                -SessionRemovalPowerShellFactory { $script:removalWorker } } |
            Should -Throw '*SSH session cleanup was cancelled*'

        $stopwatch.Stop()
        $stopwatch.ElapsedMilliseconds | Should -BeLessThan 1000
        $script:removalWorker.BeginInvokeCalls | Should -Be 1
        $script:removalWorker.EndInvokeCalls | Should -Be 0
        $script:removalWorker.BeginStopCalls | Should -Be 1
        $script:removalWorker.DisposeCalls | Should -Be 0
        $script:removalWorker.Signal.Dispose()
        $cancellation.Dispose()
    }

    It 'preserves cancellation when the native stop request itself fails' {
        $script:removalWorker = New-SshTestRemovalPowerShell -IsCompleted:$false
        $script:removalWorker | Add-Member -MemberType ScriptMethod -Name BeginStop -Force -Value {
            param($unusedCallback, $unusedState)
            $null = $unusedCallback, $unusedState
            $this.BeginStopCalls++
            throw 'native cancellation request failed'
        }
        $cancellation = [Threading.CancellationTokenSource]::new()
        $cancellation.Cancel()

        { Close-HHSshSession `
                -Session ([pscustomobject]@{ Name = 'cancel-stop-failure' }) `
                -CleanupTimeoutMilliseconds 100 `
                -CancellationToken $cancellation.Token `
                -SessionRemovalPowerShellFactory { $script:removalWorker } } |
            Should -Throw '*SSH session cleanup was cancelled*'

        $script:removalWorker.BeginStopCalls | Should -Be 2
        $script:removalWorker.EndInvokeCalls | Should -Be 0
        $script:removalWorker.DisposeCalls | Should -Be 0
        $script:removalWorker.Signal.Dispose()
        $cancellation.Dispose()
    }

    It 'preserves timeout when the native stop request itself fails' {
        $script:removalWorker = New-SshTestRemovalPowerShell -IsCompleted:$false
        $script:removalWorker | Add-Member -MemberType ScriptMethod -Name BeginStop -Force -Value {
            param($unusedCallback, $unusedState)
            $null = $unusedCallback, $unusedState
            $this.BeginStopCalls++
            throw 'native timeout stop request failed'
        }

        { Close-HHSshSession `
                -Session ([pscustomobject]@{ Name = 'timeout-stop-failure' }) `
                -CleanupTimeoutMilliseconds 1 `
                -SessionRemovalPowerShellFactory { $script:removalWorker } } |
            Should -Throw '*did not close within 1 milliseconds*'

        $script:removalWorker.BeginStopCalls | Should -Be 2
        $script:removalWorker.EndInvokeCalls | Should -Be 0
        $script:removalWorker.DisposeCalls | Should -Be 0
        $script:removalWorker.Signal.Dispose()
    }

    It 'attempts bounded stop when a native worker returns an invalid wait handle' {
        $script:removalWorker = New-SshTestRemovalPowerShell
        $script:removalWorker.AsyncResult = [pscustomobject]@{
            AsyncWaitHandle = 'not-a-wait-handle'
        }

        { Close-HHSshSession `
                -Session ([pscustomobject]@{ Name = 'invalid-wait-handle' }) `
                -CleanupTimeoutMilliseconds 100 `
                -SessionRemovalPowerShellFactory { $script:removalWorker } } |
            Should -Throw

        $script:removalWorker.BeginStopCalls | Should -Be 1
        $script:removalWorker.EndInvokeCalls | Should -Be 0
        $script:removalWorker.DisposeCalls | Should -Be 0
        $script:removalWorker.Signal.Dispose()
    }

    It 'fails bounded injected and worker cleanup seams without masking their cause' {
        { Close-HHSshSession `
                -Session ([pscustomobject]@{ Name = 'injected-timeout' }) `
                -CleanupTimeoutMilliseconds 17 `
                -SessionRemover { $false } } |
            Should -Throw '*did not close within 17 milliseconds*'

        { Close-HHSshSession -Session ([pscustomobject]@{ Name = 'invalid-native' }) } |
            Should -Throw '*requires a PowerShell PSSession*'

        { Close-HHSshSession `
                -Session ([pscustomobject]@{ Name = 'null-worker' }) `
                -SessionRemovalPowerShellFactory { $null } } |
            Should -Throw '*returned no worker*'

        $script:nullAsyncWorker = New-SshTestRemovalPowerShell
        $script:nullAsyncWorker | Add-Member -MemberType ScriptMethod -Name BeginInvoke -Force -Value {
            $this.BeginInvokeCalls++
            return $null
        }
        { Close-HHSshSession `
                -Session ([pscustomobject]@{ Name = 'null-async' }) `
                -SessionRemovalPowerShellFactory { $script:nullAsyncWorker } } |
            Should -Throw '*returned no asynchronous wait handle*'
        $script:nullAsyncWorker.DisposeCalls | Should -Be 1
        $script:nullAsyncWorker.Signal.Dispose()
    }

    It 'returns identity and command events from an established context' {
        $context = New-SshTestContext
        $result = Invoke-HHSshSessionCommand `
            -SessionContext $context `
            -ScriptBlock { param($value) $value } `
            -ArgumentList @('command-output') `
            -RemoteInvoker {
                param($unusedSession, $remoteScript, $arguments)
                $null = $unusedSession
                & $remoteScript @arguments
            }
        $result.Succeeded | Should -BeTrue
        @($result.StreamEvents | ForEach-Object Phase) | Should -Be @('Identity', 'Command')
        [string] $result.StreamEvents[-1].Value | Should -BeExactly 'command-output'
    }

    It 'fails before invocation when the identity events already consume the limit' {
        $context = New-SshTestContext -OutputBytes 100
        $script:invoked = $false
        $result = Invoke-HHSshSessionCommand `
            -SessionContext $context `
            -ScriptBlock { 'never' } `
            -MaxOutputBytes 100 `
            -RemoteInvoker { $script:invoked = $true }
        $result.Succeeded | Should -BeFalse
        $result.FailureKind | Should -BeExactly 'OutputLimitExceeded'
        $script:invoked | Should -BeFalse
    }

    It 'retains partial command events when streaming exceeds the limit' {
        $context = New-SshTestContext
        $result = Invoke-HHSshSessionCommand `
            -SessionContext $context `
            -ScriptBlock { 'unused' } `
            -MaxOutputBytes ($context.OutputBytes + 600) `
            -RemoteInvoker { 'a'; 'x' * 500; 'never-retained' }
        $result.Succeeded | Should -BeFalse
        $result.FailureKind | Should -BeExactly 'OutputLimitExceeded'
        @($result.StreamEvents | Where-Object Phase -eq Command).Count | Should -BeGreaterThan 0
        $result.OutputBytes | Should -BeLessOrEqual ($context.OutputBytes + 600)
    }

    It 'returns an empty result when a proven context and command produce no stream records' {
        $context = New-SshTestContext
        $context.IdentityEvents = @()
        $context.OutputBytes = 0

        $result = Invoke-HHSshSessionCommand `
            -SessionContext $context `
            -ScriptBlock { 'not-run-by-the-test-seam' } `
            -RemoteInvoker { }

        $result.Succeeded | Should -BeTrue
        @($result.StreamEvents).Count | Should -Be 0
        $result.OutputBytes | Should -Be 0
    }

    It 'handles an invocation failure with an explicitly empty partial-event collection' {
        $context = New-SshTestContext
        $context.IdentityEvents = @()
        $context.OutputBytes = 0

        $result = Invoke-HHSshSessionCommand `
            -SessionContext $context `
            -ScriptBlock { 'unused' } `
            -RemoteInvoker { throw 'failed before any remote stream event' }

        $result.Succeeded | Should -BeFalse
        $result.FailureKind | Should -BeExactly 'TransportFailure'
        @($result.StreamEvents).Count | Should -Be 0
    }
}

Describe 'SSH transport convenience result' -Tag Unit {
    BeforeEach {
        $env:HH_COVERAGE_CASE = [Guid]::NewGuid().ToString('N')
        $script:knownHostsPath = Join-Path $TestDrive "$($env:HH_COVERAGE_CASE)-known_hosts"
        Write-SshTestKnownHost -Path $script:knownHostsPath | Out-Null
        $script:removedSessions = 0
    }

    It 'validates without running a user command and closes the session once' {
        $result = Invoke-HHSshTransport `
            -Target (New-SshTestTarget) `
            -KnownHostsPath $script:knownHostsPath `
            -SessionFactory { [pscustomobject]@{ InstanceId = [Guid]::NewGuid() } } `
            -RemoteInvoker {
                param($unusedSession, $remoteScript, $arguments)
                $null = $unusedSession
                & $remoteScript @arguments
            } `
            -SessionRemover { $script:removedSessions++ }
        $result.Succeeded | Should -BeTrue
        $result.RemotePowerShellVersion | Should -BeExactly '7.6.5'
        $result.StreamEvents.Count | Should -Be 1
        $script:removedSessions | Should -Be 1
    }

    It 'runs a command without retry and preserves ordered events' {
        $script:commandRuns = 0
        $result = Invoke-HHSshTransport `
            -Target (New-SshTestTarget) `
            -KnownHostsPath $script:knownHostsPath `
            -RemoteScriptBlock { $script:commandRuns++; 'done' } `
            -SessionFactory { [pscustomobject]@{ InstanceId = [Guid]::NewGuid() } } `
            -RemoteInvoker {
                param($unusedSession, $remoteScript, $arguments)
                $null = $unusedSession
                & $remoteScript @arguments
            } `
            -SessionRemover { $script:removedSessions++ }
        $result.Succeeded | Should -BeTrue
        @($result.StreamEvents | ForEach-Object Sequence) | Should -Be @(0, 1)
        $script:commandRuns | Should -Be 1
        $script:removedSessions | Should -Be 1
    }

    It 'returns a classified pre-network trust failure' {
        $result = Invoke-HHSshTransport `
            -Target (New-SshTestTarget -Fingerprint 'bad') `
            -KnownHostsPath $script:knownHostsPath `
            -SessionFactory { throw 'must not open' }
        $result.Succeeded | Should -BeFalse
        $result.FailureKind | Should -BeExactly 'TrustFailure'
        $result.HostKeyFingerprint | Should -BeNullOrEmpty
        $result.StreamEvents[-1].Phase | Should -BeExactly 'Transport'
    }


    It 'handles a malformed target object that has no fingerprint property' {
        $result = Invoke-HHSshTransport `
            -Target ([pscustomobject]@{}) `
            -KnownHostsPath $script:knownHostsPath
        $result.Succeeded | Should -BeFalse
        $result.HostKeyFingerprint | Should -BeNullOrEmpty
    }

    It 'returns a finite JSON-safe transport event for a native session-open failure' {
        $nativeFailure = [Management.Automation.Remoting.PSRemotingTransportException]::new(
            'The SSH transport process has abruptly terminated.'
        )
        $result = Invoke-HHSshTransport `
            -Target (New-SshTestTarget) `
            -KnownHostsPath $script:knownHostsPath `
            -SessionFactory { throw $nativeFailure }

        $result.Succeeded | Should -BeFalse
        $result.FailureKind | Should -BeExactly 'TransportFailure'
        $result.StreamEvents[-1].Stream | Should -BeExactly 'Error'
        $result.StreamEvents[-1].Value | Should -BeOfType ([string])
        $result.StreamEvents[-1].TypeName | Should -BeExactly $nativeFailure.GetType().FullName
        $json = $result.StreamEvents[-1] | ConvertTo-Json -Depth 20 -Compress
        $json.Length | Should -BeLessThan 4096
        $json | Should -Match 'abruptly terminated'
    }

    It 'reports cleanup failure without hiding a successful validation result payload' {
        $result = Invoke-HHSshTransport `
            -Target (New-SshTestTarget) `
            -KnownHostsPath $script:knownHostsPath `
            -SessionFactory { [pscustomobject]@{ InstanceId = [Guid]::NewGuid() } } `
            -RemoteInvoker {
                param($unusedSession, $remoteScript, $arguments)
                $null = $unusedSession
                & $remoteScript @arguments
            } `
            -SessionRemover { throw 'remove failed' }
        $result.Succeeded | Should -BeFalse
        $result.FailureKind | Should -BeExactly 'TransportFailure'
        $result.SessionRemovalFailure | Should -BeTrue
        $result.RemotePowerShellVersion | Should -BeExactly '7.6.5'
    }
}

Describe 'SSH bounded session fan-out' -Tag Unit {
    BeforeEach {
        $env:HH_COVERAGE_CASE = [Guid]::NewGuid().ToString('N')
        $script:firstId = [Guid]::NewGuid()
        $script:secondId = [Guid]::NewGuid()
        $script:contexts = [ordered]@{
            alpha = New-SshTestContext -InstanceId $script:firstId
            beta = New-SshTestContext -InstanceId $script:secondId
        }
    }

    It 'maps tagged streams to two targets by proven RunspaceId in one invocation' {
        $script:fanOutCalls = 0
        $script:observedThrottle = 0
        $result = Invoke-HHSshSessionFanOut `
            -SessionContextByName $script:contexts `
            -ScriptBlock { param($value) $value } `
            -ArgumentList @('sent') `
            -ThrottleLimit 2 `
            -FanOutInvoker {
                param($sessions, $wrapper, $arguments, $throttle)
                $script:fanOutCalls++
                $script:observedThrottle = $throttle
                $sessions.Count | Should -Be 2
                $wrapper | Should -BeOfType ([scriptblock])
                $arguments.Count | Should -Be 2
                New-SshTestEnvelope -RunspaceId $script:secondId -Sequence 0 -Value 'beta-output'
                New-SshTestEnvelope -RunspaceId $script:firstId -Sequence 0 -Stream Warning -Value 'alpha-warning'
                New-SshTestEnvelope -RunspaceId $script:secondId -Sequence 1 -Kind Completion
                New-SshTestEnvelope -RunspaceId $script:firstId -Sequence 1 -Kind Completion
            }

        $script:fanOutCalls | Should -Be 1
        $script:observedThrottle | Should -Be 2
        $result.Keys | Should -Be @('alpha', 'beta')
        $result.alpha.Succeeded | Should -BeTrue
        $result.beta.Succeeded | Should -BeTrue
        ($null -eq $result.alpha.FailureKind) | Should -BeTrue
        ($null -eq $result.beta.FailureKind) | Should -BeTrue
        $result.alpha.StreamEvents[-1].Stream | Should -BeExactly 'Warning'
        [string] $result.beta.StreamEvents[-1].Value | Should -BeExactly 'beta-output'
    }

    It 'marks a completed terminating target as a remote command failure' {
        $result = Invoke-HHSshSessionFanOut `
            -SessionContextByName ([ordered]@{ alpha = $script:contexts.alpha }) `
            -ScriptBlock { throw 'bad' } `
            -FanOutInvoker {
                New-SshTestEnvelope `
                    -RunspaceId $script:firstId `
                    -Sequence 0 `
                    -Stream Error `
                    -Value 'bad' `
                    -IsTerminating $true
                New-SshTestEnvelope `
                    -RunspaceId $script:firstId `
                    -Sequence 1 `
                    -Kind Completion `
                    -Terminated $true
            }
        $result.alpha.Succeeded | Should -BeFalse
        $result.alpha.FailureKind | Should -BeExactly 'RemoteCommandFailure'
        $result.alpha.StreamEvents[-1].IsTerminating | Should -BeTrue
    }

    It 'fails closed when an envelope has no proven or known RunspaceId' {
        $result = Invoke-HHSshSessionFanOut `
            -SessionContextByName $script:contexts `
            -ScriptBlock { 'x' } `
            -FanOutInvoker {
                [pscustomobject]@{
                    Marker = 'HostHunter.StreamEnvelope.v1'
                    Kind = 'Stream'
                    Sequence = 0
                }
            }
        $result.alpha.FailureKind | Should -BeExactly 'TransportFailure'
        $result.beta.FailureKind | Should -BeExactly 'TransportFailure'
    }

    It 'fails closed when an injected fan-out invocation returns a non-envelope value' {
        $result = Invoke-HHSshSessionFanOut `
            -SessionContextByName ([ordered]@{ alpha = $script:contexts.alpha }) `
            -ScriptBlock { 'unused' } `
            -FanOutInvoker { 'invalid-envelope' }

        $result.alpha.Succeeded | Should -BeFalse
        $result.alpha.FailureKind | Should -BeExactly 'TransportFailure'
    }

    It 'fails closed on contradictory fan-out completion metadata' {
        $completion = New-SshTestEnvelope `
            -RunspaceId $script:firstId `
            -Sequence 0 `
            -Kind Completion `
            -DispatchState Completed `
            -OutcomeStatus Failed
        $result = Invoke-HHSshSessionFanOut `
            -SessionContextByName ([ordered]@{ alpha = $script:contexts.alpha }) `
            -ScriptBlock { 'unused' } `
            -FanOutInvoker { $completion }

        $result.alpha.Succeeded | Should -BeFalse
        $result.alpha.FailureKind | Should -BeExactly 'TransportFailure'
        $result.alpha.DispatchState | Should -BeExactly 'DispatchUncertain'
        $result.alpha.OutcomeStatus | Should -BeExactly 'Unknown'
    }

    It 'accepts a validated context whose identity events were consumed by its caller' {
        $context = New-SshTestContext -InstanceId $script:firstId
        $context.IdentityEvents = @()
        $context.OutputBytes = 0
        $result = Invoke-HHSshSessionFanOut `
            -SessionContextByName ([ordered]@{ alpha = $context }) `
            -ScriptBlock { 'unused' } `
            -FanOutInvoker {
                New-SshTestEnvelope `
                    -RunspaceId $script:firstId `
                    -Sequence 0 `
                    -Kind Completion
            }

        $result.alpha.Succeeded | Should -BeTrue
        @($result.alpha.StreamEvents).Count | Should -Be 0
        $result.alpha.OutputBytes | Should -Be 0
    }

    It 'fails closed on out-of-order data, invalid stream kinds, and post-completion data' {
        $outOfOrder = Invoke-HHSshSessionFanOut `
            -SessionContextByName ([ordered]@{ alpha = $script:contexts.alpha }) `
            -ScriptBlock { 'x' } `
            -FanOutInvoker { New-SshTestEnvelope -RunspaceId $script:firstId -Sequence 2 }
        $outOfOrder.alpha.FailureKind | Should -BeExactly 'TransportFailure'

        $invalidStream = Invoke-HHSshSessionFanOut `
            -SessionContextByName ([ordered]@{ alpha = $script:contexts.alpha }) `
            -ScriptBlock { 'x' } `
            -FanOutInvoker {
                $item = New-SshTestEnvelope -RunspaceId $script:firstId
                $item.Stream = 'invalid'
                $item
            }
        $invalidStream.alpha.FailureKind | Should -BeExactly 'TransportFailure'

        $postCompletion = Invoke-HHSshSessionFanOut `
            -SessionContextByName ([ordered]@{ alpha = $script:contexts.alpha }) `
            -ScriptBlock { 'x' } `
            -FanOutInvoker {
                New-SshTestEnvelope -RunspaceId $script:firstId -Sequence 0 -Kind Completion
                New-SshTestEnvelope -RunspaceId $script:firstId -Sequence 1
            }
        $postCompletion.alpha.FailureKind | Should -BeExactly 'TransportFailure'
    }

    It 'stops the shared pipeline when one target exceeds its cap and does not blame peers' {
        $cap = $script:contexts.alpha.OutputBytes + 600
        $script:generated = 0
        $result = Invoke-HHSshSessionFanOut `
            -SessionContextByName $script:contexts `
            -ScriptBlock { 'x' } `
            -MaxOutputBytes $cap `
            -FanOutInvoker {
                1..100 | ForEach-Object {
                    $script:generated++
                    New-SshTestEnvelope `
                        -RunspaceId $script:firstId `
                        -Sequence ($_ - 1) `
                        -Value ('x' * 300)
                }
            }
        $result.alpha.FailureKind | Should -BeExactly 'OutputLimitExceeded'
        $result.beta.FailureKind | Should -BeExactly 'TransportFailure'
        $script:generated | Should -BeLessThan 100
        $result.alpha.OutputBytes | Should -BeLessOrEqual $cap
    }

    It 'keeps a peer successful when its completion was observed before another target exceeded its cap' {
        $cap = $script:contexts.alpha.OutputBytes + 500
        $result = Invoke-HHSshSessionFanOut `
            -SessionContextByName $script:contexts `
            -ScriptBlock { 'x' } `
            -MaxOutputBytes $cap `
            -FanOutInvoker {
                New-SshTestEnvelope -RunspaceId $script:secondId -Sequence 0 -Value 'done'
                New-SshTestEnvelope -RunspaceId $script:secondId -Sequence 1 -Kind Completion
                New-SshTestEnvelope -RunspaceId $script:firstId -Sequence 0 -Value ('x' * 1000)
            }
        $result.alpha.FailureKind | Should -BeExactly 'OutputLimitExceeded'
        $result.beta.Succeeded | Should -BeTrue
    }

    It 'classifies a shared timeout for every incomplete target' {
        $result = Invoke-HHSshSessionFanOut `
            -SessionContextByName $script:contexts `
            -ScriptBlock { 'x' } `
            -FanOutInvoker { throw [TimeoutException]::new('timed out') }
        $result.alpha.FailureKind | Should -BeExactly 'Timeout'
        $result.beta.FailureKind | Should -BeExactly 'Timeout'
    }

    It 'rejects empty, oversized, malformed, and duplicate session context sets' {
        { Invoke-HHSshSessionFanOut -SessionContextByName @{} -ScriptBlock { 'x' } } |
            Should -Throw '*between one and eight*'

        $tooMany = [ordered]@{}
        1..9 | ForEach-Object { $tooMany["target$_"] = New-SshTestContext }
        { Invoke-HHSshSessionFanOut -SessionContextByName $tooMany -ScriptBlock { 'x' } } |
            Should -Throw '*between one and eight*'

        { Invoke-HHSshSessionFanOut `
                -SessionContextByName ([ordered]@{ alpha = [pscustomobject]@{} }) `
                -ScriptBlock { 'x' } } | Should -Throw '*requires a name and session context*'

        $badIdContext = [pscustomobject]@{
            Session = [pscustomobject]@{ InstanceId = 'not-a-guid' }
            IdentityEvents = @()
        }
        { Invoke-HHSshSessionFanOut `
                -SessionContextByName ([ordered]@{ alpha = $badIdContext }) `
                -ScriptBlock { 'x' } } | Should -Throw '*valid InstanceId*'

        $duplicate = [ordered]@{
            alpha = New-SshTestContext -InstanceId $script:firstId
            beta = New-SshTestContext -InstanceId $script:firstId
        }
        { Invoke-HHSshSessionFanOut -SessionContextByName $duplicate -ScriptBlock { 'x' } } |
            Should -Throw '*must be unique*'
    }

    It 'does not invoke a session whose identity output already reaches the cap' {
        $context = New-SshTestContext
        $context.OutputBytes = $context.IdentityEvents[0].SerializedByteCount
        $script:invoked = $false
        $result = Invoke-HHSshSessionFanOut `
            -SessionContextByName ([ordered]@{ alpha = $context }) `
            -ScriptBlock { 'x' } `
            -MaxOutputBytes $context.OutputBytes `
            -FanOutInvoker { $script:invoked = $true }
        $result.alpha.FailureKind | Should -BeExactly 'OutputLimitExceeded'
        $script:invoked | Should -BeFalse
    }

    It 'observes each attributed event before returning the retained result' {
        $script:observed = [Collections.Generic.List[string]]::new()
        $result = Invoke-HHSshSessionFanOut `
            -SessionContextByName ([ordered]@{ alpha = $script:contexts.alpha }) `
            -ScriptBlock { 'x' } `
            -EventObserver {
                param($TargetName, $EventRecord)
                $script:observed.Add("${TargetName}:$($EventRecord.Sequence):$($EventRecord.Stream)")
            } `
            -FanOutInvoker {
                New-SshTestEnvelope -RunspaceId $script:firstId -Sequence 0 -Value one
                New-SshTestEnvelope -RunspaceId $script:firstId -Sequence 1 -Stream Warning -Value two
                New-SshTestEnvelope -RunspaceId $script:firstId -Sequence 2 -Kind Completion
            }
        $result.alpha.Succeeded | Should -BeTrue
        $script:observed | Should -Be @('alpha:1:Output', 'alpha:2:Warning')
    }

    It 'bounds aggregate retained evidence across otherwise valid target contexts' {
        $aggregateIdentityBytes = $script:contexts.alpha.OutputBytes +
            $script:contexts.beta.OutputBytes
        {
            Invoke-HHSshSessionFanOut -SessionContextByName $script:contexts `
                -ScriptBlock { 'x' } `
                -MaxAggregateOutputBytes ($aggregateIdentityBytes - 1) `
                -FanOutInvoker { throw 'must not run' }
        } | Should -Throw '*aggregate controller output limit*'
    }
}

Describe 'SSH native command seams' -Tag Unit {
    BeforeEach {
        $env:HH_COVERAGE_CASE = [Guid]::NewGuid().ToString('N')
        $script:knownHostsPath = Join-Path $TestDrive "$($env:HH_COVERAGE_CASE)-known_hosts"
        Write-SshTestKnownHost -Path $script:knownHostsPath | Out-Null
        $script:nativeSession = New-SshTestPSSession
    }

    It 'executes the native envelope capture path and unwraps all supported serialized streams' {
        Mock Invoke-Command {
            [pscustomobject]@{
                Marker = 'HostHunter.StreamEnvelope.v1'
                Kind = 'Stream'
                Sequence = 0
                Stream = 'Verbose'
                TypeName = 'System.Management.Automation.VerboseRecord'
                IsTerminating = $false
                Value = 'verbose'
            }
            [pscustomobject]@{
                Marker = 'HostHunter.StreamEnvelope.v1'
                Kind = 'Stream'
                Sequence = 1
                Stream = 'Debug'
                TypeName = 'System.Management.Automation.DebugRecord'
                IsTerminating = $false
                Value = 'debug'
            }
            [pscustomobject]@{
                Marker = 'HostHunter.StreamEnvelope.v1'
                Kind = 'Stream'
                Sequence = 2
                Stream = 'Information'
                TypeName = 'System.Management.Automation.InformationRecord'
                IsTerminating = $false
                Value = $null
            }
            [pscustomobject]@{
                Marker = 'HostHunter.StreamEnvelope.v1'
                Kind = 'Completion'
                Sequence = 3
                Terminated = $false
                FailureKind = $null
                DispatchState = 'Completed'
                OutcomeStatus = 'Succeeded'
            }
        }

        $events = @(Invoke-HHSshRemoteCapture `
                -Session $script:nativeSession `
                -ScriptBlock { param($one, $two) "$one-$two" } `
                -ArgumentList @('one', 'two') `
                -Phase Command)
        @($events | ForEach-Object Stream) | Should -Be @('Verbose', 'Debug', 'Information')
        $events[-1].TypeName | Should -BeExactly 'System.Management.Automation.InformationRecord'
        $events[-1].Value | Should -BeNullOrEmpty
        Should -Invoke Invoke-Command -Times 1 -Exactly -ParameterFilter {
            $ArgumentList.Count -eq 2 -and $ErrorAction -eq 'Stop'
        }
    }

    It 'fails closed on invalid native envelopes, invalid streams, and missing completion' {
        Mock Invoke-Command { 'not-an-envelope' }
        { Invoke-HHSshRemoteCapture `
                -Session $script:nativeSession `
                -ScriptBlock { 'x' } `
                -Phase Command } | Should -Throw '*invalid envelope*'

        Mock Invoke-Command {
            [pscustomobject]@{
                Marker = 'HostHunter.StreamEnvelope.v1'
                Kind = 'Stream'
                Sequence = 0
                Stream = 'invalid'
            }
        }
        { Invoke-HHSshRemoteCapture `
                -Session $script:nativeSession `
                -ScriptBlock { 'x' } `
                -Phase Command } | Should -Throw '*invalid stream kind*'

        Mock Invoke-Command { @() }
        { Invoke-HHSshRemoteCapture `
                -Session $script:nativeSession `
                -ScriptBlock { 'x' } `
            -Phase Command } | Should -Throw '*exactly one completion*'
    }

    It 'rejects invalid per-stream dispatch metadata before retaining command evidence' {
        Mock Invoke-Command {
            [pscustomobject]@{
                Marker = 'HostHunter.StreamEnvelope.v1'
                Kind = 'Stream'
                Sequence = 0
                Stream = 'Output'
                TypeName = 'System.String'
                IsTerminating = $false
                Value = 'untrusted'
                DispatchState = 'Completed'
            }
        }
        { Invoke-HHSshRemoteCapture `
                -Session $script:nativeSession `
                -ScriptBlock { 'x' } `
                -Phase Command } | Should -Throw '*invalid stream dispatch metadata*'
    }

    It 'assigns finite fallback dispatch and outcome evidence to invocation faults' {
        $identityFailure = $null
        try {
            Invoke-HHSshRemoteCapture `
                -Session $script:nativeSession `
                -ScriptBlock { 'identity' } `
                -Phase Identity `
                -RemoteInvoker { throw [IO.IOException]::new('identity disconnected') }
        }
        catch { $identityFailure = $_ }
        $identityFailure.Exception.Data['HHDispatchState'] | Should -BeExactly NotDispatched
        $identityFailure.Exception.Data['HHOutcomeStatus'] | Should -BeExactly Failed

        $commandFailure = $null
        try {
            Invoke-HHSshRemoteCapture `
                -Session $script:nativeSession `
                -ScriptBlock { 'command' } `
                -Phase Command `
                -RemoteInvoker { throw [IO.IOException]::new('command disconnected') }
        }
        catch { $commandFailure = $_ }
        $commandFailure.Exception.Data['HHDispatchState'] | Should -BeExactly DispatchUncertain
        $commandFailure.Exception.Data['HHOutcomeStatus'] | Should -BeExactly Unknown

        $limitFailure = $null
        try {
            Invoke-HHSshRemoteCapture `
                -Session $script:nativeSession `
                -ScriptBlock { 'limited' } `
                -Phase Command `
                -RemoteInvoker {
                    throw (New-HHSshClassifiedException `
                            -FailureKind OutputLimitExceeded `
                            -Message 'synthetic output cap')
                }
        }
        catch { $limitFailure = $_ }
        $limitFailure.Exception.Data['HHOutcomeStatus'] | Should -BeExactly Failed
    }

    It 'rejects out-of-order native data and any record after completion' {
        Mock Invoke-Command {
            [pscustomobject]@{
                Marker = 'HostHunter.StreamEnvelope.v1'; Kind = 'Completion'; Sequence = 1
                Terminated = $false
                FailureKind = $null; DispatchState = 'Completed'; OutcomeStatus = 'Succeeded'
            }
        }
        { Invoke-HHSshRemoteCapture `
                -Session $script:nativeSession `
                -ScriptBlock { 'x' } `
                -Phase Command } | Should -Throw '*out-of-order completion*'

        Mock Invoke-Command {
            [pscustomobject]@{
                Marker = 'HostHunter.StreamEnvelope.v1'; Kind = 'Stream'; Sequence = 1
                Stream = 'Output'; TypeName = 'System.String'; IsTerminating = $false; Value = 'late'
            }
        }
        { Invoke-HHSshRemoteCapture `
                -Session $script:nativeSession `
                -ScriptBlock { 'x' } `
                -Phase Command } | Should -Throw '*out-of-order stream*'

        Mock Invoke-Command {
            [pscustomobject]@{
                Marker = 'HostHunter.StreamEnvelope.v1'; Kind = 'Completion'; Sequence = 0
                Terminated = $false
                FailureKind = $null; DispatchState = 'Completed'; OutcomeStatus = 'Succeeded'
            }
            [pscustomobject]@{
                Marker = 'HostHunter.StreamEnvelope.v1'; Kind = 'Stream'; Sequence = 0
                Stream = 'Output'; TypeName = 'System.String'; IsTerminating = $false; Value = 'late'
            }
        }
        { Invoke-HHSshRemoteCapture `
                -Session $script:nativeSession `
                -ScriptBlock { 'x' } `
                -Phase Command } | Should -Throw '*data after completion*'

        Mock Invoke-Command {
            [pscustomobject]@{
                Marker = 'HostHunter.StreamEnvelope.v1'; Kind = 'Completion'; Sequence = 0
                Terminated = $false; FailureKind = $null
                DispatchState = 'invalid'; OutcomeStatus = 'Succeeded'
            }
        }
        { Invoke-HHSshRemoteCapture `
                -Session $script:nativeSession `
                -ScriptBlock { 'x' } `
                -Phase Command } | Should -Throw '*invalid completion metadata*'
    }

    It 'retains native partial envelopes when invocation fails and marks remote termination' {
        Mock Invoke-Command {
            [pscustomobject]@{
                Marker = 'HostHunter.StreamEnvelope.v1'
                Kind = 'Stream'
                Sequence = 0
                Stream = 'Error'
                TypeName = 'System.Management.Automation.ErrorRecord'
                IsTerminating = $true
                Value = 'terminal'
            }
            [pscustomobject]@{
                Marker = 'HostHunter.StreamEnvelope.v1'
                Kind = 'Completion'
                Sequence = 1
                Terminated = $true
                FailureKind = 'RemoteCommandFailure'
                DispatchState = 'Completed'
                OutcomeStatus = 'Failed'
            }
        }
        $failure = $null
        try {
            Invoke-HHSshRemoteCapture `
                -Session $script:nativeSession `
                -ScriptBlock { throw 'terminal' } `
                -Phase Command | Out-Null
        }
        catch {
            $failure = $_
        }
        Get-HHSshFailureKind -ErrorObject $failure | Should -BeExactly 'RemoteCommandFailure'
        @($failure.Exception.Data['HHStreamEvents']).Count | Should -Be 1

        Mock Invoke-Command { throw 'native invocation failed' }
        $failure = $null
        try {
            Invoke-HHSshRemoteCapture `
                -Session $script:nativeSession `
                -ScriptBlock { 'x' } `
                -Phase Command | Out-Null
        }
        catch {
            $failure = $_
        }
        $failure.Exception.Data.Contains('HHStreamEvents') | Should -BeTrue
        $failure.Exception.Data['HHOutputBytes'] | Should -Be 0
    }

    It 'uses native New-PSSession and Remove-PSSession for password sessions' {
        $identity = New-SshTestIdentity
        $script:observedKnownHostsVariable = $null
        $script:observedKnownHostsPath = $null
        Mock New-PSSession {
            $script:observedKnownHostsVariable = [regex]::Match(
                [string] $Options.UserKnownHostsFile,
                '^\$\{(?<name>HH_HH_KNOWN_HOSTS_[A-F0-9]{32})\}$'
            ).Groups['name'].Value
            $script:observedKnownHostsPath = [Environment]::GetEnvironmentVariable(
                $script:observedKnownHostsVariable,
                'Process'
            )
            $script:nativeSession
        }
        Mock Invoke-Command {
            [pscustomobject]@{
                Marker = 'HostHunter.StreamEnvelope.v1'
                Kind = 'Stream'
                Sequence = 0
                Stream = 'Output'
                TypeName = 'System.Management.Automation.PSCustomObject'
                IsTerminating = $false
                Value = $identity
            }
            [pscustomobject]@{
                Marker = 'HostHunter.StreamEnvelope.v1'
                Kind = 'Completion'
                Sequence = 1
                Terminated = $false
                FailureKind = $null
                DispatchState = 'Completed'
                OutcomeStatus = 'Succeeded'
            }
        }
        $plan = New-HHSshTransportPlan -Target (New-SshTestTarget) -KnownHostsPath $script:knownHostsPath
        $context = Open-HHSshValidatedSession `
            -Plan $plan `
            -ControllerPowerShellVersion 7.6.5 `
            -SshCapabilityProbe { $true }
        $context.RemotePowerShellVersion | Should -BeExactly '7.6.5'
        $script:observedKnownHostsPath | Should -BeExactly $plan.KnownHostsPath
        [Environment]::GetEnvironmentVariable($script:observedKnownHostsVariable, 'Process') |
            Should -BeNullOrEmpty
        Close-HHSshSession -Session $context.Session
        $context.Session.State | Should -BeExactly 'Closed'
        Should -Invoke New-PSSession -Times 1 -Exactly -ParameterFilter {
            $HostName -eq 'example.test' -and
            $Port -eq 22 -and
            $UserName -eq 'operator' -and
            $SSHTransport -and
            $null -eq $KeyFilePath -and
            $Options.GlobalKnownHostsFile -ceq 'none' -and
            $Options.UpdateHostKeys -ceq 'no' -and
            $Options.UserKnownHostsFile -match '^\$\{HH_HH_KNOWN_HOSTS_[A-F0-9]{32}\}$'
        }
    }

    It 'removes the temporary known-hosts binding when native session creation fails' {
        $variableName = 'HH_HH_KNOWN_HOSTS_CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC'
        $script:failureObservedPath = $null
        Mock New-PSSession {
            $script:failureObservedPath = [Environment]::GetEnvironmentVariable(
                $variableName,
                'Process'
            )
            throw [IO.IOException]::new('native open failed')
        }
        $plan = New-HHSshTransportPlan `
            -Target (New-SshTestTarget) `
            -KnownHostsPath $script:knownHostsPath

        { Open-HHSshValidatedSession `
                -Plan $plan `
                -ControllerPowerShellVersion 7.6.5 `
                -SshCapabilityProbe { $true } `
                -EnvironmentVariableNameFactory { $variableName } } |
            Should -Throw '*native open failed*'

        $script:failureObservedPath | Should -BeExactly $plan.KnownHostsPath
        [Environment]::GetEnvironmentVariable($variableName, 'Process') | Should -BeNullOrEmpty
    }

    It 'passes KeyFilePath to native New-PSSession for a key-only plan' {
        $keyPath = Join-Path $TestDrive 'native-id-ed25519'
        [IO.File]::WriteAllText($keyPath, 'placeholder')
        if (-not $IsWindows) {
            [IO.File]::SetUnixFileMode(
                $keyPath,
                [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite
            )
        }
        Mock New-PSSession { $script:nativeSession }
        Mock Invoke-Command {
            $identity = New-SshTestIdentity
            [pscustomobject]@{
                Marker = 'HostHunter.StreamEnvelope.v1'; Kind = 'Stream'; Sequence = 0
                Stream = 'Output'; TypeName = $identity.GetType().FullName
                IsTerminating = $false; Value = $identity
            }
            [pscustomobject]@{
                Marker = 'HostHunter.StreamEnvelope.v1'; Kind = 'Completion'; Sequence = 1
                Terminated = $false
                FailureKind = $null; DispatchState = 'Completed'; OutcomeStatus = 'Succeeded'
            }
        }

        $plan = New-HHSshTransportPlan `
            -Target (New-SshTestTarget -Authentication PublicKey -KeyPath $keyPath) `
            -KnownHostsPath $script:knownHostsPath
        $context = Open-HHSshValidatedSession `
            -Plan $plan `
            -ControllerPowerShellVersion 7.6.5 `
            -SshCapabilityProbe { $true }
        $context.Session | Should -Be $script:nativeSession
        Should -Invoke New-PSSession -Times 1 -Exactly -ParameterFilter {
            $KeyFilePath -eq $keyPath
        }
    }

    It 'uses one native Invoke-Command call for fan-out' {
        $firstSession = New-SshTestPSSession -Name alpha
        $secondSession = New-SshTestPSSession -Name beta
        $firstId = $firstSession.InstanceId
        $secondId = $secondSession.InstanceId
        $contexts = [ordered]@{
            alpha = New-SshTestContext -InstanceId $firstId
            beta = New-SshTestContext -InstanceId $secondId
        }
        $contexts.alpha.Session = $firstSession
        $contexts.beta.Session = $secondSession
        Mock Invoke-Command {
            New-SshTestEnvelope -RunspaceId $firstId -Sequence 0 -Value 'alpha'
            New-SshTestEnvelope -RunspaceId $secondId -Sequence 0 -Value 'beta'
            New-SshTestEnvelope -RunspaceId $firstId -Sequence 1 -Kind Completion
            New-SshTestEnvelope -RunspaceId $secondId -Sequence 1 -Kind Completion
        }

        $result = Invoke-HHSshSessionFanOut `
            -SessionContextByName $contexts `
            -ScriptBlock { 'x' } `
            -ThrottleLimit 2
        $result.alpha.Succeeded | Should -BeTrue
        $result.beta.Succeeded | Should -BeTrue
        Should -Invoke Invoke-Command -Times 1 -Exactly -ParameterFilter {
            $Session.Count -eq 2 -and $ThrottleLimit -eq 2
        }
    }

    It 'fails every result on an unattributable fan-out protocol object' {
        Mock Invoke-Command { 'invalid' }
        $contexts = [ordered]@{ alpha = New-SshTestContext }
        $result = Invoke-HHSshSessionFanOut `
            -SessionContextByName $contexts `
            -ScriptBlock { 'x' }
        $result.alpha.FailureKind | Should -BeExactly 'TransportFailure'
    }

    It 'marks a missing fan-out completion as a local transport failure' {
        $contexts = [ordered]@{ alpha = New-SshTestContext }
        $result = Invoke-HHSshSessionFanOut `
            -SessionContextByName $contexts `
            -ScriptBlock { 'x' } `
            -FanOutInvoker { @() }
        $result.alpha.FailureKind | Should -BeExactly 'TransportFailure'
        $result.alpha.ExceptionType | Should -BeExactly ([InvalidOperationException].FullName)
    }

    It 'exercises defensive authentication validation after target normalization' {
        Mock ConvertTo-HHValidatedTargetRecord {
            [pscustomobject]@{
                Name = 'alpha'; Transport = 'SSH'; HostName = 'example.test'; Port = 22
                UserName = 'operator'; Authentication = 'Kerberos'
                HostKeyFingerprint = $script:testFingerprint; KeyPath = $null; IsActive = $true
                LastValidatedAtUtc = '2026-08-23T00:00:00.0000000Z'
                LastValidatedPowerShellVersion = '7.6.5'
            }
        }
        { New-HHSshTransportPlan `
                -Target ([pscustomobject]@{}) `
                -KnownHostsPath $script:knownHostsPath } | Should -Throw '*Password or PublicKey*'
    }

    It 'retains partial command output in the convenience transport failure result' {
        $script:capturePhase = 0
        $result = Invoke-HHSshTransport `
            -Target (New-SshTestTarget) `
            -KnownHostsPath $script:knownHostsPath `
            -RemoteScriptBlock { 'command' } `
            -MaxOutputBytes 5000 `
            -SessionFactory { $script:nativeSession } `
            -RemoteInvoker {
                param($unusedSession, $remoteScript, $arguments)
                $null = $unusedSession
                $script:capturePhase++
                if ($script:capturePhase -eq 1) {
                    New-SshTestIdentity
                }
                else {
                    & $remoteScript @arguments
                    'x' * 10000
                }
            } `
            -SessionRemover { throw 'cleanup after failure' }
        $result.Succeeded | Should -BeFalse
        $result.FailureKind | Should -BeExactly 'OutputLimitExceeded'
        $result.ValidatedAtUtc | Should -Not -BeNullOrEmpty
        $result.RemotePowerShellVersion | Should -BeExactly '7.6.5'
        $result.HostKeyFingerprint | Should -BeExactly $script:testFingerprint
        @($result.StreamEvents | Where-Object Phase -eq Command).Count | Should -BeGreaterThan 0
        $result.SessionRemovalFailure | Should -BeTrue
    }

    It 'retains partial events attached to an opening failure' {
        $partialEvent = New-HHSshStreamEvent `
            -Sequence 9 `
            -Phase Identity `
            -InputObject 'partial-identity-output'
        $script:factoryFailure = New-HHSshClassifiedException `
            -FailureKind TransportFailure `
            -Message 'open failed after partial output'
        $script:factoryFailure.Data['HHStreamEvents'] = [object[]] @($partialEvent)

        $result = Invoke-HHSshTransport `
            -Target (New-SshTestTarget) `
            -KnownHostsPath $script:knownHostsPath `
            -SessionFactory { throw $script:factoryFailure }
        $result.Succeeded | Should -BeFalse
        $result.StreamEvents[0].Sequence | Should -Be 0
        [string] $result.StreamEvents[0].Value | Should -BeExactly 'partial-identity-output'
    }

    It 'handles an opening failure with an explicitly empty partial-event collection' {
        $script:factoryFailure = New-HHSshClassifiedException `
            -FailureKind TransportFailure `
            -Message 'open failed before identity output'
        $script:factoryFailure.Data['HHStreamEvents'] = [object[]] @()

        $result = Invoke-HHSshTransport `
            -Target (New-SshTestTarget) `
            -KnownHostsPath $script:knownHostsPath `
            -SessionFactory { throw $script:factoryFailure }

        $result.Succeeded | Should -BeFalse
        $result.FailureKind | Should -BeExactly 'TransportFailure'
        @($result.StreamEvents).Count | Should -Be 1
        $result.StreamEvents[0].Phase | Should -BeExactly 'Transport'
    }
}
