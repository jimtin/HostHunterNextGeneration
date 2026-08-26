BeforeAll {
    $sourceRoot = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
        Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration'
    }
    else {
        $env:HH_TEST_SOURCE_ROOT
    }
    . (Join-Path $sourceRoot 'Private/TargetModel.ps1')
    . (Join-Path $sourceRoot 'Private/SshTransport.ps1')
    . (Join-Path $sourceRoot 'Private/RemoteOperationManifest.ps1')
    . (Join-Path $sourceRoot 'Private/Accountability.ps1')
    . (Join-Path $sourceRoot 'Private/SshKeyBootstrap.ps1')

    $script:keyBlob = [Convert]::ToBase64String(
        [Text.Encoding]::UTF8.GetBytes('hosthunter-bootstrap-public-key')
    )
    $script:otherKeyBlob = [Convert]::ToBase64String(
        [Text.Encoding]::UTF8.GetBytes('hosthunter-bootstrap-other-key')
    )
    $script:hostKeyBlob = [Convert]::ToBase64String(
        [Text.Encoding]::UTF8.GetBytes('hosthunter-bootstrap-host-key')
    )
    $script:hostFingerprint = Get-HHSshPublicKeyFingerprint `
        -PublicKeyLine "ssh-ed25519 $script:hostKeyBlob"

    function New-HHBootstrapTestTarget {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
            'PSUseShouldProcessForStateChangingFunctions',
            '',
            Justification = 'This test helper constructs an in-memory target only.'
        )]
        param(
            [ValidateSet('SSH', 'WinRM')]
            [string] $Transport = 'SSH',

            [ValidateSet('Password', 'PublicKey', 'Kerberos', 'Certificate')]
            [string] $Authentication = 'Password',

            [ValidateSet('PowerShell7', 'WindowsPowerShell51')]
            [string] $PowerShellRuntime = 'PowerShell7',

            [string] $KeyPath
        )

        $parameters = @{
            Name = 'bootstrap-node'
            Transport = $Transport
            HostName = 'bootstrap.test'
            Port = if ($Transport -eq 'SSH') { 22 } else { 5985 }
            UserName = 'operator'
            Authentication = $Authentication
            PowerShellRuntime = $PowerShellRuntime
            HostKeyFingerprint = if ($Transport -eq 'SSH') { $script:hostFingerprint } else { $null }
            KeyPath = $KeyPath
            IsActive = $true
            LastValidatedAtUtc = '2026-08-23T00:00:00.0000000Z'
            LastValidatedPSEdition = if ($PowerShellRuntime -ceq 'WindowsPowerShell51') {
                'Desktop'
            }
            else {
                'Core'
            }
            LastValidatedPowerShellVersion = if ($PowerShellRuntime -ceq 'WindowsPowerShell51') {
                '5.1.26100.9168'
            }
            else {
                '7.6.5'
            }
            LastValidatedExecutionMode = if ($PowerShellRuntime -ceq 'WindowsPowerShell51') {
                'WindowsPowerShellCompatibility'
            }
            else {
                'Direct'
            }
        }
        New-HHTargetRecord @parameters
    }

    function Write-HHBootstrapTestKnownHostFile {
        param([Parameter(Mandatory)][string] $Path)

        [IO.File]::WriteAllText(
            $Path,
            "bootstrap.test ssh-ed25519 $script:hostKeyBlob`n",
            [Text.UTF8Encoding]::new($false)
        )
        if (-not $IsWindows) {
            [IO.File]::SetUnixFileMode(
                $Path,
                [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite
            )
        }
    }

    function Write-HHBootstrapTestKeyPair {
        param(
            [Parameter(Mandatory)][string] $Path,
            [string] $Blob = $script:keyBlob
        )

        [IO.File]::WriteAllText($Path, 'test-private-key', [Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText(
            "$Path.pub",
            "ssh-ed25519 $Blob ignored-comment`n",
            [Text.UTF8Encoding]::new($false)
        )
        if (-not $IsWindows) {
            [IO.File]::SetUnixFileMode(
                $Path,
                [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite
            )
        }
    }

    function New-HHBootstrapIdentity {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
            'PSUseShouldProcessForStateChangingFunctions',
            '',
            Justification = 'This test helper constructs an in-memory identity only.'
        )]
        [CmdletBinding()]
        param(
            [ValidateSet('PowerShell7', 'WindowsPowerShell51')]
            [string] $PowerShellRuntime = 'PowerShell7'
        )

        $isWindowsPowerShell = $PowerShellRuntime -ceq 'WindowsPowerShell51'

        [pscustomobject][ordered]@{
            Marker = 'HostHunter.PowerShellIdentity.v1'
            PSEdition = if ($isWindowsPowerShell) { 'Desktop' } else { 'Core' }
            PowerShellVersion = if ($isWindowsPowerShell) { '5.1.26100.9168' } else { '7.6.5' }
            ProcessPath = if ($isWindowsPowerShell) {
                'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
            }
            else {
                '/opt/microsoft/powershell/7/pwsh'
            }
            UserName = 'operator'
            MachineName = 'bootstrap-node'
        }
    }

    function New-HHBootstrapEnvelope {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
            'PSUseShouldProcessForStateChangingFunctions',
            '',
            Justification = 'This test helper constructs an in-memory transport envelope only.'
        )]
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [ValidateSet('Stream', 'Completion')]
            [string] $Kind,

            [Parameter(Mandatory)]
            [int] $Sequence,

            [AllowNull()]
            [object] $Value
        )

        [pscustomobject][ordered]@{
            Marker = 'HostHunter.StreamEnvelope.v1'
            Kind = $Kind
            Sequence = $Sequence
            Stream = if ($Kind -ceq 'Stream') { 'Output' } else { $null }
            TypeName = if ($null -eq $Value) { 'null' } else { $Value.GetType().FullName }
            IsTerminating = $false
            Value = $Value
            Terminated = $false
            FailureKind = $null
            DispatchState = if ($Kind -ceq 'Completion') { 'Completed' } else { $null }
            OutcomeStatus = if ($Kind -ceq 'Completion') { 'Succeeded' } else { $null }
        }
    }

    function Invoke-HHBootstrapInstallLocally {
        param(
            [Parameter(Mandatory)][string] $HomePath,
            [Parameter(Mandatory)][string] $ExactLine,
            [Parameter(Mandatory)][string] $Marker
        )

        $installer = Get-HHSshAuthorizedKeyInstallScriptBlock
        & {
            param($ScopedHome, $InstallerScript, $Line, $LineMarker)
            Set-Variable -Name HOME -Value $ScopedHome -Force
            & $InstallerScript $Line $LineMarker
        } $HomePath $installer $ExactLine $Marker
    }

    function Invoke-HHBootstrapRollbackLocally {
        param(
            [Parameter(Mandatory)][string] $HomePath,
            [Parameter(Mandatory)][string] $ExactLine
        )

        $rollback = Get-HHSshAuthorizedKeyRollbackScriptBlock
        & {
            param($ScopedHome, $RollbackScript, $Line)
            Set-Variable -Name HOME -Value $ScopedHome -Force
            & $RollbackScript $Line
        } $HomePath $rollback $ExactLine
    }

    function Invoke-HHBootstrapReconciliationLocally {
        param(
            [Parameter(Mandatory)][string] $HomePath,
            [Parameter(Mandatory)][string] $ExactLine
        )

        $reconcile = Get-HHSshAuthorizedKeyReconciliationScriptBlock
        & {
            param($ScopedHome, $ReconcileScript, $Line)
            Set-Variable -Name HOME -Value $ScopedHome -Force
            & $ReconcileScript $Line
        } $HomePath $reconcile $ExactLine
    }
}

Describe 'SSH Ed25519 key bootstrap' -Tag Unit {
    BeforeEach {
        $env:HH_COVERAGE_CASE = [Guid]::NewGuid().ToString('N')
        $env:HH_TEST_CHMOD_CALLS = $null
        $env:HH_TEST_KEY_BLOB = $null
        $script:caseRoot = Join-Path $TestDrive $env:HH_COVERAGE_CASE
        [IO.Directory]::CreateDirectory($script:caseRoot) | Out-Null
        $script:knownHostsPath = Join-Path $script:caseRoot 'known_hosts'
        $script:keyPath = Join-Path $script:caseRoot 'id_ed25519'
        Write-HHBootstrapTestKnownHostFile -Path $script:knownHostsPath
        $script:passwordTarget = New-HHBootstrapTestTarget
        $script:fixedClock = { [DateTimeOffset] '2026-08-23T01:02:03Z' }
    }

    AfterEach {
        $env:HH_TEST_CHMOD_CALLS = $null
        $env:HH_TEST_KEY_BLOB = $null
    }

    It 'constructs a password-to-public-key plan without mutating the key path' {
        $plan = New-HHSshKeyBootstrapPlan `
            -Target $script:passwordTarget `
            -KnownHostsPath $script:knownHostsPath `
            -KeyPath $script:keyPath

        $plan.PSObject.TypeNames[0] | Should -Be 'HostHunter.SshKeyBootstrapPlan'
        $plan.Target.Authentication | Should -Be 'Password'
        $plan.KeyAction | Should -Be 'GenerateDedicatedEd25519Key'
        $plan.PasswordTransportPlan.Options.StrictHostKeyChecking | Should -Be 'yes'
        Test-Path -LiteralPath $script:keyPath | Should -BeFalse

        $existingPlan = New-HHSshKeyBootstrapPlan `
            -Target $script:passwordTarget `
            -KnownHostsPath $script:knownHostsPath `
            -KeyPath $script:keyPath `
            -UseExistingKey
        $existingPlan.KeyAction | Should -Be 'UseExistingEd25519Key'
    }

    It 'rejects non-password targets and relative key paths before bootstrap' {
        $publicTarget = New-HHBootstrapTestTarget `
            -Authentication PublicKey `
            -KeyPath $script:keyPath
        { New-HHSshKeyBootstrapPlan -Target $publicTarget `
                -KnownHostsPath $script:knownHostsPath -KeyPath $script:keyPath } |
            Should -Throw '*requires an SSH target using Password*'

        $winRmTarget = New-HHBootstrapTestTarget -Transport WinRM -Authentication Kerberos
        { New-HHSshKeyBootstrapPlan -Target $winRmTarget `
                -KnownHostsPath $script:knownHostsPath -KeyPath $script:keyPath } |
            Should -Throw '*requires an SSH target using Password*'

        { New-HHSshKeyBootstrapPlan -Target $script:passwordTarget `
                -KnownHostsPath $script:knownHostsPath -KeyPath 'relative-key' } |
            Should -Throw '*must be absolute*'
    }

    It 'returns a complete WhatIf plan without generating a key or opening a session' {
        $script:keyGenerationCalls = 0
        $script:sessionCalls = 0
        $result = Invoke-HHSshKeyBootstrap `
            -Target $script:passwordTarget `
            -KnownHostsPath $script:knownHostsPath `
            -KeyPath $script:keyPath `
            -KeyGenerator { $script:keyGenerationCalls++ } `
            -SessionFactory { $script:sessionCalls++; throw 'must not connect' } `
            -WhatIf

        $result.Succeeded | Should -BeTrue
        $result.Planned | Should -BeTrue
        $result.ProfileTransition | Should -BeNullOrEmpty
        $result.Installed | Should -BeFalse
        $result.RollbackAttempted | Should -BeFalse
        $result.RollbackSucceeded | Should -BeNullOrEmpty
        $result.ReconciliationRequired | Should -BeFalse
        $result.CommitState | Should -BeExactly 'NotRequested'
        $result.StreamEvents | Should -BeNullOrEmpty
        $result.Plan.KeyAction | Should -Be 'GenerateDedicatedEd25519Key'
        $script:keyGenerationCalls | Should -Be 0
        $script:sessionCalls | Should -Be 0
        Test-Path -LiteralPath $script:keyPath | Should -BeFalse
    }

    It 'prepares exact key material and a strict non-secret remote-operation manifest' {
        $prepared = Prepare-HHSshKeyBootstrapOperation `
            -Target $script:passwordTarget `
            -KnownHostsPath $script:knownHostsPath `
            -KeyPath $script:keyPath `
            -KeyGenerator { param($path) Write-HHBootstrapTestKeyPair -Path $path } `
            -Confirm:$false

        $prepared.PSObject.TypeNames[0] |
            Should -BeExactly 'HostHunter.SshKeyBootstrapPreparedOperation'
        $prepared.LocalGenerationOccurred | Should -BeTrue
        $prepared.KeyMaterial.ExactLine |
            Should -BeExactly "ssh-ed25519 $script:keyBlob $($prepared.KeyMaterial.Marker)"
        @($prepared.RemoteOperations.Phase) | Should -Be @(
            'OuterIdentity',
            'BootstrapInstall',
            'BootstrapKeyOnlyOuterIdentity',
            'BootstrapReconcile',
            'BootstrapRollback'
        )
        foreach ($operation in $prepared.RemoteOperations) {
            @($operation.PSObject.Properties.Name) | Should -Be @(
                'Phase',
                'PowerShellRuntime',
                'ScriptText',
                'SerializedArguments',
                'Conditional'
            )
        }
        {
            ConvertTo-HHCanonicalRemoteOperationManifest `
                -RemoteOperations @($prepared.RemoteOperations)
        } | Should -Not -Throw
        $manifestJson = $prepared.RemoteOperations | ConvertTo-Json -Depth 20
        $manifestJson | Should -Not -Match 'test-private-key'
        $manifestJson | Should -Not -Match '(?i)password|passphrase'
    }

    It 'keeps preparation WhatIf non-mutating and can undo only generated material' {
        $script:keyGenerationCalls = 0
        $planned = Prepare-HHSshKeyBootstrapOperation `
            -Target $script:passwordTarget `
            -KnownHostsPath $script:knownHostsPath `
            -KeyPath $script:keyPath `
            -KeyGenerator { $script:keyGenerationCalls++ } `
            -WhatIf
        $planned.Planned | Should -BeTrue
        $planned.KeyMaterial | Should -BeNullOrEmpty
        $script:keyGenerationCalls | Should -Be 0

        $prepared = Prepare-HHSshKeyBootstrapOperation `
            -Target $script:passwordTarget `
            -KnownHostsPath $script:knownHostsPath `
            -KeyPath $script:keyPath `
            -KeyGenerator { param($path) Write-HHBootstrapTestKeyPair -Path $path } `
            -Confirm:$false
        $undo = Undo-HHSshKeyBootstrapPreparation `
            -PreparedOperation $prepared `
            -Confirm:$false
        $undo.Attempted | Should -BeTrue
        $undo.Removed | Should -BeTrue
        Test-Path -LiteralPath $script:keyPath | Should -BeFalse

        Write-HHBootstrapTestKeyPair -Path $script:keyPath
        $existing = Prepare-HHSshKeyBootstrapOperation `
            -Target $script:passwordTarget `
            -KnownHostsPath $script:knownHostsPath `
            -KeyPath $script:keyPath `
            -UseExistingKey `
            -Confirm:$false
        $existingUndo = Undo-HHSshKeyBootstrapPreparation `
            -PreparedOperation $existing `
            -Confirm:$false
        $existingUndo.Attempted | Should -BeFalse
        Test-Path -LiteralPath $script:keyPath | Should -BeTrue
    }

    It 'cleans exact generated material when preparation validation fails' {
        {
            Prepare-HHSshKeyBootstrapOperation `
                -Target $script:passwordTarget `
                -KnownHostsPath $script:knownHostsPath `
                -KeyPath $script:keyPath `
                -KeyGenerator { param($path) Write-HHBootstrapTestKeyPair -Path $path } `
                -PublicKeyReader { 'not-an-ed25519-key' } `
                -Confirm:$false
        } | Should -Throw '*requires an Ed25519 public key*'
        Test-Path -LiteralPath $script:keyPath | Should -BeFalse
        Test-Path -LiteralPath "$script:keyPath.pub" | Should -BeFalse
    }

    It 'preserves a selected existing key when preparation validation fails' {
        Write-HHBootstrapTestKeyPair -Path $script:keyPath
        $script:keyRemovalAttempted = $false

        { Prepare-HHSshKeyBootstrapOperation `
                -Target $script:passwordTarget `
                -KnownHostsPath $script:knownHostsPath `
                -KeyPath $script:keyPath `
                -UseExistingKey `
                -PublicKeyReader { 'not-an-ed25519-key' } `
                -KeyRemover { $script:keyRemovalAttempted = $true } `
                -Confirm:$false } |
            Should -Throw '*requires an Ed25519 public key*'

        $script:keyRemovalAttempted | Should -BeFalse
        Test-Path -LiteralPath $script:keyPath | Should -BeTrue
        Test-Path -LiteralPath "$script:keyPath.pub" | Should -BeTrue
    }

    It 'records finite preparation-cleanup failure evidence and returns finite undo failure' {
        $caught = $null
        try {
            Prepare-HHSshKeyBootstrapOperation `
                -Target $script:passwordTarget `
                -KnownHostsPath $script:knownHostsPath `
                -KeyPath $script:keyPath `
                -KeyGenerator { param($path) Write-HHBootstrapTestKeyPair -Path $path } `
                -PublicKeyReader { 'not-an-ed25519-key' } `
                -KeyRemover { throw 'exact preparation cleanup failed' } `
                -Confirm:$false
        }
        catch {
            $caught = $_
        }
        $caught | Should -Not -BeNullOrEmpty
        $caught.Exception.Data['HHLocalKeyCleanupFailureType'] |
            Should -BeExactly 'System.Management.Automation.RuntimeException'

        $prepared = Prepare-HHSshKeyBootstrapOperation `
            -Target $script:passwordTarget `
            -KnownHostsPath $script:knownHostsPath `
            -KeyPath $script:keyPath `
            -UseExistingKey `
            -PublicKeyReader { "ssh-ed25519 $script:keyBlob" } `
            -Confirm:$false
        $prepared.LocalGenerationOccurred = $true
        $undo = Undo-HHSshKeyBootstrapPreparation `
            -PreparedOperation $prepared `
            -KeyRemover { throw 'exact undo failed' } `
            -Confirm:$false
        $undo.Attempted | Should -BeTrue
        $undo.Removed | Should -BeFalse
        $undo.FailureType | Should -BeExactly 'System.Management.Automation.RuntimeException'
    }

    It 'rejects malformed, inconsistent, and plan-only prepared operations' {
        { Assert-HHSshKeyBootstrapPreparedOperation -PreparedOperation ([pscustomobject]@{}) } |
            Should -Throw '*prepared operation is invalid*'

        $prepared = Prepare-HHSshKeyBootstrapOperation `
            -Target $script:passwordTarget `
            -KnownHostsPath $script:knownHostsPath `
            -KeyPath $script:keyPath `
            -KeyGenerator { param($path) Write-HHBootstrapTestKeyPair -Path $path } `
            -Confirm:$false
        $invalidMaterial = $prepared.PSObject.Copy()
        $invalidMaterial.KeyMaterial = $null
        { Assert-HHSshKeyBootstrapPreparedOperation -PreparedOperation $invalidMaterial } |
            Should -Throw '*prepared key material is invalid*'

        $inconsistent = $prepared.PSObject.Copy()
        $inconsistent.KeyMaterial = $prepared.KeyMaterial.PSObject.Copy()
        $inconsistent.KeyMaterial.Fingerprint = 'SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
        { Assert-HHSshKeyBootstrapPreparedOperation -PreparedOperation $inconsistent } |
            Should -Throw '*prepared key material is inconsistent*'

        $planOnly = Prepare-HHSshKeyBootstrapOperation `
            -Target $script:passwordTarget `
            -KnownHostsPath $script:knownHostsPath `
            -KeyPath (Join-Path $script:caseRoot 'plan-only-key') `
            -WhatIf
        { Invoke-HHSshKeyBootstrap -PreparedOperation $planOnly -Confirm:$false } |
            Should -Throw '*plan-only SSH key-bootstrap preparation cannot be executed*'
    }

    It 'normalizes an Ed25519 public key to an exact HostHunter marker line' {
        Write-HHBootstrapTestKeyPair -Path $script:keyPath
        $material = Get-HHSshBootstrapPublicKey -KeyPath $script:keyPath

        $material.Fingerprint | Should -Match '^SHA256:[A-Za-z0-9+/]+$'
        $material.Marker | Should -Be (
            'hosthunter-ng:{0}' -f $material.Fingerprint.Substring('SHA256:'.Length)
        )
        $material.ExactLine | Should -Be "ssh-ed25519 $script:keyBlob $($material.Marker)"
        $material.ExactLine | Should -Not -Match 'ignored-comment'
    }

    It 'supports an injected public-key reader without accepting another key type' {
        [IO.File]::WriteAllText($script:keyPath, 'private')
        $material = Get-HHSshBootstrapPublicKey `
            -KeyPath $script:keyPath `
            -PublicKeyReader { "ssh-ed25519 $script:keyBlob injected-comment" }
        $material.ExactLine | Should -Match '^ssh-ed25519 .+ hosthunter-ng:'

        { Get-HHSshBootstrapPublicKey -KeyPath $script:keyPath `
                -PublicKeyReader { "ssh-rsa $script:keyBlob" } } |
            Should -Throw '*requires an Ed25519 public key*'
    }

    It 'rejects missing, linked, multiline, and malformed public-key files' {
        [IO.File]::WriteAllText($script:keyPath, 'private')
        { Get-HHSshBootstrapPublicKey -KeyPath $script:keyPath } |
            Should -Throw '*missing or invalid*'

        $linkedPublicPath = Join-Path $script:caseRoot 'linked.pub'
        [IO.File]::WriteAllText($linkedPublicPath, "ssh-ed25519 $script:keyBlob")
        New-Item -ItemType SymbolicLink -Path "$script:keyPath.pub" -Target $linkedPublicPath | Out-Null
        { Get-HHSshBootstrapPublicKey -KeyPath $script:keyPath } |
            Should -Throw '*missing or invalid*'
        Remove-Item -LiteralPath "$script:keyPath.pub" -Force

        [IO.File]::WriteAllLines(
            "$script:keyPath.pub",
            [string[]] @("ssh-ed25519 $script:keyBlob", "ssh-ed25519 $script:otherKeyBlob")
        )
        { Get-HHSshBootstrapPublicKey -KeyPath $script:keyPath } |
            Should -Throw '*exactly one key line*'

        [IO.File]::WriteAllText("$script:keyPath.pub", 'not-a-key')
        { Get-HHSshBootstrapPublicKey -KeyPath $script:keyPath } |
            Should -Throw '*requires an Ed25519 public key*'
    }

    It 'refuses default generation when either exact key-pair path already exists' {
        [IO.File]::WriteAllText($script:keyPath, 'existing')
        { Invoke-HHSshDefaultKeyGenerator -KeyPath $script:keyPath -Comment test } |
            Should -Throw '*refuses to overwrite*'

        [IO.File]::Delete($script:keyPath)
        [IO.File]::WriteAllText("$script:keyPath.pub", 'existing')
        { Invoke-HHSshDefaultKeyGenerator -KeyPath $script:keyPath -Comment test } |
            Should -Throw '*refuses to overwrite*'
    }

    It 'creates and secures a new key directory when the native generator succeeds' -Skip:$IsWindows {
        Mock ssh-keygen {
            $arguments = [object[]] $args
            $keyPathIndex = [Array]::IndexOf($arguments, '-f')
            $generatedPath = [string] $arguments[$keyPathIndex + 1]
            [IO.File]::WriteAllText($generatedPath, 'generated-private-key')
            [IO.File]::WriteAllText(
                "$generatedPath.pub",
                "ssh-ed25519 $script:keyBlob generated"
            )
            [IO.File]::SetUnixFileMode(
                $generatedPath,
                [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite
            )
            $global:LASTEXITCODE = 0
        }
        Invoke-HHSshDefaultKeyGenerator -KeyPath $script:keyPath -Comment dedicated

        Test-Path -LiteralPath $script:keyPath | Should -BeTrue
        Test-Path -LiteralPath "$script:keyPath.pub" | Should -BeTrue
        [IO.File]::GetUnixFileMode((Split-Path -Parent $script:keyPath)) | Should -Be (
            [IO.UnixFileMode]::UserRead -bor
            [IO.UnixFileMode]::UserWrite -bor
            [IO.UnixFileMode]::UserExecute
        )
    }

    It 'fails default generation when the native generator does not create a complete pair' {
        Mock ssh-keygen {
            $global:LASTEXITCODE = 9
        }
        { Invoke-HHSshDefaultKeyGenerator -KeyPath $script:keyPath -Comment dedicated } |
            Should -Throw '*Interactive Ed25519 key generation failed*'
        Test-Path -LiteralPath $script:keyPath | Should -BeFalse
        Test-Path -LiteralPath "$script:keyPath.pub" | Should -BeFalse
    }

    It 'removes only the exact local generated key pair' {
        Write-HHBootstrapTestKeyPair -Path $script:keyPath
        $unrelated = Join-Path $script:caseRoot 'keep-me'
        [IO.File]::WriteAllText($unrelated, 'keep')

        Remove-HHSshGeneratedKey -KeyPath $script:keyPath

        Test-Path -LiteralPath $script:keyPath | Should -BeFalse
        Test-Path -LiteralPath "$script:keyPath.pub" | Should -BeFalse
        [IO.File]::ReadAllText($unrelated) | Should -Be 'keep'
    }

    It 'treats absent exact generated-key paths as an idempotent rollback' {
        { Remove-HHSshGeneratedKey -KeyPath $script:keyPath } | Should -Not -Throw
        Test-Path -LiteralPath $script:keyPath | Should -BeFalse
        Test-Path -LiteralPath "$script:keyPath.pub" | Should -BeFalse
    }

    It 'delegates exact local key removal to the injected rollback seam' {
        $script:removedPath = $null
        Remove-HHSshGeneratedKey `
            -KeyPath $script:keyPath `
            -KeyRemover { param($path) $script:removedPath = $path }
        $script:removedPath | Should -Be $script:keyPath
    }

    It 'installs the exact line, is idempotent, and secures Unix permissions' -Skip:$IsWindows {
        $material = Get-HHSshBootstrapPublicKey `
            -KeyPath $script:keyPath `
            -PublicKeyReader { "ssh-ed25519 $script:keyBlob" }
        $unrelated = "ssh-ed25519 $script:otherKeyBlob unrelated"
        $sshDirectory = Join-Path $script:caseRoot '.ssh'
        [IO.Directory]::CreateDirectory($sshDirectory) | Out-Null
        [IO.File]::WriteAllText((Join-Path $sshDirectory 'authorized_keys'), "$unrelated`n")

        $first = Invoke-HHBootstrapInstallLocally `
            -HomePath $script:caseRoot `
            -ExactLine $material.ExactLine `
            -Marker $material.Marker
        $second = Invoke-HHBootstrapInstallLocally `
            -HomePath $script:caseRoot `
            -ExactLine $material.ExactLine `
            -Marker $material.Marker

        $first.Operation | Should -Be 'HostHunterAuthorizedKeyInstall.v1'
        $first.Added | Should -BeTrue
        $second.Added | Should -BeFalse
        $lines = @([IO.File]::ReadAllLines($first.AuthorizedKeysPath))
        $lines | Should -Be @($unrelated, $material.ExactLine)
        @($lines | Where-Object { $_ -ceq $material.ExactLine }).Count | Should -Be 1
        [IO.File]::GetUnixFileMode($sshDirectory) | Should -Be (
            [IO.UnixFileMode]::UserRead -bor
            [IO.UnixFileMode]::UserWrite -bor
            [IO.UnixFileMode]::UserExecute
        )
        [IO.File]::GetUnixFileMode($first.AuthorizedKeysPath) | Should -Be (
            [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite
        )
    }

    It 'creates a missing authorized_keys file before installing the exact line' -Skip:$IsWindows {
        $material = Get-HHSshBootstrapPublicKey `
            -KeyPath $script:keyPath `
            -PublicKeyReader { "ssh-ed25519 $script:keyBlob" }

        $result = Invoke-HHBootstrapInstallLocally `
            -HomePath $script:caseRoot `
            -ExactLine $material.ExactLine `
            -Marker $material.Marker

        $result.Added | Should -BeTrue
        @([IO.File]::ReadAllLines($result.AuthorizedKeysPath)) | Should -Be @($material.ExactLine)
    }

    It 'deletes the temporary file when securing it fails before installation' -Skip:$IsWindows {
        $material = Get-HHSshBootstrapPublicKey `
            -KeyPath $script:keyPath `
            -PublicKeyReader { "ssh-ed25519 $script:keyBlob" }
        Mock chmod {
            $global:LASTEXITCODE = 1
        }
        { Invoke-HHBootstrapInstallLocally `
                -HomePath $script:caseRoot `
                -ExactLine $material.ExactLine `
                -Marker $material.Marker } |
            Should -Throw '*secure the temporary authorized_keys file*'

        $sshDirectory = Join-Path $script:caseRoot '.ssh'
        @(Get-ChildItem -LiteralPath $sshDirectory -Force -Filter '*.tmp').Count | Should -Be 0
        $authorizedKeysContents = [IO.File]::ReadAllText((Join-Path $sshDirectory 'authorized_keys'))
        $authorizedKeysContents.Length | Should -Be 0
    }

    It 'fails closed when final Unix authorized_keys permissions cannot be applied' -Skip:$IsWindows {
        $material = Get-HHSshBootstrapPublicKey `
            -KeyPath $script:keyPath `
            -PublicKeyReader { "ssh-ed25519 $script:keyBlob" }
        $env:HH_TEST_CHMOD_CALLS = '0'
        Mock chmod {
            $nextCall = [int] $env:HH_TEST_CHMOD_CALLS + 1
            $env:HH_TEST_CHMOD_CALLS = [string] $nextCall
            $global:LASTEXITCODE = if ($nextCall -eq 2) { 1 } else { 0 }
        }
        { Invoke-HHBootstrapInstallLocally `
                -HomePath $script:caseRoot `
                -ExactLine $material.ExactLine `
                -Marker $material.Marker } |
            Should -Throw '*secure the Unix authorized_keys path*'

        $authorizedKeysPath = Join-Path $script:caseRoot '.ssh/authorized_keys'
        @([IO.File]::ReadAllLines($authorizedKeysPath)) | Should -Be @($material.ExactLine)
    }

    It 'fails closed when the HostHunter marker belongs to another exact line' -Skip:$IsWindows {
        $material = Get-HHSshBootstrapPublicKey `
            -KeyPath $script:keyPath `
            -PublicKeyReader { "ssh-ed25519 $script:keyBlob" }
        $sshDirectory = Join-Path $script:caseRoot '.ssh'
        [IO.Directory]::CreateDirectory($sshDirectory) | Out-Null
        $collision = "ssh-ed25519 $script:otherKeyBlob $($material.Marker)"
        $authorizedKeysPath = Join-Path $sshDirectory 'authorized_keys'
        [IO.File]::WriteAllText($authorizedKeysPath, "$collision`n")

        { Invoke-HHBootstrapInstallLocally `
                -HomePath $script:caseRoot `
                -ExactLine $material.ExactLine `
                -Marker $material.Marker } |
            Should -Throw '*marker already belongs to a different key line*'
        @([IO.File]::ReadAllLines($authorizedKeysPath)) | Should -Be @($collision)
    }

    It 'rolls back only the last exact line while preserving order and unrelated lines' -Skip:$IsWindows {
        $material = Get-HHSshBootstrapPublicKey `
            -KeyPath $script:keyPath `
            -PublicKeyReader { "ssh-ed25519 $script:keyBlob" }
        $sshDirectory = Join-Path $script:caseRoot '.ssh'
        [IO.Directory]::CreateDirectory($sshDirectory) | Out-Null
        $authorizedKeysPath = Join-Path $sshDirectory 'authorized_keys'
        $lines = @('first unrelated', $material.ExactLine, 'middle unrelated', $material.ExactLine, 'last unrelated')
        [IO.File]::WriteAllLines($authorizedKeysPath, [string[]] $lines)

        $result = Invoke-HHBootstrapRollbackLocally `
            -HomePath $script:caseRoot `
            -ExactLine $material.ExactLine

        $result.Operation | Should -Be 'HostHunterAuthorizedKeyRollback.v1'
        $result.Removed | Should -BeTrue
        @([IO.File]::ReadAllLines($authorizedKeysPath)) | Should -Be @(
            'first unrelated',
            $material.ExactLine,
            'middle unrelated',
            'last unrelated'
        )
        [IO.File]::GetUnixFileMode($authorizedKeysPath) | Should -Be (
            [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite
        )
    }

    It 'reports a no-op rollback without creating or rewriting a file' {
        $authorizedKeysPath = Join-Path $script:caseRoot '.ssh/authorized_keys'
        $result = Invoke-HHBootstrapRollbackLocally `
            -HomePath $script:caseRoot `
            -ExactLine "ssh-ed25519 $script:keyBlob absent"

        $result.Removed | Should -BeFalse
        Test-Path -LiteralPath $authorizedKeysPath | Should -BeFalse
    }

    It 'leaves an existing empty or unrelated authorized_keys file unchanged' {
        $sshDirectory = Join-Path $script:caseRoot '.ssh'
        [IO.Directory]::CreateDirectory($sshDirectory) | Out-Null
        $emptyPath = Join-Path $sshDirectory 'authorized_keys'
        [IO.File]::WriteAllText($emptyPath, '')
        $emptyResult = Invoke-HHBootstrapRollbackLocally `
            -HomePath $script:caseRoot `
            -ExactLine "ssh-ed25519 $script:keyBlob absent"
        $emptyResult.Removed | Should -BeFalse
        $emptyContents = [IO.File]::ReadAllText($emptyPath)
        $emptyContents.Length | Should -Be 0

        $unrelatedHome = Join-Path $script:caseRoot 'unrelated-home'
        $unrelatedDirectory = Join-Path $unrelatedHome '.ssh'
        [IO.Directory]::CreateDirectory($unrelatedDirectory) | Out-Null
        $unrelatedPath = Join-Path $unrelatedDirectory 'authorized_keys'
        $unrelatedLine = "ssh-ed25519 $script:otherKeyBlob unrelated"
        [IO.File]::WriteAllText($unrelatedPath, "$unrelatedLine`n")
        $unrelatedResult = Invoke-HHBootstrapRollbackLocally `
            -HomePath $unrelatedHome `
            -ExactLine "ssh-ed25519 $script:keyBlob absent"
        $unrelatedResult.Removed | Should -BeFalse
        @([IO.File]::ReadAllLines($unrelatedPath)) | Should -Be @($unrelatedLine)
    }

    It 'preserves the original file and deletes rollback temporary state when chmod fails' -Skip:$IsWindows {
        $material = Get-HHSshBootstrapPublicKey `
            -KeyPath $script:keyPath `
            -PublicKeyReader { "ssh-ed25519 $script:keyBlob" }
        $sshDirectory = Join-Path $script:caseRoot '.ssh'
        [IO.Directory]::CreateDirectory($sshDirectory) | Out-Null
        $authorizedKeysPath = Join-Path $sshDirectory 'authorized_keys'
        [IO.File]::WriteAllText($authorizedKeysPath, "$($material.ExactLine)`n")
        Mock chmod {
            $global:LASTEXITCODE = 1
        }
        { Invoke-HHBootstrapRollbackLocally `
                -HomePath $script:caseRoot `
                -ExactLine $material.ExactLine } |
            Should -Throw '*secure the rollback authorized_keys file*'

        @([IO.File]::ReadAllLines($authorizedKeysPath)) | Should -Be @($material.ExactLine)
        @(Get-ChildItem -LiteralPath $script:caseRoot -Force -Filter '*.tmp').Count | Should -Be 0
    }

    It 'reports final rollback permission failure after removing only the exact line' -Skip:$IsWindows {
        $material = Get-HHSshBootstrapPublicKey `
            -KeyPath $script:keyPath `
            -PublicKeyReader { "ssh-ed25519 $script:keyBlob" }
        $sshDirectory = Join-Path $script:caseRoot '.ssh'
        [IO.Directory]::CreateDirectory($sshDirectory) | Out-Null
        $authorizedKeysPath = Join-Path $sshDirectory 'authorized_keys'
        [IO.File]::WriteAllLines(
            $authorizedKeysPath,
            [string[]] @('unrelated', $material.ExactLine)
        )
        $env:HH_TEST_CHMOD_CALLS = '0'
        Mock chmod {
            $nextCall = [int] $env:HH_TEST_CHMOD_CALLS + 1
            $env:HH_TEST_CHMOD_CALLS = [string] $nextCall
            $global:LASTEXITCODE = if ($nextCall -eq 2) { 1 } else { 0 }
        }
        { Invoke-HHBootstrapRollbackLocally `
                -HomePath $script:caseRoot `
                -ExactLine $material.ExactLine } |
            Should -Throw '*restore authorized_keys permissions after rollback*'

        @([IO.File]::ReadAllLines($authorizedKeysPath)) | Should -Be @('unrelated')
    }

    It 'reconciles exact-line presence read-only for present and absent files' -Skip:$IsWindows {
        $line = "ssh-ed25519 $script:keyBlob exact"
        $absent = Invoke-HHBootstrapReconciliationLocally `
            -HomePath $script:caseRoot `
            -ExactLine $line
        $absent.Operation | Should -BeExactly 'HostHunterAuthorizedKeyReconciliation.v1'
        $absent.Present | Should -BeFalse
        $absent.ExactMatchCount | Should -Be 0
        Test-Path -LiteralPath (Join-Path $script:caseRoot '.ssh') | Should -BeFalse

        $sshDirectory = Join-Path $script:caseRoot '.ssh'
        [IO.Directory]::CreateDirectory($sshDirectory) | Out-Null
        $authorizedKeysPath = Join-Path $sshDirectory 'authorized_keys'
        [IO.File]::WriteAllLines(
            $authorizedKeysPath,
            [string[]] @('unrelated', $line, $line)
        )
        $before = [IO.File]::ReadAllText($authorizedKeysPath)
        $present = Invoke-HHBootstrapReconciliationLocally `
            -HomePath $script:caseRoot `
            -ExactLine $line
        $present.Present | Should -BeTrue
        $present.ExactMatchCount | Should -Be 2
        [IO.File]::ReadAllText($authorizedKeysPath) | Should -BeExactly $before
    }

    It 'keeps finite error helpers bounded and rejects oversized evidence' {
        (Get-HHSshBootstrapFiniteText -Value $null) | Should -BeExactly ''
        (Get-HHSshBootstrapFiniteText -Value 'abcdef' -MaximumLength 3) |
            Should -BeExactly 'abc'

        $exceptionProjection = ConvertTo-HHSshBootstrapErrorProjection `
            -ErrorObject ([TimeoutException]::new('finite timeout'))
        $exceptionProjection.ExceptionType | Should -BeExactly 'System.TimeoutException'
        $exceptionProjection.FailureKind | Should -BeExactly 'Timeout'
        $exceptionProjection.FullyQualifiedErrorId | Should -BeNullOrEmpty
        $exceptionProjection.Category | Should -BeNullOrEmpty

        $valueProjection = ConvertTo-HHSshBootstrapErrorProjection `
            -ErrorObject ([pscustomobject]@{ Code = 9 })
        $valueProjection.ExceptionType | Should -BeExactly 'System.Management.Automation.PSCustomObject'
        $valueProjection.FailureKind | Should -BeExactly 'TransportFailure'

        Mock Get-HHSshFailureKind { throw 'classification failed' }
        (ConvertTo-HHSshBootstrapErrorProjection -ErrorObject 'plain failure').FailureKind |
            Should -BeExactly 'TransportFailure'

        $dataException = [InvalidOperationException]::new('data')
        $dataException.Data['Example'] = 'value'
        (Get-HHSshBootstrapExceptionDataValue `
                -ErrorObject $dataException `
                -Name Example) | Should -BeExactly 'value'
        $dataRecord = [Management.Automation.ErrorRecord]::new(
            $dataException,
            'DataRecord',
            [Management.Automation.ErrorCategory]::InvalidData,
            $null
        )
        (Get-HHSshBootstrapExceptionDataValue `
                -ErrorObject $dataRecord `
                -Name Example) | Should -BeExactly 'value'
        (Get-HHSshBootstrapExceptionDataValue `
                -ErrorObject ([pscustomobject]@{}) `
                -Name Missing) | Should -BeNullOrEmpty

        $destination = [Collections.Generic.List[object]]::new()
        $added = Add-HHSshBootstrapEvidence `
            -Destination $destination `
            -SourceEvents @(
                $null,
                [pscustomobject]@{},
                [pscustomobject]@{
                    Phase = 'Finite'
                    Stream = 'Output'
                    TypeName = ''
                    IsTerminating = $false
                    Value = $null
                },
                [pscustomobject]@{
                    Phase = 'Finite'
                    Stream = 'invalid-stream'
                    TypeName = ''
                    IsTerminating = $false
                    Value = [pscustomobject]@{ Value = 1 }
                }
            ) `
            -RemainingBytes 100000 `
            -Clock $script:fixedClock
        $added | Should -BeGreaterThan 0
        $destination.Count | Should -Be 4
        @($destination.Stream) | Should -Be @('Error', 'Error', 'Output', 'Error')
        @($destination.Phase) | Should -Be @('Bootstrap', 'Bootstrap', 'Finite', 'Finite')
        @($destination | Select-Object -First 2 | ForEach-Object Value |
                ForEach-Object ExceptionType) | Should -Be @(
            'null',
            'System.Management.Automation.PSCustomObject'
        )
        $destination[2].TypeName | Should -BeExactly 'null'
        $destination[3].TypeName |
            Should -BeExactly 'System.Management.Automation.PSCustomObject'

        {
            Add-HHSshBootstrapEvidence `
                -Destination ([Collections.Generic.List[object]]::new()) `
                -SourceEvents @($destination[0]) `
                -RemainingBytes 1 `
                -Clock $script:fixedClock
        } | Should -Throw '*cumulative SSH bootstrap output limit*'
        (Add-HHSshBootstrapFiniteFailureEvent `
                -Destination ([Collections.Generic.List[object]]::new()) `
                -ErrorObject ([InvalidOperationException]::new('x')) `
                -Phase Bootstrap `
                -RemainingBytes 0 `
                -Clock $script:fixedClock) | Should -Be 0
        (Add-HHSshBootstrapFiniteFailureEvent `
                -Destination ([Collections.Generic.List[object]]::new()) `
                -ErrorObject ([InvalidOperationException]::new('x')) `
                -Phase Bootstrap `
                -RemainingBytes 1 `
                -Clock $script:fixedClock) | Should -Be 0

        {
            New-HHSshBootstrapCommitReceipt `
                -CallbackReceipt ([pscustomobject]@{ Committed = $false }) `
                -TargetName bootstrap-node
        } | Should -Throw '*did not return a proven Committed=true receipt*'
    }

    It 'requires exactly one matching bootstrap operation output' {
        $install = [pscustomobject]@{
            Operation = 'HostHunterAuthorizedKeyInstall.v1'
            Added = $true
        }
        $events = @(
            New-HHSshStreamEvent -Sequence 0 -Phase BootstrapInstall -InputObject $install
        )
        (Get-HHSshBootstrapOperationOutput `
                -StreamEvents $events `
                -Operation 'HostHunterAuthorizedKeyInstall.v1').Added | Should -BeTrue

        { Get-HHSshBootstrapOperationOutput `
                -StreamEvents @() `
                -Operation 'HostHunterAuthorizedKeyInstall.v1' } |
            Should -Throw '*invalid result count*'
        { Get-HHSshBootstrapOperationOutput `
                -StreamEvents @($events[0], $events[0]) `
                -Operation 'HostHunterAuthorizedKeyInstall.v1' } |
            Should -Throw '*invalid result count*'
    }

    It 'reclassifies evidence-poor RuntimeMismatch without inventing an observed identity' {
        Write-HHBootstrapTestKeyPair -Path $script:keyPath
        $result = Invoke-HHSshKeyBootstrap `
            -Target $script:passwordTarget `
            -KnownHostsPath $script:knownHostsPath `
            -KeyPath $script:keyPath `
            -UseExistingKey `
            -SessionFactory {
                $failure = New-HHSshClassifiedException `
                    -FailureKind RuntimeMismatch `
                    -Message 'mismatch without observed evidence'
                $failure.Data['HHObservedProbeRuntime'] = 'PowerShell7'
                throw $failure
            } `
            -SessionRemover { } `
            -Clock $script:fixedClock `
            -Confirm:$false

        $result.Succeeded | Should -BeFalse
        $result.FailureKind | Should -BeExactly 'TransportFailure'
        $result.DispatchState | Should -BeExactly 'NotDispatched'
        $result.OutcomeStatus | Should -BeExactly 'Failed'
        $result.RemotePowerShellVersion | Should -BeNullOrEmpty
        $result.RemotePSEdition | Should -BeNullOrEmpty
        $result.ExecutionMode | Should -BeNullOrEmpty
        $result.HostKeyFingerprint | Should -BeNullOrEmpty
        $result.RemoteIdentity | Should -BeNullOrEmpty
        $result.ValidatedAtUtc | Should -BeNullOrEmpty
    }

    It 'accepts no unproven observed mismatch context as target identity evidence' {
        function Get-HHObservedMismatchFixture {
            param(
                [string] $Marker = 'HostHunter.PowerShellIdentity.v1',
                [string] $Version = '7.6.5',
                [string] $Edition = 'Core',
                [string] $Mode = 'Direct',
                [string] $ProcessPath = '/opt/microsoft/powershell/7/pwsh',
                [string] $ValidatedAtUtc = '2026-08-23T01:02:03Z',
                [string] $Fingerprint = $script:hostFingerprint
            )

            $failure = New-HHSshClassifiedException `
                -FailureKind RuntimeMismatch `
                -Message 'observed runtime mismatch fixture'
            $failure.Data['HHObservedIdentity'] = [pscustomobject][ordered]@{
                Marker = $Marker
                PSEdition = $Edition
                PowerShellVersion = $Version
                ProcessPath = $ProcessPath
                UserName = 'operator'
                MachineName = 'bootstrap-node'
            }
            $failure.Data['HHObservedRemotePowerShellVersion'] = $Version
            $failure.Data['HHObservedRemotePSEdition'] = $Edition
            $failure.Data['HHObservedExecutionMode'] = $Mode
            $failure.Data['HHObservedValidatedAtUtc'] = $ValidatedAtUtc
            $failure.Data['HHObservedHostKeyFingerprint'] = $Fingerprint
            return $failure
        }

        $transportFailure = New-HHSshClassifiedException `
            -FailureKind TransportFailure `
            -Message 'not a runtime mismatch'
        (Get-HHSshBootstrapObservedMismatchContext `
                -ErrorObject $transportFailure `
                -RequestedPowerShellRuntime PowerShell7 `
                -ExpectedHostKeyFingerprint $script:hostFingerprint) |
            Should -BeNullOrEmpty

        $invalidContexts = @(
            @{ Marker = 'wrong' },
            @{ Version = 'not-a-version' },
            @{ Edition = 'Desktop' },
            @{ Mode = 'Compatibility' },
            @{ ProcessPath = '/usr/bin/powershell' },
            @{ ValidatedAtUtc = 'not-a-date' },
            @{ Fingerprint = 'SHA256:wrong' }
        )
        foreach ($case in $invalidContexts) {
            $failure = Get-HHObservedMismatchFixture @case
            (Get-HHSshBootstrapObservedMismatchContext `
                    -ErrorObject $failure `
                    -RequestedPowerShellRuntime PowerShell7 `
                    -ExpectedHostKeyFingerprint $script:hostFingerprint) |
                Should -BeNullOrEmpty
        }

        # Even internally consistent PowerShell 7 evidence cannot prove a mismatch
        # with the requested PowerShell 7 runtime, so it must remain unusable.
        $requestedRuntime = Get-HHObservedMismatchFixture
        (Get-HHSshBootstrapObservedMismatchContext `
                -ErrorObject $requestedRuntime `
                -RequestedPowerShellRuntime PowerShell7 `
                -ExpectedHostKeyFingerprint $script:hostFingerprint) |
            Should -BeNullOrEmpty
    }

    It 'publishes a PublicKey profile only after a separate key-only identity proof' {
        $script:sessionPlans = [Collections.Generic.List[object]]::new()
        $script:removedSessions = [Collections.Generic.List[object]]::new()
        $script:armedBootstrapPhases = [Collections.Generic.List[string]]::new()
        $sessionFactory = {
            param($plan)
            $script:sessionPlans.Add($plan)
            [pscustomobject]@{ Authentication = $plan.Authentication; Id = $script:sessionPlans.Count }
        }
        $remoteInvoker = {
            param($session, $remoteScript, $argumentList)
            $null = $session
            $null = $argumentList
            $text = $remoteScript.ToString()
            if ($text.Contains('HostHunter.PowerShellIdentity.v1')) {
                New-HHBootstrapIdentity
            }
            elseif ($text.Contains('HostHunterAuthorizedKeyInstall.v1')) {
                [pscustomobject]@{
                    Operation = 'HostHunterAuthorizedKeyInstall.v1'
                    Added = $true
                    Marker = $argumentList[1]
                    AuthorizedKeysPath = '/home/operator/.ssh/authorized_keys'
                }
            }
            else {
                throw "Unexpected remote script for $($session.Authentication)."
            }
        }
        $result = Invoke-HHSshKeyBootstrap `
            -Target $script:passwordTarget `
            -KnownHostsPath $script:knownHostsPath `
            -KeyPath $script:keyPath `
            -KeyGenerator { param($path) Write-HHBootstrapTestKeyPair -Path $path } `
            -SessionFactory $sessionFactory `
            -RemoteInvoker $remoteInvoker `
            -OperationArmer {
                foreach ($phaseGroup in $args) {
                    foreach ($phase in @($phaseGroup)) {
                        $script:armedBootstrapPhases.Add([string] $phase)
                    }
                }
            } `
            -SessionRemover { param($session) $script:removedSessions.Add($session) } `
            -Clock $script:fixedClock `
            -Confirm:$false

        $result.Succeeded | Should -BeTrue
        $result.Planned | Should -BeFalse
        $result.Installed | Should -BeTrue
        $result.ProfileTransition.Authentication | Should -Be 'PublicKey'
        $result.ProfileTransition.KeyPath | Should -Be $script:keyPath
        $result.ProfileTransition.LastValidatedPowerShellVersion | Should -Be '7.6.5'
        @($script:sessionPlans.Authentication) | Should -Be @('Password', 'PublicKey')
        $script:removedSessions.Count | Should -Be 2
        @($result.StreamEvents.Phase) | Should -Be @('Identity', 'BootstrapInstall', 'Identity')
        @($script:armedBootstrapPhases) | Should -Be @(
            'OuterIdentity',
            'BootstrapInstall',
            'BootstrapKeyOnlyOuterIdentity'
        )
        Test-Path -LiteralPath $script:keyPath | Should -BeTrue
    }

    It 'executes prepared key material without rereading a changed public-key file' {
        $prepared = Prepare-HHSshKeyBootstrapOperation `
            -Target $script:passwordTarget `
            -KnownHostsPath $script:knownHostsPath `
            -KeyPath $script:keyPath `
            -KeyGenerator { param($path) Write-HHBootstrapTestKeyPair -Path $path } `
            -Confirm:$false
        [IO.File]::WriteAllText(
            "$script:keyPath.pub",
            "ssh-ed25519 $script:otherKeyBlob changed-after-preparation"
        )
        $script:installedLine = $null
        $remoteInvoker = {
            param($session, $remoteScript, $argumentList)
            $null = $session
            if ($remoteScript.ToString().Contains('HostHunter.PowerShellIdentity.v1')) {
                New-HHBootstrapIdentity
            }
            else {
                $script:installedLine = [string] $argumentList[0]
                [pscustomobject]@{
                    Operation = 'HostHunterAuthorizedKeyInstall.v1'
                    Added = $true
                }
            }
        }
        $result = Invoke-HHSshKeyBootstrap `
            -PreparedOperation $prepared `
            -SessionFactory { param($plan) [pscustomobject]@{ Authentication = $plan.Authentication } } `
            -RemoteInvoker $remoteInvoker `
            -SessionRemover { } `
            -Clock $script:fixedClock `
            -Confirm:$false

        $result.Succeeded | Should -BeTrue
        $script:installedLine | Should -BeExactly $prepared.KeyMaterial.ExactLine
        $script:installedLine | Should -Not -Match [regex]::Escape($script:otherKeyBlob)
    }

    It 'uses the default dedicated-key generator when no generator seam is supplied' -Skip:$IsWindows {
        $env:HH_TEST_KEY_BLOB = $script:keyBlob
        Mock ssh-keygen {
            $arguments = [object[]] $args
            $keyPathIndex = [Array]::IndexOf($arguments, '-f')
            $generatedPath = [string] $arguments[$keyPathIndex + 1]
            [IO.File]::WriteAllText($generatedPath, 'generated-private-key')
            [IO.File]::WriteAllText(
                "$generatedPath.pub",
                "ssh-ed25519 $env:HH_TEST_KEY_BLOB generated"
            )
            [IO.File]::SetUnixFileMode(
                $generatedPath,
                [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite
            )
            $global:LASTEXITCODE = 0
        }
        $sessionFactory = {
            param($plan)
            [pscustomobject]@{ Authentication = $plan.Authentication }
        }
        $remoteInvoker = {
            param($session, $remoteScript, $argumentList)
            $null = $session
            $text = $remoteScript.ToString()
            if ($text.Contains('HostHunter.PowerShellIdentity.v1')) {
                New-HHBootstrapIdentity
            }
            else {
                [pscustomobject]@{
                    Operation = 'HostHunterAuthorizedKeyInstall.v1'
                    Added = $true
                    Marker = $argumentList[1]
                    AuthorizedKeysPath = '/home/operator/.ssh/authorized_keys'
                }
            }
        }
        $result = Invoke-HHSshKeyBootstrap `
            -Target $script:passwordTarget `
            -KnownHostsPath $script:knownHostsPath `
            -KeyPath $script:keyPath `
            -SessionFactory $sessionFactory `
            -RemoteInvoker $remoteInvoker `
            -SessionRemover { } `
            -Confirm:$false

        $result.Succeeded | Should -BeTrue
        $result.Plan.KeyAction | Should -Be 'GenerateDedicatedEd25519Key'
        $result.ProfileTransition.Authentication | Should -Be 'PublicKey'
        Test-Path -LiteralPath $script:keyPath | Should -BeTrue
    }

    It 'fails closed when the install operation returns no attributable output' {
        Write-HHBootstrapTestKeyPair -Path $script:keyPath
        $remoteInvoker = {
            param($session, $remoteScript, $argumentList)
            $null = $session
            $null = $argumentList
            if ($remoteScript.ToString().Contains('HostHunter.PowerShellIdentity.v1')) {
                New-HHBootstrapIdentity
            }
        }
        $result = Invoke-HHSshKeyBootstrap `
            -Target $script:passwordTarget `
            -KnownHostsPath $script:knownHostsPath `
            -KeyPath $script:keyPath `
            -UseExistingKey `
            -SessionFactory { param($plan) [pscustomobject]@{ Authentication = $plan.Authentication } } `
            -RemoteInvoker $remoteInvoker `
            -SessionRemover { } `
            -Confirm:$false

        $result.Succeeded | Should -BeFalse
        $result.FailureKind | Should -Be 'TransportFailure'
        $result.Installed | Should -BeFalse
        $result.RollbackAttempted | Should -BeFalse
    }

    It 'reconciles an invalid install result without retrying the install' {
        Write-HHBootstrapTestKeyPair -Path $script:keyPath
        $script:installCalls = 0
        $script:reconcileCalls = 0
        $remoteInvoker = {
            param($session, $remoteScript, $argumentList)
            $null = $session
            $null = $argumentList
            $text = $remoteScript.ToString()
            if ($text.Contains('HostHunter.PowerShellIdentity.v1')) {
                New-HHBootstrapIdentity
            }
            elseif ($text.Contains('HostHunterAuthorizedKeyInstall.v1')) {
                $script:installCalls++
                [pscustomobject]@{
                    Operation = 'HostHunterAuthorizedKeyInstall.v1'
                    Added = 'not-a-Boolean'
                }
            }
            elseif ($text.Contains('HostHunterAuthorizedKeyReconciliation.v1')) {
                $script:reconcileCalls++
                [pscustomobject]@{
                    Operation = 'HostHunterAuthorizedKeyReconciliation.v1'
                    Present = $false
                }
            }
        }
        $result = Invoke-HHSshKeyBootstrap `
            -Target $script:passwordTarget `
            -KnownHostsPath $script:knownHostsPath `
            -KeyPath $script:keyPath `
            -UseExistingKey `
            -SessionFactory { [pscustomobject]@{ Authentication = 'Password' } } `
            -RemoteInvoker $remoteInvoker `
            -SessionRemover { } `
            -Clock $script:fixedClock `
            -Confirm:$false

        $result.Succeeded | Should -BeFalse
        $result.FailureKind | Should -BeExactly 'TransportFailure'
        $result.Installed | Should -BeFalse
        $result.ReconciliationAttempted | Should -BeTrue
        $result.ReconciliationSucceeded | Should -BeTrue
        $result.ReconciliationPresent | Should -BeFalse
        $result.RollbackAttempted | Should -BeFalse
        $script:installCalls | Should -Be 1
        $script:reconcileCalls | Should -Be 1
    }

    It 'honors a deterministic NotDispatched install failure without reconciliation' {
        Write-HHBootstrapTestKeyPair -Path $script:keyPath
        $script:reconcileCalls = 0
        $remoteInvoker = {
            param($session, $remoteScript, $argumentList)
            $null = $session
            $null = $argumentList
            $text = $remoteScript.ToString()
            if ($text.Contains('HostHunter.PowerShellIdentity.v1')) {
                New-HHBootstrapIdentity
            }
            elseif ($text.Contains('HostHunterAuthorizedKeyInstall.v1')) {
                $failure = New-HHSshClassifiedException `
                    -FailureKind Timeout `
                    -Message 'install never dispatched'
                $failure.Data['HHDispatchState'] = 'NotDispatched'
                throw $failure
            }
            elseif ($text.Contains('HostHunterAuthorizedKeyReconciliation.v1')) {
                $script:reconcileCalls++
            }
        }
        $result = Invoke-HHSshKeyBootstrap `
            -Target $script:passwordTarget `
            -KnownHostsPath $script:knownHostsPath `
            -KeyPath $script:keyPath `
            -UseExistingKey `
            -SessionFactory { [pscustomobject]@{ Authentication = 'Password' } } `
            -RemoteInvoker $remoteInvoker `
            -SessionRemover { } `
            -Clock $script:fixedClock `
            -Confirm:$false

        $result.FailureKind | Should -BeExactly 'Timeout'
        $result.DispatchState | Should -BeExactly 'NotDispatched'
        $result.OutcomeStatus | Should -BeExactly 'Failed'
        $result.Installed | Should -BeFalse
        $result.ReconciliationAttempted | Should -BeFalse
        $result.RollbackAttempted | Should -BeFalse
        $script:reconcileCalls | Should -Be 0
    }

    It 'returns Unknown when reconciliation returns a non-Boolean presence state' {
        Write-HHBootstrapTestKeyPair -Path $script:keyPath
        $remoteInvoker = {
            param($session, $remoteScript, $argumentList)
            $null = $session
            $null = $argumentList
            $text = $remoteScript.ToString()
            if ($text.Contains('HostHunter.PowerShellIdentity.v1')) {
                New-HHBootstrapIdentity
            }
            elseif ($text.Contains('HostHunterAuthorizedKeyInstall.v1')) {
                $failure = New-HHSshClassifiedException `
                    -FailureKind TransportFailure `
                    -Message 'install result uncertain'
                $failure.Data['HHDispatchState'] = 'Dispatched'
                throw $failure
            }
            elseif ($text.Contains('HostHunterAuthorizedKeyReconciliation.v1')) {
                [pscustomobject]@{
                    Operation = 'HostHunterAuthorizedKeyReconciliation.v1'
                    Present = 'not-a-Boolean'
                }
            }
        }
        $result = Invoke-HHSshKeyBootstrap `
            -Target $script:passwordTarget `
            -KnownHostsPath $script:knownHostsPath `
            -KeyPath $script:keyPath `
            -UseExistingKey `
            -SessionFactory { [pscustomobject]@{ Authentication = 'Password' } } `
            -RemoteInvoker $remoteInvoker `
            -SessionRemover { } `
            -Clock $script:fixedClock `
            -Confirm:$false

        $result.Succeeded | Should -BeFalse
        $result.FailureKind | Should -BeExactly 'TransportFailure'
        $result.DispatchState | Should -BeExactly 'DispatchUncertain'
        $result.OutcomeStatus | Should -BeExactly 'Unknown'
        $result.Installed | Should -BeNullOrEmpty
        $result.ReconciliationAttempted | Should -BeTrue
        $result.ReconciliationSucceeded | Should -BeFalse
        $result.ReconciliationRequired | Should -BeTrue
    }

    It 'contextualizes a generic key-only PSSessionOpenFailed as authentication failure' {
        Write-HHBootstrapTestKeyPair -Path $script:keyPath
        $sessionFactory = {
            param($plan)
            if ($plan.Authentication -ceq 'PublicKey') {
                $openFailure = [Management.Automation.ErrorRecord]::new(
                    [InvalidOperationException]::new('generic SSH transport termination'),
                    'PSSessionOpenFailed',
                    [Management.Automation.ErrorCategory]::OpenError,
                    $null
                )
                throw $openFailure
            }
            [pscustomobject]@{ Authentication = $plan.Authentication }
        }
        $remoteInvoker = {
            param($session, $remoteScript, $argumentList)
            $null = $session
            $null = $argumentList
            $text = $remoteScript.ToString()
            if ($text.Contains('HostHunter.PowerShellIdentity.v1')) {
                New-HHBootstrapIdentity
            }
            elseif ($text.Contains('HostHunterAuthorizedKeyInstall.v1')) {
                [pscustomobject]@{
                    Operation = 'HostHunterAuthorizedKeyInstall.v1'
                    Added = $true
                    AuthorizedKeysPath = '/home/operator/.ssh/authorized_keys'
                }
            }
            else {
                [pscustomobject]@{
                    Operation = 'HostHunterAuthorizedKeyRollback.v1'
                    Removed = $true
                    PresentAfter = $false
                }
            }
        }
        $result = Invoke-HHSshKeyBootstrap `
            -Target $script:passwordTarget `
            -KnownHostsPath $script:knownHostsPath `
            -KeyPath $script:keyPath `
            -UseExistingKey `
            -SessionFactory $sessionFactory `
            -RemoteInvoker $remoteInvoker `
            -SessionRemover { } `
            -Confirm:$false

        $result.Succeeded | Should -BeFalse
        $result.FailureKind | Should -Be 'AuthenticationFailure'
        $result.RollbackAttempted | Should -BeTrue
        $result.RollbackSucceeded | Should -BeTrue
    }

    It 'rolls back an added line and removes a generated key when key-only proof fails' {
        $script:rollbackCalls = 0
        $sessionFactory = {
            param($plan)
            if ($plan.Authentication -ceq 'PublicKey') {
                throw (New-HHSshClassifiedException `
                        -FailureKind AuthenticationFailure `
                        -Message 'forced key-only authentication failure')
            }
            [pscustomobject]@{ Authentication = $plan.Authentication }
        }
        $remoteInvoker = {
            param($session, $remoteScript, $argumentList)
            $null = $session
            $text = $remoteScript.ToString()
            if ($text.Contains('HostHunter.PowerShellIdentity.v1')) {
                New-HHBootstrapIdentity
            }
            elseif ($text.Contains('HostHunterAuthorizedKeyInstall.v1')) {
                [pscustomobject]@{
                    Operation = 'HostHunterAuthorizedKeyInstall.v1'
                    Added = $true
                    Marker = $argumentList[1]
                    AuthorizedKeysPath = '/home/operator/.ssh/authorized_keys'
                }
            }
            elseif ($text.Contains('HostHunterAuthorizedKeyRollback.v1')) {
                $script:rollbackCalls++
                [pscustomobject]@{
                    Operation = 'HostHunterAuthorizedKeyRollback.v1'
                    Removed = $true
                    PresentAfter = $false
                }
            }
        }
        $result = Invoke-HHSshKeyBootstrap `
            -Target $script:passwordTarget `
            -KnownHostsPath $script:knownHostsPath `
            -KeyPath $script:keyPath `
            -KeyGenerator { param($path) Write-HHBootstrapTestKeyPair -Path $path } `
            -SessionFactory $sessionFactory `
            -RemoteInvoker $remoteInvoker `
            -SessionRemover { } `
            -Confirm:$false

        $result.Succeeded | Should -BeFalse
        $result.FailureKind | Should -Be 'AuthenticationFailure'
        $result.ProfileTransition | Should -BeNullOrEmpty
        $result.RollbackAttempted | Should -BeTrue
        $result.RollbackSucceeded | Should -BeTrue
        $result.LocalKeyRemovedOnFailure | Should -BeTrue
        $script:rollbackCalls | Should -Be 1
        Test-Path -LiteralPath $script:keyPath | Should -BeFalse
        Test-Path -LiteralPath "$script:keyPath.pub" | Should -BeFalse
    }

    It 'preserves a generated key and classifies failure when exact remote rollback fails' {
        $sessionFactory = {
            param($plan)
            if ($plan.Authentication -ceq 'PublicKey') {
                throw 'forced public-key connection failure'
            }
            [pscustomobject]@{ Authentication = $plan.Authentication }
        }
        $remoteInvoker = {
            param($session, $remoteScript, $argumentList)
            $null = $session
            $text = $remoteScript.ToString()
            if ($text.Contains('HostHunter.PowerShellIdentity.v1')) {
                New-HHBootstrapIdentity
            }
            elseif ($text.Contains('HostHunterAuthorizedKeyInstall.v1')) {
                [pscustomobject]@{
                    Operation = 'HostHunterAuthorizedKeyInstall.v1'
                    Added = $true
                    Marker = $argumentList[1]
                    AuthorizedKeysPath = '/home/operator/.ssh/authorized_keys'
                }
            }
            elseif ($text.Contains('HostHunterAuthorizedKeyRollback.v1')) {
                $failure = New-HHSshClassifiedException `
                    -FailureKind TransportFailure `
                    -Message 'forced exact rollback failure'
                $failure.Data['HHStreamEvents'] = @(
                    New-HHSshStreamEvent `
                        -Sequence 0 `
                        -Phase BootstrapRollback `
                        -InputObject 'partial rollback evidence' `
                        -Clock $script:fixedClock
                )
                throw $failure
            }
        }
        $result = Invoke-HHSshKeyBootstrap `
            -Target $script:passwordTarget `
            -KnownHostsPath $script:knownHostsPath `
            -KeyPath $script:keyPath `
            -KeyGenerator { param($path) Write-HHBootstrapTestKeyPair -Path $path } `
            -SessionFactory $sessionFactory `
            -RemoteInvoker $remoteInvoker `
            -SessionRemover { } `
            -Confirm:$false

        $result.Succeeded | Should -BeFalse
        $result.FailureKind | Should -Be 'TransportFailure'
        $result.RollbackAttempted | Should -BeTrue
        $result.RollbackSucceeded | Should -BeFalse
        $result.LocalKeyRemovedOnFailure | Should -BeFalse
        Test-Path -LiteralPath $script:keyPath | Should -BeTrue
        Test-Path -LiteralPath "$script:keyPath.pub" | Should -BeTrue
    }

    It 'fails rollback when the remote endpoint returns no rollback operation output' {
        Write-HHBootstrapTestKeyPair -Path $script:keyPath
        $sessionFactory = {
            param($plan)
            if ($plan.Authentication -ceq 'PublicKey') {
                throw (New-HHSshClassifiedException `
                        -FailureKind AuthenticationFailure `
                        -Message 'forced proof failure')
            }
            [pscustomobject]@{ Authentication = $plan.Authentication }
        }
        $remoteInvoker = {
            param($session, $remoteScript, $argumentList)
            $null = $session
            $null = $argumentList
            $text = $remoteScript.ToString()
            if ($text.Contains('HostHunter.PowerShellIdentity.v1')) {
                New-HHBootstrapIdentity
            }
            elseif ($text.Contains('HostHunterAuthorizedKeyInstall.v1')) {
                [pscustomobject]@{
                    Operation = 'HostHunterAuthorizedKeyInstall.v1'
                    Added = $true
                    AuthorizedKeysPath = '/home/operator/.ssh/authorized_keys'
                }
            }
        }
        $result = Invoke-HHSshKeyBootstrap `
            -Target $script:passwordTarget `
            -KnownHostsPath $script:knownHostsPath `
            -KeyPath $script:keyPath `
            -UseExistingKey `
            -SessionFactory $sessionFactory `
            -RemoteInvoker $remoteInvoker `
            -SessionRemover { } `
            -Confirm:$false

        $result.Succeeded | Should -BeFalse
        $result.FailureKind | Should -Be 'TransportFailure'
        $result.RollbackAttempted | Should -BeTrue
        $result.RollbackSucceeded | Should -BeFalse
        Test-Path -LiteralPath $script:keyPath | Should -BeTrue
    }

    It 'treats a non-Boolean rollback presence result as unresolved state' {
        Write-HHBootstrapTestKeyPair -Path $script:keyPath
        $sessionFactory = {
            param($plan)
            if ($plan.Authentication -ceq 'PublicKey') {
                throw (New-HHSshClassifiedException `
                        -FailureKind AuthenticationFailure `
                        -Message 'forced proof failure')
            }
            [pscustomobject]@{ Authentication = $plan.Authentication }
        }
        $remoteInvoker = {
            param($session, $remoteScript, $argumentList)
            $null = $session
            $null = $argumentList
            $text = $remoteScript.ToString()
            if ($text.Contains('HostHunter.PowerShellIdentity.v1')) {
                New-HHBootstrapIdentity
            }
            elseif ($text.Contains('HostHunterAuthorizedKeyInstall.v1')) {
                [pscustomobject]@{
                    Operation = 'HostHunterAuthorizedKeyInstall.v1'
                    Added = $true
                }
            }
            elseif ($text.Contains('HostHunterAuthorizedKeyRollback.v1')) {
                [pscustomobject]@{
                    Operation = 'HostHunterAuthorizedKeyRollback.v1'
                    PresentAfter = 'not-a-Boolean'
                }
            }
        }
        $result = Invoke-HHSshKeyBootstrap `
            -Target $script:passwordTarget `
            -KnownHostsPath $script:knownHostsPath `
            -KeyPath $script:keyPath `
            -UseExistingKey `
            -SessionFactory $sessionFactory `
            -RemoteInvoker $remoteInvoker `
            -SessionRemover { } `
            -Clock $script:fixedClock `
            -Confirm:$false

        $result.Succeeded | Should -BeFalse
        $result.FailureKind | Should -BeExactly 'TransportFailure'
        $result.OutcomeStatus | Should -BeExactly 'Unknown'
        $result.RollbackAttempted | Should -BeTrue
        $result.RollbackSucceeded | Should -BeNullOrEmpty
        $result.ReconciliationRequired | Should -BeTrue
    }

    It 'preserves generated key material when exact local key removal itself fails' {
        $result = Invoke-HHSshKeyBootstrap `
            -Target $script:passwordTarget `
            -KnownHostsPath $script:knownHostsPath `
            -KeyPath $script:keyPath `
            -KeyGenerator { param($path) Write-HHBootstrapTestKeyPair -Path $path } `
            -SessionFactory {
                throw (New-HHSshClassifiedException `
                        -FailureKind Timeout `
                        -Message 'forced password-session timeout')
            } `
            -KeyRemover { throw 'forced exact local removal failure' } `
            -Confirm:$false

        $result.Succeeded | Should -BeFalse
        $result.FailureKind | Should -Be 'Timeout'
        $result.LocalKeyRemovedOnFailure | Should -BeFalse
        Test-Path -LiteralPath $script:keyPath | Should -BeTrue
        Test-Path -LiteralPath "$script:keyPath.pub" | Should -BeTrue
    }

    It 'propagates a failure-event clock error instead of returning an incomplete result' {
        { Invoke-HHSshKeyBootstrap `
                -Target $script:passwordTarget `
                -KnownHostsPath $script:knownHostsPath `
                -KeyPath $script:keyPath `
                -KeyGenerator { throw 'forced generation failure' } `
                -Clock { throw 'forced failure-event clock error' } `
                -Confirm:$false } |
            Should -Throw '*forced failure-event clock error*'
        Test-Path -LiteralPath $script:keyPath | Should -BeFalse
        Test-Path -LiteralPath "$script:keyPath.pub" | Should -BeFalse
    }

    It 'never deletes a user-selected existing key after a failed proof' {
        Write-HHBootstrapTestKeyPair -Path $script:keyPath
        $sessionFactory = {
            param($plan)
            if ($plan.Authentication -ceq 'PublicKey') {
                throw 'forced proof failure'
            }
            [pscustomobject]@{ Authentication = $plan.Authentication }
        }
        $remoteInvoker = {
            param($session, $remoteScript, $argumentList)
            $null = $session
            $null = $argumentList
            $text = $remoteScript.ToString()
            if ($text.Contains('HostHunter.PowerShellIdentity.v1')) {
                New-HHBootstrapIdentity
            }
            elseif ($text.Contains('HostHunterAuthorizedKeyInstall.v1')) {
                [pscustomobject]@{
                    Operation = 'HostHunterAuthorizedKeyInstall.v1'
                    Added = $true
                    AuthorizedKeysPath = '/home/operator/.ssh/authorized_keys'
                }
            }
            elseif ($text.Contains('HostHunterAuthorizedKeyRollback.v1')) {
                [pscustomobject]@{
                    Operation = 'HostHunterAuthorizedKeyRollback.v1'
                    Removed = $true
                    PresentAfter = $false
                }
            }
        }
        $result = Invoke-HHSshKeyBootstrap `
            -Target $script:passwordTarget `
            -KnownHostsPath $script:knownHostsPath `
            -KeyPath $script:keyPath `
            -UseExistingKey `
            -SessionFactory $sessionFactory `
            -RemoteInvoker $remoteInvoker `
            -SessionRemover { } `
            -Confirm:$false

        $result.Succeeded | Should -BeFalse
        $result.RollbackSucceeded | Should -BeTrue
        $result.LocalKeyRemovedOnFailure | Should -BeFalse
        [IO.File]::ReadAllText($script:keyPath) | Should -Be 'test-private-key'
        Test-Path -LiteralPath "$script:keyPath.pub" | Should -BeTrue
    }

    It 'removes a generated key without rollback when installation was idempotent' {
        $script:rollbackCalls = 0
        $sessionFactory = {
            param($plan)
            if ($plan.Authentication -ceq 'PublicKey') {
                throw 'forced proof failure'
            }
            [pscustomobject]@{ Authentication = $plan.Authentication }
        }
        $remoteInvoker = {
            param($session, $remoteScript, $argumentList)
            $null = $session
            $null = $argumentList
            $text = $remoteScript.ToString()
            if ($text.Contains('HostHunter.PowerShellIdentity.v1')) {
                New-HHBootstrapIdentity
            }
            elseif ($text.Contains('HostHunterAuthorizedKeyInstall.v1')) {
                [pscustomobject]@{
                    Operation = 'HostHunterAuthorizedKeyInstall.v1'
                    Added = $false
                    AuthorizedKeysPath = '/home/operator/.ssh/authorized_keys'
                }
            }
            elseif ($text.Contains('HostHunterAuthorizedKeyRollback.v1')) {
                $script:rollbackCalls++
            }
        }
        $result = Invoke-HHSshKeyBootstrap `
            -Target $script:passwordTarget `
            -KnownHostsPath $script:knownHostsPath `
            -KeyPath $script:keyPath `
            -KeyGenerator { param($path) Write-HHBootstrapTestKeyPair -Path $path } `
            -SessionFactory $sessionFactory `
            -RemoteInvoker $remoteInvoker `
            -SessionRemover { } `
            -Confirm:$false

        $result.Succeeded | Should -BeFalse
        $result.Installed | Should -BeFalse
        $result.RollbackAttempted | Should -BeFalse
        $result.LocalKeyRemovedOnFailure | Should -BeTrue
        $script:rollbackCalls | Should -Be 0
        Test-Path -LiteralPath $script:keyPath | Should -BeFalse
    }

    It 'reconciles an uncertain install as present and compensates with exact-line rollback' {
        Write-HHBootstrapTestKeyPair -Path $script:keyPath
        $script:phaseCalls = [Collections.Generic.List[string]]::new()
        $script:armedReconciliationPhases = [Collections.Generic.List[string]]::new()
        $script:rollbackArguments = $null
        $remoteInvoker = {
            param($session, $remoteScript, $argumentList)
            $null = $session
            $text = $remoteScript.ToString()
            if ($text.Contains('HostHunter.PowerShellIdentity.v1')) {
                New-HHBootstrapIdentity
            }
            elseif ($text.Contains('HostHunterAuthorizedKeyInstall.v1')) {
                $script:phaseCalls.Add('Install')
                $failure = New-HHSshClassifiedException `
                    -FailureKind TransportFailure `
                    -Message 'uncertain install result'
                $failure.Data['HHDispatchState'] = 'Dispatched'
                throw $failure
            }
            elseif ($text.Contains('HostHunterAuthorizedKeyReconciliation.v1')) {
                $script:phaseCalls.Add('Reconcile')
                [pscustomobject]@{
                    Operation = 'HostHunterAuthorizedKeyReconciliation.v1'
                    Present = $true
                    ExactMatchCount = 1
                }
            }
            elseif ($text.Contains('HostHunterAuthorizedKeyRollback.v1')) {
                $script:phaseCalls.Add('Rollback')
                $script:rollbackArguments = @($argumentList)
                [pscustomobject]@{
                    Operation = 'HostHunterAuthorizedKeyRollback.v1'
                    Removed = $true
                    PresentAfter = $false
                }
            }
        }
        $result = Invoke-HHSshKeyBootstrap `
            -Target $script:passwordTarget `
            -KnownHostsPath $script:knownHostsPath `
            -KeyPath $script:keyPath `
            -UseExistingKey `
            -SessionFactory { [pscustomobject]@{ Authentication = 'Password' } } `
            -RemoteInvoker $remoteInvoker `
            -OperationArmer {
                foreach ($phaseGroup in $args) {
                    foreach ($phase in @($phaseGroup)) {
                        $script:armedReconciliationPhases.Add([string] $phase)
                    }
                }
            } `
            -SessionRemover { } `
            -Clock $script:fixedClock `
            -Confirm:$false

        $result.Succeeded | Should -BeFalse
        $result.DispatchState | Should -BeExactly 'Completed'
        $result.OutcomeStatus | Should -BeExactly 'Failed'
        $result.Installed | Should -BeTrue
        $result.ReconciliationAttempted | Should -BeTrue
        $result.ReconciliationSucceeded | Should -BeTrue
        $result.ReconciliationPresent | Should -BeTrue
        $result.RollbackAttempted | Should -BeTrue
        $result.RollbackSucceeded | Should -BeTrue
        @($script:phaseCalls) | Should -Be @('Install', 'Reconcile', 'Rollback')
        @($script:armedReconciliationPhases) | Should -Contain 'BootstrapReconcile'
        @($script:rollbackArguments).Count | Should -Be 1
        $script:rollbackArguments[0] | Should -BeExactly (
            Get-HHSshBootstrapPublicKey -KeyPath $script:keyPath
        ).ExactLine
    }

    It 'reconciles an uncertain install as absent without retry or rollback' {
        Write-HHBootstrapTestKeyPair -Path $script:keyPath
        $script:installCalls = 0
        $script:rollbackCalls = 0
        $remoteInvoker = {
            param($session, $remoteScript, $argumentList)
            $null = $session
            $null = $argumentList
            $text = $remoteScript.ToString()
            if ($text.Contains('HostHunter.PowerShellIdentity.v1')) {
                New-HHBootstrapIdentity
            }
            elseif ($text.Contains('HostHunterAuthorizedKeyInstall.v1')) {
                $script:installCalls++
                $failure = New-HHSshClassifiedException `
                    -FailureKind TransportFailure `
                    -Message 'uncertain install result'
                $failure.Data['HHDispatchState'] = 'DispatchUncertain'
                throw $failure
            }
            elseif ($text.Contains('HostHunterAuthorizedKeyReconciliation.v1')) {
                [pscustomobject]@{
                    Operation = 'HostHunterAuthorizedKeyReconciliation.v1'
                    Present = $false
                    ExactMatchCount = 0
                }
            }
            elseif ($text.Contains('HostHunterAuthorizedKeyRollback.v1')) {
                $script:rollbackCalls++
            }
        }
        $result = Invoke-HHSshKeyBootstrap `
            -Target $script:passwordTarget `
            -KnownHostsPath $script:knownHostsPath `
            -KeyPath $script:keyPath `
            -UseExistingKey `
            -SessionFactory { [pscustomobject]@{ Authentication = 'Password' } } `
            -RemoteInvoker $remoteInvoker `
            -SessionRemover { } `
            -Clock $script:fixedClock `
            -Confirm:$false

        $result.Installed | Should -BeFalse
        $result.ReconciliationSucceeded | Should -BeTrue
        $result.ReconciliationPresent | Should -BeFalse
        $result.RollbackAttempted | Should -BeFalse
        $result.DispatchState | Should -BeExactly 'Completed'
        $result.OutcomeStatus | Should -BeExactly 'Failed'
        $script:installCalls | Should -Be 1
        $script:rollbackCalls | Should -Be 0
    }

    It 'returns Unknown when exact-line reconciliation cannot prove install state' {
        Write-HHBootstrapTestKeyPair -Path $script:keyPath
        $script:installCalls = 0
        $remoteInvoker = {
            param($session, $remoteScript, $argumentList)
            $null = $session
            $null = $argumentList
            $text = $remoteScript.ToString()
            if ($text.Contains('HostHunter.PowerShellIdentity.v1')) {
                New-HHBootstrapIdentity
            }
            elseif ($text.Contains('HostHunterAuthorizedKeyInstall.v1')) {
                $script:installCalls++
                $failure = New-HHSshClassifiedException `
                    -FailureKind TransportFailure `
                    -Message 'uncertain install result'
                $failure.Data['HHDispatchState'] = 'Dispatched'
                throw $failure
            }
            elseif ($text.Contains('HostHunterAuthorizedKeyReconciliation.v1')) {
                $failure = New-HHSshClassifiedException `
                    -FailureKind TransportFailure `
                    -Message 'reconciliation transport failed'
                $failure.Data['HHStreamEvents'] = @(
                    New-HHSshStreamEvent `
                        -Sequence 0 `
                        -Phase BootstrapReconcile `
                        -InputObject 'partial reconciliation evidence' `
                        -Clock $script:fixedClock
                )
                throw $failure
            }
        }
        $result = Invoke-HHSshKeyBootstrap `
            -Target $script:passwordTarget `
            -KnownHostsPath $script:knownHostsPath `
            -KeyPath $script:keyPath `
            -UseExistingKey `
            -SessionFactory { [pscustomobject]@{ Authentication = 'Password' } } `
            -RemoteInvoker $remoteInvoker `
            -SessionRemover { } `
            -Clock $script:fixedClock `
            -Confirm:$false

        $result.Installed | Should -BeNullOrEmpty
        $result.ReconciliationAttempted | Should -BeTrue
        $result.ReconciliationSucceeded | Should -BeFalse
        $result.ReconciliationPresent | Should -BeNullOrEmpty
        $result.RollbackAttempted | Should -BeFalse
        $result.DispatchState | Should -BeExactly 'DispatchUncertain'
        $result.OutcomeStatus | Should -BeExactly 'Unknown'
        $result.ReconciliationRequired | Should -BeTrue
        $script:installCalls | Should -Be 1
    }

    It 'projects cyclic partial ErrorRecord evidence into JSON-safe finite events' {
        Write-HHBootstrapTestKeyPair -Path $script:keyPath
        $remoteInvoker = {
            param($session, $remoteScript, $argumentList)
            $null = $session
            $null = $argumentList
            $text = $remoteScript.ToString()
            if ($text.Contains('HostHunter.PowerShellIdentity.v1')) {
                New-HHBootstrapIdentity
            }
            elseif ($text.Contains('HostHunterAuthorizedKeyInstall.v1')) {
                $cyclicException = [InvalidOperationException]::new('cyclic install error')
                $cyclicException.Data['Self'] = $cyclicException
                $cyclicRecord = [Management.Automation.ErrorRecord]::new(
                    $cyclicException,
                    'CyclicInstall',
                    [Management.Automation.ErrorCategory]::InvalidOperation,
                    $null
                )
                $failure = New-HHSshClassifiedException `
                    -FailureKind TransportFailure `
                    -Message 'uncertain cyclic install result'
                $failure.Data['HHDispatchState'] = 'Dispatched'
                $failure.Data['HHStreamEvents'] = [object[]] @(
                    [pscustomobject]@{
                        Phase = 'BootstrapInstall'
                        Stream = 'Error'
                        TypeName = 'System.Management.Automation.ErrorRecord'
                        RemoteSequence = 0
                        IsTerminating = $true
                        Value = $cyclicRecord
                    }
                )
                throw $failure
            }
            elseif ($text.Contains('HostHunterAuthorizedKeyReconciliation.v1')) {
                [pscustomobject]@{
                    Operation = 'HostHunterAuthorizedKeyReconciliation.v1'
                    Present = $false
                }
            }
        }
        $result = Invoke-HHSshKeyBootstrap `
            -Target $script:passwordTarget `
            -KnownHostsPath $script:knownHostsPath `
            -KeyPath $script:keyPath `
            -UseExistingKey `
            -SessionFactory { [pscustomobject]@{ Authentication = 'Password' } } `
            -RemoteInvoker $remoteInvoker `
            -SessionRemover { } `
            -Clock $script:fixedClock `
            -Confirm:$false

        @($result.StreamEvents.Value | Where-Object {
                $_ -is [Management.Automation.ErrorRecord] -or $_ -is [Exception]
            }).Count | Should -Be 0
        @($result.StreamEvents | Where-Object {
                $_.TypeName -ceq 'System.Management.Automation.ErrorRecord'
            }).Count | Should -Be 1
        { $result.StreamEvents | ConvertTo-Json -Depth 20 -Compress } | Should -Not -Throw
    }

    It 'commits the profile transition before closing the password session and returns a finite receipt' {
        Write-HHBootstrapTestKeyPair -Path $script:keyPath
        $script:lifecycle = [Collections.Generic.List[string]]::new()
        $remoteInvoker = {
            param($session, $remoteScript, $argumentList)
            $null = $session
            if ($remoteScript.ToString().Contains('HostHunter.PowerShellIdentity.v1')) {
                New-HHBootstrapIdentity
            }
            else {
                [pscustomobject]@{
                    Operation = 'HostHunterAuthorizedKeyInstall.v1'
                    Added = $true
                    Marker = $argumentList[1]
                }
            }
        }
        $result = Invoke-HHSshKeyBootstrap `
            -Target $script:passwordTarget `
            -KnownHostsPath $script:knownHostsPath `
            -KeyPath $script:keyPath `
            -UseExistingKey `
            -SessionFactory { param($plan) [pscustomobject]@{ Authentication = $plan.Authentication } } `
            -RemoteInvoker $remoteInvoker `
            -ProfileTransitionCommitter {
                param($transition, $expectedTarget, $prepared)
                $transition.Authentication | Should -BeExactly 'PublicKey'
                $expectedTarget.Authentication | Should -BeExactly 'Password'
                $prepared.KeyMaterial.ExactLine | Should -Match '^ssh-ed25519 '
                $script:lifecycle.Add('Commit')
                [pscustomobject]@{
                    Committed = $true
                    PreviousTarget = $expectedTarget
                    CurrentTarget = $transition
                }
            } `
            -SessionRemover {
                param($session)
                $script:lifecycle.Add("Close-$($session.Authentication)")
            } `
            -Clock $script:fixedClock `
            -Confirm:$false

        $result.Succeeded | Should -BeTrue
        $result.CommitState | Should -BeExactly 'Committed'
        $result.CommitReceipt.Committed | Should -BeTrue
        $result.Installed | Should -BeTrue
        $result.RollbackAttempted | Should -BeFalse
        $result.RollbackSucceeded | Should -BeNullOrEmpty
        $result.ReconciliationRequired | Should -BeFalse
        @($result.CommitReceipt.PSObject.Properties.Name) | Should -Be @(
            'Committed',
            'TargetName',
            'PreviousAuthentication',
            'CurrentAuthentication',
            'ReceiptType'
        )
        @($script:lifecycle) | Should -Be @('Commit', 'Close-PublicKey', 'Close-Password')
        $result.RemotePowerShellVersion | Should -BeExactly '7.6.5'
        $result.RemotePSEdition | Should -BeExactly 'Core'
        $result.ExecutionMode | Should -BeExactly 'Direct'
        $result.HostKeyFingerprint | Should -BeExactly $script:hostFingerprint
        $result.RemoteIdentity.Marker | Should -BeExactly 'HostHunter.PowerShellIdentity.v1'
        $result.ValidatedAtUtc | Should -BeExactly '2026-08-23T01:02:03.0000000+00:00'
    }

    It 'rolls back an exact added line on deterministic pre-commit failure' {
        Write-HHBootstrapTestKeyPair -Path $script:keyPath
        $script:rollbackCalls = 0
        $script:armedRollbackPhases = [Collections.Generic.List[string]]::new()
        $remoteInvoker = {
            param($session, $remoteScript, $argumentList)
            $null = $session
            $null = $argumentList
            $text = $remoteScript.ToString()
            if ($text.Contains('HostHunter.PowerShellIdentity.v1')) {
                New-HHBootstrapIdentity
            }
            elseif ($text.Contains('HostHunterAuthorizedKeyInstall.v1')) {
                [pscustomobject]@{
                    Operation = 'HostHunterAuthorizedKeyInstall.v1'
                    Added = $true
                }
            }
            elseif ($text.Contains('HostHunterAuthorizedKeyRollback.v1')) {
                $script:rollbackCalls++
                [pscustomobject]@{
                    Operation = 'HostHunterAuthorizedKeyRollback.v1'
                    Removed = $true
                    PresentAfter = $false
                }
            }
        }
        $result = Invoke-HHSshKeyBootstrap `
            -Target $script:passwordTarget `
            -KnownHostsPath $script:knownHostsPath `
            -KeyPath $script:keyPath `
            -UseExistingKey `
            -SessionFactory { param($plan) [pscustomobject]@{ Authentication = $plan.Authentication } } `
            -RemoteInvoker $remoteInvoker `
            -OperationArmer {
                foreach ($phaseGroup in $args) {
                    foreach ($phase in @($phaseGroup)) {
                        $script:armedRollbackPhases.Add([string] $phase)
                    }
                }
            } `
            -ProfileTransitionCommitter { throw 'compare-and-swap precondition failed' } `
            -SessionRemover { } `
            -Clock $script:fixedClock `
            -Confirm:$false

        $result.Succeeded | Should -BeFalse
        $result.CommitState | Should -BeExactly 'Failed'
        $result.RollbackAttempted | Should -BeTrue
        $result.RollbackSucceeded | Should -BeTrue
        $result.DispatchState | Should -BeExactly 'Completed'
        $result.OutcomeStatus | Should -BeExactly 'Failed'
        $result.ReconciliationRequired | Should -BeFalse
        $script:rollbackCalls | Should -Be 1
        @($script:armedRollbackPhases) | Should -Contain 'BootstrapRollback'
    }

    It 'does not blindly roll back when target-store commit state is Unknown' {
        $script:rollbackCalls = 0
        $remoteInvoker = {
            param($session, $remoteScript, $argumentList)
            $null = $session
            $null = $argumentList
            $text = $remoteScript.ToString()
            if ($text.Contains('HostHunter.PowerShellIdentity.v1')) {
                New-HHBootstrapIdentity
            }
            elseif ($text.Contains('HostHunterAuthorizedKeyInstall.v1')) {
                [pscustomobject]@{
                    Operation = 'HostHunterAuthorizedKeyInstall.v1'
                    Added = $true
                }
            }
            elseif ($text.Contains('HostHunterAuthorizedKeyRollback.v1')) {
                $script:rollbackCalls++
            }
        }
        $result = Invoke-HHSshKeyBootstrap `
            -Target $script:passwordTarget `
            -KnownHostsPath $script:knownHostsPath `
            -KeyPath $script:keyPath `
            -KeyGenerator { param($path) Write-HHBootstrapTestKeyPair -Path $path } `
            -SessionFactory { param($plan) [pscustomobject]@{ Authentication = $plan.Authentication } } `
            -RemoteInvoker $remoteInvoker `
            -ProfileTransitionCommitter {
                $failure = [InvalidOperationException]::new('commit read-back was inconclusive')
                $failure.Data['HHTargetStoreCommitState'] = 'Unknown'
                throw $failure
            } `
            -SessionRemover { } `
            -Clock $script:fixedClock `
            -Confirm:$false

        $result.Succeeded | Should -BeFalse
        $result.CommitState | Should -BeExactly 'Unknown'
        $result.Installed | Should -BeTrue
        $result.RollbackAttempted | Should -BeFalse
        $result.RollbackSucceeded | Should -BeNullOrEmpty
        $result.OutcomeStatus | Should -BeExactly 'Unknown'
        $result.ReconciliationRequired | Should -BeTrue
        $result.ProfileTransition.Authentication | Should -BeExactly 'PublicKey'
        $script:rollbackCalls | Should -Be 0
        Test-Path -LiteralPath $script:keyPath | Should -BeTrue
        Test-Path -LiteralPath "$script:keyPath.pub" | Should -BeTrue
    }

    It 'treats missing or unproven commit receipts as Unknown without blind rollback' {
        Write-HHBootstrapTestKeyPair -Path $script:keyPath
        $script:rollbackCalls = 0
        $remoteInvoker = {
            param($session, $remoteScript, $argumentList)
            $null = $session
            $null = $argumentList
            $text = $remoteScript.ToString()
            if ($text.Contains('HostHunter.PowerShellIdentity.v1')) {
                New-HHBootstrapIdentity
            }
            elseif ($text.Contains('HostHunterAuthorizedKeyInstall.v1')) {
                [pscustomobject]@{
                    Operation = 'HostHunterAuthorizedKeyInstall.v1'
                    Added = $true
                }
            }
            elseif ($text.Contains('HostHunterAuthorizedKeyRollback.v1')) {
                $script:rollbackCalls++
            }
        }
        $invokeParameters = @{
            Target = $script:passwordTarget
            KnownHostsPath = $script:knownHostsPath
            KeyPath = $script:keyPath
            UseExistingKey = $true
            SessionFactory = {
                param($plan)
                [pscustomobject]@{ Authentication = $plan.Authentication }
            }
            RemoteInvoker = $remoteInvoker
            SessionRemover = { }
            Clock = $script:fixedClock
            Confirm = $false
        }

        $missingReceipt = Invoke-HHSshKeyBootstrap @invokeParameters `
            -ProfileTransitionCommitter { return }
        $unprovenReceipt = Invoke-HHSshKeyBootstrap @invokeParameters `
            -ProfileTransitionCommitter { [pscustomobject]@{ Committed = $false } }

        foreach ($result in @($missingReceipt, $unprovenReceipt)) {
            $result.Succeeded | Should -BeFalse
            $result.FailureKind | Should -BeExactly 'TransportFailure'
            $result.CommitState | Should -BeExactly 'Unknown'
            $result.OutcomeStatus | Should -BeExactly 'Unknown'
            $result.ReconciliationRequired | Should -BeTrue
            $result.RollbackAttempted | Should -BeFalse
        }
        $script:rollbackCalls | Should -Be 0
    }

    It 'enforces one cumulative byte budget and does not start a phase with no remainder' {
        Write-HHBootstrapTestKeyPair -Path $script:keyPath
        $successInvoker = {
            param($session, $remoteScript, $argumentList)
            $null = $session
            $null = $argumentList
            if ($remoteScript.ToString().Contains('HostHunter.PowerShellIdentity.v1')) {
                New-HHBootstrapIdentity
            }
            else {
                [pscustomobject]@{
                    Operation = 'HostHunterAuthorizedKeyInstall.v1'
                    Added = $true
                }
            }
        }
        $baseline = Invoke-HHSshKeyBootstrap `
            -Target $script:passwordTarget `
            -KnownHostsPath $script:knownHostsPath `
            -KeyPath $script:keyPath `
            -UseExistingKey `
            -SessionFactory { param($plan) [pscustomobject]@{ Authentication = $plan.Authentication } } `
            -RemoteInvoker $successInvoker `
            -SessionRemover { } `
            -Clock $script:fixedClock `
            -Confirm:$false
        $baseline.Succeeded | Should -BeTrue
        $budgetThroughInstall = [long] (
            @($baseline.StreamEvents | Select-Object -First 2 | Measure-Object `
                    -Property SerializedByteCount `
                    -Sum).Sum
        )

        $script:sessionAuthentications = [Collections.Generic.List[string]]::new()
        $script:identityCalls = 0
        $script:installCalls = 0
        $script:rollbackCalls = 0
        $boundedInvoker = {
            param($session, $remoteScript, $argumentList)
            $null = $session
            $null = $argumentList
            $text = $remoteScript.ToString()
            if ($text.Contains('HostHunter.PowerShellIdentity.v1')) {
                $script:identityCalls++
                New-HHBootstrapIdentity
            }
            elseif ($text.Contains('HostHunterAuthorizedKeyInstall.v1')) {
                $script:installCalls++
                [pscustomobject]@{
                    Operation = 'HostHunterAuthorizedKeyInstall.v1'
                    Added = $true
                }
            }
            elseif ($text.Contains('HostHunterAuthorizedKeyRollback.v1')) {
                $script:rollbackCalls++
            }
        }
        $bounded = Invoke-HHSshKeyBootstrap `
            -Target $script:passwordTarget `
            -KnownHostsPath $script:knownHostsPath `
            -KeyPath $script:keyPath `
            -UseExistingKey `
            -MaxOutputBytes $budgetThroughInstall `
            -SessionFactory {
                param($plan)
                $script:sessionAuthentications.Add([string] $plan.Authentication)
                [pscustomobject]@{ Authentication = $plan.Authentication }
            } `
            -RemoteInvoker $boundedInvoker `
            -SessionRemover { } `
            -Clock $script:fixedClock `
            -Confirm:$false

        $bounded.Succeeded | Should -BeFalse
        $bounded.OutputBytes | Should -BeLessOrEqual $budgetThroughInstall
        @($bounded.StreamEvents | Measure-Object -Property SerializedByteCount -Sum).Sum |
            Should -Be $bounded.OutputBytes
        @($script:sessionAuthentications) | Should -Be @('Password')
        $script:identityCalls | Should -Be 1
        $script:installCalls | Should -Be 1
        $script:rollbackCalls | Should -Be 0
        $bounded.RollbackRequired | Should -BeTrue
        $bounded.RollbackAttempted | Should -BeFalse
        $bounded.RollbackSucceeded | Should -BeNullOrEmpty
        $bounded.OutcomeStatus | Should -BeExactly 'Unknown'
        $bounded.EvidenceTruncated | Should -BeTrue
    }

    It 'does not start installation when password identity consumes the cumulative budget' {
        Write-HHBootstrapTestKeyPair -Path $script:keyPath
        $baseline = Invoke-HHSshKeyBootstrap `
            -Target $script:passwordTarget `
            -KnownHostsPath $script:knownHostsPath `
            -KeyPath $script:keyPath `
            -UseExistingKey `
            -SessionFactory {
                param($plan)
                [pscustomobject]@{ Authentication = $plan.Authentication }
            } `
            -RemoteInvoker {
                param($session, $remoteScript, $argumentList)
                $null = $session
                $null = $argumentList
                if ($remoteScript.ToString().Contains('HostHunter.PowerShellIdentity.v1')) {
                    New-HHBootstrapIdentity
                }
                else {
                    [pscustomobject]@{
                        Operation = 'HostHunterAuthorizedKeyInstall.v1'
                        Added = $false
                    }
                }
            } `
            -SessionRemover { } `
            -Clock $script:fixedClock `
            -Confirm:$false
        $identityBudget = [long] $baseline.StreamEvents[0].SerializedByteCount

        $script:installCalls = 0
        $bounded = Invoke-HHSshKeyBootstrap `
            -Target $script:passwordTarget `
            -KnownHostsPath $script:knownHostsPath `
            -KeyPath $script:keyPath `
            -UseExistingKey `
            -MaxOutputBytes $identityBudget `
            -SessionFactory {
                param($plan)
                [pscustomobject]@{ Authentication = $plan.Authentication }
            } `
            -RemoteInvoker {
                param($session, $remoteScript, $argumentList)
                $null = $session
                $null = $argumentList
                if ($remoteScript.ToString().Contains('HostHunter.PowerShellIdentity.v1')) {
                    New-HHBootstrapIdentity
                }
                else {
                    $script:installCalls++
                }
            } `
            -SessionRemover { } `
            -Clock $script:fixedClock `
            -Confirm:$false

        $bounded.Succeeded | Should -BeFalse
        $bounded.FailureKind | Should -BeExactly 'OutputLimitExceeded'
        $bounded.DispatchState | Should -BeExactly 'NotDispatched'
        $bounded.OutcomeStatus | Should -BeExactly 'Failed'
        $bounded.Installed | Should -BeFalse
        $bounded.RollbackAttempted | Should -BeFalse
        $bounded.OutputBytes | Should -Be $identityBudget
        $script:installCalls | Should -Be 0
    }

    It 'fails finitely on session cleanup failure without revoking a proven profile transition' {
        $script:removeAttempts = 0
        $sessionFactory = {
            param($plan)
            [pscustomobject]@{ Authentication = $plan.Authentication }
        }
        $remoteInvoker = {
            param($session, $remoteScript, $argumentList)
            $null = $session
            $null = $argumentList
            $text = $remoteScript.ToString()
            if ($text.Contains('HostHunter.PowerShellIdentity.v1')) {
                New-HHBootstrapIdentity
            }
            else {
                [pscustomobject]@{
                    Operation = 'HostHunterAuthorizedKeyInstall.v1'
                    Added = $true
                    AuthorizedKeysPath = '/home/operator/.ssh/authorized_keys'
                }
            }
        }
        $result = Invoke-HHSshKeyBootstrap `
            -Target $script:passwordTarget `
            -KnownHostsPath $script:knownHostsPath `
            -KeyPath $script:keyPath `
            -KeyGenerator { param($path) Write-HHBootstrapTestKeyPair -Path $path } `
            -SessionFactory $sessionFactory `
            -RemoteInvoker $remoteInvoker `
            -SessionRemover { $script:removeAttempts++; throw 'forced close failure' } `
            -Confirm:$false

        $result.Succeeded | Should -BeFalse
        $result.FailureKind | Should -BeExactly 'TransportFailure'
        $result.DispatchState | Should -BeExactly 'Completed'
        $result.OutcomeStatus | Should -BeExactly 'Failed'
        $result.ProfileTransition.Authentication | Should -Be 'PublicKey'
        $result.SessionRemovalFailure | Should -BeTrue
        $script:removeAttempts | Should -Be 2
    }
}
