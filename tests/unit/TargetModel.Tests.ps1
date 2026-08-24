BeforeAll {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    $sourceRoot = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
        Join-Path $repoRoot 'src/HostHunterNextGeneration'
    }
    else {
        $env:HH_TEST_SOURCE_ROOT
    }
    . (Join-Path $sourceRoot 'Private/TargetModel.ps1')

    function Get-TestTarget {
        param(
            [string] $Name = 'alpha',
            [string] $Transport = 'SSH',
            [string] $HostName = 'alpha.example.test',
            [int] $Port = 22,
            [string] $Authentication = 'Password',
            [ValidateSet('PowerShell7', 'WindowsPowerShell51')]
            [string] $PowerShellRuntime = 'PowerShell7',
            [AllowNull()][string] $HostKeyFingerprint = 'SHA256:alpha',
            [AllowNull()][string] $KeyPath = $null,
            [bool] $IsActive = $true,
            [object] $LastValidatedAtUtc = '2026-08-23T00:00:00Z',
            [string] $LastValidatedPSEdition,
            [string] $LastValidatedPowerShellVersion,
            [string] $LastValidatedExecutionMode
        )

        if (-not $PSBoundParameters.ContainsKey('LastValidatedPSEdition')) {
            $LastValidatedPSEdition = if ($PowerShellRuntime -ceq 'WindowsPowerShell51') {
                'Desktop'
            }
            else {
                'Core'
            }
        }
        if (-not $PSBoundParameters.ContainsKey('LastValidatedPowerShellVersion')) {
            $LastValidatedPowerShellVersion = if ($PowerShellRuntime -ceq 'WindowsPowerShell51') {
                '5.1.26100.1'
            }
            else {
                '7.6.5'
            }
        }
        if (-not $PSBoundParameters.ContainsKey('LastValidatedExecutionMode')) {
            $LastValidatedExecutionMode = if ($PowerShellRuntime -ceq 'WindowsPowerShell51') {
                'WindowsPowerShellCompatibility'
            }
            else {
                'Direct'
            }
        }

        $parameters = @{
            Name                               = $Name
            Transport                          = $Transport
            HostName                           = $HostName
            Port                               = $Port
            UserName                           = 'operator'
            Authentication                     = $Authentication
            PowerShellRuntime                  = $PowerShellRuntime
            HostKeyFingerprint                 = $HostKeyFingerprint
            KeyPath                            = $KeyPath
            IsActive                           = $IsActive
            LastValidatedAtUtc                 = $LastValidatedAtUtc
            LastValidatedPSEdition             = $LastValidatedPSEdition
            LastValidatedPowerShellVersion     = $LastValidatedPowerShellVersion
            LastValidatedExecutionMode         = $LastValidatedExecutionMode
        }
        New-HHTargetRecord @parameters
    }
}

Describe 'Target schema v2 model' -Tag 'Unit' {
    BeforeEach {
        $env:HH_COVERAGE_CASE = [Guid]::NewGuid().ToString('N')
    }

    It 'normalizes a valid SSH password target without adding secret fields' {
        $target = New-HHTargetRecord `
            -Name '  Alpha  ' `
            -Transport SSH `
            -HostName 'alpha.example.test' `
            -Port 22 `
            -UserName '  operator  ' `
            -Authentication Password `
            -HostKeyFingerprint '  SHA256:alpha  ' `
            -KeyPath $null `
            -IsActive $true `
            -LastValidatedAtUtc '2026-08-23T10:00:00+10:00' `
            -LastValidatedPSEdition Core `
            -LastValidatedPowerShellVersion '7.6.5' `
            -LastValidatedExecutionMode Direct

        $target.Name | Should -BeExactly 'Alpha'
        $target.UserName | Should -BeExactly 'operator'
        $target.HostKeyFingerprint | Should -BeExactly 'SHA256:alpha'
        $target.LastValidatedAtUtc | Should -BeExactly '2026-08-23T00:00:00.0000000Z'
        $target.PowerShellRuntime | Should -BeExactly 'PowerShell7'
        $target.LastValidatedPSEdition | Should -BeExactly 'Core'
        $target.LastValidatedPowerShellVersion | Should -BeExactly '7.6.5'
        $target.LastValidatedExecutionMode | Should -BeExactly 'Direct'
        $target.PSObject.TypeNames[0] | Should -BeExactly 'HostHunter.Target'
        @($target.PSObject.Properties.Name) | Should -Not -Contain 'PasswordValue'
        @($target.PSObject.Properties.Name) | Should -Not -Contain 'Secret'
    }

    It 'accepts a public-key SSH target with an absolute key path and nullable fingerprint' {
        $target = Get-TestTarget `
            -Authentication PublicKey `
            -KeyPath '/keys/hosthunter_ed25519' `
            -HostKeyFingerprint $null

        $target.Authentication | Should -BeExactly 'PublicKey'
        $target.KeyPath | Should -BeExactly '/keys/hosthunter_ed25519'
        $target.HostKeyFingerprint | Should -BeNullOrEmpty
    }

    It 'accepts WinRM Kerberos and Certificate records' {
        $kerberos = Get-TestTarget `
            -Name 'win-kerberos' `
            -Transport WinRM `
            -HostName 'win-one.example.test' `
            -Port 5985 `
            -Authentication Kerberos `
            -HostKeyFingerprint $null
        $certificate = Get-TestTarget `
            -Name 'win-certificate' `
            -Transport WinRM `
            -HostName 'win-two.example.test' `
            -Port 5986 `
            -Authentication Certificate `
            -HostKeyFingerprint $null

        $kerberos.Transport | Should -BeExactly 'WinRM'
        $certificate.Authentication | Should -BeExactly 'Certificate'
    }

    It 'creates a canonical Windows PowerShell 5.1 compatibility record' {
        $target = Get-TestTarget `
            -PowerShellRuntime WindowsPowerShell51 `
            -LastValidatedPSEdition Desktop `
            -LastValidatedPowerShellVersion '5.1.26100.9168' `
            -LastValidatedExecutionMode WindowsPowerShellCompatibility

        $target.PowerShellRuntime | Should -BeExactly 'WindowsPowerShell51'
        $target.LastValidatedPSEdition | Should -BeExactly 'Desktop'
        $target.LastValidatedPowerShellVersion | Should -BeExactly '5.1.26100.9168'
        $target.LastValidatedExecutionMode | Should -BeExactly 'WindowsPowerShellCompatibility'
    }

    It 'accepts UTC DateTime and DateTimeOffset validation timestamps' {
        $utcDate = [datetime]::SpecifyKind([datetime] '2026-08-23T00:00:00', [DateTimeKind]::Utc)
        $dateTarget = Get-TestTarget -LastValidatedAtUtc $utcDate
        $offsetTarget = Get-TestTarget `
            -Name 'offset' `
            -HostName 'offset.example.test' `
            -LastValidatedAtUtc ([datetimeoffset] '2026-08-23T10:00:00+10:00')

        $dateTarget.LastValidatedAtUtc | Should -BeExactly '2026-08-23T00:00:00.0000000Z'
        $offsetTarget.LastValidatedAtUtc | Should -BeExactly '2026-08-23T00:00:00.0000000Z'
    }

    It 'rejects invalid name host and user values' {
        { Get-TestTarget -Name ' ' } | Should -Throw -ExpectedMessage '*Target Name*'
        { Get-TestTarget -Name "bad`nname" } | Should -Throw -ExpectedMessage '*null or newline*'
        { Get-TestTarget -Name ('a' * 129) } | Should -Throw -ExpectedMessage '*128*'
        { Get-TestTarget -HostName 'host name' } | Should -Throw -ExpectedMessage '*HostName*'
        { Get-TestTarget -HostName '...' } | Should -Throw -ExpectedMessage '*host or IP*'
        {
            New-HHTargetRecord `
                -Name alpha -Transport SSH -HostName host -Port 22 -UserName ' ' `
                -Authentication Password -HostKeyFingerprint $null -KeyPath $null `
                -IsActive $true -LastValidatedAtUtc '2026-08-23T00:00:00Z' `
                -LastValidatedPowerShellVersion '7.6.5'
        } | Should -Throw -ExpectedMessage '*UserName*'
    }

    It 'rejects invalid transport authentication combinations' {
        { Get-TestTarget -Authentication Kerberos } |
            Should -Throw -ExpectedMessage '*not supported for SSH*'
        { Get-TestTarget -Authentication Certificate } |
            Should -Throw -ExpectedMessage '*not supported for SSH*'
        {
            Get-TestTarget `
                -Transport WinRM `
                -Authentication PublicKey `
                -KeyPath '/keys/id' `
                -HostKeyFingerprint $null
        } | Should -Throw -ExpectedMessage '*not supported for WinRM*'
    }

    It 'enforces fingerprint and key-path ownership rules' {
        {
            Get-TestTarget `
                -Transport WinRM `
                -Authentication Password `
                -Port 5986
        } | Should -Throw -ExpectedMessage '*only valid for SSH*'
        { Get-TestTarget -HostKeyFingerprint "SHA256:bad`nvalue" } |
            Should -Throw -ExpectedMessage '*Fingerprint is invalid*'
        { Get-TestTarget -Authentication PublicKey -KeyPath $null } |
            Should -Throw -ExpectedMessage '*absolute KeyPath*'
        { Get-TestTarget -Authentication PublicKey -KeyPath 'relative-key' } |
            Should -Throw -ExpectedMessage '*absolute KeyPath*'
        { Get-TestTarget -KeyPath '/keys/not-allowed' } |
            Should -Throw -ExpectedMessage '*only valid for PublicKey*'
    }

    It 'rejects ambiguous and malformed validation timestamps' {
        { Get-TestTarget -LastValidatedAtUtc ([datetime] '2026-08-23T00:00:00') } |
            Should -Throw -ExpectedMessage '*unspecified DateTime*'
        { Get-TestTarget -LastValidatedAtUtc '2026-08-23T00:00:00' } |
            Should -Throw -ExpectedMessage '*explicit offset*'
        { Get-TestTarget -LastValidatedAtUtc 'not-a-dateZ' } |
            Should -Throw -ExpectedMessage '*explicit offset*'
        { Get-TestTarget -LastValidatedAtUtc $null } |
            Should -Throw -ExpectedMessage '*explicit offset*'
    }

    It 'rejects an invalid PowerShell version' {
        { Get-TestTarget -LastValidatedPowerShellVersion 'seven' } |
            Should -Throw -ExpectedMessage '*valid PowerShell version*'
    }

    It 'fails closed on requested and observed runtime mismatches' {
        { Get-TestTarget -LastValidatedPSEdition Desktop } |
            Should -Throw -ExpectedMessage '*PowerShell7 targets require*'
        { Get-TestTarget -LastValidatedPowerShellVersion '5.1' } |
            Should -Throw -ExpectedMessage '*PowerShell7 targets require*'
        { Get-TestTarget -LastValidatedExecutionMode WindowsPowerShellCompatibility } |
            Should -Throw -ExpectedMessage '*PowerShell7 targets require*'
        { Get-TestTarget -PowerShellRuntime WindowsPowerShell51 -LastValidatedPSEdition Core } |
            Should -Throw -ExpectedMessage '*WindowsPowerShell51 targets require*'
        { Get-TestTarget -PowerShellRuntime WindowsPowerShell51 -LastValidatedPowerShellVersion '5.2' } |
            Should -Throw -ExpectedMessage '*WindowsPowerShell51 targets require*'
        { Get-TestTarget -PowerShellRuntime WindowsPowerShell51 -LastValidatedExecutionMode Direct } |
            Should -Throw -ExpectedMessage '*WindowsPowerShell51 targets require*'
        {
            Get-TestTarget `
                -Transport WinRM `
                -Port 5985 `
                -Authentication Password `
                -HostKeyFingerprint $null `
                -PowerShellRuntime WindowsPowerShell51
        } | Should -Throw -ExpectedMessage '*supported only through SSH*'
    }

    It 'converts a complete dictionary into a fresh validated record' {
        $source = Get-TestTarget
        $dictionary = [ordered]@{}
        foreach ($property in $source.PSObject.Properties) {
            $dictionary[$property.Name] = $property.Value
        }

        $converted = ConvertTo-HHValidatedTargetRecord -InputObject $dictionary

        [object]::ReferenceEquals($converted, $source) | Should -BeFalse
        $converted.Name | Should -BeExactly 'alpha'
        $converted.PSObject.TypeNames[0] | Should -BeExactly 'HostHunter.Target'
    }

    It 'fails closed on null missing unexpected case-drifted or non-Boolean fields' {
        { ConvertTo-HHValidatedTargetRecord -InputObject $null } |
            Should -Throw -ExpectedMessage '*cannot be null*'

        $missing = Get-TestTarget | Select-Object -Property * -ExcludeProperty KeyPath
        { ConvertTo-HHValidatedTargetRecord -InputObject $missing } |
            Should -Throw -ExpectedMessage '*missing: KeyPath*'

        $secretBearing = Get-TestTarget | Select-Object *, @{ Name = 'PasswordValue'; Expression = { 'never-store-me' } }
        { ConvertTo-HHValidatedTargetRecord -InputObject $secretBearing } |
            Should -Throw -ExpectedMessage '*unexpected: PasswordValue*'

        $caseDrifted = [ordered]@{}
        foreach ($property in (Get-TestTarget).PSObject.Properties) {
            $name = if ($property.Name -eq 'Name') { 'name' } else { $property.Name }
            $caseDrifted[$name] = $property.Value
        }
        { ConvertTo-HHValidatedTargetRecord -InputObject $caseDrifted } |
            Should -Throw -ExpectedMessage '*missing: Name*unexpected: name*'

        $wrongBoolean = Get-TestTarget | Select-Object *
        $wrongBoolean.IsActive = 'false'
        { ConvertTo-HHValidatedTargetRecord -InputObject $wrongBoolean } |
            Should -Throw -ExpectedMessage '*must be a Boolean*'
    }

    It 'rejects empty sets unless explicitly allowed' {
        { Assert-HHTargetSet -Target @() } | Should -Throw -ExpectedMessage '*At least one*'
        @(Assert-HHTargetSet -Target @() -AllowEmpty).Count | Should -Be 0
    }

    It 'rejects duplicate names case-insensitively' {
        $targets = @(
            Get-TestTarget -Name 'Alpha'
            Get-TestTarget -Name 'alpha' -HostName 'other.example.test'
        )

        { Assert-HHTargetSet -Target $targets } |
            Should -Throw -ExpectedMessage '*duplicate name*'
    }

    It 'rejects equivalent endpoints case-insensitively and without a trailing DNS dot' {
        $targets = @(
            Get-TestTarget -Name 'one' -HostName 'HOST.example.test.'
            Get-TestTarget -Name 'two' -HostName 'host.EXAMPLE.test'
        )

        { Assert-HHTargetSet -Target $targets } |
            Should -Throw -ExpectedMessage '*duplicate endpoint*'
    }

    It 'allows two runtime profiles for the same SSH endpoint' {
        $targets = @(
            Get-TestTarget -Name 'core' -HostName 'dual.example.test' -PowerShellRuntime PowerShell7
            Get-TestTarget `
                -Name 'desktop' `
                -HostName 'DUAL.example.test.' `
                -PowerShellRuntime WindowsPowerShell51
        )

        $validated = @(Assert-HHTargetSet -Target $targets)
        $validated.Count | Should -Be 2
        $validated.PowerShellRuntime | Should -Be @('PowerShell7', 'WindowsPowerShell51')
    }

    It 'allows the same host and port when the transport differs' {
        $targets = @(
            Get-TestTarget -Name 'ssh' -HostName 'dual.example.test'
            Get-TestTarget `
                -Name 'winrm' `
                -Transport WinRM `
                -HostName 'dual.example.test' `
                -Port 22 `
                -Authentication Password `
                -HostKeyFingerprint $null
        )

        @(Assert-HHTargetSet -Target $targets).Count | Should -Be 2
    }

    It 'accepts eight unique targets and rejects a ninth' {
        $eight = @(
            foreach ($index in 1..8) {
                Get-TestTarget `
                    -Name "target-$index" `
                    -HostName "target-$index.example.test"
            }
        )
        @(Assert-HHTargetSet -Target $eight).Count | Should -Be 8

        $nine = @($eight) + @(
            Get-TestTarget -Name 'target-9' -HostName 'target-9.example.test'
        )
        { Assert-HHTargetSet -Target $nine } | Should -Throw -ExpectedMessage '*maximum of eight*'
    }
}
