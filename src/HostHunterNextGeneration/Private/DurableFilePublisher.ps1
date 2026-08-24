Set-StrictMode -Version Latest

function Get-HHDurablePublisherAssemblyPath {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $packagedPath = Join-Path $PSScriptRoot 'Interop/HostHunter.Persistence.Durability.dll'
    if ([IO.File]::Exists($packagedPath)) {
        return $packagedPath
    }

    $containerPath = '/opt/hosthunter-durability/HostHunter.Persistence.Durability.dll'
    if ([IO.File]::Exists($containerPath)) {
        return $containerPath
    }

    if (-not [string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT) -and
        -not [string]::IsNullOrWhiteSpace($env:HH_DURABILITY_HELPER_ROOT)) {
        $testPath = Join-Path ([IO.Path]::GetFullPath($env:HH_DURABILITY_HELPER_ROOT)) `
            'HostHunter.Persistence.Durability.dll'
        if ([IO.File]::Exists($testPath)) {
            return $testPath
        }
    }

    throw [IO.FileNotFoundException]::new(
        'The HostHunter durable publication helper is unavailable.',
        'HostHunter.Persistence.Durability.dll'
    )
}

function Import-HHDurablePublisherAssembly {
    [CmdletBinding()]
    param()

    if ($null -ne ('HostHunter.Persistence.Durability.DurablePublisher' -as [type])) {
        return
    }

    $assemblyPath = Get-HHDurablePublisherAssemblyPath
    [Reflection.Assembly]::LoadFrom($assemblyPath) | Out-Null
    if ($null -eq ('HostHunter.Persistence.Durability.DurablePublisher' -as [type])) {
        throw [TypeLoadException]::new('The HostHunter durable publication helper has an invalid identity.')
    }
}

function Publish-HHDurableFile {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'The caller already authorized and durably flushed this private staging artifact.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SourcePath,
        [Parameter(Mandatory)][string]$DestinationPath
    )

    Import-HHDurablePublisherAssembly
    [HostHunter.Persistence.Durability.DurablePublisher]::Publish($SourcePath, $DestinationPath)
}
