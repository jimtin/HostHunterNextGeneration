[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ModulePath,
    [Parameter(Mandatory)][string]$DataRoot,
    [Parameter(Mandatory)][string]$SecretRoot,
    [Parameter(Mandatory)][string]$AnchorRoot,
    [Parameter(Mandatory)][string]$ReadyPath,
    [Parameter(Mandatory)][string]$StartPath,
    [Parameter(Mandatory)][string]$ResultPath,
    [Parameter(Mandatory)][ValidateSet('Initialize', 'Advance')][string]$Mode,
    [Parameter(Mandatory)][ValidateRange(0, 20)][int]$Offset
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$module = Import-Module $ModulePath -Force -PassThru

& $module {
    param($Data, $Secrets, $Anchors, $Ready, $Start, $Result, $WorkerMode, $ByteOffset)

    function New-WorkerCoreAnchor {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
            'PSUseShouldProcessForStateChangingFunctions',
            '',
            Justification = 'This test helper constructs an in-memory anchor object and does not mutate state.'
        )]
        param([long]$Generation, [byte]$OffsetValue)
        [pscustomobject]@{
            DatabaseId = [byte[]](0..15 | ForEach-Object { [byte]($_ + $OffsetValue) })
            LedgerId = [byte[]](16..31 | ForEach-Object { [byte]($_ + $OffsetValue) })
            SchemaVersion = 1
            AuditSequence = $Generation
            AuditMac = [byte[]](32..63 | ForEach-Object { [byte]($_ + $OffsetValue) })
            TargetGeneration = $Generation
            TargetStateMac = [byte[]](64..95 | ForEach-Object { [byte]($_ + $OffsetValue) })
            SchemaFingerprint = [byte[]](96..127 | ForEach-Object { [byte]($_ + $OffsetValue) })
            ConfigurationGeneration = $Generation
            ConfigurationStateMac = [byte[]](128..159 | ForEach-Object { [byte]($_ + $OffsetValue) })
        }
    }

    $provider = New-HHDockerVolumePersistenceProvider -DataRoot $Data `
        -SecretRoot $Secrets -AnchorRoot $Anchors
    $context = [pscustomobject]@{ DataRoot = $Data }
    $key = & $provider.CoreMasterKeyProvider $context $false
    try {
        $existingAnchor = & $provider.CoreAnchorReader $context $key
        $expected = if ($null -eq $existingAnchor) { $null } else { $existingAnchor.Artifact }
        $generation = if ($null -eq $existingAnchor) { 0L } else { 1L }
        $newArtifact = ConvertTo-HHPersistenceAnchorArtifact `
            -Anchor (New-WorkerCoreAnchor -Generation $generation -OffsetValue ([byte]$ByteOffset)) `
            -MasterKey $key
        if ($WorkerMode -eq 'Initialize') {
            $expected = $null
            $success = 'INITIALIZED'
            $failure = 'DUPLICATE'
        }
        else {
            if ($null -eq $expected) { throw 'Advance requires an initialized anchor.' }
            $success = 'ADVANCED'
            $failure = 'STALE'
        }

        [IO.File]::WriteAllText($Ready, 'READY')
        $deadline = [DateTime]::UtcNow.AddSeconds(15)
        while (-not [IO.File]::Exists($Start)) {
            if ([DateTime]::UtcNow -ge $deadline) { throw 'Worker barrier timed out.' }
            Start-Sleep -Milliseconds 20
        }
        $status = $success
        try { & $provider.CoreAnchorWriter $context $expected $newArtifact $key }
        catch {
            if (($_.FullyQualifiedErrorId -split ',', 2)[0] -ne 'DockerVolumeAnchorCompareFailed') {
                throw
            }
            $status = $failure
        }
        [IO.File]::WriteAllText($Result, $status)
    }
    finally { [Array]::Clear($key, 0, $key.Length) }
} $DataRoot $SecretRoot $AnchorRoot $ReadyPath $StartPath $ResultPath $Mode $Offset
