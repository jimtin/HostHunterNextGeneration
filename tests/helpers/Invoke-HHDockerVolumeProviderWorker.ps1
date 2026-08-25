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
    param(
        $WorkerDataRoot,
        $WorkerSecretRoot,
        $WorkerAnchorRoot,
        $WorkerReadyPath,
        $WorkerStartPath,
        $WorkerResultPath,
        $WorkerMode,
        $WorkerOffset
    )

    function New-HHWorkerForensicsAnchor {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
            'PSUseShouldProcessForStateChangingFunctions',
            '',
            Justification = 'Creates an in-memory integration fixture only.'
        )]
        param([long]$Generation, [byte]$ByteOffset)

        return [pscustomobject]@{
            Schema = 'hosthunter.forensics-anchor/1'
            Service = 'HostHunterNextGeneration.Forensics.v1'
            Account = 'ledger-anchor'
            DatabaseId = [byte[]](0..15 | ForEach-Object {
                    [byte]($_ + $ByteOffset)
                })
            SchemaVersion = 1L
            SchemaFingerprint = [byte[]](16..47 | ForEach-Object {
                    [byte]($_ + $ByteOffset)
                })
            Generation = $Generation
            StateDigest = [byte[]](48..79 | ForEach-Object {
                    [byte]($_ + $ByteOffset)
                })
            StateMac = [byte[]](80..111 | ForEach-Object {
                    [byte]($_ + $ByteOffset)
                })
            ProjectionDigest = [byte[]](112..143 | ForEach-Object {
                    [byte]($_ + $ByteOffset)
                })
            ProjectionMac = [byte[]](144..175 | ForEach-Object {
                    [byte]($_ + $ByteOffset)
                })
            AnchorMac = [byte[]](176..207 | ForEach-Object {
                    [byte]($_ + $ByteOffset)
                })
        }
    }

    function Wait-HHWorkerStartSignal {
        [CmdletBinding()]
        param([Parameter(Mandatory)][string]$Path)

        $deadline = [DateTime]::UtcNow.AddSeconds(15)
        while (-not [IO.File]::Exists($Path)) {
            if ([DateTime]::UtcNow -ge $deadline) {
                throw 'The Docker-volume provider worker start signal timed out.'
            }
            Start-Sleep -Milliseconds 20
        }
    }

    $provider = New-HHDockerVolumePersistenceProvider `
        -DataRoot $WorkerDataRoot -SecretRoot $WorkerSecretRoot `
        -AnchorRoot $WorkerAnchorRoot
    $context = [pscustomobject]@{ DataRoot = $WorkerDataRoot }
    $providedKey = & $provider.ForensicsKeyProvider
    [Array]::Clear($providedKey.KeyBytes, 0, $providedKey.KeyBytes.Length)

    if ($WorkerMode -eq 'Initialize') {
        $expected = $null
        $newAnchor = New-HHWorkerForensicsAnchor `
            -Generation 0 -ByteOffset ([byte]$WorkerOffset)
        $successStatus = 'INITIALIZED'
        $failureStatus = 'DUPLICATE'
    }
    else {
        $expected = & $provider.ForensicsAnchorReader $context
        if ($null -eq $expected) {
            throw 'The advance worker requires an initialized anchor.'
        }
        $newAnchor = New-HHWorkerForensicsAnchor `
            -Generation ([long]$expected.Generation + 1) `
            -ByteOffset ([byte]$WorkerOffset)
        $successStatus = 'ADVANCED'
        $failureStatus = 'STALE'
    }

    [IO.File]::WriteAllText($WorkerReadyPath, 'READY')
    Wait-HHWorkerStartSignal -Path $WorkerStartPath
    $status = $successStatus
    try {
        & $provider.ForensicsAnchorWriter $expected $newAnchor $context
    }
    catch {
        $errorId = ($_.FullyQualifiedErrorId -split ',', 2)[0]
        if ($errorId -ne 'DockerVolumeAnchorCompareFailed') { throw }
        $status = $failureStatus
    }

    $readback = & $provider.ForensicsAnchorReader $context
    if ($null -eq $readback -or
        [long]$readback.Generation -ne [long]$newAnchor.Generation) {
        throw 'The Docker-volume provider worker could not verify the committed anchor.'
    }
    [IO.File]::WriteAllText($WorkerResultPath, $status)
} $DataRoot $SecretRoot $AnchorRoot $ReadyPath $StartPath $ResultPath $Mode $Offset

