Set-StrictMode -Version Latest

$script:HHPersistenceAnchorV1Length = 196
$script:HHPersistenceAnchorV1BodyLength = 164
$script:HHPersistenceAnchorV2Length = 236
$script:HHPersistenceAnchorV2BodyLength = 204

function Write-HHInt64BigEndian {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][byte[]]$Buffer,
        [Parameter(Mandatory)][int]$Offset,
        [Parameter(Mandatory)][long]$Value
    )

    for ($index = 0; $index -lt 8; $index++) {
        $shift = (7 - $index) * 8
        $Buffer[$Offset + $index] = [byte](($Value -shr $shift) -band 0xff)
    }
}

function Get-HHInt64BigEndian {
    [CmdletBinding()]
    [OutputType([long])]
    param(
        [Parameter(Mandatory)][byte[]]$Buffer,
        [Parameter(Mandatory)][int]$Offset
    )

    [long]$value = 0
    for ($index = 0; $index -lt 8; $index++) {
        $value = ($value -shl 8) -bor [long]$Buffer[$Offset + $index]
    }
    return $value
}

function ConvertTo-HHPersistenceAnchorArtifact {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)][object]$Anchor,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$MasterKey
    )

    Assert-HHAuditMasterKey -MasterKey $MasterKey
    foreach ($propertyName in @(
            'DatabaseId', 'LedgerId', 'SchemaVersion', 'AuditSequence', 'AuditMac',
            'TargetGeneration', 'TargetStateMac', 'SchemaFingerprint'
        )) {
        if ($null -eq $Anchor.PSObject.Properties[$propertyName]) {
            throw [System.ArgumentException]::new("Anchor is missing $propertyName.", 'Anchor')
        }
    }
    $hasConfigurationHead = $null -ne $Anchor.PSObject.Properties['ConfigurationGeneration'] -or
        $null -ne $Anchor.PSObject.Properties['ConfigurationStateMac']
    if ($hasConfigurationHead -and
        ($null -eq $Anchor.PSObject.Properties['ConfigurationGeneration'] -or
            $null -eq $Anchor.PSObject.Properties['ConfigurationStateMac'])) {
        throw [System.ArgumentException]::new('Anchor configuration fields are incomplete.', 'Anchor')
    }
    if (($Anchor.DatabaseId -isnot [byte[]]) -or $Anchor.DatabaseId.Length -ne 16 -or
        ($Anchor.LedgerId -isnot [byte[]]) -or $Anchor.LedgerId.Length -ne 16 -or
        ($Anchor.AuditMac -isnot [byte[]]) -or $Anchor.AuditMac.Length -ne 32 -or
        ($Anchor.TargetStateMac -isnot [byte[]]) -or $Anchor.TargetStateMac.Length -ne 32 -or
        ($Anchor.SchemaFingerprint -isnot [byte[]]) -or $Anchor.SchemaFingerprint.Length -ne 32 -or
        [long]$Anchor.AuditSequence -lt 0 -or [long]$Anchor.TargetGeneration -lt 0 -or
        [int]$Anchor.SchemaVersion -ne 1 -or
        ($hasConfigurationHead -and
            ([long]$Anchor.ConfigurationGeneration -lt 0 -or
                $Anchor.ConfigurationStateMac -isnot [byte[]] -or
                $Anchor.ConfigurationStateMac.Length -ne 32))) {
        throw [System.ArgumentException]::new('Anchor fields are invalid.', 'Anchor')
    }

    $artifactLength = if ($hasConfigurationHead) {
        $script:HHPersistenceAnchorV2Length
    }
    else { $script:HHPersistenceAnchorV1Length }
    $bodyLength = if ($hasConfigurationHead) {
        $script:HHPersistenceAnchorV2BodyLength
    }
    else { $script:HHPersistenceAnchorV1BodyLength }
    $artifact = [byte[]]::new($artifactLength)
    $magic = [System.Text.Encoding]::ASCII.GetBytes(
        $(if ($hasConfigurationHead) { 'HHANCH02' } else { 'HHANCH01' })
    )
    [Array]::Copy($magic, 0, $artifact, 0, 8)
    $artifact[8] = if ($hasConfigurationHead) { 2 } else { 1 }
    [Array]::Copy($Anchor.DatabaseId, 0, $artifact, 16, 16)
    [Array]::Copy($Anchor.LedgerId, 0, $artifact, 32, 16)
    $artifact[48] = 0
    $artifact[49] = 0
    $artifact[50] = 0
    $artifact[51] = 1
    Write-HHInt64BigEndian -Buffer $artifact -Offset 52 -Value ([long]$Anchor.AuditSequence)
    [Array]::Copy($Anchor.AuditMac, 0, $artifact, 60, 32)
    Write-HHInt64BigEndian -Buffer $artifact -Offset 92 -Value ([long]$Anchor.TargetGeneration)
    [Array]::Copy($Anchor.TargetStateMac, 0, $artifact, 100, 32)
    [Array]::Copy($Anchor.SchemaFingerprint, 0, $artifact, 132, 32)
    if ($hasConfigurationHead) {
        Write-HHInt64BigEndian -Buffer $artifact -Offset 164 `
            -Value ([long]$Anchor.ConfigurationGeneration)
        [Array]::Copy($Anchor.ConfigurationStateMac, 0, $artifact, 172, 32)
    }
    $anchorKey = Get-HHPersistenceDerivedKey -MasterKey $MasterKey -Purpose Anchor
    $body = [byte[]]::new($bodyLength)
    try {
        [Array]::Copy($artifact, 0, $body, 0, $body.Length)
        $mac = Get-HHPersistenceMac -Key $anchorKey -Bytes $body
        try {
            [Array]::Copy($mac, 0, $artifact, $bodyLength, 32)
        }
        finally {
            [Array]::Clear($mac, 0, $mac.Length)
        }
        Write-Output -InputObject $artifact -NoEnumerate
    }
    finally {
        [Array]::Clear($anchorKey, 0, $anchorKey.Length)
        [Array]::Clear($body, 0, $body.Length)
    }
}

function ConvertFrom-HHPersistenceAnchorArtifact {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Artifact,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$MasterKey
    )

    Assert-HHAuditMasterKey -MasterKey $MasterKey
    $magic = if ($Artifact.Length -ge 8) {
        [System.Text.Encoding]::ASCII.GetString($Artifact, 0, 8)
    }
    else { '' }
    $isV1 = $Artifact.Length -eq $script:HHPersistenceAnchorV1Length -and
        $magic -ceq 'HHANCH01' -and $Artifact[8] -eq 1
    $isV2 = $Artifact.Length -eq $script:HHPersistenceAnchorV2Length -and
        $magic -ceq 'HHANCH02' -and $Artifact[8] -eq 2
    if (-not $isV1 -and -not $isV2) {
        Stop-HHPersistenceOperation `
            -ErrorId 'AuditIntegrityFailed' `
            -Message 'The persistence anchor has an invalid format.' `
            -Category ([System.Management.Automation.ErrorCategory]::InvalidData) `
            -TargetObject $null
    }
    $bodyLength = if ($isV2) {
        $script:HHPersistenceAnchorV2BodyLength
    }
    else { $script:HHPersistenceAnchorV1BodyLength }
    $body = [byte[]]::new($bodyLength)
    $storedMac = [byte[]]::new(32)
    $anchorKey = Get-HHPersistenceDerivedKey -MasterKey $MasterKey -Purpose Anchor
    try {
        [Array]::Copy($Artifact, 0, $body, 0, $body.Length)
        [Array]::Copy($Artifact, $bodyLength, $storedMac, 0, 32)
        $expectedMac = Get-HHPersistenceMac -Key $anchorKey -Bytes $body
        try {
            if (-not (Test-HHPersistenceBytesEqual -Left $storedMac -Right $expectedMac)) {
                Stop-HHPersistenceOperation `
                    -ErrorId 'AuditIntegrityFailed' `
                    -Message 'The persistence anchor failed authentication.' `
                    -Category ([System.Management.Automation.ErrorCategory]::SecurityError) `
                    -TargetObject $null
            }
        }
        finally {
            [Array]::Clear($expectedMac, 0, $expectedMac.Length)
        }
    }
    finally {
        [Array]::Clear($body, 0, $body.Length)
        [Array]::Clear($storedMac, 0, $storedMac.Length)
        [Array]::Clear($anchorKey, 0, $anchorKey.Length)
    }

    $databaseId = [byte[]]::new(16)
    $ledgerId = [byte[]]::new(16)
    $auditMac = [byte[]]::new(32)
    $targetStateMac = [byte[]]::new(32)
    $schemaFingerprint = [byte[]]::new(32)
    [Array]::Copy($Artifact, 16, $databaseId, 0, 16)
    [Array]::Copy($Artifact, 32, $ledgerId, 0, 16)
    [Array]::Copy($Artifact, 60, $auditMac, 0, 32)
    [Array]::Copy($Artifact, 100, $targetStateMac, 0, 32)
    [Array]::Copy($Artifact, 132, $schemaFingerprint, 0, 32)
    $anchor = [pscustomobject]@{
        DatabaseId = $databaseId
        LedgerId = $ledgerId
        SchemaVersion = 1
        AuditSequence = Get-HHInt64BigEndian -Buffer $Artifact -Offset 52
        AuditMac = $auditMac
        TargetGeneration = Get-HHInt64BigEndian -Buffer $Artifact -Offset 92
        TargetStateMac = $targetStateMac
        SchemaFingerprint = $schemaFingerprint
        Artifact = [byte[]]$Artifact.Clone()
    }
    if ($isV2) {
        $configurationStateMac = [byte[]]::new(32)
        [Array]::Copy($Artifact, 172, $configurationStateMac, 0, 32)
        $anchor | Add-Member -NotePropertyName ConfigurationGeneration `
            -NotePropertyValue (Get-HHInt64BigEndian -Buffer $Artifact -Offset 164)
        $anchor | Add-Member -NotePropertyName ConfigurationStateMac `
            -NotePropertyValue $configurationStateMac
    }
    return $anchor
}

function Read-HHFilePersistenceAnchor {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$MasterKey
    )

    if (-not [System.IO.File]::Exists($Path)) {
        return $null
    }
    $attributes = [System.IO.File]::GetAttributes($Path)
    if (($attributes -band [System.IO.FileAttributes]::Directory) -ne 0 -or
        ($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        Stop-HHPersistenceOperation `
            -ErrorId 'PersistencePathUnsafe' `
            -Message 'The persistence anchor must be an owner-private regular file.' `
            -Category ([System.Management.Automation.ErrorCategory]::SecurityError) `
            -TargetObject $Path
    }
    if (-not $IsWindows) {
        $requiredMode = [System.IO.UnixFileMode]::UserRead -bor [System.IO.UnixFileMode]::UserWrite
        if ([System.IO.File]::GetUnixFileMode($Path) -ne $requiredMode) {
            Stop-HHPersistenceOperation `
                -ErrorId 'PersistencePathUnsafe' `
                -Message 'The persistence anchor file must have mode 0600.' `
                -Category ([System.Management.Automation.ErrorCategory]::SecurityError) `
            -TargetObject $Path
        }
    }
    else {
        Assert-HHWindowsPrivatePathAcl -Path $Path
    }
    $artifact = [System.IO.File]::ReadAllBytes($Path)
    return ConvertFrom-HHPersistenceAnchorArtifact -Artifact $artifact -MasterKey $MasterKey
}

function Write-HHFilePersistenceAnchor {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [AllowNull()][byte[]]$ExpectedArtifact,
        [Parameter(Mandatory)][byte[]]$NewArtifact
    )

    $current = if ([System.IO.File]::Exists($Path)) {
        [System.IO.File]::ReadAllBytes($Path)
    }
    else { $null }
    $isExpectedMatch = if ($null -eq $ExpectedArtifact) {
        $null -eq $current
    }
    else {
        $null -ne $current -and
            (Test-HHPersistenceBytesEqual -Left $ExpectedArtifact -Right $current)
    }
    if (-not $isExpectedMatch) {
        Stop-HHPersistenceOperation `
            -ErrorId 'AuditIntegrityFailed' `
            -Message 'The persistence anchor changed concurrently or regressed.' `
            -Category ([System.Management.Automation.ErrorCategory]::SecurityError) `
            -TargetObject $Path
    }

    $parentPath = Split-Path -Parent $Path
    $parentExisted = [System.IO.Directory]::Exists($parentPath)
    [System.IO.Directory]::CreateDirectory($parentPath) | Out-Null
    if ($IsWindows) {
        if ($parentExisted) {
            Assert-HHWindowsPrivatePathAcl -Path $parentPath -Directory
        }
        else {
            Protect-HHWindowsPrivatePathAcl -Path $parentPath -Directory
        }
    }
    $temporaryPath = "$Path.$([Guid]::NewGuid().ToString('N')).tmp"
    $options = [System.IO.FileStreamOptions]::new()
    $options.Mode = [System.IO.FileMode]::CreateNew
    $options.Access = [System.IO.FileAccess]::Write
    $options.Share = [System.IO.FileShare]::None
    $options.Options = [System.IO.FileOptions]::WriteThrough
    if (-not $IsWindows) {
        $options.UnixCreateMode = [System.IO.UnixFileMode]::UserRead -bor
            [System.IO.UnixFileMode]::UserWrite
    }
    $stream = $null
    try {
        $stream = [System.IO.File]::Open($temporaryPath, $options)
        $stream.Write($NewArtifact, 0, $NewArtifact.Length)
        $stream.Flush($true)
        $stream.Dispose()
        $stream = $null
        [System.IO.File]::Move($temporaryPath, $Path, $true)
        if ($IsWindows) {
            Protect-HHWindowsPrivatePathAcl -Path $Path
        }
    }
    catch {
        if (Test-Path -LiteralPath $temporaryPath) {
            Remove-Item -LiteralPath $temporaryPath -Force
        }
        throw
    }
    finally {
        if ($null -ne $stream) { $stream.Dispose() }
    }
    $readback = [System.IO.File]::ReadAllBytes($Path)
    if (-not (Test-HHPersistenceBytesEqual -Left $NewArtifact -Right $readback)) {
        Stop-HHPersistenceOperation `
            -ErrorId 'AuditIntegrityFailed' `
            -Message 'The persistence anchor could not be read back exactly.' `
            -Category ([System.Management.Automation.ErrorCategory]::WriteError) `
            -TargetObject $Path
    }
}

function Read-HHPersistenceAnchor {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$PersistenceContext,
        [Parameter(Mandatory)][byte[]]$MasterKey,
        [scriptblock]$AnchorReader
    )

    if ($null -ne $AnchorReader) {
        return & $AnchorReader $PersistenceContext $MasterKey
    }
    if ((Get-HHSecretProviderSelection) -ceq 'DockerVolume') {
        $provider = Get-HHDockerVolumePersistenceProviderFromEnvironment `
            -DataRoot $PersistenceContext.DataRoot
        return & $provider.CoreAnchorReader $PersistenceContext $MasterKey
    }
    if ($IsMacOS) {
        $item = Read-HHMacOSPersistenceAnchorItem -DataRoot $PersistenceContext.DataRoot
        if (-not $item.Found) {
            return $null
        }
        return ConvertFrom-HHPersistenceAnchorArtifact `
            -Artifact ([byte[]]$item.Artifact) `
            -MasterKey $MasterKey
    }
    return Read-HHFilePersistenceAnchor -Path $PersistenceContext.AnchorPath -MasterKey $MasterKey
}

function Write-HHPersistenceAnchor {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$PersistenceContext,
        [Parameter(Mandatory)][object]$Anchor,
        [Parameter(Mandatory)][byte[]]$MasterKey,
        [AllowNull()][byte[]]$ExpectedArtifact,
        [scriptblock]$AnchorWriter
    )

    $newArtifact = ConvertTo-HHPersistenceAnchorArtifact -Anchor $Anchor -MasterKey $MasterKey
    if ($null -ne $AnchorWriter) {
        & $AnchorWriter $PersistenceContext $ExpectedArtifact $newArtifact $MasterKey
        return
    }
    if ((Get-HHSecretProviderSelection) -ceq 'DockerVolume') {
        $provider = Get-HHDockerVolumePersistenceProviderFromEnvironment `
            -DataRoot $PersistenceContext.DataRoot
        & $provider.CoreAnchorWriter $PersistenceContext $ExpectedArtifact `
            $newArtifact $MasterKey
        return
    }
    if ($IsMacOS) {
        if ($null -eq $ExpectedArtifact) {
            New-HHMacOSPersistenceAnchorItem `
                -DataRoot $PersistenceContext.DataRoot `
                -Artifact $newArtifact
        }
        else {
            Update-HHMacOSPersistenceAnchorItem `
                -DataRoot $PersistenceContext.DataRoot `
                -ExpectedArtifact $ExpectedArtifact `
                -NewArtifact $newArtifact
        }
        return
    }
    Write-HHFilePersistenceAnchor `
        -Path $PersistenceContext.AnchorPath `
        -ExpectedArtifact $ExpectedArtifact `
        -NewArtifact $newArtifact
}
