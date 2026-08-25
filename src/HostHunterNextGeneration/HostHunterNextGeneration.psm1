Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:HHModuleRoot = $PSScriptRoot

$privateFiles = @(Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'Private') -Filter '*.ps1' -File |
        Sort-Object Name)
$publicFiles = @(Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'Public') -Filter '*.ps1' -File |
        Sort-Object Name)

foreach ($file in $privateFiles) {
    . $file.FullName
}

$forensicsRoot = Join-Path $PSScriptRoot 'Forensics'
$forensicsLoadOrderPath = Join-Path $forensicsRoot 'Forensics.LoadOrder.psd1'
if (Test-Path -LiteralPath $forensicsLoadOrderPath -PathType Leaf) {
    $forensicsLoadOrder = Import-PowerShellDataFile -LiteralPath $forensicsLoadOrderPath
    $loadOrderProperties = @($forensicsLoadOrder.Keys | Sort-Object)
    if ($loadOrderProperties.Count -ne 2 -or
        $loadOrderProperties[0] -cne 'PrivateFiles' -or
        $loadOrderProperties[1] -cne 'SchemaVersion' -or
        [int]$forensicsLoadOrder.SchemaVersion -ne 1 -or
        $forensicsLoadOrder.PrivateFiles -isnot [Collections.IList] -or
        $forensicsLoadOrder.PrivateFiles.Count -eq 0) {
        throw [IO.InvalidDataException]::new(
            'The HostHunter Forensics private load-order manifest is invalid.'
        )
    }

    $canonicalForensicsRoot = [IO.Path]::GetFullPath($forensicsRoot)
    $forensicsPrefix = $canonicalForensicsRoot + [IO.Path]::DirectorySeparatorChar
    $seenForensicsFiles = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal
    )
    foreach ($relativePathValue in $forensicsLoadOrder.PrivateFiles) {
        $relativePath = [string]$relativePathValue
        if ([string]::IsNullOrWhiteSpace($relativePath) -or
            [IO.Path]::IsPathRooted($relativePath) -or
            [IO.Path]::GetExtension($relativePath) -cne '.ps1') {
            throw [IO.InvalidDataException]::new(
                'The HostHunter Forensics load order contains an unsafe path.'
            )
        }

        $candidatePath = [IO.Path]::GetFullPath((Join-Path $forensicsRoot $relativePath))
        if (-not $candidatePath.StartsWith($forensicsPrefix, [StringComparison]::Ordinal) -or
            -not $seenForensicsFiles.Add($candidatePath) -or
            -not (Test-Path -LiteralPath $candidatePath -PathType Leaf)) {
            throw [IO.InvalidDataException]::new(
                'The HostHunter Forensics load order is missing, duplicated, or escapes its module root.'
            )
        }
        . $candidatePath
    }
}

foreach ($file in $publicFiles) {
    . $file.FullName
}

Export-ModuleMember -Function @(
    'Set-HHTarget'
    'Get-HHTarget'
    'Test-HHTarget'
    'Remove-HHTarget'
    'Invoke-HHCommand'
    'Enable-HHSshKeyAuthentication'
    'Get-HHAuditRecord'
    'Get-HHAuditOutput'
    'Set-HHWindowsProcessAuditPolicy'
    'Set-HHEscalationPreference'
    'Get-HHEscalationPreference'
)
