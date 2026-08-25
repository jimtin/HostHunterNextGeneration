[CmdletBinding()]
param(
    [Parameter(Mandatory)][version]$PowerShellVersion,
    [string]$ModulePathReceipt = '/artifacts/build/module-path.txt',
    [string]$ReceiptPath = '/artifacts/qualification/controller-floor.json'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($PSVersionTable.PSVersion -ne $PowerShellVersion) {
    throw "Expected PowerShell $PowerShellVersion; found $($PSVersionTable.PSVersion)."
}
$minimumPatchedVersion = switch ($PowerShellVersion.Minor) {
    4 { [version]'7.4.19' }
    5 { [version]'7.5.10' }
    6 { [version]'7.6.5' }
    default {
        if ($PowerShellVersion.Major -gt 7 -or
            ($PowerShellVersion.Major -eq 7 -and $PowerShellVersion.Minor -gt 6)) {
            [version]'7.0'
        }
        else {
            [version]'999.0'
        }
    }
}
if ($PSVersionTable.PSEdition -cne 'Core' -or
    $PowerShellVersion -lt $minimumPatchedVersion) {
    throw ('The controller-floor qualification requires PowerShell Core 7.4.19+, ' +
        '7.5.10+, 7.6.5+, or a later supported release.')
}
$modulePath = (Get-Content -LiteralPath $ModulePathReceipt -Raw).Trim()
$module = Import-Module $modulePath -Force -PassThru
$dataRoot = Join-Path ([IO.Path]::GetTempPath()) (
    'hosthunter-controller-floor-' + [Guid]::NewGuid().ToString('N')
)
try {
    $proof = & $module {
        param($QualificationDataRoot)

        $persistence = Get-HHPersistenceContext -DataRoot $QualificationDataRoot
        $context = Open-HHAuthenticatedPersistence `
            -PersistenceContext $persistence -AllowAnchorAdvance
        try {
            [pscustomobject]@{
                SQLiteVersion = [string](Invoke-HHSqliteScalar `
                        -Connection $context.Connection `
                        -Sql 'SELECT sqlite_version();')
                SchemaVersion = [int]$context.Schema.SchemaVersion
                RuntimeIdentifier = Resolve-HHSqliteControllerRid
            }
        }
        finally { Close-HHAuthenticatedPersistence -Context $context }
    } $dataRoot
}
finally {
    Remove-Module $module -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $dataRoot -Recurse -Force -ErrorAction SilentlyContinue
}
if ($proof.SQLiteVersion -cne '3.53.4' -or $proof.SchemaVersion -ne 2 -or
    $proof.RuntimeIdentifier -notin @('linux-x64', 'linux-arm64')) {
    throw 'The minimum controller failed packaged SQLite schema qualification.'
}
[IO.Directory]::CreateDirectory((Split-Path -Parent $ReceiptPath)) | Out-Null
[ordered]@{
    status = 'passed'
    powerShellVersion = $PSVersionTable.PSVersion.ToString()
    powerShellEdition = $PSVersionTable.PSEdition
    sqliteVersion = $proof.SQLiteVersion
    schemaVersion = $proof.SchemaVersion
    runtimeIdentifier = $proof.RuntimeIdentifier
    redacted = $true
} | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $ReceiptPath -Encoding utf8NoBOM
