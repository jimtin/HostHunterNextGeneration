[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('sysmon-1.evtx', 'security-4688.evtx')]
    [string]$FixtureName,

    [Parameter(Mandatory)]
    [ValidatePattern('^[a-f0-9]{64}$')]
    [string]$ExpectedSha256,

    [Parameter(Mandatory)]
    [ValidateRange(1, [int]::MaxValue)]
    [int]$ExpectedRecordCount,

    [Parameter(Mandatory)]
    [ValidateRange(1, [int]::MaxValue)]
    [int]$ExpectedEventCount
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $env:HH_RUNTIME_MODULE_PATH -PathType Leaf)) {
    throw 'The production package manifest is unavailable.'
}
$module = Import-Module $env:HH_RUNTIME_MODULE_PATH -Force -PassThru
$frames = [Collections.Generic.List[object]]::new()
$consumer = { param($Frame) $frames.Add($Frame) }
$completion = & /opt/hosthunter/runtime/Invoke-HHParserSocketClient.ps1 `
    -RelativePath "runtime-verify/$FixtureName" `
    -ExpectedSha256 $ExpectedSha256 `
    -ProvisionalRecordConsumer $consumer `
    -RequireRecords

if ($frames.Count -ne $ExpectedRecordCount) {
    throw "Expected $ExpectedRecordCount parser records but received $($frames.Count)."
}

$result = & $module {
    param($ParserFrames, $ArtifactSha256, $Name)

    $events = [Collections.Generic.List[object]]::new()
    foreach ($frame in $ParserFrames) {
        $bytes = [Text.Encoding]::UTF8.GetBytes([string]$frame.record_json)
        $actualRecordHash = [Convert]::ToHexString(
            (Get-HHForensicsHash -Bytes $bytes)
        ).ToLowerInvariant()
        if ($actualRecordHash -cne [string]$frame.record_sha256) {
            throw [Security.SecurityException]::new(
                'A parser frame record digest did not match its JSON payload.'
            )
        }
        $record = ConvertFrom-HHForensicsJsonLine -Bytes $bytes `
            -SourceOrdinal ([long]$frame.ordinal + 1L) `
            -SourceIdentity $ArtifactSha256
        $context = [pscustomobject]@{
            HostId = 'runtime-sidecar-fixture'
            HostName = 'RUNTIME-SIDECAR'
            ArtifactSha256 = $ArtifactSha256
            ParserVersion = '0.12.2'
            RunStartedAt = '2026-08-26T00:00:00Z'
        }
        $ecsEvent = ConvertTo-HHEcsProcessStartEvent -Record $record -Context $context
        if ($null -ne $ecsEvent) {
            [void](Test-HHEcsProcessStartContract -Event $ecsEvent)
            $events.Add($ecsEvent)
        }
        [Array]::Clear($bytes, 0, $bytes.Length)
    }
    [pscustomobject]@{
        FixtureName = $Name
        EcsVersion = '9.5.0'
        EventCount = $events.Count
        EventIds = @($events.event.id)
    }
} @($frames) $ExpectedSha256 $FixtureName

if ($result.EventCount -ne $ExpectedEventCount) {
    throw "Expected $ExpectedEventCount ECS events but produced $($result.EventCount)."
}
if (@($result.EventIds | Where-Object { $_ -cnotmatch '^[a-f0-9]{64}$' }).Count -gt 0) {
    throw 'The ECS journey produced an invalid deterministic event identifier.'
}

[pscustomobject][ordered]@{
    status = 'passed'
    fixture = $FixtureName
    packagePath = $env:HH_RUNTIME_MODULE_PATH
    parserProtocol = 'hosthunter.parser.v1'
    parserVersion = $completion.parser_version
    parserSha256 = $completion.parser_sha256
    inputSha256 = $completion.input_sha256
    recordCount = $frames.Count
    ecsVersion = $result.EcsVersion
    ecsEventCount = $result.EventCount
    plaintextJsonlArtifactCreated = $false
    runtime = $completion.runtime
} | ConvertTo-Json -Depth 8 -Compress
