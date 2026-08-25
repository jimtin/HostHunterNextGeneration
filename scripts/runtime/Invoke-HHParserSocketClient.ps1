[CmdletBinding(DefaultParameterSetName = 'ReceiptOnly')]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[^/].*\.evtx$')]
    [string]$RelativePath,

    [Parameter(Mandatory)]
    [ValidatePattern('^[a-f0-9]{64}$')]
    [string]$ExpectedSha256,

    [ValidatePattern('^[0-9a-f]{32}$')]
    [string]$RequestId = ([guid]::NewGuid().ToString('N')),

    [ValidateRange(1, 300)]
    [int]$TimeoutSeconds = 120,

    [ValidateRange(1024, 4194304)]
    [int]$MaximumLineBytes = 4194304,

    [Parameter(Mandatory, ParameterSetName = 'ReceiptOnly')]
    [switch]$ReceiptOnly,

    # Record frames are provisional until the terminal completion receipt.
    # This callback may stage in memory only; it must not persist or publish.
    [Parameter(Mandatory, ParameterSetName = 'Consume')]
    [scriptblock]$ProvisionalRecordConsumer,

    [switch]$RequireRecords,

    [string]$SocketPath = $env:HH_PARSER_SOCKET
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($SocketPath) -or
    -not [IO.Path]::IsPathRooted($SocketPath)) {
    throw 'The parser Unix-socket path must be absolute.'
}
if ($PSCmdlet.ParameterSetName -ceq 'ReceiptOnly' -and -not $ReceiptOnly) {
    throw 'ReceiptOnly must be explicitly selected when no provisional consumer is supplied.'
}
if ([IO.Path]::IsPathRooted($RelativePath) -or
    @($RelativePath -split '[/\\]' | Where-Object { $_ -eq '..' }).Count -gt 0) {
    throw 'RelativePath must remain beneath the evidence root.'
}

function Read-HHBoundedSocketLine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][IO.StreamReader]$Reader,
        [Parameter(Mandatory)][int]$MaximumCharacters
    )

    $builder = [Text.StringBuilder]::new()
    while ($true) {
        $value = $Reader.Read()
        if ($value -eq -1) {
            if ($builder.Length -eq 0) { return $null }
            throw 'The parser response ended without a newline terminator.'
        }
        if ($value -eq 10) { return $builder.ToString() }
        if ($value -eq 13) { continue }
        if ($builder.Length -ge $MaximumCharacters) {
            throw 'A parser response frame exceeded its client-side bound.'
        }
        [void]$builder.Append([char]$value)
    }
}

$socket = [Net.Sockets.Socket]::new(
    [Net.Sockets.AddressFamily]::Unix,
    [Net.Sockets.SocketType]::Stream,
    [Net.Sockets.ProtocolType]::Unspecified
)
$stream = $null
$reader = $null
$writer = $null
try {
    $socket.ReceiveTimeout = ($TimeoutSeconds + 10) * 1000
    $socket.SendTimeout = 10000
    $endpoint = [Net.Sockets.UnixDomainSocketEndPoint]::new($SocketPath)
    $socket.Connect($endpoint)
    $stream = [Net.Sockets.NetworkStream]::new($socket, $true)
    $utf8 = [Text.UTF8Encoding]::new($false, $true)
    $reader = [IO.StreamReader]::new($stream, $utf8, $false, 4096, $true)
    $writer = [IO.StreamWriter]::new($stream, $utf8, 4096, $true)
    $writer.NewLine = "`n"
    $writer.AutoFlush = $true
    $request = [ordered]@{
        protocol = 'hosthunter.parser.v1'
        request_id = $RequestId
        relative_path = $RelativePath
        expected_sha256 = $ExpectedSha256
        timeout_seconds = $TimeoutSeconds
        max_line_bytes = $MaximumLineBytes
    }
    $writer.WriteLine(($request | ConvertTo-Json -Compress))

    $recordCount = 0L
    $completion = $null
    while ($null -eq $completion) {
        $line = Read-HHBoundedSocketLine -Reader $reader `
            -MaximumCharacters ($MaximumLineBytes * 2 + 65536)
        if ($null -eq $line) {
            throw 'The parser socket closed before a terminal frame.'
        }
        $frame = $line | ConvertFrom-Json -Depth 100 -ErrorAction Stop
        if ($frame.protocol -cne 'hosthunter.parser.v1' -or
            $frame.request_id -cne $RequestId) {
            throw 'The parser returned a frame for a different protocol or request.'
        }
        switch ([string]$frame.kind) {
            record {
                if ([long]$frame.ordinal -ne $recordCount -or
                    $frame.provisional -ne $true -or
                    [string]$frame.record_sha256 -cnotmatch '^[a-f0-9]{64}$' -or
                    [string]::IsNullOrWhiteSpace([string]$frame.record_json)) {
                    throw 'The parser returned an invalid or out-of-order record frame.'
                }
                if ($PSCmdlet.ParameterSetName -ceq 'Consume') {
                    & $ProvisionalRecordConsumer $frame
                }
                $recordCount++
            }
            complete {
                if ([long]$frame.record_count -ne $recordCount -or
                    $frame.input_sha256 -cne $ExpectedSha256 -or
                    [string]$frame.parser_sha256 -cnotmatch '^[a-f0-9]{64}$') {
                    throw 'The parser completion receipt does not match the streamed records.'
                }
                $completion = $frame
            }
            error {
                throw "The parser sidecar refused the request: $($frame.error)"
            }
            default {
                throw "The parser returned unknown frame kind '$($frame.kind)'."
            }
        }
    }
    if ($RequireRecords -and $recordCount -eq 0) {
        throw 'The parser returned no records for a fixture that requires records.'
    }
    $completion
}
finally {
    if ($null -ne $writer) { $writer.Dispose() }
    if ($null -ne $reader) { $reader.Dispose() }
    if ($null -ne $stream) { $stream.Dispose() }
    else { $socket.Dispose() }
}
