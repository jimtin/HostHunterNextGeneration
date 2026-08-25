[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet(
        'Success', 'Replay', 'Conflict', 'Retryable', 'Permanent',
        'Unknown', 'ReceiptFound', 'ReceiptMissing', 'ReceiptMismatch',
        'DeclaredOverflow', 'ObservedOverflow', 'SlowBody', 'EndlessBody'
    )]
    [string]$Scenario,
    [Parameter(Mandatory)][string]$ReadyPath,
    [Parameter(Mandatory)][string]$CapturePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Read-HHFixtureRequest {
    [CmdletBinding()]
    param([Parameter(Mandatory)][IO.Stream]$Stream)

    $headerBuffer = [IO.MemoryStream]::new()
    try {
        $tail = [Collections.Generic.Queue[byte]]::new()
        while ($true) {
            $value = $Stream.ReadByte()
            if ($value -lt 0) { throw 'The client closed before the HTTP headers completed.' }
            $headerBuffer.WriteByte([byte]$value)
            $tail.Enqueue([byte]$value)
            while ($tail.Count -gt 4) { $null = $tail.Dequeue() }
            if ($tail.Count -eq 4) {
                $bytes = $tail.ToArray()
                if ($bytes[0] -eq 13 -and $bytes[1] -eq 10 -and
                    $bytes[2] -eq 13 -and $bytes[3] -eq 10) { break }
            }
            if ($headerBuffer.Length -gt 65536) { throw 'Fixture HTTP headers exceeded 64 KiB.' }
        }
        $headerText = [Text.Encoding]::ASCII.GetString($headerBuffer.ToArray())
    }
    finally { $headerBuffer.Dispose() }

    $lines = $headerText.Split(@("`r`n"), [StringSplitOptions]::None)
    $requestLine = $lines[0].Split(' ')
    if ($requestLine.Count -lt 2) { throw 'Fixture received a malformed request line.' }
    $headers = @{}
    foreach ($line in $lines[1..($lines.Count - 1)]) {
        if ([string]::IsNullOrEmpty($line)) { continue }
        $separator = $line.IndexOf(':')
        if ($separator -lt 1) { throw 'Fixture received a malformed header.' }
        $headers[$line.Substring(0, $separator).Trim()] =
            $line.Substring($separator + 1).Trim()
    }
    $length = if ($headers.ContainsKey('Content-Length')) {
        [int]$headers['Content-Length']
    }
    else { 0 }
    if ($length -lt 0 -or $length -gt 1048576) { throw 'Fixture body length is out of bounds.' }
    $body = [byte[]]::new($length)
    $offset = 0
    while ($offset -lt $length) {
        $read = $Stream.Read($body, $offset, $length - $offset)
        if ($read -le 0) { throw 'The client closed before the request body completed.' }
        $offset += $read
    }
    return [pscustomobject]@{
        Method = $requestLine[0]
        Target = $requestLine[1]
        Headers = $headers
        Body = $body
    }
}

function Write-HHFixtureResponse {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][IO.Stream]$Stream,
        [Parameter(Mandatory)][int]$StatusCode,
        [Parameter(Mandatory)][string]$Reason,
        [Parameter(Mandatory)][byte[]]$Body,
        [Nullable[long]]$DeclaredLength,
        [switch]$OmitLength,
        [int]$DelayBodySeconds
    )

    $lengthHeader = if ($OmitLength) { '' }
    elseif ($null -ne $DeclaredLength) { "Content-Length: $DeclaredLength`r`n" }
    else { "Content-Length: $($Body.Length)`r`n" }
    $header = [Text.Encoding]::ASCII.GetBytes(
        "HTTP/1.1 $StatusCode $Reason`r`nContent-Type: application/json`r`n" +
        $lengthHeader + "Connection: close`r`n`r`n"
    )
    $Stream.Write($header, 0, $header.Length)
    $Stream.Flush()
    if ($DelayBodySeconds -gt 0) { Start-Sleep -Seconds $DelayBodySeconds }
    if ($Body.Length -gt 0) { $Stream.Write($Body, 0, $Body.Length) }
    $Stream.Flush()
}

function New-HHFixtureReceiptBody {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Constructs only in-memory receipt fixture bytes.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Request,
        [Parameter(Mandatory)][int]$OriginalStatus,
        [switch]$Mismatch
    )

    $resourceUri = if ($Request.Method -ceq 'PUT') {
        [string]$Request.Target
    }
    else { '/api/v1/process-events' }
    if ($Mismatch) { $resourceUri = '/api/v1/wrong-resource' }
    $json = [ordered]@{
        schema = 'hosthunter.put-receipt/1'
        resource_uri = $resourceUri
        resource_key = 'resource-fixture'
        idempotency_key = [string]$Request.Headers['Idempotency-Key']
        content_digest = [string]$Request.Headers['Content-Digest']
        original_status = $OriginalStatus
        receipt_id = "fixture-$OriginalStatus"
    } | ConvertTo-Json -Compress
    return [Text.Encoding]::UTF8.GetBytes($json)
}

$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
$client = $null
try {
    $listener.Start()
    $port = ([Net.IPEndPoint]$listener.LocalEndpoint).Port
    [IO.File]::WriteAllText(
        $ReadyPath,
        ([pscustomobject]@{ ready = $true; port = $port } | ConvertTo-Json -Compress),
        [Text.UTF8Encoding]::new($false)
    )
    $client = $listener.AcceptTcpClient()
    $client.ReceiveTimeout = 10000
    $client.SendTimeout = 10000
    $stream = $client.GetStream()
    $request = Read-HHFixtureRequest -Stream $stream
    $capture = [pscustomobject]@{
        method = $request.Method
        target = $request.Target
        bodyBase64 = [Convert]::ToBase64String($request.Body)
        idempotencyKey = $request.Headers['Idempotency-Key']
        contentDigest = $request.Headers['Content-Digest']
        attemptId = $request.Headers['HostHunter-Attempt-Id']
        authorizationPresent = $request.Headers.ContainsKey('Authorization')
    }
    [IO.File]::WriteAllText(
        $CapturePath,
        ($capture | ConvertTo-Json -Compress),
        [Text.UTF8Encoding]::new($false)
    )

    if ($Scenario -ceq 'Unknown') {
        Start-Sleep -Seconds 3
        return
    }
    if ($Scenario -ceq 'DeclaredOverflow') {
        Write-HHFixtureResponse -Stream $stream -StatusCode 200 -Reason OK `
            -Body ([byte[]]::new(0)) -DeclaredLength 65537
        return
    }
    if ($Scenario -ceq 'ObservedOverflow') {
        Write-HHFixtureResponse -Stream $stream -StatusCode 200 -Reason OK `
            -Body ([byte[]]::new(65537)) -OmitLength
        return
    }
    if ($Scenario -ceq 'SlowBody') {
        $slowBody = New-HHFixtureReceiptBody -Request $request -OriginalStatus 201
        Write-HHFixtureResponse -Stream $stream -StatusCode 201 -Reason Created `
            -Body $slowBody -DelayBodySeconds 3
        return
    }
    if ($Scenario -ceq 'EndlessBody') {
        $header = [Text.Encoding]::ASCII.GetBytes(
            "HTTP/1.1 200 OK`r`nContent-Type: application/json`r`nConnection: close`r`n`r`n"
        )
        $stream.Write($header, 0, $header.Length)
        $chunk = [byte[]]::new(1024)
        try {
            while ($true) {
                $stream.Write($chunk, 0, $chunk.Length)
                $stream.Flush()
                Start-Sleep -Milliseconds 100
            }
        }
        finally { [Array]::Clear($chunk, 0, $chunk.Length) }
    }
    $receiptCreated = New-HHFixtureReceiptBody -Request $request -OriginalStatus 201
    $receiptReplayed = New-HHFixtureReceiptBody -Request $request -OriginalStatus 200
    $receiptFound = New-HHFixtureReceiptBody -Request $request -OriginalStatus 201
    $receiptMismatch = New-HHFixtureReceiptBody `
        -Request $request -OriginalStatus 201 -Mismatch
    $response = switch ($Scenario) {
        Success { @(201, 'Created', $receiptCreated); break }
        Replay { @(200, 'OK', $receiptReplayed); break }
        Conflict {
            @(409, 'Conflict', [Text.Encoding]::UTF8.GetBytes('{"code":"IdempotencyConflict"}'))
            break
        }
        Retryable {
            @(503, 'Service Unavailable', [Text.Encoding]::UTF8.GetBytes(
                    '{"code":"TemporarilyUnavailable"}'
                ))
            break
        }
        Permanent {
            @(422, 'Unprocessable Entity', [Text.Encoding]::UTF8.GetBytes(
                    '{"code":"SchemaRejected"}'
                ))
            break
        }
        ReceiptFound { @(200, 'OK', $receiptFound); break }
        ReceiptMissing {
            @(404, 'Not Found', [Text.Encoding]::UTF8.GetBytes('{"code":"ReceiptNotFound"}'))
            break
        }
        ReceiptMismatch { @(201, 'Created', $receiptMismatch); break }
    }
    Write-HHFixtureResponse -Stream $stream `
        -StatusCode ([int]$response[0]) -Reason ([string]$response[1]) `
        -Body ([byte[]]$response[2])
}
finally {
    if ($null -ne $client) { $client.Dispose() }
    $listener.Stop()
}
