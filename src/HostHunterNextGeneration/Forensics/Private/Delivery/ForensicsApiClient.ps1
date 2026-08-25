Set-StrictMode -Version Latest

$script:HHForensicsMaximumApiResponseBytes = 65536
$script:HHForensicsReceiptSchema = 'hosthunter.put-receipt/1'

function Assert-HHForensicsLoopbackBaseUri {
    [CmdletBinding()]
    [OutputType([Uri])]
    param([Parameter(Mandatory)][string]$BaseUri)

    $uri = $null
    if (-not [Uri]::TryCreate($BaseUri, [UriKind]::Absolute, [ref]$uri) -or
        $uri.Scheme -notin @('http', 'https') -or -not $uri.IsLoopback -or
        -not [string]::IsNullOrEmpty($uri.UserInfo) -or
        -not [string]::IsNullOrEmpty($uri.Query) -or
        -not [string]::IsNullOrEmpty($uri.Fragment)) {
        Stop-HHForensicsOperation -ErrorId ForensicsApiEndpointRejected `
            -Message 'The phase-one forensics API endpoint must be an absolute loopback HTTP URI.' `
            -Category SecurityError -TargetObject $BaseUri
    }
    return $uri
}

function Get-HHForensicsContentDigestHeader {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Digest)

    if ($Digest.Length -ne 32) {
        throw [ArgumentException]::new('Content-Digest requires a 32-byte SHA-256 digest.')
    }
    return "sha-256=:$([Convert]::ToBase64String($Digest)):"
}

function Get-HHForensicsApiProblemCode {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][int]$StatusCode,
        [AllowNull()][byte[]]$Body
    )

    if ($null -ne $Body -and $Body.Length -gt 0 -and $Body.Length -le 65536) {
        try {
            $json = [Text.UTF8Encoding]::new($false, $true).GetString($Body) |
                ConvertFrom-Json -ErrorAction Stop
            foreach ($name in @('code', 'problem', 'type')) {
                $property = $json.PSObject.Properties[$name]
                if ($null -ne $property) {
                    $candidate = [string]$property.Value
                    if ($candidate -cmatch '^[A-Za-z0-9._:-]{1,128}$') { return $candidate }
                }
            }
        }
        catch { Write-Debug 'The bounded API problem response was not canonical JSON.' }
    }
    return "Http$StatusCode"
}

function ConvertFrom-HHForensicsReceipt {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Body,
        [Parameter(Mandatory)][object]$Item
    )

    if ($Body.Length -eq 0 -or
        $Body.Length -gt $script:HHForensicsMaximumApiResponseBytes) {
        Stop-HHForensicsOperation -ErrorId ForensicsReceiptBindingRejected `
            -Message 'The API receipt body is empty or exceeds its bound.' `
            -Category InvalidData -TargetObject $Item.ResourceKey
    }
    $document = $null
    try {
        $jsonText = [Text.UTF8Encoding]::new($false, $true).GetString($Body)
        $document = [Text.Json.JsonDocument]::Parse($jsonText)
        if ($document.RootElement.ValueKind -ne [Text.Json.JsonValueKind]::Object -or
            $document.RootElement.GetRawText() -cne $jsonText) {
            throw [FormatException]::new('Receipt JSON must be one object without outer whitespace.')
        }
        $expectedNames = @(
            'schema', 'resource_uri', 'resource_key', 'idempotency_key',
            'content_digest', 'original_status', 'receipt_id'
        )
        $properties = @($document.RootElement.EnumerateObject())
        if ($properties.Count -ne $expectedNames.Count) {
            throw [FormatException]::new('Receipt JSON has missing or additional fields.')
        }
        $values = @{}
        foreach ($property in $properties) {
            if ($property.Name -cnotin $expectedNames -or $values.ContainsKey($property.Name)) {
                throw [FormatException]::new('Receipt JSON has unknown or duplicate fields.')
            }
            $values[$property.Name] = $property.Value
        }
        foreach ($name in $expectedNames) {
            if (-not $values.ContainsKey($name)) {
                throw [FormatException]::new('Receipt JSON has missing fields.')
            }
        }
        foreach ($name in @(
                'schema', 'resource_uri', 'resource_key', 'idempotency_key',
                'content_digest', 'receipt_id'
            )) {
            if ($values[$name].ValueKind -ne [Text.Json.JsonValueKind]::String) {
                throw [FormatException]::new("Receipt field '$name' must be a string.")
            }
        }
        if ($values['original_status'].ValueKind -ne [Text.Json.JsonValueKind]::Number) {
            throw [FormatException]::new('Receipt original_status must be an integer.')
        }
        $originalStatus = 0
        if (-not $values['original_status'].TryGetInt32([ref]$originalStatus) -or
            $originalStatus -notin @(200, 201) -or
            $values['original_status'].GetRawText() -cnotin @('200', '201')) {
            throw [FormatException]::new('Receipt original_status must be 200 or 201.')
        }
        $expectedDigest = Get-HHForensicsContentDigestHeader -Digest $Item.BodyDigest
        $receiptId = $values['receipt_id'].GetString()
        if ($values['schema'].GetString() -cne $script:HHForensicsReceiptSchema -or
            $values['resource_uri'].GetString() -cne $Item.ResourceUri -or
            $values['resource_key'].GetString() -cne $Item.ResourceKey -or
            $values['idempotency_key'].GetString() -cne $Item.IdempotencyKey -or
            $values['content_digest'].GetString() -cne $expectedDigest -or
            $receiptId -cnotmatch '^[A-Za-z0-9._:-]{1,128}$') {
            throw [FormatException]::new('Receipt fields do not bind to the exact request.')
        }
        return [pscustomobject]@{
            Schema = $script:HHForensicsReceiptSchema
            ResourceUri = $Item.ResourceUri
            ResourceKey = $Item.ResourceKey
            IdempotencyKey = $Item.IdempotencyKey
            ContentDigest = $expectedDigest
            OriginalStatus = $originalStatus
            ReceiptId = $receiptId
        }
    }
    catch {
        if ($_.FullyQualifiedErrorId -like 'ForensicsReceiptBindingRejected*') { throw }
        Stop-HHForensicsOperation -ErrorId ForensicsReceiptBindingRejected `
            -Message 'The API receipt is not the strict receipt bound to this request.' `
            -Category InvalidData -TargetObject $Item.ResourceKey -InnerException $_.Exception
    }
    finally {
        if ($null -ne $document) { $document.Dispose() }
    }
}

function Assert-HHForensicsTransportResponse {
    [CmdletBinding()]
    param([AllowNull()][object]$Response)

    if ($null -eq $Response -or
        $null -eq $Response.PSObject.Properties['StatusCode'] -or
        $null -eq $Response.PSObject.Properties['Body']) {
        Stop-HHForensicsOperation -ErrorId ForensicsApiResponseRejected `
            -Message 'The forensics API transport returned an invalid response shape.' `
            -Category InvalidData -TargetObject $Response
    }
    try { $statusCode = [int]$Response.StatusCode }
    catch {
        Stop-HHForensicsOperation -ErrorId ForensicsApiResponseRejected `
            -Message 'The forensics API transport returned an invalid status code.' `
            -Category InvalidData -TargetObject $Response
    }
    if ($statusCode -lt 100 -or $statusCode -gt 599) {
        Stop-HHForensicsOperation -ErrorId ForensicsApiResponseRejected `
            -Message 'The forensics API transport returned an invalid status code.' `
            -Category InvalidData -TargetObject $statusCode
    }
    [byte[]]$body = [byte[]]::new(0)
    if ($null -ne $Response.Body) { $body = [byte[]]$Response.Body }
    $declaredLength = $null
    $declaredProperty = $Response.PSObject.Properties['DeclaredLength']
    if ($null -ne $declaredProperty -and $null -ne $declaredProperty.Value) {
        try { $declaredLength = [long]$declaredProperty.Value }
        catch {
            Stop-HHForensicsOperation -ErrorId ForensicsApiResponseRejected `
                -Message 'The forensics API response declared an invalid content length.' `
                -Category InvalidData -TargetObject $declaredProperty.Value
        }
    }
    if (($null -ne $declaredLength -and
            ($declaredLength -lt 0 -or
                $declaredLength -gt $script:HHForensicsMaximumApiResponseBytes)) -or
        $body.Length -gt $script:HHForensicsMaximumApiResponseBytes) {
        Stop-HHForensicsOperation -ErrorId ForensicsApiResponseRejected `
            -Message 'The forensics API response exceeded the bounded body limit.' `
            -Category LimitsExceeded -TargetObject $body.Length
    }
    return [pscustomobject]@{
        StatusCode = $statusCode
        Body = $body
        DeclaredLength = $declaredLength
    }
}

function Invoke-HHForensicsHttpTransport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][Uri]$Uri,
        [Parameter(Mandatory)][ValidateSet('GET', 'PUT')][string]$Method,
        [AllowNull()][byte[]]$Body,
        [Parameter(Mandatory)][hashtable]$Headers,
        [Parameter(Mandatory)][ValidateRange(1, 120)][int]$TimeoutSeconds,
        [AllowNull()][scriptblock]$Transport
    )

    if ($null -ne $Transport) {
        $transportResponse = & $Transport ([pscustomobject]@{
                Uri = $Uri
                Method = $Method
                Body = $Body
                Headers = $Headers
                TimeoutSeconds = $TimeoutSeconds
            })
        return Assert-HHForensicsTransportResponse -Response $transportResponse
    }

    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $handler.UseProxy = $false
    $client = [Net.Http.HttpClient]::new($handler, $true)
    $client.Timeout = [Threading.Timeout]::InfiniteTimeSpan
    $cancellation = [Threading.CancellationTokenSource]::new(
        [TimeSpan]::FromSeconds($TimeoutSeconds)
    )
    $request = [Net.Http.HttpRequestMessage]::new(
        [Net.Http.HttpMethod]::new($Method),
        $Uri
    )
    try {
        if ($null -ne $Body) {
            $request.Content = [Net.Http.ByteArrayContent]::new($Body)
            $request.Content.Headers.ContentType =
                [Net.Http.Headers.MediaTypeHeaderValue]::new('application/json')
        }
        foreach ($entry in $Headers.GetEnumerator()) {
            $null = $request.Headers.TryAddWithoutValidation(
                [string]$entry.Key,
                [string]$entry.Value
            )
        }
        $response = $client.SendAsync(
            $request,
            [Net.Http.HttpCompletionOption]::ResponseHeadersRead,
            $cancellation.Token
        ).GetAwaiter().GetResult()
        try {
            $declaredLength = $response.Content.Headers.ContentLength
            if ($null -ne $declaredLength -and
                [long]$declaredLength -gt $script:HHForensicsMaximumApiResponseBytes) {
                Stop-HHForensicsOperation -ErrorId ForensicsApiResponseRejected `
                    -Message 'The forensics API response declared an oversized body.' `
                    -Category LimitsExceeded -TargetObject $declaredLength
            }
            $stream = $response.Content.ReadAsStreamAsync(
                $cancellation.Token
            ).GetAwaiter().GetResult()
            $buffer = [byte[]]::new(8192)
            $output = [IO.MemoryStream]::new()
            try {
                while ($true) {
                    $read = $stream.ReadAsync(
                        $buffer,
                        0,
                        $buffer.Length,
                        $cancellation.Token
                    ).GetAwaiter().GetResult()
                    if ($read -eq 0) { break }
                    if ($output.Length + $read -gt
                        $script:HHForensicsMaximumApiResponseBytes) {
                        Stop-HHForensicsOperation -ErrorId ForensicsApiResponseRejected `
                            -Message 'The forensics API response streamed an oversized body.' `
                            -Category LimitsExceeded -TargetObject ($output.Length + $read)
                    }
                    $output.Write($buffer, 0, $read)
                }
                $responseBytes = $output.ToArray()
                return Assert-HHForensicsTransportResponse -Response ([pscustomobject]@{
                        StatusCode = [int]$response.StatusCode
                        Body = [byte[]]$responseBytes
                        DeclaredLength = $declaredLength
                    })
            }
            finally {
                [Array]::Clear($buffer, 0, $buffer.Length)
                $output.Dispose()
                $stream.Dispose()
            }
        }
        finally { $response.Dispose() }
    }
    finally {
        $request.Dispose()
        $client.Dispose()
        $cancellation.Dispose()
    }
}

function Get-HHForensicsDeliveryOutcome {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][int]$StatusCode)

    if ($StatusCode -in @(200, 201)) { return 'ACCEPTED' }
    if ($StatusCode -eq 409) { return 'CONFLICT' }
    if ($StatusCode -in @(429, 500, 502, 503, 504)) { return 'RETRYABLE' }
    if ($StatusCode -eq 507) { return 'PAUSED' }
    if ($StatusCode -ge 400 -and $StatusCode -lt 500) { return 'REJECTED' }
    return 'UNKNOWN'
}

function Get-HHForensicsAccessToken {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][scriptblock]$AccessTokenProvider)

    try { $token = [string](& $AccessTokenProvider) }
    catch {
        Stop-HHForensicsOperation -ErrorId ForensicsApiAuthenticationUnavailable `
            -Message 'The in-memory forensics API access-token provider failed.' `
            -Category AuthenticationError -TargetObject $null -InnerException $_.Exception
    }
    if ([string]::IsNullOrWhiteSpace($token) -or $token.Contains("`r") -or
        $token.Contains("`n")) {
        Stop-HHForensicsOperation -ErrorId ForensicsApiAuthenticationUnavailable `
            -Message 'The in-memory forensics API access token is missing or malformed.' `
            -Category AuthenticationError -TargetObject $null
    }
    return $token
}

function Invoke-HHForensicsOutboxDelivery {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$BaseUri,
        [Parameter(Mandatory)][scriptblock]$AccessTokenProvider,
        [string]$ResourceKey,
        [ValidateRange(1, 120)][int]$TimeoutSeconds = 10,
        [AllowNull()][scriptblock]$Transport
    )

    $base = Assert-HHForensicsLoopbackBaseUri -BaseUri $BaseUri
    $item = if ([string]::IsNullOrWhiteSpace($ResourceKey)) {
        Get-HHForensicsNextOutboxItem -Context $Context
    }
    else { Get-HHForensicsOutboxItem -Context $Context -ResourceKey $ResourceKey }
    if ($null -eq $item) { return $null }
    if ($item.Status -ceq 'UNKNOWN') {
        return Invoke-HHForensicsReceiptReconciliation `
            -Context $Context -BaseUri $BaseUri `
            -AccessTokenProvider $AccessTokenProvider -ResourceKey $item.ResourceKey `
            -TimeoutSeconds $TimeoutSeconds -Transport $Transport
    }
    $token = Get-HHForensicsAccessToken -AccessTokenProvider $AccessTokenProvider
    $attemptId = [Guid]::NewGuid().ToString('N')
    $armed = Start-HHForensicsDeliveryAttempt `
        -Context $Context -ResourceKey $item.ResourceKey -AttemptId $attemptId
    try {
        $headers = @{
            Authorization = "Bearer $token"
            'Idempotency-Key' = $armed.Item.IdempotencyKey
            'Content-Digest' = Get-HHForensicsContentDigestHeader `
                -Digest $armed.Item.BodyDigest
            'HostHunter-Attempt-Id' = $attemptId
        }
        $requestUri = [Uri]::new($base, $armed.Item.ResourceUri.TrimStart('/'))
        try {
            $response = Invoke-HHForensicsHttpTransport `
                -Uri $requestUri -Method PUT -Body $armed.Item.Body `
                -Headers $headers -TimeoutSeconds $TimeoutSeconds -Transport $Transport
        }
        catch {
            return Complete-HHForensicsDeliveryAttempt `
                -Context $Context -ResourceKey $armed.Item.ResourceKey `
                -AttemptNumber $armed.AttemptNumber -Outcome UNKNOWN `
                -ProblemCode TransportOutcomeUnknown
        }
        $statusCode = [int]$response.StatusCode
        [byte[]]$responseBody = [byte[]]::new(0)
        if ($null -ne $response.Body) { $responseBody = [byte[]]$response.Body }
        $outcome = Get-HHForensicsDeliveryOutcome -StatusCode $statusCode
        $problemCode = $null
        if ($outcome -ceq 'ACCEPTED') {
            try {
                $null = ConvertFrom-HHForensicsReceipt `
                    -Body $responseBody -Item $armed.Item
            }
            catch {
                $outcome = 'CONFLICT'
                $problemCode = 'ReceiptBindingMismatch'
            }
        }
        else {
            $problemCode =
            Get-HHForensicsApiProblemCode -StatusCode $statusCode -Body $responseBody
        }
        return Complete-HHForensicsDeliveryAttempt `
            -Context $Context -ResourceKey $armed.Item.ResourceKey `
            -AttemptNumber $armed.AttemptNumber -Outcome $outcome `
            -StatusCode $statusCode -ProblemCode $problemCode -ResponseBody $responseBody
    }
    finally {
        if ($null -ne $armed.Item.Body) {
            [Array]::Clear($armed.Item.Body, 0, $armed.Item.Body.Length)
        }
    }
}

function Invoke-HHForensicsReceiptReconciliation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$BaseUri,
        [Parameter(Mandatory)][scriptblock]$AccessTokenProvider,
        [Parameter(Mandatory)][string]$ResourceKey,
        [ValidateRange(1, 120)][int]$TimeoutSeconds = 10,
        [AllowNull()][scriptblock]$Transport
    )

    $base = Assert-HHForensicsLoopbackBaseUri -BaseUri $BaseUri
    $item = Get-HHForensicsOutboxItem -Context $Context -ResourceKey $ResourceKey
    if ($null -eq $item -or $item.Status -cne 'UNKNOWN') {
        Stop-HHForensicsOperation -ErrorId ForensicsOutboxStateRejected `
            -Message 'Receipt reconciliation requires an UNKNOWN outbox item.' `
            -Category InvalidOperation -TargetObject $ResourceKey
    }
    $databaseHead = Get-HHForensicsDatabaseHead `
        -Connection $Context.Connection -ForensicsKey $Context.ForensicsKey `
        -MigrationPath $Context.Persistence.MigrationPath `
        -ProviderRoot $Context.Persistence.ProviderRoot
    $anchor = & $Context.AnchorReader $Context.Persistence
    if ($null -eq $anchor) {
        Stop-HHForensicsOperation -ErrorId ForensicsAnchorRequired `
            -Message 'The external forensics anchor disappeared before receipt dispatch.' `
            -Category SecurityError -TargetObject $Context.Persistence.DatabasePath
    }
    $comparison = Compare-HHForensicsAnchor `
        -DatabaseHead $databaseHead -Anchor $anchor -ForensicsKey $Context.ForensicsKey
    if (-not $comparison.IsEqual) {
        Stop-HHForensicsOperation -ErrorId ForensicsAnchorAdvanceRequired `
            -Message 'The external forensics anchor is stale before receipt dispatch.' `
            -Category SecurityError -TargetObject $databaseHead.Generation
    }
    $token = Get-HHForensicsAccessToken -AccessTokenProvider $AccessTokenProvider
    $headers = @{
        Authorization = "Bearer $token"
        'Idempotency-Key' = $item.IdempotencyKey
        'Content-Digest' = Get-HHForensicsContentDigestHeader -Digest $item.BodyDigest
    }
    $encodedKey = [Uri]::EscapeDataString($item.IdempotencyKey)
    $receiptUri = [Uri]::new($base, "api/v1/put-receipts/$encodedKey")
    try {
        $response = Invoke-HHForensicsHttpTransport `
            -Uri $receiptUri -Method GET -Body $null -Headers $headers `
            -TimeoutSeconds $TimeoutSeconds -Transport $Transport
    }
    catch { return $item }
    $statusCode = [int]$response.StatusCode
    [byte[]]$responseBody = [byte[]]::new(0)
    if ($null -ne $response.Body) { $responseBody = [byte[]]$response.Body }
    if ($statusCode -eq 200) {
        try {
            $null = ConvertFrom-HHForensicsReceipt -Body $responseBody -Item $item
        }
        catch {
            return Resolve-HHForensicsUnknownDelivery `
                -Context $Context -ResourceKey $ResourceKey -Outcome CONFLICT `
                -StatusCode $statusCode -ProblemCode ReceiptBindingMismatch `
                -ReceiptBody $responseBody
        }
        return Resolve-HHForensicsUnknownDelivery `
            -Context $Context -ResourceKey $ResourceKey -Outcome ACCEPTED `
            -StatusCode $statusCode -ReceiptBody $responseBody
    }
    if ($statusCode -eq 404) {
        return Resolve-HHForensicsUnknownDelivery `
            -Context $Context -ResourceKey $ResourceKey -Outcome RETRYABLE `
            -StatusCode $statusCode -ProblemCode ReceiptNotFound -ReceiptBody $responseBody
    }
    $outcome = Get-HHForensicsDeliveryOutcome -StatusCode $statusCode
    if ($outcome -in @('PAUSED', 'REJECTED', 'CONFLICT')) {
        return Resolve-HHForensicsUnknownDelivery `
            -Context $Context -ResourceKey $ResourceKey -Outcome $outcome `
            -StatusCode $statusCode `
            -ProblemCode (Get-HHForensicsApiProblemCode `
                -StatusCode $statusCode -Body $responseBody) `
            -ReceiptBody $responseBody
    }
    return $item
}
