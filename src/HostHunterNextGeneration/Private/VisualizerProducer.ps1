Set-StrictMode -Version Latest

function Get-HHVisualizerConnectionSettings {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseSingularNouns',
        '',
        Justification = 'The private helper returns the complete visualizer connection settings object.'
    )]
    [CmdletBinding()]
    param()
    [pscustomobject]@{
        BaseUri = if ([string]::IsNullOrWhiteSpace($env:HH_VISUALIZER_BASE_URI)) {
            'http://hosthunter-visualizer:3000'
        } else { $env:HH_VISUALIZER_BASE_URI.TrimEnd('/') }
        TokenPath = if ([string]::IsNullOrWhiteSpace($env:HH_VISUALIZER_TOKEN_FILE)) {
            '/run/secrets/hosthunter_visualizer_producer_token'
        } else { $env:HH_VISUALIZER_TOKEN_FILE }
    }
}

function Invoke-HHVisualizerStatus {
    [CmdletBinding()]
    param([Alias('Sender')][scriptblock]$RequestSender)

    if ($null -ne $RequestSender) { $status = & $RequestSender '/api/v1/producer/status' }
    else {
        $settings = Get-HHVisualizerConnectionSettings
        if (-not [IO.File]::Exists($settings.TokenPath)) {
            throw 'The configured visualizer producer credential is unavailable.'
        }
        $token = [IO.File]::ReadAllText($settings.TokenPath).Trim()
        if ([string]::IsNullOrWhiteSpace($token)) {
            throw 'The configured visualizer producer credential is empty.'
        }
        $handler = [Net.Http.SocketsHttpHandler]::new()
        $handler.ConnectTimeout = [TimeSpan]::FromSeconds(2)
        $client = [Net.Http.HttpClient]::new($handler)
        $client.Timeout = [TimeSpan]::FromSeconds(5)
        try {
            $request = [Net.Http.HttpRequestMessage]::new(
                [Net.Http.HttpMethod]::Get,
                "$($settings.BaseUri)/api/v1/producer/status"
            )
            try {
                $request.Headers.Authorization =
                    [Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $token)
                $response = $client.Send($request)
                try {
                    if (-not $response.IsSuccessStatusCode) {
                        throw "Visualizer producer status returned HTTP $([int]$response.StatusCode)."
                    }
                    $json = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                    if ([Text.Encoding]::UTF8.GetByteCount($json) -gt 65536) {
                        throw 'Visualizer producer status exceeded 64 KiB.'
                    }
                    $status = $json | ConvertFrom-Json -Depth 6
                }
                finally { $response.Dispose() }
            }
            finally { $request.Dispose() }
        }
        finally {
            $client.Dispose(); $handler.Dispose(); $token = $null
        }
    }
    $processSchemaProperty = if ($null -eq $status) { $null } else {
        $status.PSObject.Properties['process_event_schema_version']
    }
    if ($null -eq $status -or [string]$status.status -cne 'ready' -or
        [string]$status.service -cne 'hosthunter-visualizer' -or
        [string]$status.api_version -cne '1.0.0' -or
        [string]$status.collection_run_schema_version -cne '1.0.0' -or
        [string]$status.host_observation_schema_version -cne '1.0.0' -or
        $null -eq $processSchemaProperty -or $null -ne $processSchemaProperty.Value) {
        throw 'Visualizer producer status is incompatible with this HostHunter version.'
    }
    $active = $null
    if ($null -ne $status.active_collection_run_id -and
        -not [string]::IsNullOrWhiteSpace([string]$status.active_collection_run_id)) {
        $parsed = [Guid]::Empty
        if (-not [Guid]::TryParseExact(
                [string]$status.active_collection_run_id, 'D', [ref]$parsed
            )) { throw 'Visualizer producer status returned an invalid collection-run identifier.' }
        $active = $parsed
    }
    [pscustomobject][ordered]@{
        Status = 'ready'
        Service = 'hosthunter-visualizer'
        ApiVersion = '1.0.0'
        ProcessEventSchemaVersion = $null
        ActiveMissionId = $active
    }
}

function Invoke-HHVisualizerPut {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RelativePath,
        [Parameter(Mandatory)][byte[]]$PayloadBytes,
        [Alias('Sender')][scriptblock]$RequestSender
    )
    if ($PayloadBytes.Length -gt 262144) { throw 'Visualizer payload exceeds 256 KiB.' }
    $digest = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($PayloadBytes)
    ).ToLowerInvariant()
    if ($null -ne $RequestSender) {
        return & $RequestSender $RelativePath $PayloadBytes $digest
    }

    $settings = Get-HHVisualizerConnectionSettings
    if (-not [IO.File]::Exists($settings.TokenPath)) {
        return [pscustomobject]@{ Delivered=$false; StatusCode=$null; FailureKind='CredentialUnavailable'; ContentSha256=$digest }
    }
    $token = [IO.File]::ReadAllText($settings.TokenPath).Trim()
    if ([string]::IsNullOrWhiteSpace($token)) {
        return [pscustomobject]@{ Delivered=$false; StatusCode=$null; FailureKind='CredentialUnavailable'; ContentSha256=$digest }
    }
    $handler = [Net.Http.SocketsHttpHandler]::new()
    $handler.ConnectTimeout = [TimeSpan]::FromSeconds(2)
    $client = [Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromSeconds(5)
    try {
        $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Put, "$($settings.BaseUri)$RelativePath")
        try {
            $request.Headers.Authorization = [Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer',$token)
            $request.Headers.Add('X-HostHunter-Content-SHA256',$digest)
            $request.Content = [Net.Http.ByteArrayContent]::new($PayloadBytes)
            $request.Content.Headers.ContentType = [Net.Http.Headers.MediaTypeHeaderValue]::new('application/json')
            $response = $client.Send($request)
            try {
                [pscustomobject]@{
                    Delivered = [bool]$response.IsSuccessStatusCode
                    StatusCode = [int]$response.StatusCode
                    FailureKind = if ($response.IsSuccessStatusCode) { $null } else { 'HttpFailure' }
                    ContentSha256 = $digest
                }
            }
            finally { $response.Dispose() }
        }
        finally { $request.Dispose() }
    }
    catch {
        [pscustomobject]@{ Delivered=$false; StatusCode=$null; FailureKind='TransportFailure'; ContentSha256=$digest }
    }
    finally {
        $client.Dispose(); $handler.Dispose(); $token = $null
    }
}

function Send-HHVisualizerMission {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][Guid]$MissionId,
        [Parameter(Mandatory)][byte[]]$PayloadBytes,
        [Alias('Sender')][scriptblock]$RequestSender
    )
    $id = $MissionId.ToString('D').ToLowerInvariant()
    Invoke-HHVisualizerPut -RelativePath "/api/v1/collection-runs/$id" `
        -PayloadBytes $PayloadBytes -RequestSender $RequestSender
}

function Send-HHVisualizerObservation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][Guid]$MissionId,
        [Parameter(Mandatory)][Guid]$EventId,
        [Parameter(Mandatory)][byte[]]$PayloadBytes,
        [Alias('Sender')][scriptblock]$RequestSender
    )
    $mission = $MissionId.ToString('D').ToLowerInvariant()
    $eventIdText = $EventId.ToString('D').ToLowerInvariant()
    Invoke-HHVisualizerPut `
        -RelativePath "/api/v1/collection-runs/$mission/host-observations/$eventIdText" `
        -PayloadBytes $PayloadBytes -RequestSender $RequestSender
}
