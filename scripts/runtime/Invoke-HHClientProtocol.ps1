[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:HHClientMaximumRequestBytes = 16MB
$script:HHClientFrameLock = [object]::new()

if ($null -eq ('HostHunter.Client.CredentialBroker' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace HostHunter.Client
{
    public sealed class CredentialBroker : IDisposable
    {
        private readonly TcpListener listener;
        private readonly TextReader input;
        private readonly TextWriter output;
        private readonly string token;
        private readonly Thread thread;
        private byte[] passwordBase64;
        private volatile bool stopping;

        public CredentialBroker(TextReader input, TextWriter output)
        {
            this.input = input;
            this.output = TextWriter.Synchronized(output);
            token = Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
            listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start(4);
            thread = new Thread(Serve) { IsBackground = true, Name = "HostHunterCredentialBroker" };
            thread.Start();
        }

        public int Port => ((IPEndPoint)listener.LocalEndpoint).Port;
        public string Token => token;

        private void Serve()
        {
            while (!stopping)
            {
                TcpClient client;
                try { client = listener.AcceptTcpClient(); }
                catch (SocketException) when (stopping) { return; }
                catch (ObjectDisposedException) when (stopping) { return; }
                using (client)
                using (NetworkStream stream = client.GetStream())
                using (StreamReader reader = new StreamReader(stream, Encoding.UTF8, false, 1024, true))
                using (StreamWriter writer = new StreamWriter(stream, new UTF8Encoding(false), 1024, true) { AutoFlush = true })
                {
                    client.ReceiveTimeout = 120000;
                    client.SendTimeout = 120000;
                    string suppliedToken = reader.ReadLine();
                    string promptBase64 = reader.ReadLine();
                    if (!String.Equals(suppliedToken, token, StringComparison.Ordinal) ||
                        String.IsNullOrWhiteSpace(promptBase64) || promptBase64.Length > 16384)
                    {
                        continue;
                    }
                    if (passwordBase64 == null)
                    {
                        byte[] promptBytes = null;
                        try
                        {
                            promptBytes = Convert.FromBase64String(promptBase64);
                            if (promptBytes.Length > 4096) { continue; }
                            string promptFrame = Convert.ToBase64String(promptBytes);
                            output.WriteLine("{\"type\":\"credential_request\",\"prompt\":\"" + promptFrame + "\"}");
                            output.Flush();
                        }
                        finally
                        {
                            if (promptBytes != null) { Array.Clear(promptBytes, 0, promptBytes.Length); }
                        }
                        string response = input.ReadLine();
                        const string prefix = "credential ";
                        if (response == null || !response.StartsWith(prefix, StringComparison.Ordinal) ||
                            response.Length > 131072) { continue; }
                        passwordBase64 = Encoding.ASCII.GetBytes(response.Substring(prefix.Length));
                        byte[] decodedPassword = null;
                        try { decodedPassword = Convert.FromBase64String(Encoding.ASCII.GetString(passwordBase64)); }
                        catch (FormatException)
                        {
                            Array.Clear(passwordBase64, 0, passwordBase64.Length);
                            passwordBase64 = null;
                            continue;
                        }
                        finally
                        {
                            if (decodedPassword != null) { Array.Clear(decodedPassword, 0, decodedPassword.Length); }
                        }
                    }
                    writer.WriteLine(Encoding.ASCII.GetString(passwordBase64));
                }
            }
        }

        public void Dispose()
        {
            stopping = true;
            listener.Stop();
            if (Thread.CurrentThread != thread) { thread.Join(TimeSpan.FromSeconds(2)); }
            if (passwordBase64 != null) { Array.Clear(passwordBase64, 0, passwordBase64.Length); }
        }
    }
}
'@
}

function Write-HHClientFrame {
    param(
        [Parameter(Mandatory)][string]$Type,
        [AllowNull()][object]$Value,
        [string]$Message,
        [string]$Status
    )

    $frame = [ordered]@{ type = $Type }
    if ($PSBoundParameters.ContainsKey('Value')) {
        $serialized = [Management.Automation.PSSerializer]::Serialize($Value, 20)
        $frame.payload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($serialized))
    }
    if ($PSBoundParameters.ContainsKey('Message')) { $frame.message = $Message }
    if ($PSBoundParameters.ContainsKey('Status')) { $frame.status = $Status }
    [Threading.Monitor]::Enter($script:HHClientFrameLock)
    try {
        [Console]::Out.WriteLine(($frame | ConvertTo-Json -Compress -Depth 8))
        [Console]::Out.Flush()
    }
    finally { [Threading.Monitor]::Exit($script:HHClientFrameLock) }
}

function Write-HHClientRecord {
    param([AllowNull()][object]$Record)

    $type = switch ($Record) {
        { $_ -is [Management.Automation.ErrorRecord] } { 'error'; break }
        { $_ -is [Management.Automation.WarningRecord] } { 'warning'; break }
        { $_ -is [Management.Automation.VerboseRecord] } { 'verbose'; break }
        { $_ -is [Management.Automation.DebugRecord] } { 'debug'; break }
        { $_ -is [Management.Automation.InformationRecord] } { 'information'; break }
        { $_ -is [Management.Automation.ProgressRecord] } { 'progress'; break }
        default { 'output' }
    }
    Write-HHClientFrame -Type $type -Value $Record
}

try {
    $requestLine = [Console]::In.ReadLine()
    if ([string]::IsNullOrWhiteSpace($requestLine)) {
        throw 'HostHunter client protocol requires one request frame on standard input.'
    }
    if ([Text.Encoding]::UTF8.GetByteCount($requestLine) -gt $script:HHClientMaximumRequestBytes) {
        throw 'HostHunter client request exceeds the protocol size limit.'
    }
    $requestFrame = $requestLine | ConvertFrom-Json -AsHashtable -Depth 20
    if ($requestFrame.schema -cne 'HostHunter.ClientInvocation.v1') {
        throw 'HostHunter client invocation schema is unsupported.'
    }
    $requestXml = [Text.Encoding]::UTF8.GetString(
        [Convert]::FromBase64String([string]$requestFrame.payload)
    )
    $request = [Management.Automation.PSSerializer]::Deserialize($requestXml)
    $commandName = [string]$request.CommandName
    Import-Module $env:HH_RUNTIME_MODULE_PATH -Force
    $null = Get-Command -Module HostHunterNextGeneration -Name $commandName `
        -CommandType Function -ErrorAction Stop
    $parameters = @{}
    foreach ($entry in $request.Parameters.GetEnumerator()) {
        $parameters[[string]$entry.Key] = $entry.Value
    }

    $environmentNames = @(
        'DISPLAY', 'SSH_ASKPASS', 'SSH_ASKPASS_REQUIRE',
        'HH_CLIENT_BROKER_PORT', 'HH_CLIENT_BROKER_TOKEN'
    )
    $savedEnvironment = @{}
    foreach ($name in $environmentNames) {
        $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
    }
    $broker = [HostHunter.Client.CredentialBroker]::new([Console]::In, [Console]::Out)
    try {
        $env:DISPLAY = 'hosthunter-client'
        $env:SSH_ASKPASS = '/opt/hosthunter/runtime/client-askpass.sh'
        $env:SSH_ASKPASS_REQUIRE = 'force'
        $env:HH_CLIENT_BROKER_PORT = [string]$broker.Port
        $env:HH_CLIENT_BROKER_TOKEN = $broker.Token
        $runner = [PowerShell]::Create()
        try {
            $runnerScript = @'
param($ModulePath, $CommandName, $Parameters, $HasPipelineInput, $PipelineInput)
Import-Module $ModulePath -Force
$command = Get-Command -Module HostHunterNextGeneration -Name $CommandName `
    -CommandType Function -ErrorAction Stop
if ($HasPipelineInput) { @($PipelineInput) | & $command @Parameters }
else { & $command @Parameters }
'@
            [void]$runner.AddScript($runnerScript).AddArgument($env:HH_RUNTIME_MODULE_PATH).
                AddArgument($commandName).AddArgument($parameters).
                AddArgument([bool]$request.HasPipelineInput).AddArgument(@($request.PipelineInput))
            $output = [Management.Automation.PSDataCollection[psobject]]::new()
            $streamIndexes = @{ Output = 0 }
            foreach ($streamName in @('Error', 'Warning', 'Verbose', 'Debug', 'Information', 'Progress')) {
                $streamIndexes[$streamName] = 0
            }
            $async = $runner.BeginInvoke[object, psobject]($null, $output)
            do {
                while ($streamIndexes.Output -lt $output.Count) {
                    Write-HHClientRecord -Record $output[$streamIndexes.Output]
                    $streamIndexes.Output++
                }
                foreach ($streamName in @(
                        'Error', 'Warning', 'Verbose', 'Debug', 'Information', 'Progress'
                    )) {
                    $stream = $runner.Streams.$streamName
                    while ($streamIndexes[$streamName] -lt $stream.Count) {
                        Write-HHClientRecord -Record $stream[$streamIndexes[$streamName]]
                        $streamIndexes[$streamName]++
                    }
                }
            } while (-not $async.AsyncWaitHandle.WaitOne(25))
            $runner.EndInvoke($async)
            while ($streamIndexes.Output -lt $output.Count) {
                Write-HHClientRecord -Record $output[$streamIndexes.Output]
                $streamIndexes.Output++
            }
            foreach ($streamName in @(
                    'Error', 'Warning', 'Verbose', 'Debug', 'Information', 'Progress'
                )) {
                $stream = $runner.Streams.$streamName
                while ($streamIndexes[$streamName] -lt $stream.Count) {
                    Write-HHClientRecord -Record $stream[$streamIndexes[$streamName]]
                    $streamIndexes[$streamName]++
                }
            }
            if ($runner.HadErrors) {
                throw "HostHunter command '$commandName' emitted one or more errors."
            }
        }
        finally {
            if ($null -ne $runner) { $runner.Dispose() }
        }
    }
    finally {
        $broker.Dispose()
        foreach ($name in $environmentNames) {
            [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name], 'Process')
        }
    }
    Write-HHClientFrame -Type terminal -Status succeeded
}
catch {
    Write-HHClientFrame -Type error -Value $_
    Write-HHClientFrame -Type terminal -Status failed -Message $_.Exception.Message
    exit 1
}
