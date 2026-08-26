[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module $env:HH_RUNTIME_MODULE_PATH -Force
$module = Get-Module HostHunterNextGeneration -ErrorAction Stop
$commands = @(Get-Command -Module $module.Name -CommandType Function | Sort-Object Name)
$aliases = @(Get-Command -Module $module.Name -CommandType Alias | Sort-Object Name)

$descriptions = @(
    foreach ($command in $commands) {
        $metadata = [Management.Automation.CommandMetadata]::new($command)
        $proxyText = [Management.Automation.ProxyCommand]::Create($metadata)
        $prefix = "function __HostHunterProxy {`n"
        $tokens = $null
        $errors = $null
        $ast = [Management.Automation.Language.Parser]::ParseInput(
            "$prefix$proxyText`n}",
            [ref]$tokens,
            [ref]$errors
        )
        if ($errors.Count -gt 0) {
            throw "Generated proxy metadata for '$($command.Name)' did not parse."
        }
        $functionAst = $ast.EndBlock.Statements[0]
        $beginOffset = $functionAst.Body.BeginBlock.Extent.StartOffset - $prefix.Length
        if ($beginOffset -le 0) {
            throw "Generated proxy metadata for '$($command.Name)' has no begin block."
        }
        $pipelineParameters = @(
            foreach ($parameter in $command.Parameters.Values) {
                $acceptsPipeline = @($parameter.Attributes | Where-Object {
                        $_ -is [Management.Automation.ParameterAttribute] -and
                        ($_.ValueFromPipeline -or $_.ValueFromPipelineByPropertyName)
                    }).Count -gt 0
                if ($acceptsPipeline) { $parameter.Name }
            }
        )
        [pscustomobject][ordered]@{
            name = $command.Name
            declaration = $proxyText.Substring(0, $beginOffset).TrimEnd()
            pipelineParameters = $pipelineParameters
        }
    }
)

[pscustomobject][ordered]@{
    schema = 'HostHunter.ClientCommandMetadata.v1'
    protocolVersion = 1
    moduleVersion = [string]$module.Version
    sourceFingerprint = [string]$env:HH_SOURCE_FINGERPRINT
    commands = $descriptions
    aliases = @($aliases | ForEach-Object {
            [pscustomobject][ordered]@{ name = $_.Name; target = $_.Definition }
        })
} | ConvertTo-Json -Depth 12 -Compress
