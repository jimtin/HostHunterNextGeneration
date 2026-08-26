[CmdletBinding()]
param(
    [string]$ModuleRoot = (Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$expected = [ordered]@{
    'Set-HHTarget.ps1' = 'ValidateTarget'
    'Test-HHTarget.ps1' = 'TestTarget'
    'Invoke-HHCommand.ps1' = 'InvokeCommand'
    'Enable-HHSshKeyAuthentication.ps1' = 'EnableSshKeyAuthentication'
    'Set-HHWindowsProcessAuditPolicy.ps1' = 'SetWindowsProcessAuditPolicy'
}
$hostCmdlets = @(
    'Set-HHTarget',
    'Test-HHTarget',
    'Invoke-HHCommand',
    'Enable-HHSshKeyAuthentication',
    'Set-HHWindowsProcessAuditPolicy'
)
$forbiddenBoundaryCommands = @(
    'Invoke-HHManagedHostCommandCoordinator',
    'Invoke-HHTargetProbe',
    'Register-HHSshHostTrust',
    'Invoke-HHSshKeyBootstrap',
    'Open-HHSshSession',
    'Invoke-HHSshCommand',
    'New-PSSession',
    'Invoke-Command',
    'Register-HHAuthenticatedAuditBatch',
    'Start-HHAuthenticatedAuditCapacityReservation',
    'Arm-HHAuthenticatedRemoteOperation',
    'Complete-HHAuthenticatedTransportAudit',
    'Complete-HHAuthenticatedUnstartedAuditIntent',
    'ssh',
    'ssh-keyscan',
    'scp'
)

$publicRoot = Join-Path $ModuleRoot 'Public'
$errors = [Collections.Generic.List[string]]::new()
foreach ($entry in $expected.GetEnumerator()) {
    $path = Join-Path $publicRoot $entry.Key
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        $errors.Add("Missing managed-host public cmdlet file '$($entry.Key)'.")
        continue
    }

    $tokens = $null
    $parseErrors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile(
        $path,
        [ref]$tokens,
        [ref]$parseErrors
    )
    foreach ($parseError in @($parseErrors)) {
        $errors.Add("$($entry.Key): parse error: $($parseError.Message)")
    }

    $commands = @($ast.FindAll({
                param($candidate)
                $candidate -is [Management.Automation.Language.CommandAst]
            }, $true))
    $gatewayCalls = @($commands | Where-Object {
            $_.GetCommandName() -ceq 'Invoke-HHManagedHostOperation'
        })
    if ($gatewayCalls.Count -ne 1) {
        $errors.Add(
            "$($entry.Key): expected exactly one Invoke-HHManagedHostOperation call; found $($gatewayCalls.Count)."
        )
    }
    elseif ($gatewayCalls[0].Extent.Text -notmatch (
            '(?is)-Operation\s+' + [regex]::Escape([string]$entry.Value) + '(?:\s|$)'
        )) {
        $errors.Add(
            "$($entry.Key): gateway operation must be the literal '$($entry.Value)'."
        )
    }

    foreach ($command in $commands) {
        $commandName = $command.GetCommandName()
        if ([string]::IsNullOrWhiteSpace($commandName)) { continue }
        if ($commandName -cin $forbiddenBoundaryCommands) {
            $errors.Add("$($entry.Key): forbidden boundary bypass '$commandName'.")
        }
        if ($commandName -cin $hostCmdlets) {
            $errors.Add("$($entry.Key): public-to-public host call '$commandName'.")
        }
    }
}

$nonHostPublicFiles = @(Get-ChildItem -LiteralPath $publicRoot -Filter '*.ps1' -File |
        Where-Object { -not $expected.Contains($_.Name) })
foreach ($file in $nonHostPublicFiles) {
    $tokens = $null
    $parseErrors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile(
        $file.FullName,
        [ref]$tokens,
        [ref]$parseErrors
    )
    foreach ($parseError in @($parseErrors)) {
        $errors.Add("$($file.Name): parse error: $($parseError.Message)")
    }
    $commands = @($ast.FindAll({
                param($candidate)
                $candidate -is [Management.Automation.Language.CommandAst]
            }, $true))
    foreach ($command in $commands) {
        $commandName = $command.GetCommandName()
        if ([string]::IsNullOrWhiteSpace($commandName)) { continue }
        if ($commandName -ceq 'Invoke-HHManagedHostOperation' -or
            $commandName -cin $forbiddenBoundaryCommands) {
            $errors.Add(
                "$($file.Name): non-host cmdlet contains managed-host call '$commandName'."
            )
        }
        if ($commandName -cin $hostCmdlets) {
            $errors.Add("$($file.Name): public-to-public host call '$commandName'.")
        }
    }
}

$enginePath = Join-Path $ModuleRoot 'Private/ManagedHostOperation.ps1'
if (-not (Test-Path -LiteralPath $enginePath -PathType Leaf)) {
    $errors.Add('Missing Private/ManagedHostOperation.ps1.')
}
else {
    $engineText = [IO.File]::ReadAllText($enginePath)
    foreach ($operation in $expected.Values) {
        if ($engineText -notmatch ("'" + [regex]::Escape($operation) + "'")) {
            $errors.Add("Managed-host engine does not declare '$operation'.")
        }
    }
    if ($engineText -notmatch '(?m)^function Invoke-HHManagedHostOperation\s*\{') {
        $errors.Add('Managed-host facade function is missing.')
    }
}

if ($errors.Count -gt 0) {
    throw [IO.InvalidDataException]::new(
        "Managed-host boundary validation failed:" +
        [Environment]::NewLine +
        (($errors | ForEach-Object { " - $_" }) -join [Environment]::NewLine)
    )
}

[pscustomobject][ordered]@{
    Succeeded = $true
    ManagedHostCmdletCount = $expected.Count
    Operations = [string[]]$expected.Values
    EnginePath = [IO.Path]::GetFullPath($enginePath)
}
