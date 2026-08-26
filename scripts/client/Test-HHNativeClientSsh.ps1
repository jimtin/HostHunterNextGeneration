[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSAvoidUsingConvertToSecureStringWithPlainText',
    '',
    Justification = 'The disposable fixture password is captured directly into test-process memory and immediately converted for a mocked secure prompt.'
)]
[CmdletBinding()]
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path -LiteralPath $RepoRoot).Path
$composeFile = Join-Path $repo 'compose.test.yml'
$clientManifest = Join-Path $repo 'client/HostHunter.Client/HostHunter.Client.psd1'
$targetName = 'native-client-' + [Guid]::NewGuid().ToString('N').Substring(0, 12)
$fixtureHostName = 'hh-fixture-' + [Guid]::NewGuid().ToString('N').Substring(0, 12)
$networkName = 'hosthunter-next-generation-test_test'
$controllerId = $null
$networkConnected = $false
$targetRemoved = $false
$script:HHNativeClientCredential = $null
$script:HHNativeClientPromptCount = 0
$previousRepoRoot = $env:HH_CLIENT_REPO_ROOT

function Invoke-HHNativeDockerCapture {
    param([Parameter(Mandatory)][string[]]$Arguments)
    $lines = @(& docker @Arguments 2>&1)
    if ($LASTEXITCODE -ne 0) { throw 'A Docker fixture operation failed.' }
    [string]::Join("`n", $lines).Trim()
}

try {
    $password = Invoke-HHNativeDockerCapture @(
        'compose', '-f', $composeFile, 'exec', '-T', 'ssh-target',
        'cat', '/run/hosthunter-ssh/password'
    )
    $fingerprint = Invoke-HHNativeDockerCapture @(
        'compose', '-f', $composeFile, 'exec', '-T', 'ssh-target',
        'cat', '/run/hosthunter-ssh/hostkey.sha256'
    )
    $userName = Invoke-HHNativeDockerCapture @(
        'compose', '-f', $composeFile, 'exec', '-T', 'ssh-target',
        'cat', '/run/hosthunter-ssh/username'
    )
    $fixtureContainerId = Invoke-HHNativeDockerCapture @(
        'compose', '-f', $composeFile, 'ps', '-q', 'ssh-target'
    )
    & docker network disconnect $networkName $fixtureContainerId 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'Unable to reset the disposable fixture network alias.' }
    & docker network connect --alias $fixtureHostName $networkName $fixtureContainerId 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'Unable to assign the disposable fixture network alias.' }
    $script:HHNativeClientCredential = ConvertTo-SecureString $password -AsPlainText -Force
    $password = $null

    function global:Read-Host {
        param([string]$Prompt, [switch]$AsSecureString)
        $null = $Prompt
        if (-not $AsSecureString) { throw 'The native-client qualification only permits secure prompts.' }
        $script:HHNativeClientPromptCount++
        $script:HHNativeClientCredential
    }

    $env:HH_CLIENT_REPO_ROOT = $repo
    Import-Module $clientManifest -Force
    $exports = @(Get-Command -Module HostHunter.Client -CommandType Function |
            Where-Object Name -ne Repair-HHClientRuntime)
    if ($exports.Count -ne 11) { throw "Native client exported $($exports.Count) cmdlets; expected 11." }
    $observedCommands = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    [void]$observedCommands.Add('Get-HHTarget')
    $null = @(Get-HHTarget)
    if ((Get-Command Get-HHTargets -CommandType Alias).Definition -cne 'Get-HHTarget') {
        throw 'The native plural target alias is unavailable.'
    }

    $controllerId = Invoke-HHNativeDockerCapture @(
        'ps', '--filter',
        'label=com.docker.compose.project=hosthunter-next-generation-runtime',
        '--filter', 'label=com.docker.compose.service=controller', '--format', '{{.ID}}'
    )
    & docker network connect $networkName $controllerId 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'Unable to attach the controller to the disposable SSH network.' }
    $networkConnected = $true

    $saved = Set-HHTarget -Name $targetName -HostName $fixtureHostName -UserName $userName `
        -HostKeyFingerprint $fingerprint -Add -Confirm:$false
    [void]$observedCommands.Add('Set-HHTarget')
    if ($saved.Name -cne $targetName) { throw 'The native Set-HHTarget result was incorrect.' }
    $probe = Test-HHTarget -Name $targetName -Reason 'native client qualification'
    [void]$observedCommands.Add('Test-HHTarget')
    if (-not $probe.Succeeded) { throw 'The native Test-HHTarget probe failed.' }
    $command = Invoke-HHCommand -Target $targetName -Command "'native-client-output'" `
        -Reason 'native client qualification' -CaseId 'CASE-NATIVE-CLIENT'
    [void]$observedCommands.Add('Invoke-HHCommand')
    if (-not $command.Succeeded) { throw 'The native Invoke-HHCommand operation failed.' }
    $audit = @(Get-HHAuditRecord -InvocationId $command.InvocationId -First 1)
    [void]$observedCommands.Add('Get-HHAuditRecord')
    $output = @(Get-HHAuditOutput -InvocationId $command.InvocationId)
    [void]$observedCommands.Add('Get-HHAuditOutput')
    if ($audit.Count -ne 1 -or $output.Count -eq 0) {
        throw 'The native audit readback was incomplete.'
    }
    & docker exec $controllerId test -f /var/lib/hosthunter-data/keys/hosthunter_ed25519
    $keyArguments = if ($LASTEXITCODE -eq 0) { @{ UseExistingKey = $true } } else { @{} }
    $transition = Enable-HHSshKeyAuthentication -Name $targetName `
        -Reason 'native client qualification' -Confirm:$false @keyArguments
    [void]$observedCommands.Add('Enable-HHSshKeyAuthentication')
    if ($transition.Authentication -cne 'PublicKey') { throw 'The native key transition failed.' }
    $keyCommand = Invoke-HHCommand -Target $targetName -Command "'native-key-output'" `
        -Reason 'native client key qualification'
    if (-not $keyCommand.Succeeded) { throw 'The native key-only command failed.' }
    $policy = Set-HHWindowsProcessAuditPolicy -Target $targetName -State Enabled `
        -Escalate -Reason 'native Linux policy qualification' -Confirm:$false
    [void]$observedCommands.Add('Set-HHWindowsProcessAuditPolicy')
    if ($policy.Succeeded -or $policy.OutcomeStatus -cne 'Failed') {
        throw 'The native Linux policy operation did not return its finite audited failure.'
    }
    $preference = Set-HHEscalationPreference -Method WindowsTokenPrivilege -Confirm:$false
    [void]$observedCommands.Add('Set-HHEscalationPreference')
    $reloadedPreference = Get-HHEscalationPreference
    [void]$observedCommands.Add('Get-HHEscalationPreference')
    if ($preference.Method -cne 'WindowsTokenPrivilege' -or
        $reloadedPreference.Method -cne 'WindowsTokenPrivilege') {
        throw 'The native escalation preference round trip failed.'
    }
    Remove-HHTarget -Name $targetName -Confirm:$false | Out-Null
    [void]$observedCommands.Add('Remove-HHTarget')
    $targetRemoved = $true
    if ($observedCommands.Count -ne 11) {
        throw "Native qualification observed $($observedCommands.Count) unique cmdlets; expected 11."
    }
    if ($script:HHNativeClientPromptCount -ne 4) {
        throw "Expected four command-scoped secure prompts; observed $script:HHNativeClientPromptCount."
    }

    [pscustomobject]@{
        Status = 'passed'
        ExportCount = $exports.Count
        InvokedUniqueCommandCount = $observedCommands.Count
        SecurePromptCount = $script:HHNativeClientPromptCount
        PasswordTransport = 'stdin-to-loopback-memory-broker'
        TargetRoundTrip = $true
        AuditRoundTrip = $true
        KeyTransition = $true
    }
}
finally {
    if (-not $targetRemoved -and $null -ne (
            Get-Command Remove-HHTarget -ErrorAction SilentlyContinue
        )) {
        Remove-HHTarget -Name $targetName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
    }
    if ($networkConnected -and -not [string]::IsNullOrWhiteSpace($controllerId)) {
        & docker network disconnect $networkName $controllerId 2>$null | Out-Null
    }
    Remove-Item Function:/Read-Host -Force -ErrorAction SilentlyContinue
    Remove-Module HostHunter.Client -Force -ErrorAction SilentlyContinue
    $script:HHNativeClientCredential = $null
    $env:HH_CLIENT_REPO_ROOT = $previousRepoRoot
}
