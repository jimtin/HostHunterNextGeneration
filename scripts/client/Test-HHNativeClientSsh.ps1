[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSAvoidUsingConvertToSecureStringWithPlainText',
    '',
    Justification = 'The disposable fixture password is captured directly into test-process memory and immediately converted for a mocked secure prompt.'
)]
[CmdletBinding()]
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path,
    [switch]$RequireProfileLoadedClient
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path -LiteralPath $RepoRoot).Path
$composeFile = Join-Path $repo 'compose.test.yml'
$clientManifest = Join-Path $repo 'client/HostHunter.Client/HostHunter.Client.psd1'
$targetName = $null
$fixtureHostName = 'hh-fixture-' + [Guid]::NewGuid().ToString('N').Substring(0, 12)
$networkName = 'hosthunter-next-generation-test_test'
$controllerId = $null
$networkConnected = $false
$targetRemoved = $false
$script:HHNativeClientCredential = $null
$script:HHNativeClientPromptCount = 0
$script:HHNativeClientConfirmationCount = 0
$script:HHNativeClientAllowPasswordStorage = $false
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
        if ($AsSecureString) {
            $script:HHNativeClientPromptCount++
            return $script:HHNativeClientCredential
        }
        $script:HHNativeClientConfirmationCount++
        if ($Prompt -match 'recommends SSH key') { return 'Y' }
        if ($Prompt -match 'WARNING: Save the password') {
            if ($script:HHNativeClientAllowPasswordStorage) { return 'Y' }
            return 'N'
        }
        throw "Unexpected HostHunter confirmation prompt: $Prompt"
    }

    $env:HH_CLIENT_REPO_ROOT = $repo
    if ($RequireProfileLoadedClient) {
        $loadedClient = Get-Module HostHunter.Client
        if ($null -eq $loadedClient) {
            throw 'The fresh PowerShell process did not auto-load HostHunter.Client from its profile.'
        }
        $expectedClientPath = (Resolve-Path -LiteralPath (
                Join-Path $repo 'client/HostHunter.Client/HostHunter.Client.psm1'
            )).Path
        if ([IO.Path]::GetFullPath([string]$loadedClient.Path) -cne $expectedClientPath) {
            throw "The PowerShell profile loaded a stale HostHunter.Client from '$($loadedClient.Path)'."
        }
    }
    else {
        Import-Module $clientManifest -Force
        $loadedClient = Get-Module HostHunter.Client
    }
    $exports = @(Get-Command -Module HostHunter.Client -CommandType Function |
            Where-Object Name -ne Repair-HHClientRuntime)
    if ($exports.Count -ne 11) { throw "Native client exported $($exports.Count) cmdlets; expected 11." }
    $observedCommands = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    [void]$observedCommands.Add('Get-HHTarget')
    $emptyTargetInformation = @()
    $emptyTargets = @(Get-HHTarget -InformationVariable emptyTargetInformation)
    if ($emptyTargets.Count -ne 0 -or
        [string]$emptyTargetInformation[-1] -cne 'No currently set' -or
        'PSHOST' -cnotin @($emptyTargetInformation[-1].Tags)) {
        throw 'The native empty-target message was not emitted as host-visible console output.'
    }
    if ((Get-Command Get-HHTargets -CommandType Alias).Definition -cne 'Get-HHTarget') {
        throw 'The native plural target alias is unavailable.'
    }
    $pluralInformation = @()
    $pluralTargets = @(Get-HHTargets -InformationVariable pluralInformation)
    if ($pluralTargets.Count -ne 0 -or
        [string]$pluralInformation[-1] -cne 'No currently set' -or
        'PSHOST' -cnotin @($pluralInformation[-1].Tags)) {
        throw 'The native plural alias did not emit the host-visible empty-target message.'
    }

    $controllerId = Invoke-HHNativeDockerCapture @(
        'ps', '--filter',
        'label=com.docker.compose.project=hosthunter-next-generation-runtime',
        '--filter', 'label=com.docker.compose.service=controller', '--format', '{{.ID}}'
    )
    & docker network connect $networkName $controllerId 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'Unable to attach the controller to the disposable SSH network.' }
    $networkConnected = $true

    $trustInformation = @()
    $saved = Set-HHTarget -HostName $fixtureHostName -UserName $userName `
        -Confirm:$false -InformationVariable trustInformation
    [void]$observedCommands.Add('Set-HHTarget')
    $targetName = [string]$saved.Name
    if ([string]::IsNullOrWhiteSpace($targetName) -or
        $saved.HostKeyFingerprint -notmatch '^SHA256:[A-Za-z0-9+/]{43}$' -or
        $saved.Authentication -cne 'PublicKey' -or $saved.CredentialStorage -cne 'None') {
        throw 'The native key-first Set-HHTarget result was incomplete.'
    }
    if (@($trustInformation | Where-Object {
                [string]$_ -match '^Accepting public key ssh-.* SHA256:[A-Za-z0-9+/]{43}$'
            }).Count -ne 1) {
        throw 'First-use SSH trust did not announce the automatically pinned public key.'
    }
    $keyFirstCommand = Invoke-HHCommand -Target $targetName -Command "'native-key-first-output'" `
        -Reason 'native key-first qualification'
    [void]$observedCommands.Add('Invoke-HHCommand')
    if (-not $keyFirstCommand.Succeeded -or $script:HHNativeClientPromptCount -ne 1) {
        throw 'The automatically installed key was not used without another password prompt.'
    }
    Remove-HHTarget -Name $targetName -Confirm:$false | Out-Null
    [void]$observedCommands.Add('Remove-HHTarget')
    $targetRemoved = $true

    $script:HHNativeClientAllowPasswordStorage = $true
    $saved = Set-HHTarget -HostName $fixtureHostName -UserName $userName `
        -Authentication Password -Confirm:$false
    $targetName = [string]$saved.Name
    $targetRemoved = $false
    if ($saved.Authentication -cne 'Password' -or
        $saved.CredentialStorage -cne 'Encrypted' -or
        $script:HHNativeClientPromptCount -ne 2) {
        throw 'The warned encrypted-password onboarding path was not committed.'
    }
    $storedView = @(Get-HHTarget -Name $targetName)
    if ($storedView.Count -ne 1 -or
        $storedView[0].CredentialStorage -cne 'Encrypted') {
        throw 'The saved target did not report encrypted credential storage.'
    }
    $null = Invoke-HHNativeDockerCapture @('restart', $controllerId)
    $controllerHealthy = $false
    for ($healthAttempt = 0; $healthAttempt -lt 60; $healthAttempt++) {
        $health = Invoke-HHNativeDockerCapture @(
            'inspect', '--format', '{{.State.Health.Status}}', $controllerId
        )
        if ($health -ceq 'healthy') { $controllerHealthy = $true; break }
        if ($health -ceq 'unhealthy') { break }
        Start-Sleep -Milliseconds 250
    }
    if (-not $controllerHealthy) {
        throw 'The controller did not become healthy after the persistence restart check.'
    }
    $probe = Test-HHTarget -Name $targetName -Reason 'native stored-password qualification'
    [void]$observedCommands.Add('Test-HHTarget')
    if (-not $probe.Succeeded -or $script:HHNativeClientPromptCount -ne 2) {
        throw 'Stored-password Test-HHTarget was not invisible to the operator.'
    }
    $command = Invoke-HHCommand -Target $targetName -Command "'native-client-output'" `
        -Reason 'native client qualification' -CaseId 'CASE-NATIVE-CLIENT'
    if (-not $command.Succeeded -or $script:HHNativeClientPromptCount -ne 2) {
        throw 'Stored-password Invoke-HHCommand was not invisible to the operator.'
    }
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
    if ($transition.Authentication -cne 'PublicKey' -or
        $transition.CredentialStorage -cne 'None' -or
        $script:HHNativeClientPromptCount -ne 2) {
        throw 'Stored-password key conversion did not purge the credential invisibly.'
    }
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
    & docker exec $fixtureContainerId /usr/local/bin/hh-ssh-rotate-host-key 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'Unable to rotate the disposable fixture host key.' }
    $changedKeyProbe = Test-HHTarget -Name $targetName -Reason 'native changed-key qualification'
    if ($changedKeyProbe.Succeeded -or
        $changedKeyProbe.FailureKind -cnotin @('TrustFailure', 'TransportFailure') -or
        $changedKeyProbe.DispatchState -cne 'NotDispatched' -or
        $script:HHNativeClientPromptCount -ne 2) {
        throw 'A changed host key did not fail closed before another credential prompt.'
    }
    Remove-HHTarget -Name $targetName -Confirm:$false | Out-Null
    $targetRemoved = $true
    if ($observedCommands.Count -ne 11) {
        throw "Native qualification observed $($observedCommands.Count) unique cmdlets; expected 11."
    }
    if ($script:HHNativeClientPromptCount -ne 2) {
        throw "Expected two onboarding secure prompts; observed $script:HHNativeClientPromptCount."
    }
    if ($script:HHNativeClientConfirmationCount -ne 2) {
        throw "Expected two authentication-choice confirmations; observed $script:HHNativeClientConfirmationCount."
    }

    [pscustomobject]@{
        Status = 'passed'
        ClientLoad = if ($RequireProfileLoadedClient) {
            'fresh-process-installed-profile'
        } else { 'source-manifest' }
        ClientModulePath = [string]$loadedClient.Path
        ExportCount = $exports.Count
        InvokedUniqueCommandCount = $observedCommands.Count
        AuthenticationConfirmationCount = $script:HHNativeClientConfirmationCount
        SecurePromptCount = $script:HHNativeClientPromptCount
        PasswordTransport = 'stdin-to-loopback-memory-broker'
        TargetRoundTrip = $true
        AuditRoundTrip = $true
        KeyTransition = $true
        KeyFirstOnboarding = $true
        StoredPasswordOnboarding = $true
        InvisibleStoredPasswordInvocation = $true
        ControllerRestartPersistence = $true
        CredentialPurgedAfterKeyConversion = $true
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
