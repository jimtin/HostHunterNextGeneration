[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ModuleManifestPath,
    [string]$TargetName,
    [Parameter(Mandatory)][string]$CandidateSha,
    [Parameter(Mandatory)][string]$ControllerImageId,
    [Parameter(Mandatory)][string]$ReceiptPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$expected = @(
    'Get-HHTarget', 'Set-HHTarget', 'Get-TargetHostDetails', 'Test-HHTarget', 'Invoke-HHCommand',
    'Get-HHAuditRecord', 'Get-HHAuditOutput', 'Enable-HHSshKeyAuthentication',
    'Set-HHWindowsProcessAuditPolicy', 'Set-HHEscalationPreference',
    'Get-HHEscalationPreference', 'Remove-HHTarget'
)
$rows = [Collections.Generic.List[object]]::new()
$selectedTargetName = $null
$policyChanged = $false
$policyRestorationAttempted = $false
$policyRestorationOutcome = $null
$commandLineRestoreState = 'Unchanged'
$processCreationRestoreState = $null
$windowsAuditEventVerified = $false
$cloneMissionPaused = $false
$targetSaved = $false
$status = 'failed'
$failure = $null

function Invoke-QualificationStep {
    param([string]$Cmdlet, [scriptblock]$Action)
    $watch = [Diagnostics.Stopwatch]::StartNew()
    try {
        $value = & $Action
        $script:rows.Add([pscustomobject]@{
                cmdlet = $Cmdlet; status = 'passed'; durationMs = $watch.ElapsedMilliseconds
                error = $null; observation = $value
            })
        return $value
    }
    catch {
        $script:rows.Add([pscustomobject]@{
                cmdlet = $Cmdlet; status = 'failed'; durationMs = $watch.ElapsedMilliseconds
                error = $_.Exception.Message; observation = $null
            })
        throw
    }
    finally { $watch.Stop() }
}

function Restore-QualificationPolicy {
    if (-not $script:policyChanged -or $script:policyRestorationAttempted) { return }
    $script:policyRestorationAttempted = $true
    if ($script:processCreationRestoreState -notin @('Enabled', 'Disabled')) {
        throw 'The original Process Creation audit state is unavailable for restoration.'
    }
    $requestedCommandLineState = if (
        $script:processCreationRestoreState -ceq 'Disabled' -and
        $script:commandLineRestoreState -ceq 'Enabled'
    ) { 'Unchanged' }
    else { $script:commandLineRestoreState }
    $restoration = Set-HHWindowsProcessAuditPolicy -Target $script:selectedTargetName `
        -State $script:processCreationRestoreState -Subcategory ProcessCreation `
        -CommandLineLogging $requestedCommandLineState -Escalate `
        -Reason 'exact-SHA Windows qualification restoration' -Confirm:$false
    $policySucceeded = $null -ne $restoration.PolicyOutcome -and
        [bool]$restoration.PolicyOutcome.Succeeded
    $script:policyRestorationOutcome = [ordered]@{
        operationSucceeded = [bool]$restoration.Succeeded
        policySucceeded = $policySucceeded
        dispatchState = [string]$restoration.DispatchState
        outcomeStatus = [string]$restoration.OutcomeStatus
        failureKind = [string]$restoration.FailureKind
        exceptionType = [string]$restoration.ExceptionType
        commandLineBefore = $script:commandLineRestoreState
        commandLineAfter = [string]$restoration.PolicyOutcome.CommandLineAfter
    }
    if ($policySucceeded) {
        $script:policyChanged = $false
    }
    if (-not $policySucceeded) {
        throw 'Windows process-audit policy restoration was not confirmed by its policy outcome.'
    }
    if ([string]$restoration.PolicyOutcome.CommandLineAfter -cne
        $script:commandLineRestoreState) {
        throw 'The original command-line audit state was not restored exactly.'
    }
    if (-not $restoration.Succeeded) {
        throw 'Windows process-audit policy was restored but its operation did not terminalize successfully.'
    }
}

function Test-QualificationWindowsAuditEvent {
    $marker = 'HHQ' + [Guid]::NewGuid().ToString('N')
    $probeCommand = @'
$marker = '__MARKER__'
$startedAt = [DateTime]::UtcNow.AddSeconds(-5)
$creatorProcessId = $PID
$startInfo = [Diagnostics.ProcessStartInfo]::new()
$startInfo.FileName = Join-Path $env:SystemRoot 'System32\cmd.exe'
$startInfo.UseShellExecute = $false
$startInfo.CreateNoWindow = $true
$startInfo.Arguments = '/d /c echo ' + $marker + '>NUL'
$process = [Diagnostics.Process]::new()
$process.StartInfo = $startInfo
if (-not $process.Start()) { throw 'The audit marker process did not start.' }
try {
    if (-not $process.WaitForExit(15000)) {
        $process.Kill()
        throw 'The audit marker process did not exit in time.'
    }
    $markerProcessId = $process.Id
}
finally { $process.Dispose() }

$matched = $null
$deadline = [DateTime]::UtcNow.AddSeconds(30)
do {
    $events = @(Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            Id = 4688
            StartTime = $startedAt
        } -MaxEvents 256 -ErrorAction Stop)
    foreach ($eventRecord in $events) {
        $eventXml = [xml]$eventRecord.ToXml()
        $fields = @{}
        foreach ($field in @($eventXml.Event.EventData.Data)) {
            $fields[[string]$field.Name] = [string]$field.'#text'
        }
        $eventProcessId = [string]$fields['NewProcessId']
        $eventCreatorProcessId = [string]$fields['ProcessId']
        if ($eventProcessId -match '^0x[0-9a-fA-F]+$' -and
            $eventCreatorProcessId -match '^0x[0-9a-fA-F]+$' -and
            [Convert]::ToInt64($eventProcessId.Substring(2), 16) -eq $markerProcessId -and
            [Convert]::ToInt64($eventCreatorProcessId.Substring(2), 16) -eq
                $creatorProcessId) {
            $matched = $fields
            break
        }
    }
    if ($null -eq $matched) { Start-Sleep -Milliseconds 250 }
} while ($null -eq $matched -and [DateTime]::UtcNow -lt $deadline)

if ($null -eq $matched) { throw 'The expected Security event 4688 was not observed.' }
$commandLine = [string]$matched['CommandLine']
[pscustomobject]@{
    Marker = 'HostHunter.WindowsProcessAuditEventProbe.v1'
    EventFound = $true
    CommandLinePresent = -not [string]::IsNullOrWhiteSpace($commandLine)
    MarkerPresent = $commandLine.Contains($marker)
}
'@.Replace('__MARKER__', $marker)

    $probe = Invoke-HHCommand -Target $script:selectedTargetName -Command $probeCommand `
        -Reason 'exact-SHA Windows process-audit event proof' `
        -CaseId 'WINDOWS-QUALIFICATION-AUDIT-EVENT'
    $eventOutcome = @($probe.StreamEvents | Where-Object {
            $_.Phase -ceq 'Command' -and
            $_.Value.Marker -ceq 'HostHunter.WindowsProcessAuditEventProbe.v1'
        } | Select-Object -Last 1)
    if (-not $probe.Succeeded -or $eventOutcome.Count -ne 1 -or
        -not [bool]$eventOutcome[0].Value.EventFound -or
        -not [bool]$eventOutcome[0].Value.CommandLinePresent -or
        -not [bool]$eventOutcome[0].Value.MarkerPresent) {
        throw 'Windows Security event 4688 command-line proof failed.'
    }
    $script:windowsAuditEventVerified = $true
}

try {
    Import-Module $ModuleManifestPath -Force
    $exports = @(Get-Command -Module HostHunterNextGeneration -CommandType Function |
            Sort-Object Name | ForEach-Object Name)
    if ($exports.Count -ne 12) { throw "Expected 12 exports; observed $($exports.Count)." }

    $module = Get-Module HostHunterNextGeneration
    $pauseReceipt = & $module {
        Invoke-HHVisualizationLifecycleCore -Action pause
    }
    if ($pauseReceipt.PublishingState -cne 'Paused') {
        throw 'The disposable qualification mission state was not paused.'
    }
    $cloneMissionPaused = $true

    $savedTargets = @(Invoke-QualificationStep Get-HHTarget { @(Get-HHTarget) })
    $eligibleTargets = @($savedTargets | Where-Object {
            $_.IsActive -and $_.Transport -ceq 'SSH' -and
            $_.Authentication -ceq 'PublicKey' -and
            ([string]::IsNullOrWhiteSpace($TargetName) -or
                $_.Name -ieq $TargetName)
        })
    if ($eligibleTargets.Count -ne 1) {
        throw (
            'Windows qualification requires exactly one active saved SSH public-key ' +
            'target, or HH_WINDOWS_QUALIFICATION_TARGET must select one.'
        )
    }
    $savedTarget = $eligibleTargets[0]
    $selectedTargetName = [string]$savedTarget.Name
    $targetSaved = $true
    $null = Invoke-QualificationStep Set-HHTarget {
        Set-HHTarget -Name $selectedTargetName -HostName $savedTarget.HostName `
            -Port $savedTarget.Port -UserName $savedTarget.UserName `
            -Authentication PublicKey -KeyPath $savedTarget.KeyPath `
            -HostKeyFingerprint $savedTarget.HostKeyFingerprint `
            -Reason 'exact-SHA Windows qualification' -Confirm:$false
    }
    $details = Invoke-QualificationStep Get-TargetHostDetails {
        Get-TargetHostDetails -Name $selectedTargetName `
            -Reason 'exact-SHA Windows qualification'
    }
    if ($details.Platform -cne 'windows' -or $details.VisualizerPublishingState -cne 'Paused') {
        throw 'Windows host details did not report Windows while visualization was paused.'
    }
    $probe = Invoke-QualificationStep Test-HHTarget {
        Test-HHTarget -Name $selectedTargetName -Reason 'exact-SHA Windows qualification'
    }
    if (-not $probe.Succeeded -or $probe.RemotePSEdition -cne 'Core') {
        throw 'Windows target did not prove a PowerShell 7 Core SSH endpoint.'
    }
    $command = Invoke-QualificationStep Invoke-HHCommand {
        Invoke-HHCommand -Target $selectedTargetName `
            -Command '[Environment]::OSVersion.Platform; "HH-WINDOWS-OK"' `
            -Reason 'exact-SHA Windows qualification' -CaseId 'WINDOWS-QUALIFICATION'
    }
    if (-not $command.Succeeded) { throw 'Windows command execution failed.' }
    $record = Invoke-QualificationStep Get-HHAuditRecord {
        Get-HHAuditRecord -InvocationId $command.InvocationId -First 1
    }
    if (@($record).Count -ne 1) { throw 'Windows command audit record was not readable.' }
    $output = Invoke-QualificationStep Get-HHAuditOutput {
        @(Get-HHAuditOutput -InvocationId $command.InvocationId)
    }
    if (@($output).Count -lt 1) { throw 'Windows command output was not readable.' }
    $key = Invoke-QualificationStep Enable-HHSshKeyAuthentication {
        Enable-HHSshKeyAuthentication -Name $selectedTargetName `
            -Reason 'exact-SHA Windows qualification' -Confirm:$false
    }
    if ($key.Authentication -cne 'PublicKey') { throw 'Windows SSH key transition failed.' }
    $policy = Invoke-QualificationStep Set-HHWindowsProcessAuditPolicy {
        Set-HHWindowsProcessAuditPolicy -Target $selectedTargetName `
            -State Enabled -Subcategory ProcessCreation `
            -CommandLineLogging Enabled -Escalate `
            -Reason 'exact-SHA Windows qualification' -Confirm:$false
    }
    if (-not $policy.Succeeded) { throw 'Windows process-audit policy mutation failed.' }
    $processCreationBefore = [uint32]$policy.PolicyOutcome.AuditBefore.ProcessCreation
    $processCreationRestoreState = if (($processCreationBefore -band 1) -ne 0) {
        'Enabled'
    }
    else { 'Disabled' }
    $commandLineRestoreState = [string]$policy.PolicyOutcome.CommandLineBefore
    if ($commandLineRestoreState -notin @('Enabled', 'Disabled', 'NotConfigured')) {
        throw 'The original command-line audit setting cannot be restored exactly.'
    }
    $policyChanged = $true
    Test-QualificationWindowsAuditEvent
    $null = Invoke-QualificationStep Set-HHEscalationPreference {
        Set-HHEscalationPreference -Method WindowsTokenPrivilege -Confirm:$false
    }
    $preference = Invoke-QualificationStep Get-HHEscalationPreference { Get-HHEscalationPreference }
    if ($preference.Method -cne 'WindowsTokenPrivilege') { throw 'Escalation preference did not persist.' }
    Restore-QualificationPolicy
    $null = Invoke-QualificationStep Remove-HHTarget {
        Remove-HHTarget -Name $selectedTargetName -Confirm:$false
    }
    $targetSaved = $false
    $status = 'passed'
}
catch {
    $failure = $_.Exception.Message
}
finally {
    if ($policyChanged -and -not $policyRestorationAttempted) {
        try {
            Restore-QualificationPolicy
        }
        catch {
            $status = 'failed'
            $failure = "$failure | Policy restoration failed: $($_.Exception.Message)"
        }
    }
    if ($targetSaved) {
        try { Remove-HHTarget -Name $selectedTargetName -Confirm:$false }
        catch {
            $status = 'failed'
            $failure = "$failure | Target cleanup failed: $($_.Exception.Message)"
        }
    }
    $receipt = [ordered]@{
        schema = 'HostHunter.WindowsCmdletQualification.v1'
        status = $status
        candidateSha = $CandidateSha
        controllerImageId = $ControllerImageId
        targetPlatform = 'Windows'
        targetRuntime = 'PowerShell7'
        expectedCmdlets = $expected
        rows = @($rows)
        noAutomaticRetries = $true
        policyRestoredTo = $processCreationRestoreState
        policyRestored = -not $policyChanged
        policyRestorationOutcome = $policyRestorationOutcome
        authenticationMode = 'existing-public-key'
        operatorStateCloned = $true
        cloneMissionPaused = $cloneMissionPaused
        windowsAuditEventVerified = $windowsAuditEventVerified
        failure = $failure
    }
    $directory = Split-Path -Parent $ReceiptPath
    $null = [IO.Directory]::CreateDirectory($directory)
    $json = ConvertTo-Json $receipt -Depth 12
    [IO.File]::WriteAllText($ReceiptPath, $json, [Text.UTF8Encoding]::new($false))
}

if ($status -cne 'passed') { throw "Windows qualification failed: $failure" }
