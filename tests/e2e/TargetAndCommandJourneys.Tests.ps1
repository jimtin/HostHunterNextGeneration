[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$orderedJourney = @(
    'Get-HHTarget'
    'Set-HHTarget'
    'Get-TargetHostDetails'
    'Get-TargetProcessStartEvents'
    'Get-TargetProcessEndEvents'
    'Get-TargetAuthenticationEvents'
    'Get-TargetProcessAccessToken'
    'Get-TargetUserEffectiveRights'
    'Test-HHTarget'
    'Invoke-HHCommand'
    'Get-HHAuditRecord'
    'Get-HHAuditOutput'
    'Enable-HHSshKeyAuthentication'
    'Set-HHWindowsProcessAuditPolicy'
    'Set-HHEscalationPreference'
    'Get-HHEscalationPreference'
    'Remove-HHTarget'
)
$supportPath = Join-Path $PSScriptRoot 'HHCmdletVerifierSupport.ps1'
. $supportPath
$receiptPath = if ([string]::IsNullOrWhiteSpace($env:HH_CMDLET_RECEIPT)) {
    '/artifacts/cmdlets/receipt.json'
}
else { [IO.Path]::GetFullPath($env:HH_CMDLET_RECEIPT) }
$rows = [Collections.Generic.List[object]]::new()
$modulePath = $null
$expectedCommands = @()
$databasePath = $null
$targetHost = $null
$targetPort = 0
$userName = $null
$fingerprint = $null
$migrationCount = 0
$failurePhase = 'preflight'
$terminalError = $null
$script:commandResult = $null
$script:auditCountBeforeRemoval = 0

$env:DISPLAY = 'hosthunter-cmdlet-verifier'
$env:SSH_ASKPASS = if ([string]::IsNullOrWhiteSpace($env:HH_CMDLET_ASKPASS)) {
    '/opt/hosthunter-cmdlet-tests/fixture-askpass.sh'
}
else { $env:HH_CMDLET_ASKPASS }
$env:SSH_ASKPASS_REQUIRE = 'force'

function Assert-HHCondition {
    param(
        [Parameter(Mandatory)][bool]$Condition,
        [Parameter(Mandatory)][string]$Message
    )
    if (-not $Condition) { throw $Message }
}

function Invoke-HHFreshJson {
    param([Parameter(Mandatory)][string]$Expression)

    $body = @"
`$ErrorActionPreference = 'Stop'
Import-Module `$env:HH_RUNTIME_MODULE_PATH -Force
`$value = & { $Expression }
`$json = ConvertTo-Json -InputObject @(`$value) -Depth 12 -Compress
Write-Output ('HHJSON:' + `$json)
"@
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($body))
    $output = @(& pwsh -NoLogo -NoProfile -NonInteractive -OutputFormat Text `
            -EncodedCommand $encoded 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "Fresh PowerShell process failed: $($output | Out-String)"
    }
    $jsonLine = @($output | ForEach-Object { [string]$_ } |
            Where-Object { $_.StartsWith('HHJSON:', [StringComparison]::Ordinal) })[-1]
    if ([string]::IsNullOrWhiteSpace($jsonLine)) {
        throw "Fresh PowerShell process emitted no JSON marker: $($output | Out-String)"
    }
    return ($jsonLine.Substring(7) | ConvertFrom-Json)
}

function Get-HHDatabaseSnapshot {
    if (-not [IO.File]::Exists($databasePath)) {
        return [pscustomobject][ordered]@{
            Exists = $false
            Integrity = 'absent'
            SchemaVersion = 0
            Profiles = 0
            TargetGeneration = 0
            TargetMutations = 0
            ConfigurationGeneration = 0
            ConfigurationMutations = 0
            VisualizerGeneration = 0
            Missions = 0
            Observations = 0
            Batches = 0
            Invocations = 0
            RemoteEvents = 0
            Outcomes = 0
            Artifacts = 0
            AuditEvents = 0
        }
    }

    $builder = [Microsoft.Data.Sqlite.SqliteConnectionStringBuilder]::new()
    $builder.DataSource = $databasePath
    $builder.Mode = [Microsoft.Data.Sqlite.SqliteOpenMode]::ReadOnly
    $builder.Cache = [Microsoft.Data.Sqlite.SqliteCacheMode]::Private
    $connection = [Microsoft.Data.Sqlite.SqliteConnection]::new($builder.ConnectionString)
    $connection.Open()
    try {
        function Read-Scalar([string]$Sql) {
            $command = $connection.CreateCommand()
            try {
                $command.CommandText = $Sql
                return $command.ExecuteScalar()
            }
            finally { $command.Dispose() }
        }
        $queryOnlyCommand = $connection.CreateCommand()
        try {
            $queryOnlyCommand.CommandText = 'PRAGMA query_only=ON;'
            $null = $queryOnlyCommand.ExecuteNonQuery()
        }
        finally { $queryOnlyCommand.Dispose() }
        $queryOnly = [int](Read-Scalar 'PRAGMA query_only;')
        Assert-HHCondition ($queryOnly -eq 1) 'SQLite snapshot connection was not read-only.'
        [pscustomobject][ordered]@{
            Exists = $true
            Integrity = [string](Read-Scalar 'PRAGMA integrity_check;')
            SchemaVersion = [int](Read-Scalar 'SELECT COUNT(*) FROM schema_migrations;')
            Profiles = [int](Read-Scalar 'SELECT COUNT(*) FROM target_profiles;')
            TargetGeneration = [int](Read-Scalar 'SELECT generation FROM target_store_state WHERE singleton_id=1;')
            TargetMutations = [int](Read-Scalar 'SELECT COUNT(*) FROM target_mutations;')
            ConfigurationGeneration = [int](Read-Scalar 'SELECT generation FROM configuration_store_state WHERE singleton_id=1;')
            ConfigurationMutations = [int](Read-Scalar 'SELECT COUNT(*) FROM configuration_mutations;')
            VisualizerGeneration = [int](Read-Scalar 'SELECT generation FROM visualizer_store_state WHERE singleton_id=1;')
            Missions = [int](Read-Scalar 'SELECT COUNT(*) FROM visualizer_missions;')
            Observations = [int](Read-Scalar 'SELECT COUNT(*) FROM visualizer_host_observations;')
            Batches = [int](Read-Scalar 'SELECT COUNT(*) FROM operation_batches;')
            Invocations = [int](Read-Scalar 'SELECT COUNT(*) FROM invocations;')
            RemoteEvents = [int](Read-Scalar 'SELECT COUNT(*) FROM remote_operation_events;')
            Outcomes = [int](Read-Scalar 'SELECT COUNT(*) FROM invocation_outcomes;')
            Artifacts = [int](Read-Scalar 'SELECT COUNT(*) FROM output_artifacts;')
            AuditEvents = [int](Read-Scalar 'SELECT COUNT(*) FROM audit_events;')
        }
    }
    finally {
        $connection.Close()
        $connection.Dispose()
    }
}

function Get-HHDatabaseDelta {
    param([Parameter(Mandatory)]$Before, [Parameter(Mandatory)]$After)

    $delta = [ordered]@{}
    foreach ($name in @(
            'SchemaVersion', 'Profiles', 'TargetGeneration', 'TargetMutations',
            'ConfigurationGeneration', 'ConfigurationMutations', 'VisualizerGeneration',
            'Missions', 'Observations', 'Batches',
            'Invocations', 'RemoteEvents', 'Outcomes', 'Artifacts', 'AuditEvents'
        )) {
        $delta[$name] = [long]$After.$name - [long]$Before.$name
    }
    [pscustomobject]$delta
}

function Assert-HHStepDatabaseContract {
    param(
        [Parameter(Mandatory)][int]$Index,
        [Parameter(Mandatory)]$Before,
        [Parameter(Mandatory)]$After
    )

    $delta = Get-HHDatabaseDelta -Before $Before -After $After
    switch ($Index) {
        1 {
            Assert-HHCondition (-not $After.Exists) 'Get-HHTarget created persistence state.'
        }
        2 {
            Assert-HHCondition ($delta.Profiles -eq 1) 'Set-HHTarget did not add exactly one profile.'
            Assert-HHCondition ($delta.TargetGeneration -eq 1) 'Set-HHTarget generation delta was not one.'
            Assert-HHCondition ($delta.TargetMutations -eq 1) 'Set-HHTarget mutation delta was not one.'
            Assert-HHCondition ($delta.Invocations -eq 2 -and $delta.Outcomes -eq 2) `
                'Set-HHTarget did not persist validation plus initial host-details invocations.'
            Assert-HHCondition ($delta.Observations -eq 0) 'Paused visualization unexpectedly queued initial host details.'
        }
        3 {
            Assert-HHCondition ($delta.Invocations -eq 1 -and $delta.Outcomes -eq 1) `
                'Get-TargetHostDetails did not persist one terminal invocation.'
            Assert-HHCondition ($delta.Observations -eq 0) 'Paused visualization unexpectedly queued one observation.'
        }
        { $_ -in @(4, 5, 6, 7, 8) } {
            foreach ($property in $delta.PSObject.Properties) {
                Assert-HHCondition ([long]$property.Value -eq 0) `
                    "Mission-precondition cmdlet changed database field '$($property.Name)'."
            }
        }
        9 {
            Assert-HHCondition ($delta.TargetGeneration -eq 0) 'Test-HHTarget changed the target generation.'
            Assert-HHCondition ($delta.Invocations -eq 1 -and $delta.Outcomes -eq 1) `
                'Test-HHTarget did not persist one terminal invocation.'
        }
        10 {
            Assert-HHCondition ($delta.Invocations -eq 1 -and $delta.Outcomes -eq 1) `
                'Invoke-HHCommand did not persist one terminal invocation.'
            Assert-HHCondition ($delta.Artifacts -eq 1) 'Invoke-HHCommand did not persist one output artifact.'
        }
        { $_ -in @(11, 12, 16) } {
            foreach ($property in $delta.PSObject.Properties) {
                Assert-HHCondition ([long]$property.Value -eq 0) `
                    "Read-only cmdlet changed database field '$($property.Name)'."
            }
        }
        13 {
            Assert-HHCondition ($delta.TargetGeneration -eq 1 -and $delta.TargetMutations -eq 1) `
                'Enable-HHSshKeyAuthentication did not commit one target mutation.'
            Assert-HHCondition ($delta.Invocations -eq 1 -and $delta.Outcomes -eq 1) `
                'Enable-HHSshKeyAuthentication did not persist one terminal invocation.'
        }
        14 {
            Assert-HHCondition ($delta.Invocations -eq 1 -and $delta.Outcomes -eq 1) `
                'Set-HHWindowsProcessAuditPolicy did not persist one terminal invocation.'
        }
        15 {
            Assert-HHCondition ($delta.ConfigurationGeneration -eq 1) `
                'Set-HHEscalationPreference generation delta was not one.'
            Assert-HHCondition ($delta.ConfigurationMutations -eq 1) `
                'Set-HHEscalationPreference mutation delta was not one.'
        }
        17 {
            Assert-HHCondition ($delta.Profiles -eq -1) 'Remove-HHTarget did not remove exactly one profile.'
            Assert-HHCondition ($delta.TargetGeneration -eq 1 -and $delta.TargetMutations -eq 1) `
                'Remove-HHTarget did not commit one target mutation.'
        }
    }
}

function Invoke-HHCmdletStep {
    param(
        [Parameter(Mandatory)][int]$Index,
        [Parameter(Mandatory)][string]$Cmdlet,
        [Parameter(Mandatory)][string]$Expected,
        [Parameter(Mandatory)][scriptblock]$Action
    )

    $before = Get-HHDatabaseSnapshot
    $stopwatch = [Diagnostics.Stopwatch]::StartNew()
    $status = 'passed'
    $observation = $null
    $errorText = $null
    try { $observation = & $Action }
    catch {
        $status = 'failed'
        $errorText = $_.Exception.Message
    }
    finally { $stopwatch.Stop() }
    try {
        $after = Get-HHDatabaseSnapshot
        if ($after.Exists -and $after.Integrity -cne 'ok') {
            throw "SQLite integrity_check returned '$($after.Integrity)'."
        }
        Assert-HHStepDatabaseContract -Index $Index -Before $before -After $after
    }
    catch {
        $after = $before
        $status = 'failed'
        $snapshotError = $_.Exception.Message
        $errorText = if ($null -eq $errorText) { $snapshotError } else { "$errorText | $snapshotError" }
    }
    $rows.Add([pscustomobject][ordered]@{
            index = $Index
            cmdlet = $Cmdlet
            expected = $Expected
            status = $status
            durationMs = $stopwatch.ElapsedMilliseconds
            observation = $observation
            error = $errorText
            databaseBefore = $before
            databaseAfter = $after
            databaseDelta = Get-HHDatabaseDelta -Before $before -After $after
        })
}

try {
    $preflight = Invoke-HHCmdletVerifierPreflight `
        -ModulePath $env:HH_RUNTIME_MODULE_PATH `
        -OrderedJourney $orderedJourney `
        -DataRoot $env:HH_DATA_ROOT `
        -RuntimeDirectory $env:HH_SSH_RUNTIME_DIR `
        -ReceiptPath $receiptPath
    $modulePath = $preflight.ModulePath
    $expectedCommands = @($preflight.ExpectedCommands)
    $databasePath = $preflight.DatabasePath
    $targetHost = $env:HH_SSH_HOST
    $targetPort = [int]$env:HH_SSH_PORT
    $userName = $preflight.UserName
    $fingerprint = $preflight.Fingerprint
    $migrationCount = $preflight.MigrationCount
    $env:HH_SSH_PASSWORD_FILE = $preflight.PasswordPath
    $failurePhase = 'journey'

    Invoke-HHCmdletStep 1 'Get-HHTarget' 'empty read without state creation' {
        $information = @()
        $targets = @(Get-HHTargets -InformationVariable information)
        Assert-HHCondition ($targets.Count -eq 0) 'Expected an empty target set.'
        Assert-HHCondition ([string]$information[-1] -ceq 'No currently set') `
            'The empty target message differs.'
        Assert-HHCondition (-not [IO.File]::Exists($databasePath)) 'Read created the database.'
        @{ count = $targets.Count }
    }
    Invoke-HHCmdletStep 2 'Set-HHTarget' 'real SSH validation, paused host details, and one prompt-only fixture profile' {
        $proposal = [pscustomobject]@{
            Name = 'alpha'
            Transport = 'SSH'
            HostName = $targetHost
            Port = $targetPort
            UserName = $userName
            Authentication = 'Password'
            CredentialStorage = 'Prompt'
            PowerShellRuntime = 'PowerShell7'
            HostKeyFingerprint = $fingerprint
        }
        $saved = Set-HHTarget -InputObject @($proposal) -Confirm:$false
        Assert-HHCondition ($saved.Name -ceq 'alpha') 'Saved target name differs.'
        Assert-HHCondition ($saved.Authentication -ceq 'Password') 'Saved target is not password-authenticated.'
        Assert-HHCondition ($saved.CredentialStorage -ceq 'Prompt') `
            'The container fixture must not persist its generated password.'
        $fresh = Invoke-HHFreshJson '@(Get-HHTarget -Name alpha)'
        Assert-HHCondition (@($fresh).Count -eq 1) 'Fresh process did not reload the saved target.'
        @{ name = $saved.Name; authentication = $saved.Authentication; freshReadCount = @($fresh).Count }
    }
    Invoke-HHCmdletStep 3 'Get-TargetHostDetails' 'fresh paused host details through the managed-host engine' {
        $details=@(Get-TargetHostDetails -Name alpha -Reason 'focused cmdlet verifier')
        Assert-HHCondition ($details.Count -eq 1) 'Expected one host-details observation.'
        Assert-HHCondition (-not [string]::IsNullOrWhiteSpace([string]$details[0].Hostname)) 'Hostname is absent.'
        Assert-HHCondition ($details[0].VisualizerPublishingState -ceq 'Paused') 'Visualizer publishing was not paused.'
        @{hostname=$details[0].Hostname;visualizerState=$details[0].VisualizerPublishingState}
    }
    Invoke-HHCmdletStep 4 'Get-TargetProcessStartEvents' 'clear pre-contact mission requirement' {
        try {
            $null=Get-TargetProcessStartEvents -Name alpha
            throw 'The command unexpectedly collected without a mission.'
        }
        catch {
            Assert-HHCondition ($_.Exception.Message -match 'Start a HostHunter mission') `
                'The mission precondition was unclear.'
            @{precondition='mission-required'}
        }
    }
    Invoke-HHCmdletStep 5 'Get-TargetProcessEndEvents' 'clear pre-contact mission requirement' {
        try {
            $null=Get-TargetProcessEndEvents -Name alpha
            throw 'The command unexpectedly collected without a mission.'
        }
        catch {
            Assert-HHCondition ($_.Exception.Message -match 'Start a HostHunter mission') `
                'The mission precondition was unclear.'
            @{precondition='mission-required'}
        }
    }
    Invoke-HHCmdletStep 6 'Get-TargetAuthenticationEvents' 'clear pre-contact mission requirement' {
        try {
            $null=Get-TargetAuthenticationEvents -Name alpha
            throw 'The command unexpectedly collected without a mission.'
        }
        catch {
            Assert-HHCondition ($_.Exception.Message -match 'Start a HostHunter mission') `
                'The mission precondition was unclear.'
            @{precondition='mission-required'}
        }
    }
    Invoke-HHCmdletStep 7 'Get-TargetProcessAccessToken' 'clear pre-contact mission requirement' {
        try {
            $null=Get-TargetProcessAccessToken -Name alpha -ProcessName pwsh.exe
            throw 'The command unexpectedly collected without a mission.'
        }
        catch {
            Assert-HHCondition ($_.Exception.Message -match 'Start a HostHunter mission') `
                'The mission precondition was unclear.'
            @{precondition='mission-required'}
        }
    }
    Invoke-HHCmdletStep 8 'Get-TargetUserEffectiveRights' 'clear pre-contact mission requirement' {
        try {
            $null=Get-TargetUserEffectiveRights -Name alpha
            throw 'The command unexpectedly collected without a mission.'
        }
        catch {
            Assert-HHCondition ($_.Exception.Message -match 'Start a HostHunter mission') `
                'The mission precondition was unclear.'
            @{precondition='mission-required'}
        }
    }
    Invoke-HHCmdletStep 9 'Test-HHTarget' 'real identity probe without target mutation' {
        $result = Test-HHTarget -Name alpha -Reason 'focused cmdlet verifier'
        Assert-HHCondition ([bool]$result.Succeeded) 'Target identity probe failed.'
        Assert-HHCondition ($result.RemotePSEdition -ceq 'Core') 'Remote target is not PowerShell Core.'
        @{ succeeded = $result.Succeeded; edition = $result.RemotePSEdition }
    }
    Invoke-HHCmdletStep 10 'Invoke-HHCommand' 'one command with complete stream evidence' {
        $command = @'
Write-Output 'output-value'
Write-Warning 'warning-value'
Write-Verbose 'verbose-value' -Verbose
Write-Debug 'debug-value' -Debug
Write-Information 'information-value' -InformationAction Continue
Write-Error 'nonterminating-error' -ErrorAction Continue
'@
        $script:commandResult = Invoke-HHCommand -Command $command -Target alpha `
            -Reason 'focused cmdlet verifier' -CaseId 'CASE-CMDLETS-001'
        Assert-HHCondition ([bool]$script:commandResult.Succeeded) 'Remote command failed.'
        $streams = @($script:commandResult.StreamEvents.Stream | Sort-Object -Unique)
        $expectedStreams = @('Debug', 'Error', 'Information', 'Output', 'Verbose', 'Warning')
        Assert-HHCondition (($streams -join ',') -ceq ($expectedStreams -join ',')) `
            "Unexpected stream set: $($streams -join ',')."
        @{ invocationId = $script:commandResult.InvocationId; streams = $streams }
    }
    Invoke-HHCmdletStep 11 'Get-HHAuditRecord' 'fresh-process exact audit read without DB mutation' {
        Assert-HHCondition ($null -ne $script:commandResult) 'Command invocation is unavailable.'
        $id = [string]$script:commandResult.InvocationId
        $fresh = Invoke-HHFreshJson "@(Get-HHAuditRecord -InvocationId '$id' -First 1)"
        $record = @($fresh)[0]
        Assert-HHCondition ($record.InvocationId -ceq $id) 'Audit invocation ID differs.'
        Assert-HHCondition ($record.CaseId -ceq 'CASE-CMDLETS-001') 'Audit case ID differs.'
        @{ invocationId = $record.InvocationId; operation = $record.Operation; status = $record.Status }
    }
    Invoke-HHCmdletStep 12 'Get-HHAuditOutput' 'fresh-process ordered output read without DB mutation' {
        Assert-HHCondition ($null -ne $script:commandResult) 'Command invocation is unavailable.'
        $id = [string]$script:commandResult.InvocationId
        $fresh = Invoke-HHFreshJson "@(Get-HHAuditOutput -InvocationId '$id')"
        $events = @($fresh)
        Assert-HHCondition ($events.Count -ge 6) 'Fresh output read returned too few stream events.'
        $streams = @($events.Stream | Sort-Object -Unique)
        Assert-HHCondition ($streams -contains 'Output') 'Fresh output read omitted the Output stream.'
        @{ invocationId = $id; eventCount = $events.Count; streams = $streams }
    }
    Invoke-HHCmdletStep 13 'Enable-HHSshKeyAuthentication' 'password-to-key proof and persisted transition' {
        $result = Enable-HHSshKeyAuthentication -Name alpha `
            -Reason 'focused cmdlet verifier' -Confirm:$false
        Assert-HHCondition ($result.Authentication -ceq 'PublicKey') 'SSH key transition did not complete.'
        $fresh = Invoke-HHFreshJson '@(Get-HHTarget -Name alpha)'
        Assert-HHCondition (@($fresh)[0].Authentication -ceq 'PublicKey') `
            'Fresh process did not reload the public-key profile.'
        @{ authentication = $result.Authentication; keyPath = $result.KeyPath }
    }
    Invoke-HHCmdletStep 14 'Set-HHWindowsProcessAuditPolicy' 'finite audited Linux unsupported failure' {
        $result = Set-HHWindowsProcessAuditPolicy -State Enabled -Target alpha `
            -Escalate -Reason 'focused Linux failure proof' -Confirm:$false
        Assert-HHCondition (-not [bool]$result.Succeeded) 'Linux policy request unexpectedly succeeded.'
        Assert-HHCondition ($result.DispatchState -ceq 'Completed') 'Linux policy request was not terminal.'
        Assert-HHCondition ($result.OutcomeStatus -ceq 'Failed') 'Linux policy request was not audited failed.'
        @{ succeeded = $result.Succeeded; dispatchState = $result.DispatchState; outcome = $result.OutcomeStatus }
    }
    Invoke-HHCmdletStep 15 'Set-HHEscalationPreference' 'persist WindowsTokenPrivilege preference' {
        $saved = Set-HHEscalationPreference -Method WindowsTokenPrivilege -Confirm:$false
        Assert-HHCondition ($saved.Method -ceq 'WindowsTokenPrivilege') 'Escalation method differs.'
        Assert-HHCondition ($saved.Source -ceq 'Persisted') 'Escalation preference was not persisted.'
        @{ method = $saved.Method; source = $saved.Source }
    }
    Invoke-HHCmdletStep 16 'Get-HHEscalationPreference' 'fresh-process persisted read without DB mutation' {
        $fresh = Invoke-HHFreshJson 'Get-HHEscalationPreference'
        Assert-HHCondition ($fresh.Method -ceq 'WindowsTokenPrivilege') `
            'Fresh process did not reload the escalation method.'
        Assert-HHCondition ($fresh.Source -ceq 'Persisted') `
            'Fresh process did not report a persisted preference.'
        @{ method = $fresh.Method; source = $fresh.Source }
    }
    Invoke-HHCmdletStep 17 'Remove-HHTarget' 'remove profile while retaining audit history' {
        $script:auditCountBeforeRemoval = @(Get-HHAuditRecord -TargetName alpha -First 100).Count
        $null = Remove-HHTarget -Name alpha -Confirm:$false
        $fresh = Invoke-HHFreshJson '@(Get-HHTarget)'
        Assert-HHCondition (@($fresh).Count -eq 0) 'Fresh process still sees a target after removal.'
        $auditAfter = @(Get-HHAuditRecord -TargetName alpha -First 100).Count
        Assert-HHCondition ($script:auditCountBeforeRemoval -gt 0) 'No audit history existed before removal.'
        Assert-HHCondition ($auditAfter -eq $script:auditCountBeforeRemoval) `
            'Target removal changed retained audit history.'
        @{ remainingTargets = @($fresh).Count; retainedAuditRecords = $auditAfter }
    }
}
catch {
    $terminalError = $_.Exception.Message
    while ($rows.Count -lt $orderedJourney.Count) {
        $index = $rows.Count + 1
        $rows.Add([pscustomobject][ordered]@{
                index = $index
                cmdlet = $orderedJourney[$index - 1]
                expected = if ($failurePhase -ceq 'preflight') {
                    'verifier preflight must succeed before any cmdlet runs'
                }
                else { 'journey must reach this ordered cmdlet' }
                status = 'not-run'
                durationMs = 0
                observation = $null
                error = $terminalError
                databaseBefore = $null
                databaseAfter = $null
                databaseDelta = $null
            })
    }
}
finally {
    if ($expectedCommands.Count -eq 0 -and
        -not [string]::IsNullOrWhiteSpace($env:HH_RUNTIME_MODULE_PATH)) {
        $expectedCommands = @(try {
                Get-HHCmdletVerifierManifestCommand -ModulePath $env:HH_RUNTIME_MODULE_PATH
            }
            catch { @() })
    }
    $failed = @($rows | Where-Object status -eq 'failed')
    $finalSnapshot = if (-not [string]::IsNullOrWhiteSpace([string]$databasePath)) {
        try { Get-HHDatabaseSnapshot } catch { $null }
    }
    else { $null }
    $databaseValid = $null -ne $finalSnapshot -and $finalSnapshot.Exists -and
        $finalSnapshot.Integrity -ceq 'ok' -and
        $migrationCount -gt 0 -and $finalSnapshot.SchemaVersion -eq $migrationCount
    $passed = $null -eq $terminalError -and $failed.Count -eq 0 -and
        $rows.Count -eq $expectedCommands.Count -and $databaseValid
    $terminalPhase = if ($passed) { 'none' } else { $failurePhase }
    $receipt = [pscustomobject][ordered]@{
        schema = 'HostHunter.CmdletVerifierReceipt.v1'
        status = if ($passed) { 'passed' } else { 'failed' }
        failurePhase = $terminalPhase
        infrastructureFailure = if ($terminalPhase -ceq 'preflight') { $terminalError } else { $null }
        journeyFailure = if ($terminalPhase -ceq 'journey') { $terminalError } else { $null }
        sourceSha = $env:HH_SOURCE_SHA
        sourceFingerprint = $env:HH_SOURCE_FINGERPRINT
        runId = $env:HH_CMDLET_RUN_ID
        dirtyTree = $env:HH_DIRTY_TREE -ceq 'true'
        verifierImageId = $env:HH_VERIFIER_IMAGE_ID
        moduleManifestSha256 = if (-not [string]::IsNullOrWhiteSpace([string]$modulePath) -and
            [IO.File]::Exists($modulePath)) {
            (Get-FileHash -LiteralPath $modulePath -Algorithm SHA256).Hash.ToLowerInvariant()
        }
        else { $null }
        expectedCommands = $expectedCommands
        observedCommands = if (Get-Module HostHunterNextGeneration) {
            @(Get-Command -Module HostHunterNextGeneration -CommandType Function |
                Sort-Object Name | ForEach-Object Name)
        }
        else { @() }
        rowCount = $rows.Count
        failedCount = $failed.Count
        migrationCount = $migrationCount
        database = $finalSnapshot
        rows = $rows.ToArray()
        completedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
    }
    [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($receiptPath)) | Out-Null
    [IO.File]::WriteAllText(
        $receiptPath,
        ($receipt | ConvertTo-Json -Depth 20),
        [Text.UTF8Encoding]::new($false)
    )
    Write-Output ($receipt | ConvertTo-Json -Depth 6 -Compress)
    if ($receipt.status -ne 'passed') { exit 1 }
}
