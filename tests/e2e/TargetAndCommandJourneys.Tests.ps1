[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$expectedCommands = @(
    'Enable-HHSshKeyAuthentication'
    'Get-HHAuditOutput'
    'Get-HHAuditRecord'
    'Get-HHEscalationPreference'
    'Get-HHTarget'
    'Invoke-HHCommand'
    'Remove-HHTarget'
    'Set-HHEscalationPreference'
    'Set-HHTarget'
    'Set-HHWindowsProcessAuditPolicy'
    'Test-HHTarget'
)
$orderedJourney = @(
    'Get-HHTarget'
    'Set-HHTarget'
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
$receiptPath = if ([string]::IsNullOrWhiteSpace($env:HH_CMDLET_RECEIPT)) {
    '/artifacts/cmdlets/receipt.json'
}
else { [IO.Path]::GetFullPath($env:HH_CMDLET_RECEIPT) }
$modulePath = [IO.Path]::GetFullPath($env:HH_RUNTIME_MODULE_PATH)
$dataRoot = [IO.Path]::GetFullPath($env:HH_DATA_ROOT)
$databasePath = Join-Path $dataRoot 'hosthunter.db'
$runtimeDirectory = [IO.Path]::GetFullPath($env:HH_SSH_RUNTIME_DIR)
$targetHost = $env:HH_SSH_HOST
$targetPort = [int]$env:HH_SSH_PORT
$userName = [IO.File]::ReadAllText((Join-Path $runtimeDirectory 'username')).Trim()
$fingerprint = [IO.File]::ReadAllText((Join-Path $runtimeDirectory 'hostkey.sha256')).Trim()
$rows = [Collections.Generic.List[object]]::new()
$script:commandResult = $null
$script:auditCountBeforeRemoval = 0

$env:DISPLAY = 'hosthunter-cmdlet-verifier'
$env:SSH_ASKPASS = '/opt/hosthunter-cmdlet-tests/fixture-askpass.sh'
$env:SSH_ASKPASS_REQUIRE = 'force'
$env:HH_SSH_PASSWORD_FILE = Join-Path $runtimeDirectory 'password'

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
            'ConfigurationGeneration', 'ConfigurationMutations', 'Batches',
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
            Assert-HHCondition ($delta.Invocations -eq 1 -and $delta.Outcomes -eq 1) `
                'Set-HHTarget did not persist one terminal validation invocation.'
        }
        3 {
            Assert-HHCondition ($delta.TargetGeneration -eq 0) 'Test-HHTarget changed the target generation.'
            Assert-HHCondition ($delta.Invocations -eq 1 -and $delta.Outcomes -eq 1) `
                'Test-HHTarget did not persist one terminal invocation.'
        }
        4 {
            Assert-HHCondition ($delta.Invocations -eq 1 -and $delta.Outcomes -eq 1) `
                'Invoke-HHCommand did not persist one terminal invocation.'
            Assert-HHCondition ($delta.Artifacts -eq 1) 'Invoke-HHCommand did not persist one output artifact.'
        }
        { $_ -in @(5, 6, 10) } {
            foreach ($property in $delta.PSObject.Properties) {
                Assert-HHCondition ([long]$property.Value -eq 0) `
                    "Read-only cmdlet changed database field '$($property.Name)'."
            }
        }
        7 {
            Assert-HHCondition ($delta.TargetGeneration -eq 1 -and $delta.TargetMutations -eq 1) `
                'Enable-HHSshKeyAuthentication did not commit one target mutation.'
            Assert-HHCondition ($delta.Invocations -eq 1 -and $delta.Outcomes -eq 1) `
                'Enable-HHSshKeyAuthentication did not persist one terminal invocation.'
        }
        8 {
            Assert-HHCondition ($delta.Invocations -eq 1 -and $delta.Outcomes -eq 1) `
                'Set-HHWindowsProcessAuditPolicy did not persist one terminal invocation.'
        }
        9 {
            Assert-HHCondition ($delta.ConfigurationGeneration -eq 1) `
                'Set-HHEscalationPreference generation delta was not one.'
            Assert-HHCondition ($delta.ConfigurationMutations -eq 1) `
                'Set-HHEscalationPreference mutation delta was not one.'
        }
        11 {
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
    Import-Module $modulePath -Force
    $actualCommands = @(Get-Command -Module HostHunterNextGeneration -CommandType Function |
            Sort-Object Name | ForEach-Object Name)
    Assert-HHCondition (($actualCommands -join "`n") -ceq ($expectedCommands -join "`n")) `
        "Package exports differ from the exact eleven-command contract: $($actualCommands -join ', ')."
    $unexpectedState = @(
        Get-ChildItem -LiteralPath $dataRoot -Force -ErrorAction Stop |
            Where-Object Name -cne 'keys'
    )
    Assert-HHCondition (-not [IO.File]::Exists($databasePath) -and $unexpectedState.Count -eq 0) `
        'The verifier requires a fresh data volume; the separate SSH-key mount is allowed.'

    Invoke-HHCmdletStep 1 'Get-HHTarget' 'empty read without state creation' {
        $targets = @(Get-HHTarget)
        Assert-HHCondition ($targets.Count -eq 0) 'Expected an empty target set.'
        Assert-HHCondition (-not [IO.File]::Exists($databasePath)) 'Read created the database.'
        @{ count = $targets.Count }
    }
    Invoke-HHCmdletStep 2 'Set-HHTarget' 'real SSH validation and one persisted password profile' {
        $saved = Set-HHTarget -Name alpha -HostName $targetHost -Port $targetPort `
            -UserName $userName -HostKeyFingerprint $fingerprint -Confirm:$false
        Assert-HHCondition ($saved.Name -ceq 'alpha') 'Saved target name differs.'
        Assert-HHCondition ($saved.Authentication -ceq 'Password') 'Saved target is not password-authenticated.'
        $fresh = Invoke-HHFreshJson '@(Get-HHTarget -Name alpha)'
        Assert-HHCondition (@($fresh).Count -eq 1) 'Fresh process did not reload the saved target.'
        @{ name = $saved.Name; authentication = $saved.Authentication; freshReadCount = @($fresh).Count }
    }
    Invoke-HHCmdletStep 3 'Test-HHTarget' 'real identity probe without target mutation' {
        $result = Test-HHTarget -Name alpha -Reason 'focused cmdlet verifier'
        Assert-HHCondition ([bool]$result.Succeeded) 'Target identity probe failed.'
        Assert-HHCondition ($result.RemotePSEdition -ceq 'Core') 'Remote target is not PowerShell Core.'
        @{ succeeded = $result.Succeeded; edition = $result.RemotePSEdition }
    }
    Invoke-HHCmdletStep 4 'Invoke-HHCommand' 'one command with complete stream evidence' {
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
    Invoke-HHCmdletStep 5 'Get-HHAuditRecord' 'fresh-process exact audit read without DB mutation' {
        Assert-HHCondition ($null -ne $script:commandResult) 'Command invocation is unavailable.'
        $id = [string]$script:commandResult.InvocationId
        $fresh = Invoke-HHFreshJson "@(Get-HHAuditRecord -InvocationId '$id' -First 1)"
        $record = @($fresh)[0]
        Assert-HHCondition ($record.InvocationId -ceq $id) 'Audit invocation ID differs.'
        Assert-HHCondition ($record.CaseId -ceq 'CASE-CMDLETS-001') 'Audit case ID differs.'
        @{ invocationId = $record.InvocationId; operation = $record.Operation; status = $record.Status }
    }
    Invoke-HHCmdletStep 6 'Get-HHAuditOutput' 'fresh-process ordered output read without DB mutation' {
        Assert-HHCondition ($null -ne $script:commandResult) 'Command invocation is unavailable.'
        $id = [string]$script:commandResult.InvocationId
        $fresh = Invoke-HHFreshJson "@(Get-HHAuditOutput -InvocationId '$id')"
        $events = @($fresh)
        Assert-HHCondition ($events.Count -ge 6) 'Fresh output read returned too few stream events.'
        $streams = @($events.Stream | Sort-Object -Unique)
        Assert-HHCondition ($streams -contains 'Output') 'Fresh output read omitted the Output stream.'
        @{ invocationId = $id; eventCount = $events.Count; streams = $streams }
    }
    Invoke-HHCmdletStep 7 'Enable-HHSshKeyAuthentication' 'password-to-key proof and persisted transition' {
        $result = Enable-HHSshKeyAuthentication -Name alpha `
            -Reason 'focused cmdlet verifier' -Confirm:$false
        Assert-HHCondition ($result.Authentication -ceq 'PublicKey') 'SSH key transition did not complete.'
        $fresh = Invoke-HHFreshJson '@(Get-HHTarget -Name alpha)'
        Assert-HHCondition (@($fresh)[0].Authentication -ceq 'PublicKey') `
            'Fresh process did not reload the public-key profile.'
        @{ authentication = $result.Authentication; keyPath = $result.KeyPath }
    }
    Invoke-HHCmdletStep 8 'Set-HHWindowsProcessAuditPolicy' 'finite audited Linux unsupported failure' {
        $result = Set-HHWindowsProcessAuditPolicy -State Enabled -Target alpha `
            -Escalate -Reason 'focused Linux failure proof' -Confirm:$false
        Assert-HHCondition (-not [bool]$result.Succeeded) 'Linux policy request unexpectedly succeeded.'
        Assert-HHCondition ($result.DispatchState -ceq 'Completed') 'Linux policy request was not terminal.'
        Assert-HHCondition ($result.OutcomeStatus -ceq 'Failed') 'Linux policy request was not audited failed.'
        @{ succeeded = $result.Succeeded; dispatchState = $result.DispatchState; outcome = $result.OutcomeStatus }
    }
    Invoke-HHCmdletStep 9 'Set-HHEscalationPreference' 'persist WindowsTokenPrivilege preference' {
        $saved = Set-HHEscalationPreference -Method WindowsTokenPrivilege -Confirm:$false
        Assert-HHCondition ($saved.Method -ceq 'WindowsTokenPrivilege') 'Escalation method differs.'
        Assert-HHCondition ($saved.Source -ceq 'Persisted') 'Escalation preference was not persisted.'
        @{ method = $saved.Method; source = $saved.Source }
    }
    Invoke-HHCmdletStep 10 'Get-HHEscalationPreference' 'fresh-process persisted read without DB mutation' {
        $fresh = Invoke-HHFreshJson 'Get-HHEscalationPreference'
        Assert-HHCondition ($fresh.Method -ceq 'WindowsTokenPrivilege') `
            'Fresh process did not reload the escalation method.'
        Assert-HHCondition ($fresh.Source -ceq 'Persisted') `
            'Fresh process did not report a persisted preference.'
        @{ method = $fresh.Method; source = $fresh.Source }
    }
    Invoke-HHCmdletStep 11 'Remove-HHTarget' 'remove profile while retaining audit history' {
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
    $setupError = $_.Exception.Message
    while ($rows.Count -lt 11) {
        $index = $rows.Count + 1
        $rows.Add([pscustomobject][ordered]@{
                index = $index
                cmdlet = $orderedJourney[$index - 1]
                expected = 'journey setup must succeed'
                status = 'failed'
                durationMs = 0
                observation = $null
                error = $setupError
                databaseBefore = $null
                databaseAfter = $null
                databaseDelta = $null
            })
    }
}
finally {
    $failed = @($rows | Where-Object status -ne 'passed')
    $finalSnapshot = try { Get-HHDatabaseSnapshot } catch { $null }
    $receipt = [pscustomobject][ordered]@{
        schema = 'HostHunter.CmdletVerifierReceipt.v1'
        status = if ($failed.Count -eq 0 -and $rows.Count -eq 11) { 'passed' } else { 'failed' }
        sourceSha = $env:HH_SOURCE_SHA
        verifierImageId = $env:HH_VERIFIER_IMAGE_ID
        moduleManifestSha256 = (Get-FileHash -LiteralPath $modulePath -Algorithm SHA256).Hash.ToLowerInvariant()
        expectedCommands = $expectedCommands
        observedCommands = if (Get-Module HostHunterNextGeneration) {
            @(Get-Command -Module HostHunterNextGeneration -CommandType Function |
                Sort-Object Name | ForEach-Object Name)
        }
        else { @() }
        rowCount = $rows.Count
        failedCount = $failed.Count
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
