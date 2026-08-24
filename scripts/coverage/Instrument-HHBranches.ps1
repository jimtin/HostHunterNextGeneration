[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Path,

    [Parameter(Mandatory)]
    [string]$OutputPath,

    [Parameter(Mandatory)]
    [string]$ManifestPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$resolvedPath = (Resolve-Path -LiteralPath $Path).Path
$source = [System.IO.File]::ReadAllText($resolvedPath)
$sourceIdentity = (Get-FileHash -LiteralPath $resolvedPath -Algorithm SHA256).Hash.Substring(0, 12).ToLowerInvariant()
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseInput(
    $source,
    $resolvedPath,
    [ref]$tokens,
    [ref]$parseErrors
)

if ($parseErrors.Count -gt 0) {
    throw "Cannot instrument a file with parse errors: $($parseErrors[0].Message)"
}

$edits = [System.Collections.Generic.List[object]]::new()
$branches = [System.Collections.Generic.List[object]]::new()
$usedRanges = [System.Collections.Generic.List[object]]::new()

function Get-HHIdentifier {
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.Language.Ast]$Node,

        [Parameter(Mandatory)]
        [string]$Kind,

        [int]$Index = 0
    )

    return '{0}-{1}-L{2}C{3}-{4}' -f $sourceIdentity, $Kind,
        $Node.Extent.StartLineNumber, $Node.Extent.StartColumnNumber, $Index
}

function Get-HHContainingFunctionName {
    param([Parameter(Mandatory)][System.Management.Automation.Language.Ast]$Node)

    $parent = $Node.Parent
    while ($null -ne $parent) {
        if ($parent -is [System.Management.Automation.Language.FunctionDefinitionAst] -or
            $parent -is [System.Management.Automation.Language.FunctionMemberAst]) {
            return [string]$parent.Name
        }
        $parent = $parent.Parent
    }
    return '<script>'
}

function Get-HHBranchManifestEntry {
    param(
        [Parameter(Mandatory)][System.Management.Automation.Language.Ast]$Node,
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Kind,
        [Parameter(Mandatory)][string]$Strategy,
        [Parameter(Mandatory)][object[]]$Outcomes,
        [hashtable]$StrategyData = @{}
    )

    $entry = [ordered]@{
        id = $Id
        kind = $Kind
        strategy = $Strategy
        source = $resolvedPath
        function = Get-HHContainingFunctionName -Node $Node
        line = $Node.Extent.StartLineNumber
        column = $Node.Extent.StartColumnNumber
        outcomes = $Outcomes
    }
    foreach ($name in $StrategyData.Keys) {
        $entry[$name] = $StrategyData[$name]
    }
    return [pscustomobject]$entry
}

function Register-HHEdit {
    param(
        [Parameter(Mandatory)]
        [int]$Start,

        [Parameter(Mandatory)]
        [int]$Length,

        [Parameter(Mandatory)]
        [string]$Text,

        [Parameter(Mandatory)]
        [string]$Purpose
    )

    if ($Start -lt 0 -or $Length -lt 0 -or ($Start + $Length) -gt $source.Length) {
        throw "Invalid instrumentation edit for $Purpose."
    }

    if ($Length -gt 0) {
        foreach ($range in $usedRanges) {
            $end = $Start + $Length
            $rangeEnd = $range.Start + $range.Length
            if ($Start -lt $rangeEnd -and $range.Start -lt $end) {
                throw "Overlapping branch expressions are not supported: $Purpose overlaps $($range.Purpose)."
            }
        }
        $usedRanges.Add([pscustomobject]@{
                Start = $Start
                Length = $Length
                Purpose = $Purpose
            })
    }

    $edits.Add([pscustomobject]@{
            Start = $Start
            Length = $Length
            Text = $Text
            Purpose = $Purpose
        })
}

function Register-HHBlockProbe {
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.Language.StatementBlockAst]$Block,

        [Parameter(Mandatory)]
        [string]$OutcomeId
    )

    Register-HHEdit -Start ($Block.Extent.StartOffset + 1) -Length 0 `
        -Text "`nInvoke-HHBranchProbe -Id '$OutcomeId'`n" `
        -Purpose "block outcome $OutcomeId"
}

function Register-HHDirectBranch {
    param(
        [Parameter(Mandatory)]
        [string]$Id,

        [Parameter(Mandatory)]
        [string]$Kind,

        [Parameter(Mandatory)]
        [object[]]$Outcomes,

        [Parameter(Mandatory)]
        [System.Management.Automation.Language.Ast]$Node
    )

    $branches.Add((Get-HHBranchManifestEntry -Node $Node -Id $Id -Kind $Kind `
            -Strategy direct -Outcomes $Outcomes))
}

foreach ($ifAst in $ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.IfStatementAst]
        }, $true)) {
    $branchId = Get-HHIdentifier -Node $ifAst -Kind 'if'
    $outcomes = [System.Collections.Generic.List[object]]::new()
    $index = 0
    foreach ($clause in $ifAst.Clauses) {
        $outcomeId = "$branchId-clause-$index"
        Register-HHBlockProbe -Block $clause.Item2 -OutcomeId $outcomeId
        $outcomes.Add([pscustomobject]@{ id = $outcomeId; label = "clause-$index" })
        $index++
    }
    $elseId = "$branchId-else"
    if ($null -eq $ifAst.ElseClause) {
        Register-HHEdit -Start $ifAst.Extent.EndOffset -Length 0 `
            -Text " else { Invoke-HHBranchProbe -Id '$elseId' }" `
            -Purpose "implicit else outcome $elseId"
        $outcomes.Add([pscustomobject]@{ id = $elseId; label = 'implicit-else' })
    }
    else {
        Register-HHBlockProbe -Block $ifAst.ElseClause -OutcomeId $elseId
        $outcomes.Add([pscustomobject]@{ id = $elseId; label = 'else' })
    }
    Register-HHDirectBranch -Id $branchId -Kind 'if' -Outcomes $outcomes.ToArray() -Node $ifAst
}

foreach ($switchAst in $ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.SwitchStatementAst]
        }, $true)) {
    $branchId = Get-HHIdentifier -Node $switchAst -Kind 'switch'
    $outcomes = [System.Collections.Generic.List[object]]::new()
    $index = 0
    foreach ($clause in $switchAst.Clauses) {
        $outcomeId = "$branchId-clause-$index"
        Register-HHBlockProbe -Block $clause.Item2 -OutcomeId $outcomeId
        $outcomes.Add([pscustomobject]@{ id = $outcomeId; label = "clause-$index" })
        $index++
    }
    $defaultId = "$branchId-default"
    if ($null -eq $switchAst.Default) {
        Register-HHEdit -Start ($switchAst.Extent.EndOffset - 1) -Length 0 `
            -Text "`ndefault { Invoke-HHBranchProbe -Id '$defaultId' }`n" `
            -Purpose "implicit switch default $defaultId"
        $outcomes.Add([pscustomobject]@{ id = $defaultId; label = 'implicit-default' })
    }
    else {
        Register-HHBlockProbe -Block $switchAst.Default -OutcomeId $defaultId
        $outcomes.Add([pscustomobject]@{ id = $defaultId; label = 'default' })
    }
    Register-HHDirectBranch -Id $branchId -Kind 'switch' -Outcomes $outcomes.ToArray() -Node $switchAst
}

$preTestLoopTypes = @(
    [System.Management.Automation.Language.WhileStatementAst],
    [System.Management.Automation.Language.ForStatementAst],
    [System.Management.Automation.Language.ForEachStatementAst]
)

foreach ($loopType in $preTestLoopTypes) {
    foreach ($loopAst in $ast.FindAll({
                param($node)
                $node.GetType() -eq $loopType
            }, $true)) {
        $kind = $loopAst.GetType().Name.Replace('StatementAst', '').ToLowerInvariant()
        $branchId = Get-HHIdentifier -Node $loopAst -Kind $kind
        $evaluationId = "$branchId-evaluated"
        $bodyId = "$branchId-body"
        $correlationVariable = '__hhBranchCorrelation_{0}' -f `
            ($branchId -replace '[^A-Za-z0-9_]', '_')
        Register-HHEdit -Start $loopAst.Extent.StartOffset -Length 0 `
            -Text ('$' + $correlationVariable + " = New-HHBranchCorrelationId; " +
                "Invoke-HHBranchProbe -Id '$evaluationId' -CorrelationId `$$correlationVariable; ") `
            -Purpose "$kind evaluation $branchId"
        Register-HHEdit -Start ($loopAst.Body.Extent.StartOffset + 1) -Length 0 `
            -Text ("`nInvoke-HHBranchProbe -Id '$bodyId' -CorrelationId `$$correlationVariable`n") `
            -Purpose "correlated block outcome $bodyId"
        $branches.Add((Get-HHBranchManifestEntry -Node $loopAst -Id $branchId -Kind $kind `
                -Strategy evaluation-vs-body -Outcomes @(
                [pscustomobject]@{ id = "$branchId-entered"; label = 'entered' },
                [pscustomobject]@{ id = "$branchId-empty"; label = 'not-entered' }
            ) -StrategyData @{
                evaluationId = $evaluationId
                bodyId = $bodyId
                correlation = 'invocation'
            }))
    }
}

$postTestLoopTypes = @(
    [System.Management.Automation.Language.DoWhileStatementAst],
    [System.Management.Automation.Language.DoUntilStatementAst]
)

foreach ($loopType in $postTestLoopTypes) {
    foreach ($loopAst in $ast.FindAll({
                param($node)
                $node.GetType() -eq $loopType
            }, $true)) {
        $kind = $loopAst.GetType().Name.Replace('StatementAst', '').ToLowerInvariant()
        $branchId = Get-HHIdentifier -Node $loopAst -Kind $kind
        $bodyId = "$branchId-body"
        $completedId = "$branchId-completed"
        Register-HHBlockProbe -Block $loopAst.Body -OutcomeId $bodyId
        Register-HHEdit -Start $loopAst.Extent.EndOffset -Length 0 `
            -Text "; Invoke-HHBranchProbe -Id '$completedId'" `
            -Purpose "$kind completion $branchId"
        $branches.Add((Get-HHBranchManifestEntry -Node $loopAst -Id $branchId -Kind $kind `
                -Strategy post-test-loop -Outcomes @(
                [pscustomobject]@{ id = "$branchId-repeated"; label = 'condition-continued' },
                [pscustomobject]@{ id = "$branchId-exited"; label = 'condition-exited' }
            ) -StrategyData @{ bodyId = $bodyId; completedId = $completedId }))
    }
}

foreach ($ternaryAst in $ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.TernaryExpressionAst]
        }, $true)) {
    $branchId = Get-HHIdentifier -Node $ternaryAst -Kind 'ternary'
    $trueId = "$branchId-true"
    $falseId = "$branchId-false"
    foreach ($arm in @(
            [pscustomobject]@{ Ast = $ternaryAst.IfTrue; Id = $trueId },
            [pscustomobject]@{ Ast = $ternaryAst.IfFalse; Id = $falseId }
        )) {
        $replacement = "(& { Invoke-HHBranchProbe -Id '$($arm.Id)'; $($arm.Ast.Extent.Text) })"
        Register-HHEdit -Start $arm.Ast.Extent.StartOffset -Length `
            ($arm.Ast.Extent.EndOffset - $arm.Ast.Extent.StartOffset) `
            -Text $replacement -Purpose "ternary arm $($arm.Id)"
    }
    Register-HHDirectBranch -Id $branchId -Kind 'ternary' -Outcomes @(
        [pscustomobject]@{ id = $trueId; label = 'true' },
        [pscustomobject]@{ id = $falseId; label = 'false' }
    ) -Node $ternaryAst
}

foreach ($chainAst in $ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.PipelineChainAst] -and
                $node.Parent -isnot [System.Management.Automation.Language.PipelineChainAst]
        }, $true)) {
    $branchId = Get-HHIdentifier -Node $chainAst -Kind 'pipeline-chain'
    $evaluationId = "$branchId-evaluated"
    $rhsId = "$branchId-rhs"
    Register-HHEdit -Start $chainAst.Extent.StartOffset -Length 0 `
        -Text "Invoke-HHBranchProbe -Id '$evaluationId'; " `
        -Purpose "pipeline chain evaluation $branchId"
    $rhs = $chainAst.RhsPipeline
    $replacement = "& { Invoke-HHBranchProbe -Id '$rhsId'; $($rhs.Extent.Text) }"
    Register-HHEdit -Start $rhs.Extent.StartOffset -Length `
        ($rhs.Extent.EndOffset - $rhs.Extent.StartOffset) `
        -Text $replacement -Purpose "pipeline chain rhs $branchId"
    $branches.Add((Get-HHBranchManifestEntry -Node $chainAst -Id $branchId `
            -Kind "pipeline-$($chainAst.Operator.ToString().ToLowerInvariant())" `
            -Strategy evaluation-vs-rhs -Outcomes @(
            [pscustomobject]@{ id = "$branchId-rhs-ran"; label = 'rhs-ran' },
            [pscustomobject]@{ id = "$branchId-short-circuited"; label = 'short-circuited' }
        ) -StrategyData @{ evaluationId = $evaluationId; rhsId = $rhsId }))
}

foreach ($tryAst in $ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.TryStatementAst]
        }, $true)) {
    $branchId = Get-HHIdentifier -Node $tryAst -Kind 'try'
    $outcomes = [System.Collections.Generic.List[object]]::new()
    $normalId = "$branchId-normal"
    $stateSuffix = $branchId -replace '[^A-Za-z0-9_]', '_'
    $escapedVariable = "__hhBranchEscaped_$stateSuffix"
    $handledVariable = "__hhBranchHandled_$stateSuffix"
    Register-HHEdit -Start $tryAst.Extent.StartOffset -Length 0 `
        -Text ('try { $' + $escapedVariable + ' = $false; $' + $handledVariable +
            ' = $false; ') `
        -Purpose "try completion wrapper start $branchId"
    Register-HHEdit -Start $tryAst.Extent.EndOffset -Length 0 `
        -Text (' } catch { $' + $escapedVariable +
            " = `$true; throw } finally { if (-not `$$escapedVariable -and -not `$$handledVariable) { " +
            "Invoke-HHBranchProbe -Id '$normalId' } }") `
        -Purpose "try completion wrapper end $branchId"
    $outcomes.Add([pscustomobject]@{ id = $normalId; label = 'normal' })

    $index = 0
    foreach ($catchClause in $tryAst.CatchClauses) {
        $catchId = "$branchId-catch-$index"
        Register-HHEdit -Start ($catchClause.Body.Extent.StartOffset + 1) -Length 0 `
            -Text ("`n`$$handledVariable = `$true; Invoke-HHBranchProbe -Id '$catchId'`n") `
            -Purpose "try catch outcome $catchId"
        $outcomes.Add([pscustomobject]@{ id = $catchId; label = "catch-$index" })
        $index++
    }
    Register-HHDirectBranch -Id $branchId -Kind 'try-catch' `
        -Outcomes $outcomes.ToArray() -Node $tryAst
}

foreach ($trapAst in $ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.TrapStatementAst]
        }, $true)) {
    $namedBlock = $trapAst.Parent
    while ($null -ne $namedBlock -and
        $namedBlock -isnot [System.Management.Automation.Language.NamedBlockAst]) {
        $namedBlock = $namedBlock.Parent
    }
    if ($null -eq $namedBlock -or $namedBlock.Statements.Count -eq 0) {
        throw "A trap requires an executable containing block for branch measurement at $($trapAst.Extent.StartLineNumber)."
    }

    $branchId = Get-HHIdentifier -Node $trapAst -Kind 'trap'
    $evaluationId = "$branchId-evaluated"
    $handlerId = "$branchId-handler"
    Register-HHEdit -Start $namedBlock.Statements[0].Extent.StartOffset -Length 0 `
        -Text "Invoke-HHBranchProbe -Id '$evaluationId'; " `
        -Purpose "trap evaluation $branchId"
    Register-HHBlockProbe -Block $trapAst.Body -OutcomeId $handlerId
    $branches.Add((Get-HHBranchManifestEntry -Node $trapAst -Id $branchId -Kind trap `
            -Strategy evaluation-vs-handler -Outcomes @(
            [pscustomobject]@{ id = "$branchId-handled"; label = 'handler-ran' },
            [pscustomobject]@{ id = "$branchId-not-handled"; label = 'handler-not-run' }
        ) -StrategyData @{ evaluationId = $evaluationId; handlerId = $handlerId }))
}

$prelude = @'
function New-HHBranchCorrelationId {
    return [Guid]::NewGuid().ToString('N')
}

function Get-HHBranchProbeChecksum {
    param([Parameter(Mandatory)][string]$Payload)

    $bytes = [Text.Encoding]::UTF8.GetBytes($Payload)
    return [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($bytes)
    ).ToLowerInvariant()
}

function Invoke-HHBranchProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Id,
        [string]$CorrelationId
    )

    if ([string]::IsNullOrWhiteSpace($env:HH_BRANCH_LOG)) {
        throw 'HH_BRANCH_LOG is required for instrumented coverage execution.'
    }
    if ([string]::IsNullOrWhiteSpace($env:HH_COVERAGE_CASE)) {
        throw 'HH_COVERAGE_CASE is required for instrumented coverage execution.'
    }
    if ($Id -notmatch '^[a-f0-9]{12}-[A-Za-z0-9-]+-L[0-9]+C[0-9]+-[0-9]+-[A-Za-z0-9-]+$') {
        throw "Invalid branch event identifier '$Id'."
    }
    if (-not [string]::IsNullOrEmpty($CorrelationId) -and
        $CorrelationId -notmatch '^[a-f0-9]{32}$') {
        throw "Invalid branch correlation identifier '$CorrelationId'."
    }

    $basePath = [IO.Path]::GetFullPath($env:HH_BRANCH_LOG)
    $shardRoot = "$basePath.shards"
    [IO.Directory]::CreateDirectory($shardRoot) | Out-Null
    $process = [Diagnostics.Process]::GetCurrentProcess()
    $runspaceId = $Host.Runspace.InstanceId.ToString('N')
    $shardId = '{0}-{1}-{2}' -f $PID, $process.StartTime.ToUniversalTime().Ticks, $runspaceId
    $mutexIdentity = Get-HHBranchProbeChecksum -Payload "$basePath|$shardId"
    $mutex = [Threading.Mutex]::new($false, "HostHunterBranchCoverage-$mutexIdentity")
    $lockTaken = $false
    try {
        $lockTaken = $mutex.WaitOne([TimeSpan]::FromSeconds(30))
        if (-not $lockTaken) {
            throw "Timed out acquiring the branch shard lock for '$shardId'."
        }

        if ($null -eq (Get-Variable -Name HHBranchProbeState -Scope Global -ErrorAction Ignore)) {
            $global:HHBranchProbeState = @{}
        }
        $markerPath = Join-Path $shardRoot "$shardId.expected.json"
        if (-not $global:HHBranchProbeState.ContainsKey($mutexIdentity) -or
            -not [IO.File]::Exists($markerPath)) {
            $existingEventPath = Join-Path $shardRoot "$shardId.events.jsonl"
            $existingIndexPath = Join-Path $shardRoot "$shardId.index.tsv"
            if ([IO.File]::Exists($existingEventPath) -or [IO.File]::Exists($existingIndexPath)) {
                throw "Branch shard '$shardId' cannot resume without its in-memory state and marker."
            }
            $marker = [ordered]@{
                schemaVersion = 2
                shardId = $shardId
                processId = $PID
                processStartUtcTicks = $process.StartTime.ToUniversalTime().Ticks
                runspaceId = $runspaceId
            }
            [IO.File]::WriteAllText(
                $markerPath,
                ($marker | ConvertTo-Json -Compress),
                [Text.UTF8Encoding]::new($false)
            )
            $global:HHBranchProbeState[$mutexIdentity] = [pscustomobject]@{
                Sequence = [long]0
                PreviousChecksum = ('0' * 64)
            }
        }

        $state = $global:HHBranchProbeState[$mutexIdentity]
        $sequence = [long]$state.Sequence + 1
        $caseId = [string]$env:HH_COVERAGE_CASE
        $correlation = if ([string]::IsNullOrEmpty($CorrelationId)) { '' } else { $CorrelationId }
        $payload = '{0}{1}{2}{1}{3}{1}{4}{1}{5}{1}{6}' -f @(
            $shardId, [char]9, $sequence, $caseId, $Id, $correlation,
            $state.PreviousChecksum
        )
        $checksum = Get-HHBranchProbeChecksum -Payload $payload
        $record = [ordered]@{
            schemaVersion = 2
            shardId = $shardId
            sequence = $sequence
            caseId = $caseId
            eventId = $Id
            correlationId = $correlation
            previousChecksum = $state.PreviousChecksum
            checksum = $checksum
        }
        $eventPath = Join-Path $shardRoot "$shardId.events.jsonl"
        $indexPath = Join-Path $shardRoot "$shardId.index.tsv"
        [IO.File]::AppendAllText(
            $eventPath,
            (($record | ConvertTo-Json -Compress) + [Environment]::NewLine),
            [Text.UTF8Encoding]::new($false)
        )
        [IO.File]::AppendAllText(
            $indexPath,
            ("$sequence`t$checksum" + [Environment]::NewLine),
            [Text.UTF8Encoding]::new($false)
        )
        $state.Sequence = $sequence
        $state.PreviousChecksum = $checksum
    }
    finally {
        if ($lockTaken) {
            $mutex.ReleaseMutex()
        }
        $mutex.Dispose()
    }
}

'@

$instrumented = $source
foreach ($edit in $edits | Sort-Object Start -Descending) {
    $instrumented = $instrumented.Remove($edit.Start, $edit.Length).Insert($edit.Start, $edit.Text)
}
$instrumented = $prelude + $instrumented

$outputDirectory = Split-Path -Parent $OutputPath
$manifestDirectory = Split-Path -Parent $ManifestPath
foreach ($directory in @($outputDirectory, $manifestDirectory) | Where-Object { $_ }) {
    [System.IO.Directory]::CreateDirectory($directory) | Out-Null
}
[System.IO.File]::WriteAllText($OutputPath, $instrumented, [System.Text.UTF8Encoding]::new($false))

$manifest = [ordered]@{
    schemaVersion = 2
    source = $resolvedPath
    sourceSha256 = (Get-FileHash -LiteralPath $resolvedPath -Algorithm SHA256).Hash.ToLowerInvariant()
    branchCount = $branches.Count
    outcomeCount = @($branches | ForEach-Object { @($_.outcomes) }).Count
    branches = $branches.ToArray()
}
$manifest | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $ManifestPath -Encoding utf8NoBOM
