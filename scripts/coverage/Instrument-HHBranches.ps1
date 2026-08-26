[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$OutputPath,
    [Parameter(Mandatory)][string]$ManifestPath
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$resolvedPath = (Resolve-Path -LiteralPath $Path).Path
$source = [IO.File]::ReadAllText($resolvedPath)
$sourceIdentity = (Get-FileHash -LiteralPath $resolvedPath -Algorithm SHA256).Hash.Substring(0, 12).ToLowerInvariant()
$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseInput($source, $resolvedPath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) { throw "Cannot instrument '$resolvedPath': $($parseErrors[0].Message)" }

$unsupportedTypes = @(
    [Management.Automation.Language.DoWhileStatementAst],
    [Management.Automation.Language.DoUntilStatementAst],
    [Management.Automation.Language.TernaryExpressionAst],
    [Management.Automation.Language.PipelineChainAst],
    [Management.Automation.Language.TrapStatementAst]
)
foreach ($type in $unsupportedTypes) {
    $unsupported = $ast.Find({ param($node) $node -is $type }, $true)
    if ($null -ne $unsupported) {
        throw "Unsupported coverage decision '$($type.Name)' at ${resolvedPath}:$($unsupported.Extent.StartLineNumber)."
    }
}

$edits = [Collections.Generic.List[object]]::new()
$branches = [Collections.Generic.List[object]]::new()
function Add-HHEdit {
    param([int]$Start, [int]$Length, [string]$Text)
    if ($Start -lt 0 -or $Length -lt 0 -or ($Start + $Length) -gt $source.Length) {
        throw 'Invalid branch instrumentation edit.'
    }
    $edits.Add([pscustomobject]@{ Start = $Start; Length = $Length; Text = $Text })
}
function Get-HHBranchId {
    param([Management.Automation.Language.Ast]$Node, [string]$Kind)
    '{0}-{1}-L{2}C{3}' -f $sourceIdentity, $Kind, $Node.Extent.StartLineNumber, $Node.Extent.StartColumnNumber
}
function Get-HHFunctionName {
    param([Management.Automation.Language.Ast]$Node)
    for ($parent = $Node.Parent; $null -ne $parent; $parent = $parent.Parent) {
        if ($parent -is [Management.Automation.Language.FunctionDefinitionAst] -or
            $parent -is [Management.Automation.Language.FunctionMemberAst]) { return [string]$parent.Name }
    }
    '<script>'
}
function Add-HHProbeToBlock {
    param([Management.Automation.Language.StatementBlockAst]$Block, [string]$OutcomeId)
    Add-HHEdit -Start ($Block.Extent.StartOffset + 1) -Length 0 -Text "`nInvoke-HHBranchProbe -Id '$OutcomeId'`n"
}
function Add-HHBranch {
    param([Management.Automation.Language.Ast]$Node, [string]$Id, [string]$Kind, [object[]]$Outcomes)
    $branches.Add([pscustomobject][ordered]@{
            id = $Id; kind = $Kind; source = $resolvedPath; function = Get-HHFunctionName $Node
            line = $Node.Extent.StartLineNumber; column = $Node.Extent.StartColumnNumber; outcomes = $Outcomes
        })
}

foreach ($ifAst in $ast.FindAll({ param($node) $node -is [Management.Automation.Language.IfStatementAst] }, $true)) {
    $id = Get-HHBranchId $ifAst if
    $outcomes = [Collections.Generic.List[object]]::new()
    for ($index = 0; $index -lt $ifAst.Clauses.Count; $index++) {
        $outcomeId = "$id-clause-$index"
        Add-HHProbeToBlock $ifAst.Clauses[$index].Item2 $outcomeId
        $outcomes.Add([pscustomobject]@{ id = $outcomeId; label = "clause-$index" })
    }
    $elseId = "$id-else"
    if ($null -eq $ifAst.ElseClause) {
        Add-HHEdit $ifAst.Extent.EndOffset 0 " else { Invoke-HHBranchProbe -Id '$elseId' }"
        $outcomes.Add([pscustomobject]@{ id = $elseId; label = 'implicit-else' })
    } else {
        Add-HHProbeToBlock $ifAst.ElseClause $elseId
        $outcomes.Add([pscustomobject]@{ id = $elseId; label = 'else' })
    }
    Add-HHBranch $ifAst $id if $outcomes.ToArray()
}

foreach ($switchAst in $ast.FindAll({ param($node) $node -is [Management.Automation.Language.SwitchStatementAst] }, $true)) {
    $id = Get-HHBranchId $switchAst switch
    $outcomes = [Collections.Generic.List[object]]::new()
    for ($index = 0; $index -lt $switchAst.Clauses.Count; $index++) {
        $outcomeId = "$id-clause-$index"
        Add-HHProbeToBlock $switchAst.Clauses[$index].Item2 $outcomeId
        $outcomes.Add([pscustomobject]@{ id = $outcomeId; label = "clause-$index" })
    }
    $defaultId = "$id-default"
    if ($null -eq $switchAst.Default) {
        Add-HHEdit ($switchAst.Extent.EndOffset - 1) 0 "`ndefault { Invoke-HHBranchProbe -Id '$defaultId' }`n"
        $outcomes.Add([pscustomobject]@{ id = $defaultId; label = 'implicit-default' })
    } else {
        Add-HHProbeToBlock $switchAst.Default $defaultId
        $outcomes.Add([pscustomobject]@{ id = $defaultId; label = 'default' })
    }
    Add-HHBranch $switchAst $id switch $outcomes.ToArray()
}

$loopTypes = @(
    [Management.Automation.Language.WhileStatementAst],
    [Management.Automation.Language.ForStatementAst],
    [Management.Automation.Language.ForEachStatementAst]
)
foreach ($loopType in $loopTypes) {
    foreach ($loopAst in $ast.FindAll({ param($node) $node.GetType() -eq $loopType }, $true)) {
        $kind = $loopAst.GetType().Name.Replace('StatementAst', '').ToLowerInvariant()
        $id = Get-HHBranchId $loopAst $kind
        $enteredId = "$id-entered"
        $emptyId = "$id-not-entered"
        $variable = '__hhCoverageEntered_{0}' -f ($id -replace '[^A-Za-z0-9_]', '_')
        Add-HHEdit $loopAst.Extent.StartOffset 0 ('$' + $variable + ' = $false; ')
        Add-HHEdit ($loopAst.Body.Extent.StartOffset + 1) 0 `
            "`nif (-not `$$variable) { `$$variable = `$true; Invoke-HHBranchProbe -Id '$enteredId' }`n"
        Add-HHEdit $loopAst.Extent.EndOffset 0 `
            "; if (-not `$$variable) { Invoke-HHBranchProbe -Id '$emptyId' }"
        Add-HHBranch $loopAst $id $kind @(
            [pscustomobject]@{ id = $enteredId; label = 'entered' }
            [pscustomobject]@{ id = $emptyId; label = 'not-entered' }
        )
    }
}

foreach ($tryAst in $ast.FindAll({ param($node) $node -is [Management.Automation.Language.TryStatementAst] }, $true)) {
    $id = Get-HHBranchId $tryAst try
    $normalId = "$id-normal"
    $stateSuffix = $id -replace '[^A-Za-z0-9_]', '_'
    $escapedVariable = "__hhCoverageEscaped_$stateSuffix"
    $handledVariable = "__hhCoverageHandled_$stateSuffix"
    $outcomes = [Collections.Generic.List[object]]::new()
    Add-HHEdit $tryAst.Extent.StartOffset 0 `
        ('try { $' + $escapedVariable + ' = $false; $' + $handledVariable + ' = $false; ')
    $completionProbe = "if (-not `$$escapedVariable -and -not `$$handledVariable) { " +
        "Invoke-HHBranchProbe -Id '$normalId' }"
    Add-HHEdit $tryAst.Extent.EndOffset 0 `
        (' } catch { $' + $escapedVariable + " = `$true; throw } finally { $completionProbe }")
    $outcomes.Add([pscustomobject]@{ id = $normalId; label = 'normal' })
    for ($index = 0; $index -lt $tryAst.CatchClauses.Count; $index++) {
        $catchId = "$id-catch-$index"
        Add-HHEdit ($tryAst.CatchClauses[$index].Body.Extent.StartOffset + 1) 0 `
            "`n`$$handledVariable = `$true; Invoke-HHBranchProbe -Id '$catchId'`n"
        $outcomes.Add([pscustomobject]@{ id = $catchId; label = "catch-$index" })
    }
    Add-HHBranch $tryAst $id 'try-catch' $outcomes.ToArray()
}

$prelude = @'
function Invoke-HHBranchProbe {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Id)
    $hits = [AppDomain]::CurrentDomain.GetData('HostHunterCoverageHits')
    if ($null -eq $hits) { throw 'The in-memory HostHunter coverage collector is not initialized.' }
    $null = $hits.TryAdd($Id, 0)
}

'@
$instrumented = $source
foreach ($edit in $edits | Sort-Object Start -Descending) {
    $instrumented = $instrumented.Remove($edit.Start, $edit.Length).Insert($edit.Start, $edit.Text)
}
$instrumented = $prelude + $instrumented
foreach ($directory in @((Split-Path -Parent $OutputPath), (Split-Path -Parent $ManifestPath)) | Where-Object { $_ }) {
    [IO.Directory]::CreateDirectory($directory) | Out-Null
}
[IO.File]::WriteAllText($OutputPath, $instrumented, [Text.UTF8Encoding]::new($false))
$manifest = [ordered]@{
    schemaVersion = 3; source = $resolvedPath
    sourceSha256 = (Get-FileHash -LiteralPath $resolvedPath -Algorithm SHA256).Hash.ToLowerInvariant()
    branchCount = $branches.Count; outcomeCount = @($branches | ForEach-Object outcomes).Count
    branches = $branches.ToArray()
}
$manifest | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $ManifestPath -Encoding utf8NoBOM
