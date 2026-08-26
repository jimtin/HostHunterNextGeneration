[CmdletBinding()]
param(
    [Parameter(Mandatory)][Collections.IDictionary]$Metrics,
    [ValidateRange(0, 100)][double]$Minimum = 90
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$required = @('statements', 'branches', 'functions', 'lines')
$results = [ordered]@{}
foreach ($name in $required) {
    if (-not $Metrics.Contains($name)) { throw "Coverage metric '$name' is missing." }
    $inputMetric = $Metrics[$name]
    $covered = [int]$inputMetric.covered
    $total = [int]$inputMetric.total
    $valid = $total -gt 0 -and $covered -ge 0 -and $covered -le $total
    $percentage = if ($valid) { [math]::Round(($covered / $total) * 100, 4) } else { 0 }
    $results[$name] = [pscustomobject][ordered]@{
        name = $name
        covered = $covered
        total = $total
        percentage = $percentage
        minimum = $Minimum
        deficit = if ($total -gt 0) {
            [math]::Max(0, [math]::Ceiling(($Minimum / 100) * $total) - $covered)
        } else { 0 }
        passed = $valid -and $percentage -ge $Minimum
        reason = if (-not $valid) { 'invalid denominator or covered count' }
            elseif ($percentage -lt $Minimum) { 'below threshold' }
            else { $null }
        definition = [string]$inputMetric.definition
    }
}

[pscustomobject][ordered]@{
    passed = @($results.Values | Where-Object { -not $_.passed }).Count -eq 0
    metrics = $results
}
