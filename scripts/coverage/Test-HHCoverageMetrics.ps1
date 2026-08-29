[CmdletBinding()]
param(
    [Parameter(Mandatory)][Collections.IDictionary]$Metrics,
    [ValidateRange(0, 100)][double]$Minimum = 90
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$required = @('statements', 'lines', 'functions')
$results = [ordered]@{}

foreach ($name in $required) {
    if (-not $Metrics.Contains($name)) { throw "Coverage metric '$name' is missing." }
    $inputMetric = $Metrics[$name]
    $covered = [int]$inputMetric.covered
    $total = [int]$inputMetric.total
    $valid = $total -gt 0 -and $covered -ge 0 -and $covered -le $total
    $percentage = if ($valid) {
        [math]::Round(($covered / $total) * 100, 4)
    } else { 0 }
    $thresholdPassed = $valid -and (
        ([decimal]$covered * 100) -ge ([decimal]$Minimum * $total)
    )
    $results[$name] = [pscustomobject][ordered]@{
        name = $name
        covered = $covered
        total = $total
        percentage = $percentage
        minimum = $Minimum
        deficit = if ($total -gt 0) {
            [math]::Max(0, [math]::Ceiling(($Minimum / 100) * $total) - $covered)
        } else { 0 }
        passed = $thresholdPassed
        reason = if (-not $valid) {
            'invalid denominator or covered count'
        } elseif (-not $thresholdPassed) {
            'below threshold'
        } else { $null }
        definition = [string]$inputMetric.definition
    }
}

[pscustomobject][ordered]@{
    passed = @($results.Values | Where-Object { -not $_.passed }).Count -eq 0
    metrics = $results
}
