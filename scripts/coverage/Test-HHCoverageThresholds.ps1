[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$MetricsPath,

    [ValidateRange(0, 100)]
    [double]$Minimum = 90,

    [Parameter(Mandatory)]
    [string]$ReportPath,

    [Parameter(Mandatory)]
    [string]$JUnitPath,

    [switch]$NoThrow,

    [switch]$PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$requiredMetrics = @('statements', 'branches', 'functions', 'lines')
$inputMetrics = Get-Content -LiteralPath $MetricsPath -Raw | ConvertFrom-Json
$metricResults = [System.Collections.Generic.List[object]]::new()

foreach ($name in $requiredMetrics) {
    $property = $inputMetrics.PSObject.Properties[$name]
    $reason = $null
    $total = 0
    $covered = 0

    if ($null -eq $property) {
        $reason = 'metric is missing'
    }
    else {
        $metric = $property.Value
        if ($null -eq $metric.PSObject.Properties['total'] -or
            $null -eq $metric.PSObject.Properties['covered']) {
            $reason = 'covered or total is missing'
        }
        else {
            $total = [int]$metric.total
            $covered = [int]$metric.covered
            if ($total -le 0) {
                $reason = 'denominator is zero'
            }
            elseif ($covered -lt 0 -or $covered -gt $total) {
                $reason = 'covered count is outside the denominator'
            }
        }
    }

    $percentage = if ($total -gt 0 -and $covered -ge 0 -and $covered -le $total) {
        ($covered / $total) * 100
    }
    else {
        0
    }
    $passed = $null -eq $reason -and $percentage -ge $Minimum
    if (-not $passed -and $null -eq $reason) {
        $reason = 'below threshold'
    }

    $metricResults.Add([pscustomobject]@{
            name = $name
            total = $total
            covered = $covered
            percentage = [math]::Round($percentage, 4)
            minimum = $Minimum
            passed = $passed
            reason = $reason
        })
}

$failedMetrics = @($metricResults | Where-Object { -not $_.passed })
$report = [ordered]@{
    schemaVersion = 1
    passed = $failedMetrics.Count -eq 0
    minimum = $Minimum
    metrics = $metricResults.ToArray()
}

foreach ($path in @($ReportPath, $JUnitPath)) {
    $directory = Split-Path -Parent $path
    if ($directory) {
        [System.IO.Directory]::CreateDirectory($directory) | Out-Null
    }
}
$report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $ReportPath -Encoding utf8NoBOM

$document = [System.Xml.XmlDocument]::new()
$suite = $document.CreateElement('testsuite')
$suite.SetAttribute('name', 'HostHunter coverage thresholds')
$suite.SetAttribute('tests', [string]$requiredMetrics.Count)
$suite.SetAttribute('failures', [string]$failedMetrics.Count)
$document.AppendChild($suite) | Out-Null
foreach ($metric in $metricResults) {
    $testCase = $document.CreateElement('testcase')
    $testCase.SetAttribute('classname', 'coverage')
    $testCase.SetAttribute('name', $metric.name)
    if (-not $metric.passed) {
        $failure = $document.CreateElement('failure')
        $failure.SetAttribute('message', (
                '{0}: {1}% is not at least {2}% ({3})' -f
                    $metric.name, $metric.percentage, $metric.minimum, $metric.reason
            ))
        $testCase.AppendChild($failure) | Out-Null
    }
    $suite.AppendChild($testCase) | Out-Null
}
$settings = [System.Xml.XmlWriterSettings]@{
    Indent = $true
    Encoding = [System.Text.UTF8Encoding]::new($false)
}
$writer = [System.Xml.XmlWriter]::Create($JUnitPath, $settings)
try {
    $document.Save($writer)
}
finally {
    $writer.Dispose()
}

if ($PassThru) {
    $report
}
else {
    $report | ConvertTo-Json -Depth 6
}

if (-not $report.passed -and -not $NoThrow) {
    $names = $failedMetrics.name -join ', '
    throw "Coverage thresholds failed: $names."
}
