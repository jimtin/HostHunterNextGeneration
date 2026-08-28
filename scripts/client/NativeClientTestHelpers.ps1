Set-StrictMode -Version Latest

function Select-HHNativeClientTerminalResult {
    [CmdletBinding()]
    param([AllowEmptyCollection()][object[]]$InputObject)

    $terminal = @($InputObject | Where-Object {
            $null -ne $_ -and $null -ne $_.PSObject.Properties['Status'] -and
            [string]$_.Status -ceq 'passed'
        })
    if ($terminal.Count -ne 1) {
        throw "The native-client journey emitted $($terminal.Count) passing terminal receipts; expected exactly one."
    }
    $terminal[0]
}

function Format-HHNativeClientFailure {
    [CmdletBinding()]
    param(
        [AllowEmptyString()][string]$StandardError,
        [AllowEmptyString()][string]$StandardOutput,
        [ValidateRange(256, 8192)][int]$MaximumCharacters = 4096
    )

    $stderrBudget = [Math]::Max(128, [int]($MaximumCharacters * 0.75))
    $stdoutBudget = $MaximumCharacters - $stderrBudget
    $stderrTail = $StandardError.Trim()
    $stdoutTail = $StandardOutput.Trim()
    if ($stderrTail.Length -gt $stderrBudget) {
        $stderrTail = [string][char]0x2026 +
            $stderrTail.Substring($stderrTail.Length - $stderrBudget)
    }
    if ($stdoutTail.Length -gt $stdoutBudget) {
        $stdoutTail = [string][char]0x2026 +
            $stdoutTail.Substring($stdoutTail.Length - $stdoutBudget)
    }
    $message = ([string]::Join("`n", @(
                if (-not [string]::IsNullOrWhiteSpace($stderrTail)) {
                    "stderr:`n$stderrTail"
                }
                if (-not [string]::IsNullOrWhiteSpace($stdoutTail)) {
                    "stdout:`n$stdoutTail"
                }
            ))).Trim()
    $message = $message -replace '(?i)(token|secret|password|credential)(\s*[:=]\s*)\S+', `
        '$1$2<redacted>'
    if ($message.Length -gt ($MaximumCharacters + 32)) {
        $message = [string][char]0x2026 +
            $message.Substring($message.Length - ($MaximumCharacters + 32))
    }
    $message
}
