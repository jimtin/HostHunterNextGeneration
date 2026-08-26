function Invoke-HHCoverageFixture {
    [CmdletBinding()]
    param(
        [ValidateSet('alpha', 'other', 'throw')][string]$Mode,
        [int]$Value,
        [AllowEmptyCollection()][int[]]$Items
    )

    $sign = if ($Value -gt 0) { 'positive' } else { 'not-positive' }
    $selection = switch ($Mode) {
        alpha { 'alpha'; break }
        default { 'default' }
    }
    $total = 0
    $index = 0
    while ($index -lt $Value) { $total++; $index++ }
    for ($forIndex = 0; $forIndex -lt $Value; $forIndex++) { $total++ }
    foreach ($item in $Items) { $total += $item }
    try {
        if ($Mode -eq 'throw') { throw 'fixture' }
        $terminal = 'normal'
    }
    catch { $terminal = 'caught' }
    "$sign`:$selection`:$total`:$terminal"
}
