function Invoke-HHTryReturnFixture {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Value)

    try {
        return "return-$Value"
    }
    catch {
        return 'unexpected-catch'
    }
}

function Invoke-HHTryLoopControlFixture {
    [CmdletBinding()]
    param([Parameter(Mandatory)][ValidateSet('break', 'continue')][string]$Mode)

    $result = [Collections.Generic.List[string]]::new()
    foreach ($value in 1..2) {
        try {
            $result.Add("before-$value")
            if ($Mode -ceq 'break') {
                break
            }
            continue
        }
        catch {
            $result.Add('unexpected-catch')
        }
    }
    $result.Add('after-loop')
    return $result.ToArray()
}

function Invoke-HHTryOutcomeFixture {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('normal', 'caught', 'escaped')]
        [string]$Mode
    )

    try {
        if ($Mode -ceq 'caught') {
            throw [InvalidOperationException]::new('caught-error')
        }
        if ($Mode -ceq 'escaped') {
            throw [ArgumentException]::new('escaped-error')
        }
        'normal-result'
    }
    catch [InvalidOperationException] {
        'caught-result'
    }
}

function Invoke-HHTryAssignmentFixture {
    [CmdletBinding()]
    param([Parameter(Mandatory)][ValidateSet('normal', 'caught')][string]$Mode)

    $result = try {
        if ($Mode -ceq 'caught') {
            throw [InvalidOperationException]::new('assignment-caught')
        }
        [pscustomobject]@{ Value = 'assignment-normal' }
    }
    catch [InvalidOperationException] {
        [pscustomobject]@{ Value = 'assignment-caught' }
    }
    return $result
}

function Invoke-HHCorrelatedLoopFixture {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][int[]]$Items)

    $count = 0
    foreach ($item in $Items) {
        $count += $item
    }
    return $count
}
