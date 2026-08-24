class HHCoverageClassifier {
    [string] Classify([int]$Value) {
        if ($Value -gt 0) {
            return 'class-positive'
        }

        return 'class-not-positive'
    }
}

function Invoke-HHPipelineBlockFixture {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [int]$Value
    )

    begin {
        $total = 0
        'begin'
    }
    process {
        $total += $Value
        "process-$Value"
    }
    end {
        "end-$total"
    }
}

function Invoke-HHNestedFixture {
    [CmdletBinding()]
    param([Parameter(Mandatory)][int]$Value)

    function Get-HHNestedValue {
        param([Parameter(Mandatory)][int]$InputValue)

        if ($InputValue -ge 0) {
            return 'nested-nonnegative'
        }

        return 'nested-negative'
    }

    $scriptBlock = {
        param([int]$InputValue)

        if ($InputValue % 2 -eq 0) {
            return 'scriptblock-even'
        }

        return 'scriptblock-odd'
    }

    return @(
        Get-HHNestedValue -InputValue $Value
        & $scriptBlock $Value
    )
}

function Invoke-HHTrapFixture {
    [CmdletBinding()]
    param([switch]$ThrowInTrapScope)

    trap [System.InvalidOperationException] {
        'trap-handled'
        continue
    }

    'trap-start'
    if ($ThrowInTrapScope) {
        throw [System.InvalidOperationException]::new('trap-fixture')
    }
    'trap-end'
}

function Invoke-HHEarlyControlFixture {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [int[]]$Items
    )

    $result = [System.Collections.Generic.List[string]]::new()
    foreach ($item in $Items) {
        if ($item -lt 0) {
            continue
        }
        if ($item -gt 3) {
            break
        }
        $result.Add("control-$item")
    }

    if ($result.Count -eq 0) {
        return @('control-empty')
    }

    return $result.ToArray()
}

function Invoke-HHBranchFixture {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet(
            'alpha',
            'beta',
            'other',
            'regex-42',
            'wildcard-value',
            'throw-invalid',
            'throw-other'
        )]
        [string]$Mode,

        [Parameter(Mandatory)]
        [int]$Value,

        [AllowEmptyCollection()]
        [int[]]$Items = @(),

        [switch]$ThrowInTrapScope
    )

    $result = [System.Collections.Generic.List[string]]::new()

    if ($Value -gt 0) {
        $result.Add('positive')
    }
    elseif ($Value -eq 0) {
        $result.Add('zero')
    }
    else {
        $result.Add('negative')
    }

    if ($Mode -eq 'alpha') {
        $result.Add('implicit-if-true')
    }

    switch ($Mode) {
        'alpha' {
            $result.Add('alpha')
            break
        }
        'beta' {
            $result.Add('beta')
            break
        }
        default {
            $result.Add('default')
        }
    }

    switch -Regex ($Mode) {
        '^regex-[0-9]+$' {
            $result.Add('regex-match')
            break
        }
        default {
            $result.Add('regex-default')
        }
    }

    switch -Wildcard ($Mode) {
        'wildcard-*' {
            $result.Add('wildcard-match')
            break
        }
        default {
            $result.Add('wildcard-default')
        }
    }

    switch -Regex ($Mode) {
        '^other$' {
            $result.Add('implicit-regex-match')
        }
    }

    $whileIndex = 0
    while ($whileIndex -lt $Value) {
        $result.Add("while-$whileIndex")
        $whileIndex++
    }

    for ($forIndex = 0; $forIndex -lt $Value; $forIndex++) {
        $result.Add("for-$forIndex")
    }

    foreach ($item in $Items) {
        $result.Add("item-$item")
    }

    $doWhileIndex = 0
    do {
        $result.Add("do-while-$doWhileIndex")
        $doWhileIndex++
    } while ($doWhileIndex -lt $Value)

    $doUntilIndex = 0
    do {
        $result.Add("do-until-$doUntilIndex")
        $doUntilIndex++
    } until ($doUntilIndex -ge $Value)

    $result.Add(($Value -ge 0 ? 'ternary-true' : 'ternary-false'))

    /bin/test $Value -ge 0 && $result.Add('and-right')
    /bin/test $Value -ge 0 || $result.Add('or-right')

    try {
        if ($Mode -eq 'throw-invalid') {
            throw [System.InvalidOperationException]::new('invalid')
        }
        elseif ($Mode -eq 'throw-other') {
            throw [System.ArgumentException]::new('other')
        }
        else {
            $result.Add('try-success')
        }
    }
    catch [System.InvalidOperationException] {
        $result.Add('catch-invalid')
    }
    catch {
        $result.Add('catch-other')
    }
    finally {
        $result.Add('finally')
    }

    $classifier = [HHCoverageClassifier]::new()
    $result.Add($classifier.Classify($Value))
    $result.AddRange([string[]](Invoke-HHNestedFixture -Value $Value))
    $result.AddRange([string[]](@($Value, ($Value + 1)) | Invoke-HHPipelineBlockFixture))
    $result.AddRange([string[]](Invoke-HHTrapFixture -ThrowInTrapScope:$ThrowInTrapScope))
    $result.AddRange([string[]](Invoke-HHEarlyControlFixture -Items $Items))

    return $result.ToArray()
}
