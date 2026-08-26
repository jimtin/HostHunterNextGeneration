Set-StrictMode -Version Latest

BeforeAll {
    $script:repositoryRoot = (Resolve-Path -LiteralPath (
            Join-Path $PSScriptRoot '../..'
        )).Path
    $script:runtimeRoot = Join-Path $script:repositoryRoot 'scripts/runtime'
    $script:originalPath = $env:PATH
    $script:originalProject = $env:HH_RUNTIME_PROJECT
    $script:originalState = $env:HH_FAKE_DOCKER_STATE
    $script:originalLog = $env:HH_FAKE_DOCKER_LOG
    $script:originalFailure = $env:HH_FAKE_FAIL_REMOVE_NAME
    $script:originalAttached = $env:HH_FAKE_ATTACHED
    $script:project = 'hosthunter-runtime-lifecycle-test'
    $script:roles = @('data', 'secrets', 'anchors', 'ssh', 'evidence')
    $script:volumeNames = @($script:roles | ForEach-Object { "$($script:project)-$_" })
}

Describe 'Runtime volume lifecycle' -Tag Integration {
BeforeEach {
    $script:fakeRoot = Join-Path $TestDrive 'fake-docker'
    if (Test-Path -LiteralPath $script:fakeRoot) {
        Remove-Item -LiteralPath $script:fakeRoot -Recurse -Force
    }
    $script:fakeBin = Join-Path $PSScriptRoot 'runtime-fixture-bin'
    $script:fakeState = Join-Path $script:fakeRoot 'state'
    $script:fakeLog = Join-Path $script:fakeRoot 'docker.log'
    [IO.Directory]::CreateDirectory($script:fakeState) | Out-Null
    $fakePath = Join-Path $script:fakeBin 'docker'
    $env:PATH = "$($script:fakeBin):$($script:originalPath)"
    $env:HH_RUNTIME_PROJECT = $script:project
    $env:HH_FAKE_DOCKER_STATE = $script:fakeState
    $env:HH_FAKE_DOCKER_LOG = $script:fakeLog
    Remove-Item Env:HH_FAKE_FAIL_REMOVE_NAME -ErrorAction SilentlyContinue
    Remove-Item Env:HH_FAKE_ATTACHED -ErrorAction SilentlyContinue
    $probe = @(& $fakePath info 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "The fake Docker executable failed its setup probe: $($probe | Out-String)"
    }
}

AfterEach {
    $env:PATH = $script:originalPath
    if ($null -eq $script:originalProject) {
        Remove-Item Env:HH_RUNTIME_PROJECT -ErrorAction SilentlyContinue
    }
    else { $env:HH_RUNTIME_PROJECT = $script:originalProject }
    if ($null -eq $script:originalState) {
        Remove-Item Env:HH_FAKE_DOCKER_STATE -ErrorAction SilentlyContinue
    }
    else { $env:HH_FAKE_DOCKER_STATE = $script:originalState }
    if ($null -eq $script:originalLog) {
        Remove-Item Env:HH_FAKE_DOCKER_LOG -ErrorAction SilentlyContinue
    }
    else { $env:HH_FAKE_DOCKER_LOG = $script:originalLog }
    if ($null -eq $script:originalFailure) {
        Remove-Item Env:HH_FAKE_FAIL_REMOVE_NAME -ErrorAction SilentlyContinue
    }
    else { $env:HH_FAKE_FAIL_REMOVE_NAME = $script:originalFailure }
    if ($null -eq $script:originalAttached) {
        Remove-Item Env:HH_FAKE_ATTACHED -ErrorAction SilentlyContinue
    }
    else { $env:HH_FAKE_ATTACHED = $script:originalAttached }
}

    It 'initializes exactly five fresh project-owned external volumes without migration' {
        $output = @(& bash (Join-Path $script:runtimeRoot 'init.sh') 2>&1)
        $LASTEXITCODE | Should -Be 0 -Because ($output | Out-String)
        @(Get-ChildItem -LiteralPath $script:fakeState -File).Count | Should -Be 5
        for ($index = 0; $index -lt $script:roles.Count; $index++) {
            $state = Get-Content -LiteralPath (
                Join-Path $script:fakeState $script:volumeNames[$index]
            ) -Raw
            $state.Trim() | Should -BeExactly `
                "$($script:project)|$($script:roles[$index])"
        }
        ($output | Out-String) | Should -Match 'No native state was migrated'
    }

    It 'fails closed rather than filling a partial volume set' {
        [IO.File]::WriteAllText(
            (Join-Path $script:fakeState $script:volumeNames[0]),
            "$($script:project)|data`n"
        )
        $output = @(& bash (Join-Path $script:runtimeRoot 'init.sh') 2>&1)
        $LASTEXITCODE | Should -Be 65
        @(Get-ChildItem -LiteralPath $script:fakeState -File).Count | Should -Be 1
        ($output | Out-String) | Should -Match '1 of 5 runtime volumes already exist'
    }

    It 'requires the exact typed project and explicit volume-destruction flag' {
        $null = & bash (Join-Path $script:runtimeRoot 'init.sh') 2>&1
        $output = @(& bash (Join-Path $script:runtimeRoot 'destroy.sh') `
                --confirm-project wrong-project --destroy-volumes 2>&1)
        $LASTEXITCODE | Should -Be 64
        @(Get-ChildItem -LiteralPath $script:fakeState -File).Count | Should -Be 5
        ($output | Out-String) | Should -Match 'did not exactly match'
        (Get-Content -LiteralPath $script:fakeLog -Raw) |
            Should -Not -Match '(?m)^volume rm '
    }

    It 'refuses deletion when any exact volume remains attached' {
        $null = & bash (Join-Path $script:runtimeRoot 'init.sh') 2>&1
        $env:HH_FAKE_ATTACHED = 'attached-container-id'
        $output = @(& bash (Join-Path $script:runtimeRoot 'destroy.sh') `
                --confirm-project $script:project --destroy-volumes 2>&1)
        $LASTEXITCODE | Should -Be 74
        @(Get-ChildItem -LiteralPath $script:fakeState -File).Count | Should -Be 5
        ($output | Out-String) | Should -Match 'remains attached'
    }

    It 'removes and verifies only the exact five preflighted project volumes' {
        $null = & bash (Join-Path $script:runtimeRoot 'init.sh') 2>&1
        $output = @(& bash (Join-Path $script:runtimeRoot 'destroy.sh') `
                --confirm-project $script:project --destroy-volumes 2>&1)
        $LASTEXITCODE | Should -Be 0
        @(Get-ChildItem -LiteralPath $script:fakeState -File).Count | Should -Be 0
        ($output | Out-String) | Should -Match 'verified absence'
        $removeLines = @(Get-Content -LiteralPath $script:fakeLog |
                Where-Object { $_ -like 'volume rm *' })
        $removeLines.Count | Should -Be 1
        foreach ($name in $script:volumeNames) {
            $removeLines[0] | Should -Match ([regex]::Escape($name))
        }
    }

    It 'reports a non-atomic partial deletion and the exact survivor for rerun' {
        $null = & bash (Join-Path $script:runtimeRoot 'init.sh') 2>&1
        $env:HH_FAKE_FAIL_REMOVE_NAME = $script:volumeNames[2]
        $output = @(& bash (Join-Path $script:runtimeRoot 'destroy.sh') `
                --confirm-project $script:project --destroy-volumes 2>&1)
        $LASTEXITCODE | Should -Be 74
        @(Get-ChildItem -LiteralPath $script:fakeState -File).Count | Should -Be 1
        Test-Path -LiteralPath (Join-Path $script:fakeState $script:volumeNames[2]) |
            Should -BeTrue
        ($output | Out-String) | Should -Match 'Partial runtime-volume lifecycle'
        ($output | Out-String) | Should -Match ([regex]::Escape($script:volumeNames[2]))
        ($output | Out-String) | Should -Match 'No file-level provider cleanup'
    }

    It 'rejects a correctly named volume with the wrong ownership label' {
        for ($index = 0; $index -lt $script:roles.Count; $index++) {
            $project = if ($index -eq 4) { 'another-project' } else { $script:project }
            [IO.File]::WriteAllText(
                (Join-Path $script:fakeState $script:volumeNames[$index]),
                "$project|$($script:roles[$index])`n"
            )
        }
        $output = @(& bash (Join-Path $script:runtimeRoot 'doctor.sh') 2>&1)
        $LASTEXITCODE | Should -Be 1
        ($output | Out-String) | Should -Match 'ownership validation failed'
    }
}
