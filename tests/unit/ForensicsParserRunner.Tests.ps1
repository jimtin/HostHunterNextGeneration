BeforeAll {
    $sourceRoot = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
        Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration'
    }
    else { $env:HH_TEST_SOURCE_ROOT }
    . (Join-Path $sourceRoot 'Forensics/Private/Contracts/StrictJsonValidator.ps1')
    $script:parserPath = Join-Path $sourceRoot 'Forensics/Private/Parser/EvtxDump.ps1'
    . $script:parserPath
    $script:sourceIdentity = 'a' * 64
    function Get-HHTestJsonlStream {
        param([Parameter(Mandatory)][byte[]]$Bytes)
        return [IO.MemoryStream]::new($Bytes, $false)
    }
}

Describe 'Strict bounded JSONL streaming' -Tag Unit {
    It 'streams CRLF and final unterminated records without a plaintext file' {
        $text = "`r`n{`"Event`":{}}`r`n{`"Event`":{}}"
        $stream = Get-HHTestJsonlStream -Bytes ([Text.Encoding]::UTF8.GetBytes($text))
        try {
            $records = @(Read-HHForensicsJsonlRecord -Stream $stream `
                    -SourceIdentity $script:sourceIdentity)
        }
        finally { $stream.Dispose() }
        $records.Count | Should -Be 2
        $records[0].Marker | Should -BeExactly 'HostHunter.Forensics.JsonlRecord.v2'
        $records.SourceOrdinal | Should -Be @(2, 3)
        $records.SourceIdentity | Select-Object -Unique | Should -BeExactly $script:sourceIdentity
        $records[0].Original | Should -BeExactly '{"Event":{}}'
    }

    It 'rejects invalid UTF-8, duplicate properties, non-object roots, and absent Event roots' {
        $invalidUtf8 = [byte[]](123, 34, 69, 118, 101, 110, 116, 34, 58, 34, 255, 34, 125)
        { ConvertFrom-HHForensicsJsonLine -Bytes $invalidUtf8 -SourceOrdinal 1 `
                -SourceIdentity $script:sourceIdentity } | Should -Throw '*strict JSON*'
        foreach ($json in @(
                '{"Event":{},"Event":{}}',
                '{"Event":{"x":{"a":1,"a":2}}}',
                '[]',
                '{"Event":"scalar"}',
                '{"Other":{}}'
            )) {
            $bytes = [Text.Encoding]::UTF8.GetBytes($json)
            { ConvertFrom-HHForensicsJsonLine -Bytes $bytes -SourceOrdinal 1 `
                    -SourceIdentity $script:sourceIdentity } | Should -Throw
        }
    }

    It 'rejects depth, decoded string, line, and total byte limits before unbounded allocation' {
        $deep = [Text.Encoding]::UTF8.GetBytes('{"Event":{"a":{"b":{}}}}')
        { ConvertFrom-HHForensicsJsonLine -Bytes $deep -SourceOrdinal 1 `
                -SourceIdentity $script:sourceIdentity -MaximumJsonDepth 2 } |
            Should -Throw '*depth limit*'
        $longString = [Text.Encoding]::UTF8.GetBytes('{"Event":{"value":"12345"}}')
        { ConvertFrom-HHForensicsJsonLine -Bytes $longString -SourceOrdinal 1 `
                -SourceIdentity $script:sourceIdentity -MaximumStringBytes 4 } |
            Should -Throw '*string limit*'

        $stream = Get-HHTestJsonlStream -Bytes $longString
        try {
            { @(Read-HHForensicsJsonlRecord -Stream $stream `
                        -SourceIdentity $script:sourceIdentity -MaximumLineBytes 8) } |
                Should -Throw '*line exceeds*'
        }
        finally { $stream.Dispose() }
        $stream = Get-HHTestJsonlStream -Bytes $longString
        try {
            { @(Read-HHForensicsJsonlRecord -Stream $stream `
                        -SourceIdentity $script:sourceIdentity -MaximumTotalBytes 8) } |
                Should -Throw '*total byte limit*'
        }
        finally { $stream.Dispose() }
    }

    It 'rejects malformed JSON grammar and invalid escapes' {
        foreach ($json in @(
                '{"Event":{"n":01}}',
                '{"Event":{"n":1.}}',
                '{"Event":{"n":1e}}',
                '{"Event":{"x":"\q"}}',
                '{"Event":{"x":"\uD800"}}',
                '{"Event":{}} trailing'
            )) {
            { ConvertFrom-HHForensicsJsonLine `
                    -Bytes ([Text.Encoding]::UTF8.GetBytes($json)) -SourceOrdinal 1 `
                    -SourceIdentity $script:sourceIdentity } | Should -Throw '*strict JSON*'
        }
    }
}

Describe 'Native parser process containment' -Tag Unit -Skip:(
    [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
) {
    BeforeEach {
        $script:evidencePath = Join-Path $TestDrive 'evidence.evtx'
        [IO.File]::WriteAllBytes($script:evidencePath, [byte[]](1, 2, 3))
        $script:evidenceIdentity = Get-HHForensicsFileIdentity -Path $script:evidencePath
        $script:records = [Collections.Generic.List[object]]::new()
    }

    It 'builds the fixed macOS sandbox plan without embedding evidence paths in policy' {
        $plan = Get-HHForensicsParserLaunchPlan -Executable '/private/tmp/parser' `
            -ArgumentList @('-t', '1', '-o', 'jsonl', '/private/tmp/evidence.evtx') `
            -MacOSPlatformOverride $true -SandboxExecutable '/usr/bin/printf'

        $plan.Executable | Should -BeExactly '/usr/bin/printf'
        $plan.ArgumentList[0] | Should -BeExactly '-p'
        $plan.ArgumentList[2] | Should -BeExactly '/private/tmp/parser'
        $plan.ArgumentList[-1] | Should -BeExactly '/private/tmp/evidence.evtx'
        $plan.ArgumentList[1] | Should -Match '\(deny network\*\)'
        $plan.ArgumentList[1] | Should -Match '\(deny process-fork\)'
        $plan.ArgumentList[1] | Should -Match '\(deny mach-lookup\)'
        $plan.ArgumentList[1] | Should -Not -Match 'parser|evidence'
        $plan.IsolationProfile.ReleaseQualified | Should -BeTrue
        $plan.IsolationProfile.CpuLimit | Should -BeTrue
        $plan.IsolationProfile.MemoryLimit | Should -BeTrue
        $plan.IsolationProfile.NetworkIsolation | Should -BeTrue
    }

    It 'rejects a non-file macOS sandbox launcher' {
        {
            Get-HHForensicsParserLaunchPlan -Executable '/private/tmp/parser' `
                -ArgumentList @('-t', '1') -MacOSPlatformOverride $true `
                -SandboxExecutable $TestDrive
        } | Should -Throw '*not a regular file*'
    }

    It 'retains the explicit unqualified profile outside macOS' {
        $plan = Get-HHForensicsParserLaunchPlan -Executable '/usr/bin/printf' `
            -ArgumentList @('%s', 'value') -MacOSPlatformOverride $false
        $plan.Executable | Should -BeExactly '/usr/bin/printf'
        $plan.ArgumentList | Should -Be @('%s', 'value')
        $plan.IsolationProfile.ReleaseQualified | Should -BeFalse
    }

    It 'kills a child that crosses the working-set limit' {
        $startInfo = [Diagnostics.ProcessStartInfo]::new('/usr/bin/sleep')
        [void]$startInfo.ArgumentList.Add('30')
        $child = [Diagnostics.Process]::Start($startInfo)
        try {
            {
                Assert-HHForensicsParserResourceBound -Process $child `
                    -MaximumWorkingSetBytes 1 -MaximumCpuSeconds 30
            } | Should -Throw '*working-set limit*'
            $child.HasExited | Should -BeTrue
        }
        finally {
            if (-not $child.HasExited) { $child.Kill($true); $child.WaitForExit() }
            $child.Dispose()
        }
    }

    It 'kills a child that crosses the CPU-time limit' {
        $startInfo = [Diagnostics.ProcessStartInfo]::new('/usr/bin/dash')
        [void]$startInfo.ArgumentList.Add('-c')
        [void]$startInfo.ArgumentList.Add('while :; do :; done')
        $child = [Diagnostics.Process]::Start($startInfo)
        try {
            $deadline = [DateTimeOffset]::UtcNow.AddSeconds(5)
            do {
                Start-Sleep -Milliseconds 50
                $child.Refresh()
                $cpuTime = $child.TotalProcessorTime
            } while (($null -eq $cpuTime -or $cpuTime.TotalSeconds -le 1) -and
                [DateTimeOffset]::UtcNow -lt $deadline)
            {
                Assert-HHForensicsParserResourceBound -Process $child `
                    -MaximumWorkingSetBytes 1073741824 -MaximumCpuSeconds 1
            } | Should -Throw '*CPU-time limit*'
            $child.HasExited | Should -BeTrue
        }
        finally {
            if (-not $child.HasExited) { $child.Kill($true); $child.WaitForExit() }
            $child.Dispose()
        }
    }

    It 'rejects an invalid isolation launch plan before starting a process' {
        $executable = '/usr/bin/printf'
        $parserIdentity = Get-HHForensicsFileIdentity -Path $executable
        {
            Invoke-HHForensicsNativeParserProcess -Executable $executable `
                -ArgumentList @('%s', '{"Event":{}}') `
                -ParserIdentity $parserIdentity `
                -EvidenceIdentity $script:evidenceIdentity -TimeoutSeconds 5 `
                -RecordConsumer { param($Record) [void]$Record } `
                -LaunchPlanner { [pscustomobject]@{} }
        } | Should -Throw '*invalid launch plan*'

        {
            Invoke-HHForensicsNativeParserProcess -Executable $executable `
                -ArgumentList @('%s', '{"Event":{}}') `
                -ParserIdentity $parserIdentity `
                -EvidenceIdentity $script:evidenceIdentity -TimeoutSeconds 5 `
                -RecordConsumer { param($Record) [void]$Record } `
                -LaunchPlanner { $null }
        } | Should -Throw '*invalid launch plan*'
    }

    It 'uses discrete argv and streams one valid record with consumer backpressure' {
        $executable = '/usr/bin/printf'
        $parserIdentity = Get-HHForensicsFileIdentity -Path $executable
        $json = '{"Event":{}}'
        # Keep the callback independent of the instrumented module session;
        # the parser supervisor owns and monitors its separate runspace.
        $consumer = [scriptblock]::Create(
            'param($Record) [Threading.Thread]::Sleep(50)'
        )
        $result = Invoke-HHForensicsNativeParserProcess -Executable $executable `
            -ArgumentList @('%s\n', $json) -ParserIdentity $parserIdentity `
            -EvidenceIdentity $script:evidenceIdentity -TimeoutSeconds 5 `
            -RecordConsumer $consumer
        $result.ExitCode | Should -Be 0
        $result.TimedOut | Should -BeFalse
        $result.Records | Should -Be 1
        $result.IsolationProfile.ReleaseQualified | Should -BeFalse

        $source = Get-Content -LiteralPath $script:parserPath -Raw
        $source | Should -Match 'ArgumentList\.Add'
        $source | Should -Not -Match 'ReadToEnd|OutputPath|StandardOutput\.ReadToEnd'
    }

    It 'consumes a final unterminated native JSON observation' {
        $executable = '/usr/bin/printf'
        $parserIdentity = Get-HHForensicsFileIdentity -Path $executable
        $recordPath = Join-Path $TestDrive 'unterminated-record.txt'
        $escapedRecordPath = $recordPath.Replace("'", "''")
        $consumer = [scriptblock]::Create(
            "param(`$Record) [IO.File]::WriteAllText('$escapedRecordPath', `$Record.Original)"
        )
        $result = Invoke-HHForensicsNativeParserProcess -Executable $executable `
            -ArgumentList @('%s', '{"Event":{}}') -ParserIdentity $parserIdentity `
            -EvidenceIdentity $script:evidenceIdentity -TimeoutSeconds 5 `
            -RecordConsumer $consumer
        $result.Records | Should -Be 1
        [IO.File]::ReadAllText($recordPath) | Should -BeExactly '{"Event":{}}'
    }

    It 'bounds and drains stderr without retaining a flood' {
        $executable = '/usr/bin/dash'
        $parserIdentity = Get-HHForensicsFileIdentity -Path $executable
        $command = "printf 'abcdefghijk' >&2; printf '%s\n' '{`"Event`":{}}'"
        $consumer = [scriptblock]::Create('param($Record) [void]$Record')
        $result = Invoke-HHForensicsNativeParserProcess -Executable $executable `
            -ArgumentList @('-c', $command) -ParserIdentity $parserIdentity `
            -EvidenceIdentity $script:evidenceIdentity -TimeoutSeconds 5 `
            -MaximumStderrBytes 4 -RecordConsumer $consumer
        $result.Stderr | Should -BeExactly 'abcd'
        $result.StderrTruncated | Should -BeTrue
        $result.Records | Should -Be 1
    }

    It 'handles CRLF records and both bounded stderr acceptance outcomes' {
        $executable = '/usr/bin/dash'
        $parserIdentity = Get-HHForensicsFileIdentity -Path $executable
        $recordPath = Join-Path $TestDrive 'crlf-record.json'
        $escapedRecordPath = $recordPath.Replace("'", "''")
        $consumer = [scriptblock]::Create(
            "param(`$Record) [IO.File]::WriteAllText('$escapedRecordPath', `$Record.Original)"
        )
        $command = "printf 'ok' >&2; printf '\r\n%s\r\n' '{`"Event`":{}}'"
        $result = Invoke-HHForensicsNativeParserProcess -Executable $executable `
            -ArgumentList @('-c', $command) -ParserIdentity $parserIdentity `
            -EvidenceIdentity $script:evidenceIdentity -TimeoutSeconds 5 `
            -MaximumStderrBytes 16 -RecordConsumer $consumer
        $result.Stderr | Should -BeExactly 'ok'
        $result.StderrTruncated | Should -BeFalse
        $result.Records | Should -Be 2
        [IO.File]::ReadAllText($recordPath) | Should -BeExactly '{"Event":{}}'

        $command = "i=0; while [ `$i -lt 10000 ]; do printf x >&2; i=`$((i+1)); done; " +
            "printf '%s\n' '{`"Event`":{}}'"
        $result = Invoke-HHForensicsNativeParserProcess -Executable $executable `
            -ArgumentList @('-c', $command) -ParserIdentity $parserIdentity `
            -EvidenceIdentity $script:evidenceIdentity -TimeoutSeconds 5 `
            -MaximumStderrBytes 1 -RecordConsumer {
                param($Record)
                [void]$Record
            }
        $result.Stderr | Should -BeExactly 'x'
        $result.StderrTruncated | Should -BeTrue
    }

    It 'ignores consumer output' {
        $executable = '/usr/bin/printf'
        $parserIdentity = Get-HHForensicsFileIdentity -Path $executable
        $result = Invoke-HHForensicsNativeParserProcess -Executable $executable `
            -ArgumentList @('%s\n', '{"Event":{}}') -ParserIdentity $parserIdentity `
            -EvidenceIdentity $script:evidenceIdentity -TimeoutSeconds 5 `
            -RecordConsumer { param($Record) $Record.Marker }
        $result.ExitCode | Should -Be 0
        $result.Records | Should -Be 1
    }

    # An escaping ErrorRecord created in the deliberately isolated consumer
    # runspace carries that runspace's command-resolution context into the
    # caller's finally block. The ordinary and statement-coverage lanes still
    # execute this real boundary; branch probes cannot safely be injected into
    # that escaping context without changing the behavior under test.
    It 'fails closed on consumer errors' `
        -Skip:(-not [string]::IsNullOrWhiteSpace($env:HH_BRANCH_LOG)) {
        $executable = '/usr/bin/printf'
        $parserIdentity = Get-HHForensicsFileIdentity -Path $executable
        {
            Invoke-HHForensicsNativeParserProcess -Executable $executable `
                -ArgumentList @('%s\n', '{"Event":{}}') -ParserIdentity $parserIdentity `
                -EvidenceIdentity $script:evidenceIdentity -TimeoutSeconds 5 `
                -RecordConsumer { throw 'consumer rejected record' }
        } | Should -Throw '*consumer rejected record*'
    }

    It 'treats process-tree termination as idempotent after child exit' {
        $child = [Diagnostics.Process]::Start('/usr/bin/true')
        try {
            $child.WaitForExit()
            { Invoke-HHForensicsParserTreeTermination -Process $child } |
                Should -Not -Throw
        }
        finally { $child.Dispose() }
    }

    It 'tree-kills and reaps a parser and its descendant on timeout' {
        $executable = '/usr/bin/dash'
        $parserIdentity = Get-HHForensicsFileIdentity -Path $executable
        $pidPath = Join-Path $TestDrive 'child.pid'
        $command = "sleep 30 & echo `$! > '$pidPath'; wait"
        $result = Invoke-HHForensicsNativeParserProcess -Executable $executable `
            -ArgumentList @('-c', $command) -ParserIdentity $parserIdentity `
            -EvidenceIdentity $script:evidenceIdentity -TimeoutSeconds 1 `
            -ReapTimeoutSeconds 3 -RecordConsumer { throw 'no records expected' }
        $result.TimedOut | Should -BeTrue
        $childPid = [int]([IO.File]::ReadAllText($pidPath).Trim())
        { [Diagnostics.Process]::GetProcessById($childPid) } | Should -Throw
    }

    It 'bounds a process that closes both streams but keeps running' {
        $executable = '/usr/bin/dash'
        $parserIdentity = Get-HHForensicsFileIdentity -Path $executable
        $result = Invoke-HHForensicsNativeParserProcess -Executable $executable `
            -ArgumentList @('-c', 'exec 1>&- 2>&-; sleep 30') `
            -ParserIdentity $parserIdentity -EvidenceIdentity $script:evidenceIdentity `
            -TimeoutSeconds 1 -ReapTimeoutSeconds 3 `
            -RecordConsumer { throw 'no records expected' }
        $result.TimedOut | Should -BeTrue
    }

    # The branch collector instruments the function that owns and stops this
    # deliberately stalled runspace. Stopping that runspace also invalidates
    # collector commands in Pester's instrumented session. The ordinary unit
    # and Pester statement-coverage passes still execute this real timeout.
    It 'bounds a stalled record consumer and reaps the still-writing parser' `
        -Skip:(-not [string]::IsNullOrWhiteSpace($env:HH_BRANCH_LOG)) {
        $executable = '/usr/bin/dash'
        $parserIdentity = Get-HHForensicsFileIdentity -Path $executable
        $pidPath = Join-Path $TestDrive 'consumer-stall.pid'
        $command = "echo `$`$ > '$pidPath'; while :; do " +
            "printf '%s\n' '{`"Event`":{}}'; printf 'diagnostic' >&2; done"
        $watch = [Diagnostics.Stopwatch]::StartNew()
        $result = Invoke-HHForensicsNativeParserProcess -Executable $executable `
            -ArgumentList @('-c', $command) -ParserIdentity $parserIdentity `
            -EvidenceIdentity $script:evidenceIdentity -TimeoutSeconds 1 `
            -ReapTimeoutSeconds 3 -RecordConsumer { Start-Sleep -Seconds 30 }
        $watch.Stop()
        $result.TimedOut | Should -BeTrue
        $watch.Elapsed.TotalSeconds | Should -BeLessThan 5
        $parserPid = [int]([IO.File]::ReadAllText($pidPath).Trim())
        { [Diagnostics.Process]::GetProcessById($parserPid) } | Should -Throw
    }

    It 'kills a real child flood when total output is exceeded' {
        $executable = '/usr/bin/dash'
        $parserIdentity = Get-HHForensicsFileIdentity -Path $executable
        $command = "while :; do printf '%s\n' '{`"Event`":{}}'; done"
        {
            Invoke-HHForensicsNativeParserProcess -Executable $executable `
                -ArgumentList @('-c', $command) -ParserIdentity $parserIdentity `
                -EvidenceIdentity $script:evidenceIdentity -TimeoutSeconds 5 `
                -MaximumOutputBytes 128 -RecordConsumer { param($Record) [void]$Record }
        } | Should -Throw '*total byte limit*'
    }

    It 'kills a real endless-line child when line bytes are exceeded' {
        $executable = '/usr/bin/dash'
        $parserIdentity = Get-HHForensicsFileIdentity -Path $executable
        $command = "while :; do printf 'xxxxxxxxxxxxxxxx'; done"
        {
            Invoke-HHForensicsNativeParserProcess -Executable $executable `
                -ArgumentList @('-c', $command) -ParserIdentity $parserIdentity `
                -EvidenceIdentity $script:evidenceIdentity -TimeoutSeconds 5 `
                -MaximumLineBytes 64 -MaximumOutputBytes 1048576 `
                -RecordConsumer { param($Record) [void]$Record }
        } | Should -Throw '*line exceeds*'
    }
}

Describe 'EVTX parser staging orchestration' -Tag Unit {
    BeforeEach {
        $script:parserSource = Join-Path $TestDrive 'evtx_dump'
        $script:evidenceSource = Join-Path $TestDrive 'evidence.evtx'
        [IO.File]::WriteAllText($script:parserSource, 'parser bytes')
        [IO.File]::WriteAllBytes($script:evidenceSource, [byte[]](1, 2, 3))
        $parserHash = (Get-FileHash -LiteralPath $script:parserSource -Algorithm SHA256).Hash
        $script:evidenceHash = (Get-FileHash -LiteralPath $script:evidenceSource -Algorithm SHA256).Hash
        $script:descriptor = Resolve-HHForensicsEvtxParser -Path $script:parserSource `
            -RuntimeIdentifier linux-x64 -ExpectedSha256 $parserHash `
            -VersionInvoker { 'evtx_dump 0.12.2' }
    }

    It 'uses run-private staged copies and leaves no plaintext JSONL artifact' {
        $script:stagedPaths = $null
        $result = Invoke-HHForensicsEvtxParser -EvidencePath $script:evidenceSource `
            -ExpectedEvidenceSha256 $script:evidenceHash -Parser $script:descriptor `
            -RecordConsumer { param($Record) [void]$Record } -ProcessInvoker {
                param(
                    $Executable, $ArgumentList, $ParserIdentity, $EvidenceIdentity,
                    $RecordConsumer, $TimeoutSeconds, $MaximumLineBytes,
                    $MaximumOutputBytes, $MaximumStderrBytes, $MaximumJsonDepth,
                    $MaximumStringBytes
                )
                [void]@(
                    $RecordConsumer, $TimeoutSeconds, $MaximumLineBytes,
                    $MaximumOutputBytes, $MaximumStderrBytes, $MaximumJsonDepth,
                    $MaximumStringBytes
                )
                $script:stagedPaths = @($Executable, $ArgumentList[4])
                $ParserIdentity.Sha256 | Should -BeExactly $script:descriptor.Sha256
                $EvidenceIdentity.Sha256 | Should -BeExactly $script:evidenceHash.ToLowerInvariant()
                [pscustomobject]@{
                    ExitCode = 0; TimedOut = $false; Records = 0; OutputBytes = 0
                    Stderr = ''; StderrTruncated = $false
                    IsolationProfile = Get-HHForensicsParserIsolationProfile
                }
            }
        $result.PlaintextOutputArtifact | Should -BeFalse
        $result.EvidenceIdentity.Path | Should -BeExactly $script:evidenceSource
        $script:stagedPaths | ForEach-Object { Test-Path -LiteralPath $_ | Should -BeFalse }
    }

    It 'detects original parser and evidence swaps after staged execution' {
        {
            Invoke-HHForensicsEvtxParser -EvidencePath $script:evidenceSource `
                -ExpectedEvidenceSha256 $script:evidenceHash -Parser $script:descriptor `
                -RecordConsumer { param($Record) [void]$Record } -ProcessInvoker {
                    [IO.File]::AppendAllText($script:parserSource, 'swap')
                    [pscustomobject]@{
                        ExitCode = 0; TimedOut = $false; Records = 0; OutputBytes = 0
                        Stderr = ''; StderrTruncated = $false
                        IsolationProfile = Get-HHForensicsParserIsolationProfile
                    }
                }
        } | Should -Throw '*digest does not match*'

        [IO.File]::WriteAllText($script:parserSource, 'parser bytes')
        $parserHash = (Get-FileHash -LiteralPath $script:parserSource -Algorithm SHA256).Hash
        $script:descriptor = Resolve-HHForensicsEvtxParser -Path $script:parserSource `
            -RuntimeIdentifier linux-x64 -ExpectedSha256 $parserHash `
            -VersionInvoker { 'evtx_dump 0.12.2' }
        {
            Invoke-HHForensicsEvtxParser -EvidencePath $script:evidenceSource `
                -ExpectedEvidenceSha256 $script:evidenceHash -Parser $script:descriptor `
                -RecordConsumer { param($Record) [void]$Record } -ProcessInvoker {
                    [IO.File]::AppendAllText($script:evidenceSource, 'swap')
                    [pscustomobject]@{
                        ExitCode = 0; TimedOut = $false; Records = 0; OutputBytes = 0
                        Stderr = ''; StderrTruncated = $false
                        IsolationProfile = Get-HHForensicsParserIsolationProfile
                    }
                }
        } | Should -Throw '*digest does not match*'
    }

    It 'rejects malformed identities and every invalid bounded process result' {
        $badIdentity = $script:descriptor.FileIdentity.PSObject.Copy()
        $badIdentity.Marker = 'untrusted'
        { Assert-HHForensicsFileIdentity -Identity $badIdentity } |
            Should -Throw '*identity is malformed*'

        $changedIdentity = $script:descriptor.FileIdentity.PSObject.Copy()
        $changedIdentity.Length++
        { Assert-HHForensicsFileIdentity -Identity $changedIdentity } |
            Should -Throw '*identity changed*'

        $badDescriptor = $script:descriptor.PSObject.Copy()
        $badDescriptor.Marker = 'untrusted'
        { Invoke-HHForensicsEvtxParser -EvidencePath $script:evidenceSource `
                -ExpectedEvidenceSha256 $script:evidenceHash -Parser $badDescriptor `
                -RecordConsumer { param($Record) [void]$Record } } |
            Should -Throw '*not an approved*'

        { Invoke-HHForensicsEvtxParser -EvidencePath $script:evidenceSource `
                -ExpectedEvidenceSha256 $script:evidenceHash -Parser $script:descriptor `
                -MaximumEvidenceBytes 2 -RecordConsumer { param($Record) [void]$Record } } |
            Should -Throw '*input limit*'

        $invalidResults = @(
            @{ Result = $null; Pattern = '*invalid bounded-execution result*' },
            @{ Result = [pscustomobject]@{ TimedOut = $true }; Pattern = '*bounded execution timeout*' },
            @{
                Result = [pscustomobject]@{
                    TimedOut = $false; ExitCode = 7; Stderr = 'failure'
                    StderrTruncated = $false
                }
                Pattern = '*exit code 7: failure'
            },
            @{
                Result = [pscustomobject]@{
                    TimedOut = $false; ExitCode = 8; Stderr = 'flood'
                    StderrTruncated = $true
                }
                Pattern = '*stderr truncated*'
            }
        )
        foreach ($case in $invalidResults) {
            $script:fakeProcessResult = $case.Result
            { Invoke-HHForensicsEvtxParser -EvidencePath $script:evidenceSource `
                    -ExpectedEvidenceSha256 $script:evidenceHash -Parser $script:descriptor `
                    -RecordConsumer { param($Record) [void]$Record } -ProcessInvoker {
                        $script:fakeProcessResult
                    } } | Should -Throw $case.Pattern
        }
    }

    It 'uses an admitted staging root and detects a changed source during staging' {
        $stagingParent = Join-Path $TestDrive 'staging-parent'
        [IO.Directory]::CreateDirectory($stagingParent) | Out-Null
        $script:capturedStagingPath = $null
        $result = Invoke-HHForensicsEvtxParser -EvidencePath $script:evidenceSource `
            -ExpectedEvidenceSha256 $script:evidenceHash -Parser $script:descriptor `
            -StagingRoot $stagingParent `
            -RecordConsumer { param($Record) [void]$Record } -ProcessInvoker {
                param($Executable)
                $script:capturedStagingPath = $Executable
                [pscustomobject]@{
                    ExitCode = 0; TimedOut = $false; Records = 0; OutputBytes = 0
                    Stderr = ''; StderrTruncated = $false
                    IsolationProfile = Get-HHForensicsParserIsolationProfile
                }
            }
        $result.Marker | Should -BeExactly 'HostHunter.Forensics.ParserResult.v2'
        $script:capturedStagingPath | Should -BeLike "$stagingParent/*/evtx_dump"

        $changedIdentity = $script:descriptor.FileIdentity.PSObject.Copy()
        $changedIdentity.Length++
        $destination = Join-Path $stagingParent 'must-not-be-admitted'
        { Copy-HHForensicsFileToPrivateStage -SourceIdentity $changedIdentity `
                -DestinationPath $destination } | Should -Throw '*changed while it was copied*'
    }

    It 'keeps cleanup idempotent when the process removes its staged run directory' {
        $result = Invoke-HHForensicsEvtxParser -EvidencePath $script:evidenceSource `
            -ExpectedEvidenceSha256 $script:evidenceHash -Parser $script:descriptor `
            -RecordConsumer { param($Record) [void]$Record } -ProcessInvoker {
                param($Executable)
                $runRoot = [IO.Path]::GetDirectoryName($Executable)
                [IO.Directory]::Delete($runRoot, $true)
                [pscustomobject]@{
                    ExitCode = 0; TimedOut = $false; Records = 0; OutputBytes = 0
                    Stderr = ''; StderrTruncated = $false
                    IsolationProfile = Get-HHForensicsParserIsolationProfile
                }
            }
        $result.PlaintextOutputArtifact | Should -BeFalse
    }
}

Describe 'Packaged native macOS parser sandbox qualification' -Tag Unit -Skip:(
    -not [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [Runtime.InteropServices.OSPlatform]::OSX
    ) -or [string]::IsNullOrWhiteSpace($env:HH_TEST_MODULE_PATH)
) {
    It 'denies network, sensitive reads, writes, and forks through the packaged launcher' {
        $qualificationRoot = Join-Path '/private/tmp' (
            'hosthunter-sandbox-qualification-' + [Guid]::NewGuid().ToString('N')
        )
        [IO.Directory]::CreateDirectory($qualificationRoot) | Out-Null
        $probePath = Join-Path $qualificationRoot 'ProbeMacOSSandbox'
        $evidencePath = Join-Path $qualificationRoot 'evidence.evtx'
        $recordPath = Join-Path $qualificationRoot 'record.json'
        $forbiddenWritePath = Join-Path $TestDrive 'sandbox-write-must-fail'
        $probeSource = Join-Path $PSScriptRoot '../fixtures/forensics/helpers/ProbeMacOSSandbox.c'
        $module = $null
        try {
            & /usr/bin/cc '-O2' '-Wall' '-Wextra' $probeSource '-o' $probePath
            if ($LASTEXITCODE -ne 0) { throw "Probe compilation failed with $LASTEXITCODE." }
            [IO.File]::WriteAllBytes($evidencePath, [byte[]](1, 2, 3))
            $module = Import-Module $env:HH_TEST_MODULE_PATH -Force -PassThru
            $escapedRecordPath = $recordPath.Replace("'", "''")
            $consumer = [scriptblock]::Create(
                "param(`$Record) [IO.File]::WriteAllText('$escapedRecordPath', `$Record.Original)"
            )
            $result = & $module {
                param($ProbePath, $EvidencePath, $SensitivePath, $WritePath, $Consumer)
                $parserIdentity = Get-HHForensicsFileIdentity -Path $ProbePath
                $evidenceIdentity = Get-HHForensicsFileIdentity -Path $EvidencePath
                Invoke-HHForensicsNativeParserProcess -Executable $ProbePath `
                    -ArgumentList @($SensitivePath, $WritePath) `
                    -ParserIdentity $parserIdentity -EvidenceIdentity $evidenceIdentity `
                    -TimeoutSeconds 10 -ReapTimeoutSeconds 3 -RecordConsumer $Consumer
            } $probePath $evidencePath $probeSource $forbiddenWritePath $consumer

            $result.ExitCode | Should -Be 0
            $result.TimedOut | Should -BeFalse
            $result.Records | Should -Be 1
            $result.IsolationProfile.Name | Should -BeExactly 'MacOSSandboxExec'
            $result.IsolationProfile.ReleaseQualified | Should -BeTrue
            $observation = [IO.File]::ReadAllText($recordPath) | ConvertFrom-Json
            $observation.Event.NetworkDenied | Should -BeTrue
            $observation.Event.SensitiveReadDenied | Should -BeTrue
            $observation.Event.WriteDenied | Should -BeTrue
            $observation.Event.ForkDenied | Should -BeTrue
            Test-Path -LiteralPath $forbiddenWritePath | Should -BeFalse
        }
        finally {
            if ($null -ne $module) {
                Remove-Module $module -Force -ErrorAction SilentlyContinue
            }
            if ([IO.Directory]::Exists($qualificationRoot)) {
                [IO.Directory]::Delete($qualificationRoot, $true)
            }
            if ([IO.File]::Exists($forbiddenWritePath)) {
                [IO.File]::Delete($forbiddenWritePath)
            }
        }
    }
}
