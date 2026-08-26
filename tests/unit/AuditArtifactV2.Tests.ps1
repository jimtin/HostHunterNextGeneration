BeforeAll {
    $sourceRoot = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
        Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration'
    }
    else { $env:HH_TEST_SOURCE_ROOT }

    . (Join-Path $sourceRoot 'Private/AuditArtifactV2.ps1')

    if ($null -eq ('HHImmediateIOExceptionStream' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.IO;
public sealed class HHImmediateIOExceptionStream : Stream {
    public override bool CanRead => false;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => 0;
    public override long Position { get => 0; set => throw new NotSupportedException(); }
    public override void Flush() { }
    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new IOException("simulated durable storage failure");
}
public sealed class HHFlushIOExceptionStream : Stream {
    public override bool CanRead => false;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => 0;
    public override long Position { get => 0; set => throw new NotSupportedException(); }
    public override void Flush() { }
    public void Flush(bool flushToDisk) => throw new IOException("simulated durable flush failure");
    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) { }
}
public sealed class HHImmediateInvalidOperationStream : Stream {
    public override bool CanRead => false;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => 0;
    public override long Position { get => 0; set => throw new NotSupportedException(); }
    public override void Flush() { }
    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new InvalidOperationException("non-IO write failure");
}
public sealed class HHFlushInvalidOperationStream : Stream {
    public override bool CanRead => false;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => 0;
    public override long Position { get => 0; set => throw new NotSupportedException(); }
    public override void Flush() { }
    public void Flush(bool flushToDisk) => throw new InvalidOperationException("non-IO flush failure");
    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) { }
}
public sealed class HHDurableTestException : IOException {
    public HHDurableTestException(string failureState, string message) : base(message) {
        FailureState = failureState;
    }
    public string FailureState { get; }
}
'@
    }

    function Get-TestWriter {
        param([int]$ChunkSize = 4096)
        Open-HHAuditArtifactV2Writer -DataRoot $script:root -OutputRoot $script:output `
            -RecoveryRoot $script:recovery -DatabaseId $script:databaseId `
            -LedgerId $script:ledgerId -InvocationId $script:invocationId `
            -ArtifactId $script:artifactId -MasterKey $script:key -ChunkSize $ChunkSize
    }

    function Get-TestEvent {
        param([long]$Sequence = 0, [object]$Value = 'hello', [string]$Stream = 'Output')
        [pscustomobject][ordered]@{
            Sequence = $Sequence
            RemoteSequence = $Sequence
            ObservedAtUtc = '2026-08-24T00:00:00.0000000+00:00'
            Phase = 'Command'
            Stream = $Stream
            TypeName = if ($null -eq $Value) { 'null' } else { $Value.GetType().FullName }
            SerializedByteCount = 10
            IsTerminating = $false
            Value = $Value
        }
    }
}

Describe 'streaming audit artifact v2' -Tag Unit {
    BeforeEach {
        $env:HH_COVERAGE_CASE = [Guid]::NewGuid().ToString('N')
        $script:root = Join-Path $TestDrive ([Guid]::NewGuid().ToString('N'))
        $script:output = Join-Path $script:root 'audit/output'
        $script:recovery = Join-Path $script:root 'recovery'
        [IO.Directory]::CreateDirectory($script:root) | Out-Null
        $script:key = [byte[]](0..31)
        $script:databaseId = [byte[]](1..16)
        $script:ledgerId = [byte[]](17..32)
        $script:invocationId = [byte[]](33..48)
        $script:artifactId = [byte[]](49..64)
    }

    It 'streams, publishes, verifies, and returns typed ordered events' {
        $writer = Get-TestWriter
        Write-HHAuditArtifactV2Event -Writer $writer -EventRecord (Get-TestEvent -Value @{ answer = 42 })
        Write-HHAuditArtifactV2Event -Writer $writer -EventRecord (Get-TestEvent -Sequence 1 -Value 'warning' -Stream Warning)
        $receipt = Complete-HHAuditArtifactV2Writer -Writer $writer

        $receipt.FormatVersion | Should -Be 2
        $receipt.StreamEventCount | Should -Be 2
        $receipt.CiphertextSha256.Length | Should -Be 32
        Test-HHAuditArtifactV2 -Path $receipt.Path -DataRoot $script:root `
            -DatabaseId $script:databaseId -LedgerId $script:ledgerId `
            -InvocationId $script:invocationId -ArtifactId $script:artifactId `
            -MasterKey $script:key -ChunkSize 4096 | Should -BeTrue
        Test-HHAuditArtifactV2 -Path $receipt.Path `
            -DatabaseId $script:databaseId -LedgerId $script:ledgerId `
            -InvocationId $script:invocationId -ArtifactId $script:artifactId `
            -MasterKey $script:key -ChunkSize 4096 | Should -BeTrue
        $events = @(Read-HHAuditArtifactV2 -Path $receipt.Path -DatabaseId $script:databaseId `
                -LedgerId $script:ledgerId -InvocationId $script:invocationId `
                -ArtifactId $script:artifactId -MasterKey $script:key -ChunkSize 4096 `
                -ExpectedCiphertextSha256 $receipt.CiphertextSha256 -ExpectedLength $receipt.Bytes)
        $events.Count | Should -Be 2
        $events[0].PSObject.TypeNames | Should -Contain 'HostHunter.AuditStreamEvent'
        $events[0].Value.answer | Should -Be 42
        $events[1].Stream | Should -BeExactly Warning
        $events[1].SerializedValue | Should -Not -BeNullOrEmpty
    }

    It 'fails verification-only recovery checks for missing and tampered artifacts' {
        Test-HHAuditArtifactV2 -Path (Join-Path $script:root 'missing.hhout') `
            -DataRoot $script:root -DatabaseId $script:databaseId -LedgerId $script:ledgerId `
            -InvocationId $script:invocationId -ArtifactId $script:artifactId `
            -MasterKey $script:key -ChunkSize 4096 | Should -BeFalse
        $writer = Get-TestWriter
        Write-HHAuditArtifactV2Event -Writer $writer -EventRecord (Get-TestEvent)
        $receipt = Complete-HHAuditArtifactV2Writer -Writer $writer
        $bytes = [IO.File]::ReadAllBytes($receipt.Path)
        $bytes[90] = $bytes[90] -bxor 1
        [IO.File]::WriteAllBytes($receipt.Path, $bytes)
        Test-HHAuditArtifactV2 -Path $receipt.Path -DataRoot $script:root `
            -DatabaseId $script:databaseId -LedgerId $script:ledgerId `
            -InvocationId $script:invocationId -ArtifactId $script:artifactId `
            -MasterKey $script:key -ChunkSize 4096 | Should -BeFalse
    }

    It 'splits a canonical event across bounded independently authenticated chunks' {
        $writer = Get-TestWriter -ChunkSize 4096
        Write-HHAuditArtifactV2Event -Writer $writer -EventRecord (Get-TestEvent -Value ('x' * 12000))
        $receipt = Complete-HHAuditArtifactV2Writer -Writer $writer
        $receipt.ChunkCount | Should -BeGreaterThan 2
        $events = @(Read-HHAuditArtifactV2 -Path $receipt.Path -DatabaseId $script:databaseId `
                -LedgerId $script:ledgerId -InvocationId $script:invocationId `
                -ArtifactId $script:artifactId -MasterKey $script:key -ChunkSize 4096)
        $events[0].Value.Length | Should -Be 12000
    }

    It 'publishes an authenticated empty artifact' {
        $writer = Get-TestWriter
        $receipt = Complete-HHAuditArtifactV2Writer -Writer $writer
        $receipt.ChunkCount | Should -Be 0
        @(Read-HHAuditArtifactV2 -Path $receipt.Path -DatabaseId $script:databaseId `
                -LedgerId $script:ledgerId -InvocationId $script:invocationId `
                -ArtifactId $script:artifactId -MasterKey $script:key -ChunkSize 4096).Count | Should -Be 0
    }

    It 'quarantines incomplete staging and aborts idempotently' {
        $writer = Get-TestWriter
        Write-HHAuditArtifactV2Event -Writer $writer -EventRecord (Get-TestEvent)
        $temporary = $writer.TemporaryPath
        $quarantine = Abort-HHAuditArtifactV2Writer -Writer $writer
        $quarantine | Should -Exist
        $temporary | Should -Not -Exist
        (Abort-HHAuditArtifactV2Writer -Writer $writer) | Should -BeExactly $quarantine
    }

    It 'rejects identity substitution, wrong keys, changed hashes, and wrong lengths' {
        $writer = Get-TestWriter
        Write-HHAuditArtifactV2Event -Writer $writer -EventRecord (Get-TestEvent)
        $receipt = Complete-HHAuditArtifactV2Writer -Writer $writer
        $wrongId = [byte[]](65..80)
        { Read-HHAuditArtifactV2 -Path $receipt.Path -DatabaseId $script:databaseId `
                -LedgerId $script:ledgerId -InvocationId $wrongId -ArtifactId $script:artifactId `
                -MasterKey $script:key -ChunkSize 4096 } | Should -Throw -ErrorId 'AuditIntegrityFailed,*'
        { Read-HHAuditArtifactV2 -Path $receipt.Path -DatabaseId $script:databaseId `
                -LedgerId $script:ledgerId -InvocationId $script:invocationId -ArtifactId $script:artifactId `
                -MasterKey ([byte[]](80..111)) -ChunkSize 4096 } | Should -Throw -ErrorId 'AuditIntegrityFailed,*'
        { Read-HHAuditArtifactV2 -Path $receipt.Path -DatabaseId $script:databaseId `
                -LedgerId $script:ledgerId -InvocationId $script:invocationId -ArtifactId $script:artifactId `
                -MasterKey $script:key -ChunkSize 4096 -ExpectedCiphertextSha256 ([byte[]]::new(32)) } |
            Should -Throw -ErrorId 'AuditIntegrityFailed,*'
        { Read-HHAuditArtifactV2 -Path $receipt.Path -DatabaseId $script:databaseId `
                -LedgerId $script:ledgerId -InvocationId $script:invocationId -ArtifactId $script:artifactId `
                -MasterKey $script:key -ChunkSize 4096 -ExpectedLength ($receipt.Bytes + 1) } |
            Should -Throw -ErrorId 'AuditIntegrityFailed,*'
    }

    It 'detects chunk tampering, truncation, and trailing bytes before emitting an event' {
        $writer = Get-TestWriter
        Write-HHAuditArtifactV2Event -Writer $writer -EventRecord (Get-TestEvent)
        $receipt = Complete-HHAuditArtifactV2Writer -Writer $writer
        $original = [IO.File]::ReadAllBytes($receipt.Path)
        foreach ($variant in @('tamper', 'truncate', 'append')) {
            $copy = Join-Path $TestDrive "$variant.hhout"
            $bytes = [Collections.Generic.List[byte]]::new($original)
            if ($variant -eq 'tamper') { $bytes[110] = $bytes[110] -bxor 1 }
            elseif ($variant -eq 'truncate') { $bytes.RemoveAt($bytes.Count - 1) }
            else { $bytes.Add(0xff) }
            [IO.File]::WriteAllBytes($copy, $bytes.ToArray())
            $seen = 0
            { @(Read-HHAuditArtifactV2 -Path $copy -DatabaseId $script:databaseId `
                        -LedgerId $script:ledgerId -InvocationId $script:invocationId `
                        -ArtifactId $script:artifactId -MasterKey $script:key -ChunkSize 4096 |
                    ForEach-Object { $seen++ }) } | Should -Throw -ErrorId 'AuditIntegrityFailed,*'
            $seen | Should -Be 0
        }
    }

    It 'rejects duplicate publication, noncontiguous events, invalid event shapes, and identifiers' {
        $writer = Get-TestWriter
        { Write-HHAuditArtifactV2Event -Writer $writer -EventRecord (Get-TestEvent -Sequence 1) } |
            Should -Throw '*sequence*'
        { Write-HHAuditArtifactV2Event -Writer $writer -EventRecord ([pscustomobject]@{ Sequence = 0 }) } |
            Should -Throw '*property*'
        Write-HHAuditArtifactV2Event -Writer $writer -EventRecord (Get-TestEvent)
        Complete-HHAuditArtifactV2Writer -Writer $writer | Out-Null
        { Get-TestWriter } | Should -Throw -ErrorId 'AuditIntegrityFailed,*'
        { Open-HHAuditArtifactV2Writer -DataRoot $script:root -OutputRoot $script:output `
                -RecoveryRoot $script:recovery -DatabaseId ([byte[]]::new(15)) `
                -LedgerId $script:ledgerId -InvocationId $script:invocationId `
                -ArtifactId $script:artifactId -MasterKey $script:key -ChunkSize 4096 } |
            Should -Throw '*16 bytes*'
    }

    It 'rejects paths outside the data root and linked artifact directories' -Skip:$IsWindows {
        { Open-HHAuditArtifactV2Writer -DataRoot $script:root -OutputRoot (Join-Path $TestDrive 'outside') `
                -RecoveryRoot $script:recovery -DatabaseId $script:databaseId -LedgerId $script:ledgerId `
                -InvocationId $script:invocationId -ArtifactId $script:artifactId `
                -MasterKey $script:key -ChunkSize 4096 } | Should -Throw -ErrorId 'PersistencePathUnsafe,*'

        $real = Join-Path $script:root 'real-output'
        [IO.Directory]::CreateDirectory($real) | Out-Null
        $link = Join-Path $script:root 'linked-output'
        New-Item -ItemType SymbolicLink -Path $link -Target $real | Out-Null
        { Open-HHAuditArtifactV2Writer -DataRoot $script:root -OutputRoot $link `
                -RecoveryRoot $script:recovery -DatabaseId $script:databaseId -LedgerId $script:ledgerId `
                -InvocationId $script:invocationId -ArtifactId $script:artifactId `
                -MasterKey $script:key -ChunkSize 4096 } | Should -Throw -ErrorId 'PersistencePathUnsafe,*'
    }

    It 'returns stable unavailable and argument errors' {
        { Read-HHAuditArtifactV2 -Path (Join-Path $TestDrive 'missing.hhout') `
                -DatabaseId $script:databaseId -LedgerId $script:ledgerId `
                -InvocationId $script:invocationId -ArtifactId $script:artifactId `
                -MasterKey $script:key -ChunkSize 4096 } | Should -Throw -ErrorId 'AuditOutputUnavailable,*'
        { Get-HHAuditArtifactV2Header -DatabaseId $script:databaseId -LedgerId $script:ledgerId `
                -InvocationId $script:invocationId -ArtifactId $script:artifactId -ChunkSize 1 } |
            Should -Throw
    }

    It 'rejects invalid integer, compression, event, and frame primitives' {
        { ConvertFrom-HHAuditArtifactV2UInt64 -Bytes ([byte[]](0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)) -Offset 0 } |
            Should -Throw -ErrorId 'AuditIntegrityFailed,*'

        $compressed = Compress-HHAuditArtifactV2Chunk -Bytes ([Text.Encoding]::UTF8.GetBytes('abcdef'))
        { Expand-HHAuditArtifactV2Chunk -Bytes $compressed -ExpectedLength 2 } |
            Should -Throw -ErrorId 'AuditIntegrityFailed,*'
        { Expand-HHAuditArtifactV2Chunk -Bytes $compressed -ExpectedLength 20 } |
            Should -Throw -ErrorId 'AuditIntegrityFailed,*'
        { Expand-HHAuditArtifactV2Chunk -Bytes ([byte[]](1, 2, 3)) -ExpectedLength 3 } |
            Should -Throw -ErrorId 'AuditIntegrityFailed,*'

        $invalidCounter = Get-TestEvent
        $invalidCounter.SerializedByteCount = -1
        { Get-HHAuditArtifactV2EventFrame -EventRecord $invalidCounter } | Should -Throw '*counters*'
        $invalidTimestamp = Get-TestEvent
        $invalidTimestamp.ObservedAtUtc = 'not-a-timestamp'
        { Get-HHAuditArtifactV2EventFrame -EventRecord $invalidTimestamp } | Should -Throw '*timestamp*'

        $minimalFrame = [Text.Encoding]::UTF8.GetBytes('{"Sequence":0}')
        { ConvertFrom-HHAuditArtifactV2Frame -Bytes $minimalFrame } |
            Should -Throw -ErrorId 'AuditIntegrityFailed,*'
        $negativeFrameJson = '{"Sequence":-1,"RemoteSequence":null,' +
            '"ObservedAtUtc":"2026-08-24T00:00:00Z","Phase":"Command",' +
            '"Stream":"Output","TypeName":"System.String","SerializedByteCount":1,' +
            '"IsTerminating":false,"SerializedValue":"x"}'
        $negativeFrame = [Text.Encoding]::UTF8.GetBytes($negativeFrameJson)
        { ConvertFrom-HHAuditArtifactV2Frame -Bytes $negativeFrame -ExpectedSequence 0 } |
            Should -Throw -ErrorId 'AuditIntegrityFailed,*'
        $timestampFrameJson = '{"Sequence":0,"RemoteSequence":null,' +
            '"ObservedAtUtc":"bad","Phase":"Command","Stream":"Output",' +
            '"TypeName":"System.String","SerializedByteCount":1,' +
            '"IsTerminating":false,"SerializedValue":"x"}'
        $timestampFrame = [Text.Encoding]::UTF8.GetBytes($timestampFrameJson)
        { ConvertFrom-HHAuditArtifactV2Frame -Bytes $timestampFrame } |
            Should -Throw -ErrorId 'AuditIntegrityFailed,*'
    }

    It 'enforces writer lifecycle and canonical capacity before another chunk' {
        $writer = Get-TestWriter
        $writer.PlaintextTotal = 100L * 1024L * 1024L
        { Write-HHAuditArtifactV2Event -Writer $writer -EventRecord (Get-TestEvent) } |
            Should -Throw -ErrorId 'PersistenceCapacityInsufficient,*'
        Abort-HHAuditArtifactV2Writer -Writer $writer | Out-Null
        { Write-HHAuditArtifactV2Event -Writer $writer -EventRecord (Get-TestEvent) } |
            Should -Throw '*not open*'
        { Complete-HHAuditArtifactV2Writer -Writer $writer } | Should -Throw '*not open*'
    }

    It 'cleans a new staging file when private-mode hardening fails' {
        Mock Set-HHAuditArtifactV2PrivateMode {
            param($Path, [switch]$Directory)
            $null = $Path
            if (-not $Directory) { throw 'mode failure' }
        }
        { Get-TestWriter } | Should -Throw '*mode failure*'
        @(Get-ChildItem -LiteralPath $script:output -Filter '*.tmp').Count | Should -Be 0
    }

    It 'marks ordinary finalization and destination collision failures as faulted' {
        $faulted = Get-TestWriter
        $faulted.Stream.Dispose()
        { Complete-HHAuditArtifactV2Writer -Writer $faulted } | Should -Throw
        $faulted.State | Should -BeExactly Faulted
        Abort-HHAuditArtifactV2Writer -Writer $faulted | Should -Exist

        $unknown = Get-TestWriter
        [IO.File]::WriteAllText($unknown.FinalPath, 'collision')
        {
            Complete-HHAuditArtifactV2Writer -Writer $unknown
        } | Should -Throw -ErrorId 'AuditIntegrityFailed,*'
        $unknown.State | Should -BeExactly Faulted
        Abort-HHAuditArtifactV2Writer -Writer $unknown | Should -Exist
    }

    It 'rejects malformed footer and chunk metadata before output' {
        $writer = Get-TestWriter
        Write-HHAuditArtifactV2Event -Writer $writer -EventRecord (Get-TestEvent)
        $receipt = Complete-HHAuditArtifactV2Writer -Writer $writer
        $original = [IO.File]::ReadAllBytes($receipt.Path)
        $footerOffset = $original.Length - 108

        $cases = @(
            @{ Name = 'chunk-marker'; Offset = 0; Value = 0x58 },
            @{ Name = 'chunk-sequence'; Offset = 0; Value = 0x01 },
            @{ Name = 'footer-marker'; Offset = 4; Value = 0x58 },
            @{ Name = 'footer-envelope-length'; Offset = 75; Value = 0xff }
        )
        foreach ($case in $cases) {
            $copy = Join-Path $TestDrive "$($case.Name).hhout"
            $bytes = [byte[]]$original.Clone()
            $base = if ($case.Name -eq 'chunk-marker') { 80 }
            elseif ($case.Name -eq 'chunk-sequence') { 84 }
            else { $footerOffset }
            $bytes[$base + $case.Offset] = [byte]$case.Value
            [IO.File]::WriteAllBytes($copy, $bytes)
            { Read-HHAuditArtifactV2 -Path $copy -DatabaseId $script:databaseId `
                    -LedgerId $script:ledgerId -InvocationId $script:invocationId `
                    -ArtifactId $script:artifactId -MasterKey $script:key -ChunkSize 4096 } |
                Should -Throw -ErrorId 'AuditIntegrityFailed,*'
        }
    }

    It 'detects authenticated footer count disagreement and invalid expected hash shape' {
        $writer = Get-TestWriter
        Write-HHAuditArtifactV2Event -Writer $writer -EventRecord (Get-TestEvent)
        $writer.EventCount = 2
        $receipt = Complete-HHAuditArtifactV2Writer -Writer $writer
        { Read-HHAuditArtifactV2 -Path $receipt.Path -DatabaseId $script:databaseId `
                -LedgerId $script:ledgerId -InvocationId $script:invocationId `
                -ArtifactId $script:artifactId -MasterKey $script:key -ChunkSize 4096 } |
            Should -Throw -ErrorId 'AuditIntegrityFailed,*'
        { Read-HHAuditArtifactV2 -Path $receipt.Path -DatabaseId $script:databaseId `
                -LedgerId $script:ledgerId -InvocationId $script:invocationId `
                -ArtifactId $script:artifactId -MasterKey $script:key -ChunkSize 4096 `
                -ExpectedCiphertextSha256 ([byte[]]::new(31)) } | Should -Throw '*32 bytes*'
    }

    It 'round-trips a null remote sequence and exercises zero-length primitives' {
        $eventRecord = Get-TestEvent
        $eventRecord.RemoteSequence = $null
        $frame = Get-HHAuditArtifactV2EventFrame -EventRecord $eventRecord
        $decoded = ConvertFrom-HHAuditArtifactV2Frame -Bytes $frame -Emit
        $decoded.RemoteSequence | Should -BeNullOrEmpty

        $joined = Join-HHAuditArtifactV2Buffer -Part @()
        $joined.Length | Should -Be 0
        $stream = [IO.MemoryStream]::new([byte[]]::new(0))
        try {
            (Read-HHAuditArtifactV2Exact -Stream $stream -Length 0).Length |
                Should -Be 0
        }
        finally { $stream.Dispose() }
    }

    It 'accepts an authenticated empty compressed chunk and rejects non-string frame time' {
        # Old uncovered outcomes: AuditArtifactV2.ps1 L194 while-not-entered,
        # L613 catch-0, and L618 clause-0.
        $compressed = Compress-HHAuditArtifactV2Chunk -Bytes ([byte[]]::new(0))
        try {
            $expanded = Expand-HHAuditArtifactV2Chunk `
                -Bytes $compressed `
                -ExpectedLength 0
            $expanded.Length | Should -Be 0
        }
        finally { [Array]::Clear($compressed, 0, $compressed.Length) }

        $numericTimestamp = [Text.Encoding]::UTF8.GetBytes(
            '{"Sequence":0,"RemoteSequence":null,"ObservedAtUtc":1,' +
            '"Phase":"Command","Stream":"Output","TypeName":"System.String",' +
            '"SerializedByteCount":1,"IsTerminating":false,"SerializedValue":"x"}'
        )
        { ConvertFrom-HHAuditArtifactV2Frame -Bytes $numericTimestamp } |
            Should -Throw -ErrorId 'AuditIntegrityFailed,*'

        $invalidUtf8 = [byte[]](0xff, 0xfe, 0xfd)
        { ConvertFrom-HHAuditArtifactV2Frame -Bytes $invalidUtf8 } |
            Should -Throw -ErrorId 'AuditIntegrityFailed,*'
    }

    It 'parses canonical timestamps independently of the controller culture' {
        $previousCulture = [Globalization.CultureInfo]::CurrentCulture
        try {
            [Globalization.CultureInfo]::CurrentCulture =
                [Globalization.CultureInfo]::GetCultureInfo('en-AU')
            $eventRecord = Get-TestEvent
            $eventRecord.ObservedAtUtc = '2026-08-25T02:24:01.1234567+00:00'

            $frame = Get-HHAuditArtifactV2EventFrame -EventRecord $eventRecord
            $decoded = ConvertFrom-HHAuditArtifactV2Frame -Bytes $frame -Emit

            $decoded.ObservedAtUtc | Should -Be '2026-08-25T02:24:01.1234567+00:00'
        }
        finally {
            [Globalization.CultureInfo]::CurrentCulture = $previousCulture
        }
    }

    It 'rejects read and verification paths outside the data root or through links' -Skip:$IsWindows {
        $writer = Get-TestWriter
        $receipt = Complete-HHAuditArtifactV2Writer -Writer $writer

        { Read-HHAuditArtifactV2 -Path $receipt.Path -DataRoot (Join-Path $TestDrive 'other-root') `
                -DatabaseId $script:databaseId -LedgerId $script:ledgerId `
                -InvocationId $script:invocationId -ArtifactId $script:artifactId `
                -MasterKey $script:key -ChunkSize 4096 } |
            Should -Throw -ErrorId 'PersistencePathUnsafe,*'
        Test-HHAuditArtifactV2 -Path $receipt.Path -DataRoot (Join-Path $TestDrive 'other-root') `
            -DatabaseId $script:databaseId -LedgerId $script:ledgerId `
            -InvocationId $script:invocationId -ArtifactId $script:artifactId `
            -MasterKey $script:key -ChunkSize 4096 | Should -BeFalse

        $link = Join-Path $script:root 'linked.hhout'
        [IO.File]::CreateSymbolicLink($link, $receipt.Path) | Out-Null
        { Read-HHAuditArtifactV2 -Path $link -DataRoot $script:root `
                -DatabaseId $script:databaseId -LedgerId $script:ledgerId `
                -InvocationId $script:invocationId -ArtifactId $script:artifactId `
                -MasterKey $script:key -ChunkSize 4096 } |
            Should -Throw -ErrorId 'PersistencePathUnsafe,*'
        Test-HHAuditArtifactV2 -Path $link -DataRoot $script:root `
            -DatabaseId $script:databaseId -LedgerId $script:ledgerId `
            -InvocationId $script:invocationId -ArtifactId $script:artifactId `
            -MasterKey $script:key -ChunkSize 4096 | Should -BeFalse
    }

    It 'aborts safely when the staging artifact has already disappeared' {
        $writer = Get-TestWriter
        $writer.Stream.Dispose()
        $writer.Stream = $null
        [IO.File]::Delete($writer.TemporaryPath)

        Abort-HHAuditArtifactV2Writer -Writer $writer | Should -BeNullOrEmpty
        $writer.State | Should -BeExactly Aborted
        $writer.QuarantinePath | Should -BeNullOrEmpty
    }

    It 'rejects canonical frames with extra properties or non-boolean flags' {
        $extra = '{"Sequence":0,"RemoteSequence":0,' +
            '"ObservedAtUtc":"2026-08-24T00:00:00Z","Phase":"Command",' +
            '"Stream":"Output","TypeName":"System.String","SerializedByteCount":1,' +
            '"IsTerminating":false,"SerializedValue":"x","Unexpected":true}'
        { ConvertFrom-HHAuditArtifactV2Frame -Bytes ([Text.Encoding]::UTF8.GetBytes($extra)) } |
            Should -Throw -ErrorId 'AuditIntegrityFailed,*'

        $wrongFlag = '{"Sequence":0,"RemoteSequence":0,' +
            '"ObservedAtUtc":"2026-08-24T00:00:00Z","Phase":"Command",' +
            '"Stream":"Output","TypeName":"System.String","SerializedByteCount":1,' +
            '"IsTerminating":"false","SerializedValue":"x"}'
        { ConvertFrom-HHAuditArtifactV2Frame -Bytes ([Text.Encoding]::UTF8.GetBytes($wrongFlag)) } |
            Should -Throw -ErrorId 'AuditIntegrityFailed,*'
    }

    It 'maps a durable chunk write failure to storage-full without publishing' {
        $writer = Get-TestWriter
        $writer.Stream.Dispose()
        $writer.Stream = [HHImmediateIOExceptionStream]::new()
        {
            Write-HHAuditArtifactV2Event -Writer $writer -EventRecord (Get-TestEvent)
        } | Should -Throw -ErrorId 'PersistenceStorageFull,*'
        Test-Path -LiteralPath $writer.FinalPath | Should -BeFalse
        Abort-HHAuditArtifactV2Writer -Writer $writer | Should -Exist
    }

    It 'maps a mandatory durable event flush failure to storage-full' {
        $writer = Get-TestWriter
        $writer.Stream.Dispose()
        $writer.Stream = [HHFlushIOExceptionStream]::new()
        {
            Write-HHAuditArtifactV2Event -Writer $writer -EventRecord (Get-TestEvent)
        } | Should -Throw -ErrorId 'PersistenceStorageFull,*'
        Test-Path -LiteralPath $writer.FinalPath | Should -BeFalse
        Abort-HHAuditArtifactV2Writer -Writer $writer | Should -Exist
    }

    It 'maps a PowerShell-wrapped footer write failure to storage-full' {
        $writer = Get-TestWriter
        $writer.Stream.Dispose()
        $writer.Stream = [HHImmediateIOExceptionStream]::new()
        {
            Complete-HHAuditArtifactV2Writer -Writer $writer
        } | Should -Throw -ErrorId 'PersistenceStorageFull,*'
        $writer.State | Should -BeExactly Faulted
        $writer.FinalPath | Should -Not -Exist
        Abort-HHAuditArtifactV2Writer -Writer $writer | Should -Exist
    }

    It 'recognizes direct and PowerShell-wrapped IO exceptions without swallowing non-IO failures' {
        $io = [IO.IOException]::new('io')
        Test-HHAuditArtifactV2ExceptionType -ErrorObject $io -ExceptionType ([IO.IOException]) |
            Should -BeTrue
        $wrapped = [Management.Automation.MethodInvocationException]::new(
            'wrapped', $io
        )
        Test-HHAuditArtifactV2ExceptionType -ErrorObject $wrapped -ExceptionType ([IO.IOException]) |
            Should -BeTrue
        Test-HHAuditArtifactV2ExceptionType -ErrorObject ([ArgumentException]::new('not io')) `
            -ExceptionType ([IO.IOException]) | Should -BeFalse
        Test-HHAuditArtifactV2ExceptionType -ErrorObject $null -ExceptionType ([IO.IOException]) |
            Should -BeFalse
        Get-HHAuditArtifactV2DurableFailureState -ErrorObject (
            [HHDurableTestException]::new('PreRename', 'direct')
        ) | Should -BeExactly PreRename
        Get-HHAuditArtifactV2DurableFailureState -ErrorObject $null | Should -BeNullOrEmpty
    }

    It 'preserves non-IO chunk and event flush failures' {
        $writer = Get-TestWriter
        $writer.Stream.Dispose()
        $writer.Stream = [HHImmediateInvalidOperationStream]::new()
        { Write-HHAuditArtifactV2Event -Writer $writer -EventRecord (Get-TestEvent) } |
            Should -Throw '*non-IO write failure*'
        Abort-HHAuditArtifactV2Writer -Writer $writer | Should -Exist

        $writer = Get-TestWriter
        $writer.Stream.Dispose()
        $writer.Stream = [HHFlushInvalidOperationStream]::new()
        { Write-HHAuditArtifactV2Event -Writer $writer -EventRecord (Get-TestEvent) } |
            Should -Throw '*non-IO flush failure*'
        Abort-HHAuditArtifactV2Writer -Writer $writer | Should -Exist
    }

    It 'returns no receipt and marks publication unknown after a possibly committed rename failure' {
        $writer = Get-TestWriter
        $publisher = {
            param($SourcePath, $DestinationPath)
            [IO.File]::Move($SourcePath, $DestinationPath, $false)
            throw [HHDurableTestException]::new(
                'PostRenamePossiblyCommitted',
                'simulated directory durability failure'
            )
        }

        {
            Complete-HHAuditArtifactV2Writer -Writer $writer -DurablePublisher $publisher
        } | Should -Throw -ErrorId 'PersistenceStorageFull,*'
        $writer.State | Should -BeExactly PublicationUnknown
        $writer.FinalPath | Should -Exist
        $writer.PublishedPath | Should -BeNullOrEmpty
    }

    It 'maps a pre-rename durable publisher IO failure to faulted storage-full' {
        $writer = Get-TestWriter
        $publisher = {
            throw [Management.Automation.MethodInvocationException]::new(
                'wrapped',
                [HHDurableTestException]::new('PreRename', 'simulated pre-rename failure')
            )
        }

        {
            Complete-HHAuditArtifactV2Writer -Writer $writer -DurablePublisher $publisher
        } | Should -Throw -ErrorId 'PersistenceStorageFull,*'
        $writer.State | Should -BeExactly Faulted
        $writer.TemporaryPath | Should -Exist
        $writer.FinalPath | Should -Not -Exist
        Abort-HHAuditArtifactV2Writer -Writer $writer | Should -Exist
    }

    It 'rethrows a non-IO publisher failure unchanged and leaves staging faulted' {
        $writer = Get-TestWriter
        {
            Complete-HHAuditArtifactV2Writer -Writer $writer -DurablePublisher {
                throw [InvalidOperationException]::new('publisher contract failure')
            }
        } | Should -Throw '*publisher contract failure*'
        $writer.State | Should -BeExactly Faulted
        $writer.TemporaryPath | Should -Exist
        Abort-HHAuditArtifactV2Writer -Writer $writer | Should -Exist
    }

    It 'rejects an exact footer location with an impossible envelope length' {
        $writer = Get-TestWriter
        $receipt = Complete-HHAuditArtifactV2Writer -Writer $writer
        $bytes = [IO.File]::ReadAllBytes($receipt.Path)
        $footerMagic = [Text.Encoding]::ASCII.GetBytes('HHFOOT02')
        $footerOffset = -1
        for ($index = 0; $index -le $bytes.Length - $footerMagic.Length; $index++) {
            $matched = $true
            for ($magicIndex = 0; $magicIndex -lt $footerMagic.Length; $magicIndex++) {
                if ($bytes[$index + $magicIndex] -ne $footerMagic[$magicIndex]) {
                    $matched = $false
                    break
                }
            }
            if ($matched) {
                $footerOffset = $index
                break
            }
        }
        $footerOffset | Should -BeGreaterOrEqual 0
        [Array]::Clear($bytes, $footerOffset + 72, 4)
        $corrupt = Join-Path $TestDrive 'invalid-footer-length.hhout'
        [IO.File]::WriteAllBytes($corrupt, $bytes)

        { Read-HHAuditArtifactV2 -Path $corrupt `
                -DatabaseId $script:databaseId -LedgerId $script:ledgerId `
                -InvocationId $script:invocationId -ArtifactId $script:artifactId `
                -MasterKey $script:key -ChunkSize 4096 } |
            Should -Throw -ErrorId 'AuditIntegrityFailed,*'
    }
}
