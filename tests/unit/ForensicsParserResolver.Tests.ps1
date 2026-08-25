BeforeAll {
    $sourceRoot = if ([string]::IsNullOrWhiteSpace($env:HH_TEST_SOURCE_ROOT)) {
        Join-Path $PSScriptRoot '../../src/HostHunterNextGeneration'
    }
    else { $env:HH_TEST_SOURCE_ROOT }
    . (Join-Path $sourceRoot 'Forensics/Private/Contracts/StrictJsonValidator.ps1')
    $script:parserPath = Join-Path $sourceRoot 'Forensics/Private/Parser/EvtxDump.ps1'
    . $script:parserPath
}

Describe 'Pinned evtx_dump resolver and file admission' -Tag Unit {
    BeforeEach {
        $script:temporaryParser = Join-Path $TestDrive 'evtx_dump'
        [IO.File]::WriteAllText($script:temporaryParser, 'verified parser fixture')
        $script:parserHash = (Get-FileHash -LiteralPath $script:temporaryParser -Algorithm SHA256).Hash
    }

    It 'declares every packaged parser RID and immutable digest' {
        $expected = [ordered]@{
            'linux-arm64' = '50fcb8d316351c7a2c9f6d610ae3f9932b8f6c0ecf87f1e3756630963e263a96'
            'linux-x64' = 'c33c111c9832cff5b91dfca6fece51d603181a42dfb56f0ed0a25669f2600df9'
            'osx-arm64' = '6dd3a5b09ed73d55a3ad76548e99be587ea4258ee89424c8bfcacc18bc8c7e5b'
            'osx-x64' = '60f2a775832fa2433f981ffae83a053420b523641eba1af804d2601e5866f208'
        }
        foreach ($rid in $expected.Keys) {
            $pin = Get-HHForensicsEvtxDumpPin -RuntimeIdentifier $rid
            $pin.Version | Should -BeExactly '0.12.2'
            $pin.RelativePath | Should -BeExactly "tools/evtx_dump/$rid/evtx_dump"
            $pin.Sha256 | Should -BeExactly $expected[$rid]
        }
    }

    It 'detects the packaged controller RID and rejects Windows explicitly' {
        Get-HHForensicsRuntimeIdentifier | Should -Match '^(?:linux|osx)-(?:arm64|x64)$'
        $source = Get-Content -LiteralPath $script:parserPath -Raw
        $source | Should -Match 'supports macOS and Linux only'
    }

    It 'resolves a no-follow file only when digest and version remain stable' {
        $descriptor = Resolve-HHForensicsEvtxParser -Path $script:temporaryParser `
            -RuntimeIdentifier linux-x64 -ExpectedSha256 $script:parserHash `
            -VersionInvoker { 'evtx_dump 0.12.2' }
        $descriptor.Marker | Should -BeExactly 'HostHunter.Forensics.Parser.v2'
        $descriptor.FileIdentity.Marker | Should -BeExactly 'HostHunter.Forensics.FileIdentity.v1'
        $descriptor.Sha256 | Should -BeExactly $script:parserHash.ToLowerInvariant()

        [IO.File]::AppendAllText($script:temporaryParser, 'swap')
        { Assert-HHForensicsFileIdentity -Identity $descriptor.FileIdentity } |
            Should -Throw '*digest does not match*'
    }

    It 'detects a parser swap during version qualification' {
        {
            Resolve-HHForensicsEvtxParser -Path $script:temporaryParser `
                -RuntimeIdentifier linux-x64 -ExpectedSha256 $script:parserHash `
                -VersionInvoker {
                    param($Executable)
                    [IO.File]::AppendAllText($Executable, 'swapped')
                    'evtx_dump 0.12.2'
                }
        } | Should -Throw '*digest does not match*'
    }

    It 'rejects digest drift, version drift, directories, and missing paths' {
        {
            Resolve-HHForensicsEvtxParser -Path $script:temporaryParser `
                -RuntimeIdentifier linux-x64 -ExpectedSha256 ('0' * 64) `
                -VersionInvoker { 'evtx_dump 0.12.2' }
        } | Should -Throw '*digest does not match*'
        {
            Resolve-HHForensicsEvtxParser -Path $script:temporaryParser `
                -RuntimeIdentifier linux-x64 -ExpectedSha256 $script:parserHash `
                -VersionInvoker { 'evtx_dump 0.12.1' }
        } | Should -Throw '*required version 0.12.2*'
        { Get-HHForensicsFileIdentity -Path $TestDrive } | Should -Throw '*regular file*'
        { Get-HHForensicsFileIdentity -Path (Join-Path $TestDrive missing) } |
            Should -Throw '*component does not exist*'
    }

    It 'rejects symlinks and reparse points in any protected path component' -Skip:(
        [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
    ) {
        $link = Join-Path $TestDrive 'parser-link'
        New-Item -ItemType SymbolicLink -Path $link -Target $script:temporaryParser | Out-Null
        { Get-HHForensicsFileIdentity -Path $link } | Should -Throw '*forbidden*'
    }

    It 'copies from an open source handle into an owner-private stable file' {
        $sourceIdentity = Get-HHForensicsFileIdentity -Path $script:temporaryParser
        $staging = Initialize-HHForensicsPrivateStagingDirectory
        try {
            $destination = Join-Path $staging 'evtx_dump'
            $staged = Copy-HHForensicsFileToPrivateStage -SourceIdentity $sourceIdentity `
                -DestinationPath $destination -Executable
            $staged.Sha256 | Should -BeExactly $sourceIdentity.Sha256
            [IO.File]::ReadAllText($destination) | Should -BeExactly 'verified parser fixture'
        }
        finally {
            if ([IO.File]::Exists($destination)) { [IO.File]::Delete($destination) }
            if ([IO.Directory]::Exists($staging)) { [IO.Directory]::Delete($staging, $false) }
        }
    }

    It 'declares process-tree-only isolation as not release qualified' {
        $isolation = Get-HHForensicsParserIsolationProfile
        $isolation.ProcessTreeTermination | Should -BeTrue
        $isolation.CpuLimit | Should -BeFalse
        $isolation.MemoryLimit | Should -BeFalse
        $isolation.NetworkIsolation | Should -BeFalse
        $isolation.ReleaseQualified | Should -BeFalse
        $isolation.QualificationRequirement | Should -Match 'OS sandbox launcher'
    }

    It 'uses the discrete default version invocation and checks its exit code' -Skip:(
        [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
    ) {
        $savedVersion = $script:HHEvtxDumpVersion
        try {
            $echoVersion = [string](& /usr/bin/echo --version 2>&1)
            $match = [regex]::Match($echoVersion, '(?m)(?<![0-9.])([0-9]+\.[0-9]+)(?![0-9.])')
            $match.Success | Should -BeTrue
            $script:HHEvtxDumpVersion = $match.Groups[1].Value
            $echoHash = (Get-FileHash -LiteralPath /usr/bin/echo -Algorithm SHA256).Hash
            $descriptor = Resolve-HHForensicsEvtxParser -Path /usr/bin/echo `
                -ExpectedSha256 $echoHash
            $descriptor.Version | Should -BeExactly $script:HHEvtxDumpVersion

            $script:HHEvtxDumpVersion = '0.12.2'
            $falseHash = (Get-FileHash -LiteralPath /usr/bin/false -Algorithm SHA256).Hash
            { Resolve-HHForensicsEvtxParser -Path /usr/bin/false -RuntimeIdentifier linux-x64 `
                    -ExpectedSha256 $falseHash } | Should -Throw '*exited with code*'
        }
        finally { $script:HHEvtxDumpVersion = $savedVersion }
    }

    It 'resolves the pinned parser from an adjacent packaged module by default' {
        $packageRoot = Join-Path $TestDrive 'package'
        $packagedParserScript = Join-Path $packageRoot `
            'Forensics/Private/Parser/EvtxDump.ps1'
        $packagedBinary = Join-Path $packageRoot 'tools/evtx_dump/linux-x64/evtx_dump'
        [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($packagedParserScript)) |
            Out-Null
        [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($packagedBinary)) |
            Out-Null
        [IO.File]::Copy($script:parserPath, $packagedParserScript)
        [IO.File]::WriteAllText($packagedBinary, 'packaged parser fixture')
        try {
            . $packagedParserScript
            $packagedHash = (Get-FileHash -LiteralPath $packagedBinary -Algorithm SHA256).Hash
            $script:HHEvtxDumpPins['linux-x64'] = $packagedHash.ToLowerInvariant()
            $descriptor = Resolve-HHForensicsEvtxParser -RuntimeIdentifier linux-x64 `
                -VersionInvoker { 'evtx_dump 0.12.2' }
            $descriptor.Path | Should -BeExactly $packagedBinary
            $descriptor.Sha256 | Should -BeExactly $packagedHash.ToLowerInvariant()
        }
        finally {
            . $script:parserPath
        }
    }
}
