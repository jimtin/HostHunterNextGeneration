Set-StrictMode -Version Latest

$script:HHForensicsCredentialService = 'HostHunterNextGeneration.Forensics.v1'
$script:HHForensicsKeyAccount = 'ledger-key'
$script:HHForensicsAnchorAccount = 'ledger-anchor'

function Get-HHForensicsProviderContract {
    [CmdletBinding()]
    param()

    return [pscustomobject]@{
        Schema = 'hosthunter.forensics-provider/1'
        Service = $script:HHForensicsCredentialService
        KeyAccount = $script:HHForensicsKeyAccount
        AnchorAccount = $script:HHForensicsAnchorAccount
        KeyLength = 32
        AnchorSchema = 'hosthunter.forensics-anchor/1'
    }
}

function Stop-HHForensicsOperation {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Throws a terminating error and does not mutate external state.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ErrorId,
        [Parameter(Mandatory)][string]$Message,
        [Parameter(Mandatory)][Management.Automation.ErrorCategory]$Category,
        [AllowNull()][object]$TargetObject,
        [AllowNull()][Exception]$InnerException
    )

    $exception = [InvalidOperationException]::new($Message, $InnerException)
    $record = [Management.Automation.ErrorRecord]::new(
        $exception,
        $ErrorId,
        $Category,
        $TargetObject
    )
    $PSCmdlet.ThrowTerminatingError($record)
}

function Assert-HHForensicsKey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [byte[]]$Key
    )

    if ($null -eq $Key -or $Key.Length -ne 32) {
        Stop-HHForensicsOperation -ErrorId ForensicsKeyUnavailable `
            -Message 'The independent HostHunter forensics key must contain exactly 32 bytes.' `
            -Category SecurityError -TargetObject $null
    }
}

function Get-HHForensicsKey {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param([Parameter(Mandatory)][scriptblock]$ForensicsKeyProvider)

    try {
        $provided = & $ForensicsKeyProvider
    }
    catch {
        Stop-HHForensicsOperation -ErrorId ForensicsKeyUnavailable `
            -Message 'The independent HostHunter forensics key provider failed.' `
            -Category SecurityError -TargetObject $null -InnerException $_.Exception
    }
    if ($null -eq $provided -or
        $null -eq $provided.PSObject.Properties['Service'] -or
        $null -eq $provided.PSObject.Properties['Account'] -or
        $null -eq $provided.PSObject.Properties['KeyBytes'] -or
        [string]$provided.Service -cne $script:HHForensicsCredentialService -or
        [string]$provided.Account -cne $script:HHForensicsKeyAccount) {
        Stop-HHForensicsOperation -ErrorId ForensicsKeyUnavailable `
            -Message 'The forensics key provider returned the wrong service, account, or shape.' `
            -Category SecurityError -TargetObject $null
    }
    $key = [byte[]]$provided.KeyBytes
    Assert-HHForensicsKey -Key $key
    $copy = [byte[]]$key.Clone()
    [Array]::Clear($key, 0, $key.Length)
    Write-Output -InputObject $copy -NoEnumerate
}

function Get-HHForensicsHash {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param([Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes)

    $hash = [Security.Cryptography.SHA256]::HashData($Bytes)
    Write-Output -InputObject $hash -NoEnumerate
}

function Test-HHForensicsBytesEqual {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Left,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Right
    )

    if ($Left.Length -ne $Right.Length) { return $false }
    return [Security.Cryptography.CryptographicOperations]::FixedTimeEquals($Left, $Right)
}

function Get-HHForensicsDerivedKey {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$ForensicsKey,
        [Parameter(Mandatory)]
        [ValidateSet('BodyEncryption', 'StateIntegrity', 'AnchorIntegrity')]
        [string]$Purpose
    )

    Assert-HHForensicsKey -Key $ForensicsKey
    $label = "HostHunterNextGeneration/forensics/$($Purpose.ToLowerInvariant())/v1"
    $labelBytes = [Text.Encoding]::UTF8.GetBytes($label)
    $hmac = [Security.Cryptography.HMACSHA256]::new($ForensicsKey)
    try {
        $key = $hmac.ComputeHash($labelBytes)
        Write-Output -InputObject $key -NoEnumerate
    }
    finally {
        $hmac.Dispose()
        [Array]::Clear($labelBytes, 0, $labelBytes.Length)
    }
}

function Get-HHForensicsMac {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Key,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes
    )

    if ($Key.Length -ne 32) {
        throw [ArgumentException]::new('Forensics MAC keys must contain 32 bytes.', 'Key')
    }
    $hmac = [Security.Cryptography.HMACSHA256]::new($Key)
    try {
        $mac = $hmac.ComputeHash($Bytes)
        Write-Output -InputObject $mac -NoEnumerate
    }
    finally { $hmac.Dispose() }
}

function Join-HHForensicsEvidence {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Value)

    $stream = [IO.MemoryStream]::new()
    try {
        foreach ($item in $Value) {
            [byte[]]$bytes = @()
            if ($null -eq $item) { $bytes = @() }
            elseif ($item -is [byte[]]) { $bytes = [byte[]]$item }
            elseif ($item -is [long] -or $item -is [int]) {
                $bytes = [BitConverter]::GetBytes([long]$item)
            }
            else { $bytes = [Text.Encoding]::UTF8.GetBytes([string]$item) }
            $length = [BitConverter]::GetBytes([int]$bytes.Length)
            $stream.Write($length, 0, $length.Length)
            if ($bytes.Length -gt 0) { $stream.Write($bytes, 0, $bytes.Length) }
        }
        $joined = $stream.ToArray()
        Write-Output -InputObject $joined -NoEnumerate
    }
    finally { $stream.Dispose() }
}

function Get-HHForensicsAssociatedData {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('EventBody', 'RequestBody', 'ReceiptBody', 'ResponseBody')]
        [string]$Purpose,
        [Parameter(Mandatory)][string]$RoutingKey,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Digest
    )

    if ($Digest.Length -ne 32 -or [string]::IsNullOrWhiteSpace($RoutingKey)) {
        throw [ArgumentException]::new('Forensics associated data requires a routing key and 32-byte digest.')
    }
    return Join-HHForensicsEvidence -Value @('HHF-AAD-1', $Purpose, $RoutingKey, $Digest)
}

function Protect-HHForensicsValue {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Plaintext,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$ForensicsKey,
        [Parameter(Mandatory)]
        [ValidateSet('EventBody', 'RequestBody', 'ReceiptBody', 'ResponseBody')]
        [string]$Purpose,
        [Parameter(Mandatory)][string]$RoutingKey,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Digest
    )

    $associatedData = Get-HHForensicsAssociatedData `
        -Purpose $Purpose -RoutingKey $RoutingKey -Digest $Digest
    $key = Get-HHForensicsDerivedKey -ForensicsKey $ForensicsKey -Purpose BodyEncryption
    $nonce = [byte[]]::new(12)
    [Security.Cryptography.RandomNumberGenerator]::Fill($nonce)
    $ciphertext = [byte[]]::new($Plaintext.Length)
    $tag = [byte[]]::new(16)
    try {
        $aes = [Security.Cryptography.AesGcm]::new($key, 16)
        try { $aes.Encrypt($nonce, $Plaintext, $ciphertext, $tag, $associatedData) }
        finally { $aes.Dispose() }

        $purposeId = switch ($Purpose) {
            EventBody { 1 }
            RequestBody { 2 }
            ReceiptBody { 3 }
            ResponseBody { 4 }
        }
        $envelope = [byte[]]::new(34 + $ciphertext.Length)
        $envelope[0] = 0x48
        $envelope[1] = 0x48
        $envelope[2] = 0x46
        $envelope[3] = 0x31
        $envelope[4] = 0x01
        $envelope[5] = $purposeId
        [Array]::Copy($nonce, 0, $envelope, 6, 12)
        [Array]::Copy($tag, 0, $envelope, 18, 16)
        [Array]::Copy($ciphertext, 0, $envelope, 34, $ciphertext.Length)
        Write-Output -InputObject $envelope -NoEnumerate
    }
    finally {
        [Array]::Clear($key, 0, $key.Length)
        [Array]::Clear($associatedData, 0, $associatedData.Length)
        [Array]::Clear($ciphertext, 0, $ciphertext.Length)
        [Array]::Clear($tag, 0, $tag.Length)
    }
}

function Unprotect-HHForensicsValue {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Envelope,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$ForensicsKey,
        [Parameter(Mandatory)]
        [ValidateSet('EventBody', 'RequestBody', 'ReceiptBody', 'ResponseBody')]
        [string]$Purpose,
        [Parameter(Mandatory)][string]$RoutingKey,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Digest
    )

    $purposeId = switch ($Purpose) {
        EventBody { 1 }
        RequestBody { 2 }
        ReceiptBody { 3 }
        ResponseBody { 4 }
    }
    if ($Envelope.Length -lt 34 -or $Envelope[0] -ne 0x48 -or
        $Envelope[1] -ne 0x48 -or $Envelope[2] -ne 0x46 -or
        $Envelope[3] -ne 0x31 -or $Envelope[4] -ne 0x01 -or
        $Envelope[5] -ne $purposeId) {
        Stop-HHForensicsOperation -ErrorId ForensicsIntegrityFailed `
            -Message 'An encrypted forensics value has an invalid envelope.' `
            -Category InvalidData -TargetObject $RoutingKey
    }

    $nonce = [byte[]]::new(12)
    $tag = [byte[]]::new(16)
    $ciphertext = [byte[]]::new($Envelope.Length - 34)
    [Array]::Copy($Envelope, 6, $nonce, 0, 12)
    [Array]::Copy($Envelope, 18, $tag, 0, 16)
    [Array]::Copy($Envelope, 34, $ciphertext, 0, $ciphertext.Length)
    $plaintext = [byte[]]::new($ciphertext.Length)
    $associatedData = Get-HHForensicsAssociatedData `
        -Purpose $Purpose -RoutingKey $RoutingKey -Digest $Digest
    $key = Get-HHForensicsDerivedKey -ForensicsKey $ForensicsKey -Purpose BodyEncryption
    try {
        $aes = [Security.Cryptography.AesGcm]::new($key, 16)
        try { $aes.Decrypt($nonce, $ciphertext, $tag, $plaintext, $associatedData) }
        catch [Security.Cryptography.AuthenticationTagMismatchException] {
            Stop-HHForensicsOperation -ErrorId ForensicsIntegrityFailed `
                -Message 'An encrypted forensics value failed authentication.' `
                -Category SecurityError -TargetObject $RoutingKey -InnerException $_.Exception
        }
        finally { $aes.Dispose() }
        Write-Output -InputObject $plaintext -NoEnumerate
        $plaintext = $null
    }
    finally {
        [Array]::Clear($key, 0, $key.Length)
        [Array]::Clear($associatedData, 0, $associatedData.Length)
        [Array]::Clear($ciphertext, 0, $ciphertext.Length)
        [Array]::Clear($tag, 0, $tag.Length)
        if ($null -ne $plaintext) { [Array]::Clear($plaintext, 0, $plaintext.Length) }
    }
}
