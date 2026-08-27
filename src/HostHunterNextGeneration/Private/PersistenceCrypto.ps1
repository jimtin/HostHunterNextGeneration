Set-StrictMode -Version Latest

function Get-HHPersistenceDerivedKey {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)][AllowNull()][AllowEmptyCollection()][byte[]]$MasterKey,
        [Parameter(Mandatory)]
        [ValidateSet('RowEncryption', 'CredentialEncryption', 'AuditIntegrity', 'TargetState', 'TargetMutation', 'CaseLookup', 'Anchor')]
        [string]$Purpose
    )

    Assert-HHAuditMasterKey -MasterKey $MasterKey
    $label = "HostHunterNextGeneration/persistence/$($Purpose.ToLowerInvariant())/v1"
    $labelBytes = [System.Text.Encoding]::UTF8.GetBytes($label)
    $hmac = [System.Security.Cryptography.HMACSHA256]::new($MasterKey)
    try {
        $key = $hmac.ComputeHash($labelBytes)
        Write-Output -InputObject $key -NoEnumerate
    }
    finally {
        $hmac.Dispose()
        [Array]::Clear($labelBytes, 0, $labelBytes.Length)
    }
}

function Get-HHPersistenceHash {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param([Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes)

    $hash = [System.Security.Cryptography.SHA256]::HashData($Bytes)
    Write-Output -InputObject $hash -NoEnumerate
}

function Get-HHPersistenceMac {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Key,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes
    )

    if ($Key.Length -ne 32) {
        throw [System.ArgumentException]::new('Persistence MAC keys must contain 32 bytes.', 'Key')
    }
    $hmac = [System.Security.Cryptography.HMACSHA256]::new($Key)
    try {
        $mac = $hmac.ComputeHash($Bytes)
        Write-Output -InputObject $mac -NoEnumerate
    }
    finally {
        $hmac.Dispose()
    }
}

function Test-HHPersistenceBytesEqual {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Left,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Right
    )

    if ($Left.Length -ne $Right.Length) {
        return $false
    }
    return [System.Security.Cryptography.CryptographicOperations]::FixedTimeEquals($Left, $Right)
}

function Protect-HHPersistenceValue {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Plaintext,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$MasterKey,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$AssociatedData,
        [ValidateSet('RowEncryption', 'CredentialEncryption')]
        [string]$Purpose = 'RowEncryption'
    )

    $key = Get-HHPersistenceDerivedKey -MasterKey $MasterKey -Purpose $Purpose
    $nonce = [byte[]]::new(12)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($nonce)
    $ciphertext = [byte[]]::new($Plaintext.Length)
    $tag = [byte[]]::new(16)
    try {
        $aes = [System.Security.Cryptography.AesGcm]::new($key, 16)
        try {
            $aes.Encrypt($nonce, $Plaintext, $ciphertext, $tag, $AssociatedData)
        }
        finally {
            $aes.Dispose()
        }
        $envelope = [byte[]]::new(4 + $nonce.Length + $tag.Length + $ciphertext.Length)
        $envelope[0] = 0x48
        $envelope[1] = 0x48
        $envelope[2] = 0x01
        $envelope[3] = 0x01
        [Array]::Copy($nonce, 0, $envelope, 4, $nonce.Length)
        [Array]::Copy($tag, 0, $envelope, 16, $tag.Length)
        [Array]::Copy($ciphertext, 0, $envelope, 32, $ciphertext.Length)
        Write-Output -InputObject $envelope -NoEnumerate
    }
    finally {
        [Array]::Clear($key, 0, $key.Length)
        [Array]::Clear($ciphertext, 0, $ciphertext.Length)
        [Array]::Clear($tag, 0, $tag.Length)
    }
}

function Unprotect-HHPersistenceValue {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Envelope,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$MasterKey,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$AssociatedData,
        [ValidateSet('RowEncryption', 'CredentialEncryption')]
        [string]$Purpose = 'RowEncryption'
    )

    if ($Envelope.Length -lt 32 -or $Envelope[0] -ne 0x48 -or
        $Envelope[1] -ne 0x48 -or $Envelope[2] -ne 0x01 -or $Envelope[3] -ne 0x01) {
        Stop-HHPersistenceOperation `
            -ErrorId 'AuditIntegrityFailed' `
            -Message 'An encrypted persistence value has an invalid envelope.' `
            -Category ([System.Management.Automation.ErrorCategory]::InvalidData) `
            -TargetObject $null
    }
    $nonce = [byte[]]::new(12)
    $tag = [byte[]]::new(16)
    $ciphertext = [byte[]]::new($Envelope.Length - 32)
    [Array]::Copy($Envelope, 4, $nonce, 0, 12)
    [Array]::Copy($Envelope, 16, $tag, 0, 16)
    [Array]::Copy($Envelope, 32, $ciphertext, 0, $ciphertext.Length)
    $plaintext = [byte[]]::new($ciphertext.Length)
    $key = Get-HHPersistenceDerivedKey -MasterKey $MasterKey -Purpose $Purpose
    try {
        $aes = [System.Security.Cryptography.AesGcm]::new($key, 16)
        try {
            $aes.Decrypt($nonce, $ciphertext, $tag, $plaintext, $AssociatedData)
        }
        catch [System.Security.Cryptography.AuthenticationTagMismatchException] {
            Stop-HHPersistenceOperation `
                -ErrorId 'AuditIntegrityFailed' `
                -Message 'An encrypted persistence value failed authentication.' `
                -Category ([System.Management.Automation.ErrorCategory]::SecurityError) `
                -TargetObject $null `
                -InnerException $_.Exception
        }
        finally {
            $aes.Dispose()
        }
        Write-Output -InputObject $plaintext -NoEnumerate
        $plaintext = $null
    }
    finally {
        [Array]::Clear($key, 0, $key.Length)
        [Array]::Clear($ciphertext, 0, $ciphertext.Length)
        if ($null -ne $plaintext) {
            [Array]::Clear($plaintext, 0, $plaintext.Length)
        }
    }
}
