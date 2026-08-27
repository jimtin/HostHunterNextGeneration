Set-StrictMode -Version Latest

$script:HHTargetCredentialDomain = 'HostHunterNextGeneration/target-credential/v1'

function Get-HHTargetCredentialBindingRow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Connection,
        [AllowNull()][object]$Transaction,
        [Parameter(Mandatory)][string]$Name
    )

    $rows = @(Invoke-HHSqliteQuery -Connection $Connection -Transaction $Transaction -Sql @'
SELECT d.database_id, p.name, p.name_key, p.host_name, p.port, p.user_name,
    p.authentication, p.credential_storage, p.revision
FROM database_identity AS d
CROSS JOIN target_profiles AS p
WHERE d.singleton_id = 1 AND p.name_key = @name_key;
'@ -Parameters @{ name_key = $Name.Trim().ToUpperInvariant() })
    if ($rows.Count -ne 1) {
        throw "Stored credential target '$Name' does not exist."
    }
    return $rows[0]
}

function Get-HHTargetCredentialAssociatedData {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param([Parameter(Mandatory)][object]$Binding)

    $document = [ordered]@{
        domain = $script:HHTargetCredentialDomain
        databaseId = [Convert]::ToHexString([byte[]]$Binding.database_id).ToLowerInvariant()
        nameKey = [string]$Binding.name_key
        hostName = ([string]$Binding.host_name).ToLowerInvariant()
        port = [int]$Binding.port
        userName = [string]$Binding.user_name
        revision = [long]$Binding.revision
    }
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(
        ($document | ConvertTo-Json -Compress)
    )
    Write-Output -InputObject $bytes -NoEnumerate
}

function Assert-HHTargetCredentialState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Connection,
        [AllowNull()][object]$Transaction
    )

    $rows = @(Invoke-HHSqliteQuery -Connection $Connection -Transaction $Transaction -Sql @'
SELECT
    (SELECT COUNT(*) FROM target_profiles WHERE credential_storage = 'Encrypted') AS expected_count,
    (SELECT COUNT(*) FROM target_credentials) AS actual_count,
    (SELECT COUNT(*) FROM target_credentials AS c
        LEFT JOIN target_profiles AS p ON p.name_key = c.name_key
        WHERE p.name_key IS NULL OR p.credential_storage <> 'Encrypted'
            OR p.authentication <> 'Password' OR p.revision <> c.target_revision) AS invalid_count;
'@)
    if ($rows.Count -ne 1 -or
        [long]$rows[0].expected_count -ne [long]$rows[0].actual_count -or
        [long]$rows[0].invalid_count -ne 0) {
        throw [Security.SecurityException]::new(
            'The encrypted target credential state failed integrity validation.'
        )
    }
}

function Set-HHTargetCredential {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Runs inside an already authorized caller-owned SQLite transaction.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Connection,
        [Parameter(Mandatory)][object]$Transaction,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$MasterKey,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateCount(1, 4096)][byte[]]$PasswordBytes,
        [Parameter(Mandatory)][DateTimeOffset]$StoredAtUtc
    )

    $binding = Get-HHTargetCredentialBindingRow -Connection $Connection `
        -Transaction $Transaction -Name $Name
    if ([string]$binding.authentication -cne 'Password' -or
        [string]$binding.credential_storage -cne 'Encrypted') {
        throw "Target '$Name' is not configured for encrypted password storage."
    }
    $associatedData = Get-HHTargetCredentialAssociatedData -Binding $binding
    $envelope = $null
    try {
        $envelope = Protect-HHPersistenceValue -Plaintext $PasswordBytes `
            -MasterKey $MasterKey -AssociatedData $associatedData `
            -Purpose CredentialEncryption
        $null = Invoke-HHSqliteNonQuery -Connection $Connection -Transaction $Transaction `
            -Sql 'DELETE FROM target_credentials WHERE name_key = @name_key;' `
            -Parameters @{ name_key = [string]$binding.name_key }
        $null = Invoke-HHSqliteNonQuery -Connection $Connection -Transaction $Transaction -Sql @'
INSERT INTO target_credentials(name_key, target_revision, password_envelope, stored_at_utc)
VALUES(@name_key, @revision, @envelope, @stored_at);
'@ -Parameters @{
            name_key = [string]$binding.name_key
            revision = [long]$binding.revision
            envelope = $envelope
            stored_at = $StoredAtUtc.UtcDateTime.ToString(
                'o', [Globalization.CultureInfo]::InvariantCulture
            )
        }
    }
    finally {
        [Array]::Clear($associatedData, 0, $associatedData.Length)
        if ($null -ne $envelope) { [Array]::Clear($envelope, 0, $envelope.Length) }
    }
}

function Get-HHTargetCredential {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)][object]$Connection,
        [AllowNull()][object]$Transaction,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$MasterKey,
        [Parameter(Mandatory)][object]$Target
    )

    $validated = ConvertTo-HHValidatedTargetRecord -InputObject $Target
    if ($validated.Authentication -cne 'Password' -or
        $validated.CredentialStorage -cne 'Encrypted') {
        return $null
    }
    $binding = Get-HHTargetCredentialBindingRow -Connection $Connection `
        -Transaction $Transaction -Name $validated.Name
    $rows = @(Invoke-HHSqliteQuery -Connection $Connection -Transaction $Transaction -Sql @'
SELECT password_envelope, target_revision
FROM target_credentials
WHERE name_key = @name_key;
'@ -Parameters @{ name_key = [string]$binding.name_key })
    if ($rows.Count -ne 1 -or
        [long]$rows[0].target_revision -ne [long]$binding.revision) {
        throw [Security.SecurityException]::new(
            "The encrypted password for target '$($validated.Name)' is missing or stale. " +
            'Run Set-HHTarget again to replace it.'
        )
    }
    $associatedData = Get-HHTargetCredentialAssociatedData -Binding $binding
    $plaintext = $null
    try {
        $plaintext = Unprotect-HHPersistenceValue `
            -Envelope ([byte[]]$rows[0].password_envelope) `
            -MasterKey $MasterKey -AssociatedData $associatedData `
            -Purpose CredentialEncryption
        Write-Output -InputObject $plaintext -NoEnumerate
        $plaintext = $null
    }
    finally {
        [Array]::Clear($associatedData, 0, $associatedData.Length)
        if ($null -ne $plaintext) { [Array]::Clear($plaintext, 0, $plaintext.Length) }
    }
}
