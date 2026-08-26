@{
    IncludeDefaultRules = $true
    Severity            = @(
        'Error'
        'Warning'
    )
    # The native client intentionally exports container-discovered proxy names.
    # A static manifest list would break automatic command synchronization.
    ExcludeRules        = @('PSUseToExportFieldsInManifest')
}
