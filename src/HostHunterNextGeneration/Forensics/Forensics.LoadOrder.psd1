@{
    SchemaVersion = 1
    PrivateFiles = @(
        'Private/Identity/ForensicsIdentity.ps1'
        'Private/Contracts/StrictJsonValidator.ps1'
        'Private/Contracts/EcsProcessStartContract.ps1'
        'Private/Parser/EvtxDump.ps1'
        'Private/Normalization/EcsProcessStart.ps1'
        'Private/Persistence/ForensicsCrypto.ps1'
        'Private/Migrations/ForensicsMigrations.ps1'
        'Private/Persistence/ForensicsPersistence.ps1'
        'Private/Delivery/ForensicsOutbox.ps1'
        'Private/Delivery/ForensicsApiClient.ps1'
        'Private/ForensicsPipeline.ps1'
    )
}
