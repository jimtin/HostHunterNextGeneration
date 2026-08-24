function Remove-HHTarget {
    <#
    .SYNOPSIS
    Removes one or more saved HostHunter targets.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateCount(1, 8)]
        [string[]]$Name
    )

    begin { $requestedNames = [Collections.Generic.List[string]]::new() }
    process { foreach ($item in $Name) { $requestedNames.Add($item) } }
    end {
        if ($requestedNames.Count -gt 8) { throw 'No more than eight targets can be removed at once.' }
        $names = [string[]]$requestedNames.ToArray()
        if (-not $PSCmdlet.ShouldProcess(($names -join ', '), 'Remove saved HostHunter target(s)')) {
            return
        }
        $runtime = Get-HHRuntimeContext
        if (-not [IO.File]::Exists($runtime.DatabasePath)) {
            throw "Cannot remove unknown target(s): $($names -join ', ')."
        }
        $context = Open-HHAuthenticatedPersistence `
            -PersistenceContext $runtime `
            -AllowAnchorAdvance
        try {
            $receipt = Invoke-HHAnchoredPersistenceTransaction -Context $context `
                -ArgumentList @($names) -Action {
                param($Connection, $Transaction, $WriterContext, $Arguments)
                Remove-HHTargetRepository -Connection $Connection -Transaction $Transaction `
                    -MasterKey $WriterContext.MasterKey -Name ([string[]]$Arguments) `
                    -MutationId ([Guid]::NewGuid().ToByteArray()) `
                    -RequestedAtUtc ([DateTimeOffset]::UtcNow) `
                    -ExpectedAnchor $WriterContext.Anchor
            }
            $receipt.CurrentTargets
        }
        finally { Close-HHAuthenticatedPersistence -Context $context }
    }
}
