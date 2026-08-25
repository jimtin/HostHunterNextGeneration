Set-StrictMode -Version Latest

$script:HHProcessAuditSubcategoryGuids = @{
    ProcessCreation = [Guid]'0CCE922B-69AE-11D9-BED3-505054503030'
    ProcessTermination = [Guid]'0CCE922C-69AE-11D9-BED3-505054503030'
}
$script:HHAuditSuccess = [uint32]0x1
$script:HHAuditFailure = [uint32]0x2
$script:HHAuditNone = [uint32]0x4
$script:HHCommandLineAuditRegistryPath =
    'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
$script:HHCommandLineAuditRegistryValue = 'ProcessCreationIncludeCmdLine_Enabled'

function Initialize-HHWindowsAuditNativeType {
    [CmdletBinding()]
    param()

    if ($null -ne ('HostHunter.Native.WindowsAuditPolicy' -as [type])) {
        return
    }

    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace HostHunter.Native
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct AuditPolicyInformation
    {
        internal Guid AuditSubCategoryGuid;
        internal UInt32 AuditingInformation;
        internal Guid AuditCategoryGuid;
    }

    public static class WindowsAuditPolicy
    {
        private const string CommandLinePath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit";
        private const string CommandLineName = "ProcessCreationIncludeCmdLine_Enabled";

        public sealed class CommandLineSnapshot
        {
            public string State { get; set; }
            public bool Exists { get; set; }
            public object Value { get; set; }
            public string Kind { get; set; }
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U1)]
        private static extern bool AuditQuerySystemPolicy(
            [In] Guid[] subCategoryGuids,
            UInt32 policyCount,
            out IntPtr auditPolicy);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U1)]
        private static extern bool AuditSetSystemPolicy(
            [In] AuditPolicyInformation[] auditPolicy,
            UInt32 policyCount);

        [DllImport("advapi32.dll")]
        private static extern void AuditFree(IntPtr buffer);

        public static UInt32[] Query(Guid[] subCategoryGuids)
        {
            if (subCategoryGuids == null || subCategoryGuids.Length == 0)
                throw new ArgumentException("At least one audit subcategory is required.");

            IntPtr buffer;
            if (!AuditQuerySystemPolicy(
                    subCategoryGuids,
                    (UInt32)subCategoryGuids.Length,
                    out buffer))
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "AuditQuerySystemPolicy failed.");

            try
            {
                int size = Marshal.SizeOf(typeof(AuditPolicyInformation));
                UInt32[] values = new UInt32[subCategoryGuids.Length];
                for (int index = 0; index < values.Length; index++)
                {
                    IntPtr item = new IntPtr(buffer.ToInt64() + (index * size));
                    AuditPolicyInformation information =
                        (AuditPolicyInformation)Marshal.PtrToStructure(
                            item,
                            typeof(AuditPolicyInformation));
                    values[index] = information.AuditingInformation;
                }
                return values;
            }
            finally
            {
                AuditFree(buffer);
            }
        }

        public static void Set(Guid[] subCategoryGuids, UInt32[] values)
        {
            if (subCategoryGuids == null || values == null ||
                subCategoryGuids.Length == 0 || subCategoryGuids.Length != values.Length)
                throw new ArgumentException("Audit subcategories and values must be non-empty and aligned.");

            AuditPolicyInformation[] information =
                new AuditPolicyInformation[subCategoryGuids.Length];
            for (int index = 0; index < information.Length; index++)
            {
                information[index].AuditSubCategoryGuid = subCategoryGuids[index];
                information[index].AuditingInformation = values[index];
                information[index].AuditCategoryGuid = Guid.Empty;
            }
            if (!AuditSetSystemPolicy(information, (UInt32)information.Length))
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "AuditSetSystemPolicy failed.");
        }

        public static CommandLineSnapshot QueryCommandLine()
        {
            using (RegistryKey baseKey = RegistryKey.OpenBaseKey(
                RegistryHive.LocalMachine, RegistryView.Registry64))
            using (RegistryKey key = baseKey.OpenSubKey(CommandLinePath, false))
            {
                if (key == null || Array.IndexOf(key.GetValueNames(), CommandLineName) < 0)
                    return new CommandLineSnapshot { State = "NotConfigured", Exists = false };
                object value = key.GetValue(
                    CommandLineName, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
                return new CommandLineSnapshot {
                    State = Convert.ToInt64(value) == 1 ? "Enabled" : "Disabled",
                    Exists = true,
                    Value = value,
                    Kind = key.GetValueKind(CommandLineName).ToString()
                };
            }
        }

        public static void AssertCommandLineWriteAccess()
        {
            using (RegistryKey baseKey = RegistryKey.OpenBaseKey(
                RegistryHive.LocalMachine, RegistryView.Registry64))
            using (RegistryKey key = baseKey.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", true))
            {
                if (key == null)
                    throw new UnauthorizedAccessException(
                        "The current token cannot write the local System policy registry key.");
            }
        }

        public static void SetCommandLine(string state)
        {
            using (RegistryKey baseKey = RegistryKey.OpenBaseKey(
                RegistryHive.LocalMachine, RegistryView.Registry64))
            {
                if (String.Equals(state, "NotConfigured", StringComparison.Ordinal))
                {
                    using (RegistryKey key = baseKey.OpenSubKey(CommandLinePath, true))
                    {
                        if (key != null) key.DeleteValue(CommandLineName, false);
                    }
                    return;
                }
                using (RegistryKey key = baseKey.CreateSubKey(
                    CommandLinePath, RegistryKeyPermissionCheck.ReadWriteSubTree))
                {
                    key.SetValue(
                        CommandLineName,
                        String.Equals(state, "Enabled", StringComparison.Ordinal) ? 1 : 0,
                        RegistryValueKind.DWord);
                }
            }
        }

        public static void RestoreCommandLine(CommandLineSnapshot snapshot)
        {
            if (!snapshot.Exists)
            {
                SetCommandLine("NotConfigured");
                return;
            }
            using (RegistryKey baseKey = RegistryKey.OpenBaseKey(
                RegistryHive.LocalMachine, RegistryView.Registry64))
            using (RegistryKey key = baseKey.CreateSubKey(
                CommandLinePath, RegistryKeyPermissionCheck.ReadWriteSubTree))
            {
                RegistryValueKind kind = (RegistryValueKind)Enum.Parse(
                    typeof(RegistryValueKind), snapshot.Kind);
                key.SetValue(CommandLineName, snapshot.Value, kind);
            }
        }
    }
}
'@
}

function Assert-HHWindowsProcessAuditPlatform {
    [CmdletBinding()]
    param()

    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw [PlatformNotSupportedException]::new(
            'Windows process audit policy operations require Windows.'
        )
    }
    Initialize-HHWindowsAuditNativeType
}

function Get-HHWindowsProcessAuditFlagMap {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('ProcessCreation', 'ProcessTermination')]
        [string[]]$Subcategory
    )

    Assert-HHWindowsProcessAuditPlatform
    $guids = [Guid[]]@($Subcategory | ForEach-Object {
            $script:HHProcessAuditSubcategoryGuids[$_]
        })
    $values = [HostHunter.Native.WindowsAuditPolicy]::Query($guids)
    $result = [ordered]@{}
    for ($index = 0; $index -lt $Subcategory.Count; $index++) {
        $result[$Subcategory[$index]] = [uint32]$values[$index]
    }
    return $result
}

function Set-HHWindowsProcessAuditFlagMap {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Private native boundary is called only after public authorization.'
    )]
    [CmdletBinding()]
    param([Parameter(Mandatory)][Collections.IDictionary]$Flags)

    Assert-HHWindowsProcessAuditPlatform
    $names = [string[]]@($Flags.Keys)
    $guids = [Guid[]]@($names | ForEach-Object {
            $script:HHProcessAuditSubcategoryGuids[$_]
        })
    $values = [uint32[]]@($names | ForEach-Object { [uint32]$Flags[$_] })
    [HostHunter.Native.WindowsAuditPolicy]::Set($guids, $values)
}

function Get-HHWindowsCommandLineAuditState {
    [CmdletBinding()]
    param()

    return (Get-HHWindowsCommandLineAuditSnapshot).State
}

function Get-HHWindowsCommandLineAuditSnapshot {
    [CmdletBinding()]
    param()

    Assert-HHWindowsProcessAuditPlatform
    return [HostHunter.Native.WindowsAuditPolicy]::QueryCommandLine()
}

function Test-HHWindowsCommandLineAuditWriteAccess {
    [CmdletBinding()]
    param()

    Assert-HHWindowsProcessAuditPlatform
    [HostHunter.Native.WindowsAuditPolicy]::AssertCommandLineWriteAccess()
    return $true
}

function Set-HHWindowsCommandLineAuditState {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Private registry boundary is called only after public authorization.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Enabled', 'Disabled', 'NotConfigured')]
        [string]$State
    )

    Assert-HHWindowsProcessAuditPlatform
    [HostHunter.Native.WindowsAuditPolicy]::SetCommandLine($State)
}

function Restore-HHWindowsCommandLineAuditSnapshot {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Private compensation boundary is called only after public authorization.'
    )]
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Snapshot)

    Assert-HHWindowsProcessAuditPlatform
    [HostHunter.Native.WindowsAuditPolicy]::RestoreCommandLine($Snapshot)
}

function ConvertTo-HHCommandLineAuditState {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Value)

    if ($Value -is [string]) { return $Value }
    if ($null -ne $Value.PSObject.Properties['State']) {
        return [string]$Value.State
    }
    throw [ArgumentException]::new('The command-line audit state projection is invalid.')
}

function ConvertTo-HHDesiredAuditFlag {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][uint32]$Current,
        [Parameter(Mandatory)]
        [ValidateSet('Enabled', 'Disabled')]
        [string]$State
    )

    $failure = $Current -band $script:HHAuditFailure
    if ($State -ceq 'Enabled') {
        return [uint32]($script:HHAuditSuccess -bor $failure)
    }
    if ($failure -ne 0) { return [uint32]$failure }
    return $script:HHAuditNone
}

function Test-HHAuditFlagMapsEqual {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][Collections.IDictionary]$Left,
        [Parameter(Mandatory)][Collections.IDictionary]$Right
    )

    if ($Left.Count -ne $Right.Count) { return $false }
    foreach ($key in $Left.Keys) {
        if (-not $Right.Contains($key) -or
            [uint32]$Left[$key] -ne [uint32]$Right[$key]) {
            return $false
        }
    }
    return $true
}

function New-HHWindowsProcessAuditResult {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Constructs an in-memory immutable result projection only.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][Collections.IDictionary]$AuditBefore,
        [Parameter(Mandatory)][Collections.IDictionary]$AuditDesired,
        [AllowNull()][Collections.IDictionary]$AuditAfter,
        [Parameter(Mandatory)][string]$CommandLineBefore,
        [Parameter(Mandatory)][string]$CommandLineDesired,
        [AllowNull()][string]$CommandLineAfter,
        [Parameter(Mandatory)][bool]$Succeeded,
        [Parameter(Mandatory)][bool]$Changed,
        [Parameter(Mandatory)][string]$CompensationStatus,
        [Parameter(Mandatory)][bool]$ConflictDetected,
        [Parameter(Mandatory)][bool]$ReconciliationRequired,
        [Parameter(Mandatory)][bool]$EscalationRequested,
        [AllowNull()]$PrivilegeResult,
        [AllowNull()][string]$FailureKind,
        [AllowNull()][string]$FailureMessage
    )

    return [pscustomobject][ordered]@{
        Marker = 'HostHunter.WindowsProcessAuditPolicyResult.v1'
        Succeeded = $Succeeded
        FailureKind = $FailureKind
        FailureMessage = $FailureMessage
        AuditBefore = [pscustomobject]$AuditBefore
        AuditDesired = [pscustomobject]$AuditDesired
        AuditAfter = if ($null -eq $AuditAfter) { $null } else { [pscustomobject]$AuditAfter }
        CommandLineBefore = $CommandLineBefore
        CommandLineDesired = $CommandLineDesired
        CommandLineAfter = $CommandLineAfter
        Changed = $Changed
        CompensationStatus = $CompensationStatus
        ConflictDetected = $ConflictDetected
        ReconciliationRequired = $ReconciliationRequired
        EscalationRequested = $EscalationRequested
        EscalationMethod = if ($EscalationRequested) { 'WindowsTokenPrivilege' } else { $null }
        RequiredPrivilege = 'SeSecurityPrivilege'
        PrivilegeActivated = $null -ne $PrivilegeResult -and [bool]$PrivilegeResult.Entered
        PrivilegeChanged = $null -ne $PrivilegeResult -and [bool]$PrivilegeResult.Changed
        PrivilegeRestored = if ($null -eq $PrivilegeResult) { $null } else {
            [bool]$PrivilegeResult.Restored
        }
    }
}

function Invoke-HHWindowsProcessAuditPolicyChange {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Private coordinator is called only after public authorization.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('ProcessCreation', 'ProcessTermination')]
        [string[]]$Subcategory,

        [Parameter(Mandatory)]
        [ValidateSet('Enabled', 'Disabled')]
        [string]$State,

        [ValidateSet('Unchanged', 'Enabled', 'Disabled', 'NotConfigured')]
        [string]$CommandLineLogging = 'Unchanged',

        [switch]$Escalate,

        [ValidateSet('CurrentToken', 'WindowsTokenPrivilege')]
        [string]$EscalationMethod,

        [scriptblock]$AuditQuery = { param($Names) Get-HHWindowsProcessAuditFlagMap -Subcategory $Names },
        [scriptblock]$AuditSet = { param($Flags) Set-HHWindowsProcessAuditFlagMap -Flags $Flags },
        [scriptblock]$CommandLineQuery = { Get-HHWindowsCommandLineAuditSnapshot },
        [scriptblock]$CommandLineSet = { param($Value) Set-HHWindowsCommandLineAuditState -State $Value },
        [scriptblock]$CommandLineRestore = {
            param($Snapshot)
            Restore-HHWindowsCommandLineAuditSnapshot -Snapshot $Snapshot
        },
        [scriptblock]$RegistryPreflight = { Test-HHWindowsCommandLineAuditWriteAccess },
        [scriptblock]$PrivilegeEnter,
        [scriptblock]$PrivilegeExit
    )

    $uniqueSubcategories = [string[]]@($Subcategory | Select-Object -Unique)
    if (-not $PSBoundParameters.ContainsKey('EscalationMethod')) {
        $EscalationMethod = if ($Escalate) {
            'WindowsTokenPrivilege'
        }
        else { 'CurrentToken' }
    }
    if (($Escalate -and $EscalationMethod -cne 'WindowsTokenPrivilege') -or
        (-not $Escalate -and $EscalationMethod -cne 'CurrentToken')) {
        throw [ArgumentException]::new(
            'EscalationMethod must match whether escalation was requested.'
        )
    }
    if ($CommandLineLogging -ceq 'Enabled' -and
        ($State -cne 'Enabled' -or 'ProcessCreation' -notin $uniqueSubcategories)) {
        throw [ArgumentException]::new(
            'Command-line logging can be enabled only with enabled ProcessCreation auditing.'
        )
    }

    $operation = {
        $auditBefore = & $AuditQuery $uniqueSubcategories
        $commandSnapshot = & $CommandLineQuery
        $commandBefore = ConvertTo-HHCommandLineAuditState -Value $commandSnapshot
        $auditDesired = [ordered]@{}
        foreach ($name in $uniqueSubcategories) {
            $auditDesired[$name] = ConvertTo-HHDesiredAuditFlag `
                -Current ([uint32]$auditBefore[$name]) -State $State
        }
        $commandDesired = if ($CommandLineLogging -ceq 'Unchanged') {
            $commandBefore
        }
        else { $CommandLineLogging }

        $auditNeedsChange = -not (Test-HHAuditFlagMapsEqual `
                -Left $auditBefore -Right $auditDesired)
        $commandNeedsChange = $commandBefore -cne $commandDesired
        if ($commandNeedsChange) {
            try { $null = & $RegistryPreflight }
            catch {
                return New-HHWindowsProcessAuditResult `
                    -AuditBefore $auditBefore -AuditDesired $auditDesired `
                    -AuditAfter $auditBefore -CommandLineBefore $commandBefore `
                    -CommandLineDesired $commandDesired -CommandLineAfter $commandBefore `
                    -Succeeded $false -Changed $false `
                    -CompensationStatus 'NotRequired' -ConflictDetected $false `
                    -ReconciliationRequired $false -EscalationRequested $Escalate `
                    -PrivilegeResult $null -FailureKind 'PolicyMutationFailed' `
                    -FailureMessage $_.Exception.Message
            }
        }
        if (-not $auditNeedsChange -and -not $commandNeedsChange) {
            return New-HHWindowsProcessAuditResult `
                -AuditBefore $auditBefore -AuditDesired $auditDesired -AuditAfter $auditBefore `
                -CommandLineBefore $commandBefore -CommandLineDesired $commandDesired `
                -CommandLineAfter $commandBefore -Succeeded $true -Changed $false `
                -CompensationStatus 'NotRequired' -ConflictDetected $false `
                -ReconciliationRequired $false -EscalationRequested $Escalate `
                -PrivilegeResult $null -FailureKind $null -FailureMessage $null
        }

        $auditChanged = $false
        $commandChanged = $false
        $compensation = 'NotRequired'
        $conflict = $false
        try {
            if ($commandNeedsChange -and $commandDesired -in @('Disabled', 'NotConfigured')) {
                & $CommandLineSet $commandDesired
                $commandChanged = $true
                if ((ConvertTo-HHCommandLineAuditState -Value (& $CommandLineQuery)) -cne
                    $commandDesired) {
                    throw 'Command-line audit policy verification failed.'
                }
            }
            if ($auditNeedsChange) {
                & $AuditSet $auditDesired
                $auditChanged = $true
                $auditCurrent = & $AuditQuery $uniqueSubcategories
                if (-not (Test-HHAuditFlagMapsEqual -Left $auditCurrent -Right $auditDesired)) {
                    throw 'Process audit policy verification failed.'
                }
            }
            if ($commandNeedsChange -and $commandDesired -ceq 'Enabled') {
                & $CommandLineSet $commandDesired
                $commandChanged = $true
                if ((ConvertTo-HHCommandLineAuditState -Value (& $CommandLineQuery)) -cne
                    $commandDesired) {
                    throw 'Command-line audit policy verification failed.'
                }
            }
            $auditAfter = & $AuditQuery $uniqueSubcategories
            $commandAfter = ConvertTo-HHCommandLineAuditState -Value (& $CommandLineQuery)
            return New-HHWindowsProcessAuditResult `
                -AuditBefore $auditBefore -AuditDesired $auditDesired -AuditAfter $auditAfter `
                -CommandLineBefore $commandBefore -CommandLineDesired $commandDesired `
                -CommandLineAfter $commandAfter -Succeeded $true -Changed $true `
                -CompensationStatus $compensation -ConflictDetected $false `
                -ReconciliationRequired $false -EscalationRequested $Escalate `
                -PrivilegeResult $null -FailureKind $null -FailureMessage $null
        }
        catch {
            $failure = $_
            $compensation = if ($auditChanged -or $commandChanged) { 'Pending' } else { 'NotRequired' }
            try {
                if ($commandChanged) {
                    $currentCommand = ConvertTo-HHCommandLineAuditState `
                        -Value (& $CommandLineQuery)
                    if ($currentCommand -cne $commandDesired) {
                        $conflict = $true
                    }
                    else {
                        & $CommandLineRestore $commandSnapshot
                    }
                }
                if ($auditChanged) {
                    $currentAudit = & $AuditQuery $uniqueSubcategories
                    if (-not (Test-HHAuditFlagMapsEqual -Left $currentAudit -Right $auditDesired)) {
                        $conflict = $true
                    }
                    else {
                        & $AuditSet $auditBefore
                    }
                }
                if ($conflict) { $compensation = 'SkippedConflict' }
                elseif ($auditChanged -or $commandChanged) { $compensation = 'Succeeded' }
            }
            catch {
                $compensation = 'Failed'
            }
            $auditAfter = try { & $AuditQuery $uniqueSubcategories } catch { $null }
            $commandAfter = try {
                ConvertTo-HHCommandLineAuditState -Value (& $CommandLineQuery)
            }
            catch { $null }
            return New-HHWindowsProcessAuditResult `
                -AuditBefore $auditBefore -AuditDesired $auditDesired -AuditAfter $auditAfter `
                -CommandLineBefore $commandBefore -CommandLineDesired $commandDesired `
                -CommandLineAfter $commandAfter -Succeeded $false `
                -Changed ($auditChanged -or $commandChanged) -CompensationStatus $compensation `
                -ConflictDetected $conflict `
                -ReconciliationRequired ($compensation -in @('Failed', 'SkippedConflict')) `
                -EscalationRequested $Escalate -PrivilegeResult $null `
                -FailureKind 'PolicyMutationFailed' -FailureMessage $failure.Exception.Message
        }
    }

    if (-not $Escalate) { return & $operation }
    $scopeParameters = @{
        Method = $EscalationMethod
        PrivilegeName = 'SeSecurityPrivilege'
        Operation = $operation
    }
    if ($PSBoundParameters.ContainsKey('PrivilegeEnter')) {
        $scopeParameters.PrivilegeEnter = $PrivilegeEnter
    }
    if ($PSBoundParameters.ContainsKey('PrivilegeExit')) {
        $scopeParameters.PrivilegeExit = $PrivilegeExit
    }
    $scopeResult = Invoke-HHWindowsPrivilegeScope @scopeParameters
    if ($null -eq $scopeResult.OperationResult) {
        return New-HHWindowsProcessAuditResult `
            -AuditBefore ([ordered]@{}) -AuditDesired ([ordered]@{}) -AuditAfter $null `
            -CommandLineBefore 'Unknown' -CommandLineDesired $CommandLineLogging `
            -CommandLineAfter $null -Succeeded $false -Changed $false `
            -CompensationStatus 'NotRequired' -ConflictDetected $false `
            -ReconciliationRequired (-not $scopeResult.Restored) `
            -EscalationRequested $true -PrivilegeResult $scopeResult `
            -FailureKind $scopeResult.FailureKind -FailureMessage $scopeResult.FailureMessage
    }
    $result = $scopeResult.OperationResult
    $result.PrivilegeActivated = $scopeResult.Entered
    $result.PrivilegeChanged = $scopeResult.Changed
    $result.PrivilegeRestored = $scopeResult.Restored
    if (-not $scopeResult.Restored) {
        $result.Succeeded = $false
        $result.FailureKind = 'PrivilegeRestoreFailed'
        $result.FailureMessage = $scopeResult.FailureMessage
        $result.ReconciliationRequired = $true
    }
    return $result
}

function New-HHWindowsProcessAuditPolicyRequest {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Constructs an in-memory immutable request projection only.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('ProcessCreation', 'ProcessTermination')]
        [string[]]$Subcategory,

        [Parameter(Mandatory)]
        [ValidateSet('Enabled', 'Disabled')]
        [string]$State,

        [ValidateSet('Unchanged', 'Enabled', 'Disabled', 'NotConfigured')]
        [string]$CommandLineLogging = 'Unchanged',

        [Alias('Escalate')]
        [bool]$EscalationRequested = $false,

        [ValidateSet('CurrentToken', 'WindowsTokenPrivilege')]
        [string]$EscalationMethod = 'CurrentToken'
    )

    $subcategories = [string[]]@($Subcategory | Select-Object -Unique)
    if ($CommandLineLogging -ceq 'Enabled' -and
        ($State -cne 'Enabled' -or 'ProcessCreation' -notin $subcategories)) {
        throw [ArgumentException]::new(
            'Command-line logging can be enabled only with enabled ProcessCreation auditing.'
        )
    }
    if (($EscalationRequested -and $EscalationMethod -cne 'WindowsTokenPrivilege') -or
        (-not $EscalationRequested -and $EscalationMethod -cne 'CurrentToken')) {
        throw [ArgumentException]::new(
            'EscalationMethod must match whether escalation was requested.'
        )
    }
    return [pscustomobject][ordered]@{
        Marker = 'HostHunter.WindowsProcessAuditPolicyRequest.v1'
        Subcategory = $subcategories
        State = $State
        CommandLineLogging = $CommandLineLogging
        Escalate = $EscalationRequested
        EscalationMethod = $EscalationMethod
    }
}

function Get-HHWindowsProcessAuditPolicyScriptBlock {
    [CmdletBinding()]
    param()

    $functionNames = @(
        'Initialize-HHWindowsPrivilegeNativeType',
        'Enter-HHWindowsTokenPrivilege',
        'Exit-HHWindowsTokenPrivilege',
        'Invoke-HHWindowsPrivilegeScope',
        'Initialize-HHWindowsAuditNativeType',
        'Assert-HHWindowsProcessAuditPlatform',
        'Get-HHWindowsProcessAuditFlagMap',
        'Set-HHWindowsProcessAuditFlagMap',
        'Get-HHWindowsCommandLineAuditState',
        'Get-HHWindowsCommandLineAuditSnapshot',
        'Test-HHWindowsCommandLineAuditWriteAccess',
        'Set-HHWindowsCommandLineAuditState',
        'Restore-HHWindowsCommandLineAuditSnapshot',
        'ConvertTo-HHCommandLineAuditState',
        'ConvertTo-HHDesiredAuditFlag',
        'Test-HHAuditFlagMapsEqual',
        'New-HHWindowsProcessAuditResult',
        'Invoke-HHWindowsProcessAuditPolicyChange'
    )
    $definitions = [string[]]$functionNames.ForEach({
            $command = Get-Command -Name $_ -CommandType Function -ErrorAction Stop
            $command.ScriptBlock.Ast.Extent.Text
        })
    $constants = @'
$script:HHProcessAuditSubcategoryGuids = @{
    ProcessCreation = [Guid]'0CCE922B-69AE-11D9-BED3-505054503030'
    ProcessTermination = [Guid]'0CCE922C-69AE-11D9-BED3-505054503030'
}
$script:HHAuditSuccess = [uint32]0x1
$script:HHAuditFailure = [uint32]0x2
$script:HHAuditNone = [uint32]0x4
$script:HHCommandLineAuditRegistryPath = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
$script:HHCommandLineAuditRegistryValue = 'ProcessCreationIncludeCmdLine_Enabled'
'@
    $entryPoint = @'
if ($null -eq $Request -or
    [string]$Request.Marker -cne 'HostHunter.WindowsProcessAuditPolicyRequest.v1') {
    throw 'The remote process audit policy request is invalid.'
}
try {
    Invoke-HHWindowsProcessAuditPolicyChange `
        -Subcategory ([string[]]$Request.Subcategory) `
        -State ([string]$Request.State) `
        -CommandLineLogging ([string]$Request.CommandLineLogging) `
        -Escalate:([bool]$Request.Escalate) `
        -EscalationMethod ([string]$Request.EscalationMethod)
}
catch {
    New-HHWindowsProcessAuditResult `
        -AuditBefore ([ordered]@{}) -AuditDesired ([ordered]@{}) -AuditAfter $null `
        -CommandLineBefore 'Unknown' `
        -CommandLineDesired ([string]$Request.CommandLineLogging) `
        -CommandLineAfter $null -Succeeded $false -Changed $false `
        -CompensationStatus 'NotRequired' -ConflictDetected $false `
        -ReconciliationRequired $false `
        -EscalationRequested ([bool]$Request.Escalate) -PrivilegeResult $null `
        -FailureKind 'PolicyQueryFailed' -FailureMessage $_.Exception.Message
}
'@
    return [scriptblock]::Create(
        (@(
                'param([Parameter(Mandatory)]$Request)',
                'Set-StrictMode -Version Latest',
                $constants
            ) + $definitions + $entryPoint) -join "`n`n"
    )
}

function Test-HHWindowsProcessAuditPolicyOutcome {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Outcome)

    $required = @(
        'Marker', 'Succeeded', 'AuditBefore', 'AuditDesired', 'AuditAfter',
        'CommandLineBefore', 'CommandLineDesired', 'CommandLineAfter', 'Changed',
        'CompensationStatus', 'ConflictDetected', 'ReconciliationRequired',
        'EscalationRequested', 'RequiredPrivilege', 'PrivilegeActivated',
        'PrivilegeChanged', 'PrivilegeRestored'
    )
    if ($null -eq $Outcome -or
        [string]$Outcome.Marker -cne 'HostHunter.WindowsProcessAuditPolicyResult.v1') {
        return $false
    }
    $missingRequired = @($required.Where({
                $null -eq $Outcome.PSObject.Properties[$_]
            }, 'First'))
    if ($missingRequired.Count -ne 0) { return $false }
    return [string]$Outcome.CompensationStatus -in @(
        'NotRequired', 'Succeeded', 'Failed', 'SkippedConflict'
    )
}

function Get-HHWindowsProcessAuditPolicyOutcomeFromStreamEvents {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseSingularNouns',
        '',
        Justification = 'The input is explicitly a collection of remote stream events.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$StreamEvents,
        [bool]$Required = $true
    )

    $outcomes = @(
        $StreamEvents |
            Where-Object {
                $null -ne $_ -and
                $null -ne $_.PSObject.Properties['Value'] -and
                $null -ne $_.Value -and
                $null -ne $_.Value.PSObject.Properties['Marker'] -and
                [string]$_.Value.Marker -ceq 'HostHunter.WindowsProcessAuditPolicyResult.v1'
            } |
            ForEach-Object { $_.Value }
    )
    if ($outcomes.Count -eq 0 -and -not $Required) { return $null }
    if ($outcomes.Count -ne 1 -or
        -not (Test-HHWindowsProcessAuditPolicyOutcome -Outcome $outcomes[0])) {
        throw 'The remote stream did not contain exactly one valid process audit policy outcome.'
    }
    return $outcomes[0]
}
