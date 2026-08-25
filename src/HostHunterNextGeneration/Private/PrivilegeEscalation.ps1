Set-StrictMode -Version Latest

function Initialize-HHWindowsPrivilegeNativeType {
    [CmdletBinding()]
    param()

    if ($null -ne ('HostHunter.Native.WindowsTokenPrivileges' -as [type])) {
        return
    }

    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace HostHunter.Native
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct Luid
    {
        internal UInt32 LowPart;
        internal Int32 HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LuidAndAttributes
    {
        internal Luid Luid;
        internal UInt32 Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TokenPrivileges
    {
        internal UInt32 PrivilegeCount;
        internal LuidAndAttributes Privileges;
    }

    public sealed class PrivilegeScope
    {
        internal IntPtr TokenHandle;
        internal TokenPrivileges PreviousState;
        internal bool HasPreviousState;
        public string PrivilegeName { get; internal set; }
        public bool Changed { get; internal set; }
        public bool Restored { get; internal set; }
        public bool Closed { get; internal set; }
    }

    public static class WindowsTokenPrivileges
    {
        private const UInt32 TokenQuery = 0x0008;
        private const UInt32 TokenAdjustPrivileges = 0x0020;
        private const UInt32 PrivilegeEnabled = 0x00000002;
        private const Int32 ErrorNotAllAssigned = 1300;

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr handle);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool OpenProcessToken(
            IntPtr processHandle,
            UInt32 desiredAccess,
            out IntPtr tokenHandle);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool LookupPrivilegeValue(
            string systemName,
            string privilegeName,
            out Luid luid);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AdjustTokenPrivileges(
            IntPtr tokenHandle,
            [MarshalAs(UnmanagedType.Bool)] bool disableAllPrivileges,
            ref TokenPrivileges newState,
            UInt32 bufferLength,
            out TokenPrivileges previousState,
            out UInt32 returnLength);

        [DllImport("advapi32.dll", EntryPoint = "AdjustTokenPrivileges", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool RestoreTokenPrivileges(
            IntPtr tokenHandle,
            [MarshalAs(UnmanagedType.Bool)] bool disableAllPrivileges,
            ref TokenPrivileges newState,
            UInt32 bufferLength,
            IntPtr previousState,
            IntPtr returnLength);

        public static PrivilegeScope Enable(string privilegeName)
        {
            if (String.IsNullOrWhiteSpace(privilegeName))
                throw new ArgumentException("A privilege name is required.", "privilegeName");

            IntPtr token;
            if (!OpenProcessToken(
                    GetCurrentProcess(),
                    TokenQuery | TokenAdjustPrivileges,
                    out token))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcessToken failed.");

            try
            {
                Luid luid;
                if (!LookupPrivilegeValue(null, privilegeName, out luid))
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "LookupPrivilegeValue failed for " + privilegeName + ".");

                TokenPrivileges requested = new TokenPrivileges();
                requested.PrivilegeCount = 1;
                requested.Privileges.Luid = luid;
                requested.Privileges.Attributes = PrivilegeEnabled;
                TokenPrivileges previous;
                UInt32 returned;
                bool adjusted = AdjustTokenPrivileges(
                    token,
                    false,
                    ref requested,
                    (UInt32)Marshal.SizeOf(typeof(TokenPrivileges)),
                    out previous,
                    out returned);
                int error = Marshal.GetLastWin32Error();
                if (!adjusted)
                    throw new Win32Exception(error, "AdjustTokenPrivileges failed.");
                if (error == ErrorNotAllAssigned)
                    throw new Win32Exception(
                        error,
                        "The current token does not contain " + privilegeName + ".");

                PrivilegeScope scope = new PrivilegeScope();
                scope.TokenHandle = token;
                scope.PreviousState = previous;
                scope.HasPreviousState = previous.PrivilegeCount > 0;
                scope.PrivilegeName = privilegeName;
                scope.Changed = scope.HasPreviousState;
                scope.Restored = !scope.HasPreviousState;
                return scope;
            }
            catch
            {
                CloseHandle(token);
                throw;
            }
        }

        public static void Restore(PrivilegeScope scope)
        {
            if (scope == null)
                throw new ArgumentNullException("scope");
            if (scope.Closed)
                return;

            try
            {
                if (scope.HasPreviousState)
                {
                    TokenPrivileges previous = scope.PreviousState;
                    bool adjusted = RestoreTokenPrivileges(
                        scope.TokenHandle,
                        false,
                        ref previous,
                        0,
                        IntPtr.Zero,
                        IntPtr.Zero);
                    int error = Marshal.GetLastWin32Error();
                    if (!adjusted)
                        throw new Win32Exception(error, "Restoring the token privilege failed.");
                    if (error == ErrorNotAllAssigned)
                        throw new Win32Exception(error, "The token privilege could not be restored.");
                }
                scope.Restored = true;
            }
            finally
            {
                CloseHandle(scope.TokenHandle);
                scope.Closed = true;
            }
        }
    }
}
'@
}

function Enter-HHWindowsTokenPrivilege {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Private native boundary entered by an already authorized operation.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('SeSecurityPrivilege')]
        [string]$PrivilegeName
    )

    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw [PlatformNotSupportedException]::new(
            'Windows token privilege activation requires Windows.'
        )
    }
    Initialize-HHWindowsPrivilegeNativeType
    return [HostHunter.Native.WindowsTokenPrivileges]::Enable($PrivilegeName)
}

function Exit-HHWindowsTokenPrivilege {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Private native boundary restores an already authorized privilege scope.'
    )]
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Scope)

    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw [PlatformNotSupportedException]::new(
            'Windows token privilege restoration requires Windows.'
        )
    }
    Initialize-HHWindowsPrivilegeNativeType
    [HostHunter.Native.WindowsTokenPrivileges]::Restore($Scope)
}

function Invoke-HHWindowsPrivilegeScope {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Private coordinator is called only after public authorization.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('WindowsTokenPrivilege')]
        [string]$Method,

        [Parameter(Mandatory)]
        [ValidateSet('SeSecurityPrivilege')]
        [string]$PrivilegeName,

        [Parameter(Mandatory)]
        [scriptblock]$Operation,

        [scriptblock]$PrivilegeEnter = {
            param($Name)
            Enter-HHWindowsTokenPrivilege -PrivilegeName $Name
        },

        [scriptblock]$PrivilegeExit = {
            param($Scope)
            Exit-HHWindowsTokenPrivilege -Scope $Scope
        }
    )

    $scope = $null
    $operationResult = $null
    $operationError = $null
    $restoreError = $null
    try {
        $scope = & $PrivilegeEnter $PrivilegeName
        $operationResult = & $Operation
    }
    catch {
        $operationError = $_
    }
    finally {
        if ($null -ne $scope) {
            try {
                & $PrivilegeExit $scope
            }
            catch {
                $restoreError = $_
            }
        }
    }

    $restored = $null -ne $scope -and $null -eq $restoreError
    return [pscustomobject][ordered]@{
        Marker = 'HostHunter.PrivilegeScope.v1'
        Method = $Method
        PrivilegeName = $PrivilegeName
        Entered = $null -ne $scope
        Changed = if ($null -ne $scope -and
            $null -ne $scope.PSObject.Properties['Changed']) {
            [bool]$scope.Changed
        }
        else { $false }
        Restored = $restored
        OperationSucceeded = $null -eq $operationError -and $null -eq $restoreError
        OperationResult = $operationResult
        FailureKind = if ($null -ne $operationError) {
            'PrivilegeOrOperationFailed'
        }
        elseif ($null -ne $restoreError) { 'PrivilegeRestoreFailed' }
        else { $null }
        FailureMessage = if ($null -ne $operationError) {
            $operationError.Exception.Message
        }
        elseif ($null -ne $restoreError) { $restoreError.Exception.Message }
        else { $null }
    }
}
