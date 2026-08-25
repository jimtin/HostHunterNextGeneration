Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$nativeSource = @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

public static class HHMacOSForensicsKeychainWorker
{
    private const string SecurityFramework =
        "/System/Library/Frameworks/Security.framework/Security";
    private const string CoreFoundationFramework =
        "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation";
    private const int Success = 0;
    private const int ItemMissing = 10;
    private const int DuplicateItem = 11;
    private const int NativeFailure = 12;
    private const int InvalidInput = 13;
    private const int UnsupportedPlatform = 14;
    private const int InternalFailure = 15;
    private const int CompareMismatch = 16;
    private const int VerificationFailed = 17;
    private const int ErrSecDuplicateItem = -25299;
    private const int ErrSecItemNotFound = -25300;
    private const int KeyLength = 32;
    private const int AnchorLength = 240;
    private const string KeyService =
        "com.hosthunter.nextgeneration.forensics-key.v1";
    private const string AnchorService =
        "com.hosthunter.nextgeneration.forensics-anchor.v1";

    [DllImport(SecurityFramework, CallingConvention = CallingConvention.Cdecl)]
    private static extern int SecKeychainOpen(byte[] pathName, out IntPtr keychain);

    [DllImport(SecurityFramework, CallingConvention = CallingConvention.Cdecl)]
    private static extern int SecKeychainAddGenericPassword(
        IntPtr keychain,
        uint serviceNameLength,
        byte[] serviceName,
        uint accountNameLength,
        byte[] accountName,
        uint passwordLength,
        byte[] passwordData,
        out IntPtr item);

    [DllImport(SecurityFramework, CallingConvention = CallingConvention.Cdecl)]
    private static extern int SecKeychainFindGenericPassword(
        IntPtr keychainOrArray,
        uint serviceNameLength,
        byte[] serviceName,
        uint accountNameLength,
        byte[] accountName,
        out uint passwordLength,
        out IntPtr passwordData,
        out IntPtr item);

    [DllImport(SecurityFramework, CallingConvention = CallingConvention.Cdecl)]
    private static extern int SecKeychainItemDelete(IntPtr item);

    [DllImport(SecurityFramework, CallingConvention = CallingConvention.Cdecl)]
    private static extern int SecKeychainItemModifyAttributesAndData(
        IntPtr item,
        IntPtr attributes,
        uint length,
        byte[] data);

    [DllImport(SecurityFramework, CallingConvention = CallingConvention.Cdecl)]
    private static extern int SecKeychainItemFreeContent(IntPtr attributes, IntPtr data);

    [DllImport(CoreFoundationFramework, CallingConvention = CallingConvention.Cdecl)]
    private static extern void CFRelease(IntPtr value);

    public static int Run(string[] arguments)
    {
        if (arguments == null
            || arguments.Length != 8
            || !string.Equals(arguments[0], "-Action", StringComparison.Ordinal)
            || !string.Equals(arguments[2], "-KeychainPath", StringComparison.Ordinal)
            || !string.Equals(arguments[4], "-Service", StringComparison.Ordinal)
            || !string.Equals(arguments[6], "-Account", StringComparison.Ordinal))
        {
            return InvalidInput;
        }
        if (!OperatingSystem.IsMacOS())
        {
            return UnsupportedPlatform;
        }
        string action = arguments[1];
        string keychainPath = arguments[3];
        string service = arguments[5];
        string account = arguments[7];
        if (!ValidMetadata(keychainPath, service, account)
            || !ValidActionService(action, service))
        {
            return InvalidInput;
        }
        try
        {
            switch (action)
            {
                case "CreateKey":
                    return Create(keychainPath, service, account, KeyLength);
                case "ReadKey":
                    return Read(keychainPath, service, account, KeyLength);
                case "CreateAnchor":
                    return Create(keychainPath, service, account, AnchorLength);
                case "ReadAnchor":
                    return Read(keychainPath, service, account, AnchorLength);
                case "CompareUpdateAnchor":
                    return CompareUpdateAnchor(keychainPath, service, account);
                case "Delete":
                    return Delete(keychainPath, service, account);
                default:
                    return InvalidInput;
            }
        }
        catch
        {
            return InternalFailure;
        }
    }

    private static bool ValidMetadata(string path, string service, string account)
    {
        return !string.IsNullOrWhiteSpace(path)
            && !string.IsNullOrWhiteSpace(service)
            && !string.IsNullOrWhiteSpace(account)
            && path.IndexOf('\0') < 0
            && service.IndexOf('\0') < 0
            && account.IndexOf('\0') < 0
            && Path.IsPathFullyQualified(path);
    }

    private static bool ValidActionService(string action, string service)
    {
        switch (action)
        {
            case "CreateKey":
            case "ReadKey":
                return string.Equals(service, KeyService, StringComparison.Ordinal);
            case "CreateAnchor":
            case "ReadAnchor":
            case "CompareUpdateAnchor":
                return string.Equals(service, AnchorService, StringComparison.Ordinal);
            case "Delete":
                return string.Equals(service, KeyService, StringComparison.Ordinal)
                    || string.Equals(service, AnchorService, StringComparison.Ordinal);
            default:
                return false;
        }
    }

    private static int Create(
        string path,
        string service,
        string account,
        int length)
    {
        byte[] secret = new byte[length];
        try
        {
            if (!ReadExactInput(secret))
            {
                return InvalidInput;
            }
            int status = WithMetadata(
                path,
                service,
                account,
                (pathBytes, serviceBytes, accountBytes) =>
                {
                    IntPtr keychain = IntPtr.Zero;
                    IntPtr item = IntPtr.Zero;
                    try
                    {
                        int openStatus = SecKeychainOpen(pathBytes, out keychain);
                        if (openStatus != 0)
                        {
                            return openStatus;
                        }
                        return SecKeychainAddGenericPassword(
                            keychain,
                            (uint)serviceBytes.Length,
                            serviceBytes,
                            (uint)accountBytes.Length,
                            accountBytes,
                            (uint)secret.Length,
                            secret,
                            out item);
                    }
                    finally
                    {
                        Release(item);
                        Release(keychain);
                    }
                });
            if (status == 0)
            {
                return Success;
            }
            return status == ErrSecDuplicateItem ? DuplicateItem : NativeFailure;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
        }
    }

    private static int Read(
        string path,
        string service,
        string account,
        int requiredLength)
    {
        byte[] secret = null;
        IntPtr item = IntPtr.Zero;
        try
        {
            int status = Find(path, service, account, out secret, out item);
            if (status == ErrSecItemNotFound)
            {
                return ItemMissing;
            }
            if (status != 0 || secret == null || secret.Length != requiredLength)
            {
                return NativeFailure;
            }
            using Stream output = Console.OpenStandardOutput();
            output.Write(secret, 0, secret.Length);
            output.Flush();
            return Success;
        }
        finally
        {
            if (secret != null)
            {
                CryptographicOperations.ZeroMemory(secret);
            }
            Release(item);
        }
    }

    private static int CompareUpdateAnchor(
        string path,
        string service,
        string account)
    {
        byte[] input = null;
        byte[] expected = null;
        byte[] replacement = null;
        byte[] current = null;
        byte[] readback = null;
        IntPtr item = IntPtr.Zero;
        IntPtr readbackItem = IntPtr.Zero;
        try
        {
            input = ReadBoundedInput(AnchorLength * 2);
            if (input == null || input.Length != AnchorLength * 2)
            {
                return InvalidInput;
            }
            expected = new byte[AnchorLength];
            replacement = new byte[AnchorLength];
            Buffer.BlockCopy(input, 0, expected, 0, AnchorLength);
            Buffer.BlockCopy(input, AnchorLength, replacement, 0, AnchorLength);
            int status = Find(path, service, account, out current, out item);
            if (status == ErrSecItemNotFound)
            {
                return ItemMissing;
            }
            if (status != 0 || current == null || current.Length != AnchorLength)
            {
                return NativeFailure;
            }
            if (!CryptographicOperations.FixedTimeEquals(current, expected))
            {
                return CompareMismatch;
            }
            int modifyStatus = SecKeychainItemModifyAttributesAndData(
                item,
                IntPtr.Zero,
                (uint)replacement.Length,
                replacement);
            if (modifyStatus != 0)
            {
                return NativeFailure;
            }
            int readbackStatus = Find(
                path,
                service,
                account,
                out readback,
                out readbackItem);
            if (readbackStatus != 0
                || readback == null
                || readback.Length != AnchorLength
                || !CryptographicOperations.FixedTimeEquals(readback, replacement))
            {
                return VerificationFailed;
            }
            using Stream output = Console.OpenStandardOutput();
            output.Write(readback, 0, readback.Length);
            output.Flush();
            return Success;
        }
        finally
        {
            Clear(input);
            Clear(expected);
            Clear(replacement);
            Clear(current);
            Clear(readback);
            Release(item);
            Release(readbackItem);
        }
    }

    private static int Delete(string path, string service, string account)
    {
        byte[] secret = null;
        IntPtr item = IntPtr.Zero;
        try
        {
            int status = Find(path, service, account, out secret, out item);
            if (status == ErrSecItemNotFound)
            {
                return ItemMissing;
            }
            if (status != 0 || item == IntPtr.Zero)
            {
                return NativeFailure;
            }
            return SecKeychainItemDelete(item) == 0 ? Success : NativeFailure;
        }
        finally
        {
            Clear(secret);
            Release(item);
        }
    }

    private static int Find(
        string path,
        string service,
        string account,
        out byte[] secret,
        out IntPtr item)
    {
        byte[] foundSecret = null;
        IntPtr foundItem = IntPtr.Zero;
        int status = WithMetadata(
            path,
            service,
            account,
            (pathBytes, serviceBytes, accountBytes) =>
            {
                IntPtr keychain = IntPtr.Zero;
                IntPtr passwordData = IntPtr.Zero;
                try
                {
                    int openStatus = SecKeychainOpen(pathBytes, out keychain);
                    if (openStatus != 0)
                    {
                        return openStatus;
                    }
                    uint passwordLength;
                    int findStatus = SecKeychainFindGenericPassword(
                        keychain,
                        (uint)serviceBytes.Length,
                        serviceBytes,
                        (uint)accountBytes.Length,
                        accountBytes,
                        out passwordLength,
                        out passwordData,
                        out foundItem);
                    if (findStatus != 0)
                    {
                        return findStatus;
                    }
                    if (passwordLength > int.MaxValue || passwordData == IntPtr.Zero)
                    {
                        return NativeFailure;
                    }
                    foundSecret = new byte[(int)passwordLength];
                    Marshal.Copy(passwordData, foundSecret, 0, foundSecret.Length);
                    return Success;
                }
                finally
                {
                    if (passwordData != IntPtr.Zero)
                    {
                        SecKeychainItemFreeContent(IntPtr.Zero, passwordData);
                    }
                    Release(keychain);
                }
            });
        secret = foundSecret;
        item = foundItem;
        return status;
    }

    private static int WithMetadata(
        string path,
        string service,
        string account,
        Func<byte[], byte[], byte[], int> action)
    {
        byte[] pathBytes = Encoding.UTF8.GetBytes(path + "\0");
        byte[] serviceBytes = Encoding.UTF8.GetBytes(service);
        byte[] accountBytes = Encoding.UTF8.GetBytes(account);
        try
        {
            return action(pathBytes, serviceBytes, accountBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pathBytes);
            CryptographicOperations.ZeroMemory(serviceBytes);
            CryptographicOperations.ZeroMemory(accountBytes);
        }
    }

    private static bool ReadExactInput(byte[] destination)
    {
        using Stream input = Console.OpenStandardInput();
        int offset = 0;
        while (offset < destination.Length)
        {
            int count = input.Read(destination, offset, destination.Length - offset);
            if (count == 0)
            {
                return false;
            }
            offset += count;
        }
        return input.ReadByte() == -1;
    }

    private static byte[] ReadBoundedInput(int maximumLength)
    {
        using Stream input = Console.OpenStandardInput();
        using MemoryStream buffer = new MemoryStream();
        byte[] chunk = new byte[256];
        try
        {
            while (true)
            {
                int count = input.Read(chunk, 0, chunk.Length);
                if (count == 0)
                {
                    return buffer.ToArray();
                }
                if (buffer.Length + count > maximumLength)
                {
                    return null;
                }
                buffer.Write(chunk, 0, count);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(chunk);
            if (buffer.TryGetBuffer(out ArraySegment<byte> segment)
                && segment.Array != null)
            {
                CryptographicOperations.ZeroMemory(
                    segment.Array.AsSpan(segment.Offset, segment.Count));
            }
        }
    }

    private static void Clear(byte[] value)
    {
        if (value != null)
        {
            CryptographicOperations.ZeroMemory(value);
        }
    }

    private static void Release(IntPtr value)
    {
        if (value != IntPtr.Zero)
        {
            CFRelease(value);
        }
    }
}
'@

try {
    Add-Type -TypeDefinition $nativeSource -Language CSharp -ErrorAction Stop
    exit [HHMacOSForensicsKeychainWorker]::Run($args)
}
catch {
    exit 15
}
