using System.ComponentModel;
using System.Runtime.InteropServices;

namespace HostHunter.Persistence.Durability;

public enum DurablePublicationFailureState
{
    PreRename,
    Collision,
    PostRenamePossiblyCommitted
}

public sealed class DurablePublicationException : IOException
{
    public DurablePublicationException(
        DurablePublicationFailureState failureState,
        string message,
        Exception? innerException = null)
        : base(message, innerException)
    {
        FailureState = failureState;
    }

    public DurablePublicationFailureState FailureState { get; }
}

public static class DurablePublisher
{
    private const int AtFdcwd = -100;
    private const uint RenameNoReplace = 1;
    private const uint RenameExclusive = 0x00000004;
    private const uint MoveFileWriteThrough = 0x00000008;
    private const int ErrorFileExists = 80;
    private const int ErrorAlreadyExists = 183;
    private const int UnixAlreadyExists = 17;
    private const int UnixInterrupted = 4;
    private const int LinuxX64Directory = 0x00010000;
    private const int LinuxX64NoFollow = 0x00020000;
    private const int LinuxArm64Directory = 0x00004000;
    private const int LinuxArm64NoFollow = 0x00008000;
    private const int MacDirectory = 0x00100000;
    private const int MacNoFollow = 0x00000100;

    public static void Publish(string sourcePath, string destinationPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sourcePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(destinationPath);

        var source = Path.GetFullPath(sourcePath);
        var destination = Path.GetFullPath(destinationPath);
        var sourceDirectory = Path.GetDirectoryName(source)
            ?? throw PreRename("The source path has no parent directory.");
        var destinationDirectory = Path.GetDirectoryName(destination)
            ?? throw PreRename("The destination path has no parent directory.");
        var comparison = OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;

        if (!string.Equals(sourceDirectory, destinationDirectory, comparison))
        {
            throw PreRename("Durable publication requires source and destination in the same directory.");
        }

        ValidateSource(source);
        ValidateParent(sourceDirectory);
        if (File.Exists(destination) || Directory.Exists(destination))
        {
            throw Collision("The durable publication destination already exists.");
        }

        if (OperatingSystem.IsWindows())
        {
            PublishWindows(source, destination);
            return;
        }

        PublishUnix(source, destination, sourceDirectory);
    }

    private static void ValidateSource(string source)
    {
        if (!File.Exists(source))
        {
            throw PreRename("The durable publication source does not exist.");
        }

        var attributes = File.GetAttributes(source);
        if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
        {
            throw PreRename("The durable publication source must be a regular, non-link file.");
        }
    }

    private static void ValidateParent(string directory)
    {
        var info = new DirectoryInfo(directory);
        if (!info.Exists ||
            (info.Attributes & FileAttributes.ReparsePoint) != 0 ||
            info.LinkTarget is not null)
        {
            throw PreRename("The durable publication directory must exist and cannot be a link or reparse point.");
        }
    }

    private static void PublishWindows(string source, string destination)
    {
        if (MoveFileExW(source, destination, MoveFileWriteThrough))
        {
            return;
        }

        var error = Marshal.GetLastPInvokeError();
        var inner = new Win32Exception(error);
        if (error is ErrorFileExists or ErrorAlreadyExists)
        {
            throw Collision("The durable publication destination already exists.", inner);
        }

        var state = !File.Exists(source) && File.Exists(destination)
            ? DurablePublicationFailureState.PostRenamePossiblyCommitted
            : DurablePublicationFailureState.PreRename;
        throw Failure(state, "The Windows durable move failed.", inner);
    }

    private static void PublishUnix(string source, string destination, string directory)
    {
        int result;
        if (OperatingSystem.IsLinux())
        {
            result = RenameAt2(AtFdcwd, source, AtFdcwd, destination, RenameNoReplace);
        }
        else if (OperatingSystem.IsMacOS())
        {
            result = RenameExclusiveMac(source, destination, RenameExclusive);
        }
        else
        {
            throw new PlatformNotSupportedException("Durable publication supports Linux, macOS, and Windows.");
        }

        if (result != 0)
        {
            var error = Marshal.GetLastPInvokeError();
            var inner = new Win32Exception(error);
            if (error == UnixAlreadyExists)
            {
                throw Collision("The durable publication destination already exists.", inner);
            }

            var state = !File.Exists(source) && File.Exists(destination)
                ? DurablePublicationFailureState.PostRenamePossiblyCommitted
                : DurablePublicationFailureState.PreRename;
            throw Failure(state, "The atomic no-replace rename failed.", inner);
        }

        var directoryHandle = OpenDirectory(directory);
        if (directoryHandle < 0)
        {
            var error = Marshal.GetLastPInvokeError();
            throw PostRename(
                "The published file may have committed, but its parent directory could not be opened.",
                new Win32Exception(error));
        }

        try
        {
            while (Fsync(directoryHandle) != 0)
            {
                var error = Marshal.GetLastPInvokeError();
                if (error == UnixInterrupted)
                {
                    continue;
                }

                throw PostRename(
                    "The published file may have committed, but its parent directory could not be flushed.",
                    new Win32Exception(error));
            }
        }
        finally
        {
            _ = Close(directoryHandle);
        }
    }

    private static int OpenDirectory(string directory)
    {
        var flags = OperatingSystem.IsLinux()
            ? RuntimeInformation.ProcessArchitecture switch
            {
                Architecture.X64 => LinuxX64Directory | LinuxX64NoFollow,
                Architecture.Arm64 => LinuxArm64Directory | LinuxArm64NoFollow,
                _ => throw new PlatformNotSupportedException(
                    "Durable publication supports Linux x64 and arm64.")
            }
            : MacDirectory | MacNoFollow;
        while (true)
        {
            var handle = Open(directory, flags);
            if (handle >= 0 || Marshal.GetLastPInvokeError() != UnixInterrupted)
            {
                return handle;
            }
        }
    }

    private static DurablePublicationException PreRename(string message, Exception? inner = null) =>
        Failure(DurablePublicationFailureState.PreRename, message, inner);

    private static DurablePublicationException Collision(string message, Exception? inner = null) =>
        Failure(DurablePublicationFailureState.Collision, message, inner);

    private static DurablePublicationException PostRename(string message, Exception? inner = null) =>
        Failure(DurablePublicationFailureState.PostRenamePossiblyCommitted, message, inner);

    private static DurablePublicationException Failure(
        DurablePublicationFailureState state,
        string message,
        Exception? inner = null) => new(state, message, inner);

    [DllImport("kernel32.dll", EntryPoint = "MoveFileExW", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool MoveFileExW(string existingFileName, string newFileName, uint flags);

    [DllImport("libc", EntryPoint = "renameat2", SetLastError = true)]
    private static extern int RenameAt2(
        int oldDirectoryFileDescriptor,
        string oldPath,
        int newDirectoryFileDescriptor,
        string newPath,
        uint flags);

    [DllImport("libSystem.B.dylib", EntryPoint = "renamex_np", SetLastError = true)]
    private static extern int RenameExclusiveMac(string oldPath, string newPath, uint flags);

    [DllImport("libc", EntryPoint = "open", SetLastError = true)]
    private static extern int Open(string path, int flags);

    [DllImport("libc", EntryPoint = "fsync", SetLastError = true)]
    private static extern int Fsync(int fileDescriptor);

    [DllImport("libc", EntryPoint = "close", SetLastError = true)]
    private static extern int Close(int fileDescriptor);
}
