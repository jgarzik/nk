# Launch a /subsystem:native PE executable on reference Windows via
# ntdll!RtlCreateUserProcess, wait for it to exit, and print its transcript.
#
#   powershell -ExecutionPolicy Bypass -File run-native.ps1 <exePath> <outFile>

param(
    [Parameter(Mandatory=$true)][string]$ExePath,
    [Parameter(Mandatory=$true)][string]$OutFile
)

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class NativeRunner {
    [StructLayout(LayoutKind.Sequential)]
    struct UNICODE_STRING { public ushort Length, MaximumLength; public IntPtr Buffer; }

    [StructLayout(LayoutKind.Sequential)]
    struct CLIENT_ID { public IntPtr UniqueProcess, UniqueThread; }

    [StructLayout(LayoutKind.Sequential)]
    struct SECTION_IMAGE_INFORMATION {
        public IntPtr TransferAddress;
        public uint ZeroBits;
        public IntPtr MaximumStackSize;
        public IntPtr CommittedStackSize;
        public uint SubSystemType;
        public uint SubSystemVersion;
        public uint OperatingSystemVersion;
        public ushort ImageCharacteristics;
        public ushort DllCharacteristics;
        public ushort Machine;
        public byte ImageContainsCode;
        public byte ImageFlags;
        public uint LoaderFlags;
        public uint ImageFileSize;
        public uint CheckSum;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct RTL_USER_PROCESS_INFORMATION {
        public uint Length;
        public IntPtr Process;
        public IntPtr Thread;
        public CLIENT_ID ClientId;
        public SECTION_IMAGE_INFORMATION ImageInformation;
    }

    [DllImport("ntdll.dll")]
    static extern uint RtlCreateProcessParametersEx(
        out IntPtr pProcessParameters,
        ref UNICODE_STRING ImagePathName,
        IntPtr DllPath,
        IntPtr CurrentDirectory,
        ref UNICODE_STRING CommandLine,
        IntPtr Environment,
        IntPtr WindowTitle,
        IntPtr DesktopInfo,
        IntPtr ShellInfo,
        IntPtr RuntimeData,
        uint Flags);

    [DllImport("ntdll.dll")]
    static extern uint RtlDestroyProcessParameters(IntPtr ProcessParameters);

    [DllImport("ntdll.dll")]
    static extern uint RtlCreateUserProcess(
        ref UNICODE_STRING NtImagePathName,
        uint Attributes,
        IntPtr ProcessParameters,
        IntPtr ProcessSecurityDescriptor,
        IntPtr ThreadSecurityDescriptor,
        IntPtr ParentProcess,
        byte InheritHandles,
        IntPtr DebugPort,
        IntPtr ExceptionPort,
        ref RTL_USER_PROCESS_INFORMATION ProcessInformation);

    [DllImport("ntdll.dll")]
    static extern uint NtResumeThread(IntPtr ThreadHandle, out uint PreviousSuspendCount);

    [DllImport("ntdll.dll")]
    static extern uint NtWaitForSingleObject(IntPtr Handle, byte Alertable, IntPtr Timeout);

    [DllImport("ntdll.dll")]
    static extern uint NtClose(IntPtr Handle);

    static UNICODE_STRING MakeUs(string s) {
        UNICODE_STRING u = new UNICODE_STRING();
        u.Length = (ushort)(s.Length * 2);
        u.MaximumLength = (ushort)(s.Length * 2 + 2);
        u.Buffer = Marshal.StringToHGlobalUni(s);
        return u;
    }

    public static uint Run(string ntImagePath, string cmdLine) {
        UNICODE_STRING img = MakeUs(ntImagePath);
        UNICODE_STRING cmd = MakeUs(cmdLine);
        IntPtr procParams = IntPtr.Zero;
        uint st = RtlCreateProcessParametersEx(out procParams, ref img, IntPtr.Zero,
            IntPtr.Zero, ref cmd, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
            IntPtr.Zero, 1 /* RTL_USER_PROC_PARAMS_NORMALIZED */);
        if (st != 0) {
            Marshal.FreeHGlobal(img.Buffer);
            Marshal.FreeHGlobal(cmd.Buffer);
            return st;
        }
        RTL_USER_PROCESS_INFORMATION info = new RTL_USER_PROCESS_INFORMATION();
        info.Length = (uint)Marshal.SizeOf(info);
        st = RtlCreateUserProcess(ref img, 0x40 /* OBJ_CASE_INSENSITIVE */, procParams,
            IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0, IntPtr.Zero, IntPtr.Zero, ref info);
        RtlDestroyProcessParameters(procParams);
        Marshal.FreeHGlobal(img.Buffer);
        Marshal.FreeHGlobal(cmd.Buffer);
        if (st != 0) return st;

        uint prev = 0;
        NtResumeThread(info.Thread, out prev);
        NtWaitForSingleObject(info.Process, 0, IntPtr.Zero);
        NtClose(info.Thread);
        NtClose(info.Process);
        return 0;
    }
}
"@

$ntExe = "\??\$ExePath"
$ntOut = "\??\$OutFile"
$cmdLine = "`"$ExePath`" $ntOut"
$st = [NativeRunner]::Run($ntExe, $cmdLine)
if ($st -ne 0) {
    Write-Output ("NATIVE-RUNNER-ERROR: 0x{0:x8}" -f $st)
    exit 1
}
if (Test-Path $OutFile) {
    Get-Content -Raw $OutFile
} else {
    Write-Output "NATIVE-RUNNER-ERROR: output file not created: $OutFile"
    exit 1
}
