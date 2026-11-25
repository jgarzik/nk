# Replay an oracle script against real Windows and print the transcript.
#
#   powershell -ExecutionPolicy Bypass -File runner.ps1 <dir> <name>
#
# Reads <dir>\<name>.script and prints one line per step, each prefixed
# "NK-ORACLE ". The kernel's self-test (kernel/selftest/oracle.rs) replays
# the same script on NK and must print the same lines; README.md in this
# directory defines the script and the transcript.
#
# Requests go through the native API (ntdll), not Win32, so the status
# reported is the NTSTATUS the I/O manager returned, not a Win32 error code
# translated from it.

param([string]$Dir, [string]$Name)

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class Nt {
    [StructLayout(LayoutKind.Sequential)]
    struct UNICODE_STRING { public ushort Length, MaximumLength; public IntPtr Buffer; }

    [StructLayout(LayoutKind.Sequential)]
    struct OBJECT_ATTRIBUTES {
        public int Length; public IntPtr RootDirectory; public IntPtr ObjectName;
        public uint Attributes; public IntPtr SecurityDescriptor; public IntPtr SecurityQos;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IO_STATUS_BLOCK { public IntPtr Status; public IntPtr Information; }

    [DllImport("ntdll.dll")]
    static extern uint NtCreateFile(out IntPtr handle, uint access, ref OBJECT_ATTRIBUTES oa,
        out IO_STATUS_BLOCK iosb, IntPtr allocation, uint attributes, uint share,
        uint disposition, uint options, IntPtr ea, uint eaLength);

    [DllImport("ntdll.dll")]
    static extern uint NtDeviceIoControlFile(IntPtr handle, IntPtr ev, IntPtr apc, IntPtr ctx,
        ref IO_STATUS_BLOCK iosb, uint code, byte[] input, uint inputLength,
        byte[] output, uint outputLength);

    [DllImport("ntdll.dll")]
    static extern uint NtReadFile(IntPtr handle, IntPtr ev, IntPtr apc, IntPtr ctx,
        ref IO_STATUS_BLOCK iosb, byte[] buffer, uint length, IntPtr offset, IntPtr key);

    [DllImport("ntdll.dll")]
    static extern uint NtWriteFile(IntPtr handle, IntPtr ev, IntPtr apc, IntPtr ctx,
        ref IO_STATUS_BLOCK iosb, byte[] buffer, uint length, IntPtr offset, IntPtr key);

    [DllImport("ntdll.dll")]
    public static extern uint NtClose(IntPtr handle);

    public static ulong Information;

    // Open an object-manager path for synchronous reads and writes.
    public static uint Open(string path, out IntPtr handle) {
        IntPtr text = Marshal.StringToHGlobalUni(path);
        UNICODE_STRING name = new UNICODE_STRING();
        name.Length = (ushort)(path.Length * 2);
        name.MaximumLength = (ushort)(path.Length * 2 + 2);
        name.Buffer = text;
        IntPtr namePtr = Marshal.AllocHGlobal(Marshal.SizeOf(name));
        Marshal.StructureToPtr(name, namePtr, false);
        OBJECT_ATTRIBUTES oa = new OBJECT_ATTRIBUTES();
        oa.Length = Marshal.SizeOf(oa);
        oa.ObjectName = namePtr;
        oa.Attributes = 0x40; // OBJ_CASE_INSENSITIVE
        IO_STATUS_BLOCK iosb;
        // GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE; FILE_OPEN;
        // FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE
        uint status = NtCreateFile(out handle, 0xC0100000, ref oa, out iosb, IntPtr.Zero,
            0, 0, 1, 0x60, IntPtr.Zero, 0);
        Marshal.FreeHGlobal(namePtr);
        Marshal.FreeHGlobal(text);
        return status;
    }

    static IO_STATUS_BLOCK Fresh() {
        IO_STATUS_BLOCK iosb = new IO_STATUS_BLOCK();
        iosb.Information = new IntPtr(-1);
        return iosb;
    }

    static uint Done(uint status, IO_STATUS_BLOCK iosb) {
        Information = (ulong)iosb.Information.ToInt64();
        return status;
    }

    public static uint Ioctl(IntPtr handle, uint code, byte[] input, byte[] output) {
        IO_STATUS_BLOCK iosb = Fresh();
        return Done(NtDeviceIoControlFile(handle, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
            ref iosb, code, input.Length == 0 ? null : input, (uint)input.Length,
            output.Length == 0 ? null : output, (uint)output.Length), iosb);
    }

    public static uint Read(IntPtr handle, byte[] buffer) {
        IO_STATUS_BLOCK iosb = Fresh();
        return Done(NtReadFile(handle, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref iosb,
            buffer, (uint)buffer.Length, IntPtr.Zero, IntPtr.Zero), iosb);
    }

    public static uint Write(IntPtr handle, byte[] buffer) {
        IO_STATUS_BLOCK iosb = Fresh();
        return Done(NtWriteFile(handle, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref iosb,
            buffer, (uint)buffer.Length, IntPtr.Zero, IntPtr.Zero), iosb);
    }
}
"@

# What has been done so far, written through to the disk a line at a
# time: if a step stops Windows, this is all that is left to say which.
# The file is there already, at its full size, and is written in place:
# a file that grows needs its directory entry updated, and that would
# still be in memory when Windows stopped.
$steps = New-Object System.IO.FileStream((Join-Path $Dir "nk-save-steps.txt"),
    [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read,
    4096, [System.IO.FileOptions]::WriteThrough)
function Record([string]$line) {
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($line + "`r`n")
    $steps.Write($bytes, 0, $bytes.Length)
    $steps.Flush($true)
}

function Say([string]$line) {
    Record "NK-ORACLE $line"
    Write-Output "NK-ORACLE $line"
}

function Hex([byte[]]$bytes) {
    if ($bytes.Length -eq 0) { return "-" }
    return -join ($bytes | ForEach-Object { $_.ToString("x2") })
}

function Unhex([string]$text) {
    if ($text -eq "-") { return ,[byte[]]@() }
    $bytes = New-Object byte[] ($text.Length / 2)
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $bytes[$i] = [Convert]::ToByte($text.Substring($i * 2, 2), 16)
    }
    return ,$bytes
}

# A buffer the driver has not written keeps this fill, on both systems.
function Filled([int]$length) {
    $bytes = New-Object byte[] $length
    for ($i = 0; $i -lt $length; $i++) { $bytes[$i] = 0xEE }
    return ,$bytes
}

# "<status> <information>": the byte count only when the request did not
# fail (status below 0xC0000000), since Windows does not report one for a
# failed request.
function Outcome([uint32]$status) {
    $info = "-"
    if ([uint64]$status -lt 3221225472) { $info = [Nt]::Information.ToString() }
    return ("{0:x8} {1}" -f $status, $info)
}

$handles = @{}
foreach ($raw in Get-Content (Join-Path $Dir "$Name.script")) {
    $line = $raw.Trim()
    if ($line -eq "" -or $line.StartsWith("#")) { continue }
    $w = $line -split "\s+"
    Record "NK-BEGIN $line"
    switch ($w[0]) {
        "use" {
            # A driver that is part of Windows: nothing to load.
            Say "use $($w[1]): ok"
        }
        "load" {
            $file = Join-Path $Dir $w[2]
            sc.exe create $w[1] type= kernel binPath= $file | Out-Null
            sc.exe start $w[1] | Out-Null
            $ok = if ($LASTEXITCODE -eq 0) { "ok" } else { "failed" }
            Say "load $($w[1]): $ok"
        }
        "unload" {
            sc.exe stop $w[1] | Out-Null
            $ok = if ($LASTEXITCODE -eq 0) { "ok" } else { "failed" }
            sc.exe delete $w[1] | Out-Null
            Say "unload $($w[1]): $ok"
        }
        "open" {
            $h = [IntPtr]::Zero
            $status = [Nt]::Open($w[2], [ref]$h)
            if ($status -eq 0) { $handles[$w[1]] = $h }
            Say ("open $($w[1]) $($w[2]): {0:x8}" -f $status)
        }
        "close" {
            $status = [Nt]::NtClose($handles[$w[1]])
            $handles.Remove($w[1])
            Say ("close $($w[1]): {0:x8}" -f $status)
        }
        "ioctl" {
            $out = Filled ([int]$w[4])
            $status = [Nt]::Ioctl($handles[$w[1]], [Convert]::ToUInt32($w[2], 16), (Unhex $w[3]), $out)
            Say "ioctl $($w[1]) $($w[2]) $($w[3]) $($w[4]): $(Outcome $status) $(Hex $out)"
        }
        "read" {
            $out = Filled ([int]$w[2])
            $status = [Nt]::Read($handles[$w[1]], $out)
            Say "read $($w[1]) $($w[2]): $(Outcome $status) $(Hex $out)"
        }
        "write" {
            $status = [Nt]::Write($handles[$w[1]], (Unhex $w[2]))
            Say "write $($w[1]) $($w[2]): $(Outcome $status)"
        }
        default { Say "error: unknown step: $line" }
    }
}
Say "end"
