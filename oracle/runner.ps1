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
    static extern uint NtCreateNamedPipeFile(out IntPtr handle, uint access,
        ref OBJECT_ATTRIBUTES oa, out IO_STATUS_BLOCK iosb, uint share, uint disposition,
        uint options, uint type, uint readMode, uint completionMode, uint maxInstances,
        uint inQuota, uint outQuota, ref long timeout);

    [DllImport("ntdll.dll")]
    static extern uint NtDeviceIoControlFile(IntPtr handle, IntPtr ev, IntPtr apc, IntPtr ctx,
        ref IO_STATUS_BLOCK iosb, uint code, byte[] input, uint inputLength,
        byte[] output, uint outputLength);

    // The same, with buffers by address.
    [DllImport("ntdll.dll", EntryPoint = "NtDeviceIoControlFile")]
    static extern uint NtDeviceIoControlFileAt(IntPtr handle, IntPtr ev, IntPtr apc, IntPtr ctx,
        ref IO_STATUS_BLOCK iosb, uint code, IntPtr input, uint inputLength,
        IntPtr output, uint outputLength);

    [DllImport("ntdll.dll")]
    static extern uint NtFsControlFile(IntPtr handle, IntPtr ev, IntPtr apc, IntPtr ctx,
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

    // The attributes that name a path, from a root handle if that is not
    // zero. What they point to is freed by Release.
    static OBJECT_ATTRIBUTES Named(string path, IntPtr root) {
        UNICODE_STRING name = new UNICODE_STRING();
        name.Length = (ushort)(path.Length * 2);
        name.MaximumLength = (ushort)(path.Length * 2 + 2);
        name.Buffer = Marshal.StringToHGlobalUni(path);
        OBJECT_ATTRIBUTES oa = new OBJECT_ATTRIBUTES();
        oa.Length = Marshal.SizeOf(oa);
        oa.RootDirectory = root;
        oa.ObjectName = Marshal.AllocHGlobal(Marshal.SizeOf(name));
        Marshal.StructureToPtr(name, oa.ObjectName, false);
        oa.Attributes = 0x40; // OBJ_CASE_INSENSITIVE
        return oa;
    }

    static void Release(OBJECT_ATTRIBUTES oa) {
        UNICODE_STRING name =
            (UNICODE_STRING)Marshal.PtrToStructure(oa.ObjectName, typeof(UNICODE_STRING));
        Marshal.FreeHGlobal(name.Buffer);
        Marshal.FreeHGlobal(oa.ObjectName);
    }

    // Open (FILE_OPEN) an object-manager path, or a path below a root handle.
    public static uint Open(string path, IntPtr root, uint access, uint share, uint options,
            out IntPtr handle) {
        OBJECT_ATTRIBUTES oa = Named(path, root);
        IO_STATUS_BLOCK iosb;
        uint status = NtCreateFile(out handle, access, ref oa, out iosb, IntPtr.Zero,
            0, share, 1, options, IntPtr.Zero, 0);
        Release(oa);
        return status;
    }

    // Create an instance of a named pipe; the timeout is in milliseconds.
    public static uint Pipe(string path, uint access, uint share, uint disposition,
            uint options, uint type, uint readMode, uint completionMode, uint maxInstances,
            uint inQuota, uint outQuota, uint timeout, out IntPtr handle) {
        OBJECT_ATTRIBUTES oa = Named(path, IntPtr.Zero);
        IO_STATUS_BLOCK iosb;
        long relative = -10000L * timeout;
        uint status = NtCreateNamedPipeFile(out handle, access, ref oa, out iosb, share,
            disposition, options, type, readMode, completionMode, maxInstances,
            inQuota, outQuota, ref relative);
        Release(oa);
        return Done(status, iosb);
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

    // Device control with each buffer either an array of the caller's
    // (null for none) or, without one, the address and length given.
    public static uint IoctlAt(IntPtr handle, uint code, byte[] input, ulong inputAt,
            uint inputLength, byte[] output, ulong outputAt, uint outputLength) {
        GCHandle inputPin = new GCHandle(), outputPin = new GCHandle();
        IntPtr inputPtr = new IntPtr(unchecked((long)inputAt));
        IntPtr outputPtr = new IntPtr(unchecked((long)outputAt));
        if (input != null) {
            inputPin = GCHandle.Alloc(input, GCHandleType.Pinned);
            inputPtr = input.Length == 0 ? IntPtr.Zero : inputPin.AddrOfPinnedObject();
            inputLength = (uint)input.Length;
        }
        if (output != null) {
            outputPin = GCHandle.Alloc(output, GCHandleType.Pinned);
            outputPtr = output.Length == 0 ? IntPtr.Zero : outputPin.AddrOfPinnedObject();
            outputLength = (uint)output.Length;
        }
        IO_STATUS_BLOCK iosb = Fresh();
        uint status = NtDeviceIoControlFileAt(handle, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
            ref iosb, code, inputPtr, inputLength, outputPtr, outputLength);
        if (inputPin.IsAllocated) inputPin.Free();
        if (outputPin.IsAllocated) outputPin.Free();
        return Done(status, iosb);
    }

    public static uint Fsctl(IntPtr handle, uint code, byte[] input, byte[] output) {
        IO_STATUS_BLOCK iosb = Fresh();
        return Done(NtFsControlFile(handle, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
            ref iosb, code, input.Length == 0 ? null : input, (uint)input.Length,
            output.Length == 0 ? null : output, (uint)output.Length), iosb);
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

# The `key=value` fields of a step from field $from on, over $defaults;
# nothing if one of them is not a key of $defaults.
function Options([string[]]$w, [int]$from, [hashtable]$defaults) {
    $o = $defaults.Clone()
    for ($i = $from; $i -lt $w.Length; $i++) {
        $key, $value = $w[$i] -split "=", 2
        if (-not $defaults.ContainsKey($key)) { return $null }
        $o[$key] = $value
    }
    return $o
}

function Hex32([string]$text) { return [Convert]::ToUInt32($text, 16) }

# "@<address>:<length>" as (address, length); nothing for any other text.
function At([string]$text) {
    if (-not $text.StartsWith("@")) { return $null }
    $address, $length = $text.Substring(1) -split ":", 2
    return [Convert]::ToUInt64($address, 16), [uint32]$length
}

function Running([string]$service) {
    return (sc.exe query $service | Select-String -Pattern "STATE\s+:\s+4\s") -ne $null
}

$handles = @{}
# The services `use` started and the files `install` put in place: stopped
# and removed when the script ends.
$started = @()
$installed = @()
foreach ($raw in Get-Content (Join-Path $Dir "$Name.script")) {
    $line = $raw.Trim()
    if ($line -eq "" -or $line.StartsWith("#")) { continue }
    $w = $line -split "\s+"
    Record "NK-BEGIN $line"
    switch ($w[0]) {
        "use" {
            # A driver that is part of Windows: running already, or
            # started here and stopped again at the end.
            $ok = "ok"
            if (-not (Running $w[1])) {
                sc.exe start $w[1] | Out-Null
                if ($LASTEXITCODE -eq 0) { $started += $w[1] } else { $ok = "failed" }
            }
            Say "use $($w[1]): $ok"
        }
        "install" {
            # Where the loader looks for what a driver imports from. A
            # file of that name already there is not replaced.
            $to = Join-Path $env:SystemRoot "System32\drivers\$($w[1])"
            $ok = "failed"
            if (-not (Test-Path $to)) {
                Copy-Item (Join-Path $Dir $w[1]) $to -ErrorAction SilentlyContinue
                if ($?) { $installed += $to; $ok = "ok" }
            }
            Say "install $($w[1]): $ok"
        }
        "debugger" {
            # The oracle boots Windows with debugging enabled for a
            # script that begins this way, and is the debugger.
            $on = (bcdedit /enum "{current}" | Select-String -Pattern "^debug\s+Yes") -ne $null
            $state = if ($on) { "attached" } else { "absent" }
            Say "debugger: $state"
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
            # GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE;
            # FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE
            $o = Options $w 3 @{ root = ""; access = "c0100000"; share = "0"; options = "60" }
            if ($null -eq $o -or ($o.root -ne "" -and -not $handles.ContainsKey($o.root))) {
                Say "error: bad option: $line"
                break
            }
            $root = if ($o.root -ne "") { $handles[$o.root] } else { [IntPtr]::Zero }
            $h = [IntPtr]::Zero
            $status = [Nt]::Open($w[2], $root, (Hex32 $o.access), (Hex32 $o.share),
                (Hex32 $o.options), [ref]$h)
            if ($status -eq 0) { $handles[$w[1]] = $h }
            Say ("$($w -join ' '): {0:x8}" -f $status)
        }
        "pipe" {
            # GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE; FILE_SHARE_READ |
            # FILE_SHARE_WRITE; FILE_OPEN_IF; FILE_SYNCHRONOUS_IO_NONALERT;
            # a byte stream read as bytes, requests wait.
            $o = Options $w 3 @{ access = "c0100000"; share = "3"; disposition = "3"
                options = "20"; type = "0"; read = "0"; completion = "0"; instances = "1"
                inquota = "4096"; outquota = "4096"; timeout = "50" }
            if ($null -eq $o) {
                Say "error: bad option: $line"
                break
            }
            $h = [IntPtr]::Zero
            $status = [Nt]::Pipe($w[2], (Hex32 $o.access), (Hex32 $o.share),
                [uint32]$o.disposition, (Hex32 $o.options), [uint32]$o.type, [uint32]$o.read,
                [uint32]$o.completion, [uint32]$o.instances, [uint32]$o.inquota,
                [uint32]$o.outquota, [uint32]$o.timeout, [ref]$h)
            if ($status -eq 0) { $handles[$w[1]] = $h }
            Say "$($w -join ' '): $(Outcome $status)"
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
        "ioctlat" {
            # Each buffer is the runner's, as for `ioctl`, or an address.
            $inAt = At $w[3]
            $bytes = if ($null -eq $inAt) { Unhex $w[3] } else { $null }
            $outAt = At $w[4]
            $out = if ($null -eq $outAt) { Filled ([int]$w[4]) } else { $null }
            if ($null -eq $inAt) { $inAt = 0, 0 }
            if ($null -eq $outAt) { $outAt = 0, 0 }
            $status = [Nt]::IoctlAt($handles[$w[1]], [Convert]::ToUInt32($w[2], 16),
                $bytes, $inAt[0], $inAt[1], $out, $outAt[0], $outAt[1])
            $shown = if ($null -eq $out) { "-" } else { Hex $out }
            Say "$($w -join ' '): $(Outcome $status) $shown"
        }
        "fsctl" {
            $out = Filled ([int]$w[4])
            $status = [Nt]::Fsctl($handles[$w[1]], [Convert]::ToUInt32($w[2], 16), (Unhex $w[3]), $out)
            Say "fsctl $($w[1]) $($w[2]) $($w[3]) $($w[4]): $(Outcome $status) $(Hex $out)"
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
[array]::Reverse($started)
foreach ($service in $started) { sc.exe stop $service | Out-Null }
foreach ($file in $installed) { Remove-Item -Force $file }
Say "end"
