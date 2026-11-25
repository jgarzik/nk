#!/usr/bin/env python3
"""The reference Windows machine: run test drivers on real Windows.

Usage:
  oracle.py check              replay every oracle/*.script on Windows and
                               compare with the committed transcript
  oracle.py record <name>      replay oracle/<name>.script and write
                               oracle/<name>.txt
  oracle.py build              install Windows into the base image (once)
  oracle.py run <dir>          boot a throwaway copy, run <dir>/nk-run.cmd in
                               it with <dir> as a disk, print what it wrote
  oracle.py shot               save a screenshot of a running build (debug)

`check` and `record` replay a script twice and require the same transcript
both times. A replay is cached by the hash of everything that went into it
(script, runner, driver, Windows image), so `check` boots Windows only for
what changed. See oracle/README.md.

Windows is Microsoft's Windows 10 Enterprise 22H2 evaluation ISO (build
19045.2006), fetched by URL and SHA-256 into the cache. `build` installs
it unattended under QEMU/KVM, turns on test-signing so WDK-built test
drivers load, and leaves an agent that, at every boot, runs `nk-run.cmd`
from whichever disk carries one and powers off.

`run` never changes the base image: it boots a copy-on-write overlay that
is deleted afterwards. The files to run travel on a small FAT disk built
from <dir>; the output comes back on the same disk as `nk-out.txt`.

Everything lives under $NK_CACHE (default ~/.cache/nk): iso/, winvm/.
Nothing here is part of the gate or of CI: it needs KVM, a 5.5 GB download
and about 20 minutes for the first build.
"""

import ctypes
import hashlib
import json
import os
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import tomllib
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ORACLE = ROOT / "oracle"
FIXTURES = ROOT / "target" / "fixtures"
WINDOWS = "Windows 10.0.19045.2006 (x86-64)"
PREFIX = "NK-ORACLE "

CACHE = Path(os.environ.get("NK_CACHE", Path.home() / ".cache" / "nk"))
ISO_URL = ("https://software-static.download.prss.microsoft.com/dbazure/"
           "988969d5-f34g-4e03-ac9d-1f9786c66750/19045.2006.220908-0225.22h2_release_svc_refresh"
           "_CLIENTENTERPRISEEVAL_OEMRET_x64FRE_en-us.iso")
ISO_SHA256 = "ef7312733a9f5d7d51cfa04ac497671995674ca5e1058d5164d6028f0938d668"
ISO = CACHE / "iso" / "win10-22h2-eval-x64.iso"
VM = CACHE / "winvm"
OVMF_CODE = "/usr/share/OVMF/OVMF_CODE_4M.fd"
OVMF_VARS = "/usr/share/OVMF/OVMF_VARS_4M.fd"
BUILD_TIMEOUT = int(os.environ.get("ORACLE_BUILD_TIMEOUT", "5400"))
RUN_TIMEOUT = int(os.environ.get("ORACLE_RUN_TIMEOUT", "600"))
# An evaluation install runs for 90 days; rebuild before that.
MAX_AGE_DAYS = 80
PASSWORD = "nk-oracle-1"

_LIBC = ctypes.CDLL(None, use_errno=True)


def die_with_parent():
    _LIBC.prctl(1, signal.SIGKILL)


AUTOUNATTEND = f"""<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend"
          xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
  <settings pass="windowsPE">
    <component name="Microsoft-Windows-International-Core-WinPE" processorArchitecture="amd64"
               publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <SetupUILanguage><UILanguage>en-US</UILanguage></SetupUILanguage>
      <InputLocale>en-US</InputLocale><SystemLocale>en-US</SystemLocale>
      <UILanguage>en-US</UILanguage><UserLocale>en-US</UserLocale>
    </component>
    <component name="Microsoft-Windows-Setup" processorArchitecture="amd64"
               publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <DiskConfiguration>
        <Disk wcm:action="add">
          <DiskID>0</DiskID><WillWipeDisk>true</WillWipeDisk>
          <CreatePartitions>
            <CreatePartition wcm:action="add"><Order>1</Order><Type>EFI</Type><Size>100</Size></CreatePartition>
            <CreatePartition wcm:action="add"><Order>2</Order><Type>MSR</Type><Size>16</Size></CreatePartition>
            <CreatePartition wcm:action="add"><Order>3</Order><Type>Primary</Type><Extend>true</Extend></CreatePartition>
          </CreatePartitions>
          <ModifyPartitions>
            <ModifyPartition wcm:action="add"><Order>1</Order><PartitionID>1</PartitionID><Format>FAT32</Format><Label>System</Label></ModifyPartition>
            <ModifyPartition wcm:action="add"><Order>2</Order><PartitionID>3</PartitionID><Format>NTFS</Format><Label>Windows</Label><Letter>C</Letter></ModifyPartition>
          </ModifyPartitions>
        </Disk>
      </DiskConfiguration>
      <ImageInstall><OSImage>
        <InstallTo><DiskID>0</DiskID><PartitionID>3</PartitionID></InstallTo>
        <InstallFrom><MetaData wcm:action="add"><Key>/IMAGE/INDEX</Key><Value>1</Value></MetaData></InstallFrom>
      </OSImage></ImageInstall>
      <UserData><AcceptEula>true</AcceptEula></UserData>
    </component>
  </settings>
  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64"
               publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <ComputerName>NK-ORACLE</ComputerName><TimeZone>UTC</TimeZone>
    </component>
  </settings>
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64"
               publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <InputLocale>en-US</InputLocale><SystemLocale>en-US</SystemLocale>
      <UILanguage>en-US</UILanguage><UserLocale>en-US</UserLocale>
    </component>
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64"
               publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <OOBE>
        <HideEULAPage>true</HideEULAPage><HideOnlineAccountScreens>true</HideOnlineAccountScreens>
        <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE><HideLocalAccountScreen>true</HideLocalAccountScreen>
        <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
        <ProtectYourPC>3</ProtectYourPC>
        <SkipMachineOOBE>true</SkipMachineOOBE><SkipUserOOBE>true</SkipUserOOBE>
      </OOBE>
      <UserAccounts>
        <AdministratorPassword><Value>{PASSWORD}</Value><PlainText>true</PlainText></AdministratorPassword>
      </UserAccounts>
      <AutoLogon>
        <Enabled>true</Enabled><Username>Administrator</Username><LogonCount>99999</LogonCount>
        <Password><Value>{PASSWORD}</Value><PlainText>true</PlainText></Password>
      </AutoLogon>
      <FirstLogonCommands>
        <SynchronousCommand wcm:action="add"><Order>1</Order>
          <CommandLine>cmd /c "for %d in (D E F G H) do if exist %d:\\nk-setup.cmd call %d:\\nk-setup.cmd"</CommandLine>
        </SynchronousCommand>
      </FirstLogonCommands>
    </component>
  </settings>
</unattend>
"""

# Runs once, at the first logon, from the answer disc.
SETUP_CMD = r"""@echo off
mkdir C:\nk
copy /y "%~dp0nk-agent.cmd" C:\nk\agent.cmd
reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v nk-agent /t REG_SZ /d "cmd /c C:\nk\agent.cmd" /f
bcdedit /set testsigning on
powercfg /change standby-timeout-ac 0
powercfg /change monitor-timeout-ac 0
echo setup done > C:\nk\setup-done.txt
shutdown /s /t 5 /f
"""

# Runs at every logon: find the disk that carries a job, run it, power off.
AGENT_CMD = r"""@echo off
for %%d in (D E F G H I J) do if exist %%d:\nk-run.cmd (
  %%d:
  cd \
  call nk-run.cmd > nk-out.txt 2>&1
  echo nk-run exit %errorlevel% >> nk-out.txt
  shutdown /s /t 0 /f
  exit /b
)
"""


def log(msg):
    print(f"oracle: {msg}", flush=True)


def fetch_iso():
    if ISO.exists():
        return
    ISO.parent.mkdir(parents=True, exist_ok=True)
    part = ISO.with_suffix(".part")
    log(f"downloading the evaluation ISO (5.5 GB) to {ISO}")
    request = urllib.request.Request(ISO_URL, headers={"User-Agent": "nk-fixture-fetch"})
    digest = hashlib.sha256()
    with urllib.request.urlopen(request) as response, open(part, "wb") as out:
        while chunk := response.read(1 << 20):
            digest.update(chunk)
            out.write(chunk)
    if digest.hexdigest() != ISO_SHA256:
        part.unlink()
        sys.exit("oracle: the ISO does not have the pinned SHA-256")
    part.rename(ISO)


def qmp(directory, commands):
    results = []
    try:
        with socket.socket(socket.AF_UNIX) as s:
            s.settimeout(20)
            cwd = os.getcwd()
            os.chdir(directory)
            try:
                s.connect("qmp.sock")
            finally:
                os.chdir(cwd)
            f = s.makefile("rw")

            def reply():
                while True:
                    msg = json.loads(f.readline())
                    if "return" in msg or "error" in msg:
                        return msg

            json.loads(f.readline())
            for command in [{"execute": "qmp_capabilities"}] + commands:
                f.write(json.dumps(command) + "\n")
                f.flush()
                results.append(reply())
    except (OSError, ValueError) as e:
        results.append({"error": str(e)})
    return results[1:]


def screenshot(directory, name="screen.png"):
    return qmp(directory, [{"execute": "screendump",
                            "arguments": {"filename": name, "format": "png"}}])


def qemu(directory, disk, extra, timeout, on_tick=None):
    """Run Windows until it powers off. `directory` holds vars.fd and the
    QMP socket. Returns True if it powered off within `timeout`."""
    cmd = [
        "qemu-system-x86_64", "-machine", "q35", "-enable-kvm", "-cpu", "host",
        "-smp", "4", "-m", "4096",
        "-drive", f"if=pflash,format=raw,readonly=on,file={OVMF_CODE}",
        "-drive", "if=pflash,format=raw,file=vars.fd",
        "-drive", f"if=none,id=hd,format=qcow2,file={disk}",
        "-device", "ide-hd,drive=hd,bus=ide.0,bootindex=1",
        "-nic", "none", "-display", "none", "-vga", "std", "-monitor", "none",
        "-serial", "none", "-qmp", "unix:qmp.sock,server=on,wait=off",
    ] + extra
    proc = subprocess.Popen(cmd, cwd=directory, stdin=subprocess.DEVNULL,
                            start_new_session=True, preexec_fn=die_with_parent)
    start = time.monotonic()
    try:
        while proc.poll() is None:
            elapsed = time.monotonic() - start
            if elapsed > timeout:
                screenshot(directory, "timeout.png")
                return False
            if on_tick:
                on_tick(elapsed)
            time.sleep(1)
        return proc.returncode == 0
    finally:
        if proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        proc.wait()
        (directory / "qmp.sock").unlink(missing_ok=True)


def build():
    if not os.access("/dev/kvm", os.R_OK | os.W_OK):
        sys.exit("oracle: KVM is required")
    fetch_iso()
    work = VM / "build"
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    try:
        answer = work / "answer"
        answer.mkdir()
        (answer / "autounattend.xml").write_text(AUTOUNATTEND)
        (answer / "nk-setup.cmd").write_text(SETUP_CMD.replace("\n", "\r\n"))
        (answer / "nk-agent.cmd").write_text(AGENT_CMD.replace("\n", "\r\n"))
        subprocess.run(["xorriso", "-as", "mkisofs", "-quiet", "-J", "-r", "-V", "NKANSWER",
                        "-o", work / "answer.iso", answer], check=True, capture_output=True)
        shutil.copyfile(OVMF_VARS, work / "vars.fd")
        subprocess.run(["qemu-img", "create", "-q", "-f", "qcow2", work / "base.qcow2", "40G"],
                       check=True)

        def tick(elapsed):
            # Firmware offers the disc with "Press any key to boot from CD
            # or DVD" for a few seconds; nothing else is watching for keys
            # this early.
            if elapsed < 25:
                qmp(work, [{"execute": "send-key",
                            "arguments": {"keys": [{"type": "qcode", "data": "ret"}]}}])
            elif int(elapsed) % 60 == 0:
                screenshot(work)

        log("installing Windows (about 20 minutes)")
        ok = qemu(work, "base.qcow2", [
            "-drive", f"if=none,id=cd,media=cdrom,format=raw,readonly=on,file={ISO}",
            "-device", "ide-cd,drive=cd,bus=ide.1,bootindex=2",
            "-drive", "if=none,id=ans,media=cdrom,format=raw,readonly=on,file=answer.iso",
            "-device", "ide-cd,drive=ans,bus=ide.2",
        ], BUILD_TIMEOUT, tick)
        if not ok:
            sys.exit(f"oracle: the install did not finish; see {work}/timeout.png")
        for name in ("base.qcow2", "vars.fd"):
            (work / name).replace(VM / name)
        (VM / "meta.json").write_text(json.dumps({"built": time.time(), "iso": ISO_SHA256}) + "\n")
        log(f"base image ready: {VM / 'base.qcow2'}")
    finally:
        if (VM / "meta.json").exists() or not os.environ.get("KEEP"):
            shutil.rmtree(work, ignore_errors=True)


def base_ready():
    try:
        meta = json.loads((VM / "meta.json").read_text())
    except (OSError, ValueError):
        return False
    age = (time.time() - meta["built"]) / 86400
    return meta.get("iso") == ISO_SHA256 and age < MAX_AGE_DAYS and (VM / "base.qcow2").exists()


PART_START = 2048  # sectors
DISK_MB = 64


def make_job_disk(image, source):
    """A disk with one FAT16 partition holding the files of `source`."""
    sectors = DISK_MB * 2048
    with open(image, "wb") as f:
        f.truncate(sectors * 512)
        entry = struct.pack("<B3sB3sII", 0, b"\x00\x02\x00", 0x0E, b"\xfe\xff\xff",
                            PART_START, sectors - PART_START)
        f.seek(446)
        f.write(entry)
        f.seek(510)
        f.write(b"\x55\xaa")
    target = f"{image}@@{PART_START * 512}"
    subprocess.run(["mformat", "-i", target, "-v", "NKJOB", "::"], check=True, capture_output=True)
    for path in sorted(Path(source).iterdir()):
        if path.is_file():
            subprocess.run(["mcopy", "-i", target, path, "::"], check=True, capture_output=True)
    return target


def run(source):
    """Boot Windows with the files of `source` as a disk and return what
    its nk-run.cmd printed (None if Windows never powered off)."""
    if not base_ready():
        build()
    work = VM / f"run-{os.getpid()}"
    work.mkdir(parents=True)
    try:
        shutil.copyfile(VM / "vars.fd", work / "vars.fd")
        subprocess.run(["qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2",
                        "-b", VM / "base.qcow2", work / "overlay.qcow2"], check=True)
        target = make_job_disk(work / "job.img", source)
        ok = qemu(work, "overlay.qcow2", [
            "-drive", "if=none,id=job,format=raw,file=job.img",
            "-device", "ide-hd,drive=job,bus=ide.1",
        ], RUN_TIMEOUT)
        out = subprocess.run(["mtype", "-i", target, "::nk-out.txt"], capture_output=True)
        extras = {}
        listing = subprocess.run(["mdir", "-b", "-i", target, "::"], capture_output=True, text=True)
        for name in listing.stdout.split():
            name = name.removeprefix("::/")
            if name.lower().startswith("nk-save"):
                data = subprocess.run(["mtype", "-i", target, f"::{name}"], capture_output=True)
                extras[name] = data.stdout
        if not ok and os.environ.get("KEEP"):
            shutil.copyfile(work / "timeout.png", VM / "run-timeout.png")
        return (out.stdout.decode(errors="replace") if out.returncode == 0 else None), ok, extras
    finally:
        shutil.rmtree(work, ignore_errors=True)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def drivers_of(script):
    """{file name in the script: bytes} for its `load` steps, taken from
    the x86-64 fixture of the same name."""
    manifest = tomllib.loads((ROOT / "fixtures" / "manifest.toml").read_text())["fixture"]
    drivers = {}
    for line in script.splitlines():
        words = line.split()
        if words[:1] != ["load"]:
            continue
        stem = Path(words[2]).stem
        matches = [fx for fx in manifest
                   if fx["name"] == stem and fx["arch"] == "x86_64" and "kind" not in fx]
        if len(matches) != 1:
            sys.exit(f"oracle: no x86-64 fixture called {stem!r} in fixtures/manifest.toml")
        path = FIXTURES / matches[0]["file"]
        if not path.exists():
            sys.exit(f"oracle: {path} is not downloaded (run: make fixtures)")
        drivers[words[2]] = path.read_bytes()
    return drivers


def header(script, drivers):
    lines = [f"# Recorded on {WINDOWS} by tools/oracle.py. Do not edit.",
             f"# script sha256 {sha256(script.encode())}"]
    lines += [f"# driver {name} sha256 {sha256(data)}" for name, data in sorted(drivers.items())]
    return lines


def replay(name):
    """The transcript real Windows gives for oracle/<name>.script, as a
    list of lines. Replayed twice; the two must agree."""
    script = (ORACLE / f"{name}.script").read_text()
    runner = (ORACLE / "runner.ps1").read_bytes()
    drivers = drivers_of(script)
    key = sha256(b"\0".join([script.encode(), runner, ISO_SHA256.encode(),
                             AGENT_CMD.encode(), SETUP_CMD.encode()]
                            + [n.encode() + d for n, d in sorted(drivers.items())]))
    cached = CACHE / "oracle" / f"{name}-{key[:32]}.txt"
    if cached.exists():
        log(f"{name}: cached")
        return header(script, drivers) + cached.read_text().splitlines()

    runs = []
    for attempt in (1, 2):
        with tempfile.TemporaryDirectory(prefix="nk-oracle-") as job:
            job = Path(job)
            (job / "runner.ps1").write_bytes(runner)
            (job / f"{name}.script").write_text(script)
            for file, data in drivers.items():
                (job / file).write_bytes(data)
            (job / "nk-run.cmd").write_text(
                "@echo off\r\npowershell -NoProfile -ExecutionPolicy Bypass "
                f'-File "%~dp0runner.ps1" "%~dp0." {name}\r\n')
            log(f"{name}: replaying on Windows ({attempt} of 2)")
            text, ok, _ = run(job)
        if text is None or not ok:
            sys.exit(f"oracle: {name}: Windows did not finish the script")
        lines = [l.strip()[len(PREFIX):] for l in text.splitlines() if l.startswith(PREFIX)]
        if not lines or lines[-1] != "end":
            sys.exit(f"oracle: {name}: the transcript is incomplete:\n{text}")
        runs.append(lines)
    if runs[0] != runs[1]:
        diff = [f"  {a!r}\n  {b!r}" for a, b in zip(*runs) if a != b]
        sys.exit(f"oracle: {name}: two replays on Windows differ:\n" + "\n".join(diff))
    cached.parent.mkdir(parents=True, exist_ok=True)
    cached.write_text("\n".join(runs[0]) + "\n")
    return header(script, drivers) + runs[0]


def record(name):
    path = ORACLE / f"{name}.txt"
    path.write_text("\n".join(replay(name)) + "\n")
    log(f"wrote {path.relative_to(ROOT)}")
    return 0


def check():
    status = 0
    for script in sorted(ORACLE.glob("*.script")):
        name = script.stem
        want = (ORACLE / f"{name}.txt").read_text().splitlines()
        got = replay(name)
        if got == want:
            log(f"{name}: matches Windows ({len(got)} lines)")
            continue
        status = 1
        log(f"{name}: oracle/{name}.txt is not what Windows says now:")
        for i in range(max(len(got), len(want))):
            a = want[i] if i < len(want) else "(absent)"
            b = got[i] if i < len(got) else "(absent)"
            if a != b:
                print(f"  line {i + 1}\n    file:    {a}\n    Windows: {b}")
    return status


def main():
    args = sys.argv[1:]
    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, lambda n, _: sys.exit(128 + n))
    if args == ["build"]:
        build()
        return 0
    if args == ["check"]:
        return check()
    if len(args) == 2 and args[0] == "record":
        return record(args[1])
    if args == ["shot"]:
        print(screenshot(VM / "build"))
        return 0
    if len(args) == 2 and args[0] == "run":
        text, ok, extras = run(args[1])
        if text is None:
            sys.exit("oracle: Windows produced no nk-out.txt" + ("" if ok else " (timed out)"))
        sys.stdout.write(text)
        for name, data in extras.items():
            (Path(args[1]) / name).write_bytes(data)
        return 0 if ok else 1
    sys.exit(__doc__)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
