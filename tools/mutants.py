#!/usr/bin/env python3
"""Mutation checks: break the kernel on purpose and require a test to fail.

A test that still passes when the thing it tests is broken proves nothing.
Each file in tools/mutants/ describes one deliberate break:

    # Why this break matters, in a line or two.
    scenario: x86_64
    fails: cpu.fp-preserved
    file: kernel/arch/x86_64/trap.rs
    remove:     movups xmm3, xmmword ptr [rsp + 48]

`remove:` deletes the first line of the file equal to the text after
`remove: ` (leading spaces count); `occurrence: 3` picks the third such
line instead. `replace:` followed by `with:` swaps the line instead of
deleting it. `fails:` names the test that must report FAIL, or is
`scenario` when the scenario as a whole must fail (one that expects a
particular bugcheck, say, and no longer gets it).

Usage: mutants.py [--jobs N] [--fat] [name...]   (default: every mutant)

When running multiple mutants with `--jobs N` (default `min(6, cpus // 4)`,
override via `MUTANT_JOBS`), each worker operates in its own temporary
`git worktree` under `target/mutant-worktrees/` with a symlink to
`target/fixtures/`, leaving the main working tree untouched and keeping host
CPU usage bounded. Builds default to `CARGO_PROFILE_RELEASE_LTO=thin` (with
automatic retry under full `lto=fat` if a mutant does not catch under thin
LTO); pass `--fat` or `MUTANT_LTO=fat` to always build with full LTO.
"""

import argparse
from collections import deque
import concurrent.futures
import os
import re
import shutil
import subprocess
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MUTANTS = ROOT / "tools" / "mutants"
WORKTREES = ROOT / "target" / "mutant-worktrees"


def default_jobs():
    """Bounded worker count: uses ~25% of host cores so the host stays responsive."""
    env = os.environ.get("MUTANT_JOBS")
    if env:
        return max(1, int(env))
    cpus = os.cpu_count() or 1
    return min(6, max(1, cpus // 4))


def parse(path):
    fields = {}
    for line in path.read_text().splitlines():
        if line.startswith("#") or not line.strip():
            continue
        key, _, value = line.partition(":")
        # One space separates the key from its text; the rest is literal.
        fields[key] = value[1:] if value.startswith(" ") else value
    missing = {"scenario", "fails", "file"} - fields.keys()
    if missing or ("remove" in fields) == ("replace" in fields):
        sys.exit(f"mutants: {path.name}: needs scenario, fails, file and one of remove/replace")
    if "replace" in fields and "with" not in fields:
        sys.exit(f"mutants: {path.name}: replace needs with")
    return fields


def mutate(text, fields, name):
    target = fields.get("remove", fields.get("replace"))
    lines = text.split("\n")
    matches = [i for i, line in enumerate(lines) if line == target]
    occurrence = int(fields.get("occurrence", "1"))
    if len(matches) < occurrence:
        sys.exit(f"mutants: {name}: {fields['file']} has {len(matches)} lines equal to "
                 f"{target!r}, not {occurrence}")
    at = matches[occurrence - 1]
    lines[at:at + 1] = [] if "remove" in fields else [fields["with"]]
    return "\n".join(lines)


def arch_of(name):
    fields = parse(MUTANTS / f"{name}.mutant")
    return "aarch64" if fields["scenario"].startswith("aarch64") else "x86_64"


def build_env(thin_lto, parallel_workers):
    env = dict(os.environ)
    env["BOOT_TEST_TIMEOUT"] = os.environ.get("MUTANT_TIMEOUT", "90")
    if thin_lto:
        env["CARGO_PROFILE_RELEASE_LTO"] = "thin"
        env["CARGO_PROFILE_RELEASE_CODEGEN_UNITS"] = "4"
    else:
        env.pop("CARGO_PROFILE_RELEASE_LTO", None)
        env.pop("CARGO_PROFILE_RELEASE_CODEGEN_UNITS", None)
    if parallel_workers > 1:
        env.setdefault("CARGO_BUILD_JOBS", "2")
    return env


def run_once(name, root, thin_lto=True, parallel_workers=1):
    """Run one mutant in `root`. Returns `(caught, message)`."""
    fields = parse(MUTANTS / f"{name}.mutant")
    source = root / fields["file"]
    original = source.read_bytes()
    arch = "aarch64" if fields["scenario"].startswith("aarch64") else "x86_64"
    build = "build-arm" if arch == "aarch64" else "build"
    env = build_env(thin_lto, parallel_workers)
    try:
        source.write_text(mutate(original.decode(), fields, name))
        built = subprocess.run(["make", "--no-print-directory", build], cwd=root,
                               capture_output=True, text=True, env=env)
        if built.returncode != 0:
            return False, f"{name}: the mutant does not build:\n{built.stderr[-2000:]}"
        boot = subprocess.run([root / "tools" / "boot_test.py", fields["scenario"]],
                              cwd=root, capture_output=True, text=True, env=env)
        out = boot.stdout
    finally:
        source.write_bytes(original)
    wanted = fields["fails"]
    caught = wanted == "scenario" or bool(
        re.search(rf"NK-TEST {re.escape(wanted)}:FAIL", out))
    if boot.returncode == 0:
        return False, f"{name}: SURVIVED: the boot passed with the kernel broken"
    if not caught:
        return False, f"{name}: the boot failed, but not as expected ({wanted}):\n{out[-1500:]}"
    return True, f"{name}: caught ({wanted})"


def run(name, root=ROOT, thin_lto=True, parallel_workers=1):
    """True if the mutant was caught (retrying under fat LTO if thin LTO missed)."""
    ok, msg = run_once(name, root, thin_lto=thin_lto, parallel_workers=parallel_workers)
    if not ok and thin_lto:
        ok_fat, msg_fat = run_once(name, root, thin_lto=False, parallel_workers=parallel_workers)
        if ok_fat:
            return True, f"{msg_fat} [fat-lto retry]"
        return False, msg_fat
    return ok, msg


def working_tree_changes(root=ROOT):
    """Return `(to_copy, to_delete)` relative paths representing uncommitted
    working-tree state relative to `HEAD`: modified tracked files, untracked
    non-ignored files, and locally deleted tracked files."""
    diff = subprocess.run(["git", "diff", "--name-only", "HEAD"], cwd=root,
                          capture_output=True, text=True, check=True)
    untracked = subprocess.run(["git", "ls-files", "--others", "--exclude-standard"], cwd=root,
                               capture_output=True, text=True, check=True)
    to_copy, to_delete = [], []
    seen = set()
    for rel in diff.stdout.splitlines():
        rel = rel.strip()
        if not rel or rel in seen:
            continue
        seen.add(rel)
        if (root / rel).exists():
            to_copy.append(rel)
        else:
            to_delete.append(rel)
    for rel in untracked.stdout.splitlines():
        rel = rel.strip()
        if not rel or rel in seen:
            continue
        seen.add(rel)
        if (root / rel).exists():
            to_copy.append(rel)
    return to_copy, to_delete


def sync_working_tree(src_root, dst_root, to_copy, to_delete):
    """Mirror uncommitted additions, modifications, and deletions from
    `src_root` into `dst_root`."""
    for rel in to_delete:
        dst = dst_root / rel
        if dst.exists() or dst.is_symlink():
            dst.unlink()
    for rel in to_copy:
        src = src_root / rel
        dst = dst_root / rel
        if src.is_dir():
            continue
        if src.exists():
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)


def create_worktree(index, to_copy, to_delete):
    wdir = WORKTREES / f"w{index}"
    if wdir.exists():
        subprocess.run(["git", "worktree", "remove", "--force", str(wdir)],
                       cwd=ROOT, capture_output=True)
        shutil.rmtree(wdir, ignore_errors=True)
    wdir.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "worktree", "add", "--detach", "--force", str(wdir), "HEAD"],
                   cwd=ROOT, capture_output=True, text=True, check=True)
    sync_working_tree(ROOT, wdir, to_copy, to_delete)
    (wdir / "target").mkdir(parents=True, exist_ok=True)
    fixtures_dst = wdir / "target" / "fixtures"
    if not fixtures_dst.exists():
        os.symlink(ROOT / "target" / "fixtures", fixtures_dst)
    return wdir


def remove_worktree(wdir):
    subprocess.run(["git", "worktree", "remove", "--force", str(wdir)],
                   cwd=ROOT, capture_output=True)
    shutil.rmtree(wdir, ignore_errors=True)


def run_parallel(names, jobs, thin_lto):
    """Run `names` across `jobs` isolated worktrees, grouping arm64 mutants on
    worker 0 so only one worker cold-compiles aarch64 dependencies."""
    arm_q = deque(n for n in names if arch_of(n) == "aarch64")
    x86_q = deque(n for n in names if arch_of(n) != "aarch64")
    q_lock = threading.Lock()
    print_lock = threading.Lock()
    total = len(names)
    done = [0]
    results = {}

    def next_mutant(worker_id):
        with q_lock:
            primary, fallback = (arm_q, x86_q) if worker_id == 0 and arm_q else (x86_q, arm_q)
            if primary:
                return primary.popleft()
            if fallback:
                return fallback.popleft()
            return None

    to_copy, to_delete = working_tree_changes()
    worktrees = []
    try:
        subprocess.run(["git", "worktree", "prune"], cwd=ROOT, capture_output=True)
        worktrees = [create_worktree(i, to_copy, to_delete) for i in range(jobs)]

        def worker(worker_id):
            wdir = worktrees[worker_id]
            while True:
                name = next_mutant(worker_id)
                if name is None:
                    return
                ok, msg = run(name, root=wdir, thin_lto=thin_lto, parallel_workers=jobs)
                with print_lock:
                    done[0] += 1
                    results[name] = ok
                    print(f"[{done[0]}/{total}] {msg}", flush=True)

        with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
            futs = [pool.submit(worker, i) for i in range(jobs)]
            for fut in futs:
                fut.result()
    finally:
        for wdir in worktrees:
            remove_worktree(wdir)
        subprocess.run(["git", "worktree", "prune"], cwd=ROOT, capture_output=True)
        shutil.rmtree(WORKTREES, ignore_errors=True)

    return [results[n] for n in names]


def parse_args(argv):
    p = argparse.ArgumentParser(description="Run kernel mutation checks.")
    p.add_argument("--jobs", "-j", type=int, default=default_jobs(),
                   help="Parallel worktree workers (default: min(6, cpus // 4) or MUTANT_JOBS).")
    p.add_argument("--fat", action="store_true",
                   default=os.environ.get("MUTANT_LTO", "").lower() == "fat",
                   help="Always build mutants with full fat LTO instead of thin LTO.")
    p.add_argument("names", nargs="*", help="Mutant names to run (default: all).")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    names = args.names or sorted(p.stem for p in MUTANTS.glob("*.mutant"))
    if not names:
        sys.exit("mutants: none defined")
    thin_lto = not args.fat
    jobs = max(1, min(args.jobs, len(names)))
    if jobs == 1:
        results = []
        try:
            for i, name in enumerate(names, 1):
                ok, msg = run(name, root=ROOT, thin_lto=thin_lto, parallel_workers=1)
                print(f"[{i}/{len(names)}] {msg}", flush=True)
                results.append(ok)
        finally:
            # Leave binaries that match the sources again.
            subprocess.run(["make", "--no-print-directory", "build", "build-arm"], cwd=ROOT,
                           capture_output=True)
    else:
        lto_label = "thin-lto (fat fallback)" if thin_lto else "fat-lto"
        print(f"mutants: running {len(names)} mutants across {jobs} worktrees ({lto_label})",
              flush=True)
        results = run_parallel(names, jobs, thin_lto)
    survivors = results.count(False)
    print(f"mutants: {len(results) - survivors} of {len(results)} caught", flush=True)
    return 1 if survivors else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
