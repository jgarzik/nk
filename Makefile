# NK build and test entry points. `make help` lists them.
# The loader and kernel only build for the UEFI targets, so bare cargo is
# not enough: use these targets.

CARGO ?= cargo

VERSION := $(shell sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)
DIST := target/dist

.PHONY: help dist build build-arm check check-arm boot-fast boot-gate boot-full run run-arm test clippy clippy-arm fmt fmt-check fixtures ledger ledger-check unwind-check unwind-check-arm corpus oracle soak mutants coverage gate-fast gate gate-full clean

help:
	@echo "NK make targets:"
	@echo "  build      loader + kernel for x86-64      (build-arm: arm64)"
	@echo "  check      boot test under QEMU, x86-64    (check-arm: arm64)"
	@echo "  boot-fast  the boots of the fast gate: x86-64, the main scenario and those the change selects"
	@echo "  boot-gate  the boots of the batch gate: x86-64 (boot-full: every gate scenario, both architectures)"
	@echo "  run        boot with a serial console      (run-arm: arm64)"
	@echo "  dist       release boot images for both architectures (target/dist/)"
	@echo "  test       host unit tests (library crates and the test harness)"
	@echo "  clippy     lint x86-64 + host, warnings are errors (clippy-arm: arm64)"
	@echo "  fmt        format the tree"
	@echo "  fmt-check  fail if the tree is not formatted"
	@echo "  fixtures   download and verify the driver fixtures (target/fixtures/)"
	@echo "  ledger     regenerate the compatibility ledger (ledger/)"
	@echo "  ledger-check  the committed ledger is what the last boots printed"
	@echo "  unwind-check  x86-64 kernel code without unwind entries is on the allow-list (unwind-check-arm: arm64)"
	@echo "  corpus     download Microsoft's inbox binaries and check their committed import lists (network)"
	@echo "  oracle     replay the oracle scripts on real Windows (KVM; not in the gate)"
	@echo "  soak       the whole test list, many times, on an overloaded host"
	@echo "  mutants    break the kernel on purpose; each break must fail a test"
	@echo "  coverage   unit-test coverage of lib/, with a floor (needs cargo-llvm-cov)"
	@echo "  gate-fast  what every commit must pass; prints GATE-FAST-OK"
	@echo "  gate       what the merged tip of updates must pass; prints GATE-OK"
	@echo "  gate-full  both architectures, every scenario (nightly, milestones); prints GATE-FULL-OK"
	@echo "  clean      remove all build and test output"

X86 := x86_64-unknown-uefi
ARM := aarch64-unknown-uefi
KERNEL_CRATES := -p nkload -p nkkrnl
USER_CRATES := -p nkt

# Every function of the loader and kernel gets an unwind-table entry
# (`.pdata`), so the kernel's own frames can be walked. The variables
# name the target, so the host builds (`test`, the first half of
# `clippy`) are not touched.
UNWIND_TABLES := -C force-unwind-tables=yes
export CARGO_TARGET_X86_64_UNKNOWN_UEFI_RUSTFLAGS := $(UNWIND_TABLES)
export CARGO_TARGET_AARCH64_UNKNOWN_UEFI_RUSTFLAGS := $(UNWIND_TABLES)

build:
	$(CARGO) build --release --target $(X86) $(KERNEL_CRATES) $(USER_CRATES)

build-arm:
	$(CARGO) build --release --target $(ARM) $(KERNEL_CRATES)

# Boot tests pick up whatever fixtures are downloaded; a missing one is
# reported by the kernel as a SKIP.
check: build fixtures
	@tools/boot_test.py x86_64

check-arm: build-arm fixtures
	@tools/boot_test.py aarch64

# The boots of the three gates, each a selection of the gate tier
# (tools/scenarios.toml; tools/boot_test.py says which). boot-fast: the
# main x86-64 scenario and the x86-64 scenarios whose `paths` the branch
# changed. boot-gate: every x86-64 scenario that must pass, and those
# that must end in a bugcheck or a reported failure whose `paths` changed
# since this gate last passed. boot-full: all of them, on both
# architectures.
boot-fast: build fixtures
	@tools/boot_test.py --gate fast

boot-gate: build fixtures
	@tools/boot_test.py --gate batch

boot-full: build build-arm fixtures
	@tools/boot_test.py --gate full

run: build fixtures
	@tools/boot_test.py x86_64 --run

run-arm: build-arm fixtures
	@tools/boot_test.py aarch64 --run

# The layout test compares against the WDK tables among the fixtures.
# Release artifacts: one bootable EFI system partition image per
# architecture, holding only NK's loader and kernel. No Windows driver is
# included, so the images can be redistributed; booted as they are, the
# kernel runs its own self-tests and reports the driver tests as skipped.
dist: build build-arm
	@rm -rf $(DIST) && mkdir -p $(DIST)
	@tools/mkesp.py x86_64 $(DIST)/nk-$(VERSION)-x86_64.img --no-drivers
	@tools/mkesp.py aarch64 $(DIST)/nk-$(VERSION)-aarch64.img --no-drivers
	@tools/boot_test.py x86_64 --image $(DIST)/nk-$(VERSION)-x86_64.img
	@tools/boot_test.py aarch64 --image $(DIST)/nk-$(VERSION)-aarch64.img
	@gzip -9 -n $(DIST)/*.img
	@cd $(DIST) && sha256sum *.img.gz > SHA256SUMS && cat SHA256SUMS

test: fixtures
	$(CARGO) test
	python3 -m unittest discover -s tools -p 'test_*.py'

clippy:
	$(CARGO) clippy --all-targets -- -D warnings
	$(CARGO) clippy --release --target $(X86) $(KERNEL_CRATES) $(USER_CRATES) -- -D warnings

clippy-arm:
	$(CARGO) clippy --release --target $(ARM) $(KERNEL_CRATES) -- -D warnings

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all -- --check

# Offline is not a failure (status 2); wrong bytes are (status 1).
fixtures:
	@tools/fetch_fixtures.py; rc=$$?; [ $$rc -ne 1 ]

ledger: fixtures
	@tools/ledger.py

ledger-check: fixtures
	@tools/ledger.py --check

# The code of the kernel image that has no unwind entry is prebuilt
# library code, a leaf, or a symbol listed in tools/unwind/.
unwind-check: build
	@tools/unwind_coverage.py x86_64

unwind-check-arm: build-arm
	@tools/unwind_coverage.py aarch64

# Downloads the binaries of fixtures/corpus.toml and checks that the
# committed import lists, which the ledger counts, are what they import.
corpus:
	@tools/corpus.py check

# Replays oracle/*.script in the reference Windows VM and compares with
# the committed transcripts. Needs KVM; the first run downloads the
# evaluation ISO and installs it. See oracle/README.md.
oracle: fixtures
	@tools/oracle.py check

# Every scenario of the soak tier, SOAK_REPEAT times each (default 20),
# with the host deliberately overloaded. Long; run at the end of a phase
# and when anything about scheduling or locking changes.
soak: build build-arm fixtures
	@tools/boot_test.py --tier soak --repeat $(or $(SOAK_REPEAT),20)

# Applies each deliberate break in tools/mutants/ in turn, rebuilds, and
# requires the named test to fail. Slow (one build and boot per mutant),
# so not in the gate.
mutants: fixtures
	@tools/mutants.py

# Fails if any file in lib/ has under 95% of its lines run by the host
# unit tests. Needs cargo-llvm-cov, so it is not in the gate.
coverage: fixtures
	@tools/coverage.py

# The three gates (doc/TESTING.md): every commit passes the fast one, the
# merged tip of `updates` the batch one, and the full one runs nightly
# and at milestones.
gate-fast:
	@tools/gate.sh fast

gate:
	@tools/gate.sh batch

gate-full:
	@tools/gate.sh full

clean:
	$(CARGO) clean
