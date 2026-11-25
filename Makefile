# NK build and test entry points. `make help` lists them.
# The loader and kernel only build for the UEFI targets, so bare cargo is
# not enough: use these targets.

CARGO ?= cargo

VERSION := $(shell sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)
DIST := target/dist

.PHONY: help dist build build-arm check check-arm boot-gate run run-arm test clippy clippy-arm fmt fmt-check fixtures ledger ledger-check gate ci clean

help:
	@echo "NK make targets:"
	@echo "  build      loader + kernel for x86-64      (build-arm: arm64)"
	@echo "  check      boot test under QEMU, x86-64    (check-arm: arm64)"
	@echo "  boot-gate  every boot scenario a commit must pass, in parallel"
	@echo "  run        boot with a serial console      (run-arm: arm64)"
	@echo "  dist       release boot images for both architectures (target/dist/)"
	@echo "  test       host unit tests (library crates and the test harness)"
	@echo "  clippy     lint x86-64 + host, warnings are errors (clippy-arm: arm64)"
	@echo "  fmt        format the tree"
	@echo "  fmt-check  fail if the tree is not formatted"
	@echo "  fixtures   download and verify the driver fixtures (target/fixtures/)"
	@echo "  ledger     regenerate the compatibility ledger (ledger/)"
	@echo "  gate       everything a commit must pass; prints GATE-OK"
	@echo "  ci         the subset of the gate that hosted CI runs (no KVM there)"
	@echo "  clean      remove all build and test output"

X86 := x86_64-unknown-uefi
ARM := aarch64-unknown-uefi
KERNEL_CRATES := -p nkload -p nkkrnl

build:
	$(CARGO) build --release --target $(X86) $(KERNEL_CRATES)

build-arm:
	$(CARGO) build --release --target $(ARM) $(KERNEL_CRATES)

# Boot tests pick up whatever fixtures are downloaded; a missing one is
# reported by the kernel as a SKIP.
check: build fixtures
	@tools/boot_test.py x86_64

check-arm: build-arm fixtures
	@tools/boot_test.py aarch64

# Every scenario of the gate tier (tools/scenarios.toml): the main boot of
# each architecture, plus the boots that must end in a bugcheck or a
# reported failure.
boot-gate: build build-arm fixtures
	@tools/boot_test.py --tier gate

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
	$(CARGO) clippy --release --target $(X86) $(KERNEL_CRATES) -- -D warnings

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

gate:
	@tools/gate.sh

ci:
	@tools/gate.sh ci

clean:
	$(CARGO) clean
