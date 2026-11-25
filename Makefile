# NK build and test entry points. `make help` lists them.
# The loader and kernel only build for the UEFI targets, so bare cargo is
# not enough: use these targets.

CARGO ?= cargo

.PHONY: help test clippy fmt fmt-check gate clean

help:
	@echo "NK make targets:"
	@echo "  test       host unit tests (pure library crates)"
	@echo "  clippy     lint, warnings are errors"
	@echo "  fmt        format the tree"
	@echo "  fmt-check  fail if the tree is not formatted"
	@echo "  gate       everything a commit must pass; prints GATE-OK"
	@echo "  clean      remove all build and test output"

test:
	$(CARGO) test

clippy:
	$(CARGO) clippy --all-targets -- -D warnings

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all -- --check

gate:
	@tools/gate.sh

clean:
	$(CARGO) clean
