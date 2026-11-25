# Testing

Windows defines the expected behaviour. Until a Windows reference VM
exists, expectations come from Microsoft's documentation and from reading
the fixture binaries, and the ledger says so.

## Host unit tests

`make test`. Pure functions in `lib/` crates, tested on the build host.
Tests build their inputs in code (for example, synthetic PE images) so
they need no downloaded files. Tests that do use a fetched fixture report
that they were skipped when it is absent.

## The gate

`make gate` runs every check a commit must pass and prints `GATE-OK`.
Each commit passes it alone, so history is bisectable.
