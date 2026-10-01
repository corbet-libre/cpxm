# cpxm

**Proximity admission gate for cvld (placeholder).**

`cpxm` is a placeholder for a proximity gate: proof that a member was physically present, for example by tapping an NFC tag. Mechanism and scope are not decided.

Status: name reserved, no implementation or qualified provider adapter yet.
Empty production coverage is a blocking failure. See
[the current contract](docs/CONTRACT.md).

One gate invocation performs one provider check; `cfbk` owns ordering and
fallback, with requirements supplied by `crbk`.

## Boundaries

What it does:

- Would prove physical presence and return an opaque gate proof bound to its configured provider.

What it never does:

- No location data or tag identifiers in `cvld` output, logs, errors or fixtures.

## License

Copyright 2026 Julian Y. Richard Corbet. Licensed under
[LGPL-3.0-only](LICENSES/LGPL-3.0-only.txt)
[WITH LGPL-3.0-linking-exception](LICENSES/LGPL-3.0-linking-exception.txt).
See [LICENSE.md](LICENSE.md).

## Continuous verification

Dependency updates follow main and are tested against one CI-resolved lockfile.
Line and branch coverage target 100%; failures remain blocking. See
[the coverage contract](docs/COVERAGE.md) for measurement and exclusions.
