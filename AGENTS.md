# Agent instructions

Write all code comments and documentation in English.

## Product boundary

- Proximity gate for cvld (placeholder): proof of physical presence, for example via an NFC tag.
- Would prove physical presence and return an opaque gate proof with its trust anchor.
- No location data or tag identifiers in `cvld` output, logs, errors or fixtures.
- This crate is LGPL-3.0-only WITH LGPL-3.0-linking-exception. Do not add implementation code available only under the full GPL or AGPL.

## Quality boundary

- `cargo fmt --check`, `cargo clippy --all-targets` (no warnings),
  `cargo test` — all green before every commit. No local workstation
  builds; use GHA, Crow as fallback.
