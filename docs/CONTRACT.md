# Proximity contract

The domain supports authenticated tag reads, trusted member encounters and
trusted distance/location observations. Each result names exactly what the
mechanism establishes; none implies person uniqueness or relay resistance.

The NTAG adapter verifies bounded NDEF data through maintained `ntag424`, checks
the enrolled UID and authenticated counter, then calls atomic host `State` with
opaque identity/replay keys. Quota identity is caller-scoped. Tag counter identity
is global within the configured source domain so a changed window cannot rearm
an old read. SDM does not authenticate the host action, wall-clock read time or
physical distance; a captured unused read may still be relayed later.

The open observer `Adapter` is trusted application code, not member JSON. It
must independently authenticate subject, event ID, timestamp and the complete
request context. The library checks subject, peer or conservative WGS84 radius,
including both explicit accuracy bounds. Source quality remains caller policy;
probabilistic GPS accuracy is not silently upgraded to a hard bound.

Before any potentially billed observer call, an exact/maximum sourced tariff
must pass cfbk planning and permit validation. Effective validity never exceeds
the tariff or action deadline. Required `DispatchState` atomically reserves the
operation and total host budget before the adapter is invoked. Duplicates and
uncertain operations refuse redispatch; host state owns reconciliation and
cross-process persistence. Separate `State` atomically enforces quota and replay
following successful authentication. No database pool/connection or file cache
enters the library.

Complete upstream fields are available only by explicit request in RAM. Default
results expose guarantee and expiry; raw UID/location is discarded. Provider
extensions are available data, not automatically authenticated facts. Identity
keys are stable privacy configuration distinct from provider credentials.
Simulation uses the same observation predicates, identity transform and cfbk
cascade with dummy data and separate output types. Sandbox outputs cannot
construct a production proof or reserve production usage.

Tests use actual upstream tag vectors, geodesics and concurrent host-state
examples. Concrete reader/ranging/GNSS vendors remain candidates; no live
hardware/provider/sandbox operation has run. See [provider notes](PROVIDERS.md).

Async verification receives a trusted live clock, for example
`verify(..., || trusted_now())`. The library samples it at admission, after
operation reservation, after the provider returns and after atomic consumption.
Clock rollback refuses the operation. Expiry is exclusive: no fresh proof is
returned at or beyond its deadline. Tariff expiry controls dispatch; it does not
invalidate a timely proof from a request already sent under a valid tariff.
Transports must also check a fresh clock immediately before I/O after their own
queue waits. Atomic state ports must check proof validity within their transaction.
Late refusals preserve requested private responses and never automatically undo
committed usage or release potentially billed exposure.
Observation age and location/encounter predicates are rechecked at completion
and after registration; a queued result cannot retain its earlier freshness.
