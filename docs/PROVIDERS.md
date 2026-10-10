# Proximity integrations and credential contracts

| Integration | Implemented | Evidence limits |
|---|---|---|
| NTAG 424 DNA SDM | Maintained `ntag424` verification, expected UID and counter validation, scoped HMAC projection and atomic replay/quota port | Real public NXP vector tests; no provisioning, reader I/O or live hardware qualification. Does not prove clock freshness, action binding, distance or anti-relay. |
| Trusted encounter | Authenticated observer port and exact peer/context/time projection | Concrete vendor transport must authenticate; fixture adapter is not a live integration. |
| Trusted distance/location | Observer port plus maintained WGS84 `geographiclib-rs`, conservative uncertainty-radius predicate | Accuracy/source trust remain explicit. Browser GPS, IP location and BLE RSSI do not automatically meet a stronger guarantee. |
| Secure readers, UWB ranging, GNSS attesters and encounter platforms | Candidates implementing the open port | Distinct identity domains, protocol authentication, hardware trust, quote and mode validation must be supplied. No vendor enabled by this catalogue. |

Configure [ntag424](https://docs.rs/ntag424/latest/ntag424/sdm/struct.Verifier.html)
with trusted enrolled SDM settings, provisioned file/meta keys and expected UID.
The maintained verifier checks the MAC, then the library checks UID/counter.
Use privately provisioned keys in deployment; public zero-key vectors are inert
tests. The library never provisions a tag or contacts a reader.
[NXP's data sheet](https://www.nxp.com/docs/en/data-sheet/NT4H2421Gx.pdf)
describes the mechanism; this integration is not vendor endorsement.

Geodesic processing uses [GeographicLib Rust](https://github.com/georust/geographiclib-rs).
Caller target and provider positions must have finite coordinates/accuracy. The
whole uncertainty region must fall inside the selected radius. No local ranging
or cryptographic protocol is invented.

Inject a random stable blinding key >=32 bytes and the actual source identity
domain. Unrelated providers cannot be merged into invented person identities.
Plan key migration to retain counts and monotonic replay state; resetting quota
windows cannot reset tag counters. Adapter credentials are separately injected,
rotatable and RAM-only. No environment discovery, database connection, secret
logging or hidden SDK persistence is allowed.

Local verification has no external service charge, while hardware, CPU and
subscription costs remain separate. Any observer network action needs an explicit
exact or defensible maximum fee, provenance, denomination and expiry before I/O.
Unknown prices refuse dispatch; price lookup is not performed implicitly. Host
DispatchState must reserve operation identity/budget atomically across workers
and restarts. Ambiguous results retain exposure and cannot initiate fallback.

Production and provider sandbox are explicit adapter modes with separate outputs.
Sandbox is not assumed free. Local simulation accepts no adapter, credential or
state port and exercises real predicate/HMAC/cost transformations on dummy data.
No live tag, location, carrier, provider or sandbox call was executed for tests.
Owned keys are zeroized; upstream temporary copies and host swap/dumps prevent a
claim of perfect process-memory erasure.
