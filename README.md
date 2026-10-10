# cpxm — proximity expertise

A reusable domain library for physical tags, trusted encounters and location.
The application chooses the requirement, scope, registration limit, information
projection and state retention. cpxm authenticates and transforms through its
adapters. A phone's location claim is not automatically a proof of presence.

| Mechanism | Implementation | Guarantee |
|---|---|---|
| NTAG 424 DNA SDM | Real `ntag424` maintained Rust verifier, current compatible 0.1.x | Authentic configured tag UID and read counter; replay checked atomically by host. No clock freshness, action challenge binding, physical distance or relay resistance. |
| Trusted member encounter | Working observer integration port + fixture adapter | Adapter authenticates subject, expected peer, context and timestamp. Concrete BLE/UWB/reader vendor transports are candidates, not supplied here. |
| Trusted position/radius | Observer integration port + real `geographiclib-rs` WGS84 geodesics | Distance plus both accuracy bounds must fit the radius. Source authenticity remains the trusted observer adapter's responsibility. |

## Tag flow

Configure upstream `ntag424::sdm::Verifier` from enrolled tag settings, provisioned
file/meta keys and trusted expected UID. Supply a domain-separated `Blinding` key.
`Tag::verify` authenticates a bounded NDEF read using upstream crypto, rejects
missing UID/counter or the wrong enrolled UID, then invokes caller atomic state.
A public factory-zero-key vector is tested; deploy only privately provisioned keys.
No provisioning or NFC hardware command is issued by this library.

`State::reserve` enforces the caller's general at-most-X registration rule AND
replay prevention in one atomic transaction. It receives only opaque identity and
evidence keys. Tag counter identity is independent of scope/window, so changing a
quota window cannot rearm an old read. Host policy must handle counter exhaustion,
replacement tags and key rotation explicitly. A captured unused read can still be
relayed or submitted later: SDM does not authenticate the host action or read time.
Use a trusted reader/other mechanism when these stronger guarantees are required.

## Observer flow

Implement `observation::Adapter` with a maintained vendor/protocol authenticator.
Only trusted application code supplies this adapter; raw browser JSON must never
be treated as an authenticated `Observation`. The returned context must bind the
whole `Request::binding`, not only a loose member identifier. The library checks
subject, fresh context, observation ID/time, expected peer or location predicate.

Construct a pure `preview` from an explicit current fee/tariff with source and
exclusive validity; the effective deadline is the earlier tariff/action expiry. Select
eligible candidates through `cfbk::cost::Plan`. Pass its move-only permit to
`Service::verify`. The library requires `DispatchState::reserve_dispatch` for the
quoted operation identity/exposure before calling an adapter. Use configured or cheapest bounded-cost order;
pending/uncertain results stop fallback and retain fee exposure. Native cfbk
plans do not replace cross-process atomic operation/budget storage.

Location checks use a conservative full-uncertainty-radius inclusion. GPS accuracy
usually expresses a confidence level, not a hard bound; the caller must choose
whether that observation quality meets its policy. No conversion to a stronger
physical guarantee occurs. All numeric inputs reject NaN/infinity/invalid ranges.

## Cost, simulation and data

Local tag/geodesic verification has zero third-party service fee (`local_quote`),
not zero CPU, reader or hardware cost. Observer adapters may have provider costs:
configure exact or maximum prices including internal fallbacks and account fees.
Unknown/expired quotes cannot authorize production dispatch. No implicit free tier.

`simulate` runs the real encounter/geodesic predicates, scoped identity transform
and cfbk cost cascade with explicit dummy observations/outcomes. It returns a
distinct `Simulation` and touches no state, hardware, adapter or network. Public
simulation keys are only for dummy data. Tag authentication is exercised by real
upstream-vector tests; this simulator cannot make a tag read. Provider Sandbox
requires a separately configured adapter and produces a separate output; it cannot
reserve production registrations or yield `Proof`. No sandbox is assumed free.

All credentials, tag identities, coordinates and upstream payloads remain in RAM.
No SQL/database pool, filesystem cache, environment discovery or automatic logger.
The host supplies credentials and a random >=32-byte stable blinding key plus the
actual source identity domain. Do not unify unrelated vendor person namespaces.
Key rotation needs explicit host migration to retain quotas/replay protections.
Zeroizing key owners reduce lifetime; upstream copies, host swap and dumps are
outside the library's erasure guarantee.

`Disclosure::Minimal` returns just guarantee + expiry. `Complete` relays all
available upstream fields, including decrypted NTAG fields or arbitrary observer
JSON. These private outputs have no Debug implementation. Host persistence is
explicit; arbitrary provider fields do not become authenticated facts by being
included in JSON.

## Arsenal and limits

NFC SDM is implemented through an independent upstream, not NXP-endorsed. Secure
reader challenge/response, UWB ranging, authenticated member encounters, beacon
attestation and trusted GNSS/location services can implement the observer port.
BLE RSSI, IP geolocation, unsigned QR codes and browser GPS are low-assurance
signals; do not admit them to a stronger required capability. Fallback compares
only adapters that actually satisfy the requested guarantee.

Primary references checked 2026-10-10:
[ntag424](https://docs.rs/ntag424/latest/ntag424/),
[NXP NTAG 424 DNA data sheet](https://www.nxp.com/docs/en/data-sheet/NT4H2421Gx.pdf),
[GeographicLib Rust](https://github.com/georust/geographiclib-rs).

Tests use an actual public NTAG vector, real geodesic calculation, and explicit
trusted-observer dummies. Coverage includes privacy transformation, context,
expiry, counters, quota refusal, cost bindings, modes, ambiguity and rich fields.
No live hardware, billable provider or external sandbox call has been executed.

Async verification takes a trusted live clock (`|| trusted_now()`), rechecked
after each awaited boundary. Expired results and clock rollback refuse a new proof.

See [the contract](docs/CONTRACT.md) and [provider notes](docs/PROVIDERS.md).

Complete response access also applies to bounded provider replies that fail a
predicate or atomic consumption. Inspect `Error::report()` explicitly;
`Error::category()` preserves the domain failure used for orchestration. Reports
remain RAM-only, redact Debug/Display, and cannot create a verified proof. Trusted
extension adapters can use `Error::with_report` for their own available errors.

`tag::Tag::simulate` exercises actual local NTAG authentication using explicitly
configured fixture keys and a dummy state decision. It shares cryptographic
verification with production and returns a distinct result without touching
replay/quota state. Tag verification itself performs no network or reader I/O.
