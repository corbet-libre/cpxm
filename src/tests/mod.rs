use super::*;
use cfbk::cost::{CostOrder, DispatchPermit, Mode, Offer, Plan};
use cfbk::{Candidate, Config};
use futures::executor::block_on;
use observation::{Adapter, Observation, Position, Request, Requirement, Service, Verified};

fn context() -> Context<'static> {
    Context {
        scope: "opaque-scope",
        registration: "registration",
        maximum: 2,
        expires: 200,
    }
}
fn blind() -> Blinding {
    Blinding::new(vec![7; 32], "trusted-source-namespace".into()).unwrap()
}
#[derive(Default)]
struct Store {
    deny: bool,
    calls: Vec<(String, String, Option<u32>)>,
}
impl State for Store {
    fn reserve(
        &mut self,
        identity: &str,
        evidence: &str,
        counter: Option<u32>,
        context: &Context<'_>,
    ) -> bool {
        assert_eq!(identity.len(), 64);
        assert_eq!(evidence.len(), 64);
        assert_eq!(context.maximum, 2);
        self.calls.push((identity.into(), evidence.into(), counter));
        !self.deny
    }
}
fn settings(counter: bool) -> ntag424::types::file_settings::Sdm {
    use ntag424::types::file_settings::*;
    Sdm::try_new(
        PiccData::Encrypted {
            key: ntag424::KeyNumber::Key0,
            offset: Offset::new(10).unwrap(),
            content: if counter {
                EncryptedContent::Both(ReadCtrFeatures {
                    limit: None,
                    ret_access: CtrRetAccess::NoAccess,
                })
            } else {
                EncryptedContent::Uid
            },
        },
        Some(FileRead::MacOnly {
            key: ntag424::KeyNumber::Key0,
            window: MacWindow {
                input: Offset::new(42).unwrap(),
                mac: Offset::new(42).unwrap(),
            },
        }),
        None,
        CryptoMode::Aes,
    )
    .unwrap()
}
fn tag_with(uid: [u8; 7], key: [u8; 16]) -> tag::Tag {
    tag::Tag::new(
        ntag424::sdm::Verifier::try_new(
            &settings(true),
            ntag424::types::file_settings::CryptoMode::Aes,
        )
        .unwrap(),
        key,
        key,
        uid,
        blind(),
    )
    .unwrap()
}
fn tag() -> tag::Tag {
    tag_with([4, 0xde, 0x5f, 0x1e, 0xac, 0xc0, 0x40], [0; 16])
}
// NXP AN12196 table 4 public test vector, also used by the upstream verifier.
const NDEF: &[u8] = b"HELLOWORLDEF963FF7828658A599F3041510671E8894EED9EE65337086";

#[test]
fn real_tag_vector_transforms_private_identity_and_preserves_global_counter() {
    let engine = tag();
    let mut state = Store::default();
    let rich = engine
        .verify(NDEF, &context(), &mut state, Disclosure::Complete, 100)
        .unwrap();
    assert_eq!(rich.proof.guarantee(), Guarantee::TagRead);
    assert_eq!(rich.proof.expires(), 200);
    assert_eq!(rich.upstream.unwrap().read_ctr, Some(61));
    assert!(format!("{:?}", rich.proof).contains("TagRead"));
    assert!(
        engine
            .verify(NDEF, &context(), &mut state, Disclosure::Minimal, 100)
            .unwrap()
            .upstream
            .is_none()
    );
    engine
        .verify(
            NDEF,
            &Context {
                scope: "other",
                ..context()
            },
            &mut state,
            Disclosure::Minimal,
            100,
        )
        .unwrap();
    assert_eq!(state.calls[0], state.calls[1]);
    assert_ne!(state.calls[0].0, state.calls[2].0);
    assert_eq!(state.calls[0].1, state.calls[2].1);
    state.deny = true;
    assert!(matches!(
        engine.verify(NDEF, &context(), &mut state, Disclosure::Minimal, 100),
        Err(Error::State)
    ));
    let calls = state.calls.len();
    for bad in [vec![], vec![0; 257], vec![b'F'; NDEF.len()]] {
        assert!(
            engine
                .verify(&bad, &context(), &mut state, Disclosure::Minimal, 100)
                .is_err()
        );
    }
    assert!(
        tag_with([1; 7], [0; 16])
            .verify(NDEF, &context(), &mut state, Disclosure::Minimal, 100)
            .is_err()
    );
    assert!(
        tag_with([4, 0xde, 0x5f, 0x1e, 0xac, 0xc0, 0x40], [1; 16])
            .verify(NDEF, &context(), &mut state, Disclosure::Minimal, 100)
            .is_err()
    );
    assert_eq!(state.calls.len(), calls);
}

#[test]
fn invalid_context_blinding_and_simulation() {
    for c in [
        Context {
            scope: "",
            ..context()
        },
        Context {
            registration: "",
            ..context()
        },
        Context {
            maximum: 0,
            ..context()
        },
        Context {
            expires: 100,
            ..context()
        },
    ] {
        assert!(
            tag()
                .verify(NDEF, &c, &mut Store::default(), Disclosure::Minimal, 100)
                .is_err()
        );
    }
    assert!(Blinding::new(vec![0; 31], "domain".into()).is_err());
    assert!(Blinding::new(vec![0; 32], "".into()).is_err());
    assert_ne!(
        blind().key("subject", "scope", b"uid"),
        blind().key("subject", "different", b"uid")
    );
    assert_ne!(
        blind().key("subject", "scope", b"uid"),
        blind().key("evidence", "scope", b"uid")
    );
    for e in [
        Error::Configuration,
        Error::Rejected,
        Error::State,
        Error::Uncertain,
        Error::Cost,
    ] {
        assert!(!e.to_string().is_empty());
    }
}

struct Observer {
    mode: Mode,
    mutate: fn(&mut Observation),
    fail: bool,
}
impl Adapter for Observer {
    fn id(&self) -> &str {
        "observer-instance"
    }
    fn mode(&self) -> Mode {
        self.mode
    }
    async fn verify(
        &self,
        evidence: &[u8],
        context: &str,
        quote: &Quote,
    ) -> Result<Observation, Error> {
        assert_eq!(evidence, b"inert-evidence");
        assert!(quote.price.maximum().is_some());
        if self.fail {
            return Err(Error::Uncertain);
        }
        let mut result = Observation {
            subject: "subject".into(),
            context: context.into(),
            id: "authenticated-observation-id".into(),
            observed_at: 90,
            peer: Some("peer".into()),
            position: Some(position()),
            upstream: serde_json::json!({"unknown-field":[1,2,3]}),
        };
        (self.mutate)(&mut result);
        Ok(result)
    }
}
fn service() -> Service<Observer> {
    Service {
        adapter: Observer {
            mode: Mode::Production,
            mutate: |_| {},
            fail: false,
        },
        blinding: blind(),
    }
}
fn request() -> Request<'static> {
    Request {
        context: context(),
        subject: "subject",
        nonce: "fresh-opaque-nonce",
        max_age: 20,
        requirement: Requirement::Encounter { peer: "peer" },
    }
}
fn position() -> Position {
    Position {
        latitude: 47.0,
        longitude: 8.0,
        accuracy_m: 5.0,
    }
}
fn distance() -> Request<'static> {
    Request {
        requirement: Requirement::Distance {
            target: position(),
            radius_m: 10.0,
        },
        ..request()
    }
}
fn amount() -> Amount {
    Amount {
        unit: Unit {
            code: "TEST".into(),
            scale: 2,
        },
        atoms: 1,
    }
}
fn permit_for(
    service: &Service<Observer>,
    request: &Request<'_>,
    id: &str,
    changed: bool,
) -> DispatchPermit<String> {
    let mut quote = observation::preview(
        &service.adapter,
        request,
        b"inert-evidence",
        Price::AtMost(amount()),
        "fixture tariff".into(),
        200,
        100,
    )
    .unwrap();
    if changed {
        quote.binding = "wrong".into();
    }
    Plan::new(
        vec![Offer {
            candidate: Candidate::new(id.into(), ["proximity".to_string()]),
            quote,
        }],
        Config::new([id.into()], ["proximity".to_string()]),
        CostOrder::Configured,
        amount(),
        1,
        service.adapter.mode(),
        100,
    )
    .unwrap()
    .start()
    .begin(100)
    .unwrap()
}
fn permit(service: &Service<Observer>, request: &Request<'_>) -> DispatchPermit<String> {
    permit_for(service, request, "observer-instance", false)
}

#[test]
fn observer_transforms_actual_geodesic_and_encounter_results() {
    for (request, expected) in [
        (request(), Guarantee::ObserverEncounter),
        (distance(), Guarantee::ObserverDistance),
    ] {
        for mode in [Mode::Production, Mode::Sandbox] {
            for disclosure in [Disclosure::Minimal, Disclosure::Complete] {
                let mut svc = service();
                svc.adapter.mode = mode;
                let mut state = Store::default();
                let result = block_on(svc.verify(
                    &request,
                    b"inert-evidence",
                    permit(&svc, &request),
                    &mut state,
                    disclosure,
                    100,
                ))
                .unwrap();
                let upstream = match result {
                    Verified::Production { proof, upstream } => {
                        assert_eq!(mode, Mode::Production);
                        assert_eq!(proof.guarantee(), expected);
                        assert_eq!(state.calls.len(), 1);
                        upstream
                    }
                    Verified::Sandbox { upstream } => {
                        assert_eq!(mode, Mode::Sandbox);
                        assert!(state.calls.is_empty());
                        upstream
                    }
                };
                assert_eq!(upstream.is_some(), disclosure == Disclosure::Complete);
                if let Some(value) = upstream {
                    assert_eq!(value["unknown-field"], serde_json::json!([1, 2, 3]));
                }
            }
        }
    }
    let svc = service();
    assert!(matches!(
        block_on(svc.verify(
            &request(),
            b"inert-evidence",
            permit(&svc, &request()),
            &mut Store {
                deny: true,
                ..Default::default()
            },
            Disclosure::Minimal,
            100
        )),
        Err(Error::State)
    ));
    assert_eq!(
        local_quote(amount().unit, "local".into(), 200)
            .price
            .maximum()
            .unwrap()
            .atoms,
        0
    );
}

#[test]
fn observer_requires_authentication_context_freshness_and_explicit_permit() {
    let mutations: [fn(&mut Observation); 6] = [
        |r| r.subject = "other".into(),
        |r| r.context = "wrong".into(),
        |r| r.id.clear(),
        |r| r.observed_at = 101,
        |r| r.observed_at = 79,
        |r| r.peer = None,
    ];
    for mutate in mutations {
        let mut svc = service();
        svc.adapter.mutate = mutate;
        assert!(matches!(
            block_on(svc.verify(
                &request(),
                b"inert-evidence",
                permit(&svc, &request()),
                &mut Store::default(),
                Disclosure::Minimal,
                100
            )),
            Err(Error::Rejected)
        ));
    }
    let mutations: [fn(&mut Observation); 4] = [
        |r| r.position = None,
        |r| r.position.as_mut().unwrap().latitude = f64::NAN,
        |r| r.position.as_mut().unwrap().longitude = 9.0,
        |r| r.position.as_mut().unwrap().accuracy_m = 6.0,
    ];
    for mutate in mutations {
        let mut svc = service();
        svc.adapter.mutate = mutate;
        assert!(matches!(
            block_on(svc.verify(
                &distance(),
                b"inert-evidence",
                permit(&svc, &distance()),
                &mut Store::default(),
                Disclosure::Minimal,
                100
            )),
            Err(Error::Rejected)
        ));
    }
    let svc = service();
    for (id, changed) in [("wrong", false), ("observer-instance", true)] {
        assert!(matches!(
            block_on(svc.verify(
                &request(),
                b"inert-evidence",
                permit_for(&svc, &request(), id, changed),
                &mut Store::default(),
                Disclosure::Minimal,
                100
            )),
            Err(Error::Cost)
        ));
    }
    assert!(
        block_on(svc.verify(
            &request(),
            &vec![0; 65537],
            permit(&svc, &request()),
            &mut Store::default(),
            Disclosure::Minimal,
            100
        ))
        .is_err()
    );
    let mut svc = service();
    svc.adapter.mode = Mode::Simulation;
    assert!(
        block_on(svc.verify(
            &request(),
            b"inert-evidence",
            permit(&svc, &request()),
            &mut Store::default(),
            Disclosure::Minimal,
            100
        ))
        .is_err()
    );
    let mut svc = service();
    svc.adapter.fail = true;
    assert!(matches!(
        block_on(svc.verify(
            &request(),
            b"inert-evidence",
            permit(&svc, &request()),
            &mut Store::default(),
            Disclosure::Minimal,
            100
        )),
        Err(Error::Uncertain)
    ));
}

#[test]
fn invalid_predicates_are_refused_before_adapter_dispatch() {
    let svc = service();
    for request in [
        Request {
            subject: "",
            ..request()
        },
        Request {
            nonce: "",
            ..request()
        },
        Request {
            max_age: 0,
            ..request()
        },
        Request {
            requirement: Requirement::Encounter { peer: "" },
            ..request()
        },
        Request {
            requirement: Requirement::Encounter { peer: "subject" },
            ..request()
        },
    ] {
        assert!(
            observation::preview(
                &svc.adapter,
                &request,
                b"evidence",
                Price::Unknown,
                "source".into(),
                200,
                100
            )
            .is_err()
        );
    }
    for target in [
        Position {
            latitude: 91.0,
            ..position()
        },
        Position {
            longitude: 181.0,
            ..position()
        },
        Position {
            accuracy_m: f64::INFINITY,
            ..position()
        },
        Position {
            accuracy_m: -1.0,
            ..position()
        },
    ] {
        let r = Request {
            requirement: Requirement::Distance {
                target,
                radius_m: 100.0,
            },
            ..request()
        };
        assert!(
            observation::preview(
                &svc.adapter,
                &r,
                b"evidence",
                Price::Unknown,
                "source".into(),
                200,
                100
            )
            .is_err()
        );
    }
    for radius_m in [f64::NAN, -1.0] {
        let r = Request {
            requirement: Requirement::Distance {
                target: position(),
                radius_m,
            },
            ..request()
        };
        assert!(
            observation::preview(
                &svc.adapter,
                &r,
                b"evidence",
                Price::Unknown,
                "source".into(),
                200,
                100
            )
            .is_err()
        );
    }
}

mod atomic;

mod simulation;

impl DispatchState for Store {
    fn reserve_dispatch(&mut self, quote: &Quote) -> bool {
        assert!(!quote.binding.is_empty());
        true // Each independent fixture models a newly admitted host operation.
    }
}
