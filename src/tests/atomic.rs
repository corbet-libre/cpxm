//! Host-owned atomic replay and quota example; no storage is added to the library.
use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

#[derive(Clone, PartialEq, Eq)]
struct Terms {
    identity: String,
    scope: String,
    registration: String,
    maximum: u64,
    expires: u64,
}
impl Terms {
    fn new(identity: &str, context: &Context<'_>) -> Self {
        Self {
            identity: identity.into(),
            scope: context.scope.into(),
            registration: context.registration.into(),
            maximum: context.maximum,
            expires: context.expires,
        }
    }
}
#[derive(Default)]
struct Registry {
    registrations: BTreeMap<String, BTreeMap<String, Terms>>,
    evidence: BTreeMap<String, (Option<u32>, Terms)>,
    dispatches: BTreeSet<String>,
    exposure: u64,
}
#[derive(Clone, Default)]
struct AtomicState(Arc<Mutex<Registry>>);
impl State for AtomicState {
    fn reserve(
        &mut self,
        identity: &str,
        evidence: &str,
        counter: Option<u32>,
        context: &Context<'_>,
    ) -> bool {
        let mut state = self.0.lock().unwrap();
        let terms = Terms::new(identity, context);
        if let Some((previous, accepted)) = state.evidence.get(evidence) {
            if previous == &counter {
                return accepted == &terms;
            }
            match (previous, counter) {
                (Some(old), Some(new)) if new > *old => (),
                _ => return false,
            }
        }
        let registrations = state.registrations.entry(identity.into()).or_default();
        if let Some(previous) = registrations.get(context.registration) {
            if previous != &terms {
                return false;
            }
        } else {
            if registrations.len() as u64 >= context.maximum {
                return false;
            }
            registrations.insert(context.registration.into(), terms.clone());
        }
        state.evidence.insert(evidence.into(), (counter, terms));
        true
    }
}

#[test]
fn authenticated_tag_counter_is_atomic_global_and_idempotent_only_for_identical_context() {
    let engine = tag();
    let state = AtomicState::default();
    let accepted = std::thread::scope(|threads| {
        let joins: Vec<_> = ["first", "second"]
            .into_iter()
            .map(|registration| {
                let mut port = state.clone();
                let engine = &engine;
                threads.spawn(move || {
                    (
                        registration,
                        engine
                            .verify(
                                NDEF,
                                &Context {
                                    registration,
                                    ..context()
                                },
                                &mut port,
                                Disclosure::Minimal,
                                100,
                            )
                            .is_ok(),
                    )
                })
            })
            .collect();
        joins
            .into_iter()
            .map(|join| join.join().unwrap())
            .filter(|(_, accepted)| *accepted)
            .collect::<Vec<_>>()
    });
    assert_eq!(accepted.len(), 1);
    let registration = accepted[0].0;
    assert!(
        engine
            .verify(
                NDEF,
                &Context {
                    registration,
                    ..context()
                },
                &mut state.clone(),
                Disclosure::Minimal,
                100
            )
            .is_ok()
    );
    for changed in [
        Context {
            registration,
            scope: "new-window",
            ..context()
        },
        Context {
            registration,
            maximum: 3,
            ..context()
        },
        Context {
            registration,
            expires: 201,
            ..context()
        },
    ] {
        assert!(matches!(
            engine.verify(NDEF, &changed, &mut state.clone(), Disclosure::Minimal, 100),
            Err(Error::State)
        ));
    }
    let state = state.0.lock().unwrap();
    assert_eq!(state.evidence.len(), 1);
    assert_eq!(state.registrations.values().next().unwrap().len(), 1);
    assert!(
        state
            .evidence
            .values()
            .all(|(counter, _)| *counter == Some(61))
    );
}

#[test]
fn authenticated_observers_share_quota_but_distinct_events_cannot_exceed_caller_limit() {
    let state = AtomicState::default();
    let accepted = std::thread::scope(|threads| {
        let joins: Vec<_> = [
            ("one", "event-one"),
            ("two", "event-two"),
            ("three", "event-three"),
        ]
        .into_iter()
        .map(|(registration, nonce)| {
            let mut port = state.clone();
            threads.spawn(move || {
                let mut svc = service();
                svc.adapter.mutate = |result| result.id = result.context.clone();
                let request = Request {
                    context: Context {
                        registration,
                        ..context()
                    },
                    nonce,
                    ..request()
                };
                let result = block_on(svc.verify(
                    &request,
                    b"inert-evidence",
                    permit(&svc, &request),
                    &mut port,
                    Disclosure::Minimal,
                    || 100,
                ));
                (registration, nonce, result.is_ok())
            })
        })
        .collect();
        joins
            .into_iter()
            .map(|join| join.join().unwrap())
            .filter(|(_, _, accepted)| *accepted)
            .collect::<Vec<_>>()
    });
    assert_eq!(accepted.len(), 2);
    let (registration, nonce, _) = accepted[0];
    let mut svc = service();
    svc.adapter.mutate = |result| result.id = result.context.clone();
    let request = Request {
        context: Context {
            registration,
            ..context()
        },
        nonce,
        ..request()
    };
    assert!(matches!(
        block_on(svc.verify(
            &request,
            b"inert-evidence",
            permit(&svc, &request),
            &mut state.clone(),
            Disclosure::Minimal,
            || 100
        )),
        Err(Error::Cost)
    ));
    let state = state.0.lock().unwrap();
    assert_eq!(state.evidence.len(), 2);
    assert_eq!(state.exposure, 3); // The declined third quota reservation still incurred its provider exposure.
    assert_eq!(state.dispatches.len(), 3);
    assert_eq!(state.registrations.len(), 1);
    assert_eq!(
        state
            .registrations
            .values()
            .next()
            .unwrap()
            .keys()
            .collect::<BTreeSet<_>>()
            .len(),
        2
    );
}

#[test]
fn quote_never_extends_a_shorter_tariff_and_stale_quotes_cannot_dispatch() {
    let svc = service();
    for (tariff_expiry, expected) in [(150, 150), (250, 200)] {
        let quote = observation::preview(
            &svc.adapter,
            &request(),
            b"inert-evidence",
            Price::AtMost(amount()),
            "explicit fixture revision".into(),
            tariff_expiry,
            100,
        )
        .unwrap();
        assert_eq!(quote.valid_until, expected);
    }
    let quote = observation::preview(
        &svc.adapter,
        &request(),
        b"inert-evidence",
        Price::AtMost(amount()),
        "explicit fixture revision".into(),
        100,
        100,
    )
    .unwrap();
    let plan = Plan::new(
        vec![Offer {
            candidate: Candidate::new("observer-instance".to_owned(), ["proximity"]),
            quote,
        }],
        Config::new(["observer-instance".to_owned()], ["proximity"]),
        CostOrder::Configured,
        amount(),
        1,
        Mode::Production,
        100,
    );
    assert!(matches!(plan, Err(cfbk::cost::Error::Unavailable)));
    let quote = observation::preview(
        &svc.adapter,
        &request(),
        b"inert-evidence",
        Price::AtMost(amount()),
        "explicit fixture revision".into(),
        101,
        100,
    )
    .unwrap();
    let permit = Plan::new(
        vec![Offer {
            candidate: Candidate::new("observer-instance".to_owned(), ["proximity"]),
            quote,
        }],
        Config::new(["observer-instance".to_owned()], ["proximity"]),
        CostOrder::Configured,
        amount(),
        1,
        Mode::Production,
        100,
    )
    .unwrap()
    .start()
    .begin(100)
    .unwrap();
    assert!(matches!(
        block_on(svc.verify(
            &request(),
            b"inert-evidence",
            permit,
            &mut AtomicState::default(),
            Disclosure::Minimal,
            || 101
        )),
        Err(Error::Cost)
    ));
}

impl DispatchState for AtomicState {
    fn reserve_dispatch(&mut self, quote: &Quote) -> bool {
        let mut state = self.0.lock().unwrap();
        let cost = quote.price.maximum().unwrap();
        if state.dispatches.contains(&quote.binding)
            || cost.unit != amount().unit
            || state.exposure + cost.atoms > 3
        {
            return false;
        }
        state.exposure += cost.atoms;
        state.dispatches.insert(quote.binding.clone());
        true
    }
}
struct RefuseDispatch;
impl State for RefuseDispatch {
    fn reserve(&mut self, _: &str, _: &str, _: Option<u32>, _: &Context<'_>) -> bool {
        panic!("usage state must not be called after dispatch refusal")
    }
}
impl DispatchState for RefuseDispatch {
    fn reserve_dispatch(&mut self, _: &Quote) -> bool {
        false
    }
}
#[test]
fn observer_requires_host_dispatch_reservation_before_provider_or_usage() {
    let mut svc = service();
    svc.adapter.mutate = |_| panic!("provider must not run after dispatch refusal");
    assert!(matches!(
        block_on(svc.verify(
            &request(),
            b"inert-evidence",
            permit(&svc, &request()),
            &mut RefuseDispatch,
            Disclosure::Minimal,
            || 100
        )),
        Err(Error::Cost)
    ));
}
