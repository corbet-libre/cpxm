use super::*;
use crate::simulation::{Offer, Settings};
use cfbk::cost::Outcome;

fn options() -> Settings {
    Settings {
        order: CostOrder::Configured,
        budget: Amount {
            atoms: 3,
            ..amount()
        },
        max_attempts: 3,
        now: 100,
    }
}
fn offer(request: &Request<'_>, outcome: Outcome) -> Offer {
    Offer {
        mechanism: Guarantee::ObserverEncounter,
        outcome,
        observation: Observation {
            subject: request.subject.into(),
            context: request.binding(),
            id: "dummy-observation".into(),
            observed_at: 90,
            peer: Some("peer".into()),
            position: Some(position()),
            upstream: serde_json::Value::Null,
        },
        price: Price::AtMost(amount()),
        source: "explicit fixture".into(),
        valid_until: 150,
    }
}
#[test]
fn simulation_reuses_real_encounter_location_and_scoped_identity_transforms() {
    let r = request();
    let result = simulate(&r, vec![offer(&r, Outcome::Success)], options()).unwrap();
    assert_eq!(result.mechanism, Some(Guarantee::ObserverEncounter));
    assert_eq!(result.comparison.as_ref().unwrap().len(), 64);
    assert!(result.stop.is_none());
    assert_eq!(result.exposure.atoms, 1);
    assert!(format!("{result:?}").contains("Simulation"));
    let changed = Request {
        context: Context {
            scope: "other-scope",
            ..context()
        },
        ..request()
    };
    assert_ne!(
        result.comparison,
        simulate(&changed, vec![offer(&changed, Outcome::Success)], options())
            .unwrap()
            .comparison
    );
    let r = distance();
    let mut location = offer(&r, Outcome::Success);
    location.mechanism = Guarantee::ObserverDistance;
    assert_eq!(
        simulate(&r, vec![location], options()).unwrap().mechanism,
        Some(Guarantee::ObserverDistance)
    );
    let r = request();
    let mut bad = offer(&r, Outcome::Success);
    bad.observation.peer = Some("wrong".into());
    let result = simulate(&r, vec![bad], options()).unwrap();
    assert_eq!(result.outcome, Outcome::Refused);
    assert!(result.mechanism.is_none());
    assert!(result.comparison.is_none());
    let mut tag = offer(&r, Outcome::Success);
    tag.mechanism = Guarantee::TagRead;
    assert!(matches!(
        simulate(&r, vec![tag], options()),
        Err(Error::Cost)
    ));
    assert!(
        simulate(
            &Request {
                nonce: "",
                ..request()
            },
            vec![],
            options()
        )
        .is_err()
    );
}
#[test]
fn simulation_fallback_retains_failed_costs_and_stops_for_pending_uncertain_or_refusal() {
    let r = request();
    let result = simulate(
        &r,
        vec![offer(&r, Outcome::SafeFailure), offer(&r, Outcome::Success)],
        options(),
    )
    .unwrap();
    assert_eq!(result.attempts, 2);
    assert_eq!(result.exposure.atoms, 2);
    for outcome in [Outcome::Pending, Outcome::Uncertain, Outcome::Refused] {
        let result = simulate(
            &r,
            vec![offer(&r, outcome), offer(&r, Outcome::Success)],
            options(),
        )
        .unwrap();
        assert_eq!(result.outcome, outcome);
        assert_eq!(result.attempts, 1);
        assert_eq!(result.exposure.atoms, 1);
    }
    let result = simulate(
        &r,
        vec![offer(&r, Outcome::SafeFailure), offer(&r, Outcome::Success)],
        Settings {
            budget: amount(),
            ..options()
        },
    )
    .unwrap();
    assert_eq!(result.stop, Some(cfbk::cost::Error::Budget));
    assert_eq!(result.exposure.atoms, 1);
    let result = simulate(&r, vec![offer(&r, Outcome::SafeFailure)], options()).unwrap();
    assert_eq!(result.stop, Some(cfbk::cost::Error::Finished));
    let mut unknown = offer(&r, Outcome::Success);
    unknown.price = Price::Unknown;
    assert!(matches!(
        simulate(&r, vec![unknown], options()),
        Err(Error::Cost)
    ));
    let mut free = offer(&r, Outcome::Success);
    free.price = Price::Exact(Amount {
        atoms: 0,
        ..amount()
    });
    assert_eq!(
        simulate(
            &r,
            vec![offer(&r, Outcome::Refused), free],
            Settings {
                order: CostOrder::Cheapest,
                ..options()
            }
        )
        .unwrap()
        .exposure
        .atoms,
        0
    );
}
