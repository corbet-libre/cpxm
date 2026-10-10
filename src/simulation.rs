//! Pure observation transformations and cost cascades with explicit dummy outcomes.
use crate::{
    Blinding, Error, Guarantee,
    observation::{self, Observation, Request, Requirement},
};
use cfbk::cost::{Amount, CostOrder, Mode, Offer as CostOffer, Outcome, Plan, Price, Quote};
use cfbk::{Candidate, Config};

/// Dummy observation and known fixture cost, never a trusted provider result.
pub struct Offer {
    /// Mechanism this option is capable of establishing.
    pub mechanism: Guarantee,
    /// Explicit dummy provider outcome.
    pub outcome: Outcome,
    /// Dummy provider information, validated by the real predicate on success.
    pub observation: Observation,
    /// Bounded fixture cost including failures.
    pub price: Price,
    /// Explicit provenance.
    pub source: String,
    /// Exclusive tariff expiry.
    pub valid_until: u64,
}
/// Caller-selected simulation budget and ordering.
pub struct Settings {
    /// Configured order or lowest maximum fee first.
    pub order: CostOrder,
    /// Total exposure ceiling.
    pub budget: Amount,
    /// Maximum allowed attempts.
    pub max_attempts: usize,
    /// Fixture current time.
    pub now: u64,
}
/// Distinct output without a production proof or state-reservation operation.
#[derive(Debug)]
pub struct Simulation {
    /// Final dummy outcome, including actual predicate refusal.
    pub outcome: Outcome,
    /// Verified hypothetical predicate, never a production guarantee.
    pub mechanism: Option<Guarantee>,
    /// Scoped dummy identity under a fixed public simulation key.
    pub comparison: Option<String>,
    /// Reserved cost exposure from the real planner.
    pub exposure: Amount,
    /// Number of admitted dummy attempts.
    pub attempts: usize,
    /// Planner stop after safe failures; all incurred exposure remains visible.
    pub stop: Option<cfbk::cost::Error>,
}
fn capability(guarantee: Guarantee) -> &'static str {
    match guarantee {
        Guarantee::TagRead => "tag.read",
        Guarantee::ObserverEncounter => "observer.encounter",
        Guarantee::ObserverDistance => "observer.distance",
    }
}
/// Run real context, geodesic/encounter, identity and cost transformations on dummy inputs.
/// No transport, tag keys, provider credentials or host state can be supplied.
pub fn simulate(
    request: &Request<'_>,
    offers: Vec<Offer>,
    settings: Settings,
) -> Result<Simulation, Error> {
    request.validate(settings.now)?;
    let needed = match request.requirement {
        Requirement::Encounter { .. } => Guarantee::ObserverEncounter,
        Requirement::Distance { .. } => Guarantee::ObserverDistance,
    };
    let priced = offers
        .iter()
        .enumerate()
        .map(|(id, offer)| CostOffer {
            candidate: Candidate::new(id, [capability(offer.mechanism)]),
            quote: Quote {
                price: offer.price.clone(),
                source: offer.source.clone(),
                valid_until: offer.valid_until.min(request.context.expires),
                binding: format!("simulation:{id}"),
            },
        })
        .collect();
    let plan = Plan::new(
        priced,
        Config::new(0..offers.len(), [capability(needed)]),
        settings.order,
        settings.budget,
        settings.max_attempts,
        Mode::Simulation,
        settings.now,
    )
    .map_err(|_| Error::Cost)?;
    let mut cascade = plan.start();
    loop {
        let permit = match cascade.begin(settings.now) {
            Ok(permit) => permit,
            Err(error) => {
                return Ok(Simulation {
                    outcome: Outcome::SafeFailure,
                    mechanism: None,
                    comparison: None,
                    exposure: cascade.exposure(),
                    attempts: cascade.attempts(),
                    stop: Some(error),
                });
            }
        };
        let offer = &offers[*permit.candidate()];
        let mut outcome = offer.outcome;
        let mut mechanism = None;
        let mut comparison = None;
        if outcome == Outcome::Success {
            match observation::evaluate(request, &offer.observation, settings.now) {
                Ok(guarantee) => {
                    mechanism = Some(guarantee);
                    let blinding = Blinding::new(vec![0; 32], "simulation".into())
                        .expect("fixed dummy key and domain are valid");
                    comparison = Some(blinding.key(
                        "observer-subject",
                        request.context.scope,
                        offer.observation.subject.as_bytes(),
                    ));
                }
                Err(_) => outcome = Outcome::Refused,
            }
        }
        cascade
            .complete(outcome, None)
            .expect("an admitted pending attempt with no actual charge always reconciles");
        if outcome != Outcome::SafeFailure {
            return Ok(Simulation {
                outcome,
                mechanism,
                comparison,
                exposure: cascade.exposure(),
                attempts: cascade.attempts(),
                stop: None,
            });
        }
    }
}
