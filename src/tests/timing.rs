use super::*;
use std::cell::Cell;
use std::task::Poll;

struct DelayedObserver<'a> {
    clock: &'a Cell<u64>,
    completed_at: u64,
    observed_at: u64,
    sent: &'a Cell<usize>,
    mode: Mode,
}
impl Adapter for DelayedObserver<'_> {
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
        self.sent.set(self.sent.get() + 1);
        let mut value = service().adapter.verify(evidence, context, quote).await?;
        value.observed_at = self.observed_at;
        let mut pending = true;
        std::future::poll_fn(|cx| {
            if pending {
                pending = false;
                cx.waker().wake_by_ref();
                Poll::Pending
            } else {
                self.clock.set(self.completed_at);
                Poll::Ready(())
            }
        })
        .await;
        Ok(value)
    }
}

struct TimedPort<'a> {
    clock: &'a Cell<u64>,
    dispatch_at: u64,
    accepted_at: u64,
    dispatched: usize,
    reserved: usize,
}
impl DispatchState for TimedPort<'_> {
    fn reserve_dispatch(&mut self, _: &Quote) -> bool {
        self.dispatched += 1;
        self.clock.set(self.dispatch_at);
        true
    }
}
impl State for TimedPort<'_> {
    fn reserve(&mut self, _: &str, _: &str, _: Option<u32>, _: &Context<'_>) -> bool {
        self.reserved += 1;
        // A slow host callback reporting success must not return a stale proof.
        self.clock.set(self.accepted_at);
        true
    }
}

#[test]
fn observer_rechecks_age_and_deadlines_after_async_reply_and_host_reservation() {
    for (dispatch, completed, accepted, observed, expected, sends, reservations) in [
        (99, 100, 100, 90, Some(Error::Cost), 0, 0),
        (110, 110, 110, 90, Some(Error::Cost), 0, 0),
        (200, 200, 200, 90, Some(Error::Cost), 0, 0),
        (100, 99, 99, 90, Some(Error::Rejected), 1, 0),
        (100, 200, 200, 90, Some(Error::Rejected), 1, 0),
        (100, 111, 111, 90, Some(Error::Rejected), 1, 0),
        (100, 105, 99, 90, Some(Error::Rejected), 1, 1),
        (100, 105, 200, 90, Some(Error::Rejected), 1, 1),
        (100, 105, 111, 90, Some(Error::Rejected), 1, 1),
        // An observation produced while awaiting the provider is not in the future.
        (100, 105, 105, 105, None, 1, 1),
        // Observation age is inclusive; tariff expiry after dispatch is harmless.
        (100, 110, 110, 90, None, 1, 1),
    ] {
        for disclosure in [Disclosure::Minimal, Disclosure::Complete] {
            let clock = Cell::new(100);
            let sent = Cell::new(0);
            let svc = Service {
                adapter: DelayedObserver {
                    clock: &clock,
                    completed_at: completed,
                    observed_at: observed,
                    sent: &sent,
                    mode: Mode::Production,
                },
                blinding: blind(),
            };
            let quote = observation::preview(
                &svc.adapter,
                &request(),
                b"inert-evidence",
                Price::AtMost(amount()),
                "fixture".into(),
                110,
                100,
            )
            .unwrap();
            let permit = Plan::new(
                vec![Offer {
                    candidate: Candidate::new(
                        "observer-instance".into(),
                        ["proximity".to_string()],
                    ),
                    quote,
                }],
                Config::new(["observer-instance".into()], ["proximity".to_string()]),
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
            let mut state = TimedPort {
                clock: &clock,
                dispatch_at: dispatch,
                accepted_at: accepted,
                dispatched: 0,
                reserved: 0,
            };
            let result = block_on(svc.verify(
                &request(),
                b"inert-evidence",
                permit,
                &mut state,
                disclosure,
                || clock.get(),
            ));
            if let Some(error) = &expected {
                let actual = result.err().expect("late or rolled-back clock must refuse");
                assert_eq!(actual.category(), error);
                assert_eq!(
                    actual.report().is_some(),
                    sends == 1 && disclosure == Disclosure::Complete
                );
                if let Some(report) = actual.report() {
                    assert_eq!(
                        report.information()["unknown-field"],
                        serde_json::json!([1, 2, 3])
                    );
                }
            } else {
                assert!(matches!(result.unwrap(), Verified::Production { .. }));
            }
            assert_eq!(sent.get(), sends);
            assert_eq!(state.reserved, reservations);
            assert_eq!(
                state.dispatched, 1,
                "expiry never releases admitted exposure"
            );
        }
    }
}

#[test]
fn sandbox_observations_must_still_be_fresh_at_completion() {
    let clock = Cell::new(100);
    let sent = Cell::new(0);
    let svc = Service {
        adapter: DelayedObserver {
            clock: &clock,
            completed_at: 111,
            observed_at: 90,
            sent: &sent,
            mode: Mode::Sandbox,
        },
        blinding: blind(),
    };
    let quote = observation::preview(
        &svc.adapter,
        &request(),
        b"inert-evidence",
        Price::AtMost(amount()),
        "fixture".into(),
        110,
        100,
    )
    .unwrap();
    let permit = Plan::new(
        vec![Offer {
            candidate: Candidate::new("observer-instance".into(), ["proximity".to_string()]),
            quote,
        }],
        Config::new(["observer-instance".into()], ["proximity".to_string()]),
        CostOrder::Configured,
        amount(),
        1,
        Mode::Sandbox,
        100,
    )
    .unwrap()
    .start()
    .begin(100)
    .unwrap();
    let mut state = TimedPort {
        clock: &clock,
        dispatch_at: 100,
        accepted_at: 111,
        dispatched: 0,
        reserved: 0,
    };
    let error = block_on(svc.verify(
        &request(),
        b"inert-evidence",
        permit,
        &mut state,
        Disclosure::Complete,
        || clock.get(),
    ))
    .err()
    .unwrap();
    assert_eq!(error.category(), &Error::Rejected);
    assert!(error.report().is_some());
    assert_eq!(state.reserved, 0);
}
