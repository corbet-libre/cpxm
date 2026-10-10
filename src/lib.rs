//! Proximity expertise: authenticated tag reads and trusted encounter/location observations.
//! Proof guarantees remain mechanism-specific; none imply relay resistance by default.
#![forbid(unsafe_code)]

pub mod observation;
pub mod tag;
use cfbk::cost::{Amount, Price, Quote, Unit};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

/// Redacted domain errors; no tag UID, coordinates or upstream payload.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Invalid trusted configuration or request.
    #[error("invalid proximity configuration")]
    Configuration,
    /// Authentication or requested proximity requirement failed.
    #[error("proximity rejected")]
    Rejected,
    /// Caller state refused the atomic reservation.
    #[error("proximity usage unavailable")]
    State,
    /// Provider outcome is uncertain; retain fee exposure and stop fallback.
    #[error("proximity provider outcome uncertain")]
    Uncertain,
    /// Cost authorization is invalid for this operation.
    #[error("proximity cost authorization rejected")]
    Cost,
}

/// Required caller-owned atomic dispatch and budget reservation.
/// Configure this port with the stable application operation and its total budget.
/// No database connection is accepted or opened by the library.
pub trait DispatchState {
    /// Atomically reserve the exact quote binding and its maximum fee before I/O.
    /// Return true only for a newly admitted dispatch. Previously dispatched,
    /// pending or uncertain bindings must return false, including after restarts.
    /// Reconciliation belongs to the host; dropping an adapter is not a rollback.
    fn reserve_dispatch(&mut self, quote: &Quote) -> bool;
}

/// Scope and general registration limit supplied by the application.
pub struct Context<'a> {
    /// Stable policy scope; include a caller-defined window or epoch when needed.
    pub scope: &'a str,
    /// Opaque registration identity; retries reuse it.
    pub registration: &'a str,
    /// Maximum distinct registrations for this underlying identity in the scope.
    pub maximum: u64,
    /// Caller deadline; not a claim about tag-read freshness.
    pub expires: u64,
}
impl Context<'_> {
    pub(crate) fn validate(&self, now: u64) -> Result<(), Error> {
        if self.scope.is_empty()
            || self.registration.is_empty()
            || self.maximum == 0
            || now >= self.expires
        {
            return Err(Error::Configuration);
        }
        Ok(())
    }
}

/// Caller state must atomically enforce BOTH identity quota and evidence replay rules.
pub trait State {
    /// Reserve a registration up to the context maximum, idempotently for exact retries.
    /// `identity` is scoped; `evidence` is globally stable within the source domain.
    /// A tag counter must exceed the last accepted counter for that evidence identity.
    /// `None` means single-use observation ID. Never count-then-write, nor reset
    /// monotonic counters when a quota window changes. Store only these opaque keys.
    fn reserve(
        &mut self,
        identity: &str,
        evidence: &str,
        counter: Option<u32>,
        context: &Context<'_>,
    ) -> bool;
}

/// Exact guarantee returned; applications choose which satisfy their requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Guarantee {
    /// Authenticated NTAG read counter; neither distance nor clock freshness is proven.
    TagRead,
    /// A configured trusted observer attests that the requested two parties encountered.
    ObserverEncounter,
    /// Trusted reported position falls wholly inside the requested radius including accuracy.
    ObserverDistance,
}

/// Small verified domain result, not constructible from arbitrary provider JSON.
#[derive(Debug)]
pub struct Proof {
    guarantee: Guarantee,
    expires: u64,
}
impl Proof {
    /// Mechanism guarantee, without provider bookkeeping or raw identity.
    pub fn guarantee(&self) -> Guarantee {
        self.guarantee
    }
    /// Application deadline, subject to the mechanism's documented freshness limit.
    pub fn expires(&self) -> u64 {
        self.expires
    }
}

/// Domain-separated HMAC identity transformation; key rotation needs host migration.
pub struct Blinding {
    key: Zeroizing<Vec<u8>>,
    domain: String,
}
impl Blinding {
    /// Supply at least 32 random bytes and a stable source identity domain.
    /// Distinct vendor identity spaces must never share a made-up person namespace.
    pub fn new(key: Vec<u8>, domain: String) -> Result<Self, Error> {
        if key.len() < 32 || domain.is_empty() {
            return Err(Error::Configuration);
        }
        Ok(Self {
            key: Zeroizing::new(key),
            domain,
        })
    }
    pub(crate) fn key(&self, purpose: &str, scope: &str, value: &[u8]) -> String {
        let mut mac = <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(&self.key)
            .expect("HMAC accepts key length");
        for part in [
            b"cpxm.v1".as_slice(),
            self.domain.as_bytes(),
            purpose.as_bytes(),
            scope.as_bytes(),
            value,
        ] {
            mac.update(&(part.len() as u64).to_be_bytes());
            mac.update(part);
        }
        hex::encode(mac.finalize().into_bytes())
    }
}

/// Explicit full-result access. Neither credentials nor private data implement Debug.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Disclosure {
    /// Minimal proof only.
    Minimal,
    /// Include all available upstream fields in transient output.
    Complete,
}

pub mod simulation;
pub use simulation::{Simulation, simulate};

/// Local verification has zero external service fee; CPU/reader costs are separate.
pub fn local_quote(unit: Unit, binding: String, valid_until: u64) -> Quote {
    Quote {
        price: Price::Exact(Amount { unit, atoms: 0 }),
        source: "local verification; no third-party call".into(),
        binding,
        valid_until,
    }
}

#[cfg(test)]
mod tests;
