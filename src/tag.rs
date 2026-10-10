//! NXP NTAG 424 DNA SDM verification through maintained `ntag424`.
use crate::{Blinding, Context, Disclosure, Error, Guarantee, Proof, State};
use ntag424::sdm::{SdmVerification, Verifier};
use zeroize::Zeroizing;

/// Server verifier configured for one authorized tag; no reader I/O or provisioning.
pub struct Tag {
    verifier: Verifier,
    file_key: Zeroizing<[u8; 16]>,
    meta_key: Zeroizing<[u8; 16]>,
    expected_uid: [u8; 7],
    blinding: Blinding,
}

/// Explicit full upstream output, without automatic logging or serialization.
pub struct Verified {
    /// Minimal requested proof.
    pub proof: Proof,
    /// All upstream fields, including UID, read counter and decrypted data when available.
    pub upstream: Option<SdmVerification>,
}

/// Complete native upstream fields, available only through explicit access.
#[derive(PartialEq, Eq)]
pub struct Report(SdmVerification);
impl Report {
    /// Borrow every field supplied by the upstream verifier without a lossy mapping.
    pub fn information(&self) -> &SdmVerification {
        &self.0
    }
}
impl std::fmt::Debug for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TagReport([redacted])")
    }
}
fn failure(error: Error, result: SdmVerification, disclosure: Disclosure) -> Error {
    if disclosure == Disclosure::Complete {
        Error::TagReported {
            cause: Box::new(error),
            report: Report(result),
        }
    } else {
        error
    }
}

impl Tag {
    /// Use the tag's trusted SDM settings and provisioned keys. Factory keys are
    /// suitable only for test vectors. The expected UID comes from trusted enrollment.
    pub fn new(
        verifier: Verifier,
        file_key: [u8; 16],
        meta_key: [u8; 16],
        expected_uid: [u8; 7],
        blinding: Blinding,
    ) -> Result<Self, Error> {
        verifier.validate().map_err(|_| Error::Configuration)?;
        Ok(Self {
            verifier,
            file_key: Zeroizing::new(file_key),
            meta_key: Zeroizing::new(meta_key),
            expected_uid,
            blinding,
        })
    }

    /// Authenticate a bounded NDEF read, blind identity, then atomically enforce
    /// counter replay prevention and the caller's registration quota.
    pub fn verify(
        &self,
        ndef: &[u8],
        context: &Context<'_>,
        store: &mut impl State,
        disclosure: Disclosure,
        now: u64,
    ) -> Result<Verified, Error> {
        let result = self.authenticate(ndef, context, disclosure, now)?;
        let counter = result.read_ctr.expect("authenticate requires a counter");
        let identity = self
            .blinding
            .key("tag-identity", context.scope, &self.expected_uid);
        let evidence = self.blinding.key("tag-counter", "", &self.expected_uid);
        if !store.reserve(&identity, &evidence, Some(counter), context) {
            return Err(failure(Error::State, result, disclosure));
        }
        Ok(Verified {
            proof: Proof {
                guarantee: Guarantee::TagRead,
                expires: context.expires,
            },
            upstream: (disclosure == Disclosure::Complete).then_some(result),
        })
    }

    /// Run real local tag authentication with explicit fixture keys and a dummy
    /// state decision. No host state is read or changed, and no production proof
    /// is returned. This checks tag authenticity, not physical presence.
    pub fn simulate(
        &self,
        ndef: &[u8],
        context: &Context<'_>,
        permitted: bool,
        disclosure: Disclosure,
        now: u64,
    ) -> Result<Simulation, Error> {
        let result = self.authenticate(ndef, context, disclosure, now)?;
        if !permitted {
            return Err(failure(Error::State, result, disclosure));
        }
        Ok(Simulation {
            expires: context.expires,
            upstream: (disclosure == Disclosure::Complete).then_some(result),
        })
    }

    fn authenticate(
        &self,
        ndef: &[u8],
        context: &Context<'_>,
        disclosure: Disclosure,
        now: u64,
    ) -> Result<SdmVerification, Error> {
        context.validate(now)?;
        if ndef.len() > 256 {
            return Err(Error::Rejected);
        }
        let result = self
            .verifier
            .verify_with_meta_key(ndef, &self.file_key, &self.meta_key)
            .map_err(|_| Error::Rejected)?;
        self.accept_result(result, disclosure)
    }

    pub(crate) fn accept_result(
        &self,
        result: SdmVerification,
        disclosure: Disclosure,
    ) -> Result<SdmVerification, Error> {
        if result.uid != Some(self.expected_uid) || result.read_ctr.is_none() {
            return Err(failure(Error::Rejected, result, disclosure));
        }
        Ok(result)
    }
}

/// Hypothetical authenticated tag result, distinct from a consumed production proof.
pub struct Simulation {
    /// Caller-selected fixture expiry, without a physical freshness claim.
    pub expires: u64,
    /// Full real upstream verification fields when explicitly requested.
    pub upstream: Option<SdmVerification>,
}
