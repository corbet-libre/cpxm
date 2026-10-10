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
        context.validate(now)?;
        if ndef.len() > 256 {
            return Err(Error::Rejected);
        }
        let result = self
            .verifier
            .verify_with_meta_key(ndef, &self.file_key, &self.meta_key)
            .map_err(|_| Error::Rejected)?;
        if result.uid != Some(self.expected_uid) {
            return Err(Error::Rejected);
        }
        let counter = result.read_ctr.ok_or(Error::Rejected)?;
        let identity = self
            .blinding
            .key("tag-identity", context.scope, &self.expected_uid);
        let evidence = self.blinding.key("tag-counter", "", &self.expected_uid);
        if !store.reserve(&identity, &evidence, Some(counter), context) {
            return Err(Error::State);
        }
        Ok(Verified {
            proof: Proof {
                guarantee: Guarantee::TagRead,
                expires: context.expires,
            },
            upstream: (disclosure == Disclosure::Complete).then_some(result),
        })
    }
}
