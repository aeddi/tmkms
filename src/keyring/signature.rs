//! Signing signature

pub use super::ed25519;
use crate::proto;
pub use k256::ecdsa;

/// Cryptographic signature used for block signing
pub enum Signature {
    /// ECDSA signature (e.g secp256k1)
    Ecdsa(ecdsa::Signature),

    ///  ED25519 signature
    Ed25519(ed25519::Signature),
}

impl Signature {
    /// Serialize this signature as a byte vector.
    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            Self::Ecdsa(sig) => sig.to_vec(),
            Self::Ed25519(sig) => sig.to_vec(),
        }
    }
}

impl From<ecdsa::Signature> for Signature {
    fn from(sig: ecdsa::Signature) -> Signature {
        Self::Ecdsa(sig)
    }
}

impl From<ed25519::Signature> for Signature {
    fn from(sig: ed25519::Signature) -> Signature {
        Self::Ed25519(sig)
    }
}

impl From<Signature> for cometbft::Signature {
    fn from(sig: Signature) -> cometbft::Signature {
        // `cometbft::Signature` only rejects signatures longer than 64 bytes.
        // Ed25519 signatures are exactly 64 and secp256k1 ECDSA signatures are at
        // most 64 in their fixed-width encoding, so this cannot fail.
        sig.to_vec()
            .try_into()
            .expect("signature length is bounded by 64 bytes")
    }
}

impl From<Signature> for proto::privval::celestia::SignedRawBytesResponse {
    fn from(sig: Signature) -> Self {
        proto::privval::celestia::SignedRawBytesResponse {
            signature: sig.to_vec(),
            error: None,
        }
    }
}
