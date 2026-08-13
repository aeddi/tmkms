use super::{Signature, VerifyingKey};
use crate::error::{Error, ErrorKind};
use sha2::Sha512;
use signature::Signer;
use zeroize::Zeroizing;

const COMBINED_KEY_LENGTH: usize =
    ed25519_dalek::EXPANDED_SECRET_KEY_LENGTH + ed25519_dalek::PUBLIC_KEY_LENGTH;

/// Ed25519 signing key.
#[derive(Debug)]
pub struct SigningKey {
    expanded: ed25519_dalek::hazmat::ExpandedSecretKey,
    seed: Option<Zeroizing<[u8; Self::BYTE_SIZE]>>,
}

impl SigningKey {
    /// Size of an encoded Ed25519 signing key in bytes.
    pub const BYTE_SIZE: usize = 32;

    /// Get the verifying key for this signing key.
    pub fn verifying_key(&self) -> VerifyingKey {
        let public_key = ed25519_dalek::VerifyingKey::from(&self.expanded);
        VerifyingKey(public_key)
    }

    /// Return the 32-byte seed if this signing key was constructed from one.
    pub fn as_bytes(&self) -> Option<&[u8; Self::BYTE_SIZE]> {
        self.seed.as_deref()
    }
}

impl Signer<Signature> for SigningKey {
    fn try_sign(&self, msg: &[u8]) -> signature::Result<Signature> {
        // `hazmat::raw_sign` is used because this type must support pre-expanded
        // keys that no seed exists for (YubiHSM exports, 64-byte keys), which the
        // safe API cannot represent.
        //
        // The hazard it carries is the ed25519 "public key oracle" attack: signing
        // with a verifying key that does not match the secret leaks the private
        // key. That is avoided by deriving the verifying key from `expanded` on
        // every call rather than storing one alongside it, so the two cannot
        // disagree. See https://github.com/MystenLabs/ed25519-unsafe-libs
        let signature =
            ed25519_dalek::hazmat::raw_sign::<Sha512>(&self.expanded, msg, &self.verifying_key().0);
        Ok(signature.to_bytes().into())
    }
}

impl TryFrom<&[u8]> for SigningKey {
    type Error = Error;

    fn try_from(slice: &[u8]) -> Result<Self, Error> {
        match slice.len() {
            ed25519_dalek::SECRET_KEY_LENGTH => {
                let mut seed = Zeroizing::new([0u8; Self::BYTE_SIZE]);
                seed.copy_from_slice(&slice[..Self::BYTE_SIZE]);

                // `SecretKey` is a bare `[u8; 32]` alias with no `Drop`, so the
                // copy it makes of the seed needs wiping explicitly
                let secret_key = Zeroizing::new(
                    ed25519_dalek::SecretKey::try_from(seed.as_ref())
                        .map_err(|_| ErrorKind::InvalidKey)?,
                );
                let expanded_key = ed25519_dalek::hazmat::ExpandedSecretKey::from(&*secret_key);

                Ok(Self {
                    expanded: expanded_key,
                    seed: Some(seed),
                })
            }

            // big-endian encoded, prehashed key
            ed25519_dalek::EXPANDED_SECRET_KEY_LENGTH => {
                let expanded_key = ed25519_dalek::hazmat::ExpandedSecretKey::from_bytes(
                    slice.try_into().map_err(|_| ErrorKind::InvalidKey)?,
                );

                Ok(Self {
                    expanded: expanded_key,
                    seed: None,
                })
            }

            // little-endian encoded, prehashed key, exported from YubiHSM
            COMBINED_KEY_LENGTH => {
                // Holds expanded secret key material, so it must be wiped on drop
                let mut key_bytes: Zeroizing<[u8; ed25519_dalek::EXPANDED_SECRET_KEY_LENGTH]> =
                    Zeroizing::new(
                        slice[..ed25519_dalek::EXPANDED_SECRET_KEY_LENGTH]
                            .try_into()
                            .map_err(|_| ErrorKind::InvalidKey)?,
                    );

                key_bytes[..ed25519_dalek::SECRET_KEY_LENGTH].reverse();

                let expanded_key = ed25519_dalek::hazmat::ExpandedSecretKey::from_bytes(&key_bytes);

                Ok(Self {
                    expanded: expanded_key,
                    seed: None,
                })
            }

            other_len => Err(ErrorKind::InvalidKey
                .context(format!(
                    "invalid Ed25519 key size: expected 32, 64, or 96, but got {}",
                    other_len
                ))
                .into()),
        }
    }
}

impl From<cometbft::private_key::Ed25519> for SigningKey {
    fn from(signing_key: cometbft::private_key::Ed25519) -> SigningKey {
        signing_key
            .as_bytes()
            .try_into()
            .expect("invalid Ed25519 signing key")
    }
}

impl From<&SigningKey> for cometbft_p2p::PublicKey {
    fn from(signing_key: &SigningKey) -> cometbft_p2p::PublicKey {
        signing_key.verifying_key().into()
    }
}
