//! Ledger Tendermint signer

mod client;
mod error;
mod signer;

use self::signer::Ed25519LedgerTmAppSigner;
use crate::{
    chain,
    config::provider::ledgertm::LedgerTendermintConfig,
    error::{Error, ErrorKind::*},
    keyring::{
        SigningProvider,
        ed25519::{self, Signer},
    },
    prelude::*,
};
use cometbft::{CometbftKey, PublicKey};

/// Create Ledger Tendermint signer object from the given configuration
pub fn init(
    chain_registry: &mut chain::Registry,
    ledgertm_configs: &[LedgerTendermintConfig],
) -> Result<(), Error> {
    if ledgertm_configs.is_empty() {
        return Ok(());
    }

    if ledgertm_configs.len() != 1 {
        fail!(
            ConfigError,
            "expected one [providers.ledgertm] in config, found: {}",
            ledgertm_configs.len()
        );
    }

    let provider = Ed25519LedgerTmAppSigner::connect().map_err(|_| Error::from(SigningError))?;

    let verifying_key = ed25519::VerifyingKey::try_from(&provider)
        .map_err(|e| format_err!(InvalidKey, "couldn't read Ledger public key: {}", e))?;

    let public_key = PublicKey::from_raw_ed25519(verifying_key.as_bytes())
        .ok_or_else(|| format_err!(InvalidKey, "invalid Ed25519 public key from Ledger"))?;

    let signer = Signer::new(
        SigningProvider::LedgerTm,
        CometbftKey::ConsensusKey(public_key),
        Box::new(provider),
    );

    for chain_id in &ledgertm_configs[0].chain_ids {
        chain_registry.add_consensus_key(chain_id, signer.clone())?;
    }

    Ok(())
}
