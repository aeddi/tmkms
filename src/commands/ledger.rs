//! `tmkms ledger` CLI (sub)commands

use crate::{
    chain,
    error::{Error, ErrorKind::*},
    prelude::*,
    privval::{ConsensusMsg, ConsensusMsgType},
    proto,
};
use abscissa_core::{Command, Runnable};
use clap::{Parser, Subcommand};
use cometbft::Vote;
use std::{path::PathBuf, process};

/// `ledger` subcommand
#[derive(Command, Debug, Runnable, Subcommand)]
pub enum LedgerCommand {
    /// initialise the height/round/step
    Init(InitCommand),
}

impl LedgerCommand {
    pub(super) fn config_path(&self) -> Option<&PathBuf> {
        match self {
            LedgerCommand::Init(init) => init.config.as_ref(),
        }
    }
}

/// `ledger init` subcommand
#[derive(Command, Debug, Parser)]
pub struct InitCommand {
    /// config file path
    #[clap(short = 'c', long = "config")]
    pub config: Option<PathBuf>,

    /// block height
    #[clap(short = 'H', long = "height", required = true)]
    pub height: i64,

    /// block round
    #[clap(short = 'r', long = "round", required = true)]
    pub round: i32,
}

impl Runnable for InitCommand {
    fn run(&self) {
        self.init().unwrap_or_else(|e| {
            status_err!("{}", e);
            process::exit(1);
        });
    }
}

impl InitCommand {
    /// Sign an initial proposal to establish the height/round/step on the device
    fn init(&self) -> Result<(), Error> {
        let config = APP.config();

        chain::load_config(&config)
            .map_err(|e| format_err!(ConfigError, "error loading configuration: {}", e))?;

        let validator = config
            .validator
            .first()
            .ok_or_else(|| format_err!(ConfigError, "no [[validator]] configured to initialize"))?;
        let chain_id = validator.chain_id.clone();

        let registry = chain::REGISTRY.get();
        let chain = registry.get_chain(&chain_id).ok_or_else(|| {
            format_err!(ConfigError, "chain '{}' missing from registry", chain_id)
        })?;

        let vote = proto::types::v1beta1::Vote {
            height: self.height,
            round: self.round,
            r#type: ConsensusMsgType::Proposal.into(),
            ..Default::default()
        };

        let msg = ConsensusMsg::from(
            Vote::try_from(vote)
                .map_err(|e| format_err!(InvalidMessageError, "invalid vote: {}", e))?,
        );

        // Go through the same double signing checks as a signing request, so this
        // cannot be used to sign at a height already signed for.
        //
        // NOTE: this is currently unreachable. The `Vote` built above carries no
        // timestamp and a proposal message code, both of which `Vote::try_from`
        // rejects, so the command always fails before reaching this point. Left in
        // place so the check is already correct once the message construction is
        // fixed; see the backlog task for `tmkms ledger init`.
        chain
            .state
            .lock()
            .map_err(|e| format_err!(PoisonError, "state lock poisoned: {}", e))?
            .update_consensus_state(msg.consensus_state())?;

        let to_sign = msg.canonical_bytes(chain_id)?;
        chain.keyring.sign(None, &to_sign)?;

        status_ok!(
            "Initialized",
            "height: {}, round: {}",
            self.height,
            self.round
        );

        Ok(())
    }
}
