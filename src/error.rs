//! Error types

use crate::{chain, prelude::*};
use abscissa_core::error::{BoxError, Context};
use std::{
    any::Any,
    fmt::{self, Display},
    io,
    ops::Deref,
};
use thiserror::Error;

/// Kinds of errors
#[derive(Copy, Clone, Eq, PartialEq, Debug, Error)]
pub enum ErrorKind {
    /// Access denied
    #[error("access denied")]
    AccessError,

    /// Invalid Chain ID
    #[error("chain ID error")]
    ChainIdError,

    /// Error in configuration file
    #[error("config error")]
    ConfigError,

    /// Error in validator connection
    #[error("connection error")]
    ConnectionError,

    /// Cryptographic operation failed
    #[error("cryptographic error")]
    CryptoError,

    /// Double sign attempted
    #[error("attempted double sign")]
    DoubleSign,

    /// Request a signature above max height
    #[error("requested signature above stop height")]
    ExceedMaxHeight,

    /// Fortanix DSM related error
    #[cfg(feature = "fortanixdsm")]
    #[error("Fortanix DSM error")]
    FortanixDsmError,

    /// Error running a subcommand to update chain state
    #[error("subcommand hook failed")]
    HookError,

    /// Malformed or otherwise invalid cryptographic key
    #[error("invalid key")]
    InvalidKey,

    /// Validation of consensus message failed
    #[error("invalid consensus message")]
    InvalidMessageError,

    /// Input/output error
    #[error("I/O error")]
    IoError,

    /// KMS internal panic
    #[error("internal crash")]
    PanicError,

    /// Parse error
    #[error("parse error")]
    ParseError,

    /// KMS state has been poisoned
    #[error("internal state poisoned")]
    PoisonError,

    /// Network protocol-related errors
    #[error("protocol error")]
    ProtocolError,

    /// Serialization error
    #[error("serialization error")]
    SerializationError,

    /// Failed to persist double signing protection state
    #[error("state persistence failed")]
    StateSyncError,

    /// Signing operation failed
    #[error("signing operation failed")]
    SigningError,

    /// Errors originating in the Tendermint crate
    #[error("Tendermint error")]
    TendermintError,

    /// Verification operation failed
    #[error("verification failed")]
    VerificationError,

    /// YubiHSM-related errors
    #[cfg(feature = "yubihsm")]
    #[error("YubiHSM error")]
    YubihsmError,

    /// Protobuf encoding error
    #[error("protobuf error")]
    ProtobufError,
}

impl ErrorKind {
    /// Create an error context from this error
    pub fn context(self, source: impl Into<BoxError>) -> Context<ErrorKind> {
        Context::new(self, Some(source.into()))
    }
}

/// Error type
#[derive(Debug)]
pub struct Error(Box<Context<ErrorKind>>);

impl Error {
    /// Create an error from a panic
    pub fn from_panic(panic_msg: Box<dyn Any>) -> Self {
        let err_msg = if let Some(msg) = panic_msg.downcast_ref::<String>() {
            msg.as_ref()
        } else if let Some(msg) = panic_msg.downcast_ref::<&str>() {
            msg
        } else {
            "unknown cause"
        };

        let kind = if err_msg.contains("PoisonError") {
            ErrorKind::PoisonError
        } else {
            ErrorKind::PanicError
        };

        format_err!(kind, err_msg).into()
    }
}

impl Deref for Error {
    type Target = Context<ErrorKind>;

    fn deref(&self) -> &Context<ErrorKind> {
        &self.0
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Context::new(kind, None).into()
    }
}

impl From<Context<ErrorKind>> for Error {
    fn from(context: Context<ErrorKind>) -> Self {
        Error(Box::new(context))
    }
}

impl From<io::Error> for Error {
    fn from(other: io::Error) -> Self {
        ErrorKind::IoError.context(other).into()
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.source()
    }
}

impl From<prost::DecodeError> for Error {
    fn from(other: prost::DecodeError) -> Self {
        ErrorKind::ProtocolError.context(other).into()
    }
}

impl From<prost::EncodeError> for Error {
    fn from(other: prost::EncodeError) -> Self {
        ErrorKind::ProtocolError.context(other).into()
    }
}

impl From<serde_json::error::Error> for Error {
    fn from(other: serde_json::error::Error) -> Self {
        ErrorKind::SerializationError.context(other).into()
    }
}

impl From<signature::Error> for Error {
    fn from(other: signature::Error) -> Self {
        ErrorKind::CryptoError.context(other).into()
    }
}

impl From<cometbft::Error> for Error {
    fn from(other: cometbft::error::Error) -> Self {
        ErrorKind::TendermintError.context(other).into()
    }
}

impl From<cometbft_p2p::Error> for Error {
    fn from(other: cometbft_p2p::Error) -> Self {
        ErrorKind::ConnectionError.context(other).into()
    }
}

impl From<cometbft_proto::Error> for Error {
    fn from(other: cometbft_proto::Error) -> Self {
        ErrorKind::ProtobufError.context(other).into()
    }
}

impl From<chain::state::StateError> for Error {
    fn from(other: chain::state::StateError) -> Self {
        use chain::state::StateErrorKind;

        // Only refusals to sign belong in the double-sign family; a failure to
        // persist state is an I/O problem and must not be reported as an
        // attempted equivocation
        let kind = match other.kind() {
            StateErrorKind::DoubleSign
            | StateErrorKind::HeightRegression
            | StateErrorKind::RoundRegression
            | StateErrorKind::StepRegression => ErrorKind::DoubleSign,
            StateErrorKind::SyncError => ErrorKind::StateSyncError,
            // A refusal to trust the state hook's height: neither an equivocation
            // attempt nor a disk failure. Matches how `chain::from_config` labels
            // it, so `fail_closed` reporting stays consistent.
            StateErrorKind::HookHeightOutOfRange => ErrorKind::HookError,
        };

        kind.context(other).into()
    }
}

#[cfg(test)]
mod tests {
    use super::{Error, ErrorKind};
    use crate::chain::state::{StateError, StateErrorKind};

    #[test]
    fn state_sync_failure_is_not_reported_as_a_double_sign() {
        let error = Error::from(StateError::from(StateErrorKind::SyncError));

        assert_eq!(*error.kind(), ErrorKind::StateSyncError);
    }

    #[test]
    fn double_sign_attempt_is_reported_as_a_double_sign() {
        let error = Error::from(StateError::from(StateErrorKind::DoubleSign));

        assert_eq!(*error.kind(), ErrorKind::DoubleSign);
    }

    #[test]
    fn hook_height_out_of_range_is_not_reported_as_a_double_sign() {
        let error = Error::from(StateError::from(StateErrorKind::HookHeightOutOfRange));

        assert_eq!(*error.kind(), ErrorKind::HookError);
    }

    #[test]
    fn height_regression_is_reported_as_a_double_sign() {
        let error = Error::from(StateError::from(StateErrorKind::HeightRegression));

        assert_eq!(*error.kind(), ErrorKind::DoubleSign);
    }
}
