//! TCP socket connection to a validator

use std::{
    io,
    net::{SocketAddr, TcpStream, ToSocketAddrs},
    path::PathBuf,
    time::Duration,
};

use cometbft::node;
use cometbft_p2p::{IdentitySecret, PublicKey, SecretConnection};
use subtle::ConstantTimeEq;

use crate::{
    error::{Error, ErrorKind::*},
    key_utils,
    prelude::*,
};

/// Default timeout in seconds
const DEFAULT_TIMEOUT: u16 = 10;

/// Open a TCP socket connection encrypted with SecretConnection
pub fn open_secret_connection(
    host: &str,
    port: u16,
    identity_key_path: &Option<PathBuf>,
    peer_id: &Option<node::Id>,
    timeout: Option<u16>,
) -> Result<SecretConnection<TcpStream>, Error> {
    let identity_key_path = identity_key_path.as_ref().ok_or_else(|| {
        format_err!(
            ConfigError,
            "config error: no `secret_key` for validator: {}:{}",
            host,
            port
        )
    })?;

    let identity_key = IdentitySecret::from(key_utils::load_identity_key(identity_key_path)?);
    info!("KMS node ID: {}", PublicKey::from(&identity_key));

    let timeout = Duration::from_secs(timeout.unwrap_or(DEFAULT_TIMEOUT).into());

    // `TcpStream::connect` has no timeout of its own, so an unreachable validator
    // would otherwise hang here for the OS default (minutes). Note that DNS
    // resolution below is still unbounded: std offers no way to time it out.
    let addrs = format!("{host}:{port}")
        .to_socket_addrs()?
        .collect::<Vec<_>>();

    if addrs.is_empty() {
        fail!(
            ConfigError,
            "couldn't resolve validator address: {}:{}",
            host,
            port
        );
    }

    let socket = connect_first_available(&addrs, timeout)?;
    socket.set_read_timeout(Some(timeout))?;
    socket.set_write_timeout(Some(timeout))?;

    let connection = match SecretConnection::new(socket, &identity_key) {
        Ok(conn) => conn,
        Err(error) => fail!(ProtocolError, format!("{error}")),
    };
    let actual_peer_id = connection.peer_public_key().peer_id();

    // TODO(tarcieri): move this into `SecretConnection::new`
    if let Some(expected_peer_id) = peer_id {
        if expected_peer_id
            .as_bytes()
            .ct_eq(actual_peer_id.as_bytes())
            .unwrap_u8()
            == 0
        {
            fail!(
                VerificationError,
                "{}:{}: validator peer ID mismatch! (expected {}, got {})",
                host,
                port,
                expected_peer_id,
                actual_peer_id
            );
        }
    }

    Ok(connection)
}

/// Connect to the first of `addrs` that accepts a connection within `timeout`.
///
/// `TcpStream::connect` tries every address a name resolves to, so a host with an
/// unreachable AAAA record still connects over IPv4. `TcpStream::connect_timeout`
/// takes a single address and has no such fallback, so the iteration is done here.
fn connect_first_available(addrs: &[SocketAddr], timeout: Duration) -> io::Result<TcpStream> {
    let mut last_error = None;

    for addr in addrs {
        match TcpStream::connect_timeout(addr, timeout) {
            Ok(socket) => return Ok(socket),
            Err(e) => {
                debug!("couldn't connect to {}: {}", addr, e);
                last_error = Some(e);
            }
        }
    }

    Err(last_error.unwrap_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "no addresses to connect to")
    }))
}

#[cfg(test)]
mod tests {
    use super::connect_first_available;
    use std::{
        net::{SocketAddr, TcpListener},
        time::Duration,
    };

    const TIMEOUT: Duration = Duration::from_secs(5);

    #[test]
    fn falls_back_to_a_later_address_when_the_first_is_unreachable() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let reachable = listener.local_addr().unwrap();

        // Port 1 on the loopback interface has nothing listening, standing in for
        // the unreachable AAAA record a dual-stack host resolves to first
        let unreachable: SocketAddr = "127.0.0.1:1".parse().unwrap();

        let socket = connect_first_available(&[unreachable, reachable], TIMEOUT)
            .expect("should fall back to the reachable address");

        assert_eq!(socket.peer_addr().unwrap(), reachable);
    }

    #[test]
    fn reports_the_last_error_when_every_address_fails() {
        let unreachable: SocketAddr = "127.0.0.1:1".parse().unwrap();

        connect_first_available(&[unreachable], TIMEOUT).expect_err("expected a connection error");
    }
}
