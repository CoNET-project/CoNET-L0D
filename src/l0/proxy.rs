//! Per-line proxy data plane.
//!
//! The occupied L0 pipe is the only transport boundary.  This module keeps
//! the upstream connection and byte forwarding independent per session; it
//! never stores mailbox data or shares a socket between clients.

use crate::config::ValidatedL0Proxy;
use crate::error::L0dError;
use crate::l0::identity::TemporaryIdentity;
use std::sync::Arc;
use tokio::io::{self, AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

pub struct ProxyLine {
    pub session_id: String,
    pub target: ValidatedL0Proxy,
    /// Per-line communication identity. It is dropped with this ProxyLine.
    /// The billing wallet is intentionally not stored here.
    pub identity: TemporaryIdentity,
}

impl ProxyLine {
    pub fn new(session_id: impl Into<String>, target: ValidatedL0Proxy) -> Result<Self, L0dError> {
        Ok(Self {
            session_id: session_id.into(),
            target,
            identity: TemporaryIdentity::generate()?,
        })
    }

    pub async fn connect_upstream(&self) -> Result<TcpStream, L0dError> {
        let address = format!("{}:{}", self.target.host, self.target.port);
        timeout(CONNECT_TIMEOUT, TcpStream::connect(&address))
            .await
            .map_err(|_| {
                L0dError::Net(format!(
                    "proxy upstream connect timeout: {}",
                    self.session_id
                ))
            })?
            .map_err(|err| {
                L0dError::Net(format!(
                    "proxy upstream connect failed for {}: {err}",
                    self.session_id
                ))
            })
    }
}

pub async fn copy_bidirectional_bounded<A, B>(
    session_id: &str,
    left: A,
    right: B,
) -> Result<(u64, u64), L0dError>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let mut left = left;
    let mut right = right;
    let (left_to_right, right_to_left) = io::copy_bidirectional(&mut left, &mut right)
        .await
        .map_err(|err| L0dError::Net(format!("proxy copy failed for {session_id}: {err}")))?;
    Ok((left_to_right, right_to_left))
}

/// Forward bytes for one occupied duplex line to its configured upstream.
///
/// The channels are owned by this session. Consequently, two clients using
/// the same logical port cannot share a socket, AES stream, or pipe queue.
pub async fn run_proxy_line(
    line: ProxyLine,
    mut incoming: mpsc::Receiver<Vec<u8>>,
    outgoing: mpsc::Sender<Vec<u8>>,
) -> Result<(u64, u64), L0dError> {
    let mut upstream = line.connect_upstream().await?;
    let mut upstream_buf = vec![0u8; 16 * 1024];
    let mut from_pipe = 0u64;
    let mut from_upstream = 0u64;
    let mut pipe_open = true;
    let mut upstream_open = true;

    while pipe_open || upstream_open {
        tokio::select! {
            maybe = incoming.recv(), if pipe_open => {
                match maybe {
                    Some(bytes) => {
                        upstream.write_all(&bytes).await.map_err(|err| {
                            L0dError::Net(format!(
                                "proxy upstream write failed for {}: {err}",
                                line.session_id
                            ))
                        })?;
                        from_pipe += bytes.len() as u64;
                    }
                    None => {
                        pipe_open = false;
                        upstream.shutdown().await.map_err(|err| {
                            L0dError::Net(format!(
                                "proxy upstream shutdown failed for {}: {err}",
                                line.session_id
                            ))
                        })?;
                    }
                }
            }
            result = tokio::io::AsyncReadExt::read(&mut upstream, &mut upstream_buf), if upstream_open => {
                let n = result.map_err(|err| {
                    L0dError::Net(format!(
                        "proxy upstream read failed for {}: {err}",
                        line.session_id
                    ))
                })?;
                if n == 0 {
                    upstream_open = false;
                    pipe_open = false;
                } else {
                    outgoing.send(upstream_buf[..n].to_vec()).await.map_err(|_| {
                        L0dError::Net(format!(
                            "proxy duplex receiver closed for {}",
                            line.session_id
                        ))
                    })?;
                    from_upstream += n as u64;
                }
            }
        }
    }
    Ok((from_pipe, from_upstream))
}

pub fn find_target(targets: &[ValidatedL0Proxy], port: u16) -> Option<ValidatedL0Proxy> {
    targets.iter().find(|target| target.port == port).cloned()
}

#[derive(Debug, Clone)]
pub struct ProxyRegistry {
    targets: Arc<Vec<ValidatedL0Proxy>>,
}

impl ProxyRegistry {
    pub fn new(targets: Vec<ValidatedL0Proxy>) -> Self {
        Self {
            targets: Arc::new(targets),
        }
    }

    pub fn line(&self, session_id: &str, port: u16) -> Result<Option<ProxyLine>, L0dError> {
        find_target(&self.targets, port)
            .map(|target| ProxyLine::new(session_id, target))
            .transpose()
    }

    pub fn len(&self) -> usize {
        self.targets.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn each_line_keeps_its_session_identity() {
        let target = ValidatedL0Proxy {
            host: "127.0.0.1".into(),
            port: 8400,
        };
        let registry = ProxyRegistry::new(vec![target.clone()]);
        let first = registry.line("first", 8400).unwrap().unwrap();
        let second = registry.line("second", 8400).unwrap().unwrap();
        assert_ne!(first.session_id, second.session_id);
        assert_ne!(
            first.identity.wallet_address(),
            second.identity.wallet_address()
        );
        assert_eq!(first.target.port, second.target.port);
    }
}
