//! Per-line proxy data plane.
//!
//! The occupied L0 pipe is the only transport boundary.  This module keeps
//! the upstream connection and byte forwarding independent per session; it
//! never stores mailbox data or shares a socket between clients.

use crate::config::{ProxyMode, ValidatedL0Proxy};
use crate::error::L0dError;
use std::sync::Arc;
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

pub struct ProxyLine {
    pub session_id: String,
    pub target: ValidatedL0Proxy,
}

impl ProxyLine {
    pub fn new(session_id: impl Into<String>, target: ValidatedL0Proxy) -> Self {
        Self {
            session_id: session_id.into(),
            target,
        }
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
    run_proxy_stream(&line.session_id, &mut upstream, &mut incoming, &outgoing).await
}

/// Establish the upstream TCP connection and synchronously complete the first
/// request/response exchange.  The first upstream read is intentionally
/// bounded to one chunk: the socket remains owned by this task and is not
/// drained further until the caller has delivered that response in
/// `duplex_accept.responseChunk`.
pub async fn connect_upstream_with_initial(
    line: &ProxyLine,
    initial: &[u8],
) -> Result<(TcpStream, Vec<u8>), L0dError> {
    let mut upstream = line.connect_upstream().await?;
    upstream.write_all(initial).await.map_err(|err| {
        L0dError::Net(format!(
            "proxy upstream initial write failed for {}: {err}",
            line.session_id
        ))
    })?;
    let mut response = vec![0u8; 16 * 1024];
    let n = timeout(CONNECT_TIMEOUT, upstream.read(&mut response))
        .await
        .map_err(|_| {
            L0dError::Net(format!(
                "proxy upstream initial read timeout: {}",
                line.session_id
            ))
        })?
        .map_err(|err| {
            L0dError::Net(format!(
                "proxy upstream initial read failed for {}: {err}",
                line.session_id
            ))
        })?;
    if n == 0 {
        return Err(L0dError::Net(format!(
            "proxy upstream closed before responseChunk: {}",
            line.session_id
        )));
    }
    response.truncate(n);
    Ok((upstream, response))
}

/// Continue forwarding on an already handshaken upstream socket.
pub async fn run_proxy_stream(
    session_id: &str,
    upstream: &mut TcpStream,
    incoming: &mut mpsc::Receiver<Vec<u8>>,
    outgoing: &mpsc::Sender<Vec<u8>>,
) -> Result<(u64, u64), L0dError> {
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
                                session_id
                            ))
                        })?;
                        from_pipe += bytes.len() as u64;
                    }
                    None => {
                        pipe_open = false;
                        upstream.shutdown().await.map_err(|err| {
                            L0dError::Net(format!(
                                "proxy upstream shutdown failed for {}: {err}",
                                session_id
                            ))
                        })?;
                    }
                }
            }
            result = tokio::io::AsyncReadExt::read(upstream, &mut upstream_buf), if upstream_open => {
                let n = result.map_err(|err| {
                    L0dError::Net(format!(
                        "proxy upstream read failed for {}: {err}",
                            session_id
                    ))
                })?;
                if n == 0 {
                    upstream_open = false;
                    pipe_open = false;
                } else {
                    outgoing.send(upstream_buf[..n].to_vec()).await.map_err(|_| {
                        L0dError::Net(format!(
                            "proxy duplex receiver closed for {}",
                            session_id
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

pub fn target_mode(targets: &[ValidatedL0Proxy], port: u16) -> Option<ProxyMode> {
    find_target(targets, port).map(|target| target.mode)
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
            .map(|target| Ok(ProxyLine::new(session_id, target)))
            .transpose()
    }

    pub fn len(&self) -> usize {
        self.targets.len()
    }

    pub fn mode(&self, port: u16) -> Option<ProxyMode> {
        target_mode(&self.targets, port)
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
            mode: ProxyMode::Duplex,
        };
        let registry = ProxyRegistry::new(vec![target.clone()]);
        let first = registry.line("first", 8400).unwrap().unwrap();
        let second = registry.line("second", 8400).unwrap().unwrap();
        assert_ne!(first.session_id, second.session_id);
        assert_eq!(first.target.port, second.target.port);
    }
}
