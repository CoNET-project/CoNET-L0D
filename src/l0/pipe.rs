//! Keep-alive HTTP `/post` after the first `{ "data": armor }` JSON.
//!
//! SI `getDataPOST` reads `Content-Length`, then unshifts leftover TCP bytes.
//! After `l0_connect` occupies an idle L0 SSE, those leftover lines are AES
//! blobs (not OpenPGP). reqwest cannot keep that TCP, so this module writes
//! the JSON body then extra `\n` + base64 lines on the same stream.

use crate::error::L0dError;
use crate::l0::post;
use rustls::pki_types::ServerName;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::TlsConnector;

pub async fn run_occupied_pipe(
    entries: &[String],
    connect_armor: &str,
    mut first: Option<String>,
    mut rx: mpsc::Receiver<String>,
) -> Result<(), L0dError> {
    if entries.is_empty() {
        return Err(L0dError::L0("l0.entries is empty; refusing l0_connect pipe".into()));
    }
    let mut last = L0dError::L0("l0_connect pipe failed".into());
    for entry in entries {
        match open_pipe(entry, connect_armor).await {
            Ok(mut stream) => {
                if let Some(blob) = first.take() {
                    write_blob_line(&mut stream, &blob).await?;
                }
                while let Some(blob) = rx.recv().await {
                    write_blob_line(&mut stream, &blob).await?;
                }
                return Ok(());
            }
            Err(err) => last = err,
        }
    }
    Err(last)
}

async fn write_blob_line(stream: &mut SplitPipe, blob: &str) -> Result<(), L0dError> {
    let line = format!("{blob}\n");
    stream
        .write_all(line.as_bytes())
        .await
        .map_err(|e| L0dError::L0(format!("l0 pipe write: {e}")))?;
    stream
        .flush()
        .await
        .map_err(|e| L0dError::L0(format!("l0 pipe flush: {e}")))
}

enum PipeStream {
    Plain(TcpStream),
    Tls(tokio_rustls::client::TlsStream<TcpStream>),
}

impl PipeStream {
    fn split_read(self) -> (PipeReader, PipeWriter) {
        match self {
            Self::Plain(s) => {
                let (r, w) = s.into_split();
                (PipeReader::Plain(r), PipeWriter::Plain(w))
            }
            Self::Tls(s) => {
                let (r, w) = tokio::io::split(s);
                (PipeReader::Tls(r), PipeWriter::Tls(w))
            }
        }
    }
}

enum PipeReader {
    Plain(tokio::net::tcp::OwnedReadHalf),
    Tls(tokio::io::ReadHalf<tokio_rustls::client::TlsStream<TcpStream>>),
}

enum PipeWriter {
    Plain(tokio::net::tcp::OwnedWriteHalf),
    Tls(tokio::io::WriteHalf<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl PipeWriter {
    async fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Plain(s) => s.write_all(buf).await,
            Self::Tls(s) => s.write_all(buf).await,
        }
    }

    async fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Plain(s) => s.flush().await,
            Self::Tls(s) => s.flush().await,
        }
    }
}

struct SplitPipe {
    writer: PipeWriter,
}

impl SplitPipe {
    async fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        self.writer.write_all(buf).await
    }

    async fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush().await
    }
}

async fn open_pipe(entry: &str, armor: &str) -> Result<SplitPipe, L0dError> {
    let url = post::post_url(entry)?;
    let parsed = url::Url::parse(&url).map_err(|e| L0dError::L0(format!("l0 pipe URL: {e}")))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| L0dError::L0("l0 pipe URL missing host".into()))?
        .to_string();
    let https = parsed.scheme() == "https";
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| L0dError::L0("l0 pipe URL missing port".into()))?;
    let path = if parsed.path().is_empty() {
        "/post".to_string()
    } else {
        parsed.path().to_string()
    };
    let body = post::json_body_bytes(armor)?;
    let req = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: keep-alive\r\n\
         User-Agent: conet-l0d/0.1\r\n\
         \r\n",
        body.len()
    );
    let tcp = TcpStream::connect((host.as_str(), port))
        .await
        .map_err(|e| L0dError::L0(format!("l0 pipe connect {host}:{port}: {e}")))?;
    tcp.set_nodelay(true)
        .map_err(|e| L0dError::L0(format!("l0 pipe nodelay: {e}")))?;
    let stream = if https {
        let tls = tls_connector()?;
        let name = ServerName::try_from(host.clone())
            .map_err(|_| L0dError::L0("l0 pipe TLS server name".into()))?;
        let tls_stream = tls
            .connect(name, tcp)
            .await
            .map_err(|e| L0dError::L0(format!("l0 pipe TLS: {e}")))?;
        PipeStream::Tls(tls_stream)
    } else {
        PipeStream::Plain(tcp)
    };
    let (mut reader, mut writer) = stream.split_read();
    writer
        .write_all(req.as_bytes())
        .await
        .map_err(|e| L0dError::L0(format!("l0 pipe headers: {e}")))?;
    writer
        .write_all(&body)
        .await
        .map_err(|e| L0dError::L0(format!("l0 pipe body: {e}")))?;
    writer
        .flush()
        .await
        .map_err(|e| L0dError::L0(format!("l0 pipe body flush: {e}")))?;
    tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        loop {
            let n = match &mut reader {
                PipeReader::Plain(r) => r.read(&mut buf).await,
                PipeReader::Tls(r) => r.read(&mut buf).await,
            };
            match n {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    });
    Ok(SplitPipe { writer })
}

fn tls_connector() -> Result<TlsConnector, L0dError> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(cfg)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_body_bytes_is_data_only() {
        let raw = post::json_body_bytes(
            "-----BEGIN PGP MESSAGE-----\n\nxxxx\n-----END PGP MESSAGE-----\n",
        )
        .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        let obj = v.as_object().unwrap();
        assert_eq!(obj.len(), 1);
        assert!(obj.contains_key("data"));
    }
}
