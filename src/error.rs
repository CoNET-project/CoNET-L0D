use thiserror::Error;

#[derive(Debug, Error)]
pub enum L0dError {
    #[error("invalid web3:// locator: {0}")]
    Locator(String),
    #[error("invalid config: {0}")]
    Config(String),
    #[error("l0 client: {0}")]
    L0(String),
    /// SI wrote `{"type":"l0_pipe_end",...}` on the occupied inbound TCP before teardown.
    ///
    #[error("l0 pipe ended ({reason})")]
    L0PipeEnd { reason: String, session_id: String },
    #[error("start/stop/teardown require Linux with CAP_NET_ADMIN, ip, and iptables")]
    NotLinux,
    #[error("net operation failed: {0}")]
    #[allow(dead_code)]
    Net(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
