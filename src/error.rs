use thiserror::Error;

#[derive(Debug, Error)]
pub enum L0dError {
    #[error("invalid web3:// locator: {0}")]
    Locator(String),
    #[error("invalid config: {0}")]
    Config(String),
    #[error("start/stop/teardown require Linux with CAP_NET_ADMIN, ip, and iptables")]
    NotLinux,
    #[error("net operation failed: {0}")]
    #[allow(dead_code)]
    Net(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
