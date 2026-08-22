use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "conet-l0d",
    about = "CoNET L1 overlay daemon: own TUN + iptables for geth/beacon overlay P2P"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Validate TOML without touching the network
    CheckConfig {
        #[arg(long)]
        config: PathBuf,
    },
    /// Parse a web3:// locator; optional config fills in the overlay vIP
    Resolve {
        uri: String,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Linux: create TUN, route, CONET_L0D, then run the packet loop
    Start {
        #[arg(long)]
        config: PathBuf,
        /// Main paid wallet used to sign and settle proxy-channel commands.
        #[arg(long = "mainWallet")]
        main_wallet: Option<String>,
        /// Optional OpenPGP secret key file for the main wallet.
        #[arg(long = "mainWalletPgp")]
        main_wallet_pgp: Option<PathBuf>,
        /// Local hex secp256k1 key file for main-wallet EIP-191 signing.
        #[arg(long = "mainWalletKey")]
        main_wallet_key: Option<PathBuf>,
        /// Proxy target, repeatable as host:port. The port is the L0 logical port.
        #[arg(long = "proxy", value_name = "HOST:PORT")]
        proxy: Vec<String>,
        /// Persistent bidirectional proxy target, repeatable as host:port.
        #[arg(long = "proxyDuplex", alias = "proxy-duplex", value_name = "HOST:PORT")]
        proxy_duplex: Vec<String>,
        /// Client target, repeatable as web3://<wallet|tag.web3>:<port>.
        /// Local request/response endpoint toward that mainWallet:port.
        #[arg(long = "client", value_name = "web3://HOST:PORT")]
        client: Vec<String>,
        /// Duplex client target, repeatable as web3://<wallet|tag.web3>:<port>.
        #[arg(
            long = "clientDuplex",
            alias = "client-duplex",
            value_name = "web3://HOST:PORT"
        )]
        client_duplex: Vec<String>,
    },
    /// Run the application gateway without creating a TUN or changing iptables
    Gateway {
        #[arg(long)]
        config: PathBuf,
    },
    /// Signal the pid in the state file, then teardown
    Stop {
        #[arg(long)]
        config: PathBuf,
    },
    /// Remove owned TUN / route / iptables even if the daemon is dead
    Teardown {
        #[arg(long)]
        config: PathBuf,
    },
    /// Print state-file status
    Status {
        #[arg(long)]
        config: PathBuf,
    },
}
