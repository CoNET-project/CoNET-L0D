use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "conet-l0d",
    about = "Linux runtime for wallet-addressed web3:// services over CoNET Layer Minus"
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
    /// Parse a web3:// application locator and optional local endpoint mapping
    Resolve {
        uri: String,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Run configured web3:// server proxies and client endpoints
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
        /// Request/response upstream, repeatable as host:port.
        #[arg(long = "proxy", value_name = "HOST:PORT")]
        proxy: Vec<String>,
        /// Persistent bidirectional upstream, repeatable as host:port.
        #[arg(long = "proxyDuplex", alias = "proxy-duplex", value_name = "HOST:PORT")]
        proxy_duplex: Vec<String>,
        /// Persistent client target exposed through a local TCP endpoint.
        /// Repeatable. The same logical PORT may map to several remotes.
        #[arg(
            long = "clientDuplex",
            aliases = ["client", "client-duplex"],
            value_name = "web3://HOST:PORT[@LOCAL]"
        )]
        client_duplex: Vec<String>,
    },
    /// Run the signed web request gateway for a loopback HTTP upstream
    Gateway {
        #[arg(long)]
        config: PathBuf,
    },
    /// Signal the pid in the state file, then clean up daemon state
    Stop {
        #[arg(long)]
        config: PathBuf,
    },
    /// Remove daemon-owned runtime state even if the process is dead
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
