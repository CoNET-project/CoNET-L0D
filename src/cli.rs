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
