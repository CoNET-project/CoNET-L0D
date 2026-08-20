mod cli;
mod config;
mod error;
mod forward;
mod gateway;
mod l0;
mod lifecycle;
mod locator;
mod netops;
mod packet;
mod platform;
mod state;

use clap::Parser;
use cli::{Cli, Command};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    if let Err(err) = run().await {
        eprintln!("{err:#}");
        std::process::exit(1);
    }
}

async fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::CheckConfig { config } => lifecycle::check_config(&config),
        Command::Resolve { uri, config } => lifecycle::resolve(&uri, config.as_deref()),
        Command::Start { config } => lifecycle::start(&config).await,
        Command::Gateway { config } => gateway::run(&config).await,
        Command::Stop { config } => lifecycle::stop(&config).await,
        Command::Teardown { config } => lifecycle::teardown(&config).await,
        Command::Status { config } => lifecycle::status(&config),
    }
}
