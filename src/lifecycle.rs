use crate::config::{DaemonConfig, ValidatedConfig};
use crate::error::L0dError;
use crate::locator::Locator;
use crate::netops;
use crate::state::RuntimeState;
use serde_json::json;
use std::path::Path;
use std::time::Duration;

pub fn check_config(path: &Path) -> anyhow::Result<()> {
    let cfg = load_validated(path)?;
    println!("ok");
    println!("tun            {}", cfg.raw.tun_name);
    println!("overlay        {}", cfg.overlay.display());
    println!("local_vip      {}", cfg.local_vip);
    println!("iptables_chain {}", cfg.raw.iptables_chain);
    println!("identity       {}", cfg.identity.display());
    println!("peers          {}", cfg.peers.len());
    println!("l0.enabled     {}", cfg.l0.enabled);
    println!("l0.rpc         {}", cfg.l0.rpc);
    println!("l0.address_pgp {}", cfg.l0.address_pgp);
    println!("l0.entries     {}", cfg.l0.entries.len());
    println!("l0.listen      {}", cfg.l0.listen_entries.len());
    println!(
        "l0.routing_key {}",
        if cfg.l0.routing_key_file.is_some() {
            "set"
        } else {
            "unset"
        }
    );
    println!(
        "l0.mailbox_rt  {}",
        if cfg.l0.mailbox_route_pgp_file.is_some() {
            "set"
        } else {
            "unset"
        }
    );
    let pgp_ready = cfg
        .peers
        .iter()
        .filter(|p| p.user_pgp_file.is_some() && p.route_pgp_file.is_some())
        .count();
    println!(
        "l0.peer_pgp    {pgp_ready}/{} (user+route files; contents not printed)",
        cfg.peers.len()
    );
    if let Some(eoa) = cfg.l0.routing_eoa.as_deref().or(match &cfg.identity.host {
        crate::locator::LocatorHost::Eoa(e) => Some(e.as_str()),
        crate::locator::LocatorHost::Tag(_) => None,
    }) {
        if let Ok(call) = crate::l0::address_pgp::encode_search_key_call(eoa) {
            println!("l0.searchKey   {call}");
        }
    }
    if let Some(uid) = cfg.raw.validator_uid {
        println!("validator_uid  {uid} (never captured)");
    }
    Ok(())
}

pub fn resolve(uri: &str, config: Option<&Path>) -> anyhow::Result<()> {
    let locator = Locator::parse(uri)?;
    let mut vip = None;
    if let Some(path) = config {
        let cfg = load_validated(path)?;
        vip = cfg.lookup_locator(&locator).map(|ip| ip.to_string());
    }
    let host = match &locator.host {
        crate::locator::LocatorHost::Eoa(eoa) => json!({ "kind": "eoa", "eoa": eoa }),
        crate::locator::LocatorHost::Tag(tag) => json!({ "kind": "tag", "tag": tag }),
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "locator": locator.display(),
            "service": locator.service.as_str(),
            "host": host,
            "vip": vip,
            "note": "web3:// is a peer locator, not ERC-4804 content. Exact BeamioTag only (CoNET ≠ CONET)."
        }))?
    );
    Ok(())
}

pub fn status(path: &Path) -> anyhow::Result<()> {
    let cfg = DaemonConfig::load(path)?.validate()?;
    match RuntimeState::load(&cfg.raw.state_path)? {
        None => {
            println!("stopped");
            println!("state_path {}", cfg.raw.state_path.display());
        }
        Some(state) => {
            let alive = netops::process_alive(state.pid);
            println!("{}", if alive { "running" } else { "dirty" });
            println!("pid      {}", state.pid);
            println!("tun      {}", state.tun_name);
            println!("overlay  {}", state.overlay_cidr);
            println!("vip      {}", state.local_vip);
            println!("chain    {}", state.iptables_chain);
            println!("started  {}", state.started_at);
            if !alive {
                println!("hint     sudo conet-l0d teardown --config {}", path.display());
            }
        }
    }
    Ok(())
}

pub async fn start(path: &Path) -> anyhow::Result<()> {
    if !cfg!(target_os = "linux") {
        anyhow::bail!(L0dError::NotLinux);
    }
    let cfg = load_validated(path)?;
    if RuntimeState::load(&cfg.raw.state_path)?.is_some() {
        tracing::warn!("dirty state present; tearing down first");
        teardown_inner(&cfg).await?;
    }
    netops::install(&cfg).await?;
    let state = RuntimeState::from_config(&cfg, std::process::id());
    if let Err(err) = state.write(&cfg.raw.state_path) {
        let _ = netops::uninstall(&cfg, Some(&state)).await;
        return Err(err.into());
    }
    tracing::info!(
        tun = %cfg.raw.tun_name,
        vip = %cfg.local_vip,
        chain = %cfg.raw.iptables_chain,
        "conet-l0d started; owns TUN + iptables"
    );

    let run = async {
        #[cfg(unix)]
        {
            let mut sigterm =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = sigterm.recv() => {}
                r = netops::packet_loop(&cfg) => { r?; }
            }
        }
        #[cfg(not(unix))]
        {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                r = netops::packet_loop(&cfg) => { r?; }
            }
        }
        Ok::<(), anyhow::Error>(())
    };

    let result = run.await;
    teardown_inner(&cfg).await?;
    result
}

pub async fn stop(path: &Path) -> anyhow::Result<()> {
    if !cfg!(target_os = "linux") {
        anyhow::bail!(L0dError::NotLinux);
    }
    let cfg = load_validated(path)?;
    if let Some(state) = RuntimeState::load(&cfg.raw.state_path)? {
        if netops::process_alive(state.pid) && state.pid != std::process::id() {
            netops::signal_stop(state.pid)?;
            wait_dead(state.pid, Duration::from_secs(5)).await;
        }
    }
    teardown_inner(&cfg).await?;
    Ok(())
}

pub async fn teardown(path: &Path) -> anyhow::Result<()> {
    if !cfg!(target_os = "linux") {
        anyhow::bail!(L0dError::NotLinux);
    }
    let cfg = load_validated(path)?;
    teardown_inner(&cfg).await?;
    Ok(())
}

async fn teardown_inner(cfg: &ValidatedConfig) -> Result<(), L0dError> {
    let state = RuntimeState::load(&cfg.raw.state_path)?;
    netops::uninstall(cfg, state.as_ref()).await?;
    RuntimeState::remove(&cfg.raw.state_path)?;
    tracing::info!("owned TUN / route / {} removed", cfg.raw.iptables_chain);
    Ok(())
}

fn load_validated(path: &Path) -> Result<ValidatedConfig, L0dError> {
    DaemonConfig::load(path)?.validate()
}

async fn wait_dead(pid: u32, timeout: Duration) {
    let deadline = tokio::time::Instant::now() + timeout;
    while netops::process_alive(pid) && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
