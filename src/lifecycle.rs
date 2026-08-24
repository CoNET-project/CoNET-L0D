use crate::config::{DaemonConfig, ValidatedConfig};
use crate::error::L0dError;
use crate::locator::{ClientTarget, Locator, LocatorHost};
use crate::netops;
use crate::state::RuntimeState;
use serde_json::json;
use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Process-wide guard for one config/state namespace.  The file itself may
/// remain after a crash; `flock` is released by the kernel with the process.
struct InstanceLock {
    _file: File,
}

fn instance_lock_path(state_path: &Path) -> PathBuf {
    let mut raw = state_path.as_os_str().to_os_string();
    raw.push(".lock");
    PathBuf::from(raw)
}

fn acquire_instance_lock(state_path: &Path) -> anyhow::Result<InstanceLock> {
    let lock_path = instance_lock_path(state_path);
    if let Some(parent) = lock_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(&lock_path)?;
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        anyhow::bail!(
            "conet-l0d already owns state namespace {} (lock {}: {err})",
            state_path.display(),
            lock_path.display()
        );
    }
    Ok(InstanceLock { _file: file })
}

pub fn check_config(path: &Path) -> anyhow::Result<()> {
    let cfg = load_validated(path)?;
    println!("ok");
    println!("network        {}", cfg.overlay.display());
    println!("local_endpoint {}", cfg.local_vip);
    println!("identity       {}", cfg.identity.display());
    println!("peers          {}", cfg.peers.len());
    println!("l0.enabled     {}", cfg.l0.enabled);
    println!("l0.rpc         {}", cfg.l0.rpc);
    println!("l0.address_pgp {}", cfg.l0.address_pgp);
    println!("l0.entries     {}", cfg.l0.entries.len());
    println!("l0.listen      {}", cfg.l0.listen_entries.len());
    println!("l0.channels    {}", cfg.l0.channels.len());
    println!("l0.proxies     {}", cfg.l0.proxies.len());
    println!("l0.client_duplex {}", cfg.client_duplex.len());
    for (target, endpoint) in cfg.client_mappings() {
        println!("client         {target} -> {endpoint}");
    }
    println!(
        "l0.routing_key {}",
        if cfg.l0.routing_key_file.is_some() {
            "set"
        } else {
            "unset"
        }
    );
    println!(
        "l0.eth_key     {}",
        if cfg.l0.routing_eth_key_file.is_some() {
            "set"
        } else {
            "unset"
        }
    );
    println!(
        "l0.billing_pgp {}",
        if cfg.l0.billing_pgp_file.is_some() {
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
    match Locator::parse(uri) {
        Ok(locator) => {
            let mut local_endpoint = None;
            if let Some(path) = config {
                let cfg = load_validated(path)?;
                local_endpoint = cfg.lookup_locator(&locator).map(|ip| ip.to_string());
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "locator": locator.display(),
                    "kind": "resource",
                    "host": locator_host_json(&locator.host),
                    "path_and_query": &locator.path_and_query,
                    "compatibility_service": locator.service().map(|service| service.as_str()),
                    "local_endpoint": local_endpoint,
                    "note": "web3:// identifies a wallet-addressed application resource. Exact BeamioTag only (CoNET ≠ CONET)."
                }))?
            );
            Ok(())
        }
        Err(resource_error) => match ClientTarget::parse(uri) {
            Ok(target) => {
                let mut local_endpoint = None;
                let target_display = target.display();
                if let Some(path) = config {
                    let cfg = load_validated(path)?;
                    local_endpoint = cfg
                        .client_mappings()
                        .into_iter()
                        .find(|(configured, _)| configured == &target_display)
                        .map(|(_, endpoint)| endpoint.to_string());
                }
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "locator": target_display,
                        "kind": "stream",
                        "host": locator_host_json(&target.host),
                        "logical_port": target.port,
                        "compatibility_service": target.service().map(|service| service.as_str()),
                        "local_endpoint": local_endpoint,
                        "note": "web3:// identifies a wallet-addressed application stream. Exact BeamioTag only (CoNET ≠ CONET)."
                    }))?
                );
                Ok(())
            }
            Err(stream_error) => Err(anyhow::anyhow!(
                "invalid web3:// URI: resource form failed ({resource_error}); stream form failed ({stream_error})"
            )),
        },
    }
}

fn locator_host_json(host: &LocatorHost) -> serde_json::Value {
    match host {
        LocatorHost::Eoa(eoa) => json!({ "kind": "eoa", "eoa": eoa }),
        LocatorHost::Tag(tag) => json!({ "kind": "tag", "tag": tag }),
    }
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
            println!("network  {}", state.overlay_cidr);
            println!("endpoint {}", state.local_vip);
            println!("started  {}", state.started_at);
            if !alive {
                println!("hint     conet-l0d teardown --config {}", path.display());
            }
        }
    }
    Ok(())
}

pub async fn start(path: &Path) -> anyhow::Result<()> {
    start_with_overrides(path, None, None, None, &[], &[], &[], &[]).await
}

pub async fn start_with_overrides(
    path: &Path,
    main_wallet: Option<String>,
    main_wallet_pgp: Option<&Path>,
    main_wallet_key: Option<&Path>,
    proxy_specs: &[String],
    proxy_duplex_specs: &[String],
    client_specs: &[String],
    client_duplex_specs: &[String],
) -> anyhow::Result<()> {
    if !cfg!(target_os = "linux") {
        anyhow::bail!(L0dError::NotLinux);
    }
    let mut raw = DaemonConfig::load(path)?;
    raw.apply_cli_overrides(
        main_wallet,
        main_wallet_pgp.map(Path::to_path_buf),
        main_wallet_key.map(Path::to_path_buf),
        proxy_specs,
        proxy_duplex_specs,
        client_specs,
        client_duplex_specs,
    )?;
    let cfg = raw.validate()?;
    // Hold this guard for the entire daemon lifetime.  Checking the JSON state
    // alone is racy: an earlier implementation removed an active process's
    // state and then started a second daemon over the same listeners.
    let _instance_lock = acquire_instance_lock(&cfg.raw.state_path)?;
    if let Some(state) = RuntimeState::load(&cfg.raw.state_path)? {
        if netops::process_alive(state.pid) && state.pid != std::process::id() {
            anyhow::bail!(
                "conet-l0d is already running with pid {} for state {}",
                state.pid,
                cfg.raw.state_path.display()
            );
        }
        tracing::warn!(pid = state.pid, "stale state present; tearing down first");
        teardown_inner(&cfg).await?;
    }
    let proxy_only = cfg.proxy_server_only();
    let packet_mode = cfg.packet_mode_required();
    if proxy_only {
        tracing::info!(
            proxies = cfg.l0.proxies.len(),
            proxy_duplex = cfg.l0.proxy_duplex.len(),
            "web3 server mode: accepting Layer Minus proxy lines"
        );
    } else if !packet_mode {
        tracing::info!(
            client_duplex = cfg.client_duplex.len(),
            "web3 client mode: local TCP endpoints carry bidirectional application streams"
        );
    }
    for (target, endpoint) in cfg.client_mappings() {
        tracing::info!(%target, %endpoint, "local web3 client endpoint");
    }
    if packet_mode {
        netops::install(&cfg).await?;
    }
    let state = RuntimeState::from_config(&cfg, std::process::id());
    if let Err(err) = state.write(&cfg.raw.state_path) {
        if packet_mode {
            let _ = netops::uninstall(&cfg, Some(&state)).await;
        }
        return Err(err.into());
    }
    if proxy_only {
        tracing::info!(
            proxies = cfg.l0.proxies.len(),
            proxy_duplex = cfg.l0.proxy_duplex.len(),
            "conet-l0d web3 server started"
        );
    } else if packet_mode {
        tracing::info!(
            endpoint = %cfg.local_vip,
            "conet-l0d request/response runtime started"
        );
    } else {
        tracing::info!("conet-l0d web3 duplex client started");
    }

    let run = async {
        #[cfg(unix)]
        {
            let mut sigterm =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
            if proxy_only {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = sigterm.recv() => {}
                    r = netops::proxy_loop(&cfg) => { r?; }
                }
            } else if packet_mode {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = sigterm.recv() => {}
                    r = netops::packet_loop(&cfg) => { r?; }
                }
            } else {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = sigterm.recv() => {}
                    r = netops::stream_loop(&cfg) => { r?; }
                }
            }
        }
        #[cfg(not(unix))]
        {
            if proxy_only {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    r = netops::proxy_loop(&cfg) => { r?; }
                }
            } else if packet_mode {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    r = netops::packet_loop(&cfg) => { r?; }
                }
            } else {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    r = netops::stream_loop(&cfg) => { r?; }
                }
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
            if !wait_dead(state.pid, Duration::from_secs(5)).await {
                anyhow::bail!(
                    "conet-l0d pid {} did not stop within 5s; state was preserved",
                    state.pid
                );
            }
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
    let owns_network = state
        .as_ref()
        .map(|saved| !saved.proxy_only && cfg.packet_mode_required())
        .unwrap_or(cfg.packet_mode_required());
    if owns_network {
        netops::uninstall(cfg, state.as_ref()).await?;
    }
    RuntimeState::remove(&cfg.raw.state_path)?;
    tracing::info!("conet-l0d runtime state removed");
    Ok(())
}

fn load_validated(path: &Path) -> Result<ValidatedConfig, L0dError> {
    DaemonConfig::load(path)?.validate()
}

async fn wait_dead(pid: u32, timeout: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    while netops::process_alive(pid) && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    !netops::process_alive(pid)
}

#[cfg(test)]
mod tests {
    use super::{acquire_instance_lock, instance_lock_path};

    #[test]
    fn instance_lock_is_exclusive_and_survives_lock_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = dir.path().join("runtime.json");

        let first = acquire_instance_lock(&state).expect("first lock");
        assert!(instance_lock_path(&state).exists());
        assert!(acquire_instance_lock(&state).is_err());

        drop(first);
        acquire_instance_lock(&state).expect("lock after owner exits");
    }
}
