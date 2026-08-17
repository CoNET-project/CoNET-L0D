use crate::config::ValidatedConfig;
use crate::error::L0dError;
use crate::forward::ForwardStats;
use crate::state::RuntimeState;
use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd};
use std::process::Stdio;
use tokio::io::AsyncReadExt;
use tokio::process::Command;

const COMMENT: &str = "conet-l0d";

pub async fn install(cfg: &ValidatedConfig) -> Result<(), L0dError> {
    let tun = &cfg.raw.tun_name;
    let vip = cfg.local_vip;
    let cidr = cfg.overlay.display();
    let chain = &cfg.raw.iptables_chain;

    let _ = run_ip(&["tuntap", "add", "dev", tun, "mode", "tun"]).await;
    run_ip(&["link", "set", tun, "up"]).await?;
    let vip32 = format!("{vip}/32");
    let _ = run_ip(&["addr", "add", &vip32, "dev", tun]).await;
    let _ = run_ip(&["route", "add", &cidr, "dev", tun]).await;

    for table in ["filter", "mangle"] {
        ensure_chain(table, chain).await?;
        flush_chain(table, chain).await?;
        append_return(table, chain, "-d", "127.0.0.0/8").await?;
        append_return(table, chain, "-s", "127.0.0.0/8").await?;
        if let Some(uid) = cfg.raw.validator_uid {
            append_uid_return(table, chain, uid).await?;
        }
    }

    ensure_jump("filter", "OUTPUT", chain).await?;
    ensure_jump("mangle", "OUTPUT", chain).await?;
    ensure_jump("mangle", "PREROUTING", chain).await?;
    Ok(())
}

pub async fn uninstall(cfg: &ValidatedConfig, state: Option<&RuntimeState>) -> Result<(), L0dError> {
    let tun = state
        .map(|s| s.tun_name.as_str())
        .unwrap_or(cfg.raw.tun_name.as_str());
    let cidr = state
        .map(|s| s.overlay_cidr.clone())
        .unwrap_or_else(|| cfg.overlay.display());
    let vip = state
        .map(|s| s.local_vip.clone())
        .unwrap_or_else(|| cfg.local_vip.to_string());
    let chain = state
        .map(|s| s.iptables_chain.as_str())
        .unwrap_or(cfg.raw.iptables_chain.as_str());

    let _ = delete_jump("filter", "OUTPUT", chain).await;
    let _ = delete_jump("mangle", "OUTPUT", chain).await;
    let _ = delete_jump("mangle", "PREROUTING", chain).await;

    for table in ["filter", "mangle"] {
        let _ = iptables(table, &["-F", chain]).await;
        let _ = iptables(table, &["-X", chain]).await;
    }

    let vip32 = format!("{vip}/32");
    let _ = run_ip(&["route", "del", &cidr, "dev", tun]).await;
    let _ = run_ip(&["addr", "del", &vip32, "dev", tun]).await;
    let _ = run_ip(&["link", "del", tun]).await;
    Ok(())
}

pub async fn packet_loop(cfg: &ValidatedConfig) -> Result<(), L0dError> {
    let fd = open_tun(&cfg.raw.tun_name)?;
    let std_file = unsafe { std::fs::File::from_raw_fd(fd.into_raw_fd()) };
    let mut file = tokio::fs::File::from_std(std_file);
    let mut buf = vec![0u8; 2048];
    let mut stats = ForwardStats::new(cfg);
    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        stats.on_tun_frame(cfg, &buf[..n]);
    }
    Ok(())
}

pub fn signal_stop(pid: u32) -> Result<(), L0dError> {
    let rc = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ESRCH) {
            return Ok(());
        }
        return Err(L0dError::Net(format!("kill {pid}: {err}")));
    }
    Ok(())
}

pub fn process_alive(pid: u32) -> bool {
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

fn open_tun(name: &str) -> Result<OwnedFd, L0dError> {
    let fd = unsafe { libc::open(b"/dev/net/tun\0".as_ptr() as *const libc::c_char, libc::O_RDWR) };
    if fd < 0 {
        return Err(L0dError::Net(format!(
            "open /dev/net/tun: {}",
            std::io::Error::last_os_error()
        )));
    }
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    let name_c = std::ffi::CString::new(name)
        .map_err(|_| L0dError::Config("tun_name contains NUL".into()))?;
    let bytes = name_c.as_bytes();
    if bytes.len() >= libc::IFNAMSIZ {
        return Err(L0dError::Config("tun_name is too long".into()));
    }
    unsafe {
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr() as *const libc::c_char,
            ifr.ifr_name.as_mut_ptr(),
            bytes.len(),
        );
        ifr.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;
        let rc = libc::ioctl(fd, libc::TUNSETIFF, &mut ifr);
        if rc < 0 {
            return Err(L0dError::Net(format!(
                "TUNSETIFF {name}: {}",
                std::io::Error::last_os_error()
            )));
        }
    }
    Ok(owned)
}

async fn run_ip(args: &[&str]) -> Result<(), L0dError> {
    run("ip", args).await
}

async fn iptables(table: &str, args: &[&str]) -> Result<std::process::Output, L0dError> {
    let mut cmd = Command::new("iptables");
    cmd.arg("-t").arg(table).args(args);
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    tracing::debug!(table, ?args, "iptables");
    cmd.output()
        .await
        .map_err(|e| L0dError::Net(format!("iptables: {e}")))
}

async fn run(bin: &str, args: &[&str]) -> Result<(), L0dError> {
    tracing::debug!(bin, ?args, "netops");
    let out = Command::new(bin)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|e| L0dError::Net(format!("{bin}: {e}")))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(L0dError::Net(format!(
            "{bin} {} failed: {}",
            args.join(" "),
            stderr.trim()
        )));
    }
    Ok(())
}

async fn ensure_chain(table: &str, chain: &str) -> Result<(), L0dError> {
    if iptables(table, &["-L", chain, "-n"]).await?.status.success() {
        return Ok(());
    }
    let out = iptables(table, &["-N", chain]).await?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        if !stderr.contains("already") {
            return Err(L0dError::Net(format!(
                "iptables -t {table} -N {chain}: {}",
                stderr.trim()
            )));
        }
    }
    Ok(())
}

async fn flush_chain(table: &str, chain: &str) -> Result<(), L0dError> {
    let _ = iptables(table, &["-F", chain]).await?;
    Ok(())
}

async fn append_return(
    table: &str,
    chain: &str,
    dir: &str,
    cidr: &str,
) -> Result<(), L0dError> {
    let out = iptables(
        table,
        &[
            "-A", chain, dir, cidr, "-m", "comment", "--comment", COMMENT, "-j", "RETURN",
        ],
    )
    .await?;
    if !out.status.success() {
        return Err(L0dError::Net(format!(
            "failed to append loopback RETURN on {table}/{chain}"
        )));
    }
    Ok(())
}

async fn append_uid_return(table: &str, chain: &str, uid: u32) -> Result<(), L0dError> {
    let uid_s = uid.to_string();
    let out = iptables(
        table,
        &[
            "-A",
            chain,
            "-m",
            "owner",
            "--uid-owner",
            &uid_s,
            "-m",
            "comment",
            "--comment",
            COMMENT,
            "-j",
            "RETURN",
        ],
    )
    .await?;
    if !out.status.success() {
        return Err(L0dError::Net(format!(
            "failed to RETURN validator uid {uid} on {table}/{chain}"
        )));
    }
    Ok(())
}

async fn ensure_jump(table: &str, hook: &str, chain: &str) -> Result<(), L0dError> {
    if iptables(table, &["-C", hook, "-j", chain])
        .await?
        .status
        .success()
    {
        return Ok(());
    }
    let out = iptables(table, &["-I", hook, "1", "-j", chain]).await?;
    if !out.status.success() {
        return Err(L0dError::Net(format!(
            "failed to insert {table} {hook} -> {chain}"
        )));
    }
    Ok(())
}

async fn delete_jump(table: &str, hook: &str, chain: &str) -> Result<(), L0dError> {
    let _ = iptables(table, &["-D", hook, "-j", chain]).await;
    Ok(())
}
