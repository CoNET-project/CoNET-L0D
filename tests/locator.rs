use std::path::PathBuf;
use std::process::Command;

fn bin() -> PathBuf {
    env!("CARGO_BIN_EXE_conet-l0d").into()
}

fn example_config() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config/conet-l0d.example.toml")
}

#[test]
fn check_config_example() {
    let out = Command::new(bin())
        .args(["check-config", "--config"])
        .arg(example_config())
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("ok"));
    assert!(stdout.contains("100.64.0.5"));
}

#[test]
fn resolve_eoa() {
    let out = Command::new(bin())
        .args([
            "resolve",
            "web3://0x1111111111111111111111111111111111111111/p2p/geth",
            "--config",
        ])
        .arg(example_config())
        .output()
        .expect("run");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("0x1111111111111111111111111111111111111111"));
    assert!(stdout.contains("100.64.0.5"));
}

#[test]
fn resolve_exact_tags_differ() {
    let a = Command::new(bin())
        .args(["resolve", "web3://CoNET.web3/p2p/geth"])
        .output()
        .expect("run");
    let b = Command::new(bin())
        .args(["resolve", "web3://CONET.web3/p2p/geth"])
        .output()
        .expect("run");
    assert!(a.status.success());
    assert!(b.status.success());
    let sa = String::from_utf8_lossy(&a.stdout);
    let sb = String::from_utf8_lossy(&b.stdout);
    assert!(sa.contains("\"tag\": \"CoNET\""));
    assert!(sb.contains("\"tag\": \"CONET\""));
    assert_ne!(sa, sb);
}

#[test]
fn reject_results_zero() {
    let out = Command::new(bin())
        .args(["resolve", "web3://results[0]/p2p/geth"])
        .output()
        .expect("run");
    assert!(!out.status.success());
}

#[test]
fn start_is_linux_only_on_macos() {
    if cfg!(target_os = "linux") {
        return;
    }
    let out = Command::new(bin())
        .args(["start", "--config"])
        .arg(example_config())
        .output()
        .expect("run");
    assert!(!out.status.success());
    let err = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        err.contains("Linux") || err.contains("CAP_NET_ADMIN"),
        "{err}"
    );
}
