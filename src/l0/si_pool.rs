//! GuardianNodesInfoV6 SI discovery (UI-style).
//!
//! Pull all registered SI nodes from chain, keep a local pool, and when a
//! caller needs an SI entry: random-pick → soft qualify → return base URL.
//! Static toml `entries` / `listen_entries` are optional overrides only.

use crate::error::L0dError;
use rand::seq::SliceRandom;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tiny_keccak::{Hasher, Keccak};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tokio::time::timeout;

/// Live GuardianNodesInfoV6 (same address as SilentPassUI / CoNET-SI).
pub const GUARDIAN_NODES_V6: &str = "0xBC6b53065b5647261396d002bDBA0d3396E0722f";

const PAGE: u64 = 100;
const REFRESH_INTERVAL: Duration = Duration::from_secs(300);
const FAIL_COOLDOWN: Duration = Duration::from_secs(180);
const QUALIFY_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_PICK_ATTEMPTS: usize = 24;
const MAX_CONSECUTIVE_RPC_FAIL: u32 = 5;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct SiNode {
    pub id: u64,
    pub domain: String,
    pub ip_addr: String,
    pub region: String,
    /// Base URL, e.g. `http://20ab90fe82d0e9e3.conet.network`
    pub entry: String,
}

pub struct SiPool {
    rpc: String,
    contract: String,
    nodes: RwLock<Vec<SiNode>>,
    last_refresh: RwLock<Option<Instant>>,
    /// entry → cooldown-until
    cooldown: RwLock<HashMap<String, Instant>>,
    http: reqwest::Client,
}

impl SiPool {
    pub fn new(rpc: &str) -> Result<Arc<Self>, L0dError> {
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(8))
            .timeout(Duration::from_secs(45))
            .pool_max_idle_per_host(0)
            .tcp_nodelay(true)
            .http1_only()
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("conet-l0d/0.1-si-pool")
            .build()
            .map_err(|e| L0dError::L0(format!("SI pool HTTP client: {e}")))?;
        Ok(Arc::new(Self {
            rpc: rpc.trim().trim_end_matches('/').to_string(),
            contract: GUARDIAN_NODES_V6.to_string(),
            nodes: RwLock::new(Vec::new()),
            last_refresh: RwLock::new(None),
            cooldown: RwLock::new(HashMap::new()),
            http,
        }))
    }

    /// Background refresh loop. Safe to spawn once per process.
    pub fn spawn_refresh_loop(self: &Arc<Self>) {
        let pool = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                match pool.refresh().await {
                    Ok(n) => {
                        tracing::info!(nodes = n, "SI pool refreshed from GuardianNodesInfoV6")
                    }
                    Err(err) => tracing::warn!(error = %err, "SI pool refresh failed"),
                }
                tokio::time::sleep(REFRESH_INTERVAL).await;
            }
        });
    }

    #[allow(dead_code)]
    pub async fn ensure_fresh(self: &Arc<Self>) -> Result<(), L0dError> {
        let stale = {
            let last = self.last_refresh.read().await;
            match *last {
                None => true,
                Some(t) => t.elapsed() >= REFRESH_INTERVAL,
            }
        };
        let empty = self.nodes.read().await.is_empty();
        if stale || empty {
            self.refresh().await?;
        }
        Ok(())
    }

    pub async fn refresh(&self) -> Result<usize, L0dError> {
        let mut all = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut offset: u64 = 0;
        let mut consecutive_fail = 0u32;
        for _ in 0..1000 {
            let page =
                match eth_call_get_all_nodes(&self.http, &self.rpc, &self.contract, offset, PAGE)
                    .await
                {
                    Ok(p) => {
                        consecutive_fail = 0;
                        p
                    }
                    Err(err) => {
                        let msg = err.to_string();
                        if msg.contains("empty (0x)") {
                            break;
                        }
                        consecutive_fail += 1;
                        tracing::warn!(
                            error = %err,
                            consecutive_fail,
                            offset,
                            "SI pool getAllNodes page failed"
                        );
                        if consecutive_fail >= MAX_CONSECUTIVE_RPC_FAIL {
                            return Err(err);
                        }
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        continue;
                    }
                };
            if page.is_empty() {
                break;
            }
            let page_len = page.len() as u64;
            let mut added = 0usize;
            for node in page {
                let key = node.entry.to_ascii_lowercase();
                if key.is_empty() || !seen.insert(key) {
                    continue;
                }
                all.push(node);
                added += 1;
            }
            if added == 0 || page_len < PAGE {
                break;
            }
            offset += page_len;
        }

        let n = all.len();
        if n == 0 {
            return Err(L0dError::L0(
                "SI pool: GuardianNodesInfoV6 returned zero nodes".into(),
            ));
        }
        *self.nodes.write().await = all;
        *self.last_refresh.write().await = Some(Instant::now());
        Ok(n)
    }

    pub async fn mark_failed(&self, entry: &str) {
        let key = entry.trim().trim_end_matches('/').to_string();
        if key.is_empty() {
            return;
        }
        self.cooldown
            .write()
            .await
            .insert(key, Instant::now() + FAIL_COOLDOWN);
    }

    /// Random pick from pool, skip exclude + cooldown, soft-qualify, return entry.
    pub async fn acquire(&self, exclude: Option<&str>) -> Result<String, L0dError> {
        self.ensure_fresh_inner().await?;
        let exclude_norm = exclude.map(|e| e.trim().trim_end_matches('/').to_string());
        let now = Instant::now();
        {
            let mut cd = self.cooldown.write().await;
            cd.retain(|_, until| *until > now);
        }

        let candidates: Vec<String> = {
            let nodes = self.nodes.read().await;
            if nodes.is_empty() {
                return Err(L0dError::L0("SI pool is empty".into()));
            }
            let cd = self.cooldown.read().await;
            let mut list: Vec<String> = nodes
                .iter()
                .map(|n| n.entry.clone())
                .filter(|e| {
                    let t = e.trim().trim_end_matches('/');
                    if exclude_norm.as_deref() == Some(t) {
                        return false;
                    }
                    !cd.contains_key(t) && !cd.contains_key(e)
                })
                .collect();
            if list.is_empty() {
                // All cooling down — allow any except exclude.
                list = nodes
                    .iter()
                    .map(|n| n.entry.clone())
                    .filter(|e| exclude_norm.as_deref() != Some(e.trim().trim_end_matches('/')))
                    .collect();
            }
            if list.is_empty() {
                // Single-node pool equal to exclude: still retry it.
                list = nodes.iter().map(|n| n.entry.clone()).collect();
            }
            list
        };

        let order = {
            let mut order = candidates;
            // ThreadRng is !Send — drop it before any `.await`.
            order.shuffle(&mut rand::thread_rng());
            order
        };

        let mut last_err = L0dError::L0("SI pool: no qualified node".into());
        for entry in order.into_iter().take(MAX_PICK_ATTEMPTS) {
            match qualify_entry(&entry).await {
                Ok(()) => {
                    tracing::debug!(entry = %entry, "SI pool acquired qualified entry");
                    return Ok(entry);
                }
                Err(err) => {
                    tracing::debug!(entry = %entry, error = %err, "SI pool qualify failed");
                    self.mark_failed(&entry).await;
                    last_err = err;
                }
            }
        }
        Err(last_err)
    }

    async fn ensure_fresh_inner(&self) -> Result<(), L0dError> {
        let stale = {
            let last = self.last_refresh.read().await;
            match *last {
                None => true,
                Some(t) => t.elapsed() >= REFRESH_INTERVAL,
            }
        };
        let empty = self.nodes.read().await.is_empty();
        if stale || empty {
            self.refresh().await?;
        }
        Ok(())
    }
}

fn entry_url_from_domain(domain: &str) -> Option<String> {
    let d = domain.trim().trim_matches(|c| c == '/' || c == '.');
    if d.is_empty() {
        return None;
    }
    // Domain labels in contract are hex-ish; UI uses lowercase host.
    let host = d.to_ascii_lowercase();
    if host.contains('.') || host.contains('/') || host.contains(':') {
        return None;
    }
    Some(format!("http://{host}.conet.network"))
}

async fn qualify_entry(entry: &str) -> Result<(), L0dError> {
    let host = host_of_entry(entry)?;
    // Soft check: TCP :80 reachable. pool_full is only known after listen POST;
    // callers mark_failed on that path so the next acquire skips the host.
    match timeout(QUALIFY_TIMEOUT, TcpStream::connect((host.as_str(), 80))).await {
        Ok(Ok(_stream)) => Ok(()),
        Ok(Err(err)) => Err(L0dError::L0(format!("SI qualify connect {host}:80: {err}"))),
        Err(_) => Err(L0dError::L0(format!(
            "SI qualify connect {host}:80 timed out"
        ))),
    }
}

fn host_of_entry(entry: &str) -> Result<String, L0dError> {
    let trimmed = entry.trim().trim_end_matches('/');
    let rest = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .ok_or_else(|| L0dError::L0("SI entry must be http(s) URL".into()))?;
    let host = rest
        .split('/')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    if host.is_empty() {
        return Err(L0dError::L0("SI entry host is empty".into()));
    }
    Ok(host)
}

fn get_all_nodes_selector() -> [u8; 4] {
    let mut hasher = Keccak::v256();
    hasher.update(b"getAllNodes(uint256,uint256)");
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    [out[0], out[1], out[2], out[3]]
}

fn encode_get_all_nodes_call(start: u64, count: u64) -> String {
    let mut data = Vec::with_capacity(4 + 64);
    data.extend_from_slice(&get_all_nodes_selector());
    data.extend_from_slice(&u256_be(start));
    data.extend_from_slice(&u256_be(count));
    format!("0x{}", hex::encode(data))
}

fn u256_be(v: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&v.to_be_bytes());
    out
}

async fn eth_call_get_all_nodes(
    http: &reqwest::Client,
    rpc: &str,
    contract: &str,
    start: u64,
    count: u64,
) -> Result<Vec<SiNode>, L0dError> {
    let call = encode_get_all_nodes_call(start, count);
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_call",
        "params": [{"to": contract, "data": call}, "latest"]
    });
    let response = http
        .post(rpc)
        .json(&body)
        .send()
        .await
        .map_err(|e| L0dError::L0(format!("SI pool eth_call transport: {e}")))?;
    let status = response.status();
    let text = response
        .text()
        .await
        .map_err(|e| L0dError::L0(format!("SI pool eth_call body: {e}")))?;
    if !status.is_success() {
        return Err(L0dError::L0(format!(
            "SI pool eth_call HTTP {status}: {}",
            text.chars().take(200).collect::<String>()
        )));
    }
    let v: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| L0dError::L0(format!("SI pool eth_call JSON: {e}")))?;
    if let Some(err) = v.get("error") {
        return Err(L0dError::L0(format!("SI pool eth_call error: {err}")));
    }
    let result = v
        .get("result")
        .and_then(|r| r.as_str())
        .ok_or_else(|| L0dError::L0("SI pool eth_call missing result".into()))?;
    if result == "0x" || result == "0X" {
        return Err(L0dError::L0("SI pool eth_call empty (0x)".into()));
    }
    decode_get_all_nodes_result(result)
}

pub fn decode_get_all_nodes_result(hex_data: &str) -> Result<Vec<SiNode>, L0dError> {
    let raw = hex_data
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X");
    let data = hex::decode(raw).map_err(|e| L0dError::L0(format!("getAllNodes hex: {e}")))?;
    if data.len() < 64 {
        return Err(L0dError::L0("getAllNodes ABI result is too short".into()));
    }
    let array_off = read_offset(&data, 0)?;
    if array_off + 32 > data.len() {
        return Err(L0dError::L0("getAllNodes array header truncated".into()));
    }
    let n = read_u64_word(&data, array_off)? as usize;
    // Element offsets are relative to the start of the offset table
    // (first byte after the length word), matching ethers AbiCoder on this
    // GuardianNodesInfoV6 payload — not relative to the length word itself.
    let heads_base = array_off + 32;
    let mut out = Vec::with_capacity(n.min(512));
    for i in 0..n {
        let off_pos = heads_base + i * 32;
        let tuple_rel = read_offset(&data, off_pos)?;
        let tuple_abs = heads_base
            .checked_add(tuple_rel)
            .ok_or_else(|| L0dError::L0("getAllNodes tuple abs overflow".into()))?;
        let id = read_u64_word(&data, tuple_abs)?;
        let pgp_off = read_offset(&data, tuple_abs + 32)?;
        let key_off = read_offset(&data, tuple_abs + 64)?;
        let ip_off = read_offset(&data, tuple_abs + 96)?;
        let region_off = read_offset(&data, tuple_abs + 128)?;
        let _pgp = read_string(&data, tuple_abs + pgp_off)?;
        let domain = read_string(&data, tuple_abs + key_off)?;
        let ip_addr = read_string(&data, tuple_abs + ip_off)?;
        let region = read_string(&data, tuple_abs + region_off)?;
        let Some(entry) = entry_url_from_domain(&domain) else {
            continue;
        };
        out.push(SiNode {
            id,
            domain: domain.trim().to_string(),
            ip_addr: ip_addr.trim().to_string(),
            region: region.trim().to_string(),
            entry,
        });
    }
    Ok(out)
}

fn read_offset(data: &[u8], at: usize) -> Result<usize, L0dError> {
    Ok(read_u64_word(data, at)? as usize)
}

fn read_u64_word(data: &[u8], at: usize) -> Result<u64, L0dError> {
    if at + 32 > data.len() {
        return Err(L0dError::L0("ABI word truncated".into()));
    }
    let mut word = [0u8; 8];
    word.copy_from_slice(&data[at + 24..at + 32]);
    Ok(u64::from_be_bytes(word))
}

fn read_string(data: &[u8], offset: usize) -> Result<String, L0dError> {
    if offset + 32 > data.len() {
        return Err(L0dError::L0("ABI string header truncated".into()));
    }
    let len = read_u64_word(data, offset)? as usize;
    let start = offset + 32;
    let end = start
        .checked_add(len)
        .ok_or_else(|| L0dError::L0("ABI string length overflow".into()))?;
    if end > data.len() {
        return Err(L0dError::L0("ABI string payload truncated".into()));
    }
    String::from_utf8(data[start..end].to_vec())
        .map_err(|_| L0dError::L0("ABI string is not UTF-8".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selector_matches_ethers() {
        assert_eq!(hex::encode(get_all_nodes_selector()), "4272c81e");
    }

    #[test]
    fn entry_url_lowercases_domain() {
        assert_eq!(
            entry_url_from_domain("20AB90FE82D0E9E3").as_deref(),
            Some("http://20ab90fe82d0e9e3.conet.network")
        );
        assert!(entry_url_from_domain("").is_none());
        assert!(entry_url_from_domain("evil.example").is_none());
    }

    #[test]
    fn decodes_live_two_node_page() {
        let hex = "0x0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000540000000000000000000000000000000000000000000000000000000000000006400000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000440000000000000000000000000000000000000000000000000000000000000048000000000000000000000000000000000000000000000000000000000000004c000000000000000000000000000000000000000000000000000000000000003644c5330744c5331435255644a54694251523141675546564354456c44494574465753424354453944537930744c53307443677034616b3146576e4579566a56345755704c64316c43516b464959564a334f454a42555752426148464a61545a7a55586776643346765a3051725644425a5a6e52336333673361554a6f5a44524a6557674b62464a44526d354b53304a505245684f533270434e466b79536b4e52616b5636546e70464e553536546b564f56475273546d314b52553545566d6852656b4a72576d315752314a455554564e4d6b6b78436b39565754565352474d7955584e4c54554a43515664445a304572516c6c4b62584a615747354351584e4b516e646e536d7442636c70595955787664544e76546b463456556c445a3146585155464a51677042614774435158427a5245466f4e454a476155564665475a6a527a4a704d3231684e6e4d334d6c5a5354304e306247527664576b335a57637751554649526d644255554e79564468354d566b324f55674b6231685553475a6b5448564661797459565552776354524451585a714e3074725348686955453552565374515555517655325243596c4a5659335a5461337036623155306445786a5748685753544252436c4e554f4870684d576832627a4e535a4664445a327834515642505430465362584a61574735465a323979516d6446525546615a465a42555656435156466b51574e4d55476877616a52585a474e61546770314e3342514c30784d57566c71656d6377536d683557585a57634552335657395959546c5862577476524546525a306833626d644652304a5a5330464462305a6e625746306247566a536d7442636c6f4b5747464d6233557a6230354263484e4e526d6c465258686d5930637961544e7459545a7a4e7a4a57556b39446447786b623356704e32566e4d45464252485a5351564645636d64504f45737261487068436e52494e457855634564614e30397a59304d3354544a61644656574d487059633268496245567565464d31546d64454c31704451556868596d737757545133596b464f5230633353334a6a63584e4957516f7a6347316d57564a51526d4e3259327442623142705957646a50516f39566d68445a676f744c5330744c55564f52434251523141675546564354456c44494574465753424354453944537930744c53307443673d3d0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000103939373745394134353138374444383000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f3231372e3136302e3138392e313539000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000054e572e4445000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006500000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000440000000000000000000000000000000000000000000000000000000000000048000000000000000000000000000000000000000000000000000000000000004c000000000000000000000000000000000000000000000000000000000000003644c5330744c5331435255644a54694251523141675546564354456c44494574465753424354453944537930744c53307443677034616b3146576d3835535652435755704c64316c43516b464959564a334f454a425557524264455a486131684e5445685451556f7a616b316151565a745a6b313264455a474e7a52516133425a556a6b4b56445577637a6c4f5a4849325347354f533270434e453574536b644e4d455a6f546e704a4d6b315856586c4e56557073546c5661616b35365a336852563031335431565a4e553545597a465a656d6843436b3136556b4a6161315a7357574e4c54554a43515664445a304572516c6c4b62576f776145314351584e4b516e646e536d74505a53396e655735454d545a556245463456556c445a3146585155464a51677042614774435158427a5245466f4e454a476155564663457078544545795258424c5256424562474644535455334b30524c59314259634539565155464d5132524255554e4a526e6c454c307873596c6b4b556b6458656e6c6855797372516b4a4f53584e7354323972644842496548706a5a314d72633051335a45706e5a3056426545643252467052615855304d6d7733566d785464485a73546a524b4f557079436b6458536e6b34623342585657786e61453147593170495a334a505430465362576f77614531465a323979516d6446525546615a465a42555656435156466b515846305a585a474e5456534d564a495677706f4d307734626d393256325a7961586c5964565a61536d3876646e645656486c735558646b5132646e524546525a306833626d644652304a5a5330464462305a6e6257465155305633536d74505a53384b5a336c75524445325647784263484e4e526d6c465258424b635578424d6b5677533056515247786851306b314e79744553324e5157484250565546425345684751564644596b39726246647762564a33436d6c76636b7849614549354f5870695955356d633234354c30597964557033556e4d355654417662554a426146464651576377566b396a4e4735455a6d4935545551776445685555445a6a636b51324d67704759566c4761564533646b3554516d387a524856596248637750516f395746685464516f744c5330744c55564f52434251523141675546564354456c44494574465753424354453944537930744c53307443673d3d0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000104234434230413431333532453942444600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000d39332e39332e3131322e3138370000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000054d442e4553000000000000000000000000000000000000000000000000000000";
        let nodes = decode_get_all_nodes_result(hex).expect("decode");
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].id, 100);
        assert_eq!(nodes[0].domain.to_ascii_uppercase(), "9977E9A45187DD80");
        assert_eq!(nodes[0].entry, "http://9977e9a45187dd80.conet.network");
        assert_eq!(nodes[1].id, 101);
    }
}
