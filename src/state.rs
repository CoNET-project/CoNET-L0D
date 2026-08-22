use crate::config::ValidatedConfig;
use crate::error::L0dError;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeState {
    pub pid: u32,
    pub tun_name: String,
    pub overlay_cidr: String,
    pub local_vip: String,
    pub iptables_chain: String,
    pub started_at: String,
    #[serde(default)]
    pub proxy_only: bool,
    #[serde(default)]
    pub client_mappings: Vec<String>,
}

impl RuntimeState {
    pub fn from_config(cfg: &ValidatedConfig, pid: u32) -> Self {
        Self {
            pid,
            tun_name: cfg.raw.tun_name.clone(),
            overlay_cidr: cfg.overlay.display(),
            local_vip: cfg.local_vip.to_string(),
            iptables_chain: cfg.raw.iptables_chain.clone(),
            started_at: chrono::Utc::now().to_rfc3339(),
            proxy_only: cfg.proxy_server_only(),
            client_mappings: cfg
                .client_mappings()
                .into_iter()
                .map(|(target, endpoint)| format!("{target} -> {endpoint}"))
                .collect(),
        }
    }

    pub fn load(path: &Path) -> Result<Option<Self>, L0dError> {
        if !path.exists() {
            return Ok(None);
        }
        let text = std::fs::read_to_string(path)?;
        let state = serde_json::from_str(&text)
            .map_err(|e| L0dError::Config(format!("state file: {e}")))?;
        Ok(Some(state))
    }

    pub fn write(&self, path: &Path) -> Result<(), L0dError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let text = serde_json::to_string_pretty(self)
            .map_err(|e| L0dError::Config(format!("encode state: {e}")))?;
        std::fs::write(path, text)?;
        Ok(())
    }

    pub fn remove(path: &Path) -> Result<(), L0dError> {
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        Ok(())
    }
}
