use crate::config::ValidatedConfig;
use crate::error::L0dError;
use crate::platform;
use crate::state::RuntimeState;

pub async fn install(cfg: &ValidatedConfig) -> Result<(), L0dError> {
    platform::install(cfg).await
}

pub async fn uninstall(
    cfg: &ValidatedConfig,
    state: Option<&RuntimeState>,
) -> Result<(), L0dError> {
    platform::uninstall(cfg, state).await
}

pub async fn packet_loop(cfg: &ValidatedConfig) -> Result<(), L0dError> {
    platform::packet_loop(cfg).await
}

pub fn signal_stop(pid: u32) -> Result<(), L0dError> {
    platform::signal_stop(pid)
}

pub fn process_alive(pid: u32) -> bool {
    platform::process_alive(pid)
}
