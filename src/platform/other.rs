use crate::config::ValidatedConfig;
use crate::error::L0dError;
use crate::state::RuntimeState;

pub async fn install(_cfg: &ValidatedConfig) -> Result<(), L0dError> {
    Err(L0dError::NotLinux)
}

pub async fn uninstall(_cfg: &ValidatedConfig, _state: Option<&RuntimeState>) -> Result<(), L0dError> {
    Err(L0dError::NotLinux)
}

pub async fn packet_loop(_cfg: &ValidatedConfig) -> Result<(), L0dError> {
    Err(L0dError::NotLinux)
}

pub fn signal_stop(_pid: u32) -> Result<(), L0dError> {
    Err(L0dError::NotLinux)
}

pub fn process_alive(_pid: u32) -> bool {
    false
}
