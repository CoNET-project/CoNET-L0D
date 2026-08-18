use crate::config::ValidatedConfig;
use crate::l0::L0Client;
use crate::packet::{ipv4_dest, overlay_channel_port};

#[derive(Debug, Default)]
#[allow(dead_code)]
pub struct ForwardStats {
    pub ipv4_packets: u64,
    pub l0: L0Client,
}

impl ForwardStats {
    #[allow(dead_code)]
    pub fn new(cfg: &ValidatedConfig) -> Self {
        Self {
            ipv4_packets: 0,
            l0: L0Client::from_config(cfg),
        }
    }

    #[allow(dead_code)]
    pub fn on_tun_frame(&mut self, cfg: &ValidatedConfig, frame: &[u8]) {
        let Some(dest) = ipv4_dest(frame) else {
            return;
        };
        self.ipv4_packets += 1;
        let known = cfg.overlay_ports();
        let locator = match overlay_channel_port(frame, &known) {
            Some(_port) if dest == cfg.local_vip => Some(cfg.identity.clone()),
            Some(port) => cfg.lookup_peer(dest, port).map(|p| p.locator.clone()),
            None => None,
        };
        tracing::debug!(
            dest = %dest,
            packets = self.ipv4_packets,
            "overlay IPv4 on TUN"
        );
        self.l0
            .note_overlay_packet(dest, locator.as_ref(), frame);
    }
}
