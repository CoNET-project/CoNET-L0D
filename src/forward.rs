use crate::config::ValidatedConfig;
use crate::l0::L0Stub;
use crate::locator::Locator;
use crate::packet::ipv4_dest;
use std::net::Ipv4Addr;

#[derive(Debug, Default)]
#[allow(dead_code)]
pub struct ForwardStats {
    pub ipv4_packets: u64,
    pub stub: L0Stub,
}

impl ForwardStats {
    #[allow(dead_code)]
    pub fn on_tun_frame(&mut self, cfg: &ValidatedConfig, frame: &[u8]) {
        let Some(dest) = ipv4_dest(frame) else {
            return;
        };
        self.ipv4_packets += 1;
        let locator = lookup_dest(cfg, dest);
        tracing::info!(
            dest = %dest,
            packets = self.ipv4_packets,
            "overlay IPv4 on TUN"
        );
        self.stub.note_overlay_packet(dest, locator.as_ref());
    }
}

#[allow(dead_code)]
fn lookup_dest(cfg: &ValidatedConfig, dest: Ipv4Addr) -> Option<Locator> {
    if dest == cfg.local_vip {
        return Some(cfg.identity.clone());
    }
    cfg.peers
        .iter()
        .find(|p| p.vip == dest)
        .map(|p| p.locator.clone())
}
