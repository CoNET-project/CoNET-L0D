//! Layer Minus client **stub**.
//!
//! Do not claim a live SI command named `p2p_stream_*` or `listenKind: "l1p2p"`.
//! Any future byte-stream must reuse `POST /post` with `{ "data": "<armor>" }`.

use crate::locator::Locator;
use std::net::Ipv4Addr;

#[derive(Debug, Default)]
#[allow(dead_code)]
pub struct L0Stub {
    pub noted_packets: u64,
}

impl L0Stub {
    #[allow(dead_code)]
    pub fn note_overlay_packet(&mut self, dest: Ipv4Addr, locator: Option<&Locator>) {
        self.noted_packets += 1;
        match locator {
            Some(loc) => tracing::debug!(
                dest = %dest,
                locator = %loc.display(),
                "L0 stub: would encrypt overlay TCP to peer user PGP; not a live SI stream"
            ),
            None => tracing::debug!(
                dest = %dest,
                "L0 stub: dest vIP is not in the static peer table"
            ),
        }
    }
}
