use std::net::Ipv4Addr;

/// Dest IPv4 from a TUN IPv4 packet (IFF_NO_PI).
#[allow(dead_code)]
pub fn ipv4_dest(packet: &[u8]) -> Option<Ipv4Addr> {
    if packet.len() < 20 {
        return None;
    }
    if packet[0] >> 4 != 4 {
        return None;
    }
    Some(Ipv4Addr::new(
        packet[16], packet[17], packet[18], packet[19],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_dest() {
        let mut pkt = [0u8; 20];
        pkt[0] = 0x45;
        pkt[16] = 100;
        pkt[17] = 64;
        pkt[18] = 0;
        pkt[19] = 1;
        assert_eq!(ipv4_dest(&pkt), Some(Ipv4Addr::new(100, 64, 0, 1)));
    }
}
