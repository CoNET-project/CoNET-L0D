use std::collections::HashSet;
use std::net::Ipv4Addr;

pub const OVERLAY_GETH_TCP: u16 = 8400;
pub const OVERLAY_BEACON_TCP: u16 = 4200;
pub const OVERLAY_BEACON_UDP: u16 = 4300;

/// Default overlay service ports when `[[l0.channels]]` is omitted.
pub const DEFAULT_OVERLAY_PORTS: [u16; 3] =
    [OVERLAY_GETH_TCP, OVERLAY_BEACON_TCP, OVERLAY_BEACON_UDP];

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

/// TCP/UDP source and dest ports. `None` if the packet is not IPv4 TCP/UDP.
#[allow(dead_code)]
pub fn ipv4_l4_ports(packet: &[u8]) -> Option<(u16, u16)> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    let ihl = ((packet[0] & 0x0f) as usize).saturating_mul(4);
    if ihl < 20 || packet.len() < ihl + 4 {
        return None;
    }
    let proto = packet[9];
    if proto != 6 && proto != 17 {
        return None;
    }
    let sport = u16::from_be_bytes([packet[ihl], packet[ihl + 1]]);
    let dport = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
    Some((sport, dport))
}

/// Pick the overlay channel port from a well-known sport **or** dport.
///
/// Return-path TCP has dest = ephemeral and source = 8400/4200/4300.
/// Both sides well-known and different → fail-closed (`None`).
#[allow(dead_code)]
pub fn overlay_channel_port(packet: &[u8], known: &HashSet<u16>) -> Option<u16> {
    if known.is_empty() {
        return None;
    }
    let (sport, dport) = ipv4_l4_ports(packet)?;
    let src_hit = known.contains(&sport);
    let dst_hit = known.contains(&dport);
    match (src_hit, dst_hit) {
        (true, true) if sport != dport => None,
        (true, _) => Some(sport),
        (false, true) => Some(dport),
        (false, false) => None,
    }
}

pub fn default_overlay_port_set() -> HashSet<u16> {
    DEFAULT_OVERLAY_PORTS.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_tcp(sport: u16, dport: u16) -> Vec<u8> {
        let mut p = vec![0u8; 40];
        p[0] = 0x45;
        p[2] = 0;
        p[3] = 40;
        p[9] = 6;
        p[16] = 100;
        p[17] = 64;
        p[18] = 0;
        p[19] = 6;
        p[20..22].copy_from_slice(&sport.to_be_bytes());
        p[22..24].copy_from_slice(&dport.to_be_bytes());
        p
    }

    fn ipv4_udp(sport: u16, dport: u16) -> Vec<u8> {
        let mut p = ipv4_tcp(sport, dport);
        p[9] = 17;
        p
    }

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

    #[test]
    fn reads_tcp_ports() {
        let pkt = ipv4_tcp(57594, 8400);
        assert_eq!(ipv4_l4_ports(&pkt), Some((57594, 8400)));
    }

    #[test]
    fn outbound_uses_dest_8400() {
        let known = default_overlay_port_set();
        assert_eq!(
            overlay_channel_port(&ipv4_tcp(57594, 8400), &known),
            Some(8400)
        );
    }

    #[test]
    fn return_path_uses_source_8400() {
        let known = default_overlay_port_set();
        assert_eq!(
            overlay_channel_port(&ipv4_tcp(8400, 57594), &known),
            Some(8400)
        );
    }

    #[test]
    fn beacon_udp_4300() {
        let known = default_overlay_port_set();
        assert_eq!(
            overlay_channel_port(&ipv4_udp(4300, 4300), &known),
            Some(4300)
        );
        assert_eq!(
            overlay_channel_port(&ipv4_udp(35256, 4300), &known),
            Some(4300)
        );
    }

    #[test]
    fn conflict_two_well_known_ports_is_none() {
        let known = default_overlay_port_set();
        assert_eq!(overlay_channel_port(&ipv4_tcp(8400, 4200), &known), None);
    }

    #[test]
    fn unknown_ports_fail_closed() {
        let known = default_overlay_port_set();
        assert_eq!(overlay_channel_port(&ipv4_tcp(1234, 5678), &known), None);
    }
}
