//! Binary overlay frame. Not an SI command.

use crate::error::L0dError;

pub const MAGIC: &[u8; 4] = b"L0D1";
pub const VERSION: u8 = 1;
const HEADER_LEN: usize = 13;

/// `L0D1` + version + big-endian seq + raw IPv4 packet.
pub fn encode(seq: u64, ipv4: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + ipv4.len());
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(ipv4);
    out
}

#[allow(dead_code)]
pub fn decode(buf: &[u8]) -> Result<(u64, &[u8]), L0dError> {
    if buf.len() < HEADER_LEN {
        return Err(L0dError::L0(
            "overlay frame is shorter than the header".into(),
        ));
    }
    if &buf[0..4] != MAGIC {
        return Err(L0dError::L0("overlay frame magic is not L0D1".into()));
    }
    if buf[4] != VERSION {
        return Err(L0dError::L0(format!(
            "unsupported overlay frame version {}",
            buf[4]
        )));
    }
    let seq = u64::from_be_bytes(
        buf[5..HEADER_LEN]
            .try_into()
            .map_err(|_| L0dError::L0("overlay frame seq is truncated".into()))?,
    );
    Ok((seq, &buf[HEADER_LEN..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let pkt = [0x45, 0x00, 0x00, 0x14];
        let encoded = encode(7, &pkt);
        let (seq, rest) = decode(&encoded).expect("decode");
        assert_eq!(seq, 7);
        assert_eq!(rest, pkt);
    }

    #[test]
    fn reject_bad_magic() {
        let mut buf = encode(1, &[0x45]);
        buf[0] = b'X';
        assert!(decode(&buf).is_err());
    }
}
