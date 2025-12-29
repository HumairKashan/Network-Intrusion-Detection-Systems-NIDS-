#![allow(dead_code)]
use std::net::Ipv4Addr;

pub fn protocol_string(proto: u8) -> String {
    match proto {
        6 => "TCP".to_string(),
        17 => "UDP".to_string(),
        1 => "ICMP".to_string(),
        _ => format!("PROTO_{}", proto),
    }
}

/// Extract IPv4 src/dst and ports (if TCP/UDP) from raw ethernet frame bytes.
/// Returns (src_ip, dst_ip, src_port, dst_port, proto)
pub fn extract_ipv4_and_ports(pkt: &[u8]) -> Option<(String, String, u16, u16, u8)> {
    if pkt.len() < 14 + 20 {
        return None;
    }

    // Ethernet type at bytes 12-13
    let ethertype = u16::from_be_bytes([pkt[12], pkt[13]]);
    if ethertype != 0x0800 {
        // not IPv4
        return None;
    }

    let ip_start = 14;
    let ver_ihl = pkt[ip_start];
    let version = ver_ihl >> 4;
    if version != 4 {
        return None;
    }

    let ihl = (ver_ihl & 0x0F) as usize * 4;
    if pkt.len() < ip_start + ihl {
        return None;
    }

    let proto = pkt[ip_start + 9];

    let src = Ipv4Addr::new(
        pkt[ip_start + 12],
        pkt[ip_start + 13],
        pkt[ip_start + 14],
        pkt[ip_start + 15],
    );

    let dst = Ipv4Addr::new(
        pkt[ip_start + 16],
        pkt[ip_start + 17],
        pkt[ip_start + 18],
        pkt[ip_start + 19],
    );

    let mut src_port: u16 = 0;
    let mut dst_port: u16 = 0;

    // L4 start
    let l4_start = ip_start + ihl;
    if proto == 6 || proto == 17 {
        if pkt.len() < l4_start + 4 {
            return None;
        }
        src_port = u16::from_be_bytes([pkt[l4_start], pkt[l4_start + 1]]);
        dst_port = u16::from_be_bytes([pkt[l4_start + 2], pkt[l4_start + 3]]);
    }

    Some((src.to_string(), dst.to_string(), src_port, dst_port, proto))
}
