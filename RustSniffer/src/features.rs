#![allow(dead_code)]
use serde::Serialize;

#[derive(Serialize, Debug, Clone)]
pub struct PacketFeatures {
    pub duration: f64,
    pub protocol: String,
    pub src_bytes: usize,
    pub dst_bytes: usize,
    pub packet_count: u32,
    pub is_syn: bool,
    pub is_ack: bool,
    pub is_fin: bool,
}

impl PacketFeatures {
    pub fn new() -> Self {
        PacketFeatures {
            duration: 0.0,
            protocol: String::from("UNKNOWN"),
            src_bytes: 0,
            dst_bytes: 0,
            packet_count: 0,
            is_syn: false,
            is_ack: false,
            is_fin: false,
        }
    }

    pub fn from_tcp_flags(flags: u8) -> (bool, bool, bool) {
        let syn = (flags & 0x02) != 0;
        let ack = (flags & 0x10) != 0;
        let fin = (flags & 0x01) != 0;
        (syn, ack, fin)
    }
}

/// Extract basic features for ML detection
pub fn extract_basic_features(packet_size: usize, protocol: &str) -> PacketFeatures {
    let mut features = PacketFeatures::new();
    features.src_bytes = packet_size;
    features.protocol = protocol.to_string();
    features.packet_count = 1;
    features
}

/// Calculate statistics for packet flow
pub fn calculate_flow_stats(packets: &[usize]) -> (f64, f64, f64) {
    if packets.is_empty() {
        return (0.0, 0.0, 0.0);
    }

    let sum: usize = packets.iter().sum();
    let count = packets.len() as f64;
    let mean = sum as f64 / count;

    // Calculate variance
    let variance: f64 = packets
        .iter()
        .map(|&x| {
            let diff = x as f64 - mean;
            diff * diff
        })
        .sum::<f64>()
        / count;

    let std_dev = variance.sqrt();

    (mean, variance, std_dev)
}