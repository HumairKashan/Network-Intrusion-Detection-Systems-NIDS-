#![allow(dead_code)]
use anyhow::Context;
use base64::{engine::general_purpose, Engine as _};
use pcap::{Capture, Device};
use serde::Serialize;
use std::net::Ipv4Addr;
use std::time::Instant;

use crate::sender::SocketSender;
use crate::utils::{extract_ipv4_and_ports, protocol_string};

#[derive(Serialize, Debug, Clone)]
pub struct RawPacketData {
    pub timestamp: u128,
    pub protocol: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub length: usize,

    // Your receiver.py explicitly looks for this
    pub raw_data: String,

    // Optional fields receiver.py may read (safe defaults)
    pub packet_count: u32,
    pub duration: f64,
    pub src_bytes: usize,
    pub dst_bytes: usize,
}

/// Prefer Wi-Fi/Ethernet adapters by *description*.
/// Avoid WAN Miniport, Loopback, and similar "fake" adapters.
fn pick_device() -> anyhow::Result<Device> {
    let devices = Device::list().context("Failed to list pcap devices")?;

    // Rank devices: prefer non-loopback, non-wan-miniport, etc.
    let mut candidates: Vec<Device> = devices
        .into_iter()
        .filter(|d| {
            let name = d.name.to_lowercase();
            let desc = d.desc.clone().unwrap_or_default().to_lowercase();
            let bad = [
                "loopback",
                "npcap loopback",
                "wan miniport",
                "isatap",
                "teredo",
                "bluetooth",
                "virtual",
                "vmware",
                "hyper-v",
                "pseudo",
                "vpn",
                "tunnel",
            ];
            !bad.iter().any(|b| name.contains(b) || desc.contains(b))
        })
        .collect();

    if candidates.is_empty() {
        // fallback: just take first available
        let all = Device::list().context("Failed to list pcap devices")?;
        return all
            .into_iter()
            .next()
            .context("No pcap devices found (even fallback)");
    }

    // Prefer devices with description containing "wi-fi" or "ethernet"
    candidates.sort_by_key(|d| {
        let desc = d.desc.clone().unwrap_or_default().to_lowercase();
        let name = d.name.to_lowercase();
        let mut score = 0i32;
        if desc.contains("wi-fi") || desc.contains("wifi") || name.contains("wi-fi") || name.contains("wifi") {
            score -= 10;
        }
        if desc.contains("ethernet") || name.contains("ethernet") {
            score -= 8;
        }
        score
    });

    Ok(candidates.remove(0))
}

fn build_packet_struct(pkt: &[u8]) -> Option<RawPacketData> {
    // Extract IPv4 / ports if possible
    let (src_ip, dst_ip, src_port, dst_port, proto) = extract_ipv4_and_ports(pkt)?;

    let timestamp = chrono::Utc::now().timestamp_millis() as u128;
    let protocol = protocol_string(proto);

    let length = pkt.len();

    // base64 encode raw bytes
    let raw_data = general_purpose::STANDARD.encode(pkt);

    Some(RawPacketData {
        timestamp,
        protocol,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        length,
        raw_data,
        packet_count: 1,
        duration: 0.0,
        src_bytes: length,
        dst_bytes: 0,
    })
}

pub async fn start_capture() -> anyhow::Result<()> {
    let device = pick_device().context("Failed to pick a suitable device")?;
    println!("[INFO] Using device: {} ({:?})", device.name, device.desc);

    // Windows/Npcap likes immediate mode + small timeout
    let mut cap = Capture::from_device(device)?
        .promisc(true)
        .immediate_mode(true)
        .timeout(1000)
        .open()
        .context("Failed to open capture")?;

    // Optional: only IP packets (helps reduce noise)
    // cap.filter("ip", true).ok();

    let addr = "127.0.0.1:8080";
    let mut sender = SocketSender::new(addr)
        .await
        .context("Failed to connect to Python receiver")?;
    println!("[INFO] Connected to Python receiver at {}", addr);

    let start = Instant::now();
    let mut packet_count: u32 = 0;
    let mut dropped_count: u32 = 0;

    loop {
        match cap.next_packet() {
            Ok(packet) => {
                packet_count += 1;

                if let Some(mut data) = build_packet_struct(packet.data) {
                    // Provide a rough duration since capture started
                    data.packet_count = packet_count;
                    data.duration = start.elapsed().as_secs_f64();

                    // Send to Python
                    if let Err(e) = sender.send_packet(&data).await {
                        eprintln!("[ERROR] Failed sending to Python: {e}");
                        // If send fails, break (Python might be down)
                        break;
                    }

                    if packet_count % 500 == 0 {
                        println!(
                            "[INFO] Captured/sent packets: {} (dropped: {})",
                            packet_count, dropped_count
                        );
                    }
                } else {
                    // Non IPv4 or unparseable -> ignore silently
                    dropped_count += 1;
                }
            }

            Err(pcap::Error::TimeoutExpired) => {
                // This is NORMAL on Windows/Npcap. It just means "no packet arrived in timeout window".
                // Do NOT treat as fatal.
            }

            Err(e) => {
                eprintln!("[ERROR] Capture error: {e}");
                break;
            }
        }
    }

    Ok(())
}
