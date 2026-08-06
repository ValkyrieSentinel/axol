use aya::maps::{HashMap, PerCpuArray, MapData};
use aya::programs::Xdp;
use aya::Ebpf;
use aya::{include_bytes_aligned, Pod};
use clap::Parser;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};

#[derive(Parser, Debug)]
#[command(author, version, about = "AXOL Core Sovereign Orchestrator - Production Node")]
struct Args {
    #[arg(short, long, default_value = "eth0")]
    interface: String,

    #[arg(long, value_name = "IP")]
    block: Vec<String>,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PacketStats {
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub dropped_packets: u64,
    pub vfr_anomalies: u64,
}

unsafe impl Pod for PacketStats {}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse();

    log::info!("Initializing AXOL Core Production Daemon on interface: {}", args.interface);

    #[cfg(debug_assertions)]
    let mut bpf = Ebpf::load(include_bytes_aligned!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../target/bpfel-unknown-none/debug/ebpf_probe"
    )))?;

    #[cfg(not(debug_assertions))]
    let mut bpf = Ebpf::load(include_bytes_aligned!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../target/bpfel-unknown-none/release/ebpf_probe"
    )))?;

    let prog_mut = bpf.program_mut("sentinel_vfr_filter")
        .ok_or_else(|| anyhow::anyhow!("Critical: Program sentinel_vfr_filter not found in ELF"))?;
    
    let program: &mut Xdp = prog_mut.try_into()?;
    program.load()?;
    
    let _link = program.attach(&args.interface, Default::default())
        .map_err(|e| anyhow::anyhow!("Failed to attach XDP program to {}: {}", args.interface, e))?;
    
    log::info!("XDP program successfully locked and attached to driver interface: {}", args.interface);

    let stats_map_data = bpf.take_map("STATS")
        .ok_or_else(|| anyhow::anyhow!("STATS map missing from eBPF object"))?;
    let stats_map = PerCpuArray::try_from(stats_map_data)?;

    let blocklist_map_data = bpf.take_map("BLOCKLIST")
        .ok_or_else(|| anyhow::anyhow!("BLOCKLIST map missing from eBPF object"))?;
    
    let blocklist_map = HashMap::<MapData, u32, u32>::try_from(blocklist_map_data)?;
    let blocklist_map = Arc::new(Mutex::new(blocklist_map));

  
    for ip_str in args.block {
        match ip_str.parse::<Ipv4Addr>() {
            Ok(ip) => {
                let key = u32::from(ip);
                blocklist_map.lock().await.insert(key, 1, 0)?;
                log::warn!("SECURITY ALERT: Injected static threat IP into kernel BLOCKLIST: {}", ip);
            }
            Err(e) => {
                log::error!("Malformed IP address in arguments '{}': {}", ip_str, e);
            }
        }
    }

    
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<Ipv4Addr>(100);
    let _cmd_sender = cmd_tx;

    
    let map_clone = blocklist_map.clone();
    tokio::spawn(async move {
        while let Some(ip_to_block) = cmd_rx.recv().await {
            let key = u32::from(ip_to_block);
            if let Err(e) = map_clone.lock().await.insert(key, 1, 0) {
                log::error!("Failed to inject dynamic block rule for {}: {}", ip_to_block, e);
            } else {
                log::info!("Dynamic runtime block enforced for IP: {}", ip_to_block);
            }
        }
    });

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        log::warn!("Shutdown signal received. Initiating graceful teardown...");
        r.store(false, Ordering::SeqCst);
    })?;

    log::info!("AXOL Core operational. Entering high-performance telemetry loop...");

    let mut prev_packets = 0;
    let mut prev_bytes = 0;

    while running.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_secs(1)).await;

        let mut total = PacketStats {
            rx_packets: 0,
            rx_bytes: 0,
            dropped_packets: 0,
            vfr_anomalies: 0,
        };

        if let Ok(values) = stats_map.get(&0, 0) {
            total.rx_packets = values.iter().map(|v: &PacketStats| v.rx_packets).sum();
            total.rx_bytes = values.iter().map(|v: &PacketStats| v.rx_bytes).sum();
            total.dropped_packets = values.iter().map(|v: &PacketStats| v.dropped_packets).sum();
            total.vfr_anomalies = values.iter().map(|v: &PacketStats| v.vfr_anomalies).sum();
        }

        let pps = total.rx_packets.saturating_sub(prev_packets);
        let bps = total.rx_bytes.saturating_sub(prev_bytes);
        prev_packets = total.rx_packets;
        prev_bytes = total.rx_bytes;

        log::info!(
            "METRICS | PPS: {} | BPS: {} | Total RX: {} | Dropped: {} | VFR Anomalies: {}",
            pps,
            bps,
            total.rx_packets,
            total.dropped_packets,
            total.vfr_anomalies
        );
    }

    log::info!("AXOL Core successfully shutdown. eBPF probes detached automatically.");
    Ok(())
}