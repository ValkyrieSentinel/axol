# AXOL Core (Sovereign Orchestrator)

High-performance XDP network filter with Virtual Fragment Reassembly (VFR) anomaly detection and dynamic blocklist.

## Overview
AXOL is a production-ready network security daemon built with Rust and eBPF (Aya). It operates at the XDP layer to drop malicious traffic before it reaches the kernel network stack.

## Key Features
- VFR Anomaly Detection: State machine to detect overlapping IP fragments (classic firewall evasion).
- Dynamic Blocklist: User-space daemon (tokio) manages an eBPF HashMap for real-time IP blocking via mpsc channel.
- VLAN Support: Automatically strips 802.1Q/802.1AD headers to inspect inner IPv4 packets.
- Hand-written ASM: Optimized x86-64 assembly (scan_pattern_asm) for high-throughput payload inspection.
- Per-CPU Telemetry: Lock-free statistics collection (RX, Drops, VFR Anomalies) via PerCpuArray.

## Architecture
- ebpf_probe: The kernel-space XDP program (no_std).
- axol-core: The user-space orchestrator managing maps and telemetry.

## Build and Run

    cargo build --release
    sudo ./target/release/axol-core --interface eth0 --block 192.168.1.100

## License
MIT. Part of the ValkyrieSentinel ecosystem.
