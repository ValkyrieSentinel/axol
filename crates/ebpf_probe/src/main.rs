#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{HashMap, LruHashMap, PerCpuArray},
    programs::XdpContext,
};

const ETH_P_IP: u16 = 0x0800;
const ETH_P_8021Q: u16 = 0x8100;
const ETH_P_8021AD: u16 = 0x88A8;

const IP_MF: u16 = 0x2000;
const IP_OFFSET: u16 = 0x1FFF;

#[repr(C)]
pub struct EthHdr {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ether_type: u16,
}

#[repr(C)]
pub struct VlanHdr {
    pub h_vlan_tci: u16,
    pub h_vlan_encapsulated_proto: u16,
}

#[repr(C)]
pub struct IpHdr {
    pub version_ihl: u8,
    pub tos: u8,
    pub tot_len: u16,
    pub id: u16,
    pub frag_off: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub check: u16,
    pub src_addr: u32,
    pub dst_addr: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FragKey {
    pub src_addr: u32,
    pub dst_addr: u32,
    pub id: u16,
    pub protocol: u8,
    pub _pad: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FragState {
    pub action: u32,
    pub max_offset: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PacketStats {
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub dropped_packets: u64,
    pub vfr_anomalies: u64,
}

#[map]
static BLOCKLIST: HashMap<u32, u32> = HashMap::with_max_entries(65536, 0);

#[map]
static FRAG_TABLE: LruHashMap<FragKey, FragState> = LruHashMap::with_max_entries(65536, 0);

#[map]
static STATS: PerCpuArray<PacketStats> = PerCpuArray::with_max_entries(1, 0);

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = core::mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

#[xdp]
pub fn sentinel_vfr_filter(ctx: XdpContext) -> u32 {
    match try_sentinel_vfr_filter(&ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
fn try_sentinel_vfr_filter(ctx: &XdpContext) -> Result<u32, ()> {
    let eth = unsafe { &*ptr_at::<EthHdr>(ctx, 0)? };
    let mut eth_type = u16::from_be(eth.ether_type);
    let mut ip_offset = core::mem::size_of::<EthHdr>();

    if eth_type == ETH_P_8021Q || eth_type == ETH_P_8021AD {
        let vlan = unsafe { &*ptr_at::<VlanHdr>(ctx, ip_offset)? };
        eth_type = u16::from_be(vlan.h_vlan_encapsulated_proto);
        ip_offset += core::mem::size_of::<VlanHdr>();
    }

    let packet_len = (ctx.data_end() - ctx.data()) as u64;

    if eth_type != ETH_P_IP {
        record_rx(packet_len);
        return Ok(xdp_action::XDP_PASS);
    }

    let ip = unsafe { &*ptr_at::<IpHdr>(ctx, ip_offset)? };
    let ihl_bytes = ((ip.version_ihl & 0x0F) * 4) as u32;

    if ihl_bytes < 20 {
        record_vfr_anomaly();
        record_drop(packet_len);
        return Ok(xdp_action::XDP_DROP);
    }

    let src_ip = ip.src_addr;

    if unsafe { BLOCKLIST.get(&src_ip).is_some() } {
        record_drop(packet_len);
        return Ok(xdp_action::XDP_DROP);
    }

    let frag_off_raw = u16::from_be(ip.frag_off);
    let mf = (frag_off_raw & IP_MF) != 0;
    let frag_offset = ((frag_off_raw & IP_OFFSET) as u32) * 8;

    if mf || frag_offset > 0 {
        let total_len = u16::from_be(ip.tot_len) as u32;
        let payload_len = total_len.saturating_sub(ihl_bytes);

        let frag_key = FragKey {
            src_addr: ip.src_addr,
            dst_addr: ip.dst_addr,
            id: ip.id,
            protocol: ip.protocol,
            _pad: 0,
        };

        if frag_offset == 0 {
            let state = FragState {
                action: xdp_action::XDP_PASS,
                max_offset: payload_len,
            };
            let _ = FRAG_TABLE.insert(&frag_key, &state, 0);
        } else {
            match FRAG_TABLE.get_ptr_mut(&frag_key) {
                Some(state_ptr) => {
                    let current_max = unsafe { (*state_ptr).max_offset };

                    if frag_offset < current_max {
                        record_vfr_anomaly();
                        record_drop(packet_len);
                        return Ok(xdp_action::XDP_DROP);
                    }
                    unsafe {
                        (*state_ptr).max_offset = frag_offset + payload_len;
                    }
                }
                None => {
                    record_vfr_anomaly();
                    record_drop(packet_len);
                    return Ok(xdp_action::XDP_DROP);
                }
            }
        }
    }

    record_rx(packet_len);
    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn record_rx(packet_len: u64) {
    if let Some(stats_ptr) = STATS.get_ptr_mut(0) {
        unsafe {
            (*stats_ptr).rx_packets += 1;
            (*stats_ptr).rx_bytes += packet_len;
        }
    }
}

#[inline(always)]
fn record_drop(packet_len: u64) {
    if let Some(stats_ptr) = STATS.get_ptr_mut(0) {
        unsafe {
            (*stats_ptr).dropped_packets += 1;
            (*stats_ptr).rx_bytes += packet_len;
        }
    }
}

#[inline(always)]
fn record_vfr_anomaly() {
    if let Some(stats_ptr) = STATS.get_ptr_mut(0) {
        unsafe {
            (*stats_ptr).vfr_anomalies += 1;
        }
    }
}
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}